// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2023 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wallet/wallet.h"

#include "blockstorage/blockstorage.h"
#include "chain.h"
#include "checkpoints.h"
#include "coincontrol.h"
#include "consensus/consensus.h"
#include "consensus/grouptokens.h"
#include "consensus/validation.h"
#include "core_io.h" // Freeze for debug only
#include "dstencode.h"
#include "fs.h"
#include "grouptokenwallet.h"
#include "key.h"
#include "keystore.h"
#include "main.h"
#include "net.h"
#include "policy/policy.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "script/scripttemplate.h"
#include "script/sign.h"
#include "timedata.h"
#include "txadmission.h"
#include "txmempool.h"
#include "ui_interface.h"
#include "util.h"
#include "utilmoneystr.h"
#include "validation/validation.h"

#include <algorithm>
#include <assert.h>
#include <functional>
#include <numeric>

#include <boost/algorithm/string/replace.hpp>
#include <thread>

using namespace std;

CWallet *pwalletMain = nullptr;
unsigned int nTxConfirmTarget = DEFAULT_TX_CONFIRM_TARGET;
bool bSpendZeroConfChange = DEFAULT_SPEND_ZEROCONF_CHANGE;
bool fSendFreeTransactions = DEFAULT_SEND_FREE_TRANSACTIONS;

const unsigned int P2PKH_LEN = 34;
const unsigned int MIN_BYTES_IN_TX = 185;

const char *DEFAULT_WALLET_DAT = "wallet.dat";

const uint256 CMerkleTx::ABANDON_HASH(uint256S("0000000000000000000000000000000000000000000000000000000000000001"));

extern CTweak<bool> useBIP69;
extern CTweak<bool> feeEstimationTweak;
extern CTweak<bool> instantTxns;
extern CTweak<uint32_t> instantTxnsDelay;
extern CTweak<bool> autoTxns;

/** @defgroup mapWallet
 *
 * @{
 */

struct CompareValueOnly
{
    bool operator()(const pair<CAmount, COutput> &t1, const pair<CAmount, COutput> &t2) const
    {
        return t1.first < t2.first;
    }
};

std::string COutput::ToString() const
{
    return strprintf("COutput(%s, %d) [%s]", tx->GetId().ToString(), i, FormatMoney(tx->vout[i].nValue));
}

const CWalletTxRef CWallet::GetWalletTx(const uint256 &hash) const
{
    LOCK(cs_wallet);
    // Wallet stores its transactions by their raw hash in the same map as it stores utxos
    MapWallet::const_iterator it = mapWallet.find(COutPoint(hash));
    if (it == mapWallet.end())
        return nullptr;
    return it->second.tx;
}

const COutput CWallet::GetWalletCoin(const COutPoint &prevout) const
{
    LOCK(cs_wallet);
    MapWallet::const_iterator it = mapWallet.find(prevout);
    if (it == mapWallet.end())
        return COutput();
    return it->second;
}


void CWallet::Check()
{
    return;
    if (!Params().DefaultConsistencyChecks())
        return;

    LOCK(cs_wallet);
    for (auto &mi : mapWallet)
    {
        const COutPoint &outpoint = mi.first;
        const COutput &coin = mi.second;
        auto tx = coin.tx;
        uint256 txid = tx->GetId();
        uint256 txidem = tx->GetIdem();
        assert(tx);

        if (outpoint.hash == tx->GetId()) // If its the tx record, run cross checks
        {
            assert(mapWallet.count(COutPoint(txidem)) == 1); // An Idem must exist
            const COutput &c = mapWallet[COutPoint(txidem)];
            if (c.tx->GetId() == txid)
            {
                // If this is the same transaction, then it
                // must share the same underlying tx memory
                DbgAssert(c.tx == tx, );
            }
            // Check that all of my outpoints exist and share the same underlying tx memory
            for (unsigned int i = 0; i < tx->vout.size(); i++)
            {
                auto newOutpoint = tx->OutpointAt(i);
                // assert(mapWallet.count(newOutpoint) == 1);
                isminetype mine = IsMine(tx->vout[i]);
                if (mine != ISMINE_NO)
                {
                    DbgAssert(mapWallet.count(newOutpoint) == 1, );
                    const COutput &co = mapWallet[newOutpoint];
                    if (co.tx->GetId() == txid)
                    {
                        // If this is the same transaction, then it must share the same underlying tx memory
                        DbgAssert(co.tx == tx, );
                    }
                }
            }
        }
    }
}

CPubKey CWallet::GenerateNewKey()
{
    AssertLockHeld(cs_wallet); // mapKeyMetadata
    // default to compressed public keys if we want 0.6.0 wallets
    bool fCompressed = CanSupportFeature(FEATURE_COMPRPUBKEY);

    CKey secret;

    // Create new metadata
    int64_t nCreationTime = GetTime();
    CKeyMetadata metadata(nCreationTime);

    // use HD key derivation if HD was enabled during wallet creation
    if (IsHDEnabled())
    {
        DeriveNewChildKey(metadata, secret);
    }
    else
    {
        secret.MakeNewKey(fCompressed);
    }

    // Compressed public keys were introduced in version 0.6.0
    if (fCompressed)
        SetMinVersion(FEATURE_COMPRPUBKEY);

    CPubKey pubkey = secret.GetPubKey();
    assert(secret.VerifyPubKey(pubkey));

    mapKeyMetadata[pubkey.GetID()] = metadata;
    if (!nTimeFirstKey || nCreationTime < nTimeFirstKey)
        nTimeFirstKey = nCreationTime;

    if (!AddKeyPubKey(secret, pubkey))
        throw std::runtime_error("CWallet::GenerateNewKey(): AddKey failed");
    return pubkey;
}

void CWallet::DeriveNewChildKey(CKeyMetadata &metadata, CKey &secret)
{
    // for now we use a fixed keypath scheme of m/0'/0'/k
    CKey key; // master key seed (256bit)
    CExtKey masterKey; // hd master key
    CExtKey accountKey; // key at m/0'
    CExtKey externalChainChildKey; // key at m/0'/0'
    CExtKey childKey; // key at m/0'/0'/<n>'

    // try to get the master key
    if (!GetKey(hdChain.masterKeyID, key))
        throw std::runtime_error(std::string(__func__) + ": Master key not found");

    masterKey.SetMaster(key.begin(), key.size());

    // derive m/0'
    // use hardened derivation (child keys >= 0x80000000 are hardened after bip32)
    masterKey.Derive(accountKey, BIP32_HARDENED_KEY_LIMIT);

    // derive m/0'/0'
    accountKey.Derive(externalChainChildKey, BIP32_HARDENED_KEY_LIMIT);

    // derive child key at next index, skip keys already known to the wallet
    do
    {
        // always derive hardened keys
        // childIndex | BIP32_HARDENED_KEY_LIMIT = derive childIndex in hardened child-index-range
        // example: 1 | BIP32_HARDENED_KEY_LIMIT == 0x80000001 == 2147483649
        externalChainChildKey.Derive(childKey, hdChain.nExternalChainCounter | BIP32_HARDENED_KEY_LIMIT);
        metadata.hdKeypath = "m/0'/0'/" + std::to_string(hdChain.nExternalChainCounter) + "'";
        metadata.hdMasterKeyID = hdChain.masterKeyID;
        // increment childkey index
        hdChain.nExternalChainCounter++;
    } while (HaveKey(childKey.key.GetPubKey().GetID()));
    secret = childKey.key;

    // update the chain model in the database
    if (!CWalletDB(strWalletFile).WriteHDChain(hdChain))
        throw std::runtime_error(std::string(__func__) + ": Writing HD chain model failed");
}

bool CWallet::AddKeyPubKey(const CKey &secret, const CPubKey &pubkey)
{
    AssertLockHeld(cs_wallet); // mapKeyMetadata
    if (!CCryptoKeyStore::AddKeyPubKey(secret, pubkey))
        return false;

    // check if we need to remove from watch-only
    CScript script;
    script = GetScriptForDestination(pubkey.GetID());
    if (HaveWatchOnly(script))
        RemoveWatchOnly(script);
    script = GetScriptForRawPubKey(pubkey);
    if (HaveWatchOnly(script))
        RemoveWatchOnly(script);

    if (!fFileBacked)
        return true;
    if (!IsCrypted())
    {
        return CWalletDB(strWalletFile).WriteKey(pubkey, secret.GetPrivKey(), mapKeyMetadata[pubkey.GetID()]);
    }
    return true;
}

bool CWallet::AddCryptedKey(const CPubKey &vchPubKey, const vector<unsigned char> &vchCryptedSecret)
{
    if (!CCryptoKeyStore::AddCryptedKey(vchPubKey, vchCryptedSecret))
        return false;
    if (!fFileBacked)
        return true;
    {
        LOCK(cs_wallet);
        if (pwalletdbEncryption)
            return pwalletdbEncryption->WriteCryptedKey(vchPubKey, vchCryptedSecret, mapKeyMetadata[vchPubKey.GetID()]);
        else
            return CWalletDB(strWalletFile)
                .WriteCryptedKey(vchPubKey, vchCryptedSecret, mapKeyMetadata[vchPubKey.GetID()]);
    }
    return false;
}

bool CWallet::LoadKeyMetadata(const CPubKey &pubkey, const CKeyMetadata &meta)
{
    AssertLockHeld(cs_wallet); // mapKeyMetadata
    if (meta.nCreateTime && (!nTimeFirstKey || meta.nCreateTime < nTimeFirstKey))
        nTimeFirstKey = meta.nCreateTime;

    mapKeyMetadata[pubkey.GetID()] = meta;
    return true;
}

bool CWallet::LoadCryptedKey(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret)
{
    return CCryptoKeyStore::AddCryptedKey(vchPubKey, vchCryptedSecret);
}

bool CWallet::AddCScript(const CScript &redeemScript)
{
    if (!CCryptoKeyStore::AddCScript(redeemScript))
        return false;
    if (!fFileBacked)
        return true;
    return CWalletDB(strWalletFile).WriteCScript(Hash160(redeemScript), redeemScript);
}

bool CWallet::LoadCScript(const CScript &redeemScript)
{
    /**
     * A sanity check was added in pull #3843 to avoid adding redeemScripts that
     * never can be redeemed. However, old wallets may still contain these. Do
     * not add them to the wallet and warn.
     */
    if (redeemScript.size() > MAX_SCRIPT_ELEMENT_SIZE)
    {
        std::string strAddr = EncodeDestination(CScriptID(redeemScript));
        LOGA("%s: Warning: This wallet contains a redeemScript of size %i "
             "which exceeds maximum size %i thus can never be redeemed. "
             "Do not use address %s.\n",
            __func__, redeemScript.size(), MAX_SCRIPT_ELEMENT_SIZE, strAddr);
        return true;
    }

    return CCryptoKeyStore::AddCScript(redeemScript);
}

bool CWallet::LoadFreezeScript(CPubKey newKey, CScriptNum nFreezeLockTime, std::string strLabel, std::string &address)
{
    // Template rpcdump.cpp::ImportAddress();

    // Get Freeze Script
    CScript freezeScript = GetScriptForFreeze(nFreezeLockTime, newKey);

    // Test and Add Script to wallet
    if (!this->HaveCScript(freezeScript) && !this->AddCScript(freezeScript))
    {
        LOGA("LoadFreezeScript: Error adding p2sh freeze redeemScript to wallet. \n ");
        return false;
    }
    // If just added then return P2SH for user
    address = EncodeDestination(CScriptID(freezeScript));
    LOGA("CLTV Freeze Script Load \n %s => %s \n ", ::ScriptToAsmStr(freezeScript), address.c_str());
    return true;
}

bool CWallet::AddWatchOnly(const CScript &dest)
{
    if (!CCryptoKeyStore::AddWatchOnly(dest))
        return false;
    nTimeFirstKey = 1; // No birthday information for watch-only keys.
    NotifyWatchonlyChanged(true);
    if (!fFileBacked)
        return true;
    return CWalletDB(strWalletFile).WriteWatchOnly(dest);
}

bool CWallet::RemoveWatchOnly(const CScript &dest)
{
    AssertLockHeld(cs_wallet);
    if (!CCryptoKeyStore::RemoveWatchOnly(dest))
        return false;
    if (!HaveWatchOnly())
        NotifyWatchonlyChanged(false);
    if (fFileBacked)
        if (!CWalletDB(strWalletFile).EraseWatchOnly(dest))
            return false;

    return true;
}

bool CWallet::LoadWatchOnly(const CScript &dest) { return CCryptoKeyStore::AddWatchOnly(dest); }
bool CWallet::Unlock(const SecureString &strWalletPassphrase)
{
    CCrypter crypter;
    CKeyingMaterial _vMasterKey;

    {
        LOCK(cs_wallet);
        for (const MasterKeyMap::value_type &pMasterKey : mapMasterKeys)
        {
            if (!crypter.SetKeyFromPassphrase(strWalletPassphrase, pMasterKey.second.vchSalt,
                    pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
                return false;
            if (!crypter.Decrypt(pMasterKey.second.vchCryptedKey, _vMasterKey))
                continue; // try another master key
            if (CCryptoKeyStore::Unlock(_vMasterKey))
                return true;
        }
    }
    return false;
}

bool CWallet::ChangeWalletPassphrase(const SecureString &strOldWalletPassphrase,
    const SecureString &strNewWalletPassphrase)
{
    bool fWasLocked = IsLocked();

    {
        LOCK(cs_wallet);
        Lock();

        CCrypter crypter;
        CKeyingMaterial _vMasterKey;
        for (MasterKeyMap::value_type &pMasterKey : mapMasterKeys)
        {
            if (!crypter.SetKeyFromPassphrase(strOldWalletPassphrase, pMasterKey.second.vchSalt,
                    pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
                return false;
            if (!crypter.Decrypt(pMasterKey.second.vchCryptedKey, _vMasterKey))
                return false;
            if (CCryptoKeyStore::Unlock(_vMasterKey))
            {
                int64_t nStartTime = GetTimeMillis();
                crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt,
                    pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod);
                pMasterKey.second.nDeriveIterations =
                    pMasterKey.second.nDeriveIterations * (100 / ((double)(GetTimeMillis() - nStartTime)));

                nStartTime = GetTimeMillis();
                crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt,
                    pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod);
                pMasterKey.second.nDeriveIterations =
                    (pMasterKey.second.nDeriveIterations +
                        pMasterKey.second.nDeriveIterations * 100 / ((double)(GetTimeMillis() - nStartTime))) /
                    2;

                if (pMasterKey.second.nDeriveIterations < 25000)
                    pMasterKey.second.nDeriveIterations = 25000;

                LOGA("Wallet passphrase changed to an nDeriveIterations of %i\n", pMasterKey.second.nDeriveIterations);

                if (!crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt,
                        pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
                    return false;
                if (!crypter.Encrypt(_vMasterKey, pMasterKey.second.vchCryptedKey))
                    return false;
                CWalletDB(strWalletFile).WriteMasterKey(pMasterKey.first, pMasterKey.second);
                if (fWasLocked)
                    Lock();
                return true;
            }
        }
    }

    return false;
}

void CWallet::SetBestChain(const CBlockLocator &loc)
{
    CWalletDB walletdb(strWalletFile);
    walletdb.WriteBestBlock(loc);
}

bool CWallet::SetMinVersion(enum WalletFeature nVersion, CWalletDB *pwalletdbIn, bool fExplicit)
{
    LOCK(cs_wallet); // nWalletVersion
    if (nWalletVersion >= nVersion)
        return true;

    // when doing an explicit upgrade, if we pass the max version permitted, upgrade all the way
    if (fExplicit && nVersion > nWalletMaxVersion)
        nVersion = FEATURE_LATEST;

    nWalletVersion = nVersion;

    if (nVersion > nWalletMaxVersion)
        nWalletMaxVersion = nVersion;

    if (fFileBacked)
    {
        CWalletDB *pwalletdb = pwalletdbIn ? pwalletdbIn : new CWalletDB(strWalletFile);
        if (nWalletVersion > 40000)
            pwalletdb->WriteMinVersion(nWalletVersion);
        if (!pwalletdbIn)
            delete pwalletdb;
    }

    return true;
}

bool CWallet::SetMaxVersion(int nVersion)
{
    LOCK(cs_wallet); // nWalletVersion, nWalletMaxVersion
    // cannot downgrade below current version
    if (nWalletVersion > nVersion)
        return false;

    nWalletMaxVersion = nVersion;

    return true;
}

set<uint256> CWallet::GetConflicts(const uint256 &txid) const
{
    set<uint256> result;
    AssertLockHeld(cs_wallet);

    // wallet stores its tx by their hashes in mapWallet directly in "fake" outpoints, alongside the real outpoints
    MapWallet::const_iterator it = mapWallet.find(COutPoint(txid));
    if (it == mapWallet.end())
        return result;
    const CWalletTxRef wtx = it->second.tx;

    std::pair<TxSpends::const_iterator, TxSpends::const_iterator> range;

    for (const CTxIn &txin : wtx->vin)
    {
        if (mapTxSpends.count(txin.prevout) <= 1)
            continue; // No conflict if zero or one spends
        range = mapTxSpends.equal_range(txin.prevout);
        for (TxSpends::const_iterator it2 = range.first; it2 != range.second; ++it2)
        {
            if (it2->second != txid)
                result.insert(it2->second);
        }
    }
    return result;
}

void CWallet::Flush(bool shutdown) { bitdb.Flush(shutdown); }
bool CWallet::Verify()
{
    std::string walletFile = GetArg("-wallet", DEFAULT_WALLET_DAT);

    LOGA("Using wallet %s\n", walletFile);
    uiInterface.InitMessage(_("Verifying wallet..."));

    // Wallet file must be a plain filename without a directory
    if (fs::path(walletFile).filename() != walletFile)
        return InitError(
            strprintf(_("Wallet %s resides outside data directory %s"), walletFile, GetDataDir().string()));

    if (!bitdb.Open(GetDataDir()))
    {
        // try moving the database env out of the way
        fs::path pathDatabase = GetDataDir() / "database";
        fs::path pathDatabaseBak = GetDataDir() / strprintf("database.%d.bak", GetTime());
        try
        {
            fs::rename(pathDatabase, pathDatabaseBak);
            LOGA("Moved old %s to %s. Retrying.\n", pathDatabase.string(), pathDatabaseBak.string());
        }
        catch (const fs::filesystem_error &)
        {
            // failure is ok (well, not really, but it's not worse than what we started with)
        }

        // try again
        if (!bitdb.Open(GetDataDir()))
        {
            // if it still fails, it probably means we can't even create the database env
            return InitError(strprintf(_("Error initializing wallet database environment %s!"), GetDataDir()));
        }
    }

    if (GetBoolArg("-salvagewallet", false))
    {
        // Recover readable keypairs:
        if (!CWalletDB::Recover(bitdb, walletFile, true))
            return false;
    }

    if (fs::exists(GetDataDir() / walletFile))
    {
        CDBEnv::VerifyResult r = bitdb.Verify(walletFile, CWalletDB::Recover);
        if (r == CDBEnv::RECOVER_OK)
        {
            InitWarning(strprintf(_("Warning: Wallet file corrupt, data salvaged!"
                                    " Original %s saved as %s in %s; if"
                                    " your balance or transactions are incorrect you should"
                                    " restore from a backup."),
                walletFile, "wallet.{timestamp}.bak", GetDataDir()));
        }
        if (r == CDBEnv::RECOVER_FAIL)
            return InitError(strprintf(_("%s corrupt, salvage failed"), walletFile));
    }

    return true;
}

void CWallet::SyncMetaData(pair<TxSpends::iterator, TxSpends::iterator> range)
{
    // We want all the wallet transactions in range to have the same metadata as
    // the oldest (smallest nOrderPos).
    // So: find smallest nOrderPos:

    int nMinOrderPos = std::numeric_limits<int>::max();
    CWalletTxRef copyFrom;
    for (TxSpends::iterator it = range.first; it != range.second; ++it)
    {
        // Note: now we could also look it up directly from the OutPoint -- TxSpends could become a set
        const COutPoint txkey(it->second);
        int n = mapWallet[txkey].tx->nOrderPos;
        if (n < nMinOrderPos)
        {
            nMinOrderPos = n;
            copyFrom = mapWallet[txkey].tx;
        }
    }
    // Now copy data from copyFrom to rest:
    for (TxSpends::iterator it = range.first; it != range.second; ++it)
    {
        // Note: now we could also look it up directly from the OutPoint, -- TxSpends could become a set
        const COutPoint txkey(it->second);
        CWalletTxRef copyTo = mapWallet[txkey].tx;
        if (copyFrom == copyTo)
            continue;
        if (!copyFrom->IsEquivalentTo(*copyTo))
            continue;
        copyTo->mapValue = copyFrom->mapValue;
        copyTo->vOrderForm = copyFrom->vOrderForm;
        // fTimeReceivedIsTxTime not copied on purpose
        // nTimeReceived not copied on purpose
        copyTo->nTimeSmart = copyFrom->nTimeSmart;
        copyTo->fFromMe = copyFrom->fFromMe;
        copyTo->strFromAccount = copyFrom->strFromAccount;
        // nOrderPos not copied on purpose
        // cached members not copied on purpose
    }
}

/**
 * Outpoint is spent if any non-conflicted transaction
 * spends it:
 */
bool CWallet::IsSpent(const COutPoint &outpoint) const
{
    pair<TxSpends::const_iterator, TxSpends::const_iterator> range;
    range = mapTxSpends.equal_range(outpoint);

    for (TxSpends::const_iterator it = range.first; it != range.second; ++it)
    {
        const uint256 &wtxid = it->second;
        // Look up the transaction that spend this outpoint to see its status
        MapWallet::const_iterator mit = mapWallet.find(COutPoint(wtxid));
        if (mit != mapWallet.end())
        {
            CWalletTxRef tx = mit->second.tx;
            // Verify spend
            bool spent = false;
            for (const CTxIn &in : tx->vin)
            {
                if (in.prevout == outpoint)
                {
                    spent = true;
                    break;
                }
            }
            DbgAssert(spent == true, return false);
            int depth = tx->GetDepthInMainChain();
            if (depth > 0 || (depth == 0 && !tx->isAbandoned()))
                return true; // Spent
        }
        else
        {
            // cannot have a spent entry but no transaction in the map!
            DbgAssert(false, return true);
        }
    }
    return false;
}


void CWallet::AddToSpends(const COutPoint &outpoint, const uint256 &wtxid)
{
    mapTxSpends.insert(make_pair(outpoint, wtxid));

    pair<TxSpends::iterator, TxSpends::iterator> range;
    range = mapTxSpends.equal_range(outpoint);
    SyncMetaData(range);
}

void CWallet::RemoveFromSpends(const COutPoint &outpoint, const uint256 &txId)
{
    auto range = mapTxSpends.equal_range(outpoint);
    while (range.first != range.second)
    {
        if (range.first->second == txId)
            range.first = mapTxSpends.erase(range.first);
        else
            range.first++;
    }
}

void CWallet::AddToSpends(const CWalletTxRef wtx)
{
    uint256 txid = wtx->GetId();
    assert(mapWallet.count(COutPoint(txid))); // tx better be in the wallet
    uint256 txidem = wtx->GetIdem();
    assert(mapWallet.count(COutPoint(txidem))); // tx better be in the wallet
    if (wtx->IsCoinBase()) // Coinbases don't spend anything!
        return;

    for (const CTxIn &txin : wtx->vin)
    {
        AddToSpends(txin.prevout, txid);
    }
}

void CWallet::RemoveFromSpends(const CWalletTxRef wtx)
{
    uint256 txid = wtx->GetId();
    assert(mapWallet.count(COutPoint(txid))); // tx better be in the wallet
    uint256 txidem = wtx->GetIdem();
    assert(mapWallet.count(COutPoint(txidem))); // tx better be in the wallet
    if (wtx->IsCoinBase()) // Coinbases don't spend anything!
        return;

    for (const CTxIn &txin : wtx->vin)
    {
        RemoveFromSpends(txin.prevout, txid);
    }
}


bool CWallet::EncryptWallet(const SecureString &strWalletPassphrase)
{
    if (IsCrypted())
        return false;

    CKeyingMaterial _vMasterKey;

    _vMasterKey.resize(WALLET_CRYPTO_KEY_SIZE);
    GetStrongRandBytes(&_vMasterKey[0], WALLET_CRYPTO_KEY_SIZE);

    CMasterKey kMasterKey;

    kMasterKey.vchSalt.resize(WALLET_CRYPTO_SALT_SIZE);
    GetStrongRandBytes(&kMasterKey.vchSalt[0], WALLET_CRYPTO_SALT_SIZE);

    CCrypter crypter;
    int64_t nStartTime = GetTimeMillis();
    crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, 25000, kMasterKey.nDerivationMethod);
    kMasterKey.nDeriveIterations = 2500000 / ((double)(GetTimeMillis() - nStartTime));

    nStartTime = GetTimeMillis();
    crypter.SetKeyFromPassphrase(
        strWalletPassphrase, kMasterKey.vchSalt, kMasterKey.nDeriveIterations, kMasterKey.nDerivationMethod);
    kMasterKey.nDeriveIterations =
        (kMasterKey.nDeriveIterations + kMasterKey.nDeriveIterations * 100 / ((double)(GetTimeMillis() - nStartTime))) /
        2;

    if (kMasterKey.nDeriveIterations < 25000)
        kMasterKey.nDeriveIterations = 25000;

    LOGA("Encrypting Wallet with an nDeriveIterations of %i\n", kMasterKey.nDeriveIterations);

    if (!crypter.SetKeyFromPassphrase(
            strWalletPassphrase, kMasterKey.vchSalt, kMasterKey.nDeriveIterations, kMasterKey.nDerivationMethod))
        return false;
    if (!crypter.Encrypt(_vMasterKey, kMasterKey.vchCryptedKey))
        return false;

    {
        LOCK(cs_wallet);
        mapMasterKeys[++nMasterKeyMaxID] = kMasterKey;
        if (fFileBacked)
        {
            assert(!pwalletdbEncryption);
            pwalletdbEncryption = new CWalletDB(strWalletFile);
            if (!pwalletdbEncryption->TxnBegin())
            {
                delete pwalletdbEncryption;
                pwalletdbEncryption = nullptr;
                return false;
            }
            pwalletdbEncryption->WriteMasterKey(nMasterKeyMaxID, kMasterKey);
        }

        if (!EncryptKeys(_vMasterKey))
        {
            if (fFileBacked)
            {
                pwalletdbEncryption->TxnAbort();
                delete pwalletdbEncryption;
            }
            // We now probably have half of our keys encrypted in memory, and half not...
            // die and let the user reload the unencrypted wallet.
            assert(false);
        }

        // Encryption was introduced in version 0.4.0
        SetMinVersion(FEATURE_WALLETCRYPT, pwalletdbEncryption, true);

        if (fFileBacked)
        {
            if (!pwalletdbEncryption->TxnCommit())
            {
                delete pwalletdbEncryption;
                // We now have keys encrypted in memory, but not on disk...
                // die to avoid confusion and let the user reload the unencrypted wallet.
                assert(false);
            }

            delete pwalletdbEncryption;
            pwalletdbEncryption = nullptr;
        }

        Lock();
        Unlock(strWalletPassphrase);

        // if we are using HD, replace the HD master key with a new one
        if (!hdChain.masterKeyID.IsNull())
        {
            CKey key;
            CPubKey masterPubKey = GenerateNewHDMasterKey();
            if (!SetHDMasterKey(masterPubKey))
                return false;
        }

        NewKeyPool();
        Lock();

        // Need to completely rewrite the wallet file; if we don't, bdb might keep
        // bits of the unencrypted private key in slack space in the database file.
        CDB::Rewrite(strWalletFile);
    }
    NotifyStatusChanged(this);

    return true;
}

int64_t CWallet::IncOrderPosNext(CWalletDB *pwalletdb)
{
    AssertLockHeld(cs_wallet); // nOrderPosNext
    int64_t nRet = nOrderPosNext++;
    if (pwalletdb)
    {
        pwalletdb->WriteOrderPosNext(nOrderPosNext);
    }
    else
    {
        CWalletDB(strWalletFile).WriteOrderPosNext(nOrderPosNext);
    }
    return nRet;
}

void CWallet::MarkDirty()
{
    LOCK(cs_wallet);
    for (MapWallet::value_type &item : mapWallet)
    {
        item.second.tx->MarkDirty();
    }
}

bool CWallet::AddToWallet(CWalletTxRef wtx, bool fFromLoadWallet, CWalletDB *pwalletdb)
{
    LOCK(cs_wallet);
    if (fFromLoadWallet)
    {
        DbgAssert(wtx->nOrderPos != -1, wtx->nOrderPos = IncOrderPosNext(pwalletdb));
        assert(wtx->nOrderPos != -1);
        // Add every outpoint
        for (size_t i = 0; i < wtx->vout.size(); i++)
        {
            isminetype mine = IsMine(wtx->vout[i]);
            if (mine != ISMINE_NO)
            {
                const auto &outpoint = wtx->OutpointAt(i);
                COutput output = COutput(wtx, i, mine);
                mapWallet[outpoint] = output;

                // Add to unspent map
                if (!IsSpent(outpoint))
                    mapWalletUnspent[outpoint] = output;
            }
        }
        // Add id and idem for easy lookup
        mapWallet[COutPoint(wtx->GetId())] = COutput(wtx, -1, isminetype::ISMINE_NO);
        mapWallet[COutPoint(wtx->GetIdem())] = COutput(wtx, -1, isminetype::ISMINE_NO);

        wtx->BindWallet(this);
        wtxOrdered.insert(make_pair(wtx->nOrderPos, TxPair(wtx, nullptr)));
        AddToSpends(wtx);
        for (const CTxIn &txin : wtx->vin)
        {
            auto it = mapWallet.find(txin.prevout);
            // If a parent is conflicted then also mark this wallet as conflicted
            if (it != mapWallet.end())
            {
                COutput &prevout = it->second;
                CWalletTxRef prevtx = prevout.tx;
                // can't conflict with yourself
                if ((prevtx->GetIdem() != wtx->GetIdem()) &&
                    // if unconfirmed and we are not abandoning this prevtx
                    (prevtx->nIndex == -1) && !prevtx->hashUnset())
                {
                    MarkConflicted(prevtx->hashBlock, wtx->GetId());
                }
            }
        }
    }
    else
    {
        CWalletTxRef wtxIn = wtx;
        COutput dummyout(wtx, -1, isminetype::ISMINE_NO);
        // Inserts only if not already there, returns tx inserted or tx found
        if (wtx->nOrderPos == -1)
            wtx->nOrderPos = IncOrderPosNext(pwalletdb);
        pair<MapWallet::iterator, bool> ret = mapWallet.insert(make_pair(COutPoint(wtx->GetId()), dummyout));
        wtx = ret.first->second.tx; // wtx is now the wallet's transaction, whether it came from the param or the map
        dummyout.tx = wtx; // Reset in case it changed
        bool fInsertedNew = ret.second;

        // Add idem for easy lookup (id was added in first insert). We will alway overwrite the idem entry
        // with the last notified transaction.  This will mean that a tx confirmed in a block gets the idem entry.
        mapWallet[COutPoint(wtx->GetIdem())] = dummyout;


        // Always add coins to the unspent wallet
        for (size_t i = 0; i < wtx->vout.size(); i++)
        {
            isminetype mine = IsMine(wtx->vout[i]);
            // Add to unspent map
            const auto &outpoint = wtx->OutpointAt(i);
            if (!IsSpent(outpoint) && mine != ISMINE_NO)
            {
                mapWalletUnspent[outpoint] = COutput(wtx, i, mine);
            }
        }

        if (fInsertedNew)
        {
            wtx->BindWallet(this);
            // Add every outpoint
            for (size_t i = 0; i < wtx->vout.size(); i++)
            {
                isminetype mine = IsMine(wtx->vout[i]);
                if (mine != ISMINE_NO)
                    mapWallet[wtx->OutpointAt(i)] = COutput(wtx, i, mine);
            }

            wtx->nTimeReceived = GetAdjustedTime();
            assert(wtx->nOrderPos != -1);
            wtxOrdered.insert(make_pair(wtx->nOrderPos, TxPair(wtx, nullptr)));

            wtx->nTimeSmart = wtx->nTimeReceived;
            if (!wtx->hashUnset())
            {
                CBlockIndex *tmp = nullptr;
                if ((tmp = LookupBlockIndex(wtx->hashBlock)) != nullptr)
                {
                    int64_t latestNow = wtx->nTimeReceived;
                    int64_t latestEntry = 0;
                    {
                        // Tolerate times up to the last timestamp in the wallet not more than 5 minutes into the future
                        int64_t latestTolerated = latestNow + 300;
                        const TxItems &txOrdered = wtxOrdered;
                        for (TxItems::const_reverse_iterator it = txOrdered.rbegin(); it != txOrdered.rend(); ++it)
                        {
                            CWalletTxRef pwtx = (*it).second.first;
                            if (pwtx == wtx)
                                continue;
                            CAccountingEntry *const pacentry = (*it).second.second;
                            int64_t nSmartTime;
                            if (pwtx)
                            {
                                nSmartTime = pwtx->nTimeSmart;
                                if (!nSmartTime)
                                    nSmartTime = pwtx->nTimeReceived;
                            }
                            else
                                nSmartTime = pacentry->nTime;
                            if (nSmartTime <= latestTolerated)
                            {
                                latestEntry = nSmartTime;
                                if (nSmartTime > latestNow)
                                    latestNow = nSmartTime;
                                break;
                            }
                        }
                    }

                    int64_t blocktime = tmp->GetBlockTime();
                    wtx->nTimeSmart = std::max(latestEntry, std::min(blocktime, latestNow));
                }
                else
                    LOGA("AddToWallet(): found %s in block %s not in index\n", wtx->GetId().ToString(),
                        wtx->hashBlock.ToString());
            }
            AddToSpends(wtx);
        }

        bool fUpdated = false;
        if (!fInsertedNew) // Merge
        {
            // When the tx is accepted by the txpool, it will be added to the wallet but any account info is stripped
            // since accounts are not part of the base CTransaction.  This addition races against the wallet adding
            // the transaction (with account info) itself.  If the txpool path wins, we may need to update the tx with
            // account info.
            fUpdated = wtx->Update(*wtxIn);
        }

        // Only useful if debugging wallet
        // LOGA("AddToWallet %s  %s%s\n", wtx->GetHash().ToString(), (fInsertedNew ? "new" : ""),
        //    (fUpdated ? "update" : ""));

        // Write to disk
        if (fInsertedNew || fUpdated)
            if (!wtx->WriteToDisk(pwalletdb))
                return false;

        // Break debit/credit balance caches:
        wtx->MarkDirty();

        // Notify UI of new or updated transaction
        NotifyTransactionChanged(this, wtx->GetIdem(), fInsertedNew ? CT_NEW : CT_UPDATED);

        // notify an external script when a wallet transaction comes in or is updated
        std::string strCmd = GetArg("-walletnotify", "");

        if (!strCmd.empty())
        {
            boost::replace_all(strCmd, "%s", wtx->GetIdem().GetHex());
            std::thread t(runCommand, strCmd);
            t.detach(); // thread runs free
        }
    }
    assert(wtx->nOrderPos != -1);
    Check();
    return true;
}

bool CWalletTx::Update(const CWalletTx &wtx)
{
    bool fUpdated = false;
    // Don't update a transaction if they aren't actually the same one
    DbgAssert(GetIdem() == wtx.GetIdem(), return false);

    if ((wtx.strFromAccount.size() > 0) && (strFromAccount.size() == 0))
    {
        LOGA("Add an account into wallet tx");
        strFromAccount = wtx.strFromAccount;
        fUpdated = true;
    }
    if (!wtx.hashUnset() && wtx.hashBlock != hashBlock)
    {
        hashBlock = wtx.hashBlock;
        fUpdated = true;
    }
    // If no longer abandoned, update
    if (wtx.hashBlock.IsNull() && isAbandoned())
    {
        hashBlock = wtx.hashBlock;
        fUpdated = true;
    }
    // Once we know about a confirmation, don't overwrite it
    if ((wtx.nIndex != -1) && (wtx.nIndex != nIndex))
    {
        nIndex = wtx.nIndex;
        fUpdated = true;
    }
    if (wtx.fFromMe && wtx.fFromMe != fFromMe)
    {
        fFromMe = wtx.fFromMe;
        fUpdated = true;
    }

    return fUpdated;
}


/**
 * Add a transaction to the wallet, or update it.
 * pblock is optional, but should be provided if the transaction is known to be in a block.
 * If fUpdate is true, existing transactions will be updated.
 * @return true if the wallet was updated
 */
bool CWallet::AddToWalletIfInvolvingMe(const CTransactionRef &ptx,
    const ConstCBlockRef pblock,
    bool fUpdate,
    int txIndex)
{
    AssertLockHeld(cs_wallet);

    if (pblock)
    {
        uint256 txId = ptx->GetId();
        for (const CTxIn &txin : ptx->vin)
        {
            std::pair<TxSpends::const_iterator, TxSpends::const_iterator> range = mapTxSpends.equal_range(txin.prevout);
            while (range.first != range.second)
            {
                if (range.first->second != txId)
                {
                    LOGA("Transaction %s (in block %s) conflicts with wallet transaction %s (both spend %s)\n",
                        ptx->GetId().ToString(), pblock->GetHash().ToString(), range.first->second.ToString(),
                        range.first->first.hash.ToString());
                    MarkConflicted(pblock->GetHash(), range.first->second);
                }
                range.first++;
            }
        }
    }

    bool fExisted = mapWallet.count(COutPoint(ptx->GetIdem())) != 0;
    if (fExisted && !fUpdate)
        return false;
    if (fExisted || IsMine(*ptx) || IsFromMe(*ptx))
    {
        CWalletTxRef wtx = std::make_shared<CWalletTx>(this, *ptx);

        // Get merkle branch if transaction was found in a block
        if (pblock)
            wtx->SetMerkleBranch(*pblock, txIndex);

        // Do not flush the wallet here for performance reasons
        // this is safe, as in case of a crash, we rescan the necessary blocks on startup through our
        // SetBestChain-mechanism
        CWalletDB walletdb(strWalletFile, "r+", false);

        return AddToWallet(wtx, false, &walletdb);
    }
    return false;
}

bool CWallet::AbandonTransaction(const uint256 &hashTx)
{
    LOCK(cs_wallet);

    // Do not flush the wallet here for performance reasons
    CWalletDB walletdb(strWalletFile, "r+", false);

    std::set<uint256> todo;
    std::set<uint256> done;

    // Can't mark abandoned if confirmed
    CWalletTxRef origtx = GetWalletTx(hashTx);
    if (!origtx)
        return false; // Not a wallet tx
    if (origtx->GetDepthInMainChain() > 0)
    {
        return false;
    }

    // Remove this tx from the txpool before it is abandoned by the wallet.
    // But there is no guarantee that other nodes don't still hold this transaction, so it could still be committed
    mempool.Remove(origtx->GetId());

    todo.insert(hashTx);

    while (!todo.empty())
    {
        uint256 now = *todo.begin();
        todo.erase(now);
        done.insert(now);
        CWalletTxRef wtx = GetWalletTx(now);

        assert(wtx);
        int currentconfirm = wtx->GetDepthInMainChain();
        // If the orig tx was not in block, none of its spends can be
        assert(currentconfirm <= 0);
        // if (currentconfirm < 0) {Tx and spends are already conflicted, no need to abandon}
        if (currentconfirm == 0 && !wtx->isAbandoned())
        {
            // If the orig tx was not in block/txpool, none of its spends can be in txpool
            assert(!wtx->InMempool());
            wtx->nIndex = -1;
            wtx->setAbandoned(); // Since all outputs in mapWallet point to the same object this will set all outputs
            wtx->MarkDirty();
            wtx->WriteToDisk(&walletdb);
            NotifyTransactionChanged(this, wtx->GetIdem(), CT_UPDATED);
            // Iterate over all its outputs, and mark transactions in the wallet that spend them abandoned too
            for (size_t i = 0; i < wtx->vout.size(); i++)
            {
                auto range = mapTxSpends.equal_range(wtx->OutpointAt(i));
                while (range.first != range.second)
                {
                    todo.insert(range.first->second);
                    range.first++;
                }
            }
            RemoveFromSpends(wtx);

            // If a transaction changes 'conflicted' state, that changes the balance
            // available of the outputs it spends. So force those to be recomputed
            for (const CTxIn &txin : wtx->vin)
            {
                auto access = mapWallet.find(txin.prevout);
                if (access != mapWallet.end())
                {
                    access->second.tx->MarkDirty();
                    AddToWallet(access->second.tx, false, &walletdb);
                }
            }
        }
    }

    return true;
}

void CWallet::MarkDoubleSpent(const uint256 &txid)
{
    LOCK(cs_wallet);
    CWalletTxRef wtx = GetWalletTx(txid);
    if (wtx)
    {
        wtx->fDoubleSpent = true;
        NotifyTransactionChanged(this, wtx->GetIdem(), CT_UPDATED);
    }
}

void CWallet::MarkConflicted(const uint256 &hashBlock, const uint256 &hashTx)
{
    LOCK(cs_wallet);

    int conflictconfirms = 0;
    CBlockIndex *pindex = LookupBlockIndex(hashBlock);
    if (pindex)
    {
        if (chainActive.Contains(pindex))
        {
            conflictconfirms = -(chainActive.Height() - pindex->height() + 1);
        }
    }
    // If number of conflict confirms cannot be determined, this means
    // that the block is still unknown or not yet part of the main chain,
    // for example when loading the wallet during a reindex. Do nothing in that
    // case.
    if (conflictconfirms >= 0)
        return;

    // Do not flush the wallet here for performance reasons
    CWalletDB walletdb(strWalletFile, "r+", false);

    std::set<uint256> todo;
    std::set<uint256> done;

    todo.insert(hashTx);

    while (!todo.empty())
    {
        uint256 now = *todo.begin();
        todo.erase(now);
        done.insert(now);
        CWalletTxRef wtx = GetWalletTx(now);
        assert(wtx);
        int currentconfirm = wtx->GetDepthInMainChain();
        if (conflictconfirms < currentconfirm)
        {
            // Block is 'more conflicted' than current confirm; update.
            // Mark transaction as conflicted with this block.
            wtx->nIndex = -1;
            wtx->hashBlock = hashBlock;
            wtx->MarkDirty();
            wtx->WriteToDisk(&walletdb);
            // Iterate over all its outputs, and mark transactions in the wallet that spend them conflicted too
            for (size_t i = 0; i < wtx->vout.size(); i++)
            {
                auto range = mapTxSpends.equal_range(wtx->OutpointAt(i));
                while (range.first != range.second)
                {
                    todo.insert(range.first->second);
                    range.first++;
                }
            }

            // If a transaction changes 'conflicted' state, that changes the balance
            // available of the outputs it spends. So force those to be recomputed
            for (const CTxIn &txin : wtx->vin)
            {
                auto prev = mapWallet.find(txin.prevout);
                if (prev != mapWallet.end())
                {
                    prev->second.tx->MarkDirty();
                    AddToWallet(prev->second.tx, false, &walletdb);
                }
            }
        }
    }
}

void CWallet::SyncTransaction(const CTransactionRef &ptx, const ConstCBlockRef pblock, int txIdx)
{
    LOCK(cs_wallet);

    if (!AddToWalletIfInvolvingMe(ptx, pblock, true, txIdx))
        return; // Not one of ours

    // If a transaction changes 'conflicted' state, that changes the balance
    // available of the outputs it spends. So force those to be
    // recomputed, also:
    for (const CTxIn &txin : ptx->vin)
    {
        auto prev = mapWallet.find(txin.prevout);
        if (prev != mapWallet.end())
            prev->second.tx->MarkDirty();
    }
}

CAmount CWallet::GetDebit(const CTxIn &txin, const isminefilter &filter) const
{
    LOCK(cs_wallet);
    MapWallet::const_iterator mi = mapWallet.find(txin.prevout);
    if (mi != mapWallet.end())
    {
        const CWalletTxRef prev = (*mi).second.tx;
        assert(prev);
        const int n = (*mi).second.i;
        if (n < (int)prev->vout.size())
            if (IsMine(prev->vout[n]) & filter)
                return prev->vout[n].nValue;
    }
    return 0;
}

isminetype CWallet::IsMine(const CTxDestination &dest) const { return ::IsMine(*this, dest, chainActive.Tip()); }
isminetype CWallet::IsMine(const CTxOut &txout) const { return ::IsMine(*this, txout.scriptPubKey, chainActive.Tip()); }
isminetype CWallet::IsMine(const CTxIn &txin) const
{
    LOCK(cs_wallet);
    MapWallet::const_iterator mi = mapWallet.find(txin.prevout);
    if (mi != mapWallet.end())
    {
        const COutput &prevout = mi->second;
        const CWalletTxRef prevtx = prevout.tx;
        assert(prevtx);
        DbgAssert(prevout.i >= 0, return ISMINE_NO); // Found the tx not an outpoint
        DbgAssert(prevout.i < (int)prevtx->vout.size(), return ISMINE_NO);
        if ((prevout.i < (int)prevtx->vout.size()) && (prevout.i >= 0))
            return IsMine(prevtx->vout[prevout.i]);
    }
    return ISMINE_NO;
}

bool CWallet::IsMine(const CTransaction &tx) const
{
    for (const CTxOut &txout : tx.vout)
    {
        if (IsMine(txout) != ISMINE_NO)
            return true;
    }
    return false;
}

CAmount CWallet::GetCredit(const CTxOut &txout, const isminefilter &filter) const
{
    if (txout.nValue == 0)
        return 0; // quickly handle data txouts
    if (!MoneyRange(txout.nValue))
        throw std::runtime_error("CWallet::GetCredit(): value out of range");
    return ((IsMine(txout) & filter) ? txout.nValue : 0);
}

bool CWallet::IsChange(const CTxOut &txout) const
{
    // TODO: fix handling of 'change' outputs. The assumption is that any
    // payment to a script that is ours, but is not in the address book
    // is change. That assumption is likely to break when we implement multisignature
    // wallets that return change back into a multi-signature-protected address;
    // a better way of identifying which outputs are 'the send' and which are
    // 'the change' will need to be implemented (maybe extend CWalletTx to remember
    // which output, if any, was change).
    if (::IsMine(*this, txout.scriptPubKey, chainActive.Tip()))
    {
        CTxDestination address;
        if (!ExtractDestination(txout.scriptPubKey, address))
            return true;

        LOCK(cs_wallet);
        if (!mapAddressBook.count(address))
            return true;
    }
    return false;
}

CAmount CWallet::GetChange(const CTxOut &txout) const
{
    if (!MoneyRange(txout.nValue))
        throw std::runtime_error("CWallet::GetChange(): value out of range");
    return (IsChange(txout) ? txout.nValue : 0);
}

bool CWallet::IsFromMe(const CTransaction &tx) const { return (GetDebit(tx, ISMINE_ALL) > 0); }
CAmount CWallet::GetDebit(const CTransaction &tx, const isminefilter &filter) const
{
    CAmount nDebit = 0;
    for (const CTxIn &txin : tx.vin)
    {
        nDebit += GetDebit(txin, filter);
        if (!MoneyRange(nDebit))
            throw std::runtime_error("CWallet::GetDebit(): value out of range");
    }
    return nDebit;
}

CAmount CWallet::GetCredit(const CTransaction &tx, const isminefilter &filter) const
{
    CAmount nCredit = 0;
    for (const CTxOut &txout : tx.vout)
    {
        nCredit += GetCredit(txout, filter);
        if (!MoneyRange(nCredit))
            throw std::runtime_error("CWallet::GetCredit(): value out of range");
    }
    return nCredit;
}

CAmount CWallet::GetChange(const CTransaction &tx) const
{
    CAmount nChange = 0;
    for (const CTxOut &txout : tx.vout)
    {
        nChange += GetChange(txout);
        if (!MoneyRange(nChange))
            throw std::runtime_error("CWallet::GetChange(): value out of range");
    }
    return nChange;
}

CPubKey CWallet::GenerateNewHDMasterKey()
{
    CKey key;
    key.MakeNewKey(true);

    int64_t nCreationTime = GetTime();
    CKeyMetadata metadata(nCreationTime);

    // calculate the pubkey
    CPubKey pubkey = key.GetPubKey();
    assert(key.VerifyPubKey(pubkey));

    // set the hd keypath to "m" -> Master, refers the masterkeyid to itself
    metadata.hdKeypath = "m";
    metadata.hdMasterKeyID = pubkey.GetID();

    {
        LOCK(cs_wallet);

        // mem store the metadata
        mapKeyMetadata[pubkey.GetID()] = metadata;

        // write the key&metadata to the database
        if (!AddKeyPubKey(key, pubkey))
            throw std::runtime_error("CWallet::GenerateNewKey(): AddKey failed");
    }

    return pubkey;
}

bool CWallet::SetHDMasterKey(const CPubKey &pubkey)
{
    LOCK(cs_wallet);

    // ensure this wallet.dat can only be opened by clients supporting HD
    SetMinVersion(FEATURE_HD);

    // store the keyid (hash160) together with
    // the child index counter in the database
    // as a hdchain object
    CHDChain newHdChain;
    newHdChain.masterKeyID = pubkey.GetID();
    SetHDChain(newHdChain, false);

    return true;
}

bool CWallet::SetHDChain(const CHDChain &chain, bool memonly)
{
    LOCK(cs_wallet);
    if (!memonly && !CWalletDB(strWalletFile).WriteHDChain(chain))
        throw runtime_error("AddHDChain(): writing chain failed");

    hdChain = chain;
    return true;
}

bool CWallet::IsHDEnabled() { return !hdChain.masterKeyID.IsNull(); }
int64_t CWalletTx::GetTxTime() const
{
    int64_t n = nTimeSmart;
    return n ? n : nTimeReceived;
}

int CWalletTx::GetRequestCount() const
{
    // Returns -1 if it wasn't being tracked
    int nRequests = -1;
    {
        LOCK(pwallet->cs_wallet);
        if (IsCoinBase())
        {
            // Generated block
            if (!hashUnset())
            {
                map<uint256, int>::const_iterator mi = pwallet->mapRequestCount.find(hashBlock);
                if (mi != pwallet->mapRequestCount.end())
                    nRequests = (*mi).second;
            }
        }
        else
        {
            // Did anyone request this transaction?
            map<uint256, int>::const_iterator mi = pwallet->mapRequestCount.find(GetId());
            if (mi != pwallet->mapRequestCount.end())
            {
                nRequests = (*mi).second;

                // How about the block it's in?
                if (nRequests == 0 && !hashUnset())
                {
                    map<uint256, int>::const_iterator mi2 = pwallet->mapRequestCount.find(hashBlock);
                    if (mi2 != pwallet->mapRequestCount.end())
                        nRequests = (*mi2).second;
                    else
                        nRequests = 1; // If it's in someone else's block it must have got out
                }
            }
        }
    }
    return nRequests;
}

void CWalletTx::GetAmounts(list<COutputEntry> &listReceived,
    list<COutputEntry> &listSent,
    CAmount &nFee,
    string &strSentAccount,
    const isminefilter &filter) const
{
    nFee = 0;
    listReceived.clear();
    listSent.clear();
    strSentAccount = strFromAccount;

    // Compute fee:
    CAmount nDebit = GetDebit(filter);
    if (nDebit > 0) // debit>0 means we signed/sent this transaction
    {
        CAmount nValueOut = GetValueOut();
        nFee = nDebit - nValueOut;
    }

    // Sent/received.
    for (unsigned int i = 0; i < vout.size(); ++i)
    {
        const CTxOut &txout = vout[i];
        isminetype fIsMine = pwallet->IsMine(txout);
        // Only need to handle txouts if AT LEAST one of these is true:
        //   1) they debit from us (sent)
        //   2) the output is to us (received)
        if (nDebit > 0)
        {
            // Don't report 'change' txouts
            if (pwallet->IsChange(txout))
                continue;
        }
        else if (!(fIsMine & filter))
            continue;

        // In either case, we need to get the destination address
        CTxDestination address;
        txnouttype whichType;
        if (!ExtractDestinationAndType(txout.scriptPubKey, address, whichType) && !txout.scriptPubKey.IsUnspendable())
        {
            LOGA("CWalletTx::GetAmounts: Unknown transaction type found, txid %s\n", this->GetId().ToString());
            address = CNoDestination();
        }

        // Do not return group outputs from this API
        if ((whichType != TX_GRP_PUBKEYHASH) && (whichType != TX_GRP_SCRIPTHASH))
        {
            COutputEntry output = {address, txout.nValue, (int)i};

            // If we are debited by the transaction, add the output as a "sent" entry
            if (nDebit > 0)
                listSent.push_back(output);

            // If we are receiving the output, add it as a "received" entry
            if (fIsMine & filter)
                listReceived.push_back(output);
        }
    }
}

void CWalletTx::GetGroupAmounts(const CGroupTokenID &grp,
    list<COutputEntry> &listReceived,
    list<COutputEntry> &listSent,
    CAmount &nFee,
    string &strSentAccount,
    const isminefilter &filter) const
{
    nFee = 0;
    listReceived.clear();
    listSent.clear();
    strSentAccount = strFromAccount;

    // Compute fee:
    CAmount nDebit = GetDebit(filter);
    if (nDebit > 0) // debit>0 means we signed/sent this transaction
    {
        CAmount nValueOut = GetValueOut();
        nFee = nDebit - nValueOut;
    }

    // Sent/received.
    for (unsigned int i = 0; i < vout.size(); ++i)
    {
        const CTxOut &txout = vout[i];
        isminetype fIsMine = pwallet->IsMine(txout);
        // Only need to handle txouts if AT LEAST one of these is true:
        //   1) they debit from us (sent)
        //   2) the output is to us (received)
        if (nDebit > 0)
        {
            // Don't report 'change' txouts
            if (pwallet->IsChange(txout))
                continue;
        }
        else if (!(fIsMine & filter))
            continue;

        // In either case, we need to get the destination address
        CTxDestination address;
        txnouttype whichType;
        if (!ExtractDestinationAndType(txout.scriptPubKey, address, whichType) && !txout.scriptPubKey.IsUnspendable())
        {
            LOGA("CWalletTx::GetAmounts: Unknown transaction type found, txid %s\n", this->GetId().ToString());
            address = CNoDestination();
        }

        // Only return group outputs from this API
        if ((whichType == TX_GRP_PUBKEYHASH) || (whichType == TX_GRP_SCRIPTHASH))
        {
            CGroupTokenInfo txgrp(txout.scriptPubKey);
            if (grp == txgrp.associatedGroup)
            {
                COutputEntry output = {address, txgrp.quantity, (int)i};

                // If we are debited by the transaction, add the output as a "sent" entry
                if (nDebit > 0)
                    listSent.push_back(output);

                // If we are receiving the output, add it as a "received" entry
                if (fIsMine & filter)
                    listReceived.push_back(output);
            }
        }
    }
}

void CWalletTx::GetAmounts(list<CGroupedOutputEntry> &listReceived,
    list<CGroupedOutputEntry> &listSent,
    CAmount &nFee,
    string &strSentAccount,
    const isminefilter &filter) const
{
    nFee = 0;
    listReceived.clear();
    listSent.clear();
    strSentAccount = strFromAccount;

    // Compute fee:
    CAmount nDebit = GetDebit(filter);
    if (nDebit > 0) // debit>0 means we signed/sent this transaction
    {
        CAmount nValueOut = GetValueOut();
        nFee = nDebit - nValueOut;
    }

    // Sent/received.
    for (unsigned int i = 0; i < vout.size(); ++i)
    {
        const CTxOut &txout = vout[i];
        isminetype fIsMine = pwallet->IsMine(txout);
        // Only need to handle txouts if AT LEAST one of these is true:
        //   1) they debit from us (sent)
        //   2) the output is to us (received)
        if (nDebit > 0)
        {
            // Don't report 'change' txouts
            if (pwallet->IsChange(txout))
                continue;
        }
        else if (!(fIsMine & filter))
            continue;

        // In either case, we need to get the destination address
        CTxDestination address;
        txnouttype whichType;
        if (!ExtractDestinationAndType(txout.scriptPubKey, address, whichType) && !txout.scriptPubKey.IsUnspendable())
        {
            LOGA("CWalletTx::GetAmounts: Unknown transaction type found, txid %s\n", this->GetId().ToString());
            address = CNoDestination();
        }

        CGroupTokenInfo txgrp(txout.scriptPubKey); // If group is invalid, txgrp zeros its members.
        CGroupedOutputEntry output(txgrp.associatedGroup, txgrp.quantity, address, txout.nValue, (int)i);
        // If we are debited by the transaction, add the output as a "sent" entry
        if (nDebit > 0)
            listSent.push_back(output);

        // If we are receiving the output, add it as a "received" entry
        if (fIsMine & filter)
            listReceived.push_back(output);
    }
}


void CWalletTx::GetAccountAmounts(const string &strAccount,
    CAmount &nReceived,
    CAmount &nSent,
    CAmount &nFee,
    const isminefilter &filter) const
{
    nReceived = nSent = nFee = 0;

    CAmount allFee;
    string strSentAccount;
    list<COutputEntry> listReceived;
    list<COutputEntry> listSent;
    GetAmounts(listReceived, listSent, allFee, strSentAccount, filter);

    if (strAccount == strSentAccount)
    {
        for (const COutputEntry &s : listSent)
        {
            nSent += s.amount;
        }
        nFee = allFee;
    }
    {
        LOCK(pwallet->cs_wallet);
        for (const COutputEntry &r : listReceived)
        {
            if (pwallet->mapAddressBook.count(r.destination))
            {
                map<CTxDestination, CAddressBookData>::const_iterator mi = pwallet->mapAddressBook.find(r.destination);
                if (mi != pwallet->mapAddressBook.end() && (*mi).second.name == strAccount)
                    nReceived += r.amount;
            }
            else if (strAccount.empty())
            {
                nReceived += r.amount;
            }
        }
    }
}


bool CWalletTx::WriteToDisk(CWalletDB *pwalletdb) { return pwalletdb->WriteTx(*this); }
/**
 * Scan the block chain (starting in pindexStart) for transactions
 * from or to us. If fUpdate is true, found transactions that already
 * exist in the wallet will be updated.
 */
int CWallet::ScanForWalletTransactions(CBlockIndex *pindexStart, bool fUpdate)
{
    // Begin rescan by setting fRescan to true.  This prevents any new inbound network connections
    // from being initiated and thus prevents us from banning repeated and failed network connection
    // attempts while the rescan is in progress.  Once the flag is set then it is safe to disconnect
    // any current connections. Note: we don't disconnect nodes in regtest as this prevents the tests
    // from passing since the nodes will not auto-reconnect after a wallet scan has completed.
    fRescan = true;
    if (Params().NetworkIDString() != "regtest")
    {
        LOCK(cs_vNodes);
        for (CNode *pnode : vNodes)
        {
            LOGA("Disconnecting peer: %s before wallet rescan\n", pnode->GetLogName());
            pnode->fDisconnect = true;
        }
    }

    int ret = 0;
    int64_t nNow = GetTime();

    CBlockIndex *pindex = pindexStart;
    {
        LOCK(cs_wallet);

        // no need to read and scan block, if block was created before
        // our wallet birthday (as adjusted for block time variability)
        while (pindex && nTimeFirstKey && (pindex->GetBlockTime() < (nTimeFirstKey - 7200)))
            pindex = chainActive.Next(pindex);

        // If pindex is zero here, the wallet's first time key must be at least 7200 seconds in the future,
        // since pindex advanced to the end of the chain.  So this is generally an impossible situation.
        // 7200 was chosen because blocks can misreport their time by no more than 2 hours.
        if (pindex == nullptr)
        {
            fRescan = false;
            return 0;
        }

        // show rescan progress in GUI as dialog or on splashscreen, if -rescan on startup
        ShowProgress(_("Rescanning..."), 0);
        double dProgressStart = Checkpoints::GuessVerificationProgress(pindex, false);
        double dProgressTip = Checkpoints::GuessVerificationProgress(chainActive.Tip(), false);
        while (pindex)
        {
            if (pindex->height() % 100 == 0 && dProgressTip - dProgressStart > 0.0)
                ShowProgress(_("Rescanning..."),
                    std::max(
                        1, std::min(99, (int)((Checkpoints::GuessVerificationProgress(pindex, false) - dProgressStart) /
                                              (dProgressTip - dProgressStart) * 100))));

            const ConstCBlockRef pblock = ReadBlockFromDisk(pindex, Params().GetConsensus());
            if (!pblock)
            {
                LOGA("ERROR: Could not read block from disk\n");
                fRescan = false;
                return 0;
            }
            int txIdx = 0;
            for (const auto &ptx : pblock->vtx)
            {
                if (AddToWalletIfInvolvingMe(ptx, pblock, fUpdate, txIdx))
                    ret++;
                txIdx++;
            }
            pindex = chainActive.Next(pindex);
            if (GetTime() >= nNow + 60)
            {
                nNow = GetTime();
                if (pindex) // if pindex is nullptr we are done anyway so no need to show the log
                    LOGA("Still rescanning. At block %d. Progress=%f\n", pindex->height(),
                        Checkpoints::GuessVerificationProgress(pindex, false));
            }
        }
        ShowProgress(_("Rescanning..."), 100); // hide progress dialog in GUI
    }
    // Rescan is now finished. Set to false to allow network connections to resume.
    fRescan = false;

    return ret;
}

void CWallet::ReacceptWalletTransactions()
{
    // If transactions aren't being broadcasted, don't let them into local txpool either
    if (!fBroadcastTransactions)
        return;
    std::map<int64_t, CTransactionRef> mapSorted;

    {
        LOCK(cs_wallet);

        // Sort pending wallet transactions based on their initial wallet insertion order
        for (MapWallet::value_type &item : mapWallet)
        {
            const uint256 &wtxid = item.first.hash;
            CWalletTxRef wtx = item.second.tx;

            if (wtx->GetId() == wtxid) // Only grab tx records, not outpoints
            {
                int nDepth = wtx->GetDepthInMainChain();

                if (!wtx->IsCoinBase() && (nDepth == 0 && !wtx->isAbandoned()))
                {
                    mapSorted.insert(std::make_pair(wtx->nOrderPos, std::static_pointer_cast<const CTransaction>(wtx)));
                }
            }
        }
    }

    // Try to add wallet transactions to memory pool
    for (std::pair<const int64_t, CTransactionRef> &item : mapSorted)
    {
        CValidationState state;
        AcceptToMemoryPool(mempool, state, item.second, AreFreeTxnsAllowed(), nullptr, true, TransactionClass::DEFAULT);
        SyncWithWallets(item.second, nullptr, -1);
    }
    CommitTxToMempool();
}

bool CWalletTx::RelayWalletTransaction()
{
    assert(pwallet->GetBroadcastTransactions());
    if (!IsCoinBase())
    {
        if (GetDepthInMainChain() == 0 && !isAbandoned() && InMempool())
        {
            // LOGA("Relaying wtx %s\n", GetHash().ToString());
            RelayTransaction(MakeTransactionRef((CTransaction) * this));
            return true;
        }
    }
    return false;
}

set<uint256> CWalletTx::GetConflicts() const
{
    set<uint256> result;
    if (pwallet != nullptr)
    {
        uint256 myId = GetId();
        result = pwallet->GetConflicts(myId);
        result.erase(myId);
    }
    return result;
}

CAmount CWalletTx::GetDebit(const isminefilter &filter) const
{
    if (vin.empty())
        return 0;

    CAmount debit = 0;
    if (filter & ISMINE_SPENDABLE)
    {
        if (fDebitCached)
            debit += nDebitCached;
        else
        {
            nDebitCached = pwallet->GetDebit(*this, ISMINE_SPENDABLE);
            fDebitCached = true;
            debit += nDebitCached;
        }
    }
    if (filter & ISMINE_WATCH_ONLY)
    {
        if (fWatchDebitCached)
            debit += nWatchDebitCached;
        else
        {
            nWatchDebitCached = pwallet->GetDebit(*this, ISMINE_WATCH_ONLY);
            fWatchDebitCached = true;
            debit += nWatchDebitCached;
        }
    }
    return debit;
}

CAmount CWalletTx::GetCredit(const isminefilter &filter) const
{
    // Must wait until coinbase is safely deep enough in the chain before valuing it
    if (IsCoinBase() && GetBlocksToMaturity() > 0)
        return 0;

    int64_t credit = 0;
    if (filter & ISMINE_SPENDABLE)
    {
        // GetBalance can assume transactions in mapWallet won't change
        if (fCreditCached)
            credit += nCreditCached;
        else
        {
            nCreditCached = pwallet->GetCredit(*this, ISMINE_SPENDABLE);
            fCreditCached = true;
            credit += nCreditCached;
        }
    }
    if (filter & ISMINE_WATCH_ONLY)
    {
        if (fWatchCreditCached)
            credit += nWatchCreditCached;
        else
        {
            nWatchCreditCached = pwallet->GetCredit(*this, ISMINE_WATCH_ONLY);
            fWatchCreditCached = true;
            credit += nWatchCreditCached;
        }
    }
    return credit;
}

CAmount CWalletTx::GetImmatureCredit(bool fUseCache) const
{
    if (IsCoinBase() && GetBlocksToMaturity() > 0 && IsInMainChain())
    {
        if (fUseCache && fImmatureCreditCached)
            return nImmatureCreditCached;
        nImmatureCreditCached = pwallet->GetCredit(*this, ISMINE_SPENDABLE);
        fImmatureCreditCached = true;
        return nImmatureCreditCached;
    }

    return 0;
}

CAmount CWalletTx::GetAvailableCredit(bool fUseCache) const
{
    if (pwallet == nullptr)
    {
        // LOGA("%s: pwallet == nullptr", GetId().GetHex());
        return 0;
    }

    // Must wait until coinbase is safely deep enough in the chain before valuing it
    if (IsCoinBase() && GetBlocksToMaturity() > 0)
    {
        // LOGA("%s: immature", GetId().GetHex());
        return 0;
    }

    if (fUseCache && fAvailableCreditCached)
        return nAvailableCreditCached;

    CAmount nCredit = 0;
    uint256 txidem = GetIdem();
    for (unsigned int i = 0; i < vout.size(); i++)
    {
        const CTxOut &txout = vout[i];
        if (!pwallet->IsSpent(COutPoint(txidem, i)) && (GetGroupToken(vout[i].scriptPubKey) == NoGroup))
        {
            auto amt = pwallet->GetCredit(txout, ISMINE_SPENDABLE);
            nCredit += amt;
            if (!MoneyRange(nCredit))
                throw std::runtime_error("CWalletTx::GetAvailableCredit(false) : value out of range");
        }
    }

    nAvailableCreditCached = nCredit;
    fAvailableCreditCached = true;
    return nCredit;
}

CAmount CWalletTx::GetImmatureWatchOnlyCredit(const bool &fUseCache) const
{
    if (IsCoinBase() && GetBlocksToMaturity() > 0 && IsInMainChain())
    {
        if (fUseCache && fImmatureWatchCreditCached)
            return nImmatureWatchCreditCached;
        nImmatureWatchCreditCached = pwallet->GetCredit(*this, ISMINE_WATCH_ONLY);
        fImmatureWatchCreditCached = true;
        return nImmatureWatchCreditCached;
    }

    return 0;
}

CAmount CWalletTx::GetAvailableWatchOnlyCredit(const bool &fUseCache) const
{
    if (pwallet == nullptr)
        return 0;

    // Must wait until coinbase is safely deep enough in the chain before valuing it
    if (IsCoinBase() && GetBlocksToMaturity() > 0)
        return 0;

    if (fUseCache && fAvailableWatchCreditCached)
        return nAvailableWatchCreditCached;

    CAmount nCredit = 0;
    uint256 txidem = GetIdem();
    for (unsigned int i = 0; i < vout.size(); i++)
    {
        if (!pwallet->IsSpent(COutPoint(txidem, i)) && (GetGroupToken(vout[i].scriptPubKey) == NoGroup))
        {
            const CTxOut &txout = vout[i];
            nCredit += pwallet->GetCredit(txout, ISMINE_WATCH_ONLY);
            if (!MoneyRange(nCredit))
                throw std::runtime_error("CWalletTx::GetAvailableCredit(false) : value out of range");
        }
    }

    nAvailableWatchCreditCached = nCredit;
    fAvailableWatchCreditCached = true;
    return nCredit;
}

CAmount CWalletTx::GetChange() const
{
    if (fChangeCached)
        return nChangeCached;
    nChangeCached = pwallet->GetChange(*this);
    fChangeCached = true;
    return nChangeCached;
}

bool CWalletTx::InMempool() const
{
    if (mempool.exists(GetId()))
    {
        return true;
    }
    return false;
}

bool CWalletTx::IsTrusted() const
{
    // Quick answer in most cases
    if (!CheckFinalTx(MakeTransactionRef(*this)))
        return false;
    int nDepth = GetDepthInMainChain();
    if (nDepth < 0)
        return false;

    // Check depth depending on whether instant transactions are turned on or not.
    // If instant transactions are turned on then all unconfirmed transactions will
    // show in the wallet as available to be spent.
    bool fInstantTransactions = instantTxns.Value();
    if (nDepth >= 1)
    {
        return true;
    }
    else if (!fInstantTransactions)
    {
        if (!bSpendZeroConfChange || !IsFromMe(ISMINE_ALL)) // using wtx's cached debit
            return false;

        // Don't trust unconfirmed transactions from us unless they are in the txpool.
        if (!InMempool())
            return false;

        // Trusted if all inputs are from us and are in the txpool:
        for (const CTxIn &txin : vin)
        {
            // Transactions not sent by us: not trusted
            const COutput parent = pwallet->GetWalletCoin(txin.prevout);
            if (parent.isNull())
                return false;
            assert(parent.i >= 0); // Should have accessed a coin, not the tx
            const CTxOut &parentOut = parent.tx->vout[parent.i];
            if (pwallet->IsMine(parentOut) != ISMINE_SPENDABLE)
                return false;
        }
    }
    else // Instant Transactions
    {
        // If we are doing instant transactions we have to check for double spends.  If this
        // transaction is double spent then we mark it as a pending transaction in the wallet (This is
        // the only instance a transaction will be shown as pending when using instant transactions).
        if (fDoubleSpent)
            return false;

        // If we are doing instant transactions then the tx must be in the txpool. Also, the tx must
        // not be in the orphanpool, but if it's in the txpool then by default we know it is not in the orphanpool.
        if (!InMempool())
            return false;

        // Time delay for when an instant transaction can be spendable. Default is a few seconds
        // but can be modified by the tweak.  If the transaction is from ourselves or is some change
        // then no delay is necessary.
        if (((GetTime() - nTimeReceived) < instantTxnsDelay.Value()) && (!IsFromMe(ISMINE_ALL)))
        {
            return false;
        }
    }

    return true;
}

std::vector<uint256> CWallet::ResendWalletTransactionsBefore(int64_t nTime)
{
    std::vector<uint256> result;

    multimap<unsigned int, CWalletTxRef> mapSorted;
    {
        LOCK(cs_wallet);
        // Sort them in chronological order
        for (MapWallet::value_type &item : mapWallet)
        {
            const CWalletTxRef wtx = item.second.tx;
            assert(wtx);
            // Don't rebroadcast if newer than nTime:
            if (wtx->nTimeReceived > nTime)
                continue;
            if (item.first.hash == wtx->GetId()) // If its the tx record
            {
                mapSorted.insert(make_pair(wtx->nTimeReceived, wtx));
            }
        }
    }
    for (PAIRTYPE(const unsigned int, CWalletTxRef) & item : mapSorted)
    {
        CWalletTxRef &wtx = item.second;
        if (wtx->RelayWalletTransaction())
            result.push_back(wtx->GetIdem());
    }
    return result;
}

void CWallet::ResendWalletTransactions(int64_t nBestBlockTime)
{
    // Do this infrequently and randomly to avoid giving away
    // that these are our transactions.
    if (GetTime() < nNextResend || !fBroadcastTransactions)
        return;
    bool fFirst = (nNextResend == 0);
    nNextResend = GetTime() + GetRand(30 * 60);
    if (fFirst)
        return;

    // Only do it if there's been a new block since last time
    if (nBestBlockTime < nLastResend)
        return;
    nLastResend = GetTime();

    // Rebroadcast unconfirmed txes older than 5 minutes before the last
    // block was found:
    std::vector<uint256> relayed = ResendWalletTransactionsBefore(nBestBlockTime - 5 * 60);
    if (!relayed.empty())
        LOGA("%s: rebroadcast %u unconfirmed transactions\n", __func__, relayed.size());
}

/** @} */ // end of mapWallet


/** @defgroup Actions
 *
 * @{
 */


CAmount CWallet::GetBalance()
{
    CAmount nTotal = 0;
    {
        LOCK(cs_wallet);
        for (MapWallet::const_iterator it = mapWalletUnspent.begin(); it != mapWalletUnspent.end(); ++it)
        {
            const CWalletTxRef ptx = it->second.tx;
            if (ptx->IsCoinBase() && ptx->GetBlocksToMaturity() > 0)
                continue;

            if (ptx->IsTrusted())
            {
                if (!IsSpent(it->first) && (GetGroupToken(it->second.GetScriptPubKey()) == NoGroup))
                {
                    nTotal += GetCredit(it->second.GetTxOut(), ISMINE_SPENDABLE);
                }
            }
        }

#ifdef DEBUG
        // Make sure the new and old method have matching totals
        CAmount nTotal2 = 0;
        for (MapWallet::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTxRef ptx = it->second.tx;
            if (it->first.hash == ptx->GetId()) // If its the tx record
            {
                if (ptx->IsTrusted())
                {
                    CAmount tmp = ptx->GetAvailableCredit(false);
                    nTotal2 += tmp;
                }
            }
        }
        assert(nTotal == nTotal2);
#endif
    }

    return nTotal;
}

CAmount CWallet::GetUnconfirmedBalance() const
{
    CAmount nTotal = 0;
    {
        LOCK(cs_wallet);
        for (MapWallet::const_iterator it = mapWalletUnspent.begin(); it != mapWalletUnspent.end(); ++it)
        {
            const CWalletTxRef ptx = it->second.tx;
            if (ptx->IsCoinBase() && ptx->GetBlocksToMaturity() > 0)
                continue;

            if (!ptx->IsTrusted() && ptx->GetDepthInMainChain() == 0 && ptx->InMempool())
            {
                if (!IsSpent(it->first) && (GetGroupToken(it->second.GetScriptPubKey()) == NoGroup))
                {
                    nTotal += GetCredit(it->second.GetTxOut(), ISMINE_SPENDABLE);
                }
            }
        }

#ifdef DEBUG
        // Make sure the new and old method have matching totals
        CAmount nTotal2 = 0;
        for (MapWallet::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTxRef ptx = it->second.tx;
            if (it->first.hash == ptx->GetId()) // If its the tx record
            {
                if (!ptx->IsTrusted() && ptx->GetDepthInMainChain() == 0 && ptx->InMempool())
                {
                    CAmount tmp = ptx->GetAvailableCredit(false);
                    nTotal2 += tmp;
                }
            }
        }
        assert(nTotal == nTotal2);
#endif
    }

    return nTotal;
}

CAmount CWallet::GetImmatureBalance() const
{
    CAmount nTotal = 0;
    {
        LOCK(cs_wallet);
        for (MapWallet::const_iterator it = mapWalletUnspent.begin(); it != mapWalletUnspent.end(); ++it)
        {
            const CWalletTxRef ptx = it->second.tx;
            if (ptx->IsCoinBase() && ptx->GetBlocksToMaturity() > 0 && ptx->IsInMainChain())
            {
                nTotal += GetCredit(it->second.GetTxOut(), ISMINE_SPENDABLE);
            }
        }

#ifdef DEBUG
        // Make sure the new and old method have matching totals
        CAmount nTotal2 = 0;
        for (MapWallet::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTxRef ptx = it->second.tx;
            if (it->first.hash == ptx->GetId()) // If its the tx record
            {
                nTotal2 += ptx->GetImmatureCredit(false);
            }
        }
        assert(nTotal == nTotal2);
#endif
    }

    return nTotal;
}

CAmount CWallet::GetWatchOnlyBalance() const
{
    if (!HaveWatchOnly())
        return 0;

    CAmount nTotal = 0;
    {
        LOCK(cs_wallet);
        for (MapWallet::const_iterator it = mapWalletUnspent.begin(); it != mapWalletUnspent.end(); ++it)
        {
            const CWalletTxRef ptx = it->second.tx;
            if (ptx->IsCoinBase() && ptx->GetBlocksToMaturity() > 0)
                continue;

            if (ptx->IsTrusted())
            {
                if (!IsSpent(it->first) && (GetGroupToken(it->second.GetScriptPubKey()) == NoGroup))
                {
                    nTotal += GetCredit(it->second.GetTxOut(), ISMINE_WATCH_ONLY);
                }
            }
        }

#ifdef DEBUG
        // Make sure the new and old method have matching totals
        CAmount nTotal2 = 0;
        for (MapWallet::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTxRef ptx = it->second.tx;
            if (it->first.hash == ptx->GetId()) // If its the tx record
            {
                if (ptx->IsTrusted())
                    nTotal2 += ptx->GetAvailableWatchOnlyCredit(false);
            }
        }
        assert(nTotal == nTotal2);
#endif
    }

    return nTotal;
}

CAmount CWallet::GetUnconfirmedWatchOnlyBalance() const
{
    if (!HaveWatchOnly())
        return 0;

    CAmount nTotal = 0;
    {
        LOCK(cs_wallet);
        for (MapWallet::const_iterator it = mapWalletUnspent.begin(); it != mapWalletUnspent.end(); ++it)
        {
            const CWalletTxRef ptx = it->second.tx;
            if (ptx->IsCoinBase() && ptx->GetBlocksToMaturity() > 0)
                continue;

            if (!ptx->IsTrusted() && ptx->GetDepthInMainChain() == 0 && ptx->InMempool())
            {
                if (!IsSpent(it->first) && (GetGroupToken(it->second.GetScriptPubKey()) == NoGroup))
                {
                    nTotal += GetCredit(it->second.GetTxOut(), ISMINE_WATCH_ONLY);
                }
            }
        }

#ifdef DEBUG
        // Make sure the new and old method have matching totals
        CAmount nTotal2 = 0;
        for (MapWallet::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTxRef ptx = it->second.tx;
            if (it->first.hash == ptx->GetId()) // If its the tx record
            {
                if (!ptx->IsTrusted() && ptx->GetDepthInMainChain() == 0 && ptx->InMempool())
                    nTotal2 += ptx->GetAvailableWatchOnlyCredit(false);
            }
        }
        assert(nTotal == nTotal2);
#endif
    }

    return nTotal;
}

CAmount CWallet::GetImmatureWatchOnlyBalance() const
{
    if (!HaveWatchOnly())
        return 0;

    CAmount nTotal = 0;
    {
        LOCK(cs_wallet);
        for (MapWallet::const_iterator it = mapWalletUnspent.begin(); it != mapWalletUnspent.end(); ++it)
        {
            const CWalletTxRef ptx = it->second.tx;
            if (ptx->IsCoinBase() && ptx->GetBlocksToMaturity() > 0 && ptx->IsInMainChain())
            {
                nTotal += GetCredit(it->second.GetTxOut(), ISMINE_WATCH_ONLY);
            }
        }

#ifdef DEBUG
        // Make sure the new and old method have matching totals
        CAmount nTotal2 = 0;
        for (MapWallet::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTxRef ptx = it->second.tx;
            if (it->first.hash == ptx->GetId()) // If its the tx record
            {
                nTotal2 += ptx->GetImmatureWatchOnlyCredit(false);
            }
        }
        assert(nTotal == nTotal2);
#endif
    }

    return nTotal;
}

unsigned int CWallet::FilterCoins(vector<COutput> &vCoins, std::function<bool(const COutput &)> func) const
{
    vCoins.clear();
    unsigned int ret = 0;

    {
        LOCK(cs_wallet);
        for (MapWallet::const_iterator it = mapWalletUnspent.begin(); it != mapWalletUnspent.end(); ++it)
        {
            const COutPoint &outpoint = it->first;
            const COutput &pcoin = it->second;
            auto wtx = pcoin.tx;
            assert(wtx);

            if (pcoin.txOnly())
                continue; // Only look for output coins.

            if (!CheckFinalTx(std::static_pointer_cast<const CTransaction>(wtx)))
                continue;

            if (wtx->IsCoinBase() && wtx->GetBlocksToMaturity() > 0)
                continue;

            int depth = wtx->GetDepthInMainChain();
            if (depth < 0)
                continue;

            // We should not consider coins which aren't at least in our txpool
            // It's possible for these to be conflicted via ancestors which we may never be able to detect
            if (depth == 0 && !wtx->InMempool())
                continue;

            // only my outputs are stored in mapWallet
            DbgAssert(pcoin.mine != ISMINE_NO, continue);

            if (!(IsSpent(outpoint)) && !IsLockedCoin(outpoint) && func(pcoin))
            {
                // The UTXO is available
                vCoins.push_back(pcoin);
                ret++;
            }
        }
    }
    return ret;
}


void CWallet::RedetermineIfMine()
{
    LOCK(cs_wallet);
    for (MapWallet::iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
    {
        COutput &coin = it->second;
        auto wtx = coin.tx;
        assert(wtx);

        if (coin.txOnly())
            continue; // Only look for output coins.

        DbgAssert(coin.i < (int)wtx->vout.size(), );
        if (!(coin.i < (int)wtx->vout.size()))
            continue;

        isminetype mine = IsMine(wtx->vout[coin.i]);
        if (coin.mine != mine) // Ownership flags changed
        {
            coin.mine = mine;
        }
    }
}

void CWallet::AvailableCoins(SpendableTxos &coins, const CCoinControl *coinControl, bool fIncludeZeroValue)
{
    vector<COutput> sel;
    AvailableCoins(sel, coinControl, false);
    for (const auto &coin : sel)
    {
        coins.insert(SpendableTxos::value_type(coin.GetValue(), coin));
    }
}

void CWallet::AvailableCoins(vector<COutput> &vCoins,
    const CCoinControl *coinControl,
    bool fIncludeZeroValue,
    uint32_t *pNumUtxos)
{
    vCoins.clear();

    {
        uint32_t nCount = 0;
        LOCK(cs_wallet);
        auto it = mapWalletUnspent.begin();
        while (it != mapWalletUnspent.end())
        {
            const COutPoint &outpoint = it->first;
            const COutput &coin = it->second;
            auto wtx = coin.tx;
            assert(wtx);

            // Remove spent coins from the map.
            if (IsSpent(outpoint))
            {
                it = mapWalletUnspent.erase(it);
                continue;
            }
            it++;

            if (coin.txOnly())
                continue; // Only look for output coins.

            if (!wtx)
                continue; // should never happen

            if (!CheckFinalTx(std::static_pointer_cast<const CTransaction>(wtx)))
                continue;

            if (!wtx->IsTrusted())
                continue;

            if (wtx->IsCoinBase() && wtx->GetBlocksToMaturity() > 0)
                continue;

            // Update depth if its changed
            int depth = wtx->GetDepthInMainChain();
            if (depth < 0)
                continue;

            // We should not consider coins which aren't at least in our txpool
            // It's possible for these to be conflicted via ancestors which we may never be able to detect
            if (depth == 0 && !wtx->InMempool())
                continue;

            if (coin.mine == ISMINE_NO)
            {
                DbgAssert(false, ); // No coin that is not mine should be added to the wallet as an outpoint
                continue; // Watch only is added to this list
            }
            if (IsLockedCoin(outpoint))
                continue;
            if ((wtx->vout[coin.i].nValue == 0) && !fIncludeZeroValue)
                continue;
            if (coinControl && !coinControl->fAllowWatchOnly && coin.mine != ISMINE_SPENDABLE)
                continue;
            // Must not be a token otherwise we could end up spending all group
            // authorities and tokens by accident.
            CGroupTokenInfo tg(coin.GetScriptPubKey());
            if (tg.associatedGroup != NoGroup)
                continue;
            if (!coinControl || !coinControl->HasSelected() || coinControl->fAllowOtherInputs ||
                coinControl->IsSelected(outpoint))
            {
                // The UTXO is available
                vCoins.push_back(coin);

                // Break early if requested. This is needed for extremely large wallets.
                nCount++;
                if (pNumUtxos && (nCount > *pNumUtxos))
                    break;
            }
        }
    }
}

static void ApproximateBestSubset(vector<pair<CAmount, COutput> > vValue,
    const CAmount &nTotalLower,
    const CAmount &nTargetValue,
    vector<char> &vfBest,
    CAmount &nBest,
    int iterations = 1000)
{
    vector<char> vfIncluded;

    vfBest.assign(vValue.size(), true);
    nBest = nTotalLower;

    FastRandomContext insecure_rand;

    for (int nRep = 0; nRep < iterations && nBest != nTargetValue; nRep++)
    {
        vfIncluded.assign(vValue.size(), false);
        CAmount nTotal = 0;
        bool fReachedTarget = false;
        for (int nPass = 0; nPass < 2 && !fReachedTarget; nPass++)
        {
            for (unsigned int i = 0; i < vValue.size(); i++)
            {
                // The solver here uses a randomized algorithm,
                // the randomness serves no real security purpose but is just
                // needed to prevent degenerate behavior and it is important
                // that the rng is fast. We do not use a constant random sequence,
                // because there may be some privacy improvement by making
                // the selection random.
                if (nPass == 0 ? insecure_rand.randbool() : !vfIncluded[i])
                {
                    nTotal += vValue[i].first;
                    vfIncluded[i] = true;
                    if (nTotal >= nTargetValue)
                    {
                        fReachedTarget = true;
                        if (nTotal < nBest)
                        {
                            nBest = nTotal;
                            vfBest = vfIncluded;
                        }
                        nTotal -= vValue[i].first;
                        vfIncluded[i] = false;
                    }
                }
            }
        }
    }

    // Reduces the approximate best subset by removing any inputs that are smaller than the surplus of nTotal beyond
    // nTargetValue.
    for (unsigned int i = 0; i < vValue.size(); i++)
    {
        if (vfBest[i] && (nBest - vValue[i].first) >= nTargetValue)
        {
            vfBest[i] = false;
            nBest -= vValue[i].first;
        }
    }
}

bool CWallet::SelectCoinsMinConf(const CAmount &nTargetValue,
    int nConfMine,
    int nConfTheirs,
    vector<COutput> vCoins,
    set<COutput> &setCoinsRet,
    CAmount &nValueRet) const
{
    setCoinsRet.clear();
    nValueRet = 0;

    // List of values less than target
    pair<CAmount, COutput> coinLowestLarger;
    coinLowestLarger.first = std::numeric_limits<CAmount>::max();
    coinLowestLarger.second.tx.reset();
    vector<pair<CAmount, COutput> > vValue;
    CAmount nTotalLower = 0;

    Shuffle(vCoins.begin(), vCoins.end(), FastRandomContext());
    for (const COutput &output : vCoins)
    {
        if (!output.spendable())
            continue;

        const CWalletTxRef &tx = output.tx;

        int depth = output.GetDepthInMainChain();
        if (depth < (tx->IsFromMe(ISMINE_ALL) ? nConfMine : nConfTheirs))
            continue;

        CAmount n = output.GetValue();

        pair<CAmount, COutput> coin = make_pair(n, output);

        if (n == nTargetValue)
        {
            setCoinsRet.insert(coin.second);
            nValueRet += coin.first;
            return true;
        }
        else if (n < nTargetValue)
        {
            vValue.push_back(coin);
            nTotalLower += n;
        }
        else if (n < coinLowestLarger.first)
        {
            coinLowestLarger = coin;
        }
    }

    if (nTotalLower == nTargetValue)
    {
        for (unsigned int i = 0; i < vValue.size(); ++i)
        {
            setCoinsRet.insert(vValue[i].second);
            nValueRet += vValue[i].first;
        }
        return true;
    }

    if (nTotalLower < nTargetValue)
    {
        if (coinLowestLarger.second.isNull())
            return false;
        setCoinsRet.insert(coinLowestLarger.second);
        nValueRet += coinLowestLarger.first;
        return true;
    }

    // Solve subset sum by stochastic approximation
    sort(vValue.rbegin(), vValue.rend(), CompareValueOnly());
    vector<char> vfBest;
    CAmount nBest;

    ApproximateBestSubset(vValue, nTotalLower, nTargetValue, vfBest, nBest);
    if (nBest != nTargetValue && nTotalLower >= nTargetValue + MIN_CHANGE)
        ApproximateBestSubset(vValue, nTotalLower, nTargetValue + MIN_CHANGE, vfBest, nBest);

    // If we have a bigger coin and (either the stochastic approximation didn't find a good solution,
    //                                   or the next bigger coin is closer), return the bigger coin
    if (coinLowestLarger.second.tx &&
        ((nBest != nTargetValue && nBest < nTargetValue) || coinLowestLarger.first <= nBest))
    {
        setCoinsRet.insert(coinLowestLarger.second);
        nValueRet += coinLowestLarger.first;
    }
    else
    {
        for (unsigned int i = 0; i < vValue.size(); i++)
            if (vfBest[i])
            {
                setCoinsRet.insert(vValue[i].second);
                nValueRet += vValue[i].first;
            }

        LOG(SELECTCOINS, "SelectCoins() best subset: ");
        for (unsigned int i = 0; i < vValue.size(); i++)
            if (vfBest[i])
                LOG(SELECTCOINS, "%s ", FormatMoney(vValue[i].first));
        LOG(SELECTCOINS, "total %s\n", FormatMoney(nBest));
    }

    return true;
}

void CWallet::FillAvailableCoins(const CCoinControl *coinControl)
{
    LOCK(cs_wallet);
    available.clear();
    vector<COutput> sel;
    AvailableCoins(sel, coinControl, false);
    for (const auto &coin : sel)
    {
        if (coin.mine == ISMINE_SPENDABLE)
            available.insert(SpendableTxos::value_type(coin.GetValue(), coin));
    }
}


bool CWallet::SelectCoins(const CAmount &nTargetValue,
    CFeeRate fee,
    unsigned int changeLen,
    std::vector<COutput> &setCoinsRet,
    CAmount &nValueRet,
    const CCoinControl *coinControl)
{
    AssertLockHeld(cs_wallet);

    setCoinsRet.clear();
    assert(nValueRet == 0);
    CAmount tgtValue = nTargetValue;
    bool filled = false;

    SpendableTxos customAvailable;
    SpendableTxos *possibleCoins = &available; // By default use the coins periodically gathered
    // coin control -> return all selected outputs (we want all selected to go into the transaction)
    if (coinControl)
    {
        LOG(SELECTCOINS, "CoinSelection: other inputs?: %d\n", coinControl->fAllowOtherInputs);

        if (coinControl->HasSelected()) // Some coins were selected, let's find out which ones and add them to the set
        {
            std::vector<COutPoint> selectedCoins;
            coinControl->ListSelected(selectedCoins);

            for (const COutPoint &outpt : selectedCoins) // for every selected coin
            {
                MapWallet::iterator txfound = mapWallet.find(outpt); // get its transaction
                if (txfound != mapWallet.end())
                {
                    // const uint256 hash = txfound->first;
                    COutput &coin = txfound->second;

                    LOG(SELECTCOINS, "CoinSelection: adding coincontrol selection valued at: %lu\n", coin.GetValue());
                    //? if (!out.fSpendable) continue;
                    nValueRet += coin.GetValue();
                    // decrease the value we will auto-find by what the user hand-selected.
                    tgtValue -= coin.GetValue();
                    setCoinsRet.push_back(coin);

                    if (nValueRet >= nTargetValue)
                        return true;
                }
                else // TODO: Allow non-wallet inputs
                {
                    return false;
                }
            }
        }

        if (!coinControl->fAllowOtherInputs) // No other inputs allowed so stop here.
            return (nValueRet >= nTargetValue);

        // Any special coincontrol means we need to figure out what coins match it
        // If the user is manually selecting outputs (only way is via the GUI) this is
        // not performance sensitive anyway (and we need to make sure coincontrol coins
        // are not in the list)
        if ((coinControl->HasSelected() || coinControl->fAllowWatchOnly || available.size() < 100))
        { // this "if" statement skips case where coincontrol is only used to supply a change address
            // flush the txns waiting to enter the txpool so we can respend them
            CommitTxToMempool();
            AvailableCoins(customAvailable, coinControl);
            possibleCoins = &customAvailable; // Override what coins we can select from
            filled = true;
        }
    }

    // Cleanup the available map of entries that has already been spent.
    //
    // TODO: This is not the most performant but is a quick fix for a bug.  Ultimately
    // we should just directly use mapWalletUnspent when doing CoinSelection() however
    // that would require a fairly invasive refactor.
    {
        for (auto i = available.begin(); i != available.end();)
        {
            if (!mapWalletUnspent.count(i->second.GetOutPoint()))
            {
                i = available.erase(i);
                continue;
            }
            i++;
        }
    }

    // If there are very few TXOs, then regenerate them.  If the wallet HAS few TXOs
    // then regenerate every time -- its fast for few.
    if (available.size() < MAX_TX_NUM_VIN)
    {
        // flush the txns waiting to enter the txpool so we can respend them
        CommitTxToMempool();
        FillAvailableCoins(coinControl);
        filled = true;
    }

    // The selected coins are all we need
    if (tgtValue <= 0)
        return true;

    // 100 is about half of a normal transaction, so overpay the fee by about half to avoid change
    TxoGroup g;
    CAmount dust = minRelayTxFee.GetDust();
    g = CoinSelection(*possibleCoins, tgtValue, dust, fee, changeLen);
    if ((!filled) && (g.first == 0)) // Ok no solution was found.  So let's regenerate the TXOs and try again.
    {
        LOG(SELECTCOINS, "Flush all pending tx and reload available coins\n");
        // flush the txns waiting to enter the txpool so we can respend them
        CommitTxToMempool();
        // now get all tx
        FillAvailableCoins(coinControl);
        g = CoinSelection(*possibleCoins, tgtValue, dust, fee, changeLen);
    }
    if (g.first == 0)
    {
        LOG(SELECTCOINS, "no solution found, %d utxos\n", available.size());
        return false; // no solution found
    }

    // Calculate the value and set of coins to return.
    // And cleanup the set of available coins as well.
    for (TxoItVec::iterator i = g.second.begin(); i != g.second.end();)
    {
        SpendableTxos::iterator j = *i; // i is and iterator over iterators
        const COutput &out = j->second;
        ++i;

        nValueRet += j->first;
        setCoinsRet.push_back(out);
        // remove this txo from the list so it is not used next time.  TODO: if the wallet does not
        // use this tx then the txo is temporarily lost (until available is refilled).
        possibleCoins->erase(j);
        if (possibleCoins != &available)
        {
            available.erase(j->first);
        }
    }
    DbgAssert(nValueRet >= nTargetValue, return false);
    return true;
}

bool CWallet::SignTransaction(CMutableTransaction &tx)
{
    AssertLockHeld(cs_wallet); // mapWallet

    SigHashType sighashType = defaultSigHashType;

    CTransaction txNewConst(tx);
    int nIn = 0;
    for (const auto &input : tx.vin)
    {
        MapWallet::const_iterator mi = mapWallet.find(input.prevout);
        if (mi == mapWallet.end())
        {
            return false;
        }
        auto coin = mi->second;
        if (coin.isNull() || coin.txOnly())
            return false;

        const CScript &scriptPubKey = coin.GetScriptPubKey();
        CScript &scriptSigRes = tx.vin[nIn].scriptSig;
        if (!ProduceSignature(
                TransactionSignatureCreator(this, &txNewConst, nIn, sighashType), scriptPubKey, scriptSigRes))
        {
            return false;
        }
        nIn++;
    }
    return true;
}

bool CWallet::FundTransaction(CMutableTransaction &tx,
    CAmount &nFeeRet,
    int &nChangePosRet,
    std::string &strFailReason,
    bool includeWatching)
{
    vector<CRecipient> vecSend;

    // Turn the txout set into a CRecipient vector
    for (const CTxOut &txOut : tx.vout)
    {
        CRecipient recipient = {txOut.scriptPubKey, txOut.nValue, false};
        vecSend.push_back(recipient);
    }

    CCoinControl coinControl;
    coinControl.fAllowOtherInputs = true;
    coinControl.fAllowWatchOnly = includeWatching;
    for (const CTxIn &txin : tx.vin)
    {
        coinControl.Select(txin.prevout);
    }

    CReserveKey reservekey(this);
    CWalletTx wtx;
    if (!CreateTransaction(vecSend, wtx, reservekey, nFeeRet, nChangePosRet, strFailReason, &coinControl, false))
        return false;

    if (nChangePosRet != -1)
    {
        tx.vout.insert(tx.vout.begin() + nChangePosRet, wtx.vout[nChangePosRet]);
        // we dont have the normal Create/Commit cycle, and dont want to risk reusing change,
        // so just remove the key from the keypool here.
        reservekey.KeepKey();
    }

    // Add new txins (keeping original txin scriptSig/order)
    for (const CTxIn &txin : wtx.vin)
    {
        bool found = false;
        for (const CTxIn &origTxIn : tx.vin)
        {
            if (txin.prevout == origTxIn.prevout)
            {
                found = true;
                break;
            }
        }
        if (!found)
            tx.vin.push_back(txin);
    }

    if (tx.nLockTime == 0)
        tx.nLockTime = wtx.nLockTime;
    return true;
}

bool InputSortBIP69(const CTxIn &a, const CTxIn &b) { return a.prevout.hash < b.prevout.hash; };

bool OutputSortBIP69(const CTxOut &a, const CTxOut &b)
{
    if (a.nValue == b.nValue)
    {
        return a.scriptPubKey < b.scriptPubKey;
    }
    return a.nValue < b.nValue;
};

void sortInputsBIP69(std::vector<CTxIn> &vin, std::vector<unsigned int> &inputOrder)
{
    std::sort(inputOrder.begin(), inputOrder.end(),
        [&vin](unsigned int a, unsigned int b) { return InputSortBIP69(vin[a], vin[b]); });

    std::sort(vin.begin(), vin.end(), InputSortBIP69);
}

void sortOutputsBIP69(std::vector<CTxOut> &vout, int *pChangePosRet)
{
    CTxOut savedChangeOut;
    if (pChangePosRet)
    {
        // Caller has a change position they are keeping track of, so note which CTxOut it is.
        savedChangeOut = vout[*pChangePosRet];
    }

    // outputs do not need the sort changes tracked
    std::sort(vout.begin(), vout.end(), OutputSortBIP69);

    if (pChangePosRet)
    {
        // Figure out where the change position ended up after the sort. Note
        // that std::find is ok here because all CTxOuts that compare equal
        // are identical and indistinguishable.
        const auto it = std::find(vout.begin(), vout.end(), savedChangeOut);
        // ensure that std::sort did not drop the output
        assert(it != vout.end());
        *pChangePosRet = it - vout.begin();
    }
}

class CompareCoinValue
{
public:
    bool operator()(const COutput &a, const COutput &b) const { return a.GetValue() < b.GetValue(); }
};
bool CWallet::CreateTransaction(const vector<CRecipient> &vecSend,
    CWalletTx &wtxNew,
    CReserveKey &reservekey,
    CAmount &nFeeRet,
    int &nChangePosRet,
    std::string &strFailReason,
    const CCoinControl *coinControl,
    bool sign)
{
    // If automatic consolidation is turned on then create a chain of as many transactions that are
    // required to satisfy the send amount. Either -spendzeroconfchange or instant transactions must be
    // turned on and we must not be using coin control or have any cointrol items selected.
    bool fCoinControl = (coinControl && coinControl->HasSelected());
    if (autoTxns.Value() && !fCoinControl && (instantTxns.Value() || bSpendZeroConfChange))
    {
        // Get an address we can spend to ourselves if we need to
        CReserveKey myReservekey(pwalletMain);
        CPubKey vchPubKey;
        if (!myReservekey.GetReservedKey(vchPubKey))
        {
            strFailReason = "Error: could not get an address";
            return false;
        }

        // Get a list of available coins and select up to the max vin allowed
        CCoinControl _coinControl;
        _coinControl.fAllowOtherInputs = true; // must be true because we might add an output to create a txn chain
        _coinControl.fAllowWatchOnly = false;

        do
        {
            vector<COutput> coins;
            CAmount _nValue = 0;
            uint32_t count = _coinControl.NumSelected();
            pwalletMain->AvailableCoins(coins, &_coinControl, false);
            // Sort entries from smallest to largest if the wallet is not too big. This
            // helps to remove the smallest dust from the wallet first.
            if (coins.size() < 10000)
                std::sort(coins.begin(), coins.end(), CompareCoinValue());

            bool fMaxVin = false;
            bool fDone = false;
            uint32_t nSubtractFeeFromAmount = 0;
            CAmount nToSend = 0;
            CAmount nFeeNeeded = 0;
            if (nFeeRet)
                nFeeNeeded = nFeeRet;
            else
                nFeeNeeded = maxTxFeeTweak.Value(); // assume the highest fee possible
            for (auto &recipient : vecSend)
            {
                nToSend += recipient.nAmount;
                if (recipient.fSubtractFeeFromAmount)
                    nSubtractFeeFromAmount++;
            }

            for (const auto &coin : coins)
            {
                _coinControl.Select(coin.GetOutPoint());
                _nValue += coin.GetValue();
                count++;
                if (count >= MAX_TX_NUM_VIN)
                {
                    fMaxVin = true;
                    break;
                }
                if (_nValue >= nFeeNeeded + nToSend)
                {
                    fDone = true;
                    break;
                }
            }
            // If don't have max vin then we need to account for fees.  If max vin then
            // we don't because in the case of max vin we are paying fees subtracted from our total.
            if (!fMaxVin && !fDone && !nSubtractFeeFromAmount)
            {
                strFailReason += _("The transaction amount is too small to send after the fee has been deducted");
                return false;
            }

            // Check if this is the final transaction.  If so then send to the final address
            // but if not, then spend to ourselves and chain this transaction to the next one
            // we create.
            //
            // Create the final transaction
            if (!fMaxVin || fDone)
            {
                if (!pwalletMain->CreateOneTransaction(
                        vecSend, wtxNew, reservekey, nFeeRet, nChangePosRet, strFailReason, &_coinControl, sign))
                {
                    strFailReason += _("Turn off auto consolidate and try sending again.");
                    return false;
                }
                return true;
            }
            else
            {
                // Prepare the recepient vector which will be a spend to ourselves if needed.
                vector<CRecipient> vecSendToMe;
                CScript scriptPubKey = P2pktOutput(vchPubKey);
                CRecipient me = {scriptPubKey, _nValue, true};
                vecSendToMe.push_back(me);

                // Create a transaction which spends to ourselves and which will be then chained to the next one
                // we create.
                if (!pwalletMain->CreateOneTransaction(
                        vecSendToMe, wtxNew, reservekey, nFeeRet, nChangePosRet, strFailReason, &_coinControl, sign))
                {
                    strFailReason += _("Turn off auto consolidate and try sending again.");
                    return false;
                }

                // Commit the transaction
                std::string error;
                if (!pwalletMain->CommitTransaction(wtxNew, reservekey, error))
                {
                    strFailReason += _("CommitTransaction failed.");
                    return false;
                }

                // Add the new outputs to coincontrol
                _coinControl.UnSelectAll();
                for (size_t i = 0; i < wtxNew.vout.size(); i++)
                {
                    _coinControl.Select(COutPoint(wtxNew.GetIdem(), i));
                }
            }
        } while (true);
    }
    else
    {
        return CreateOneTransaction(
            vecSend, wtxNew, reservekey, nFeeRet, nChangePosRet, strFailReason, coinControl, sign);
    }
}

bool CWallet::CreateOneTransaction(const vector<CRecipient> &vecSend,
    CWalletTx &wtxNew,
    CReserveKey &reservekey,
    CAmount &nFeeRet,
    int &nChangePosRet,
    std::string &strFailReason,
    const CCoinControl *coinControl,
    bool sign)
{
    uint64_t start = GetStopwatchMicros();
    CAmount nValue = 0;
    unsigned int nSubtractFeeFromAmount = 0;
    bool involvesPublicLabel = false;
    for (const CRecipient &recipient : vecSend)
    {
        if (getLabelPublic(recipient.scriptPubKey) != "")
            involvesPublicLabel = true;
        if (nValue < 0 || recipient.nAmount < 0)
        {
            strFailReason = _("Transaction amounts must be positive");
            return false;
        }
        nValue += recipient.nAmount;

        if (recipient.fSubtractFeeFromAmount)
            nSubtractFeeFromAmount++;
    }
    if (vecSend.empty() || nValue < 0)
    {
        strFailReason = _("Transaction amounts must be positive");
        return false;
    }

    wtxNew.fTimeReceivedIsTxTime = true;
    wtxNew.BindWallet(this);
    CMutableTransaction txNew;

    // Discourage fee sniping.
    //
    // For a large miner the value of the transactions in the best block and
    // the txpool can exceed the cost of deliberately attempting to mine two
    // blocks to orphan the current best block. By setting nLockTime such that
    // only the next block can include the transaction, we discourage this
    // practice as the height restricted and limited blocksize gives miners
    // considering fee sniping fewer options for pulling off this attack.
    //
    // A simple way to think about this is from the wallet's point of view we
    // always want the blockchain to move forward. By setting nLockTime this
    // way we're basically making the statement that we only want this
    // transaction to appear in the next block; we don't want to potentially
    // encourage reorgs by allowing transactions to appear at lower heights
    // than the next block in forks of the best chain.
    //
    // Of course, the subsidy is high enough, and transaction volume low
    // enough, that fee sniping isn't a problem yet, but by implementing a fix
    // now we ensure code won't be written that makes assumptions about
    // nLockTime that preclude a fix later.
    auto height = chainActive.Height();
    if (height == -1) // If chainActive height is unavailable, skip the fee sniping fix.
    {
        txNew.nLockTime = 0;
    }
    else
    {
        txNew.nLockTime = height;
    }

    assert(txNew.nLockTime < LOCKTIME_THRESHOLD);

    {
        LOCK(cs_wallet);
        {
            CAmount nFeeNeeded = 0;
            // Estimate base fee from an approx minimum size tx
            nFeeRet = GetMinimumFee(MIN_BYTES_IN_TX, nTxConfirmTarget, mempool);

            // Loop until there is enough fee
            while (true)
            {
                txNew.vin.clear();
                txNew.vout.clear();
                wtxNew.fFromMe = true;
                nChangePosRet = -1;
                bool fFirst = true;

                CAmount nValueToSelect = nValue;
                if (nSubtractFeeFromAmount == 0)
                    nValueToSelect += nFeeRet;
                double dPriority = 0;
                // vouts to the payees
                for (const CRecipient &recipient : vecSend)
                {
                    CTxOut txout(recipient.nAmount, recipient.scriptPubKey);

                    if (txout.IsDust())
                    {
                        if (recipient.fSubtractFeeFromAmount && nFeeRet > 0)
                        {
                            if (txout.nValue < 0)
                                strFailReason = _("The transaction amount is too small to pay the fee");
                            else
                                strFailReason =
                                    _("The transaction amount is too small to send after the fee has been deducted");
                        }
                        else
                            strFailReason = _("Transaction amount too small");
                        return false;
                    }
                    txNew.vout.push_back(txout);
                }


                // Choose coins to use
                std::vector<COutput> setCoins;
                CAmount nValueIn = 0;

                CAmount feeperbyte = GetMinimumFee(1, nTxConfirmTarget, mempool);
                uint64_t preSelect = GetLogTimeMicros();
                // No fee if I'm subtracting the fee out of the outputs
                CFeeRate selectionFeeRate = (nSubtractFeeFromAmount == 0) ? CFeeRate(feeperbyte) : CFeeRate(0);
                if (!SelectCoins(nValueToSelect, selectionFeeRate, P2PKH_LEN, setCoins, nValueIn, coinControl))
                {
                    strFailReason = _("Insufficient funds or funds not confirmed");
                    return false;
                }
                uint64_t postSelect = GetLogTimeMicros();
                // BU if the fee does not match, there might be extra in the selected coins to increase the fee so loop
                do
                {
                    txNew.vin.clear();
                    wtxNew.fFromMe = true;
                    nChangePosRet = -1;

                    // If I can remove the added change output from the prior loop, I can get rid of clearing and
                    // recalculating this
                    // vouts to the payees
                    txNew.vout.clear();
                    for (const CRecipient &recipient : vecSend)
                    {
                        CTxOut txout(recipient.nAmount, recipient.scriptPubKey);

                        if (recipient.fSubtractFeeFromAmount)
                        {
                            // Subtract fee equally from each selected recipient
                            txout.nValue -= nFeeRet / nSubtractFeeFromAmount;

                            if (fFirst) // first receiver pays the remainder not divisible by output count
                            {
                                fFirst = false;
                                txout.nValue -= nFeeRet % nSubtractFeeFromAmount;
                            }
                        }

                        if (txout.IsDust())
                        {
                            if (recipient.fSubtractFeeFromAmount && nFeeRet > 0)
                            {
                                if (txout.nValue < 0)
                                    strFailReason = _("The transaction amount is too small to pay the fee");
                                else
                                    strFailReason = _(
                                        "The transaction amount is too small to send after the fee has been deducted");
                            }
                            else
                                strFailReason = _("Transaction amount too small");
                            return false;
                        }
                        txNew.vout.push_back(txout);
                    }

                    for (const auto &coin : setCoins)
                    {
                        CAmount nCredit = coin.GetValue();
                        // The coin age after the next block (depth+1) is used instead of the current,
                        // reflecting an assumption the user would accept a bit more delay for
                        // a chance at a free transaction.
                        // But txpool inputs might still be in the txpool, so their age stays 0
                        int age = coin.tx->GetDepthInMainChain();
                        assert(age >= 0);
                        if (age != 0)
                            age += 1;
                        dPriority += (double)nCredit * age;
                    }

                    const CAmount nChange = nValueIn - nValueToSelect;
                    if (nChange > 0)
                    {
                        // Fill a vout to ourself
                        // TODO: pass in scriptChange instead of reservekey so
                        // change transaction isn't always pay-to-bitcoin-address
                        CScript scriptChange;

                        // coin control: send change to custom address
                        if (coinControl && !std::get_if<CNoDestination>(&coinControl->destChange))
                            scriptChange = GetScriptForDestination(coinControl->destChange);

                        // no coin control: send change to newly generated address
                        else
                        {
                            // Note: We use a new key here to keep it from being obvious which side is the change.
                            //  The drawback is that by not reusing a previous key, the change may be lost if a
                            //  backup is restored, if the backup doesn't have the new private key for the change.
                            //  If we reused the old key, it would be possible to add code to look for and
                            //  rediscover unknown transactions that were written with keys of ours to recover
                            //  post-backup change.

                            // Reserve a new key pair from key pool
                            CPubKey vchPubKey;
                            bool ret;
                            ret = reservekey.GetReservedKey(vchPubKey);
                            if (!ret)
                            {
                                strFailReason = _("Keypool ran out, please call keypoolrefill first");
                                return false;
                            }

                            scriptChange = P2pktOutput(vchPubKey);
                        }

                        CTxOut newTxOut(nChange, scriptChange);

                        // We do not move dust-change to fees, because the sender would end up paying more than
                        // requested.
                        // This would be against the purpose of the all-inclusive feature.
                        // So instead we raise the change and deduct from the recipient.
                        if (nSubtractFeeFromAmount > 0 && newTxOut.IsDust())
                        {
                            CAmount nDust = newTxOut.GetDustThreshold() - newTxOut.nValue;
                            newTxOut.nValue += nDust; // raise change until no more dust
                            for (unsigned int i = 0; i < vecSend.size(); i++) // subtract from first recipient
                            {
                                if (vecSend[i].fSubtractFeeFromAmount)
                                {
                                    txNew.vout[i].nValue -= nDust;
                                    if (txNew.vout[i].IsDust())
                                    {
                                        strFailReason = _("The transaction amount is too small to send after the fee "
                                                          "has been deducted");
                                        return false;
                                    }
                                    break;
                                }
                            }
                        }

                        // Never create dust outputs; if we would, just
                        // add the dust to the fee.
                        if (newTxOut.IsDust())
                        {
                            nFeeRet += nChange;
                            reservekey.ReturnKey();
                        }
                        else
                        {
                            if (!involvesPublicLabel)
                            {
                                // Insert change txn at random position:
                                nChangePosRet = GetRandInt(txNew.vout.size() + 1);
                                vector<CTxOut>::iterator position = txNew.vout.begin() + nChangePosRet;
                                txNew.vout.insert(position, newTxOut);
                            }
                            else
                                // Insert change at end position because original txout order is critical for public
                                // label
                                txNew.vout.insert(txNew.vout.end(), newTxOut);
                        }
                    }
                    else
                        reservekey.ReturnKey();

                    // Fill vin
                    //
                    // Note how the sequence number is set to max()-1 so that the
                    // nLockTime set above actually works.
                    for (const auto &coin : setCoins)
                    {
                        txNew.vin.push_back(CTxIn(coin.GetOutPoint(), coin.GetValue(), CScript(),
                            std::numeric_limits<unsigned int>::max() - 1));

                        // If the input is a Freeze CLTV lock-by-blocktime then update the txNew.nLockTime
                        CScriptNum nFreezeLockTime = CScriptNum::fromIntUnchecked(0);
                        if (isFreezeCLTV(*this, coin.GetScriptPubKey(), nFreezeLockTime))
                        {
                            if (nFreezeLockTime.getint64() > LOCKTIME_THRESHOLD)
                                txNew.nLockTime = chainActive.Tip()->GetMedianTimePast();
                        }
                    }

                    // BIP69
                    // only use BIP69 when signing otherwise it is not guaranteed that SIGHASH_ALL
                    // was used
                    // we do not need these input_order vector if BIP69 is not used
                    // but we create it anyway to simplify the signing logic later
                    // should use std::array instead of std::vector but array requires
                    // vin size to be constexpr
                    std::vector<unsigned int> inputOrder(txNew.vin.size());
                    std::iota(inputOrder.begin(), inputOrder.end(), 0);
                    // public label transactions are order dependent, we can not use BIP69 with them
                    if (sign && !involvesPublicLabel && useBIP69.Value() == true)
                    {
                        sortInputsBIP69(txNew.vin, inputOrder);
                        sortOutputsBIP69(txNew.vout, nChangePosRet >= 0 && unsigned(nChangePosRet) < txNew.vout.size() ?
                                                         &nChangePosRet :
                                                         nullptr);
                    }

                    // Sign
                    SigHashType sighashType = defaultSigHashType;
                    size_t nIn = 0;
                    CTransaction txNewConst(txNew);
                    while (nIn < setCoins.size())
                    {
                        auto coin = setCoins[inputOrder[nIn]];
                        bool signSuccess = false;
                        const CScript &scriptPubKey = coin.GetScriptPubKey();
                        CScript &scriptSigRes = txNew.vin[nIn].scriptSig;
                        if (sign)
                        {
                            signSuccess =
                                ProduceSignature(TransactionSignatureCreator(this, &txNewConst, nIn, sighashType),
                                    scriptPubKey, scriptSigRes);
                        }
                        // We aren't signing this input, so produce a script with the proper form, but without sig or
                        // other specific data.
                        else
                            signSuccess = ProduceSignature(DummySignatureCreator(), scriptPubKey, scriptSigRes, false);

                        if (!signSuccess)
                        {
                            strFailReason = _("Signing transaction failed");
                            return false;
                        }
                        nIn++;
                    }

                    unsigned int nBytes = ::GetSerializeSize(txNew, SER_NETWORK, PROTOCOL_VERSION);

                    // Remove scriptSigs if we used dummy signatures for fee calculation
                    if (!sign)
                    {
                        for (CTxIn &vin : txNew.vin)
                        {
                            vin.scriptSig = CScript();
                        }
                    }

                    // Check input and output limits
                    if ((txNew.vout.size() > MAX_TX_NUM_VOUT) && (txNew.vin.size() > MAX_TX_NUM_VIN))
                    {
                        strFailReason = strprintf(_("Transaction has %d inputs and %d outputs. Maximum inputs allowed "
                                                    "are %d and maximum outputs are %d"),
                            txNew.vin.size(), txNew.vout.size(), MAX_TX_NUM_VIN, MAX_TX_NUM_VOUT);
                        return false;
                    }
                    if (txNew.vout.size() > MAX_TX_NUM_VOUT)
                    {
                        strFailReason = strprintf(_("Transaction has %d outputs. Maximum outputs allowed is %d"),
                            txNew.vout.size(), MAX_TX_NUM_VOUT);
                        return false;
                    }
                    if (txNew.vin.size() > MAX_TX_NUM_VIN)
                    {
                        strFailReason = strprintf(_("Transaction has %d inputs. Maximum inputs allowed is %d. Try "
                                                    "reducing inputs by transferring a smaller amount."),
                            txNew.vin.size(), MAX_TX_NUM_VIN);
                        return false;
                    }

                    // Embed the constructed transaction data in wtxNew.
                    *static_cast<CTransaction *>(&wtxNew) = CTransaction(txNew);

                    // Limit size
                    if (nBytes > MAX_STANDARD_TX_SIZE)
                    {
                        strFailReason =
                            strprintf(_("Transaction of %d bytes is too large. Maximum allowed is %d bytes"), nBytes,
                                MAX_STANDARD_TX_SIZE);
                        return false;
                    }

                    dPriority = wtxNew.ComputePriority(dPriority, nBytes);

                    // Can we complete this as a free transaction?
                    if (fSendFreeTransactions && nBytes <= MAX_STANDARD_TX_SIZE &&
                        GetBoolArg("-relaypriority", DEFAULT_RELAYPRIORITY))
                    {
                        // Require at least hard-coded AllowFree.
                        if (AllowFree(dPriority))
                            break;
                    }
                    if (fSendFreeTransactions && !AreFreeTxnsAllowed())
                    {
                        strFailReason = _("You can not send free transactions if you have configured a "
                                          "-relay.limitFreeRelay of zero");
                        return false;
                    }

                    nFeeNeeded = GetMinimumFee(nBytes, nTxConfirmTarget, mempool);
                    if (coinControl && nFeeNeeded > 0 && coinControl->nMinimumTotalFee > nFeeNeeded)
                    {
                        nFeeNeeded = coinControl->nMinimumTotalFee;
                    }

                    // If we made it here and we aren't even able to meet the relay fee on the next pass, give up
                    // because we must be at the maximum allowed fee.
                    if (nFeeNeeded < ::minRelayTxFee.GetFee(nBytes))
                    {
                        strFailReason = _("Transaction too large for fee policy");
                        return false;
                    }


                    if (nFeeNeeded > maxTxFeeTweak.Value())
                    {
                        strFailReason = strprintf(_("Fee: %ld is larger than configured maximum allowed fee of "
                                                    ": %ld.  To change, set 'wallet.maxTxFee'."),
                            nFeeNeeded, maxTxFeeTweak.Value());
                        return false;
                    }


                    // Can we complete this as a free transaction?
                    if (fSendFreeTransactions && nBytes <= MAX_STANDARD_TX_SIZE &&
                        GetBoolArg("-relaypriority", DEFAULT_RELAYPRIORITY))
                    {
                        // Require at least hard-coded AllowFree.
                        if (dPriority >= AllowFree(dPriority))
                            break;
                    }

                    // try with these inputs again if the fee we allocated is less than what is needed,
                    // BUT the inputs contain enough coins to cover the needed fees.
                    if ((nFeeRet < nFeeNeeded) && (nValueIn - nValue >= nFeeNeeded))
                    {
                        // if we are pulling fees from sending amounts, do not select greater amounts
                        if (!nSubtractFeeFromAmount)
                            nValueToSelect = nValue + nFeeNeeded;
                        nFeeRet = nFeeNeeded;
                    }
                    else
                        break;
                } while (1);

                uint64_t signLoop = GetStopwatchMicros();
                LOG(BENCH, "CreateTransaction: total: %llu, selection: %llu, signloop: %llu\n", signLoop - start,
                    postSelect - preSelect, signLoop - postSelect);
                if (nFeeRet >= nFeeNeeded)
                    break; // Done, enough fee included.

                // Include more fee and try again.
                LOG(SELECTCOINS, "Warning: need fee of %d, got %d\n", nFeeNeeded, nFeeRet);

                // Include more fee and try again.
                nFeeRet = nFeeNeeded;
                continue;
            }
        }
    }

    return true;
}

/**
 * Call after CreateTransaction unless you want to abort
 */
bool CWallet::CommitTransaction(CWalletTx &wtxNew, CReserveKey &reservekey, std::string &errorString)
{
    /** When the wallet is parallelized, this will higher performing, however right now its a wash.
        Enqueuing like this will not provide feedback if the the txpool doesn't accept the tx.
        And for RPC calls, you must FlushTxAdmission before returning
    CTxInputData d;
    d.tx = MakeTransactionRef(wtxNew);
    d.whitelisted = true;
    d.nodeName = "wallet";
    EnqueueTxForAdmission(d);
    */

    auto txId = wtxNew.GetId();
    if (fBroadcastTransactions)
    {
        auto txref = MakeTransactionRef(wtxNew);
        CValidationDebugger debugger;
        CValidationState state;
        bool fMissingInputs = false;
        std::vector<COutPoint> vCoinsToUncache;
        bool isRespend = false;
        const bool rejectAbsurdFee = true;
        // Since this is our own wallet, we can use nonstandard
        // TODO: limit nonstandard to a tweak because unless you are a miner it won't be mined
        // setting ignoreFee to false -- it should be a power-user option only to create unrelayable tx
        ParallelAcceptToMemoryPool(txHandlerSnap, mempool, state, txref, AreFreeTxnsAllowed(), &fMissingInputs,
            rejectAbsurdFee, TransactionClass::NONSTANDARD, vCoinsToUncache, &isRespend, &debugger);
        if (debugger.IsValid())
        {
            CTxInputData d;
            d.tx = MakeTransactionRef(wtxNew);
            d.whitelisted = true;
            d.nodeName = "wallet";
            EnqueueTxForAdmission(d);
        }
        else
        {
            errorString = "The following errors encountered when committing the transaction:\n\n";
            std::vector<std::string> vErrors = debugger.GetRejectReasons();
            for (std::string e : vErrors)
                errorString += "    : " + e + "\n";
            LOGA("CommitTransaction(): Error: Transaction not valid: %s\n", errorString.c_str());

            return false;
        }
    }

    // tx must be in mempool or we can end up getting AvailableCoins() that are not really available.
    int count = 0;
    while (!mempool.exists(txId) && count < 100)
    {
        count++;
        MilliSleep(50);
    }

    {
        LOCK(cs_wallet);
        // This is only to keep the database open to defeat the auto-flush for the
        // duration of this scope.  This is the only place where this optimization
        // maybe makes sense; please don't do it anywhere else.
        CWalletDB *pwalletdb = fFileBacked ? new CWalletDB(strWalletFile, "r+") : nullptr;

        // Take key pair from key pool so it won't be used again
        reservekey.KeepKey();

        // Add tx to wallet because if it has change it is also ours
        // otherwise for transaction history in the event we are not
        // broadcasting right away.
        CWalletTxRef storedTx = MakeWalletTxRef(wtxNew);
        AddToWallet(storedTx, false, pwalletdb);

        // Notify that old coins are spent
        for (const CTxIn &txin : storedTx->vin)
        {
            CWalletTxRef wtx = mapWallet[txin.prevout].tx;
            wtx->BindWallet(this);
            NotifyTransactionChanged(this, wtx->GetIdem(), CT_UPDATED);
        }

        if (fFileBacked)
            delete pwalletdb;

        // Track how many getdata requests our transaction gets
        mapRequestCount[txId] = 0;

        if (fBroadcastTransactions)
        {
            SyncWithWallets(std::static_pointer_cast<const CTransaction>(storedTx), nullptr, -1);
        }
    }

    return true;
}

bool CWallet::AddAccountingEntry(const CAccountingEntry &acentry, CWalletDB &pwalletdb)
{
    if (!pwalletdb.WriteAccountingEntry_Backend(acentry))
        return false;

    laccentries.push_back(acentry);
    CAccountingEntry &entry = laccentries.back();
    wtxOrdered.insert(make_pair(entry.nOrderPos, TxPair(nullptr, &entry)));

    return true;
}

CAmount CWallet::GetRequiredFee(unsigned int nTxBytes) { return ::minRelayTxFee.GetFee(nTxBytes); }

CAmount CWallet::GetMinimumFee(unsigned int nTxBytes, unsigned int nConfirmTarget, const CTxMemPool &pool)
{
    // payTxFee is user-set "I want to pay this much"
    CAmount nFeeNeeded = CFeeRate(payTxFeeTweak.Value()).GetFee(nTxBytes);

    // If fee estimation is turned on then get an estimate
    CAmount nFeeEstimate = 0;
    if (feeEstimationTweak.Value())
    {
        nFeeEstimate = pool.estimateFee(nConfirmTarget).GetFee(nTxBytes);
    }

    // pick the larger of the paytxfee or the fee estimate
    nFeeNeeded = std::max(nFeeNeeded, nFeeEstimate);

    // prevent user from paying a fee below minRelayTxFee or payTxFee
    nFeeNeeded = std::max(nFeeNeeded, GetRequiredFee(nTxBytes));

    // But always obey the maximum
    if (nFeeNeeded > maxTxFeeTweak.Value())
        nFeeNeeded = maxTxFeeTweak.Value();

    return nFeeNeeded;
}

void CWallet::ClearAllSpent()
{
    LOCK(cs_wallet);
    auto iter = mapWalletUnspent.begin();
    while (iter != mapWalletUnspent.end())
    {
        if (IsSpent(iter->first))
        {
            iter = mapWalletUnspent.erase(iter);
            continue;
        }
        else
            iter++;
    }
}

DBErrors CWallet::LoadWallet(bool &fFirstRunRet)
{
    if (!fFileBacked)
        return DB_LOAD_OK;
    fFirstRunRet = false;
    DBErrors nLoadWalletRet = CWalletDB(strWalletFile, "cr+").LoadWallet(this);
    if (nLoadWalletRet == DB_NEED_REWRITE)
    {
        if (CDB::Rewrite(strWalletFile, "\x04pool"))
        {
            LOCK(cs_wallet);
            setKeyPool.clear();
            // Note: can't top-up keypool here, because wallet is locked.
            // User will be prompted to unlock wallet the next operation
            // that requires a new key.
        }
    }

    if (nLoadWalletRet != DB_LOAD_OK)
        return nLoadWalletRet;
    fFirstRunRet = !vchDefaultKey.IsValid();

    // Make sure to clear all spent items from the unspent map
    ClearAllSpent();

    uiInterface.LoadWallet(this);

    return DB_LOAD_OK;
}

DBErrors CWallet::ZapSelectTx(vector<uint256> &vHashIn, vector<uint256> &vHashOut)
{
    if (!fFileBacked)
        return DB_LOAD_OK;
    DBErrors nZapSelectTxRet = CWalletDB(strWalletFile, "cr+").ZapSelectTx(this, vHashIn, vHashOut);
    if (nZapSelectTxRet == DB_NEED_REWRITE)
    {
        if (CDB::Rewrite(strWalletFile, "\x04pool"))
        {
            LOCK(cs_wallet);
            setKeyPool.clear();
            // Note: can't top-up keypool here, because wallet is locked.
            // User will be prompted to unlock wallet the next operation
            // that requires a new key.
        }
    }

    if (nZapSelectTxRet != DB_LOAD_OK)
        return nZapSelectTxRet;

    MarkDirty();

    return DB_LOAD_OK;
}

DBErrors CWallet::ZapWalletTx(std::vector<CWalletTxRef> &vWtx)
{
    if (!fFileBacked)
        return DB_LOAD_OK;
    DBErrors nZapWalletTxRet = CWalletDB(strWalletFile, "cr+").ZapWalletTx(this, vWtx);
    if (nZapWalletTxRet == DB_NEED_REWRITE)
    {
        if (CDB::Rewrite(strWalletFile, "\x04pool"))
        {
            LOCK(cs_wallet);
            setKeyPool.clear();
            // Note: can't top-up keypool here, because wallet is locked.
            // User will be prompted to unlock wallet the next operation
            // that requires a new key.
        }
    }
    if (nZapWalletTxRet != DB_LOAD_OK)
    {
        return nZapWalletTxRet;
    }
    return DB_LOAD_OK;
}


bool CWallet::SetAddressBook(const CTxDestination &address, const string &strName, const string &strPurpose)
{
    bool fUpdated = false;
    {
        LOCK(cs_wallet); // mapAddressBook
        std::map<CTxDestination, CAddressBookData>::iterator mi = mapAddressBook.find(address);
        fUpdated = mi != mapAddressBook.end();
        mapAddressBook[address].name = strName;
        if (!strPurpose.empty()) /* update purpose only if requested */
            mapAddressBook[address].purpose = strPurpose;
    }
    // double negative means it IS mine
    NotifyAddressBookChanged(this, address, strName, ::IsMine(*this, address, chainActive.Tip()) != ISMINE_NO,
        strPurpose, (fUpdated ? CT_UPDATED : CT_NEW));
    if (!fFileBacked)
        return false;

    if (!strPurpose.empty() && !CWalletDB(strWalletFile).WritePurpose(address, strPurpose))
    {
        return false;
    }

    return CWalletDB(strWalletFile).WriteName(address, strName);
}

bool CWallet::DelAddressBook(const CTxDestination &address)
{
    {
        LOCK(cs_wallet); // mapAddressBook

        if (fFileBacked)
        {
            // Delete destdata tuples associated with address.
            for (const std::pair<const std::string, std::string> &item : mapAddressBook[address].destdata)
            {
                CWalletDB(strWalletFile).EraseDestData(address, item.first);
            }
        }
        mapAddressBook.erase(address);
    }

    NotifyAddressBookChanged(
        this, address, "", ::IsMine(*this, address, chainActive.Tip()) != ISMINE_NO, "", CT_DELETED);

    if (!fFileBacked)
        return false;

    CWalletDB(strWalletFile).ErasePurpose(address);
    return CWalletDB(strWalletFile).EraseName(address);
}

bool CWallet::SetDefaultKey(const CPubKey &vchPubKey)
{
    if (fFileBacked)
    {
        if (!CWalletDB(strWalletFile).WriteDefaultKey(vchPubKey))
            return false;
    }
    vchDefaultKey = vchPubKey;
    return true;
}

/**
 * Mark old keypool keys as used,
 * and generate all new keys
 */
bool CWallet::NewKeyPool()
{
    LOCK(cs_wallet);
    CWalletDB walletdb(strWalletFile);
    for (int64_t nIndex : setKeyPool)
    {
        walletdb.ErasePool(nIndex);
    }
    setKeyPool.clear();

    if (IsLocked())
        return false;

    int64_t nKeys = max(GetArg("-keypool", DEFAULT_KEYPOOL_SIZE), (int64_t)0);
    for (int i = 0; i < nKeys; i++)
    {
        int64_t nIndex = i + 1;
        walletdb.WritePool(nIndex, CKeyPool(GenerateNewKey()));
        setKeyPool.insert(nIndex);
    }
    LOGA("CWallet::NewKeyPool wrote %d new keys\n", nKeys);
    return true;
}

bool CWallet::TopUpKeyPool(unsigned int kpSize)
{
    LOCK(cs_wallet);

    if (IsLocked())
        return false;

    CWalletDB walletdb(strWalletFile);

    // Top up key pool
    unsigned int nTargetSize;
    if (kpSize > 0)
        nTargetSize = kpSize;
    else
        nTargetSize = max(GetArg("-keypool", DEFAULT_KEYPOOL_SIZE), (int64_t)0);

    if (setKeyPool.size() >= nTargetSize)
        return false;

    while (setKeyPool.size() < nTargetSize)
    {
        int64_t nEnd = 1;
        if (!setKeyPool.empty())
            nEnd = *(--setKeyPool.end()) + 1;
        if (!walletdb.WritePool(nEnd, CKeyPool(GenerateNewKey())))
            throw runtime_error("TopUpKeyPool(): writing generated key failed");
        setKeyPool.insert(nEnd);
        LOG(SELECTCOINS, "keypool added key %d, size=%u\n", nEnd, setKeyPool.size());
    }
    return true;
}

void CWallet::ReserveKeyFromKeyPool(int64_t &nIndex, CKeyPool &keypool)
{
    nIndex = -1;
    keypool.vchPubKey = CPubKey();
    {
        LOCK(cs_wallet);

        if (!IsLocked())
            TopUpKeyPool();

        // Get the oldest key
        if (setKeyPool.empty())
            return;

        CWalletDB walletdb(strWalletFile);

        nIndex = *(setKeyPool.begin());
        setKeyPool.erase(setKeyPool.begin());
        if (!walletdb.ReadPool(nIndex, keypool))
            throw runtime_error("ReserveKeyFromKeyPool(): read failed");
        if (!HaveKey(keypool.vchPubKey.GetID()))
            throw runtime_error("ReserveKeyFromKeyPool(): unknown key in key pool");
        assert(keypool.vchPubKey.IsValid());
        LOG(DBASE, "keypool reserve %d\n", nIndex);
    }
}

void CWallet::KeepKey(int64_t nIndex)
{
    // Remove from key pool
    if (fFileBacked)
    {
        CWalletDB walletdb(strWalletFile);
        walletdb.ErasePool(nIndex);
    }
    LOG(DBASE, "keypool keep %d\n", nIndex);
}

void CWallet::ReturnKey(int64_t nIndex)
{
    // Return to key pool
    {
        LOCK(cs_wallet);
        setKeyPool.insert(nIndex);
    }
    LOG(DBASE, "keypool return %d\n", nIndex);
}

bool CWallet::GetKeyFromPool(CPubKey &result)
{
    int64_t nIndex = 0;
    CKeyPool keypool;
    {
        LOCK(cs_wallet);
        ReserveKeyFromKeyPool(nIndex, keypool);
        if (nIndex == -1)
        {
            if (IsLocked())
                return false;
            result = GenerateNewKey();
            return true;
        }
        KeepKey(nIndex);
        result = keypool.vchPubKey;
    }
    return true;
}

int64_t CWallet::GetOldestKeyPoolTime()
{
    int64_t nIndex = 0;
    CKeyPool keypool;
    ReserveKeyFromKeyPool(nIndex, keypool);
    if (nIndex == -1)
        return GetTime();
    ReturnKey(nIndex);
    return keypool.nTime;
}

std::map<CTxDestination, CAmount> CWallet::GetAddressBalances()
{
    map<CTxDestination, CAmount> balances;

    {
        LOCK(cs_wallet);
        for (auto &walletEntry : mapWallet)
        {
            COutput &coin = walletEntry.second;
            CWalletTxRef &wtx = coin.tx;

            // Only access full tx records (note it would be cleaner to do the opposite)
            if (wtx->GetId() != walletEntry.first.hash)
                continue;

            if (!wtx->IsTrusted())
                continue;

            if (wtx->IsCoinBase() && wtx->GetBlocksToMaturity() > 0)
                continue;

            int nDepth = wtx->GetDepthInMainChain();
            if (nDepth < (wtx->IsFromMe(ISMINE_ALL) ? 0 : 1))
                continue;

            for (unsigned int i = 0; i < wtx->vout.size(); i++)
            {
                CTxDestination addr;
                if (!IsMine(wtx->vout[i]))
                    continue;
                if (!ExtractDestination(wtx->vout[i].scriptPubKey, addr))
                    continue;

                CAmount n = IsSpent(COutPoint(wtx->GetIdem(), i)) ? 0 : wtx->vout[i].nValue;

                if (!balances.count(addr))
                    balances[addr] = 0;
                balances[addr] += n;
            }
        }
    }

    return balances;
}

set<set<CTxDestination> > CWallet::GetAddressGroupings()
{
    AssertLockHeld(cs_wallet); // mapWallet
    set<set<CTxDestination> > groupings;
    set<CTxDestination> grouping;

    for (auto &walletEntry : mapWallet)
    {
        COutput &coin = walletEntry.second;
        CWalletTxRef &wtx = coin.tx;

        // Only access full tx records (note it would be cleaner to do the opposite)
        if (wtx->GetId() != walletEntry.first.hash)
            continue;

        if (wtx->vin.size() > 0)
        {
            bool any_mine = false;
            // group all input addresses with each other
            for (CTxIn txin : wtx->vin)
            {
                CTxDestination address;
                if (!IsMine(txin)) /* If this input isn't mine, ignore it */
                    continue;
                if (!ExtractDestination(mapWallet[txin.prevout].GetScriptPubKey(), address))
                    continue;
                grouping.insert(address);
                any_mine = true;
            }

            // group change with input addresses
            if (any_mine)
            {
                for (CTxOut txout : wtx->vout)
                {
                    if (IsChange(txout))
                    {
                        CTxDestination txoutAddr;
                        if (!ExtractDestination(txout.scriptPubKey, txoutAddr))
                            continue;
                        grouping.insert(txoutAddr);
                    }
                }
            }
            if (grouping.size() > 0)
            {
                groupings.insert(grouping);
                grouping.clear();
            }
        }

        // group lone addrs by themselves
        for (unsigned int i = 0; i < wtx->vout.size(); i++)
        {
            if (IsMine(wtx->vout[i]))
            {
                CTxDestination address;
                if (!ExtractDestination(wtx->vout[i].scriptPubKey, address))
                    continue;
                grouping.insert(address);
                groupings.insert(grouping);
                grouping.clear();
            }
        }
    }

    set<set<CTxDestination> *> uniqueGroupings; // a set of pointers to groups of addresses
    map<CTxDestination, set<CTxDestination> *> setmap; // map addresses to the unique group containing it
    for (set<CTxDestination> grouping2 : groupings)
    {
        // make a set of all the groups hit by this new group
        set<set<CTxDestination> *> hits;
        map<CTxDestination, set<CTxDestination> *>::iterator it;
        for (CTxDestination address : grouping2)
        {
            if ((it = setmap.find(address)) != setmap.end())
                hits.insert((*it).second);
        }

        // merge all hit groups into a new single group and delete old groups
        set<CTxDestination> *merged = new set<CTxDestination>(grouping2);
        for (set<CTxDestination> *hit : hits)
        {
            merged->insert(hit->begin(), hit->end());
            uniqueGroupings.erase(hit);
            delete hit;
        }
        uniqueGroupings.insert(merged);

        // update setmap
        for (CTxDestination element : *merged)
        {
            setmap[element] = merged;
        }
    }

    set<set<CTxDestination> > ret;
    for (set<CTxDestination> *uniqueGrouping : uniqueGroupings)
    {
        ret.insert(*uniqueGrouping);
        delete uniqueGrouping;
    }

    return ret;
}

std::set<CTxDestination> CWallet::GetAccountAddresses(const std::string &strAccount) const
{
    LOCK(cs_wallet);
    set<CTxDestination> result;
    for (const PAIRTYPE(const CTxDestination, CAddressBookData) & item : mapAddressBook)
    {
        const CTxDestination &address = item.first;
        const string &strName = item.second.name;
        if (strName == strAccount)
            result.insert(address);
    }
    return result;
}

bool CReserveKey::GetReservedKey(CPubKey &pubkey)
{
    if (nIndex == -1)
    {
        CKeyPool keypool;
        pwallet->ReserveKeyFromKeyPool(nIndex, keypool);
        if (nIndex != -1)
            vchPubKey = keypool.vchPubKey;
        else
        {
            return false;
        }
    }
    assert(vchPubKey.IsValid());
    pubkey = vchPubKey;
    return true;
}

void CReserveKey::KeepKey()
{
    if (nIndex != -1)
        pwallet->KeepKey(nIndex);
    nIndex = -1;
    vchPubKey = CPubKey();
}

void CReserveKey::ReturnKey()
{
    if (nIndex != -1)
        pwallet->ReturnKey(nIndex);
    nIndex = -1;
    vchPubKey = CPubKey();
}

void CWallet::GetAllReserveKeys(set<CKeyID> &setAddress) const
{
    setAddress.clear();

    CWalletDB walletdb(strWalletFile);

    LOCK(cs_wallet);
    for (const int64_t &id : setKeyPool)
    {
        CKeyPool keypool;
        if (!walletdb.ReadPool(id, keypool))
            throw runtime_error("GetAllReserveKeyHashes(): read failed");
        assert(keypool.vchPubKey.IsValid());
        CKeyID keyID = keypool.vchPubKey.GetID();
        if (!HaveKey(keyID))
            throw runtime_error("GetAllReserveKeyHashes(): unknown key in key pool");
        setAddress.insert(keyID);
    }
}

void CWallet::UpdatedTransactionByOutpoint(const COutPoint &outpt)
{
    LOCK(cs_wallet);
    // Only notify UI if this transaction is in this wallet
    MapWallet::const_iterator mi = mapWallet.find(outpt);
    if (mi != mapWallet.end())
    {
        NotifyTransactionChanged(this, mi->second.tx->GetIdem(), CT_UPDATED);
        // Base class might do something with this
        UpdatedTransaction(mi->second.tx->GetId());
    }
}

void CWallet::GetScriptForMining(boost::shared_ptr<CReserveScript> &script)
{
    boost::shared_ptr<CReserveKey> rKey(new CReserveKey(this));
    CPubKey pubkey;
    if (!rKey->GetReservedKey(pubkey))
        return;

    script = rKey;
    // script->reserveScript = CScript() << ToByteVector(pubkey) << OP_CHECKSIG;
    script->reserveScript = P2pktOutput(pubkey);
}

void CWallet::LockCoin(const COutPoint &output)
{
    AssertLockHeld(cs_wallet); // setLockedCoins
    setLockedCoins.insert(output);
}

void CWallet::UnlockCoin(const COutPoint &output)
{
    AssertLockHeld(cs_wallet); // setLockedCoins
    setLockedCoins.erase(output);
}

void CWallet::UnlockAllCoins()
{
    AssertLockHeld(cs_wallet); // setLockedCoins
    setLockedCoins.clear();
}

bool CWallet::IsLockedCoin(const COutPoint &outpt) const
{
    AssertLockHeld(cs_wallet); // setLockedCoins
    return (setLockedCoins.count(outpt) > 0);
}

void CWallet::ListLockedCoins(std::vector<COutPoint> &vOutpts)
{
    AssertLockHeld(cs_wallet); // setLockedCoins
    for (std::set<COutPoint>::iterator it = setLockedCoins.begin(); it != setLockedCoins.end(); it++)
    {
        COutPoint outpt = (*it);
        vOutpts.push_back(outpt);
    }
}

/** @} */ // end of Actions

class CAffectedKeysVisitor
{
private:
    const CKeyStore &keystore;
    std::vector<CKeyID> &vKeys;

public:
    CAffectedKeysVisitor(const CKeyStore &keystoreIn, std::vector<CKeyID> &vKeysIn)
        : keystore(keystoreIn), vKeys(vKeysIn)
    {
    }

    void Process(const CScript &script)
    {
        txnouttype type;
        std::vector<CTxDestination> vDest;
        int nRequired;
        if (ExtractDestinations(script, type, vDest, nRequired))
        {
            for (const CTxDestination &dest : vDest)
            {
                std::visit(*this, dest);
            }
        }
    }

    void operator()(const CKeyID &keyId)
    {
        if (keystore.HaveKey(keyId))
            vKeys.push_back(keyId);
    }

    void operator()(const CScriptID &scriptId)
    {
        CScript script;
        if (keystore.GetCScript(scriptId, script))
            Process(script);
    }

    void operator()(const ScriptTemplateDestination &id)
    {
        CScript ugs = UngroupedScriptTemplate(id.output);
        LOCK(keystore.cs_KeyStore);
        const Spendable *sp = keystore._GetTemplate(ugs);
        if (sp)
        {
            std::vector<CPubKey> involved = sp->PubKeys();
            for (const auto &i : involved)
            {
                vKeys.push_back(i.GetID());
            }
        }
    }


    void operator()(const CNoDestination &none) {}
};

void CWallet::GetKeyBirthTimes(std::map<CKeyID, int64_t> &mapKeyBirth) const
{
    AssertLockHeld(cs_wallet); // mapKeyMetadata
    mapKeyBirth.clear();

    // get birth times for keys with metadata
    for (std::map<CKeyID, CKeyMetadata>::const_iterator it = mapKeyMetadata.begin(); it != mapKeyMetadata.end(); it++)
        if (it->second.nCreateTime)
            mapKeyBirth[it->first] = it->second.nCreateTime;

    // map in which we'll infer heights of other keys
    // the tip can be reorganised; use a 144-block safety margin
    CBlockIndex *pindexMax = chainActive[std::max((int64_t)0, chainActive.Height() - 144)];
    std::map<CKeyID, CBlockIndex *> mapKeyFirstBlock;
    std::set<CKeyID> setKeys;
    GetKeys(setKeys);
    for (const CKeyID &keyid : setKeys)
    {
        if (mapKeyBirth.count(keyid) == 0)
            mapKeyFirstBlock[keyid] = pindexMax;
    }
    setKeys.clear();

    // if there are no such keys, we're done
    if (mapKeyFirstBlock.empty())
        return;

    READLOCK(cs_mapBlockIndex);
    // find first block that affects those keys, if there are any left
    std::vector<CKeyID> vAffected;
    for (MapWallet::const_iterator it = mapWallet.begin(); it != mapWallet.end(); it++)
    {
        // iterate over all wallet transactions...
        const CWalletTxRef wtx = (*it).second.tx;
        BlockMap::const_iterator blit = mapBlockIndex.find(wtx->hashBlock);
        if (blit != mapBlockIndex.end() && chainActive.Contains(blit->second))
        {
            // ... which are already in a block
            int nHeight = blit->second->height();
            for (const CTxOut &txout : wtx->vout)
            {
                // iterate over all their outputs
                CAffectedKeysVisitor(*this, vAffected).Process(txout.scriptPubKey);
                for (const CKeyID &keyid : vAffected)
                {
                    // ... and all their affected keys
                    std::map<CKeyID, CBlockIndex *>::iterator rit = mapKeyFirstBlock.find(keyid);
                    if (rit != mapKeyFirstBlock.end() && nHeight < rit->second->height())
                        rit->second = blit->second;
                }
                vAffected.clear();
            }
        }
    }

    // Extract block timestamps for those keys
    for (std::map<CKeyID, CBlockIndex *>::const_iterator it = mapKeyFirstBlock.begin(); it != mapKeyFirstBlock.end();
         it++)
        mapKeyBirth[it->first] = it->second->GetBlockTime() - 7200; // block times can be 2h off
}

bool CWallet::AddDestData(const CTxDestination &dest, const std::string &key, const std::string &value)
{
    if (std::get_if<CNoDestination>(&dest))
        return false;

    mapAddressBook[dest].destdata.insert(std::make_pair(key, value));
    if (!fFileBacked)
        return true;

    return CWalletDB(strWalletFile).WriteDestData(dest, key, value);
}

bool CWallet::EraseDestData(const CTxDestination &dest, const std::string &key)
{
    if (!mapAddressBook[dest].destdata.erase(key))
        return false;
    if (!fFileBacked)
        return true;

    return CWalletDB(strWalletFile).EraseDestData(dest, key);
}

bool CWallet::LoadDestData(const CTxDestination &dest, const std::string &key, const std::string &value)
{
    mapAddressBook[dest].destdata.insert(std::make_pair(key, value));
    return true;
}

bool CWallet::GetDestData(const CTxDestination &dest, const std::string &key, std::string *value) const
{
    std::map<CTxDestination, CAddressBookData>::const_iterator i = mapAddressBook.find(dest);
    if (i != mapAddressBook.end())
    {
        CAddressBookData::StringMap::const_iterator j = i->second.destdata.find(key);
        if (j != i->second.destdata.end())
        {
            if (value)
                *value = j->second;
            return true;
        }
    }
    return false;
}

bool CWallet::InitLoadWallet()
{
    std::string walletFile = GetArg("-wallet", DEFAULT_WALLET_DAT);

    // needed to restore wallet transaction meta data after -zapwallettxes
    std::vector<CWalletTxRef> vWtx;
    if (GetBoolArg("-zapwallettxes", false))
    {
        uiInterface.InitMessage(_("Zapping all transactions from wallet..."));
        CWallet *tempWallet = new CWallet(walletFile);
        DBErrors nZapWalletRet = tempWallet->ZapWalletTx(vWtx);
        if (nZapWalletRet != DB_LOAD_OK)
        {
            return InitError(strprintf(_("Error loading %s: Wallet corrupted"), walletFile));
        }
        delete tempWallet;
        tempWallet = nullptr;
    }
    uiInterface.InitMessage(_("Loading wallet..."));
    int64_t nStart = GetTimeMillis();
    bool fFirstRun = true;
    CWallet *walletInstance = new CWallet(walletFile);
    DBErrors nLoadWalletRet = walletInstance->LoadWallet(fFirstRun);
    if (nLoadWalletRet != DB_LOAD_OK)
    {
        if (nLoadWalletRet == DB_CORRUPT)
        {
            return InitError(strprintf(_("Error loading %s: Wallet corrupted"), walletFile));
        }
        else if (nLoadWalletRet == DB_NONCRITICAL_ERROR)
        {
            InitWarning(strprintf(_("Error reading %s! All keys read correctly, but transaction data"
                                    " or address book entries might be missing or incorrect."),
                walletFile));
        }
        else if (nLoadWalletRet == DB_TOO_NEW)
        {
            return InitError(
                strprintf(_("Error loading %s: Wallet requires newer version of %s"), walletFile, _(PACKAGE_NAME)));
        }
        else if (nLoadWalletRet == DB_NEED_REWRITE)
        {
            return InitError(strprintf(_("Wallet needed to be rewritten: restart %s to complete"), _(PACKAGE_NAME)));
        }
        else
        {
            return InitError(strprintf(_("Error loading %s"), walletFile));
        }
    }
    if (GetBoolArg("-upgradewallet", fFirstRun))
    {
        int nMaxVersion = GetArg("-upgradewallet", 0);
        if (nMaxVersion == 0) // the -upgradewallet without argument case
        {
            LOGA("Performing wallet upgrade to %i\n", FEATURE_LATEST);
            nMaxVersion = CLIENT_VERSION;
            walletInstance->SetMinVersion(FEATURE_LATEST); // permanently upgrade the wallet immediately
        }
        else
        {
            LOGA("Allowing wallet upgrade up to %i\n", nMaxVersion);
        }
        if (nMaxVersion < walletInstance->GetVersion())
        {
            return InitError(_("Cannot downgrade wallet"));
        }
        walletInstance->SetMaxVersion(nMaxVersion);
    }
    if (fFirstRun)
    {
        // Create new keyUser and set as default key
        if (GetBoolArg("-usehd", DEFAULT_USE_HD_WALLET) && !walletInstance->IsHDEnabled())
        {
            // generate a new master key
            CKey key;
            CPubKey masterPubKey = walletInstance->GenerateNewHDMasterKey();
            if (!walletInstance->SetHDMasterKey(masterPubKey))
            {
                throw std::runtime_error("CWallet::GenerateNewKey(): Storing master key failed");
            }
            // ensure this wallet.dat can only be opened by clients supporting HD
            walletInstance->SetMinVersion(FEATURE_HD);
        }
        CPubKey newDefaultKey;
        if (walletInstance->GetKeyFromPool(newDefaultKey))
        {
            walletInstance->SetDefaultKey(newDefaultKey);
            ScriptTemplateDestination dest(P2pktOutput(newDefaultKey));
            if (!walletInstance->SetAddressBook(dest, "", "receive"))
            {
                return InitError(_("Cannot write default address") += "\n");
            }
        }
        walletInstance->SetBestChain(chainActive.GetLocator());
    }
    else if (mapArgs.count("-usehd"))
    {
        bool useHD = GetBoolArg("-usehd", DEFAULT_USE_HD_WALLET);
        if (walletInstance->IsHDEnabled() && !useHD)
        {
            return InitError(
                strprintf(_("Error loading %s: You can't disable HD on a already existing HD wallet"), walletFile));
        }
        if (!walletInstance->IsHDEnabled() && useHD)
        {
            return InitError(
                strprintf(_("Error loading %s: You can't enable HD on a already existing non-HD wallet"), walletFile));
        }
    }
    LOGA(" wallet      %15dms\n", GetTimeMillis() - nStart);
    RegisterValidationInterface(walletInstance);
    CBlockIndex *pindexRescan = nullptr;
    if (GetBoolArg("-rescan", false))
    {
        pindexRescan = chainActive.Genesis();
    }
    else
    {
        CWalletDB walletdb(walletFile);
        CBlockLocator locator;
        if (walletdb.ReadBestBlock(locator))
        {
            pindexRescan = FindForkInGlobalIndex(chainActive, locator);
        }
        else
        {
            pindexRescan = chainActive.Genesis();
        }
    }
    if (chainActive.Tip() && chainActive.Tip() != pindexRescan)
    {
        // We can't rescan beyond non-pruned blocks, stop and throw an error
        // this might happen if a user uses a old wallet within a pruned node
        // or if he ran -disablewallet for a longer time, then decided to re-enable
        if (fPruneMode)
        {
            CBlockIndex *block = chainActive.Tip();
            while (block && block->pprev && (block->pprev->nStatus & BLOCK_HAVE_DATA) && block->pprev->processed() &&
                   pindexRescan != block)
            {
                block = block->pprev;
            }
            if (pindexRescan != block)
            {
                return InitError(_("Prune: last wallet synchronisation goes beyond pruned data. You need to -reindex "
                                   "(download the whole blockchain again in case of pruned node)"));
            }
        }
        uiInterface.InitMessage(_("Rescanning..."));
        LOGA("Rescanning last %i blocks (from block %i)...\n", chainActive.Height() - pindexRescan->height(),
            pindexRescan->height());
        nStart = GetTimeMillis();
        walletInstance->ScanForWalletTransactions(pindexRescan, true);
        LOGA(" rescan      %15dms\n", GetTimeMillis() - nStart);
        walletInstance->SetBestChain(chainActive.GetLocator());
        nWalletDBUpdated++;
        // Restore wallet transaction metadata after -zapwallettxes=1
        if (GetBoolArg("-zapwallettxes", false) && GetArg("-zapwallettxes", "1") != "2")
        {
            CWalletDB walletdb(walletFile);

            for (const CWalletTxRef &wtxOld : vWtx)
            {
                // can use idem or id here, mapWallet contains both
                MapWallet::iterator mi = walletInstance->mapWallet.find(COutPoint(wtxOld->GetIdem()));
                if (mi != walletInstance->mapWallet.end())
                {
                    const CWalletTxRef copyFrom = wtxOld;
                    std::shared_ptr<CWalletTx> copyTo = mi->second.tx;
                    copyTo->mapValue = copyFrom->mapValue;
                    copyTo->vOrderForm = copyFrom->vOrderForm;
                    copyTo->nTimeReceived = copyFrom->nTimeReceived;
                    copyTo->nTimeSmart = copyFrom->nTimeSmart;
                    copyTo->fFromMe = copyFrom->fFromMe;
                    copyTo->strFromAccount = copyFrom->strFromAccount;
                    copyTo->nOrderPos = copyFrom->nOrderPos;
                    copyTo->WriteToDisk(&walletdb);
                }
            }
        }
    }
    walletInstance->SetBroadcastTransactions(GetBoolArg("-walletbroadcast", DEFAULT_WALLETBROADCAST));
    pwalletMain = walletInstance;
    return true;
}

bool CWallet::ParameterInteraction()
{
    // check payTxFee
    if (payTxFeeTweak.Value() > 0)
    {
        if (payTxFeeTweak.Value() > HIGH_TX_FEE_PER_KB)
            InitWarning(_("-wallet.payTxFee is set very high! This is the transaction fee you will pay if you send a "
                          "transaction."));
        CFeeRate payTxFee = CFeeRate(payTxFeeTweak.Value(), 1000);
        if (payTxFee < ::minRelayTxFee)
        {
            return InitError(strprintf(_("Invalid amount for -wallet.payTxFee=<amount>: '%u' (must be at least %s)"),
                payTxFee.ToString(), ::minRelayTxFee.ToString()));
        }
    }

    // check maxTxFee
    {
        if (maxTxFeeTweak.Value() > HIGH_MAX_TX_FEE)
            InitWarning(_("-wallet.maxTxFee is set very high! Fees this large could be paid on a single transaction."));
        if (CFeeRate(maxTxFeeTweak.Value(), 1000) < ::minRelayTxFee)
        {
            return InitError(
                strprintf(_("Invalid amount for -wallet.maxTxFee=<amount>: '%u' (must be at least the minrelay "
                            "fee of %s to prevent stuck transactions)"),
                    maxTxFeeTweak.Value(), ::minRelayTxFee.ToString()));
        }
    }
    nTxConfirmTarget = GetArg("-txconfirmtarget", DEFAULT_TX_CONFIRM_TARGET);

    // If instant transactions is turned on then we must be able to spend zero conf change as well.
    if (instantTxns.Value())
    {
        bSpendZeroConfChange = GetBoolArg("-spendzeroconfchange", true);
    }
    else
    {
        bSpendZeroConfChange = GetBoolArg("-spendzeroconfchange", DEFAULT_SPEND_ZEROCONF_CHANGE);
    }

    // If auto consolidation is on then we must have at least spendzeroconfchange
    if (autoTxns.Value())
    {
        bSpendZeroConfChange = GetBoolArg("-spendzeroconfchange", true);
        if (!bSpendZeroConfChange && !instantTxns.Value())
        {
            InitWarning(_("You are trying to use -wallet.auto but neither -spendzeroconfchange nor -wallet.instant is "
                          "turned on"));
        }
    }

    fSendFreeTransactions = GetBoolArg("-sendfreetransactions", DEFAULT_SEND_FREE_TRANSACTIONS);

    return true;
}

void CWallet::EraseFromRam(CWalletTxRef tx)
{
    // Remove id record
    mapWallet.erase(COutPoint(tx->GetId()));
    // Remove idem record
    mapWallet.erase(COutPoint(tx->GetIdem()));
    // remove all outpoint records
    for (size_t i = 0; i < tx->vout.size(); i++)
    {
        mapWallet.erase(tx->OutpointAt(i));
    }
}

CKeyPool::CKeyPool() { nTime = GetTime(); }
CKeyPool::CKeyPool(const CPubKey &vchPubKeyIn)
{
    nTime = GetTime();
    vchPubKey = vchPubKeyIn;
}

CWalletKey::CWalletKey(int64_t nExpires)
{
    nTimeCreated = (nExpires ? GetTime() : 0);
    nTimeExpires = nExpires;
}

int CMerkleTx::SetMerkleBranch(const CBlock &block, int txIdx)
{
    // txIdx never == -1 since the caller already know txIdx
    assert(txIdx >= 0);
    CBlock blockTmp;

    // Update the tx's hashBlock
    hashBlock = block.GetHash();
    // Set the position of the transaction in the block
    nIndex = txIdx;

    // Is the tx in a block that's in the main chain
    const CBlockIndex *pindex = LookupBlockIndex(hashBlock);
    if (!pindex || !chainActive.Contains(pindex))
        return 0;

    return chainActive.Height() - pindex->height() + 1;
}

int CMerkleTx::GetDepthInMainChain(const CBlockIndex *&pindexRet) const
{
    if (hashUnset())
        return 0;

    // Find the block it claims to be in
    const CBlockIndex *pindex = LookupBlockIndex(hashBlock);
    if (!pindex || !chainActive.Contains(pindex))
        return 0;

    pindexRet = pindex; // we can return a pindex out of the lock because block headers are never deleted
    return ((nIndex == -1) ? (-1) : 1) * (chainActive.Height() - pindex->height() + 1);
}

int CMerkleTx::GetBlocksToMaturity() const
{
    if (!IsCoinBase())
        return 0;

    return max(0, (Params().GetConsensus().coinbaseMaturity + 1) - GetDepthInMainChain());
}

void ThreadRescan()
{
    pwalletMain->ScanForWalletTransactions(chainActive.Genesis(), true);
    pwalletMain->ReacceptWalletTransactions();
    pwalletMain->Flush();
    statusStrings.Clear("rescanning");
}

void StartWalletRescanThread()
{
    statusStrings.Set("rescanning");
    std::thread rescanThread(std::bind(&TraceThread<void (*)()>, "rescan", &ThreadRescan));
    rescanThread.detach();
}
