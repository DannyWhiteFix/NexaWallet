// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_SCRIPT_SIGN_H
#define NEXA_SCRIPT_SIGN_H

#include "hashwrapper.h"
#include "key.h"
#include "keystore.h"
#include "script/interpreter.h"
#include "script/sighashtype.h"
#include <vector>

class CKey;
class CKeyID;
class CKeyStore;
class CScript;
class CTransaction;

struct CMutableTransaction;

extern uint256 GetPrevoutHash(const CTransaction &txTo, unsigned int firstN);
extern uint256 GetInputAmountHash(const CTransaction &txTo, unsigned int firstN);
extern uint256 GetSequenceHash(const CTransaction &txTo, unsigned int firstN);
extern uint256 GetOutputsHash(const CTransaction &txTo, unsigned int firstN);

/** Virtual base class for signature creators. */
class BaseSignatureCreator
{
protected:
    const CKeyStore *keystore;

public:
    BaseSignatureCreator(const CKeyStore *keystoreIn) : keystore(keystoreIn) {}
    const CKeyStore &KeyStore() const { return *keystore; };
    virtual ~BaseSignatureCreator() {}
    virtual const BaseSignatureChecker &Checker() const = 0;

    /** Create a singular (non-script) signature. */
    virtual bool CreateSig(std::vector<unsigned char> &vchSig,
        const CKeyID &keyid,
        const CScript &scriptCode) const = 0;
};

/** A signature creator for transactions. */
class TransactionSignatureCreator : public BaseSignatureCreator
{
    const CTransaction *txTo;
    unsigned int nIn;
    SigHashType sigHashType;
    const TransactionSignatureChecker checker;

public:
    TransactionSignatureCreator(const CKeyStore *keystoreIn,
        const CTransaction *txToIn,
        unsigned int nInIn,
        SigHashType sigHashTypeIn);
    const BaseSignatureChecker &Checker() const { return checker; }
    bool CreateSig(std::vector<unsigned char> &vchSig, const CKeyID &keyid, const CScript &scriptCode) const;
};


/** Pretends that all keys exist, but always returns the same dummy public key.  Used for sizing satisfier scripts,
    and for building the script, with "blanks" in the data fields.
*/
class DummySizeOnlyKeyStore : public CKeyStore
{
public:
    static const CPubKey dummyPubKey;
    SpendableP2PKT dummySpendable;
    DummySizeOnlyKeyStore() : dummySpendable(dummyPubKey, this) {}
    virtual ~DummySizeOnlyKeyStore() {}
    //! Add a key to the store.
    virtual bool AddKeyPubKey(const CKey &key, const CPubKey &pubkey) { return true; }
    virtual bool AddKey(const CKey &key) { return true; };

    //! Check whether a key corresponding to a given address is present in the store.
    virtual bool HaveKey(const CKeyID &address) const { return true; }
    //! Check whether a key corresponding to a given address is present in the store, caller must hold cs_KeyStore
    virtual bool _HaveKey(const CKeyID &address) const { return true; }

    bool GetKey(const CTxDestination &dest, CKey &keyOut) const
    {
        keyOut = CKey();
        return true;
    }
    virtual bool GetKey(const CKeyID &address, CKey &keyOut) const
    {
        keyOut = CKey();
        return true;
    }
    virtual void GetKeys(std::set<CKeyID> &setAddress) const {}
    virtual bool GetPubKey(const CKeyID &address, CPubKey &pubKeyOut) const
    {
        pubKeyOut = dummyPubKey;
        return true;
    }
    virtual bool GetPubKey(const ScriptTemplateDestination &address, CPubKey &pubKeyOut) const
    {
        pubKeyOut = dummyPubKey;
        return true;
    }

    //! Support for BIP 0013 : see https://github.com/bitcoin/bips/blob/master/bip-0013.mediawiki
    virtual bool AddCScript(const CScript &redeemScript) { return true; }
    virtual bool HaveCScript(const CScriptID &hash) const { return true; }
    virtual bool GetCScript(const CScriptID &hash, CScript &redeemScriptOut) const { return true; }

    //! Support for Watch-only addresses
    virtual bool AddWatchOnly(const CScript &dest) { return true; }
    virtual bool RemoveWatchOnly(const CScript &dest) { return true; }
    virtual bool HaveWatchOnly(const CScript &dest) const { return true; }
    virtual bool HaveWatchOnly() const { return true; }

    virtual isminetype HaveTemplate(const CScript &output) const { return ISMINE_SPENDABLE; }
    virtual const Spendable *_GetTemplate(const CScript &output) const { return &dummySpendable; }

    virtual bool HaveTxDestination(const CTxDestination &addr)
    {
        return std::visit(CKeyStore::CheckTxDestination(this), addr);
    }
};


/** A signature creator that just produces 72-byte empty signatyres. */
class DummySignatureCreator : public BaseSignatureCreator
{
    DummySizeOnlyKeyStore ks;

public:
    // Gives empty signatures and empty pubkeys
    DummySignatureCreator() : BaseSignatureCreator(&ks) {}
    // Gives empty signatures for actual pubkeys (useful for watch only addresses)
    DummySignatureCreator(const CKeyStore *keystoreIn) : BaseSignatureCreator(keystoreIn) {}
    const BaseSignatureChecker &Checker() const;
    bool CreateSig(std::vector<unsigned char> &vchSig, const CKeyID &keyid, const CScript &scriptCode) const;
};

/** Produce a script signature using a generic signature creator.
    if verify is true, the created signature script is executed against the passed scriptpubkey to ensure it works */
bool ProduceSignature(const BaseSignatureCreator &creator,
    const CScript &scriptPubKey,
    CScript &scriptSig,
    bool verify = true,
    unsigned int *flags = nullptr);

/** Produce a script signature for a transaction. */
bool SignSignature(const CKeyStore &keystore,
    const CScript &fromPubKey,
    CMutableTransaction &txTo,
    unsigned int nIn,
    const CAmount &amount,
    SigHashType sigHashType = defaultSigHashType,
    uint32_t nSigType = SIGTYPE_SCHNORR,
    unsigned int *flags = nullptr);
bool SignSignature(const CKeyStore &keystore,
    const CTxOut &spendingThis,
    CMutableTransaction &txTo,
    unsigned int nIn,
    SigHashType sigHashType = defaultSigHashType,
    uint32_t nSigType = SIGTYPE_SCHNORR,
    unsigned int *flags = nullptr);

/** Combine two script signatures using a generic signature checker, intelligently, possibly with OP_0 placeholders. */
CScript CombineSignatures(const CScript &scriptPubKey,
    const BaseSignatureChecker &checker,
    const CScript &scriptSig1,
    const CScript &scriptSig2,
    unsigned int *flags = nullptr);

template <typename BYTEARRAY>
std::vector<unsigned char> signmessage(const BYTEARRAY &data, const CKey &key)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic << data;

    std::vector<unsigned char> vchSig;
    if (!key.SignCompact(ss.GetHash(), vchSig)) // signing will only fail if the key is bogus
    {
        return std::vector<unsigned char>();
    }
    return vchSig;
}

/** sign arbitrary data using the same algorithm as the signmessage/verifymessage RPCs and OP_CHECKDATASIG(VERIFY) */
extern template std::vector<unsigned char> signmessage(const std::vector<unsigned char> &data, const CKey &key);
extern template std::vector<unsigned char> signmessage(const std::string &data, const CKey &key);


#endif // NEXA_SCRIPT_SIGN_H
