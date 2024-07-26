// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "script/sign.h"

#include "key.h"
#include "keystore.h"
#include "policy/policy.h"
#include "primitives/transaction.h"
#include "script/sighashtype.h"
#include "script/standard.h"
#include "uint256.h"

typedef std::vector<uint8_t> valtype;

#ifdef ANDROID // log sighash calculations
#include <android/log.h>
#define p(...)
// __android_log_print(ANDROID_LOG_DEBUG, "BU.sig", __VA_ARGS__)
#else
#define p(...)
// tinyformat::format(std::cout, __VA_ARGS__)
#endif

using namespace std;

const unsigned char vchDummyPubKey[33] = {
    2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
const CPubKey DummySizeOnlyKeyStore::dummyPubKey(vchDummyPubKey, vchDummyPubKey + 33);

TransactionSignatureCreator::TransactionSignatureCreator(const CKeyStore *keystoreIn,
    const CTransaction *txToIn,
    unsigned int nInIn,
    SigHashType sigHashTypeIn)
    // Note the use of STANDARD_SCRIPT_VERIFY_FLAGS here means that the full node wallet won't be able to use
    // post-upgrade features right away.  But this is ok because none of the scripts it is capable of signing need
    // them.
    : BaseSignatureCreator(keystoreIn), txTo(txToIn), nIn(nInIn), sigHashType(sigHashTypeIn),
      checker(txTo, nIn, STANDARD_SCRIPT_VERIFY_FLAGS)
{
    for (unsigned int i = 0; i < txToIn->vin.size(); i++) // catch uninitialized amounts
    {
        assert(txTo->vin[i].amount != -1);
    }
}

bool TransactionSignatureCreator::CreateSig(std::vector<uint8_t> &vchSig,
    const CKeyID &address,
    const CScript &scriptCode) const
{
    // Bad tx info
    if (txTo == nullptr || nIn >= txTo->vin.size())
        return false;
    CKey key;
    if (!keystore->GetKey(address, key))
    {
        return false;
    }

    uint256 hash;
    if (!SignatureHashNexa(scriptCode, *txTo, nIn, sigHashType, hash))
        return false;
    if (!key.SignSchnorr(hash, vchSig))
        return false;
    sigHashType.appendToSig(vchSig);

    // CPubKey pub = key.GetPubKey();
    p("Sign Schnorr: sig: %x, pubkey: %x sighash: %x\n", HexStr(vchSig), HexStr(pub.begin(), pub.end()), hash.GetHex());
    return true;
}


static bool Sign1(const CKeyID &address,
    const BaseSignatureCreator &creator,
    const CScript &scriptCode,
    CScript &scriptSigRet)
{
    std::vector<uint8_t> vchSig;
    if (!creator.CreateSig(vchSig, address, scriptCode))
    {
        return false;
    }
    scriptSigRet << vchSig;
    return true;
}

static bool SignN(const std::vector<valtype> &multisigdata,
    const BaseSignatureCreator &creator,
    const CScript &scriptCode,
    CScript &scriptSigRet)
{
    int nSigned = 0;
    int nRequired = multisigdata.front()[0];
    uint32_t signedBitmap = 0;
    CScript tmp;
    for (unsigned int i = 1; i < multisigdata.size() - 1 && nSigned < nRequired; i++)
    {
        const valtype &pubkey = multisigdata[i];
        CKeyID keyID = CPubKey(pubkey).GetID();
        if (Sign1(keyID, creator, scriptCode, tmp))
        {
            ++nSigned;
            signedBitmap |= 1 << (i - 1);
        }
    }
    scriptSigRet << signedBitmap;
    scriptSigRet.insert(scriptSigRet.end(), tmp.begin(), tmp.end());
    return nSigned == nRequired;
}

/**
 * Sign scriptPubKey using signature made with creator.
 * Signatures are returned in scriptSigRet (or returns false if scriptPubKey can't be signed),
 * unless whichTypeRet is TX_SCRIPTHASH, in which case scriptSigRet is the redemption script.
 * Returns false if scriptPubKey could not be completely satisfied.
 */
static bool SignStep(const BaseSignatureCreator &creator,
    const CScript &scriptPubKey,
    CScript &scriptSigRet,
    txnouttype &whichTypeRet)
{
    scriptSigRet.clear();

    std::vector<valtype> vSolutions;
    if (!Solver(scriptPubKey, whichTypeRet, vSolutions))
    {
        return false;
    }

    CKeyID keyID;
    switch (whichTypeRet)
    {
    case TX_SCRIPT_TEMPLATE:
    {
        const CKeyStore &keystore = creator.KeyStore();
        // Solver parses out stuff like the group, so mash back together the important items and look that up in our
        // keystore rather then looking the scriptPubKey up directly.
        // Really though, we need to look up the script in whatever way someone might have stored it, so there might
        // be other searches here in the future.  This one will catch all "well-known" scripts.
        CScript strippedScript = ScriptTemplateOutput(vSolutions[0], vSolutions[1]);
        {
            LOCK(keystore.cs_KeyStore);
            const Spendable *sp = keystore._GetTemplate(strippedScript);
            if (!sp)
                return false; // I can't sign this; I don't know about it
            // Spendable knows how to create a scriptSig... but it doesn't know how to actually sign
            // but the signature creator does.
            scriptSigRet = sp->SpendScript(creator);
            if (scriptSigRet.size() == 0)
                return false;
        }
    }
        return true;
    // These are OP_RETURN unspendable outputs so they should never be an input that needs signing
    case TX_LABELPUBLIC:
    case TX_NONSTANDARD:
    case TX_NULL_DATA:
        return false;
    case TX_PUBKEY:
        keyID = CPubKey(vSolutions[0]).GetID();
        return Sign1(keyID, creator, scriptPubKey, scriptSigRet);
    case TX_PUBKEYHASH:
    case TX_GRP_PUBKEYHASH:
        keyID = CKeyID(uint160(vSolutions[0]));
        if (!Sign1(keyID, creator, scriptPubKey, scriptSigRet))
        {
            return false;
        }
        else
        {
            CPubKey vch;
            bool ok = creator.KeyStore().GetPubKey(keyID, vch);
            if (!ok)
            {
                return false;
            }
            scriptSigRet << ToByteVector(vch);
        }
        return true;

    case TX_SCRIPTHASH:
    case TX_GRP_SCRIPTHASH:
        return creator.KeyStore().GetCScript(uint160(vSolutions[0]), scriptSigRet);

    case TX_MULTISIG:
        return (SignN(vSolutions, creator, scriptPubKey, scriptSigRet));
    }

    return false;
}

bool ProduceSignature(const BaseSignatureCreator &creator,
    const CScript &fromPubKey,
    CScript &scriptSig,
    bool verify,
    unsigned int *flags)
{
    txnouttype whichType;
    if (!SignStep(creator, fromPubKey, scriptSig, whichType))
    {
        return false;
    }

    if ((whichType == TX_SCRIPTHASH) || (whichType == TX_GRP_SCRIPTHASH))
    {
        // Solver returns the subscript that need to be evaluated;
        // the final scriptSig is the signatures from that
        // and then the serialized subscript:
        CScript subscript = scriptSig;

        txnouttype subType;
        bool fSolved = SignStep(creator, subscript, scriptSig, subType) && subType != TX_SCRIPTHASH;
        // Append serialized subscript whether or not it is completely signed:
        scriptSig << valtype(subscript.begin(), subscript.end());
        if (!fSolved)
        {
            return false;
        }
    }

    // Test solution
    // We can hard-code maxOps because this client has no templates capable of producing and signing longer scripts.
    // Additionally, while this constant is currently being raised it will eventually settle to a very high const
    // value.  There is no reason to break layering by using the tweak only to take that out later.

    // We don't have the capability of signing with tx context dependent instructions so ScriptImportedState can be
    // degenerate.
    if (verify)
    {
        ScriptImportedState sis(&creator.Checker());
        ScriptError serror;

        // Add fork flags if there are any
        unsigned int tmp = 0;
        tmp |= sis.checker->flags();
        if (flags)
        {
            tmp = tmp | *flags;
        }

        bool ret = VerifyScript(scriptSig, fromPubKey, tmp, sis, &serror);
        if (!ret)
        {
            LOGA("Internal sign verification failed with error %s\n", ScriptErrorString(serror));
        }
        return ret;
    }
    return true;
}

bool SignSignature(const CKeyStore &keystore,
    const CScript &fromPubKey,
    CMutableTransaction &txTo,
    unsigned int nIn,
    const CAmount &amount,
    SigHashType sigHashType,
    uint32_t nSigType,
    unsigned int *flags)
{
    assert(nIn < txTo.vin.size());
    CTxIn &txin = txTo.vin[nIn];
    if (txin.amount != amount) // compare input amount to amount in utxo
    {
        return false;
    }

    CTransaction txToConst(txTo);
    TransactionSignatureCreator creator(&keystore, &txToConst, nIn, sigHashType);
    return ProduceSignature(creator, fromPubKey, txin.scriptSig, flags);
}

bool SignSignature(const CKeyStore &keystore,
    const CTxOut &spendingThis,
    CMutableTransaction &txTo,
    unsigned int nIn,
    SigHashType sigHashType,
    uint32_t nSigType,
    unsigned int *flags)
{
    assert(nIn < txTo.vin.size());
    CTxIn &txin = txTo.vin[nIn];
    if (spendingThis.nValue != txin.amount)
        return false;
    return SignSignature(keystore, spendingThis.scriptPubKey, txTo, nIn, txin.amount, sigHashType);
}

static CScript PushAll(const Stack &values)
{
    CScript result;
    for (const StackItem &v : values)
        result << v.data(); // Every item must be a vch or data() throws
    return result;
}

static CScript CombineMultisig(const CScript &scriptPubKey,
    const BaseSignatureChecker &checker,
    const vector<valtype> &vSolutions,
    const Stack &sigs1,
    const Stack &sigs2)
{
    // Combine all the signatures we've got:
    set<valtype> allsigs;
    for (const StackItem &v : sigs1)
    {
        if (!v.empty())
            allsigs.insert(v.data());
    }
    for (const StackItem &v : sigs2)
    {
        if (!v.empty())
        {
            allsigs.insert(v.data());
        }
    }

    // Build a map of pubkey -> signature by matching sigs to pubkeys:
    assert(vSolutions.size() > 1);
    unsigned int nSigsRequired = vSolutions.front()[0];
    unsigned int nPubKeys = vSolutions.size() - 2; // vSolutions is [ required, pubkey0, ... pubkeyN, Num pubkeys]
    std::map<valtype, valtype> sigs;
    for (const valtype &sig : allsigs)
    {
        for (unsigned int i = 0; i < nPubKeys; i++)
        {
            const valtype &pubkey = vSolutions[i + 1];
            if (sigs.count(pubkey))
            {
                continue; // Already got a sig for this pubkey
            }

            if (checker.CheckSig(sig, pubkey, scriptPubKey))
            {
                sigs[pubkey] = sig;
                break;
            }
        }
    }
    // Now build a merged CScript:
    unsigned int nSigsHave = 0;
    CScript tmp;
    uint32_t signedBitmap = 0;
    for (unsigned int i = 0; i < nPubKeys && nSigsHave < nSigsRequired; i++)
    {
        if (sigs.count(vSolutions[i + 1]))
        {
            tmp << sigs[vSolutions[i + 1]];
            ++nSigsHave;
            signedBitmap |= (1 << i);
        }
    }
    CScript result;
    result << signedBitmap;
    result.insert(result.end(), tmp.begin(), tmp.end());

    // Fill any missing with OP_0:
    for (unsigned int i = nSigsHave; i < nSigsRequired; i++)
        result << OP_0;

    return result;
}

static CScript CombineSignatures(const CScript &scriptPubKey,
    const BaseSignatureChecker &checker,
    const txnouttype txType,
    const vector<valtype> &vSolutions,
    Stack &sigs1,
    Stack &sigs2)
{
    switch (txType)
    {
    case TX_SCRIPT_TEMPLATE:
    case TX_NONSTANDARD:
    case TX_NULL_DATA:
        // Don't know anything about this, assume bigger one is correct:
        if (sigs1.size() >= sigs2.size())
        {
            return PushAll(sigs1);
        }
        return PushAll(sigs2);
    case TX_PUBKEY:
    case TX_PUBKEYHASH:
    case TX_GRP_PUBKEYHASH:
        // Signatures are bigger than placeholders or empty scripts:
        if (sigs1.empty() || sigs1[0].empty())
        {
            return PushAll(sigs2);
        }
        return PushAll(sigs1);
    case TX_GRP_SCRIPTHASH:
    case TX_SCRIPTHASH:
        if (sigs1.empty() || sigs1.back().empty())
        {
            return PushAll(sigs2);
        }
        else if (sigs2.empty() || sigs2.back().empty())
        {
            return PushAll(sigs1);
        }
        else
        {
            // Recur to combine:
            valtype spk = sigs1.back().data();
            CScript pubKey2(spk.begin(), spk.end());

            txnouttype txType2;
            std::vector<std::vector<uint8_t> > vSolutions2;
            Solver(pubKey2, txType2, vSolutions2);
            sigs1.pop_back();
            sigs2.pop_back();
            CScript result = CombineSignatures(pubKey2, checker, txType2, vSolutions2, sigs1, sigs2);
            result << spk;
            return result;
        }
    case TX_MULTISIG:
        return CombineMultisig(scriptPubKey, checker, vSolutions, sigs1, sigs2);
    // These are OP_RETURN unspendable outputs so they should never be an input that needs signing
    case TX_LABELPUBLIC:
        return CScript();
    }

    return CScript();
}

CScript CombineSignatures(const CScript &scriptPubKey,
    const BaseSignatureChecker &checker,
    const CScript &scriptSig1,
    const CScript &scriptSig2,
    unsigned int *flags)
{
    txnouttype txType;
    std::vector<std::vector<uint8_t> > vSolutions;
    Solver(scriptPubKey, txType, vSolutions);

    Stack stack1;
    // scriptSig should have no ops in them, only data pushes.  Send MAX_OPS_PER_SCRIPT to mirror existing
    // behavior exactly.
    unsigned int tmp = SCRIPT_VERIFY_STRICTENC;
    if (flags)
    {
        // Add fork flags if there are any
        tmp = tmp | *flags;
    }
    EvalScript(stack1, scriptSig1, tmp, MAX_OPS_PER_SCRIPT, ScriptImportedState());
    Stack stack2;
    EvalScript(stack2, scriptSig2, tmp, MAX_OPS_PER_SCRIPT, ScriptImportedState());

    return CombineSignatures(scriptPubKey, checker, txType, vSolutions, stack1, stack2);
}

namespace
{
/** Dummy signature checker which accepts all signatures. */
class DummySignatureChecker : public BaseSignatureChecker
{
public:
    DummySignatureChecker() {}
    bool CheckSig(const std::vector<uint8_t> &scriptSig,
        const std::vector<uint8_t> &vchPubKey,
        const CScript &scriptCode) const
    {
        return true;
    }
};
const DummySignatureChecker dummyChecker;
} // namespace

const BaseSignatureChecker &DummySignatureCreator::Checker() const { return dummyChecker; }
bool DummySignatureCreator::CreateSig(std::vector<uint8_t> &vchSig,
    const CKeyID &keyid,
    const CScript &scriptCode) const
{
    // Create a dummy signature that is a valid DER-encoding
    // This is a validly-encoded 64 byte DER sig; also a valid Schnorr encoding.
    vchSig.assign(64, 0x44);
    vchSig[0] = 0x30;
    vchSig[1] = 0x3e;
    vchSig[2] = 0x02;
    vchSig[33] = 0x02;
    SigHashType biggest;
    biggest.dummyLongest();
    biggest.appendToSig(vchSig);
    return true;
}


template std::vector<uint8_t> signmessage(const std::vector<uint8_t> &data, const CKey &key);
template std::vector<uint8_t> signmessage(const std::string &data, const CKey &key);
