// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/* clang-format off */
// must be first for windows
#include "compat.h"

/* clang-format on */
#include "base58.h"
#include "primitives/transaction.h"
#include "script/sighashtype.h"
#include "script/sign.h"
#include "stdio.h"
#include "streams.h"
#include "uint256.h"
#include "utilstrencodings.h"

#include <string>
#include <vector>

#ifdef ANDROID // log sighash calculations
#include <android/log.h>
#define p(...)
// __android_log_print(ANDROID_LOG_DEBUG, "BU.sig", __VA_ARGS__)
#else
#define p(...)
// tinyformat::format(std::cout, __VA_ARGS__)
#endif

const SigHashType defaultSigHashType; // ALL/ALL is the default construction

uint256 GetPrevoutHash(const SatoshiTransaction &txTo)
{
    CHashWriter ss(SER_GETHASH, 0);
    for (unsigned int n = 0; n < txTo.vin.size(); n++)
    {
        ss << txTo.vin[n].prevout;
    }
    return ss.GetHash();
}

uint256 GetSequenceHash(const SatoshiTransaction &txTo)
{
    CHashWriter ss(SER_GETHASH, 0);
    for (unsigned int n = 0; n < txTo.vin.size(); n++)
    {
        ss << txTo.vin[n].nSequence;
    }
    return ss.GetHash();
}

uint256 GetOutputsHash(const SatoshiTransaction &txTo)
{
    CHashWriter ss(SER_GETHASH, 0);
    for (unsigned int n = 0; n < txTo.vout.size(); n++)
    {
        ss << txTo.vout[n];
    }
    return ss.GetHash();
}

uint256 GetPrevoutHashOf(const CTransaction &txTo, unsigned int n)
{
    CHashWriter ss(SER_GETHASH, 0);
    assert(n < txTo.vin.size());
    ss << txTo.vin[n].type << txTo.vin[n].prevout;
    return ss.GetHash();
}

uint256 GetPrevoutHash(const CTransaction &txTo, unsigned int firstN)
{
    CHashWriter ss(SER_GETHASH, 0);
    assert(firstN <= txTo.vin.size());
    for (unsigned int n = 0; n < firstN; n++)
    {
        ss << txTo.vin[n].type << txTo.vin[n].prevout;
    }
    return ss.GetHash();
}

uint256 GetInputAmountHashOf(const CTransaction &txTo, unsigned int n)
{
    CHashWriter ss(SER_GETHASH, 0);
    assert(n < txTo.vin.size());
    ss << txTo.vin[n].amount;
    return ss.GetHash();
}
uint256 GetInputAmountHash(const CTransaction &txTo, unsigned int firstN)
{
    CHashWriter ss(SER_GETHASH, 0);
    assert(firstN <= txTo.vin.size());

    for (unsigned int n = 0; n < firstN; n++)
    {
        ss << txTo.vin[n].amount;
    }
    return ss.GetHash();
}

uint256 GetSequenceHash(const CTransaction &txTo, unsigned int firstN)
{
    CHashWriter ss(SER_GETHASH, 0);
    assert(firstN <= txTo.vin.size());
    for (unsigned int n = 0; n < firstN; n++)
    {
        ss << txTo.vin[n].nSequence;
    }
    return ss.GetHash();
}

uint256 GetSequenceHashOf(const CTransaction &txTo, unsigned int n)
{
    CHashWriter ss(SER_GETHASH, 0);
    assert(n < txTo.vin.size());
    ss << txTo.vin[n].nSequence;
    return ss.GetHash();
}

uint256 GetOutputsHash(const CTransaction &txTo, unsigned int firstN)
{
    CHashWriter ss(SER_GETHASH, 0);
    assert(firstN <= txTo.vout.size());

    for (unsigned int n = 0; n < firstN; n++)
    {
        ss << txTo.vout[n];
    }
    return ss.GetHash();
}

uint256 GetOutputsHashOf(const CTransaction &txTo, unsigned int a, unsigned int b)
{
    CHashWriter ss(SER_GETHASH, 0);
    assert(a < txTo.vout.size());
    assert(b < txTo.vout.size());
    ss << txTo.vout[a] << txTo.vout[b];
    return ss.GetHash();
}

/**
 * Wrapper that serializes like CTransaction, but with the modifications
 *  required for the signature hash done in-place
 */
class BitcoinTransactionSignatureSerializer
{
private:
    const SatoshiTransaction &txTo; //! reference to the spending transaction (the one being serialized)
    const CScript &scriptCode; //! output script being consumed
    const unsigned int nIn; //! input index of txTo being signed
    const bool fAnyoneCanPay; //! whether the hashtype has the BTCBCH_SIGHASH_ANYONECANPAY flag set
    const bool fHashSingle; //! whether the hashtype is BTCBCH_SIGHASH_SINGLE
    const bool fHashNone; //! whether the hashtype is BTCBCH_SIGHASH_NONE

public:
    BitcoinTransactionSignatureSerializer(const SatoshiTransaction &txToIn,
        const CScript &scriptCodeIn,
        unsigned int nInIn,
        uint8_t nHashTypeIn)
        : txTo(txToIn), scriptCode(scriptCodeIn), nIn(nInIn),
          fAnyoneCanPay(!!(nHashTypeIn & BTCBCH_SIGHASH_ANYONECANPAY)),
          fHashSingle((nHashTypeIn & 0x1f) == BTCBCH_SIGHASH_SINGLE),
          fHashNone((nHashTypeIn & 0x1f) == BTCBCH_SIGHASH_NONE)
    {
    }

    /** Serialize the passed scriptCode, skipping OP_CODESEPARATORs */
    template <typename S>
    void SerializeScriptCode(S &s) const
    {
        CScript::const_iterator it = scriptCode.begin();
        CScript::const_iterator itBegin = it;
        opcodetype opcode;
        unsigned int nCodeSeparators = 0;
        while (scriptCode.GetOp(it, opcode))
        {
            if (opcode == OP_CODESEPARATOR)
                nCodeSeparators++;
        }
        ::WriteCompactSize(s, scriptCode.size() - nCodeSeparators);
        it = itBegin;
        while (scriptCode.GetOp(it, opcode))
        {
            if (opcode == OP_CODESEPARATOR)
            {
                s.write((char *)&itBegin[0], it - itBegin - 1);
                itBegin = it;
            }
        }
        if (itBegin != scriptCode.end())
            s.write((char *)&itBegin[0], it - itBegin);
    }

    /** Serialize an input of txTo */
    template <typename S>
    void SerializeInput(S &s, unsigned int nInput) const
    {
        // In case of BTCBCH_SIGHASH_ANYONECANPAY, only the input being signed is serialized
        if (fAnyoneCanPay)
            nInput = nIn;
        // Serialize the prevout
        ::Serialize(s, txTo.vin[nInput].prevout);
        // Serialize the script
        if (nInput != nIn)
            // Blank out other inputs' signatures
            ::Serialize(s, CScriptBase());
        else
            SerializeScriptCode(s);
        // Serialize the nSequence
        if (nInput != nIn && (fHashSingle || fHashNone))
            // let the others update at will
            ::Serialize(s, (int)0);
        else
            ::Serialize(s, txTo.vin[nInput].nSequence);
    }

    /** Serialize an output of txTo */
    template <typename S>
    void SerializeOutput(S &s, unsigned int nOutput) const
    {
        if (fHashSingle && nOutput != nIn)
            // Do not lock-in the txout payee at other indices as txin
            ::Serialize(s, CTxOut());
        else
            ::Serialize(s, txTo.vout[nOutput]);
    }

    /** Serialize txTo */
    template <typename S>
    void Serialize(S &s) const
    {
        // Serialize nVersion
        ::Serialize(s, txTo.nVersion);
        // Serialize vin
        unsigned int nInputs = fAnyoneCanPay ? 1 : txTo.vin.size();
        ::WriteCompactSize(s, nInputs);
        for (unsigned int nInput = 0; nInput < nInputs; nInput++)
            SerializeInput(s, nInput);
        // Serialize vout
        unsigned int nOutputs = fHashNone ? 0 : (fHashSingle ? nIn + 1 : txTo.vout.size());
        ::WriteCompactSize(s, nOutputs);
        for (unsigned int nOutput = 0; nOutput < nOutputs; nOutput++)
            SerializeOutput(s, nOutput);
        // Serialize nLockTime
        ::Serialize(s, txTo.nLockTime);
    }
};


// WARNING: Never use this to signal errors in a signature hash function. This is here solely for legacy reasons!
const uint256 SIGNATURE_HASH_ERROR(uint256S("0000000000000000000000000000000000000000000000000000000000000001"));

uint256 SignatureHashBitcoin(const CScript &scriptCode,
    const SatoshiTransaction &txTo,
    unsigned int nIn,
    const uint8_t nHashType,
    size_t *nHashedOut)
{
    if (nIn >= txTo.vin.size())
    {
        //  nIn out of range
        // IMPORTANT NOTICE:
        // Returning one from SignatureHash..() to signal error conditions is a kludge that
        // is also breaking the ECDSA assumption that only cryptographic hashes are signed. The special value
        // returned here is, however, due to further omissions in CheckSig, part of the pre-BCH
        // consensus rule set and needs to be left as-is.
        // See also: https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2014-November/006878.html
        return SIGNATURE_HASH_ERROR;
    }

    // Check for invalid use of BTCBCH_SIGHASH_SINGLE
    if ((nHashType & 0x1f) == BTCBCH_SIGHASH_SINGLE)
    {
        if (nIn >= txTo.vout.size())
        {
            //  nOut out of range
            // IMPORTANT NOTICE:
            // Returning one from SignatureHash..() to signal error conditions is a kludge that
            // is also breaking the ECDSA assumption that only cryptographic hashes are signed. The special value
            // returned here is, however, due to further omissions in CheckSig, part of the pre-BCH
            // consensus rule set and needs to be left as-is.
            // See also: https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2014-November/006878.html
            return SIGNATURE_HASH_ERROR;
        }
    }

    // Wrapper to serialize only the necessary parts of the transaction being signed
    BitcoinTransactionSignatureSerializer txTmp(txTo, scriptCode, nIn, nHashType);

    // Serialize and hash
    CHashWriter ss(SER_GETHASH, 0);
    ss << txTmp << nHashType;
    if (nHashedOut != nullptr)
        *nHashedOut = ss.GetNumBytesHashed();
    return ss.GetHash();
}

// ONLY to be called with BTCBCH_SIGHASH_FORKID set in nHashType!
uint256 SignatureHashBitcoinCash(const CScript &scriptCode,
    const SatoshiTransaction &txTo,
    unsigned int nIn,
    const uint8_t nHashType,
    const CAmount &amount,
    size_t *nHashedOut)
{
    uint256 hashPrevouts;
    uint256 hashSequence;
    uint256 hashInputAmounts;
    uint256 hashOutputs;

    p("Signature hash calculation with type: 0x%x\n", nHashType);
    if (!(nHashType & BTCBCH_SIGHASH_ANYONECANPAY))
    {
        hashPrevouts = GetPrevoutHash(txTo);
        p("Hashing prevouts to: %s\n", hashPrevouts.GetHex().c_str());
    }

    /* gets the hash of the sequence numbers of every input */
    if (!(nHashType & BTCBCH_SIGHASH_ANYONECANPAY) && (nHashType & 0x1f) != BTCBCH_SIGHASH_SINGLE &&
        (nHashType & 0x1f) != BTCBCH_SIGHASH_NONE)
    {
        hashSequence = GetSequenceHash(txTo);
        p("Hashing input sequence numbers to: %s\n", hashSequence.GetHex().c_str());
    }

    /* gets the hash of the serialization of every output */
    if ((nHashType & 0x1f) != BTCBCH_SIGHASH_SINGLE && (nHashType & 0x1f) != BTCBCH_SIGHASH_NONE)
    {
        hashOutputs = GetOutputsHash(txTo);
        p("Hashing every output to: %s\n", hashOutputs.GetHex().c_str());
    }
    /* Or just serialize the output that corresponds to this input */
    else if ((nHashType & 0x1f) == BTCBCH_SIGHASH_SINGLE && nIn < txTo.vout.size())
    {
        CHashWriter ss(SER_GETHASH, 0);
        ss << txTo.vout[nIn];
        hashOutputs = ss.GetHash();
        p("Hashing just output %d to: %s\n", nIn, hashOutputs.GetHex().c_str());
    }

    CHashWriter ss(SER_GETHASH, 0);
    // Version
    ss << txTo.nVersion;
    // Input prevouts/nSequence (none/all, depending on flags)
    ss << hashPrevouts;
    ss << hashSequence;
    // The input being signed (replacing the scriptSig with scriptCode +
    // amount). The prevout may already be contained in hashPrevout, and the
    // nSequence may already be contain in hashSequence.
    ss << txTo.vin[nIn].prevout;
    ss << static_cast<const CScriptBase &>(scriptCode);
    p("ScriptCode: %s\n", scriptCode.GetHex().c_str());
    ss << amount;
    p("Amount: %ld\n", (long int)amount);
    ss << txTo.vin[nIn].nSequence;
    p("This input sequence: %d\n", txTo.vin[nIn].nSequence);
    // Outputs (none/one/all, depending on flags)
    ss << hashOutputs;
    // Locktime
    ss << txTo.nLockTime;
    p("Locktime: %d\n", txTo.nLockTime);
    // Sighash type
    ss << (uint32_t)nHashType;
    p("sigHashType: %x\n", nHashType);

    p("Num bytes hashed: %d\n", (int)ss.GetNumBytesHashed());
    uint256 sighash = ss.GetHash();
    p("Final sighash is: %s\n", sighash.GetHex().c_str());
    return sighash;
}

bool SignatureHashNexaComponents(const CTransaction &txTo,
    unsigned int nIn,
    const SigHashType &sigHashType,
    uint256 &hashPrevouts,
    uint256 &hashSequence,
    uint256 &hashInputAmounts,
    uint256 &hashOutputs)
{
    size_t vinSize = txTo.vin.size();
    size_t voutSize = txTo.vout.size();

    if (nIn >= vinSize)
        return false;
    if (sigHashType.isInvalid())
        return false;

    switch (sigHashType.inp)
    {
    case SigHashType::Input::FIRSTN:
    {
        // Shouldn't ever happen because sighashtype would be invalid()
        DbgAssert(sigHashType.inpData.size() == 1, return false);
        unsigned int firstN = sigHashType.inpData[0];
        if (firstN > vinSize)
            return false;
        hashPrevouts = GetPrevoutHash(txTo, firstN);
        hashSequence = GetSequenceHash(txTo, firstN);
        hashInputAmounts = GetInputAmountHash(txTo, firstN);
    }
    break;
    case SigHashType::Input::THISIN:
    {
        // Shouldn't ever happen because sighashtype would be invalid()
        DbgAssert(sigHashType.inpData.size() == 0, return false);
        hashPrevouts = GetPrevoutHashOf(txTo, nIn);
        hashSequence = GetSequenceHashOf(txTo, nIn);
        hashInputAmounts = GetInputAmountHashOf(txTo, nIn);
    }
    break;
    case SigHashType::Input::ALL:
        // Shouldn't ever happen because sighashtype would be invalid()
        DbgAssert(sigHashType.inpData.size() == 0, return false);
        hashPrevouts = GetPrevoutHash(txTo, vinSize);
        hashSequence = GetSequenceHash(txTo, vinSize);
        hashInputAmounts = GetInputAmountHash(txTo, vinSize);
        break;
    default:
        // Shouldn't ever happen because sighashtype would be invalid()
        return false;
    }

    switch (sigHashType.out)
    {
    case SigHashType::Output::TWO:
    {
        DbgAssert(sigHashType.outData.size() == 2, return false);
        if (sigHashType.outData[0] >= voutSize)
            return false;
        if (sigHashType.outData[1] >= voutSize)
            return false;
        hashOutputs = GetOutputsHashOf(txTo, sigHashType.outData[0], sigHashType.outData[1]);
    }
    break;
    case SigHashType::Output::FIRSTN:
    {
        DbgAssert(sigHashType.outData.size() == 1, return false);
        unsigned int count = sigHashType.outData[0];
        if (count > voutSize)
            return false;
        hashOutputs = GetOutputsHash(txTo, count);
    }
    break;
    case SigHashType::Output::ALL:
        hashOutputs = GetOutputsHash(txTo, voutSize);
        break;
    default:
        return false;
    }

    return true;
}

bool SignatureHashNexa(const CScript &scriptCode,
    const CTransaction &txTo,
    unsigned int nIn,
    const SigHashType &sigHashType,
    uint256 &result,
    size_t *nHashedOut)
{
    uint256 hashPrevouts;
    uint256 hashSequence;
    uint256 hashInputAmounts;
    uint256 hashOutputs;

    p("Signature hash calculation with type: %s\n", sigHashType.ToString().c_str());
    result = SIGNATURE_HASH_ERROR;

    // Calculate all needed portions of the sighash
    if (!SignatureHashNexaComponents(txTo, nIn, sigHashType, hashPrevouts, hashSequence, hashInputAmounts, hashOutputs))
        return false;

    return SignatureHashNexa(scriptCode, txTo.nVersion, txTo.nLockTime, sigHashType, hashPrevouts, hashSequence,
        hashInputAmounts, hashOutputs, result, nHashedOut);
}

bool SignatureHashNexa(const CScript &scriptCode,
    uint8_t txVersion,
    uint32_t txLockTime,
    const SigHashType &sigHashType,
    const uint256 &hashPrevouts,
    const uint256 &hashSequence,
    const uint256 &hashInputAmounts,
    const uint256 &hashOutputs,
    uint256 &result,
    size_t *nHashedOut)
{
    CHashWriter ss(SER_GETHASH, 0);
    // Version
    ss << txVersion;
    // Input prevouts/nSequence (none/all, depending on flags)
    ss << hashPrevouts;
    ss << hashInputAmounts;
    ss << hashSequence;
    ss << static_cast<const CScriptBase &>(scriptCode);
    p("ScriptCode: %s\n", scriptCode.GetHex().c_str());

    // Outputs (none/one/all, depending on flags)
    ss << hashOutputs;
    // Locktime
    ss << txLockTime;
    p("Locktime: %d\n", txLockTime);

    // Sighash type -- if the sighashtype is all, you MUST use the empty vector representation here.
    ss << sigHashType;
    p("sigHashType: %s\n", sigHashType.ToString().c_str());

    p("Num bytes hashed: %d\n", (int)ss.GetNumBytesHashed());
    if (nHashedOut != nullptr)
        *nHashedOut = ss.GetNumBytesHashed();
    result = ss.GetHash();
    p("Final sighash is: %s\n", result.GetHex().c_str());
    return true;
}


uint256 SignatureHash(const CScript &scriptCode,
    const CTransaction &txTo,
    unsigned int nIn,
    const SigHashType &sigHashType,
    const CAmount &amount,
    size_t *nHashedOut)
{
    if (sigHashType.isInvalid())
    {
        return SIGNATURE_HASH_ERROR;
    }
    uint256 result;
    if (!SignatureHashNexa(scriptCode, txTo, nIn, sigHashType, result, nHashedOut))
        return SIGNATURE_HASH_ERROR;
    return result;
}

SigHashType GetSigHashType(const std::vector<unsigned char> &vchSig)
{
    if (vchSig.size() == 0)
    {
        return SigHashType().invalidate();
    }

    return SigHashType(vchSig);
}

void RemoveSigHashType(std::vector<unsigned char> &vchSig)
{
    vchSig.resize(64); // Schnorr signatures are 64 bytes
}

SigHashType &SigHashType::fromSig(const std::vector<unsigned char> &sig)
{
    size_t sigsz = sig.size();
    if (sigsz < 64)
        return *this; // invalid
    return fromBytes(sig, 64);
}

SigHashType &SigHashType::fromBytes(const std::vector<unsigned char> &byteArray, int start)
{
    invalidate(); // Start clean

    size_t sigsz = byteArray.size();
    if (sigsz - start == 0) // No bytes is ALL/ALL
    {
        valid = true;
        return *this;
    }
    size_t curPos = start;

    uint8_t io = byteArray[curPos];
    out = static_cast<SigHashType::Output>(io & 0xf);
    inp = static_cast<SigHashType::Input>(io >> 4);

    if (out > Output::LAST_VALID)
        return invalidate();
    if (inp > Input::LAST_VALID)
        return invalidate();

    curPos++;
    // Grab any extra bytes needed
    if (inp == Input::FIRSTN)
    {
        if (sigsz <= curPos)
            return invalidate(); // invalid
        inpData.resize(1);
        inpData[0] = byteArray[curPos];
        curPos++;
    }

    if (out == Output::FIRSTN)
    {
        if (sigsz <= curPos)
            return invalidate(); // invalid
        outData.resize(1);
        outData[0] = byteArray[curPos];
        curPos++;
    }
    else if (out == Output::TWO)
    {
        if (sigsz <= curPos + 1)
            return invalidate(); // invalid
        outData.resize(2);
        outData[0] = byteArray[curPos];
        outData[1] = byteArray[curPos + 1];
        curPos += 2;
    }

    // Require that no extra bytes come after this sighashtype
    if (sigsz != curPos)
        return invalidate();

    valid = true;
    return *this;
}

/** append this hash type to a signature so that the resulting data describes what it signed */
bool SigHashType::appendToSig(std::vector<unsigned char> &sig) const
{
    // If its an invalid sigtype return false, and use the safest
    // choice ALL/ALL (which is encoded as 0 bytes)
    if (!valid)
        return false;

    // ALL/ALL shorthand is no bytes
    if ((inp == SigHashType::Input::ALL) && (out == SigHashType::Output::ALL))
        return true;

    sig.push_back((static_cast<uint8_t>(inp) << 4) | static_cast<uint8_t>(out));

    switch (inp)
    {
    case SigHashType::Input::FIRSTN:
    {
        DbgAssert(inpData.size() == 1, );
        assert(inpData.size() > 0);
        sig.push_back(inpData[0]);
    }
    break;
    case SigHashType::Input::THISIN:
    case SigHashType::Input::ALL:
        break;

    default:
        return false;
    }

    switch (out)
    {
    case SigHashType::Output::TWO:
    {
        DbgAssert(outData.size() == 2, );
        assert(outData.size() > 1);
        sig.push_back(outData[0]);
        sig.push_back(outData[1]);
    }
    break;
    case SigHashType::Output::FIRSTN:
    {
        DbgAssert(outData.size() == 1, );
        assert(outData.size() > 0);
        sig.push_back(outData[0]);
    }
    break;
    case SigHashType::Output::ALL:
        break;
    default: // This structure should never hold an illegal sighashtype, except during testing
        return false;
    }
    return true;
}


std::string SigHashType::HexStr() const
{
    std::vector<unsigned char> sighashbytes;
    if (appendToSig(sighashbytes))
    {
        return ::HexStr(sighashbytes);
    }
    // SigHashType is Invalid
    return "";
}

/** Convert to a human readable representation of the sighash */
std::string SigHashType::ToString() const
{
    std::string ret;
    if (isInvalid())
        return std::string("INVALID");
    if (hasAll())
        return "ALL";
    switch (inp)
    {
    case Input::ALL:
        ret = "ALL_IN";
        break;
    case Input::FIRSTN:
        ret = "FIRST_" + std::to_string(inpData[0]) + "_IN";
        break;
    case Input::THISIN:
        ret = "THIS_IN";
        break;
    default:
        return std::string("INVALID");
    }

    ret += "|";

    switch (out)
    {
    case Output::ALL:
        ret += "ALL_OUT";
        break;
    case Output::FIRSTN:
        ret += "FIRST_" + std::to_string(outData[0]) + "_OUT";
        break;
    case Output::TWO:
        ret += std::to_string(outData[0]) + "_" + std::to_string(outData[1]) + "_OUT";
        break;
    default:
        return std::string("INVALID");
    }

    return ret;
}


SigHashType &SigHashType::from(const std::string &flagStr)
{
    std::vector<std::string> strings;

    if (flagStr == "ALL")
    {
        setAll();
        return *this;
    }

    std::istringstream ss(flagStr);
    std::string s;
    while (getline(ss, s, '|'))
    {
        TrimString(s);
        if (s == "ALL_IN")
        {
            inp = SigHashType::Input::ALL;
            inpData.resize(0);
        }
        else if (s == "ALL_OUT")
        {
            out = SigHashType::Output::ALL;
            outData.resize(0);
        }
        else if (s == "THIS_IN")
        {
            inp = SigHashType::Input::THISIN;
            inpData.resize(0);
        }
        else
        {
            // Parse token by underscores
            std::istringstream us(s);
            std::string up;
            if (!getline(us, up, '_'))
                return invalidate();
            if (up == "FIRST")
            {
                if (!getline(us, up, '_'))
                    return invalidate();
                int n = std::stoi(up);
                if ((n < 0) || (n > 255))
                    return invalidate();
                if (!getline(us, up, '_'))
                    return invalidate();
                if (up == "IN")
                {
                    setFirstNIn(n);
                }
                else if (up == "OUT")
                {
                    setFirstNOut(n);
                }
                else
                    return invalidate();
            }
            else // 2 outputs following the form: a_b_OUT
            {
                int a = 0;
                try
                {
                    a = std::stoi(up);
                }
                catch (...)
                {
                    return invalidate();
                }
                if ((a < 0) || (a > 255))
                    return invalidate();
                if (!getline(us, up, '_'))
                    return invalidate();
                int b = 0;
                try
                {
                    b = std::stoi(up);
                }
                catch (...)
                {
                    return invalidate();
                }
                if ((b < 0) || (b > 255))
                    return invalidate();
                if (!getline(us, up, '_'))
                    return invalidate();
                if (up != "OUT")
                    return invalidate();
                set2Outs(a, b);
            }
        }
    }
    return *this;
}
