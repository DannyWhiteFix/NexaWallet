// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "libnexa.h"
#include "libnexa_common.h"

#ifdef DEBUG
#ifdef IOS
#define p(...) // tinyformat::format(std::cout, __VA_ARGS__)
#else // not IOS
#define p(...) // tinyformat::format(std::cout, __VA_ARGS__)
#endif // IOS
#else // not DEBUG
#define p(...)
#endif // DEBUG

// in headervalidation.cpp
bool CheckBlockHeader(const Consensus::Params &consensusParams,
    const CBlockHeader &block,
    CValidationState &state,
    bool fCheckPOW);

SLAPI int32_t libnexaVersion() { return LIBNEXA_VERSION; }

SLAPI unsigned int get_libnexa_error() { return get_error_code(); }

SLAPI void get_libnexa_error_string(char *buf, uint64_t buflen) { get_error_string(buf, buflen); }

SLAPI int encode64(const unsigned char *data, int size, char *result, int resultMaxLen)
{
    auto dataAsStr = EncodeBase64(data, size);
    if (dataAsStr.size() > std::numeric_limits<int>::max())
    {
        set_error(LIBNEXA_ERROR::RETURN_FAILURE, "number of bytes to be returned cannot be represented by an int\n");
        return -1;
    }
    const int outsz = dataAsStr.size();
    if (outsz >= resultMaxLen)
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "returned data larger than the result buffer provided\n");
        return -outsz;
    }
    strncpy(result, dataAsStr.c_str(), resultMaxLen);
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    return (int)outsz;
}

SLAPI int decode64(const char *data, unsigned char *result, int resultMaxLen)
{
    bool invalid = true;
    auto dataBytes = DecodeBase64(data, &invalid);
    if (invalid)
    {
        set_error(LIBNEXA_ERROR::DECODE_FAILURE, "data passed in was invalid base64\n");
        return 0;
    }
    if (dataBytes.size() > std::numeric_limits<int>::max())
    {
        set_error(LIBNEXA_ERROR::RETURN_FAILURE, "number of bytes to be returned cannot be represented by an int\n");
        return -1;
    }
    const int outsz = dataBytes.size();
    if (outsz > resultMaxLen)
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "returned data larger than the result buffer provided\n");
        return -outsz;
    }
    memcpy(result, &dataBytes[0], outsz);
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    return (int)outsz;
}

/** Convert binary data to a hex string.  The provided result buffer must be 2*length+1 bytes.
 */
SLAPI int Bin2Hex(const unsigned char *val, int length, char *result, unsigned int resultLen)
{
    std::string s = GetHex(val, length);
    const size_t sz = s.size() + 1; // add one for \n
    if (sz > std::numeric_limits<int>::max())
    {
        set_error(LIBNEXA_ERROR::RETURN_FAILURE, "number of bytes to be returned cannot be represented by an int\n");
        return -1;
    }
    if (sz >= resultLen)
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "returned data larger than the result buffer provided\n");
        return 0; // need 1 more for /0
    }
    strncpy(result, s.c_str(), resultLen);
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    return (int)sz;
}

/** Derive a BIP-0044 heirarchial deterministic wallet key */
SLAPI int hd44DeriveChildKey(const unsigned char *secretSeed,
    unsigned int secretSeedLen,
    unsigned int purpose,
    unsigned int coinType,
    unsigned int account,
    bool change,
    unsigned int index,
    unsigned char *secret,
    char *keypath)
{
    CKey derivedSecret;
    if ((secretSeedLen < 16) || (secretSeedLen > 64))
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "invalid seed len, len was < 16 or > 64\n");
        return -1;
    }
    checkSigInit();
    std::string derivPath;
    int ret = Hd44DeriveChildKey(
        secretSeed, secretSeedLen, purpose, coinType, account, change, index, derivedSecret, nullptr);
    std::memcpy(secret, derivedSecret.begin(), 32);
    // if (keypath != nullptr) keypath[0] = 0;
    // strcpy(keypath, derivPath.c_str());
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    return ret;
}


/** Given a private key, return its corresponding public key */
SLAPI int GetPubKey(const unsigned char *keyData, unsigned char *result, unsigned int resultLen)
{
    checkSigInit();
    CKey key = LoadKey(keyData);
    if (key.IsValid() == false)
    {
        set_error(LIBNEXA_ERROR::DECODE_FAILURE, "data passed in decoded to an invalid key\n");
        return 0;
    }
    CPubKey pubkey = key.GetPubKey();
    size_t size = pubkey.size();
    if (size > std::numeric_limits<int>::max())
    {
        set_error(LIBNEXA_ERROR::RETURN_FAILURE, "number of bytes to be returned cannot be represented by an int\n");
        return -1;
    }
    if (size > resultLen)
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "returned data larger than the result buffer provided\n");
        return 0;
    }
    std::copy(pubkey.begin(), pubkey.end(), result);
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    return (int)size;
}

/** Sign data (compatible with BCH OP_CHECKDATASIG) */
SLAPI int SignHashEDCSA(const unsigned char *data,
    int datalen,
    const unsigned char *secret,
    unsigned char *result,
    unsigned int resultLen)
{
    checkSigInit();
    CKey key = LoadKey(secret);
    uint256 hash;
    CSHA256().Write(data, datalen).Finalize(hash.begin());
    std::vector<uint8_t> sig;
    if (!key.SignECDSA(hash, sig))
    {
        set_error(LIBNEXA_ERROR::DECODE_FAILURE, "data passed in decoded to an invalid key\n");
        return 0;
    }
    unsigned int sigSize = sig.size();
    if (sigSize > std::numeric_limits<int>::max())
    {
        set_error(LIBNEXA_ERROR::RETURN_FAILURE, "number of bytes to be returned cannot be represented by an int\n");
        return -1;
    }
    if (sigSize > resultLen)
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "returned data larger than the result buffer provided\n");
        return 0;
    }
    std::copy(sig.begin(), sig.end(), result);
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    return (int)sigSize;
}

SLAPI int txid(const unsigned char *txData, int txbuflen, unsigned char *result)
{
    CTransaction tx;
    CDataStream ssData((char *)txData, (char *)txData + txbuflen, SER_NETWORK, PROTOCOL_VERSION);
    try
    {
        ssData >> tx;
    }
    catch (const std::exception &)
    {
        set_error(LIBNEXA_ERROR::DECODE_FAILURE, "tx data provided failed to decode\n");
        return 0;
    }
    uint256 ret = tx.GetId();
    // no need to check retlen, will always be 64
    int retlen = ret.size();
    memcpy(result, ret.begin(), retlen);
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    return retlen;
}

SLAPI int txidem(const unsigned char *txData, int txbuflen, unsigned char *result)
{
    CTransaction tx;
    CDataStream ssData((char *)txData, (char *)txData + txbuflen, SER_NETWORK, PROTOCOL_VERSION);
    try
    {
        ssData >> tx;
    }
    catch (const std::exception &)
    {
        set_error(LIBNEXA_ERROR::DECODE_FAILURE, "tx data provided failed to decode\n");
        return 0;
    }
    uint256 ret = tx.GetIdem();
    // no need to check retlen, will always be 64
    int retlen = ret.size();
    memcpy(result, ret.begin(), retlen);
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    return retlen;
}

SLAPI int blockHash(const unsigned char *data, int len, unsigned char *result)
{
    CDataStream dataStrm((char *)data, (char *)data + len, SER_NETWORK, PROTOCOL_VERSION);
    CBlockHeader blkHeader;
    try
    {
        dataStrm >> blkHeader;
    }
    catch (const std::exception &)
    {
        set_error(LIBNEXA_ERROR::DECODE_FAILURE, "block header data provided failed to decode\n");
        return 0;
    }
    uint256 hash = blkHeader.GetHash();
    // no need to check hashlen, will always be 64
    int hashlen = hash.size();
    memcpy(result, hash.begin(), hashlen);
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    return hashlen;
}


/** Sign one input of a transaction
    All buffer arguments should be in binary-serialized data.
    The transaction (txData) must contain the COutPoint (tx hash and vout) of all relevant inputs,
    however, it is not necessary to provide the spend script.
    Returns length of returned signature.
*/
SLAPI int SignTxECDSA(const unsigned char *txData,
    int txbuflen,
    unsigned int inputIdx,
    int64_t inputAmount,
    const unsigned char *prevoutScript,
    uint32_t priorScriptLen,
    uint32_t nHashType,
    const unsigned char *keyData,
    unsigned char *result,
    unsigned int resultLen)
{
    DbgAssert(nHashType & BTCBCH_SIGHASH_FORKID, return 0);
    uint8_t sigHashType(nHashType);
    checkSigInit();
    SatoshiTransaction tx;
    result[0] = 0;

    CDataStream ssData((char *)txData, (char *)txData + txbuflen, SER_NETWORK, PROTOCOL_VERSION);
    try
    {
        ssData >> tx;
    }
    catch (const std::exception &)
    {
        set_error(LIBNEXA_ERROR::DECODE_FAILURE, "tx data provided failed to decode\n");
        return 0;
    }
    if (inputIdx >= tx.vin.size())
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "input index is greater than tx vin size\n");
        return 0;
    }
    CScript priorScript(prevoutScript, prevoutScript + priorScriptLen);
    CKey key = LoadKey(keyData);

    size_t nHashedOut = 0;
    uint256 sighash = SignatureHashBitcoinCash(priorScript, tx, inputIdx, sigHashType, inputAmount, &nHashedOut);
    std::vector<unsigned char> sig;
    if (!key.SignECDSA(sighash, sig))
    {
        set_error(LIBNEXA_ERROR::DECODE_FAILURE, "data passed in decoded to an invalid key\n");
        return 0;
    }
    sig.push_back(sigHashType);
    const size_t sigSize = sig.size();
    if (sigSize > std::numeric_limits<int>::max())
    {
        set_error(LIBNEXA_ERROR::RETURN_FAILURE, "number of bytes to be returned cannot be represented by an int\n");
        return -1;
    }
    if (sigSize > resultLen)
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "returned data larger than the result buffer provided\n");
        return 0;
    }
    std::copy(sig.begin(), sig.end(), result);
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    return (int)sigSize;
}

/** Sign one input of a transaction
    All buffer arguments should be in binary-serialized data.
    The transaction (txData) must contain the COutPoint (tx hash and vout) of all relevant inputs,
    however, it is not necessary to provide the spend script.
    Since the sighashtype is appended to the signature, more than 64 bytes should be alloced for the result.
*/
SLAPI int signBchTxOneInputUsingSchnorr(const unsigned char *txData,
    int txbuflen,
    unsigned int inputIdx,
    int64_t inputAmount,
    const unsigned char *prevoutScript,
    uint32_t priorScriptLen,
    uint32_t nHashType,
    const unsigned char *keyData,
    unsigned char *result,
    unsigned int resultLen)
{
    DbgAssert(nHashType & BTCBCH_SIGHASH_FORKID, return 0);
    uint8_t sigHashType = nHashType;
    checkSigInit();
    SatoshiTransaction tx;
    result[0] = 0;

    CDataStream ssData((char *)txData, (char *)txData + txbuflen, SER_NETWORK, PROTOCOL_VERSION);
    try
    {
        ssData >> tx;
    }
    catch (const std::exception &)
    {
        set_error(LIBNEXA_ERROR::DECODE_FAILURE, "tx data provided failed to decode\n");
        return 0;
    }

    if (inputIdx >= tx.vin.size())
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "input index larger than the tx vin size\n");
        return 0;
    }

    CScript priorScript(prevoutScript, prevoutScript + priorScriptLen);
    CKey key = LoadKey(keyData);

    size_t nHashedOut = 0;
    uint256 sighash = SignatureHashBitcoinCash(priorScript, tx, inputIdx, sigHashType, inputAmount, &nHashedOut);
    std::vector<unsigned char> sig;
    if (!key.SignSchnorr(sighash, sig))
    {
        set_error(LIBNEXA_ERROR::DECODE_FAILURE, "data passed in decoded to an invalid key\n");
        return 0;
    }
    // CPubKey pub = key.GetPubKey();
    // p("Sign BCH Schnorr: sig: %s, pubkey: %s sighash: %s\n", HexStr(sig).c_str(),
    //    HexStr(pub.begin(), pub.end()).c_str(), sighash.GetHex().c_str());
    sig.push_back(sigHashType);
    const size_t sigSize = sig.size();
    if (sigSize > std::numeric_limits<int>::max())
    {
        set_error(LIBNEXA_ERROR::RETURN_FAILURE, "number of bytes to be returned cannot be represented by an int\n");
        return -1;
    }
    if (sigSize > resultLen)
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "returned data larger than the result buffer provided\n");
        return 0;
    }
    std::copy(sig.begin(), sig.end(), result);
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    return (int)sigSize;
}

/** Sign one input of a transaction
    All buffer arguments should be in binary-serialized data.
    The transaction (txData) must contain the COutPoint (tx hash and vout) of all relevant inputs,
    however, it is not necessary to provide the spend script.
*/

SLAPI int signTxOneInputUsingSchnorr(const unsigned char *txData,
    int txbuflen,
    unsigned int inputIdx,
    int64_t inputAmount,
    const unsigned char *prevoutScript,
    uint32_t priorScriptLen,
    const unsigned char *hashType,
    unsigned int hashTypeLen,
    const unsigned char *keyData,
    unsigned char *result,
    unsigned int resultLen)
{
    checkSigInit();
    CTransaction tx;
    result[0] = 0;

    std::vector<uint8_t> sigHashVec(hashType, hashType + hashTypeLen);
    SigHashType sigHashType;
    sigHashType.fromBytes(sigHashVec);
    // p("SigHashType vec size: %d, %d, %s(%s): invalid: %d\n", sigHashVec.size(), hashTypeLen,
    //    sigHashType.ToString().c_str(), sigHashType.HexStr().c_str(), sigHashType.isInvalid());

    CDataStream ssData((char *)txData, (char *)txData + txbuflen, SER_NETWORK, PROTOCOL_VERSION);
    try
    {
        ssData >> tx;
    }
    catch (const std::exception &)
    {
        set_error(LIBNEXA_ERROR::DECODE_FAILURE, "tx data provided failed to decode\n");
        return 0;
    }

    if (inputIdx >= tx.vin.size())
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "input index larger than tx vin size\n");
        return 0;
    }

    CScript priorScript(prevoutScript, prevoutScript + priorScriptLen);
    CKey key = LoadKey(keyData);

    size_t nHashedOut = 0;
    uint256 sighash;
    if (!SignatureHashNexa(priorScript, tx, inputIdx, sigHashType, sighash, &nHashedOut))
    {
        return 0;
    }
    std::vector<unsigned char> sig;
    if (!key.SignSchnorr(sighash, sig))
    {
        return 0;
    }
    // p("Sign Schnorr: sig: %s, pubkey: %s sighash: %s\n", HexStr(sig).c_str(), key.GetPubKey().GetHex().c_str(),
    //    sighash.GetHex().c_str());
    sigHashType.appendToSig(sig);
    const size_t sigSize = sig.size();
    if (sigSize > std::numeric_limits<int>::max())
    {
        set_error(LIBNEXA_ERROR::RETURN_FAILURE, "number of bytes to be returned cannot be represented by an int\n");
        return -1;
    }
    if (sigSize > resultLen)
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "returned data larger than the result buffer provided\n");
        return 0;
    }
    std::copy(sig.begin(), sig.end(), result);
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    return (int)sigSize;
}

// deprecated
SLAPI int SignTxSchnorr(const unsigned char *txData,
    int txbuflen,
    unsigned int inputIdx,
    int64_t inputAmount,
    const unsigned char *prevoutScript,
    uint32_t priorScriptLen,
    const unsigned char *hashType,
    unsigned int hashTypeLen,
    const unsigned char *keyData,
    unsigned char *result,
    unsigned int resultLen)
{
    return signTxOneInputUsingSchnorr(txData, txbuflen, inputIdx, inputAmount, prevoutScript, priorScriptLen, hashType,
        hashTypeLen, keyData, result, resultLen);
}

// deprecated
SLAPI int SignHashSchnorr(const unsigned char *hash, const unsigned char *keyData, unsigned char *result)
{
    return signHashSchnorr(hash, keyData, result);
}

/** Sign data via the Schnorr signature algorithm.  hash must be 32 bytes.
    All buffer arguments should be in binary-serialized data.
    The transaction (txData) must contain the COutPoint (tx hash and vout) of all relevant inputs,
    however, it is not necessary to provide the spend script.

    The returned signature will not have a sighashtype byte.
*/
SLAPI int signHashSchnorr(const unsigned char *hash, const unsigned char *keyData, unsigned char *result)
{
    uint256 sighash(hash);
    std::vector<unsigned char> sig;
    checkSigInit();

    CKey key = LoadKey(keyData);

    if (!key.SignSchnorr(sighash, sig))
    {
        set_error(LIBNEXA_ERROR::DECODE_FAILURE, "data passed in decoded to an invalid key\n");
        return 0;
    }
    const size_t sigSize = sig.size();
    if (sigSize > std::numeric_limits<int>::max())
    {
        set_error(LIBNEXA_ERROR::RETURN_FAILURE, "number of bytes to be returned cannot be represented by an int\n");
        return -1;
    }
    if (sigSize > MAX_SIG_LEN) // should never happen for the constant-sized schnorr signatures
    {
        set_error(LIBNEXA_ERROR::INTERNAL_ERROR, "produced a Schnorr signature of an invalid size\n");
        return 0;
    }
    std::copy(sig.begin(), sig.end(), result);
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    return (int)sigSize;
}

SLAPI int signHashSchnorrWithNonce(const unsigned char *hash,
    const unsigned char *keyData,
    const unsigned char *nonce,
    unsigned char *result)
{
    uint256 sighash(hash);
    std::vector<unsigned char> sig;
    checkSigInit();

    CKey key = LoadKey(keyData);

    if (!key.SignSchnorrWithNonce(sighash, nonce, sig))
    {
        set_error(LIBNEXA_ERROR::DECODE_FAILURE, "data passed in decoded to an invalid key\n");
        return 0;
    }
    const size_t sigSize = sig.size();
    if (sigSize > std::numeric_limits<int>::max())
    {
        set_error(LIBNEXA_ERROR::RETURN_FAILURE, "number of bytes to be returned cannot be represented by an int\n");
        return -1;
    }
    if (sigSize > MAX_SIG_LEN) // should never happen for the constant-sized schnorr signatures
    {
        set_error(LIBNEXA_ERROR::INTERNAL_ERROR, "produced a Schnorr signature of an invalid size\n");
        return 0;
    }
    std::copy(sig.begin(), sig.end(), result);
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    return (int)sigSize;
}


static const std::vector<std::string> descriptionTitles = {"ticker", "name", "url", "hash", "decimals"};

SLAPI int parseGroupDescription(const uint8_t *in, const uint64_t inlen, uint8_t *out, uint64_t outlen)
{
    std::vector<std::string> _vDesc;
    CScript script(in, in + inlen);
    if (!GetTokenDescription(script, _vDesc))
    {
        set_error(LIBNEXA_ERROR::DECODE_FAILURE, "failed to get token description from the script provided\n");
        return -1;
    }
    // {} : and ,      (11)
    // 0 is "ticker"    (8)
    // 1 is "name"      (6)
    // 2 is "url"       (5)
    // 3 is "hash"      (6)
    // 4 is "decimals"  (10)

    // for ease of copy, build the json object in a std::string first
    std::string result = "{";
    for (size_t i = 0; i < _vDesc.size(); ++i)
    {
        result = result + "\"" + descriptionTitles[i] + "\":\"" + _vDesc[i] + "\",";
    }
    result.pop_back(); // remove final trailing ","
    result = result + "}";
    const size_t result_size = result.size() + 1; // +1 for \0
    if (result_size > std::numeric_limits<int>::max())
    {
        set_error(LIBNEXA_ERROR::RETURN_FAILURE, "number of bytes to be returned cannot be represented by an int\n");
        return -1;
    }
    // check that out buffer has enough space
    if (outlen < result_size)
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "returned data larger than the result buffer provided\n");
        return -1;
    }
    // copy result into the out buffer
    strncpy((char *)out, result.c_str(), outlen);
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    return (int)result_size;
}


SLAPI int getArgsHashFromScriptPubkey(const uint8_t *spkIn, const uint64_t spkInLen, uint8_t *out, uint64_t outlen)
{
    if (outlen < 20)
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "output buffer must be 20 bytes or larger\n");
        return -1;
    }

    CScript scriptIn(spkIn, spkIn + spkInLen);
    scriptIn.type = ScriptType::TEMPLATE;
    CGroupTokenInfo groupInfo;
    std::vector<uint8_t> templateHash;
    std::vector<uint8_t> argsHash;

    ScriptTemplateError sctError = GetScriptTemplate(scriptIn, &groupInfo, &templateHash, &argsHash, nullptr);
    if (sctError != ScriptTemplateError::OK)
    {
        set_error(LIBNEXA_ERROR::DECODE_FAILURE, "failed to get script template from script provided\n");
        return -1;
    }
    const size_t size_argsHash = argsHash.size();
    if (size_argsHash > std::numeric_limits<int>::max())
    {
        set_error(LIBNEXA_ERROR::RETURN_FAILURE, "number of bytes to be returned cannot be represented by an int\n");
        return -1;
    }
    if (size_argsHash > outlen)
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "returned data larger than the result buffer provided\n");
        return -1;
    }
    std::copy(argsHash.begin(), argsHash.end(), out);
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    return (int)size_argsHash;
}

SLAPI int getTemplateHashFromScriptPubkey(const uint8_t *spkIn, const uint64_t spkInLen, uint8_t *out, uint64_t outlen)
{
    if (outlen < 20)
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "output buffer must be larger than 20 bytes\n");
        return -1;
    }

    CScript scriptIn(spkIn, spkIn + spkInLen);
    scriptIn.type = ScriptType::TEMPLATE;
    CGroupTokenInfo groupInfo;
    std::vector<uint8_t> templateHash;
    std::vector<uint8_t> argsHash;

    ScriptTemplateError sctError = GetScriptTemplate(scriptIn, &groupInfo, &templateHash, &argsHash, nullptr);
    if (sctError != ScriptTemplateError::OK)
    {
        set_error(LIBNEXA_ERROR::DECODE_FAILURE, "failed to get script template from script provided\n");
        return -1;
    }
    const size_t size_templateHash = templateHash.size();
    if (size_templateHash > std::numeric_limits<int>::max())
    {
        set_error(LIBNEXA_ERROR::RETURN_FAILURE, "number of bytes to be returned cannot be represented by an int\n");
        return -1;
    }
    if (size_templateHash > outlen)
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "returned data larger than the result buffer provided\n");
        return -1;
    }
    std::copy(templateHash.begin(), templateHash.end(), out);
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    return (int)size_templateHash;
}

SLAPI int getGroupTokenInfoFromScriptPubkey(const uint8_t *spkIn,
    const uint64_t spkInLen,
    uint8_t *grpId,
    const uint64_t grpIdlimit,
    uint64_t *grpFlags,
    int64_t *grpAmount)
{
    CScript scriptIn(spkIn, spkIn + spkInLen);
    scriptIn.type = ScriptType::TEMPLATE;
    CGroupTokenInfo groupInfo;
    std::vector<uint8_t> templateHash;
    std::vector<uint8_t> argsHash;

    ScriptTemplateError sctError = GetScriptTemplate(scriptIn, &groupInfo, &templateHash, &argsHash, nullptr);
    if (sctError != ScriptTemplateError::OK)
    {
        set_error(LIBNEXA_ERROR::DECODE_FAILURE, "failed to get script template from script provided\n");
        return -1;
    }

    const size_t grpIdSize = groupInfo.associatedGroup.bytes().size();
    if (grpIdSize > std::numeric_limits<int>::max())
    {
        set_error(LIBNEXA_ERROR::RETURN_FAILURE, "number of bytes to be returned cannot be represented by an int\n");
        return -1;
    }
    if (grpIdSize > grpIdlimit)
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "returned data larger than the result buffer provided\n");
        return -1;
    }
    std::copy(groupInfo.associatedGroup.bytes().begin(), groupInfo.associatedGroup.bytes().end(), grpId);
    *grpFlags = (uint64_t)groupInfo.controllingGroupFlags;
    *grpAmount = groupInfo.quantity;
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    return (int)grpIdSize;
}

SLAPI int signMessage(const unsigned char *message,
    unsigned int msgLen,
    const unsigned char *secret,
    unsigned int secretLen,
    unsigned char *result,
    unsigned int resultLen)
{
    if (secretLen != 32)
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "secret must be 32 bytes\n");
        return 0;
    }

    checkSigInit();

    CKey key = LoadKey((const unsigned char *)secret);

    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic << std::vector<unsigned char>(message, message + msgLen);

    uint256 msgHash = ss.GetHash();
    // __android_log_print(ANDROID_LOG_INFO, APPNAME, "signing msgHash %s\n", msgHash.GetHex().c_str());
    std::vector<unsigned char> vchSig;
    if (!key.SignCompact(msgHash, vchSig)) // signing will only fail if the key is bogus
    {
        set_error(LIBNEXA_ERROR::DECODE_FAILURE, "data passed in decoded to an invalid key\n");
        return 0;
    }
    const size_t sz = vchSig.size();
    // check that the size of a returned sig can be represented properly as an int, it should always be
    // CPubKey::COMPACT_SIGNATURE_SIZE
    static_assert(CPubKey::COMPACT_SIGNATURE_SIZE < std::numeric_limits<int>::max());
    if (sz != CPubKey::COMPACT_SIGNATURE_SIZE)
    {
        // this will only happen if std::vector::resize() is broken
        // or there is an implementation error in libsecp256k1 that is returning bad
        // ECDSA sigs
        set_error(LIBNEXA_ERROR::INTERNAL_ERROR, "produced an ECDSA signature of an invalid size\n");
        return -1;
    }
    if (sz > resultLen)
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "returned data larger than the result buffer provided\n");
        return 0;
    }

    // __android_log_print(ANDROID_LOG_INFO, APPNAME, "signing sigSize %d data %s\n", vchSig.size(),
    // GetHex(vchSig.begin(), vchSig.size()).c_str());
    memcpy(result, vchSig.data(), sz);
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    return (int)sz;
}

SLAPI int capdSolve(const unsigned char *message, unsigned int msgLen, unsigned char *result, unsigned int resultLen)
{
    CDataStream dataStrm((char *)message, (char *)message + msgLen, SER_NETWORK, PROTOCOL_VERSION);
    CapdMsg msg;
    try
    {
        dataStrm >> msg;
    }
    catch (const std::exception &)
    {
        p("libnexa capd deserialize error");
        set_error(LIBNEXA_ERROR::DECODE_FAILURE, "data passed in failed to decode to a capd message\n");
        return -1;
    }
    // one year of seconds.  This is not going to work because Solve interprets this as an offset from "now" and changes
    // the message time field.  But we do not return the changed time.  Callers should manually do this if they
    // want an offset.  Since such an ancient message is unrelayable this must be an invalid capd message anyway.
    if (msg.createTime < 31536000)
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "message create time must be at least 31536000\n");
        return -2;
    }
    bool solved = msg.Solve(msg.createTime);
    if (solved)
    {
        const size_t sz = msg.nonce.size();
        if (sz > std::numeric_limits<int>::max())
        {
            set_error(
                LIBNEXA_ERROR::RETURN_FAILURE, "number of bytes to be returned cannot be represented by an int\n");
            return -1;
        }
        if (sz > resultLen)
        {
            set_error(LIBNEXA_ERROR::INVALID_ARG, "returned data larger than the result buffer provided\n");
            return 0;
        }
        memcpy(result, msg.nonce.data(), sz);
        set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
        return (int)sz;
    }
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    return 0;
}

SLAPI int capdCheck(const unsigned char *message, unsigned int msgLen)
{
    CDataStream dataStrm((char *)message, (char *)message + msgLen, SER_NETWORK, PROTOCOL_VERSION);
    CapdMsg msg;
    try
    {
        dataStrm >> msg;
    }
    catch (const std::exception &)
    {
        p("libnexa capd deserialize error");
        return -1;
    }
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    return msg.DoesPowMeetTarget();
}

SLAPI int capdSetPowTargetHarderThanPriority(const unsigned char *message,
    const unsigned int msgLen,
    const double priority,
    unsigned char *result,
    const unsigned int resultLen)
{
    CDataStream dataStrm((char *)message, (char *)message + msgLen, SER_NETWORK, PROTOCOL_VERSION);
    CapdMsg msg;
    try
    {
        dataStrm >> msg;
    }
    catch (const std::exception &)
    {
        p("libnexa capd deserialize error");
        return -1;
    }
    msg.SetPowTargetHarderThanPriority(priority);
    CDataStream returnStream(SER_NETWORK, PROTOCOL_VERSION);
    try
    {
        returnStream << msg;
    }
    catch (const std::exception &)
    {
        p("libnexa capd serialize error");
        return -2;
    }
    const size_t retSize = returnStream.size();
    if (retSize > resultLen)
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "returned data larger than the result buffer provided\n");
        return -3;
    }
    std::memcpy(result, returnStream.data(), retSize);
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    return (int)retSize;
}

SLAPI int capdHash(const unsigned char *message, unsigned int msgLen, unsigned char *result, unsigned int resultLen)
{
    CDataStream dataStrm((char *)message, (char *)message + msgLen, SER_NETWORK, PROTOCOL_VERSION);
    CapdMsg msg;
    try
    {
        dataStrm >> msg;
    }
    catch (const std::exception &)
    {
        p("libnexa capd deserialize error");
        set_error(LIBNEXA_ERROR::DECODE_FAILURE, "data passed in failed to decode to a capd message\n");
        return 0;
    }
    uint256 hash = msg.CalcHash();
    const size_t sz = hash.size();
    if (sz > std::numeric_limits<int>::max())
    {
        set_error(LIBNEXA_ERROR::RETURN_FAILURE, "number of bytes to be returned cannot be represented by an int\n");
        return -1;
    }
    if (sz > resultLen)
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "returned data larger than the result buffer provided\n");
        return 0;
    }
    memcpy(result, hash.begin(), sz);
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    return (int)sz;
}

SLAPI int verifyMessage(const unsigned char *message,
    unsigned int msgLen,
    const unsigned char *addr,
    unsigned int addrLen,
    const unsigned char *sig,
    unsigned int sigLen,
    unsigned char *result,
    unsigned int resultLen)
{
    if (addrLen != 20)
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "address must be 20 bytes\n");
        return 0;
    }

    checkSigInit();

    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic << std::vector<unsigned char>(message, message + msgLen);
    uint256 msgHash = ss.GetHash();
    //__android_log_print(ANDROID_LOG_INFO, APPNAME, "verifying msgHash %s\n", msgHash.GetHex().c_str());
    //__android_log_print(ANDROID_LOG_INFO, APPNAME, "verifying sigSize %d data %s\n", sig.size, GetHex(sig.data,
    // sig.size).c_str());

    CPubKey pubkey;
    std::vector<unsigned char> sigv(sig, sig + sigLen);
    if (!pubkey.RecoverCompact(msgHash, sigv))
    {
        set_error(LIBNEXA_ERROR::DECODE_FAILURE, "could not recover pubkey from msg and sig data provided\n");
        return 0;
    }

    CKeyID pkAddr = pubkey.GetID();
    CKeyID passedAddr = CKeyID(uint160(addr));
    //__android_log_print(ANDROID_LOG_INFO, APPNAME, "pkAddr %s\n", pkAddr.GetHex().c_str());
    //__android_log_print(ANDROID_LOG_INFO, APPNAME, "passedAddr %s\n", passedAddr.GetHex().c_str());
    const size_t sz = pubkey.size();
    if (sz > std::numeric_limits<int>::max())
    {
        set_error(LIBNEXA_ERROR::RETURN_FAILURE, "number of bytes to be returned cannot be represented by an int\n");
        return -1;
    }
    if (sz > resultLen)
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "returned data larger than the result buffer provided\n");
        return 0;
    }
    memcpy(result, pubkey.begin(), sz);
    const int res = (int)sz;
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    if (pkAddr == passedAddr)
    {
        return res;
    }
    else
    {
        return -res;
    }
}

SLAPI bool verifyDataSchnorr(const unsigned char *message,
    unsigned int msgLen,
    const unsigned char *pubkey,
    int lenPubkey,
    const unsigned char *sig) // sig must be 64 bytes
{
    checkSigInit();
    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic << std::vector<unsigned char>(message, message + msgLen);
    uint256 messageHash = ss.GetHash();
    CPubKey pk(&pubkey[0], &pubkey[0] + lenPubkey);
    // If the pubkey is not valid, VerifySchnorr will return false, and an invalid pubkey can never
    // have signed a message.  While for debugging it might be nice to check and return an error
    // this is less efficient, but is placed here commented out for dev debugging.
    // if (!pk.isFullyValid())
    //     set_error(LIBNEXA_ERROR::INVALID_ARG, "bad pubkey\n");
    std::vector<uint8_t> sigv(sig, sig + 64);
    return pk.VerifySchnorr(messageHash, sigv);
}

SLAPI bool verifyHashSchnorr(const unsigned char *hash,
    const unsigned char *pubkey,
    int lenPubkey,
    const unsigned char *sig) // sig must be 64 bytes
{
    checkSigInit();
    uint256 messageHash(hash);
    CPubKey pk(&pubkey[0], &pubkey[0] + lenPubkey);
    // If the pubkey is not valid, VerifySchnorr will return false, and an invalid pubkey can never
    // have signed a message.  While for debugging it might be nice to check and return an error
    // this is less efficient, but is placed here commented out for dev debugging.
    // if (!pk.isFullyValid())
    //     set_error(LIBNEXA_ERROR::INVALID_ARG, "bad pubkey\n");
    std::vector<uint8_t> sigv(sig, sig + 64);
    return pk.VerifySchnorr(messageHash, sigv);
}


SLAPI bool verifyBlockHeader(int chainSelector, const unsigned char *serializedHeader, int serLen)
{
    checkSigInit();
    const CChainParams *cp = GetChainParams(static_cast<ChainSelector>(chainSelector));
    if (cp == nullptr)
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "invalid chain selector\n");
        return false;
    }
    CDataStream dataStrm((char *)serializedHeader, (char *)serializedHeader + serLen, SER_NETWORK, PROTOCOL_VERSION);
    CBlockHeader blkHeader;
    try
    {
        dataStrm >> blkHeader;
    }
    catch (const std::exception &)
    {
        set_error(LIBNEXA_ERROR::DECODE_FAILURE, "block header data failed to decode\n");
        return false;
    }
    CValidationState state;
    bool result = CheckBlockHeader(cp->GetConsensus(), blkHeader, state, true);
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    return result;
}


SLAPI int encodeCashAddr(int chainSelector, int typ, const unsigned char *data, int len, char *result, int resultMaxLen)
{
    CTxDestination dst = CNoDestination();

    if ((typ == PayAddressTypeP2PKH) || (typ == PayAddressTypeP2SH))
    {
        if (len != 20)
        {
            set_error(LIBNEXA_ERROR::INVALID_ARG, "type was p2pkh or p2sh but the address len was not 20 bytes\n");
            return 0;
        }
        uint160 tmp((const uint8_t *)data);
        if (typ == PayAddressTypeP2PKH)
        {
            dst = CKeyID(tmp);
        }
        else if (typ == PayAddressTypeP2SH)
        {
            dst = CScriptID(tmp);
        }
    }
    else if (typ == PayAddressTypeTEMPLATE)
    {
        // A PayAddress contains a serialized script
        // Really the "right" way to do this is to just encode the exact bytes without stripping off
        // the serialization and putting it back on but that does not work with the "Destination" code.
        // As it is, any additional parts (currently none are defined) to the PayAddress will be removed
        ScriptTemplateDestination st;
        std::vector<unsigned char> vec(data, data + len);
        CDataStream ssData(vec, SER_NETWORK, PROTOCOL_VERSION);
        ssData >> st;
        dst = st;
    }
    else
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "invalid addres type provided\n");
        return 0;
    }

    const CChainParams *cp = GetChainParams((ChainSelector)chainSelector);
    if (cp == nullptr)
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "invalid chain selector\n");
        return 0;
    }
    std::string addrAsStr(EncodeCashAddr(dst, *cp));
    const int sz = addrAsStr.size();
    if (sz > std::numeric_limits<int>::max())
    {
        set_error(LIBNEXA_ERROR::RETURN_FAILURE, "number of bytes to be returned cannot be represented by an int\n");
        return -1;
    }
    if (sz >= resultMaxLen)
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "returned data larger than the result buffer provided\n");
        return -sz;
    }
    strncpy(result, addrAsStr.c_str(), sz);
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    return (int)sz;
}


SLAPI int decodeCashAddr(int chainSelector, const char *addrstr, unsigned char *result, int resultMaxLen)
{
    const CChainParams *cp = GetChainParams((ChainSelector)chainSelector);
    if (cp == nullptr)
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "invalid chain selector\n");
        return 0;
    }
    CTxDestination dst = DecodeCashAddr(addrstr, *cp);
    std::vector<unsigned char> resultv;
    std::visit(PubkeyExtractor(resultv, *cp), dst);
    const int sz = resultv.size();
    if (sz > std::numeric_limits<int>::max())
    {
        set_error(LIBNEXA_ERROR::RETURN_FAILURE, "number of bytes to be returned cannot be represented by an int\n");
        return -1;
    }
    if (sz > resultMaxLen)
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "returned data larger than the result buffer provided\n");
        return -sz;
    }
    memcpy(result, &resultv[0], sz);
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    return (int)sz;
}

SLAPI int decodeCashAddrContent(int chainSelector,
    const char *addrstr,
    unsigned char *result,
    int resultMaxLen,
    unsigned char *type)
{
    const CChainParams *cp = GetChainParams((ChainSelector)chainSelector);
    if (cp == nullptr)
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "invalid chain selector\n");
        return 0;
    }
    CashAddrContent content = DecodeCashAddrContent(addrstr, *cp);
    const int hash_size = content.hash.size();
    if (hash_size > std::numeric_limits<int>::max())
    {
        set_error(LIBNEXA_ERROR::RETURN_FAILURE, "number of bytes to be returned cannot be represented by an int\n");
        return -1;
    }
    if (hash_size > resultMaxLen)
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "returned data larger than the result buffer provided\n");
        return -hash_size;
    }
    memcpy(result, &content.hash[0], hash_size);
    memcpy(type, &content.type, 1);
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    return (int)hash_size;
}

SLAPI int serializeScript(const uint8_t *script, const unsigned int lenScript, uint8_t *result, int resultMaxLen)
{
    std::vector<uint8_t> vec(script, script + lenScript);
    CDataStream ssData(SER_NETWORK, PROTOCOL_VERSION);
    ssData << vec;
    const size_t data_size = ssData.size();
    if (data_size > std::numeric_limits<int>::max())
    {
        set_error(LIBNEXA_ERROR::RETURN_FAILURE, "number of bytes to be returned cannot be represented by an int\n");
        return -1;
    }
    std::memcpy(result, ssData.data(), data_size);
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    return (int)data_size;
}

// TODO - add support for creating a script template destination that includes a specific group / amount
SLAPI int pubkeyToScriptTemplate(const unsigned char *pubkey, int lenPubkey, unsigned char *result, int resultMaxLen)
{
    // CScript P2pktOutput(const CPubKey &pubkey, const CGroupTokenID &group = NoGroup, CAmount grpQuantity = 0);
    const CScript scriptTemplate = P2pktOutput(CPubKey(&pubkey[0], &pubkey[0] + lenPubkey));
    const int scriptTemplateSize = scriptTemplate.size();
    if (scriptTemplateSize > std::numeric_limits<int>::max())
    {
        set_error(LIBNEXA_ERROR::RETURN_FAILURE, "number of bytes to be returned cannot be represented by an int\n");
        return -1;
    }
    if (scriptTemplateSize > resultMaxLen)
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "returned data larger than the result buffer provided\n");
        return -scriptTemplateSize;
    }
    std::memcpy(result, &scriptTemplate[0], scriptTemplateSize);
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    return (int)scriptTemplateSize;
}


SLAPI int groupIdToAddr(int chainSelector, const unsigned char *data, int len, char *result, int resultMaxLen)
{
    if (len < 32)
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "input data < 32 bytes\n");
        return -len;
    }
    if (len > 520)
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "input data > 520 bytes\n");
        return -len;
    }
    CGroupTokenID grp((uint8_t *)data, len);
    const CChainParams *cp = GetChainParams((ChainSelector)chainSelector);
    if (cp == nullptr)
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "invalid chain selector\n");
        return 0;
    }
    std::string addrAsStr(EncodeGroupToken(grp, *cp));
    const int sz = addrAsStr.size();
    if (sz > std::numeric_limits<int>::max())
    {
        set_error(LIBNEXA_ERROR::RETURN_FAILURE, "number of bytes to be returned cannot be represented by an int\n");
        return -1;
    }
    if (sz >= resultMaxLen)
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "returned data larger than the result buffer provided\n");
        return -sz;
    }
    strncpy(result, addrAsStr.c_str(), resultMaxLen);
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    return (int)sz;
}


SLAPI int groupIdFromAddr(int chainSelector, const char *addrstr, unsigned char *result, int resultMaxLen)
{
    const CChainParams *cp = GetChainParams((ChainSelector)chainSelector);
    if (cp == nullptr)
    {
        return 0;
        set_error(LIBNEXA_ERROR::INVALID_ARG, "invalid chain selector\n");
    }
    CGroupTokenID gid = DecodeGroupToken(addrstr, *cp);
    const size_t size = gid.bytes().size();
    if (size < 32) // min group id size
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "input data < 32 bytes\n");
        return -size;
    }
    if (size > 520) // max group id size
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "input data > 520 bytes\n");
        return -size;
    }
    if (size > (unsigned int)resultMaxLen)
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "returned data larger than the result buffer provided\n");
        return -size;
    }
    memcpy(result, &gid.bytes().front(), size);
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    return size;
}


SLAPI int decodeWifPrivateKey(int chainSelector, const char *secretWIF, unsigned char *result, int resultMaxLen)
{
    const CChainParams *cp = GetChainParams(static_cast<ChainSelector>(chainSelector));
    if (cp == nullptr)
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "invalid chain selector\n");
        return 0;
    }
    CBitcoinSecret secret;
    const bool ok = secret.SetString(*cp, secretWIF);
    if (!ok)
    {
        return 0;
    }
    const CKey key = secret.GetKey();
    if (!key.IsValid())
    {
        return 0;
    }
    const size_t sz = key.size();
    if (sz > std::numeric_limits<int>::max())
    {
        set_error(LIBNEXA_ERROR::RETURN_FAILURE, "number of bytes to be returned cannot be represented by an int\n");
        return -1;
    }
    if (sz > (unsigned int)resultMaxLen)
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "returned data larger than the result buffer provided\n");
        return -sz;
    }
    memcpy(result, static_cast<const uint8_t *>(key.begin()), sz);
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    return (int)sz;
}

// result must be 32 bytes
SLAPI void sha256(const unsigned char *data, unsigned int len, unsigned char *result)
{
    CSHA256 sha;
    sha.Write((const unsigned char *)data, len);
    sha.Finalize((unsigned char *)result);
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
}


// result must be 32 bytes
SLAPI void hash256(const unsigned char *data, unsigned int len, unsigned char *result)
{
    CHash256 hash;
    hash.Write((const unsigned char *)data, len);
    hash.Finalize((unsigned char *)result);
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
}


// result must be 20 bytes
SLAPI void hash160(const unsigned char *data, unsigned int len, unsigned char *result)
{
    CHash160 hash;
    hash.Write((const unsigned char *)data, len);
    hash.Finalize((unsigned char *)result);
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
}

// result buffer length must be len (or more) bytes, secret must be 32 bytes, iv must be 16 or more bytes, len must be a
// multiple of 16
SLAPI int cryptAES256CBC(unsigned int encrypt,
    const unsigned char *data,
    unsigned int len,
    const unsigned char *secret,
    const unsigned char *iv,
    unsigned char *result)
{
    int nBytes = 0;
    if (encrypt == 1)
    {
        AES256CBCEncrypt crypter(secret, iv, false);
        nBytes = crypter.Encrypt(data, len, result);
    }
    else if (encrypt == 0)
    {
        AES256CBCDecrypt crypter(secret, iv, false);
        nBytes = crypter.Decrypt(data, len, result);
    }
    else
    {
        return -1;
    }
    if (nBytes == 0)
    {
        return -2;
    }
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    return len;
}

/** Get work from nbits */
SLAPI void getWorkFromDifficultyBits(unsigned long int nBits, unsigned char *result)
{
    arith_uint256 work = GetWorkForDifficultyBits((uint32_t)nBits);
    uint256 ui = ArithToUint256(work);
    ui.reverse();
    memcpy(result, ui.begin(), 32);
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
}

SLAPI unsigned int getDifficultyBitsFromWork(unsigned char *work256Bits)
{
    uint256 ui(work256Bits);
    arith_uint256 work = UintToArith256(ui);
    // we need to compute ((2**256)/x) - 1
    // ~x (bitflip) is mathematically (2**256) - 1 - x
    // ~x/x is (2**256)/x - 1/x - x/x or (2**256)/x - 1 because 1/x is 0 in integral math
    work = ~work / work;
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    return work.GetCompact(false);
}


/** Create a bloom filter */
SLAPI int createBloomFilter(const unsigned char *data,
    unsigned int len,
    double falsePosRate,
    int capacity,
    int maxSize,
    int flags,
    int tweak,
    unsigned char *result)
{
    if (!result)
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "result was a null pointer\n");
        return 0; // failed
    }
    if (capacity < 10)
    {
        capacity = 10; // sanity check the capacity
    }
    if (falsePosRate < 0)
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "false positive rate less than 0.0\n");
        return 0;
    }
    if (falsePosRate > 1.0)
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "false positive rate greater than 1.0\n");
        return 0;
    }

    int maxx = (capacity > (int)len) ? capacity : len;
    CBloomFilter bloom(maxx, falsePosRate, tweak, flags, maxSize);

    const unsigned char *elemData = data;
    while (elemData - data < len)
    {
        int elemLen = *elemData; // first byte is the length of the element
        elemData++;
        bloom.insert(std::vector<unsigned char>(elemData, elemData + elemLen));
        elemData += elemLen;
    }

    CDataStream serializer(SER_NETWORK, PROTOCOL_VERSION);
    serializer << bloom;
    //__android_log_print(ANDROID_LOG_INFO, APPNAME, "Bloom size: %d Bloom serialized size: %d numAddrs: %d\n",
    //    (unsigned int)bloom.vDataSize(), (unsigned int)serializer.size(), (unsigned int)len);
    const size_t ret = serializer.size();
    if (ret > std::numeric_limits<int>::max())
    {
        set_error(LIBNEXA_ERROR::RETURN_FAILURE, "number of bytes to be returned cannot be represented by an int\n");
        return -1;
    }
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    memcpy(result, serializer.data(), ret);
    return (int)ret;
}

// Since partial Merkle blocks are just trees of hashes, this structure is the same for Nexa and BCH
SLAPI int extractFromMerkleBlock(int numTxes,
    const unsigned char *merkleProofPath,
    int mppLen,
    const unsigned char *hashIn,
    int numHashes,
    unsigned char *result,
    int resultLen)
{
    const unsigned int HASH_LEN = 32;
    CDecodablePartialMerkleTree tree(numTxes, merkleProofPath, mppLen);
    // Copy the hashes out of the array into the PartialMerkleTree
    auto &hashes = tree.accessHashes();
    hashes.resize(numHashes);
    for (size_t i = 0; i < (unsigned int)numHashes; i++)
    {
        hashes[i] = uint256(hashIn + (i * HASH_LEN));
    }

    std::vector<uint256> matches;
    std::vector<unsigned int> matchIndexes;
    uint256 merkleRoot = tree.ExtractMatches(matches, matchIndexes);

    unsigned char *dest = result;
    unsigned char *end = result + resultLen;

    const size_t ret = matches.size() + 1;
    if (ret > std::numeric_limits<int>::max())
    {
        set_error(LIBNEXA_ERROR::RETURN_FAILURE, "number of bytes to be returned cannot be represented by an int\n");
        return -1;
    }
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    if (dest + HASH_LEN > end)
    {
        return (int)ret;
    }

    memcpy(dest, merkleRoot.begin(), HASH_LEN);

    dest += HASH_LEN;
    if (dest > end)
    {
        return (int)ret;
    }

    // Fill the rest with transaction hashes
    for (size_t i = 0; i < matches.size(); i++)
    {
        memcpy(dest, matches[i].begin(), HASH_LEN);
        dest += HASH_LEN;
        if (dest > end)
        {
            return (int)ret;
        }
    }
    return (int)ret;
}

#ifdef IOS
#include <Security/Security.h>
// Implement in Android by calling into the java SecureRandom implementation.
// You must provide this Java API
SLAPI int RandomBytes(unsigned char *buf, int num)
{
    int rc = SecRandomCopyBytes(kSecRandomDefault, num, buf);
    if (rc != 0)
        return 0;
    return num;
}
// Implement APIs normally provided by random.cpp
void GetRandBytes(unsigned char *buf, int num)
{
    // it would be dangerous to return if we aren't getting random bytes
    while (1)
    {
        int ret = RandomBytes(buf, num);
        if (ret == num)
            return;
        sleep(100);
    }
}
void GetStrongRandBytes(unsigned char *buf, int num)
{
    // it would be dangerous to return if we aren't getting random bytes
    while (1)
    {
        int ret = RandomBytes(buf, num);
        if (ret == num)
            return;
        sleep(100);
    }
}
#endif // IOS

#if !defined(ANDROID) && !defined(IOS)
/** Return random bytes from cryptographically acceptable random sources */
SLAPI int RandomBytes(unsigned char *buf, int num)
{
    GetStrongRandBytes(buf, num);
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    return num;
}

#endif // !defined(JAVA) && !defined(ANDROID) && !defined(IOS)
