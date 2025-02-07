// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "libnexa.h"
#include "libnexa_common.h"
#include "libnexa_script_machine.h"


#ifdef ANDROID // Workaround to fix gradle build
#define SECP256K1_INLINE inline
#endif // ANDROID

#if defined(ANDROID) // log sighash calculations
#include <android/log.h>
#define p(...) __android_log_print(ANDROID_LOG_DEBUG, "libnexa", __VA_ARGS__)
#elif defined(JAVA)
#define p(...) // tinyformat::format(std::cout, __VA_ARGS__)
#else
#define p(...) // tinyformat::format(std::cout, __VA_ARGS__)
#endif

#if defined(JAVA)
#include <jni.h>

// On windows we need to set JNI calls to be exported from the DLL
#ifdef __MINGW32__
#undef JNIEXPORT
#define JNIEXPORT __declspec(dllexport)
#else
#ifdef __MINGW64__
#undef JNIEXPORT
#define JNIEXPORT __declspec(dllexport)
#endif // __MINGW64__
#endif // else cond after if __MINGW32__

// in headervalidation.cpp
bool CheckBlockHeader(const Consensus::Params &consensusParams,
    const CBlockHeader &block,
    CValidationState &state,
    bool fCheckPOW = true);

#define APPNAME "BU.wallet.libnexa"

class ByteArrayAccessor
{
public:
    JNIEnv *env;
    jbyteArray &obj;
    uint8_t *data;
    size_t size;

    std::vector<uint8_t> vec() { return std::vector<uint8_t>(data, data + size); }
    ByteArrayAccessor(JNIEnv *e, jbyteArray &arg) : env(e), obj(arg)
    {
        size = env->GetArrayLength(obj);
        data = (uint8_t *)env->GetByteArrayElements(obj, nullptr);
    }

    ~ByteArrayAccessor()
    {
        size = 0;
        if (data)
            env->ReleaseByteArrayElements(obj, (jbyte *)data, 0);
    }
};

// credit: https://stackoverflow.com/questions/41820039/jstringjni-to-stdstringc-with-utf8-characters
std::string toString(JNIEnv *env, jstring jStr)
{
    if (!jStr)
        return "";

    const jclass stringClass = env->GetObjectClass(jStr);
    const jmethodID getBytes = env->GetMethodID(stringClass, "getBytes", "(Ljava/lang/String;)[B");
    const jbyteArray stringJbytes = (jbyteArray)env->CallObjectMethod(jStr, getBytes, env->NewStringUTF("UTF-8"));

    size_t length = (size_t)env->GetArrayLength(stringJbytes);
    jbyte *pBytes = env->GetByteArrayElements(stringJbytes, nullptr);

    std::string ret = std::string((char *)pBytes, length);
    env->ReleaseByteArrayElements(stringJbytes, pBytes, JNI_ABORT);

    env->DeleteLocalRef(stringJbytes);
    env->DeleteLocalRef(stringClass);
    return ret;
}

jint triggerJavaIllegalStateException(JNIEnv *env, const char *message)
{
    jclass exc = env->FindClass("java/lang/IllegalStateException");
    if (nullptr == exc)
        return 0;
    return env->ThrowNew(exc, message);
}

/** converts a arith_uint256 into something that java BigInteger can grab */
jbyteArray encodeUint256(JNIEnv *env, arith_uint256 value)
{
    const size_t size = 256 / 8;
    jbyteArray result = env->NewByteArray(size);
    if (result != nullptr)
    {
        jbyte *data = env->GetByteArrayElements(result, nullptr);
        if (data != nullptr)
        {
            int i;
            for (i = (int)(size - 1); i >= 0; i--)
            {
                data[i] = (jbyte)(value.GetLow64() & 0xFF);
                value >>= 8;
            }
            env->ReleaseByteArrayElements(result, data, 0);
        }
    }
    return result;
}

jbyteArray makeJByteArray(JNIEnv *env, const uint256 &hash)
{
    jbyteArray bArray = env->NewByteArray(256 / 8);
    jbyte *dest = env->GetByteArrayElements(bArray, 0);
    const int8_t *buf = (const int8_t *)hash.begin();
    memcpy(dest, buf, 256 / 8);
    env->ReleaseByteArrayElements(bArray, dest, 0); // release my changes into the jbyteArray
    return bArray;
}

jbyteArray makeJByteArray(JNIEnv *env, const uint8_t *buf, const size_t size)
{
    jbyteArray bArray = env->NewByteArray(size);
    jbyte *dest = env->GetByteArrayElements(bArray, 0);
    memcpy(dest, buf, size);
    env->ReleaseByteArrayElements(bArray, dest, 0);
    return bArray;
}

jbyteArray makeJByteArray(JNIEnv *env, const std::string &buf)
{
    jbyteArray bArray = env->NewByteArray(buf.size());
    jbyte *dest = env->GetByteArrayElements(bArray, 0);
    memcpy(dest, buf.c_str(), buf.size());
    env->ReleaseByteArrayElements(bArray, dest, 0);
    return bArray;
}

jbyteArray makeJByteArray(JNIEnv *env, std::vector<unsigned char> &buf)
{
    jbyteArray bArray = env->NewByteArray(buf.size());
    jbyte *dest = env->GetByteArrayElements(bArray, 0);
    memcpy(dest, &buf[0], buf.size());
    env->ReleaseByteArrayElements(bArray, dest, 0);
    return bArray;
}

extern "C" JNIEXPORT jboolean JNICALL Java_org_nexa_libnexakotlin_Native_initializeLibNexa(JNIEnv *env, jobject ths)
{
    // A chain selection parameter should be part of every libnexa API, but the underlying code still
    // requires a default to be set so pick Nexa as the default.
    SelectParams("nexa");
    checkSigInit();
    return true;
}

extern "C" JNIEXPORT jint JNICALL Java_org_nexa_libnexakotlin_Native_libnexaVersion(JNIEnv *env, jobject ths)
{
    return LIBNEXA_VERSION;
}

extern "C" JNIEXPORT jstring JNICALL Java_org_nexa_libnexakotlin_Native_encode64(JNIEnv *env,
    jobject ths,
    jbyteArray jdata)
{
    ByteArrayAccessor data(env, jdata);
    auto dataAsStr = EncodeBase64(data.data, data.size);
    return env->NewStringUTF(dataAsStr.c_str());
}

extern "C" JNIEXPORT jbyteArray JNICALL Java_org_nexa_libnexakotlin_Native_decode64(JNIEnv *env,
    jobject ths,
    jstring jdata)
{
    std::string data = toString(env, jdata);
    bool invalid = true;
    auto dataBytes = DecodeBase64(data.c_str(), &invalid);
    if (invalid)
    {
        triggerJavaIllegalStateException(env, "bad encoding");
        return jbyteArray();
    }
    return makeJByteArray(env, dataBytes);
}

/// libnexa-inconsistency: no Bin2Hex equivalent

// many of the args are long so that the hardened selectors (i.e. 0x80000000) are not negative
extern "C" JNIEXPORT jbyteArray JNICALL Java_org_nexa_libnexakotlin_Native_deriveHd44ChildKey(JNIEnv *env,
    jobject ths,
    jbyteArray masterSecretBytes,
    jlong purpose,
    jlong coinType,
    jlong account,
    jint change,
    jint index)
{
    size_t mslen = env->GetArrayLength(masterSecretBytes);
    if ((mslen < 16) || (mslen > 64))
    {
        triggerJavaIllegalStateException(env, "key derivation failure -- master secret is incorrect length");
        return nullptr;
    }

    jbyte *msdata = env->GetByteArrayElements(masterSecretBytes, 0);

    CKey secret;
    Hd44DeriveChildKey((unsigned char *)msdata, mslen, purpose, coinType, account, change, index, secret, nullptr);

    jbyteArray bArray = env->NewByteArray(32);
    jbyte *data = env->GetByteArrayElements(bArray, 0);
    if (secret.size() != 32)
    {
        triggerJavaIllegalStateException(env, "key derivation failure -- derived secret is incorrect length");
        return nullptr;
    }
    memcpy(data, secret.begin(), 32);
    env->ReleaseByteArrayElements(bArray, data, 0);
    return bArray;
}

/** Given a private key, return its corresponding public key */
extern "C" JNIEXPORT jbyteArray JNICALL Java_org_nexa_libnexakotlin_Native_getPubKey(JNIEnv *env,
    jobject ths,
    jbyteArray arg)
{
    size_t len = env->GetArrayLength(arg);
    jbyte *data = env->GetByteArrayElements(arg, nullptr);

    if (len != 32)
    {
        std::stringstream err;
        err << "GetPubKey: Incorrect length for argument 'secret'. "
            << "Expected 32, got " << len << ".";
        triggerJavaIllegalStateException(env, err.str().c_str());
        return nullptr;
    }

    CKey k = LoadKey((const unsigned char *)data);
    if (!k.IsValid())
    {
        triggerJavaIllegalStateException(env, "invalid secret");
        return nullptr;
    }
    CPubKey pub = k.GetPubKey();
    jbyteArray bArray = env->NewByteArray(pub.size());
    jbyte *dest = env->GetByteArrayElements(bArray, 0);
    memcpy(dest, pub.begin(), pub.size());

    env->ReleaseByteArrayElements(arg, data, 0);
    env->ReleaseByteArrayElements(bArray, dest, 0);
    return bArray;
}

// libnexa-inconsistency: no SignHashEDCSA equivalent

extern "C" JNIEXPORT jbyteArray JNICALL Java_org_nexa_libnexakotlin_Native_txid(JNIEnv *env,
    jobject ths,
    jbyteArray arg)
{
    size_t len = env->GetArrayLength(arg);
    jbyte *data = env->GetByteArrayElements(arg, 0);

    jbyteArray bArray = env->NewByteArray(32);
    jbyte *dest = env->GetByteArrayElements(bArray, 0);

    txid((unsigned char *)data, len, (unsigned char *)dest);

    // unpins the java objects
    env->ReleaseByteArrayElements(arg, data, 0);
    env->ReleaseByteArrayElements(bArray, dest, 0);
    return bArray;
}

extern "C" JNIEXPORT jbyteArray JNICALL Java_org_nexa_libnexakotlin_Native_txidem(JNIEnv *env,
    jobject ths,
    jbyteArray arg)
{
    size_t len = env->GetArrayLength(arg);
    jbyte *data = env->GetByteArrayElements(arg, 0);

    jbyteArray bArray = env->NewByteArray(32);
    jbyte *dest = env->GetByteArrayElements(bArray, 0);

    txidem((unsigned char *)data, len, (unsigned char *)dest);

    // unpins the java objects
    env->ReleaseByteArrayElements(arg, data, 0);
    env->ReleaseByteArrayElements(bArray, dest, 0);
    return bArray;
}

extern "C" JNIEXPORT jbyteArray JNICALL Java_org_nexa_libnexakotlin_Native_blockHash(JNIEnv *env,
    jobject ths,
    jbyteArray arg)
{
    size_t len = env->GetArrayLength(arg);
    jbyte *data = env->GetByteArrayElements(arg, 0);

    jbyteArray bArray = env->NewByteArray(32);
    jbyte *dest = env->GetByteArrayElements(bArray, 0);

    CDataStream dataStrm((char *)data, (char *)data + len, SER_NETWORK, PROTOCOL_VERSION);
    CBlockHeader blkHeader;
    dataStrm >> blkHeader;

    uint256 hash = blkHeader.GetHash();
    memcpy(dest, hash.begin(), 256 / 8);
    // unpins the java objects
    env->ReleaseByteArrayElements(arg, data, 0);
    env->ReleaseByteArrayElements(bArray, dest, 0);
    return bArray;
}

extern "C" JNIEXPORT jbyteArray JNICALL Java_org_nexa_libnexakotlin_Native_signOneInputUsingECDSA(JNIEnv *env,
    jobject ths,
    jbyteArray txData,
    jint sigHashType,
    jlong inputIdx,
    jlong inputAmount,
    jbyteArray prevoutScript,
    jbyteArray secret)
{
    ByteArrayAccessor tx(env, txData);
    ByteArrayAccessor prevout(env, prevoutScript);
    ByteArrayAccessor privkey(env, secret);
    if (privkey.size != 32)
        return jbyteArray();

    unsigned char result[MAX_SIG_LEN];
    uint32_t resultLen = SignTxECDSA(tx.data, tx.size, inputIdx, inputAmount, prevout.data, prevout.size, sigHashType,
        privkey.data, result, MAX_SIG_LEN);

    if (resultLen == 0)
        return jbyteArray();
    return makeJByteArray(env, result, resultLen);
}

extern "C" JNIEXPORT jbyteArray JNICALL Java_org_nexa_libnexakotlin_Native_signOneBchInputUsingSchnorr(JNIEnv *env,
    jobject ths,
    jbyteArray txData,
    jint sigHashType,
    jlong inputIdx,
    jlong inputAmount,
    jbyteArray prevoutScript,
    jbyteArray secret)
{
    ByteArrayAccessor tx(env, txData);
    ByteArrayAccessor prevout(env, prevoutScript);
    ByteArrayAccessor privkey(env, secret);
    if (privkey.size != 32)
        return jbyteArray();

    unsigned char result[MAX_SIG_LEN];
    uint32_t resultLen = signBchTxOneInputUsingSchnorr(tx.data, tx.size, inputIdx, inputAmount, prevout.data,
        prevout.size, sigHashType, privkey.data, result, MAX_SIG_LEN);

    if (resultLen == 0)
    {
        triggerJavaIllegalStateException(env, "signing operation failed");
        return nullptr;
    }
    return makeJByteArray(env, result, resultLen);
}

extern "C" JNIEXPORT jbyteArray JNICALL Java_org_nexa_libnexakotlin_Native_signOneInputUsingSchnorr(JNIEnv *env,
    jobject ths,
    jbyteArray txData,
    jbyteArray hashType,
    jlong inputIdx,
    jlong inputAmount,
    jbyteArray prevoutScript,
    jbyteArray secret)
{
    ByteArrayAccessor tx(env, txData);
    ByteArrayAccessor prevout(env, prevoutScript);
    ByteArrayAccessor privkey(env, secret);
    ByteArrayAccessor sigHashType(env, hashType);
    if (privkey.size != 32)
        return jbyteArray();

    unsigned char result[MAX_SIG_LEN];
    uint32_t resultLen = signTxOneInputUsingSchnorr(tx.data, tx.size, inputIdx, inputAmount, prevout.data, prevout.size,
        sigHashType.data, sigHashType.size, privkey.data, result, MAX_SIG_LEN);

    if (resultLen == 0)
    {
        triggerJavaIllegalStateException(env, "signing operation failed");
        return nullptr;
    }
    return makeJByteArray(env, result, resultLen);
}

extern "C" JNIEXPORT jbyteArray JNICALL Java_org_nexa_libnexakotlin_Native_signHashSchnorr(JNIEnv *env,
    jobject ths,
    jbyteArray message,
    jbyteArray secret)
{
    ByteArrayAccessor data(env, message);
    ByteArrayAccessor privkey(env, secret);
    if (privkey.size != 32)
    {
        std::stringstream err;
        err << "signHashSchnorr: Incorrect length for argument 'secret'. "
            << "Expected 32, got " << privkey.size << ".";
        triggerJavaIllegalStateException(env, err.str().c_str());
        return nullptr;
    }

    if (data.size != 32)
    {
        triggerJavaIllegalStateException(env, "signHashSchnorr: Must sign a 32 byte hash.");
        return nullptr;
    }

    unsigned char result[MAX_SIG_LEN];
    uint32_t resultLen = signHashSchnorr(data.data, privkey.data, result);

    if (resultLen == 0)
    {
        triggerJavaIllegalStateException(env, "signHashSchnorr: Failed to sign data.");
        return nullptr;
    }
    return makeJByteArray(env, result, resultLen);
}

extern "C" JNIEXPORT jbyteArray JNICALL Java_org_nexa_libnexakotlin_Native_signHashSchnorrWithNonce(JNIEnv *env,
    jobject ths,
    jbyteArray message,
    jbyteArray secret,
    jbyteArray nonce)
{
    ByteArrayAccessor data(env, message);
    ByteArrayAccessor k(env, nonce);  // Schnorr private nonce is typically "k" in the literature
    ByteArrayAccessor privkey(env, secret);
    if (privkey.size != 32)
    {
        std::stringstream err;
        err << "signHashSchnorrWithNonce: Incorrect length for argument 'secret'. "
            << "Expected 32, got " << privkey.size << ".";
        triggerJavaIllegalStateException(env, err.str().c_str());
        return nullptr;
    }

    if (data.size != 32)
    {
        triggerJavaIllegalStateException(env, "signHashSchnorrWithNonce: Must sign a 32 byte hash.");
        return nullptr;
    }
    if (k.size != 32)
    {
        triggerJavaIllegalStateException(env, "signHashSchnorrWithNonce: Private nonce must be 32 bytes.");
        return nullptr;
    }

    unsigned char result[MAX_SIG_LEN];
    uint32_t resultLen = signHashSchnorrWithNonce(data.data, privkey.data, k.data, result);

    if (resultLen == 0)
    {
        triggerJavaIllegalStateException(env, "signHashSchnorrWithNonce: Failed to sign data.");
        return nullptr;
    }
    return makeJByteArray(env, result, resultLen);
}



// libnexa-inconsistency: no parseGroupDescription equivalent

// libnexa-inconsistency: no getArgsHashFromScriptPubkey equivalent

// libnexa-inconsistency: no getTemplateHashFromScriptPubkey equivalent

// libnexa-inconsistency: no getGroupTokenInfoFromScriptPubkey equivalent

extern "C" JNIEXPORT jbyteArray JNICALL Java_org_nexa_libnexakotlin_Native_signMessage(JNIEnv *env,
    jobject ths,
    jbyteArray jmessage,
    jbyteArray secret)
{
    ByteArrayAccessor message(env, jmessage);
    ByteArrayAccessor privkey(env, secret);
    if (privkey.size != 32)
        return jbyteArray();

    checkSigInit();

    CKey key = LoadKey((const unsigned char *)privkey.data);

    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic << message.vec();

    uint256 msgHash = ss.GetHash();
    // __android_log_print(ANDROID_LOG_INFO, APPNAME, "signing msgHash %s\n", msgHash.GetHex().c_str());
    std::vector<unsigned char> vchSig;
    if (!key.SignCompact(msgHash, vchSig)) // signing will only fail if the key is bogus
    {
        return jbyteArray();
    }
    if (vchSig.size() == 0)
        return jbyteArray();

    // __android_log_print(ANDROID_LOG_INFO, APPNAME, "signing sigSize %d data %s\n", vchSig.size(),
    // GetHex(vchSig.begin(), vchSig.size()).c_str());
    return makeJByteArray(env, vchSig);
}

extern "C" JNIEXPORT jbyteArray JNICALL Java_org_nexa_libnexakotlin_Native_verifyMessage(JNIEnv *env,
    jobject ths,
    jbyteArray jmessage,
    jbyteArray addrBytes,
    jbyteArray sigBytes)
{
    ByteArrayAccessor message(env, jmessage);
    ByteArrayAccessor addr(env, addrBytes);
    ByteArrayAccessor sig(env, sigBytes);
    CTxDestination destination;

    // There are only a few script types that we can extract a pubkey from.  If the data size is
    // 24, its a binary format script template address
    if (addr.size == 24)
    {
        ScriptTemplateDestination st;
        std::vector<unsigned char> vec(addr.data, addr.data + addr.size);
        CDataStream ssData(vec, SER_NETWORK, PROTOCOL_VERSION);
        ssData >> st;
        destination = st;
    }
    // If the data size is 20 its a raw pubkeyhash
    else if (addr.size == 20)
    {
        destination = CKeyID(uint160(addr.data));
    }
    // If it was neither of those or they didn't decode, try string decoding of any blockchain
    if (!IsValidDestination(destination))
    {
        // decode this address as if it was a string
        auto s = std::string(addr.data, addr.data + addr.size);
        destination = DecodeDestination(s, Params(CBaseChainParams::NEXA));
        if (!IsValidDestination(destination))
        {
            destination = DecodeDestination(s, Params(CBaseChainParams::TESTNET));
            if (!IsValidDestination(destination))
            {
                destination = DecodeDestination(s, Params(CBaseChainParams::REGTEST));
                if (!IsValidDestination(destination))
                {
                    destination = DecodeDestination(s, Params(CBaseChainParams::LEGACY_UNIT_TESTS));
                    if (!IsValidDestination(destination))
                    {
                        return jbyteArray();
                    }
                }
            }
        }
    }

    checkSigInit();

    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic << message.vec();

    uint256 msgHash = ss.GetHash();
    CPubKey pubkey;
    if (!pubkey.RecoverCompact(msgHash, sig.vec()))
    {
        return jbyteArray();
    }

    ScriptTemplateDestination *st = nullptr;
    const CKeyID *keyID = std::get_if<CKeyID>(&destination);
    if (keyID)
    {
        if (pubkey.GetID() != *keyID)
        {
            return jbyteArray();
        }
    }
    else if ((st = std::get_if<ScriptTemplateDestination>(&destination)) != nullptr)
    {
        CGroupTokenInfo groupInfo;
        std::vector<unsigned char> templateHash;

        // We do not understand this address as a script template so cannot verify this
        if (ScriptTemplateError::OK != GetScriptTemplate(st->toScript(), &groupInfo, &templateHash))
        {
            return jbyteArray();
        }
        // We cannot figure out the pubkeyhash of a template type that we do not understand
        if (templateHash != P2PKT_ID)
        {
            return jbyteArray();
        }
        // ok see if this pubkey makes the same p2pkt script as was given to us
        ScriptTemplateDestination signedBy(P2pktOutput(pubkey));
        if (!(*st == signedBy))
        {
            return jbyteArray();
        }
    }
    else // We don't know this destination type
    {
        return jbyteArray();
    }

    // checks succeeded, this is a good sig
    auto pkv = std::vector<unsigned char>(pubkey.begin(), pubkey.end());
    return makeJByteArray(env, pkv);
}

extern "C" JNIEXPORT jboolean JNICALL Java_org_nexa_libnexakotlin_Native_verifyBlockHeader(JNIEnv *env,
    jobject ths,
    jbyte chainSelector,
    jbyteArray arg)
{
    const CChainParams *cp = GetChainParams(static_cast<ChainSelector>(chainSelector));
    if (cp == nullptr)
    {
        triggerJavaIllegalStateException(env, "Unknown blockchain selection");
        return false;
    }
    size_t len = env->GetArrayLength(arg);
    jbyte *data = env->GetByteArrayElements(arg, 0);

    CDataStream dataStrm((char *)data, (char *)data + len, SER_NETWORK, PROTOCOL_VERSION);
    CBlockHeader blkHeader;
    dataStrm >> blkHeader;

    CValidationState state;
    bool result = CheckBlockHeader(cp->GetConsensus(), blkHeader, state, true);

    // unpins the java objects
    env->ReleaseByteArrayElements(arg, data, 0);
    return result;
}

extern "C" JNIEXPORT jstring JNICALL Java_org_nexa_libnexakotlin_Native_encodeCashAddr(JNIEnv *env,
    jobject ths,
    jbyte chainSelector,
    jbyte typ,
    jbyteArray arg)
{
    jbyte *data = env->GetByteArrayElements(arg, 0);
    size_t len = env->GetArrayLength(arg);
    CTxDestination dst = CNoDestination();

    if ((typ == PayAddressTypeP2PKH) || (typ == PayAddressTypeP2SH))
    {
        if (len != 20)
        {
            triggerJavaIllegalStateException(env, "bad address argument length");
            return nullptr;
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
        triggerJavaIllegalStateException(env, "Address type cannot be encoded to cashaddr");
        return nullptr;
    }

    env->ReleaseByteArrayElements(arg, data, 0);

    const CChainParams *cp = GetChainParams((ChainSelector)chainSelector);
    if (cp == nullptr)
    {
        triggerJavaIllegalStateException(env, "Unknown blockchain selection");
        return nullptr;
    }
    std::string addrAsStr(EncodeCashAddr(dst, *cp));
    return env->NewStringUTF(addrAsStr.c_str());
}

extern "C" JNIEXPORT jbyteArray JNICALL Java_org_nexa_libnexakotlin_Native_decodeCashAddr(JNIEnv *env,
    jobject ths,
    jbyte chainSelector,
    jstring addrstr)
{
    const CChainParams *cp = GetChainParams((ChainSelector)chainSelector);
    if (cp == nullptr)
    {
        triggerJavaIllegalStateException(env, "Unknown blockchain selection");
        return nullptr;
    }

    CTxDestination dst = DecodeCashAddr(toString(env, addrstr), *cp);
    std::vector<unsigned char> result;
    std::visit(PubkeyExtractor(result, *cp), dst);
    jbyteArray bArray = env->NewByteArray(result.size());
    jbyte *data = env->GetByteArrayElements(bArray, 0);
    memcpy(data, &result[0], result.size());
    env->ReleaseByteArrayElements(bArray, data, 0);
    return bArray;
}

// libnexa-inconsistency: no decodeCashAddrContent equivalent

// libnexa-inconsistency: no serializeScript equivalent

// libnexa-inconsistency: no pubkeyToScriptTemplate equivalent

extern "C" JNIEXPORT jstring JNICALL Java_org_nexa_libnexakotlin_Native_groupIdToAddr(JNIEnv *env,
    jobject ths,
    jbyte chainSelector,
    jbyteArray arg)
{
    size_t len = env->GetArrayLength(arg);
    if (len < 32)
    {
        triggerJavaIllegalStateException(env, "bad address argument length too small");
        return nullptr;
    }
    if (len > 520)
    {
        triggerJavaIllegalStateException(env, "bad address argument length too large");
        return nullptr;
    }
    jbyte *data = env->GetByteArrayElements(arg, 0);

    CGroupTokenID grp((uint8_t *)data, len);

    env->ReleaseByteArrayElements(arg, data, 0);

    const CChainParams *cp = GetChainParams((ChainSelector)chainSelector);
    if (cp == nullptr)
    {
        triggerJavaIllegalStateException(env, "Unknown blockchain selection");
        return nullptr;
    }
    std::string addrAsStr(EncodeGroupToken(grp, *cp));
    return env->NewStringUTF(addrAsStr.c_str());
}

extern "C" JNIEXPORT jbyteArray JNICALL Java_org_nexa_libnexakotlin_Native_groupIdFromAddr(JNIEnv *env,
    jobject ths,
    jbyte chainSelector,
    jstring addrstr)
{
    const CChainParams *cp = GetChainParams((ChainSelector)chainSelector);
    if (cp == nullptr)
    {
        triggerJavaIllegalStateException(env, "Unknown blockchain selection");
        return nullptr;
    }
    auto addr = toString(env, addrstr);
    CGroupTokenID gid = DecodeGroupToken(addr, *cp);
    size_t size = gid.bytes().size();
    if (size < 32) // min group id size
    {
        triggerJavaIllegalStateException(env, "Address is not a group (too small)");
        return nullptr;
    }
    if (size > 520) // max group id size
    {
        triggerJavaIllegalStateException(env, "Address is not a group (too large)");
        return nullptr;
    }

    jbyteArray bArray = env->NewByteArray(size);
    jbyte *data = env->GetByteArrayElements(bArray, 0);
    memcpy((uint8_t *)data, &gid.bytes().front(), size);
    env->ReleaseByteArrayElements(bArray, data, 0);
    return bArray;
}

extern "C" JNIEXPORT jbyteArray JNICALL Java_org_nexa_libnexakotlin_Native_decodeWifPrivateKey(JNIEnv *env,
    jobject ths,
    jbyte chainSelector,
    jstring secretWIF)
{
    const CChainParams *cp = GetChainParams(static_cast<ChainSelector>(chainSelector));
    if (cp == nullptr)
    {
        triggerJavaIllegalStateException(env, "Unknown blockchain selection");
        return nullptr;
    }
    CBitcoinSecret secret;
    const std::string wif = toString(env, secretWIF);
    const bool ok = secret.SetString(*cp, wif);

    if (!ok)
    {
        triggerJavaIllegalStateException(env, "Invalid private key");
        return nullptr;
    }
    const CKey key = secret.GetKey();
    if (!key.IsValid())
    {
        triggerJavaIllegalStateException(env, "Private key outside allowed range");
        return nullptr;
    }
    return makeJByteArray(env, static_cast<const uint8_t *>(key.begin()), key.size());
}

extern "C" JNIEXPORT jbyteArray JNICALL Java_org_nexa_libnexakotlin_Native_sha256(JNIEnv *env,
    jobject ths,
    jbyteArray arg)
{
    size_t len = env->GetArrayLength(arg);
    jbyte *data = env->GetByteArrayElements(arg, 0);

    jbyteArray bArray = env->NewByteArray(32);
    jbyte *dest = env->GetByteArrayElements(bArray, 0);
    sha256((unsigned char *)data, len, (unsigned char *)dest);

    env->ReleaseByteArrayElements(arg, data, 0);
    env->ReleaseByteArrayElements(bArray, dest, 0);
    return bArray;
}

extern "C" JNIEXPORT jbyteArray JNICALL Java_org_nexa_libnexakotlin_Native_hash256(JNIEnv *env,
    jobject ths,
    jbyteArray arg)
{
    size_t len = env->GetArrayLength(arg);
    jbyte *data = env->GetByteArrayElements(arg, 0);

    jbyteArray bArray = env->NewByteArray(32);
    jbyte *dest = env->GetByteArrayElements(bArray, 0);
    hash256((unsigned char *)data, len, (unsigned char *)dest);

    env->ReleaseByteArrayElements(arg, data, 0);
    env->ReleaseByteArrayElements(bArray, dest, 0);
    return bArray;
}

extern "C" JNIEXPORT jbyteArray JNICALL Java_org_nexa_libnexakotlin_Native_hash160(JNIEnv *env,
    jobject ths,
    jbyteArray arg)
{
    size_t len = env->GetArrayLength(arg);
    jbyte *data = env->GetByteArrayElements(arg, 0);

    jbyteArray bArray = env->NewByteArray(20);
    jbyte *dest = env->GetByteArrayElements(bArray, 0);
    hash160((unsigned char *)data, len, (unsigned char *)dest);

    env->ReleaseByteArrayElements(arg, data, 0);
    env->ReleaseByteArrayElements(bArray, dest, 0);
    return bArray;
}

/** Get work from nbits */
extern "C" JNIEXPORT jbyteArray JNICALL Java_org_nexa_libnexakotlin_Native_getWorkFromDifficultyBits(JNIEnv *env,
    jobject ths,
    jlong nBits)
{
    arith_uint256 result = GetWorkForDifficultyBits((uint32_t)nBits);
    return encodeUint256(env, result);
}

/** Get nbits from work */
extern "C" JNIEXPORT jint JNICALL Java_org_nexa_libnexakotlin_Native_getDifficultyBitsFromWork(JNIEnv *env,
    jobject ths,
    jbyteArray work)
{
    ByteArrayAccessor data(env, work);
    return getDifficultyBitsFromWork(data.data);
}


/** Create a bloom filter */
extern "C" JNIEXPORT jbyteArray JNICALL Java_org_nexa_libnexakotlin_Native_createBloomFilter(JNIEnv *env,
    jobject ths,
    jobjectArray arg,
    jdouble falsePosRate,
    jint capacity,
    jint maxSize,
    jint flags,
    jint tweak)
{
    jclass byteArrayClass = env->FindClass("[B");
    size_t len = env->GetArrayLength(arg);
    if (capacity < 10)
        capacity = 10; // sanity check the capacity

    if (!((falsePosRate >= 0) && (falsePosRate <= 1.0)))
    {
        triggerJavaIllegalStateException(env, "incorrect false positive rate");
        return nullptr;
    }

    CBloomFilter bloom(std::max((size_t)capacity, len), falsePosRate, tweak, flags, maxSize);

    for (size_t i = 0; i < len; i++)
    {
        jobject obj = env->GetObjectArrayElement(arg, i);
        if (!env->IsInstanceOf(obj, byteArrayClass))
        {
            triggerJavaIllegalStateException(env, "incorrect element data type (must be ByteArray)");
            return nullptr;
        }
        jbyteArray elem = (jbyteArray)obj;
        jbyte *elemData = env->GetByteArrayElements(elem, 0);
        if (elemData == NULL)
        {
            triggerJavaIllegalStateException(env, "incorrect element data type (must be ByteArray)");
            return nullptr;
        }
        size_t elemLen = env->GetArrayLength(elem);
        bloom.insert(std::vector<unsigned char>(elemData, elemData + elemLen));
        env->ReleaseByteArrayElements(elem, elemData, 0);
    }

    CDataStream serializer(SER_NETWORK, PROTOCOL_VERSION);
    serializer << bloom;
    //__android_log_print(ANDROID_LOG_INFO, APPNAME, "Bloom size: %d Bloom serialized size: %d numAddrs: %d\n",
    //    (unsigned int)bloom.vDataSize(), (unsigned int)serializer.size(), (unsigned int)len);
    jbyteArray ret = env->NewByteArray(serializer.size());
    jbyte *retData = env->GetByteArrayElements(ret, 0);

    if (!retData)
        return ret; // failed
    memcpy(retData, serializer.data(), serializer.size());

    env->ReleaseByteArrayElements(ret, retData, 0);
    return ret;
}

// Since partial Merkle blocks are just trees of hashes, this structure is the same for Nexa and BCH
jobjectArray JNICALL
MerkleBlock_Extract(JNIEnv *env, jobject ths, jint numTxes, jbyteArray merkleProofPath, jobjectArray hashArray)
{
    const unsigned int HASH_LEN = 32;
    size_t hashArrayLen = env->GetArrayLength(hashArray);

    jbyte *mppData = env->GetByteArrayElements(merkleProofPath, 0);
    size_t mppLen = env->GetArrayLength(merkleProofPath);
    CDecodablePartialMerkleTree tree(numTxes, (const unsigned char *)mppData, mppLen);
    env->ReleaseByteArrayElements(merkleProofPath, mppData, 0);

    // Copy the hashes out of the java wrapper objects into the PartialMerkleTree
    auto &hashes = tree.accessHashes();
    hashes.resize(hashArrayLen);
    for (size_t i = 0; i < hashArrayLen; i++)
    {
        jbyteArray elem = (jbyteArray)env->GetObjectArrayElement(hashArray, i);
        jbyte *elemData = env->GetByteArrayElements(elem, 0);
        size_t elemLen = env->GetArrayLength(elem);
        if (elemLen != HASH_LEN)
        {
            triggerJavaIllegalStateException(env, "invalid hash: bad length");
            return nullptr;
        }
        hashes[i] = uint256((unsigned char *)elemData);
        env->ReleaseByteArrayElements(elem, elemData, 0);
    }

    std::vector<uint256> matches;
    std::vector<unsigned int> matchIndexes;
    uint256 merkleRoot = tree.ExtractMatches(matches, matchIndexes);

    jclass elementClass = env->GetObjectClass(merkleProofPath); // get the class of a jbyteArray
    jobjectArray ret = env->NewObjectArray(matches.size() + 1, elementClass, nullptr);

    // Put the merkle root in the first slot
    {
        jbyteArray bArray = env->NewByteArray(HASH_LEN);
        jbyte *dest = env->GetByteArrayElements(bArray, 0);
        memcpy(dest, merkleRoot.begin(), HASH_LEN);
        env->ReleaseByteArrayElements(bArray, dest, 0);
        env->SetObjectArrayElement(ret, 0, bArray);
    }

    // Fill the rest with transactions hashes
    for (size_t i = 0; i < matches.size(); i++)
    {
        jbyteArray bArray = env->NewByteArray(HASH_LEN);
        jbyte *dest = env->GetByteArrayElements(bArray, 0);
        memcpy(dest, matches[i].begin(), HASH_LEN);
        env->ReleaseByteArrayElements(bArray, dest, 0);
        env->SetObjectArrayElement(ret, i + 1, bArray);
    }
    return ret;
}

extern "C" JNIEXPORT jobjectArray JNICALL Java_org_nexa_libnexakotlin_Native_extractFromMerkleBlock(JNIEnv *env,
    jobject ths,
    jint numTxes,
    jbyteArray merkleProofPath,
    jobjectArray hashArray)
{
    return MerkleBlock_Extract(env, ths, numTxes, merkleProofPath, hashArray);
}

extern "C" JNIEXPORT jboolean JNICALL Java_org_nexa_libnexakotlin_Native_verifyHashSchnorr(JNIEnv *env,
    jobject ths,
    jbyteArray jhash,
    jbyteArray jpubkey,
    jbyteArray jsig)
{
    ByteArrayAccessor hash(env, jhash);
    ByteArrayAccessor pubkeybytes(env, jpubkey);
    ByteArrayAccessor sig(env, jsig);
    if (hash.size != 32)
    {
        triggerJavaIllegalStateException(env, "verifyHashSchnorr: Must verify a 32 byte hash.");
        return false;
    }

    uint256 messageHash(hash.data);
    CPubKey pubkey(pubkeybytes.vec());
    if (sig.size != 64)
    {
        triggerJavaIllegalStateException(env, "verifyHashSchnorr: Schnorr signature must be 64 bytes.");
        return false;
    }
    return pubkey.VerifySchnorr(messageHash, sig.vec());
}

extern "C" JNIEXPORT jboolean JNICALL Java_org_nexa_libnexakotlin_Native_verifyDataSchnorr(JNIEnv *env,
    jobject ths,
    jbyteArray jdata,
    jbyteArray jpubkey,
    jbyteArray jsig)
{
    ByteArrayAccessor message(env, jdata);
    ByteArrayAccessor pubkeybytes(env, jpubkey);
    ByteArrayAccessor sig(env, jsig);

    std::vector<unsigned char> vchHash(32);
    CSHA256().Write(message.data, message.size).Finalize(vchHash.data());
    uint256 messageHash(vchHash);
    CPubKey pubkey(pubkeybytes.vec());
    if (sig.size != 64)
    {
        triggerJavaIllegalStateException(env, "verifyHashSchnorr: Schnorr signature must be 64 bytes.");
        return false;
    }
    return pubkey.VerifySchnorr(messageHash, sig.vec());
}

extern "C" JNIEXPORT jbyteArray JNICALL Java_org_nexa_libnexakotlin_Native_capdSolve(JNIEnv *env,
    jobject ths,
    jbyteArray jmessage)
{
    ByteArrayAccessor message(env, jmessage);
    CDataStream dataStrm((char *)message.data, (char *)message.data + message.size, SER_NETWORK, PROTOCOL_VERSION);
    CapdMsg msg;
    try
    {
        dataStrm >> msg;
    }
    catch (const std::exception &)
    {
        // p("libnexa capd deserialize error");
        return jbyteArray();
    }
    // one year of seconds.  This is not going to work because Solve interprets this as an offset from "now" and changes
    // the message time field.  But we do not return the changed time.  Callers should manually do this if they
    // want an offset.  Since such an ancient message is unrelayable this must be an invalid capd message anyway.
    if (msg.createTime < 31536000)
        return jbyteArray();
    bool solved = msg.Solve(msg.createTime);
    if (solved)
    {
        return makeJByteArray(env, msg.nonce);
    }
    return jbyteArray();
}

extern "C" JNIEXPORT jboolean JNICALL Java_org_nexa_libnexakotlin_Native_capdCheck(JNIEnv *env,
    jobject ths,
    jbyteArray jmessage)
{
    ByteArrayAccessor message(env, jmessage);
    CDataStream dataStrm((char *)message.data, (char *)message.data + message.size, SER_NETWORK, PROTOCOL_VERSION);
    CapdMsg msg;
    try
    {
        dataStrm >> msg;
    }
    catch (const std::exception &)
    {
        return false;
    }
    return msg.DoesPowMeetTarget();
}

extern "C" JNIEXPORT jbyteArray JNICALL Java_org_nexa_libnexakotlin_Native_capdHash(JNIEnv *env,
    jobject ths,
    jbyteArray jmessage)
{
    ByteArrayAccessor message(env, jmessage);
    CDataStream dataStrm((char *)message.data, (char *)message.data + message.size, SER_NETWORK, PROTOCOL_VERSION);
    CapdMsg msg;
    try
    {
        dataStrm >> msg;
    }
    catch (const std::exception &)
    {
        // p("libnexa capd deserialize error");
        return jbyteArray();
    }
    uint256 hash = msg.CalcHash();
    // p("C hash: %s\n", HexStr(hash.begin(), hash.end()).c_str());
    jbyteArray ret = makeJByteArray(env, hash);
    return ret;
}

extern "C" JNIEXPORT jbyteArray JNICALL Java_org_nexa_libnexakotlin_Native_capdSetPowTargetHarderThanPriority(JNIEnv *env,
    jobject ths,
    jbyteArray jmessage,
    jdouble priority)
{
    ByteArrayAccessor message(env, jmessage);
    CDataStream dataStrm((char *)message.data, (char *)message.data + message.size, SER_NETWORK, PROTOCOL_VERSION);
    CapdMsg msg;
    try
    {
        dataStrm >> msg;
    }
    catch (const std::exception &)
    {
        // p("libnexa capd deserialize error");
        return jbyteArray();
    }
    msg.SetPowTargetHarderThanPriority(priority);
    // reserialise the message
    CDataStream serializer(SER_NETWORK, PROTOCOL_VERSION);
    try
    {
        serializer << msg;
    }
    catch (const std::exception &)
    {
        // p("libnexa capd serialize error");
        return jbyteArray();
    }
    jbyteArray ret = env->NewByteArray(serializer.size());
    jbyte *retData = env->GetByteArrayElements(ret, 0);
    if (!retData)
    {
        return ret; // failed
    }
    memcpy(retData, serializer.data(), serializer.size());
    env->ReleaseByteArrayElements(ret, retData, 0);
    return ret;
}

extern "C" JNIEXPORT jbyteArray JNICALL Java_org_nexa_libnexakotlin_Native_cryptAES256CBC(JNIEnv *env,
    jobject ths,
    jbyteArray message,
    jbyteArray secret,
    jbyteArray initial,
    jboolean encrypt)
{
    ByteArrayAccessor data(env, message);
    ByteArrayAccessor privkey(env, secret);
    ByteArrayAccessor iv(env, initial);

    if (privkey.size != AES256_KEYSIZE)
        return jbyteArray();
    if (iv.size != AES_BLOCKSIZE)
        return jbyteArray();
    if ((data.size % AES_BLOCKSIZE) != 0)
        return jbyteArray();

    jbyteArray ret = env->NewByteArray(data.size);
    jbyte *dest = env->GetByteArrayElements(ret, 0);

    int nBytes = 0;
    if (encrypt)
    {
        AES256CBCEncrypt crypter(privkey.data, iv.data, false);
        nBytes = crypter.Encrypt(data.data, data.size, (unsigned char *)dest);
    }
    else
    {
        AES256CBCDecrypt crypter(privkey.data, iv.data, false);
        nBytes = crypter.Decrypt(data.data, data.size, (unsigned char *)dest);
    }
    if (nBytes == 0)
        return jbyteArray();
    // this copies the generated data from the C buffer into the java bytearray
    env->ReleaseByteArrayElements(ret, dest, 0);
    return ret;
}


/////// Script machine JVM ////////

#ifndef LIGHT

extern "C" JNIEXPORT jlong JNICALL Java_org_nexa_libnexakotlin_ScriptMachine_create(JNIEnv *env,
    jobject ths,
    jbyteArray tx,
    jbyteArray outpoints,
    jint inputIdx,
    jint flags)
{
    ByteArrayAccessor txb(env, tx);
    ByteArrayAccessor outpointb(env, outpoints);

    if (flags == -1)
        flags = STANDARD_SCRIPT_VERIFY_FLAGS;
    std::string error;
    void *sm = CreateScriptMachine(flags, inputIdx, txb.data, txb.size, outpointb.data, outpointb.size, &error);
    if (sm == nullptr)
    {
        triggerJavaIllegalStateException(env, error.c_str());
    }
    return ((jlong)sm);
}

extern "C" JNIEXPORT jlong JNICALL Java_org_nexa_libnexakotlin_ScriptMachine_createTemplateContext(JNIEnv *env,
    jobject ths,
    jbyteArray tx,
    jbyteArray outpoints,
    jbyteArray satisfierba,
    jbyteArray constraintba,
    jint inputIdx,
    jint flags)
{
    ByteArrayAccessor txb(env, tx);
    ByteArrayAccessor outpointb(env, outpoints);
    ByteArrayAccessor satbaa(env, satisfierba);
    ByteArrayAccessor conbaa(env, constraintba);

    CScript satisfier(satbaa.data, satbaa.data + satbaa.size);
    CScript constraint(conbaa.data, conbaa.data + conbaa.size);

    if (!satisfier.IsPushOnly())
    {
        triggerJavaIllegalStateException(env, "satisfier is not push-only");
        return 0;
    }
    if (!constraint.IsPushOnly())
    {
        triggerJavaIllegalStateException(env, "constraint is not push-only");
        return 0;
    }

    if (flags == -1)
        flags = STANDARD_SCRIPT_VERIFY_FLAGS;

    const unsigned int maxOps = 0xffffffff;
    ScriptImportedState noSis;
    ScriptMachine ssm(flags, noSis, maxOps, 0);
    if (!ssm.Eval(satisfier))
    {
        triggerJavaIllegalStateException(env, ScriptErrorString(ssm.getError()));
        return 0;
    }
    ScriptMachine csm(flags, noSis, maxOps, 0);
    if (!csm.Eval(constraint))
    {
        triggerJavaIllegalStateException(env, ScriptErrorString(csm.getError()));
        return 0;
    }

    std::string error;
    void *smh = CreateScriptMachine(flags, inputIdx, txb.data, txb.size, outpointb.data, outpointb.size, &error);

    if (smh)
    {
        // copy over the stacks that were created by running the constraint and satisfier
        ScriptMachineData *smd = (ScriptMachineData *)smh;
        smd->sm->setAltStack(csm.getStack());
        smd->sm->setStack(ssm.getStack());
    }
    else
    {
        triggerJavaIllegalStateException(env, error.c_str());
        return 0;
    }
    return ((jlong)smh);
}


extern "C" JNIEXPORT jlong JNICALL Java_org_nexa_libnexakotlin_ScriptMachine_createNoContext(JNIEnv *env,
    jobject ths,
    jint flags)
{
    if (flags == -1)
        flags = STANDARD_SCRIPT_VERIFY_FLAGS;
    void *sm = CreateNoContextScriptMachine(flags);
    return ((jlong)sm);
}


extern "C" JNIEXPORT jboolean Java_org_nexa_libnexakotlin_ScriptMachine_eval(JNIEnv *env,
    jobject ths,
    jlong smid,
    jbyteArray scriptBytes,
    jboolean run)
{
    ByteArrayAccessor script(env, scriptBytes);
    bool ret = true;
    if (run)
    {
        ret = SmEval((void *)smid, script.data, script.size);
    }
    else
    {
        ret = SmBeginStep((void *)smid, script.data, script.size);
    }
    return ret;
}

extern "C" JNIEXPORT jboolean JNICALL Java_org_nexa_libnexakotlin_ScriptMachine_cont(JNIEnv *env,
    jobject ths,
    jlong smid)
{
    ScriptMachineData *smd = (ScriptMachineData *)smid;
    if ((!smd) || (!smd->sm))
    {
        triggerJavaIllegalStateException(env, "internal error: no script machine");
        return false;
    }
    return smd->sm->Continue();
}

extern "C" JNIEXPORT jboolean JNICALL Java_org_nexa_libnexakotlin_ScriptMachine_step(JNIEnv *env,
    jobject ths,
    jlong smid)
{
    ScriptMachineData *smd = (ScriptMachineData *)smid;
    if ((!smd) || (!smd->sm))
    {
        triggerJavaIllegalStateException(env, "internal error: no script machine");
        return false;
    }
    if (!smd->sm->isMoreSteps())
    {
        triggerJavaIllegalStateException(env, "completed");
        return false;
    }
    return smd->sm->Step();
}


extern "C" JNIEXPORT void JNICALL Java_org_nexa_libnexakotlin_ScriptMachine_swapStacks(JNIEnv *env,
    jobject ths,
    jlong smid)
{
    ScriptMachineData *smd = (ScriptMachineData *)smid;
    if ((!smd) || (!smd->sm))
        triggerJavaIllegalStateException(env, "internal error: no script machine");
    else
    {
        Stack tmp = smd->sm->getStack();
        smd->sm->setStack(smd->sm->getAltStack());
        smd->sm->setAltStack(tmp);
    }
}

extern "C" JNIEXPORT jstring Java_org_nexa_libnexakotlin_ScriptMachine_getError(JNIEnv *env, jobject ths, jlong smid)
{
    ScriptMachineData *smd = (ScriptMachineData *)smid;
    if ((!smd) || (!smd->sm))
    {
        triggerJavaIllegalStateException(env, "internal error: no script machine");
        return nullptr;
    }

    auto err = smd->sm->getError();

    std::string ret(ScriptErrorString(err));
    ret += "(" + std::to_string(err) + ")";
    return env->NewStringUTF(ret.c_str());
}

// Step-by-step interface: get current position in this script, in bytes offset from the script start
extern "C" JNIEXPORT jint Java_org_nexa_libnexakotlin_ScriptMachine_getPos(JNIEnv *env, jobject ths, jlong smId)

{
    ScriptMachineData *smd = (ScriptMachineData *)smId;
    if ((!smd) || (!smd->sm))
    {
        triggerJavaIllegalStateException(env, "internal error: no script machine");
        return -1;
    }
    return smd->sm->getPos();
}

// Step-by-step interface: get current position in this script, in bytes offset from the script start
extern "C" JNIEXPORT jint Java_org_nexa_libnexakotlin_ScriptMachine_setPos(JNIEnv *env,
    jobject ths,
    jlong smId,
    jint pos)

{
    ScriptMachineData *smd = (ScriptMachineData *)smId;
    if ((!smd) || (!smd->sm))
    {
        triggerJavaIllegalStateException(env, "internal error: no script machine");
        return -1;
    }
    if (pos < 0)
    {
        triggerJavaIllegalStateException(env, "internal error: no script machine");
        return -1;
    }
    return smd->sm->setPos(pos);
}


// Step-by-step interface: get current position in this script, in bytes offset from the script start
extern "C" JNIEXPORT jstring Java_org_nexa_libnexakotlin_ScriptMachine_getBMD(JNIEnv *env, jobject ths, jlong smId)

{
    ScriptMachineData *smd = (ScriptMachineData *)smId;
    if ((!smd) || (!smd->sm))
    {
        triggerJavaIllegalStateException(env, "internal error: no script machine");
        return nullptr;
    }
    return env->NewStringUTF(smd->sm->bigNumModulo.str(16).c_str());
}

// Step-by-step interface: get current position in this script, in bytes offset from the script start
extern "C" JNIEXPORT bool Java_org_nexa_libnexakotlin_ScriptMachine_modify(JNIEnv *env,
    jobject ths,
    jlong smId,
    jint offset,
    jbyteArray data)

{
    ScriptMachineData *smd = (ScriptMachineData *)smId;
    if ((!smd) || (!smd->sm))
    {
        triggerJavaIllegalStateException(env, "internal error: no script machine");
        return false;
    }
    ByteArrayAccessor d(env, data);
    return smd->sm->ModifyScript(offset, d.data, d.size);
}


/** This makes sense to give as text because we don't want the higher layers to have to parse the BigNum format
    and certainly don't want to expose the internal bignum representation
*/
extern "C" JNIEXPORT jstring Java_org_nexa_libnexakotlin_ScriptMachine_getStackItemText(JNIEnv *env,
    jobject ths,
    jlong smid,
    jint whichStack,
    jint index)
{
    ScriptMachineData *smd = (ScriptMachineData *)smid;
    if ((!smd) || (!smd->sm))
    {
        triggerJavaIllegalStateException(env, "internal error: no script machine");
        return nullptr;
    }

    const std::vector<StackItem> &stk = (whichStack == 0) ? smd->sm->getStack() : smd->sm->getAltStack();
    if ((int)stk.size() <= index)
        return env->NewStringUTF("");
    index = stk.size() - index - 1;
    const StackItem &item = stk[index];
    std::string ret;
    // return TYPE SIZE string(hex or false) DECIMAL
    if (item.type == StackElementType::VCH)
    {
        size_t sz = item.size();
        // special case for false stack item because insanity of interpreter
        if (sz == 0)
            return env->NewStringUTF((ret + "BYTES 0 false 0").c_str());
        ret += "BYTES " + std::to_string(sz) + " " + item.hex() + "h";
        try
        {
            int64_t t = item.asInt64(false); // TODO report minimal encoding
            ret += " " + std::to_string(t);
        }
        catch (script_error &e)
        {
            ret += " NaN";
        }
        catch (BadOpOnType &e)
        {
            ret += " NaN";
        }
    }
    else if (item.type == StackElementType::BIGNUM)
    {
        const BigNum &num = item.num();
        size_t sz = num.magSize();
        ret += "BIGNUM " + std::to_string(sz) + " " + item.hex() + "h " + num.str();
    }
    else
    {
        ret += "UNKNW"; // this sw needs to be updated for the newly added type
    }

    return env->NewStringUTF(ret.c_str());
}


extern "C" JNIEXPORT jboolean JNICALL Java_org_nexa_libnexakotlin_ScriptMachine_delete(JNIEnv *env,
    jobject ths,
    jlong smid)
{
    SmRelease((void *)smid);
    return true;
}

#endif // ifndef ANDROID
#endif  // defined(JAVA)
