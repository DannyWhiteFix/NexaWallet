// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_HASH_H
#define NEXA_HASH_H

#include "crypto/hash160.h"
#include "crypto/ripemd160.h"
#include "crypto/sha256.h"
#include "prevector.h"
#include "serialize.h"
#include "uint256.h"
#include "version.h"

#include <vector>

#include "utilstrencodings.h"

typedef uint256 ChainCode;

/** A hasher class for Bitcoin's 256-bit hash (double SHA-256). */
class CHash256
{
private:
    CSHA256 sha;

public:
    static const size_t OUTPUT_SIZE = CSHA256::OUTPUT_SIZE;

    void Finalize(unsigned char hash[OUTPUT_SIZE])
    {
        unsigned char buf[CSHA256::OUTPUT_SIZE];
        sha.Finalize(buf);
        sha.Reset().Write(buf, CSHA256::OUTPUT_SIZE).Finalize(hash);
        // Useful to debug hash mismatches but too time consuming to even have as a conditional log
        // printf("CHash256 Finalized size %ld hash: %s\n", sha.GetNumBytesHashed(),
        // HexStr(hash,hash+OUTPUT_SIZE).c_str());
    }

    CHash256 &Write(const unsigned char *data, size_t len)
    {
        // Useful to debug hash mismatches but too time consuming to even have as a conditional log
        // printf("CHash256 %d: %s\n", (int) len, HexStr(data,data+len).c_str());
        sha.Write(data, len);
        return *this;
    }

    CHash256 &Reset()
    {
        sha.Reset();
        return *this;
    }

    /** Return the total number of bytes hashed since the last Reset() (or object construction) */
    size_t GetNumBytesHashed() const { return sha.GetNumBytesHashed(); }
};

/** Compute the 256-bit hash of an object. */
template <typename T1>
inline uint256 Hash(const T1 pbegin, const T1 pend)
{
    static const unsigned char pblank[1] = {};
    uint256 result;
    CHash256()
        .Write(pbegin == pend ? pblank : (const unsigned char *)&pbegin[0], (pend - pbegin) * sizeof(pbegin[0]))
        .Finalize((unsigned char *)&result);
    return result;
}

/** Compute the 256-bit hash of the concatenation of two objects. */
template <typename T1, typename T2>
inline uint256 Hash(const T1 p1begin, const T1 p1end, const T2 p2begin, const T2 p2end)
{
    static const unsigned char pblank[1] = {};
    uint256 result;
    CHash256()
        .Write(p1begin == p1end ? pblank : (const unsigned char *)&p1begin[0], (p1end - p1begin) * sizeof(p1begin[0]))
        .Write(p2begin == p2end ? pblank : (const unsigned char *)&p2begin[0], (p2end - p2begin) * sizeof(p2begin[0]))
        .Finalize((unsigned char *)&result);
    return result;
}

/** Compute the 256-bit hash of the concatenation of three objects. */
template <typename T1, typename T2, typename T3>
inline uint256 Hash(const T1 p1begin,
    const T1 p1end,
    const T2 p2begin,
    const T2 p2end,
    const T3 p3begin,
    const T3 p3end)
{
    static const unsigned char pblank[1] = {};
    uint256 result;
    CHash256()
        .Write(p1begin == p1end ? pblank : (const unsigned char *)&p1begin[0], (p1end - p1begin) * sizeof(p1begin[0]))
        .Write(p2begin == p2end ? pblank : (const unsigned char *)&p2begin[0], (p2end - p2begin) * sizeof(p2begin[0]))
        .Write(p3begin == p3end ? pblank : (const unsigned char *)&p3begin[0], (p3end - p3begin) * sizeof(p3begin[0]))
        .Finalize((unsigned char *)&result);
    return result;
}

/** Compute the 256-bit hash an object. */
template <typename T1>
inline std::vector<unsigned char> VchHash(const T1 pbegin, const T1 pend)
{
    static unsigned char pblank[1] = {};
    std::vector<unsigned char> result(32);
    CHash256()
        .Write(pbegin == pend ? pblank : (const unsigned char *)&pbegin[0], (pend - pbegin) * sizeof(pbegin[0]))
        .Finalize(&result[0]);
    return result;
}

/** Compute the 256-bit hash of a vector. */
inline std::vector<unsigned char> VchHash(const std::vector<unsigned char> &vch)
{
    return VchHash(vch.begin(), vch.end());
}

/** A writer stream (for serialization) that computes a 256-bit hash (double SHA256). */
class CHashWriter
{
private:
    CHash256 ctx;

    const int nType;
    const int nVersion;

public:
    CHashWriter(int nTypeIn = SER_GETHASH, int nVersionIn = 0) : nType(nTypeIn), nVersion(nVersionIn) {}
    int GetType() const { return nType; }
    int GetVersion() const { return nVersion; }
    void write(const char *pch, size_t size) { ctx.Write((const unsigned char *)pch, size); }
    // invalidates the object
    uint256 GetHash()
    {
        uint256 result;
        ctx.Finalize((unsigned char *)&result);
        return result;
    }

    /** Return the total number of bytes hashed by this object */
    size_t GetNumBytesHashed() const { return ctx.GetNumBytesHashed(); }
    template <typename T>
    CHashWriter &operator<<(const T &obj)
    {
        // Serialize to this stream
        ::Serialize(*this, obj);
        return (*this);
    }
};

/** A writer stream (for serialization) that computes a 256-bit hash. */
class CSHA256Writer
{
private:
    CSHA256 ctx;

    const int nType;
    const int nVersion;

public:
    CSHA256Writer(int nTypeIn = SER_GETHASH, int nVersionIn = 0) : nType(nTypeIn), nVersion(nVersionIn) {}
    int GetType() const { return nType; }
    int GetVersion() const { return nVersion; }
    void write(const char *pch, size_t size) { ctx.Write((const unsigned char *)pch, size); }
    // invalidates the object
    uint256 GetHash()
    {
        uint256 result;
        ctx.Finalize((unsigned char *)&result);
        return result;
    }

    /** Return the total number of bytes hashed by this object */
    size_t GetNumBytesHashed() const { return ctx.GetNumBytesHashed(); }
    template <typename T>
    CSHA256Writer &operator<<(const T &obj)
    {
        // Serialize to this stream
        ::Serialize(*this, obj);
        return (*this);
    }
};


/** Reads data from an underlying stream, while hashing the read data. */
template <typename Source>
class CHashVerifier : public CHashWriter
{
private:
    Source *source;

public:
    CHashVerifier(Source *source_) : CHashWriter(source_->GetType(), source_->GetVersion()), source(source_) {}
    void read(char *pch, size_t nSize)
    {
        source->read(pch, nSize);
        this->write(pch, nSize);
    }

    void ignore(size_t nSize)
    {
        char data[1024];
        while (nSize > 0)
        {
            size_t now = std::min<size_t>(nSize, 1024);
            read(data, now);
            nSize -= now;
        }
    }

    template <typename T>
    CHashVerifier<Source> &operator>>(T &obj)
    {
        // Unserialize from this stream
        ::Unserialize(*this, obj);
        return (*this);
    }
};

/** Compute the 256-bit hash of an object's serialization. */
template <typename T>
uint256 SerializeHash(const T &obj, int nType = SER_GETHASH, int nVersion = PROTOCOL_VERSION)
{
    CHashWriter ss(nType, nVersion);
    ss << obj;
    return ss.GetHash();
}

/** Compute the 256-bit hash of an object's serialization. */
template <typename T>
uint256 SerializeIdem(const T &obj, int nType = SER_GETIDEM, int nVersion = PROTOCOL_VERSION)
{
    CHashWriter ss(nType, nVersion);
    ss << obj;
    return ss.GetHash();
}

unsigned int MurmurHash3(unsigned int nHashSeed, const std::vector<unsigned char> &vDataToHash);

void BIP32Hash(const ChainCode &chainCode,
    unsigned int nChild,
    unsigned char header,
    const unsigned char data[32],
    unsigned char output[64]);

/** SipHash-2-4 */
class CSipHasher
{
private:
    uint64_t v[4];
    uint64_t tmp;
    int count;

public:
    /** Construct a SipHash calculator initialized with 128-bit key (k0, k1) */
    CSipHasher(uint64_t k0, uint64_t k1);
    /** Hash a 64-bit integer worth of data
     *  It is treated as if this was the little-endian interpretation of 8 bytes.
     *  This function can only be used when a multiple of 8 bytes have been written so far.
     */
    CSipHasher &Write(uint64_t data);
    /** Hash arbitrary bytes. */
    CSipHasher &Write(const unsigned char *data, size_t size);
    /** Compute the 64-bit SipHash-2-4 of the data written so far. The object remains untouched. */
    uint64_t Finalize() const;
};

/** Optimized SipHash-2-4 implementation for uint256.
 *
 *  It is identical to:
 *    SipHasher(k0, k1)
 *      .Write(val.GetUint64(0))
 *      .Write(val.GetUint64(1))
 *      .Write(val.GetUint64(2))
 *      .Write(val.GetUint64(3))
 *      .Finalize()
 */
uint64_t SipHashUint256(uint64_t k0, uint64_t k1, const uint256 &val);
uint64_t SipHashUint256Extra(uint64_t k0, uint64_t k1, const uint256 &val, uint32_t extra);

#endif // NEXA_HASH_H
