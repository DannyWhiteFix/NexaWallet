// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_CRYPTO_HASH160_H
#define NEXA_CRYPTO_HASH160_H

#include "crypto/ripemd160.h"
#include "crypto/sha256.h"
#include "prevector.h"
#include "uint256.h"

/** A hasher class for Bitcoin's 160-bit hash (SHA-256 + RIPEMD-160). */
class CHash160
{
private:
    CSHA256 sha;

public:
    static const size_t OUTPUT_SIZE = CRIPEMD160::OUTPUT_SIZE;

    void Finalize(unsigned char hash[OUTPUT_SIZE])
    {
        unsigned char buf[CSHA256::OUTPUT_SIZE];
        sha.Finalize(buf);
        CRIPEMD160().Write(buf, CSHA256::OUTPUT_SIZE).Finalize(hash);
    }

    CHash160 &Write(const unsigned char *data, size_t len)
    {
        sha.Write(data, len);
        return *this;
    }

    CHash160 &Reset()
    {
        sha.Reset();
        return *this;
    }
};

/** Compute the 160-bit hash an object. */
template <typename T1>
inline uint160 Hash160(const T1 pbegin, const T1 pend)
{
    static unsigned char pblank[1] = {};
    uint160 result;
    CHash160()
        .Write(pbegin == pend ? pblank : (const unsigned char *)&pbegin[0], (pend - pbegin) * sizeof(pbegin[0]))
        .Finalize((unsigned char *)&result);
    return result;
}

/** Compute the 160-bit hash an object. */
template <typename T1>
inline std::vector<unsigned char> VchHash160(const T1 pbegin, const T1 pend)
{
    static unsigned char pblank[1] = {};
    std::vector<unsigned char> result(20);
    CHash160()
        .Write(pbegin == pend ? pblank : (const unsigned char *)&pbegin[0], (pend - pbegin) * sizeof(pbegin[0]))
        .Finalize(&result[0]);
    return result;
}

/** Compute the 160-bit hash of a vector. */
inline uint160 Hash160(const std::vector<unsigned char> &vch) { return Hash160(vch.begin(), vch.end()); }
/** Compute the 160-bit hash of a vector. */
inline std::vector<unsigned char> VchHash160(const std::vector<unsigned char> &vch)
{
    return VchHash160(vch.begin(), vch.end());
}
/** Compute the 160-bit hash of a vector. */
template <unsigned int N>
inline uint160 Hash160(const prevector<N, unsigned char> &vch)
{
    return Hash160(vch.begin(), vch.end());
}
/** Compute the 160-bit hash of a vector. */
template <unsigned int N>
inline std::vector<unsigned char> VchHash160(const prevector<N, unsigned char> &vch)
{
    return VchHash160(vch.begin(), vch.end());
}

#endif // NEXA_CRYPTO_HASH160_H
