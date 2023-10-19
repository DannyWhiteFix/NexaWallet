// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CASHLIB_H
#define CASHLIB_H

// This removes an unneeded define that confuses the Kotlin/Native binding program
#ifdef CINTEROP
#define SLAPI
#endif

#include "stdint.h"
#include <stdbool.h>

// cashlib version
SLAPI int cashlibVersion();

/** Sign data (compatible with BCH OP_CHECKDATASIG) */
SLAPI int SignHashEDCSA(const unsigned char *data,
    int datalen,
    const unsigned char *secret,
    unsigned char *result,
    unsigned int resultLen);

/** Sign data via the Schnorr signature algorithm.  hash must be 32 bytes.
    All buffer arguments should be in binary-serialized data.
    The transaction (txData) must contain the COutPoint (tx hash and vout) of all relevant inputs,
    however, it is not necessary to provide the spend script.

    The returned signature will not have a sighashtype byte.
*/
SLAPI int SignHashSchnorr(const unsigned char *hash,
    const unsigned char *keyData,
    unsigned char *result);

/** Convert binary data to a hex string.  The provided result buffer must be 2*length+1 bytes.
 */
SLAPI int Bin2Hex(const unsigned char *val, int length, char *result, unsigned int resultLen);

/** Given a private key, return its corresponding public key */
SLAPI int GetPubKey(const unsigned char *keyData, unsigned char *result, unsigned int resultLen);

/** Sign one input of a transaction using an ECDSA signature
    All buffer arguments should be in binary-serialized data.
    The transaction (txData) must contain the COutPoint (tx hash and vout) of all relevant inputs,
    however, it is not necessary to provide the spend script.
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
    unsigned int resultLen);

/** Sign one input of a transaction using a Schnorr signature
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
    unsigned int resultLen);

/** Sign one input of a transaction using a Schnorr signature
    All buffer arguments should be in binary-serialized data.
    The transaction (txData) must contain the COutPoint (tx hash and vout) of all relevant inputs,
    however, it is not necessary to provide the spend script.
    Since the sighashtype is appended to the signature, more than 64 bytes should be alloced for the result.
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
    unsigned int resultLen);

/* DEPRECATED: same as SignTxOneInputUsingSchnorr */
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
    unsigned int resultLen);

/* Sign a hash (presumably the hash of some data) using an ECDSA signature */
SLAPI int SignHashECDSA(const unsigned char *hash,
    const unsigned char *keyData,
    unsigned char *result,
    unsigned int resultLen);



/* Sign a hash (presumably the hash of some data) using a Schnorr signature.  Result must be at least 64 bytes. */
SLAPI int SignHashSchnorr(const unsigned char *hash,
    const unsigned char *keyData,
    unsigned char *result);


// Returns <= 0 if error, size of result if good.
SLAPI int signMessage(const unsigned char* message, unsigned int msgLen,
                      const unsigned char* secret, unsigned int secretLen,
                      unsigned char *result, unsigned int resultLen);

// returns 0 if error, -size if recovered pubkey does not match addr (with pubkey in result), +size if match
SLAPI int verifyMessage(const unsigned char* message, unsigned int msgLen,
                         const unsigned char* addr, unsigned int addrLen,
                         const unsigned char* sig, unsigned int sigLen,
                         unsigned char *result, unsigned int resultLen);

/** Calculates the sha256 of data, and places it in result.  Result must be 32 bytes */
SLAPI void sha256(const unsigned char* data, unsigned int len, unsigned char* result);

/** Calculates the double sha256 of data and places it in result. Result must be 32 bytes */
SLAPI void hash256(const unsigned char* data, unsigned int len, unsigned char* result);

/** Calculates the RIPEMD160 of the SHA256 of data and places it in result. Result must be 20 bytes */
SLAPI void hash160(const unsigned char* data, unsigned int len, unsigned char* result);

/** Calculates the id of the passed serialized transaction.  Result must be 32 bytes */
SLAPI int txid(const unsigned char *txData, int txbuflen, unsigned char *result);

/** Calculates the idem of the passed serialized transaction.  Result must be 32 bytes */
SLAPI int txidem(const unsigned char *txData, int txbuflen, unsigned char *result);

/** Return random bytes from cryptographically acceptable random sources */
SLAPI int RandomBytes(unsigned char *buf, int num);

/** Get work from nbits */
SLAPI void getWorkFromDifficultyBits(unsigned long int nBits, unsigned char* result);


/** Returns 0 if invalid, -sizeNeeded if you did not give a large enough buffer, or the length of the result if it
    worked.
 */
SLAPI int encode64(const unsigned char* data, int size, char* result, int resultMaxLen);
SLAPI int decode64(const char* data, unsigned char* result, int resultMaxLen);

/** Create a bloom filter
The size of the result array must be allocated to be at least 32 bytes bigger than maxSize to account for the
serialization overhead.
*/
SLAPI int createBloomFilter(const unsigned char* data, unsigned int len, unsigned int elemLen, double falsePosRate, int capacity, int maxSize, int flags, int tweak, unsigned char* result);

/** Derive a BIP-0044 heirarchial deterministic wallet key */
SLAPI int hd44DeriveChildKey(const unsigned char *secretSeed,
    unsigned int secretSeedLen,
    unsigned int purpose,
    unsigned int coinType,
    unsigned int account,
    bool change,
    unsigned int index,
    unsigned char* secret,
    char *keypath);

SLAPI bool verifyBlockHeader(int chainSelector, const unsigned char *serializedHeader, int serLen);
SLAPI int encodeCashAddr(int chainSelector, int typ, const unsigned char *data, int len, char *result, int resultMaxLen);
SLAPI int decodeCashAddr(int chainSelector, const char *addrstr, unsigned char *result, int resultMaxLen);
SLAPI int groupIdFromAddr(int chainSelector,  const char *addrstr, unsigned char *result, int resultMaxLen);
SLAPI int groupIdToAddr(int chainSelector, const unsigned char *data, int len, char *result, int resultMaxLen);


SLAPI int decodeWifPrivateKey(int chainSelector, const char *secretWIF, unsigned char *result, int resultMaxLen);

SLAPI int blockHash(const unsigned char *data, int len, unsigned char *result);

SLAPI int extractFromMerkleBlock(int numTxes, const unsigned char *merkleProofPath, int mppLen,
                                 const unsigned char *hashIn, int numHashes,
                                 unsigned char *result, int resultLen);


#endif /* CASHLIB_H */
