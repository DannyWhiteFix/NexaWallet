// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_CONSENSUS_CONSENSUS_H
#define NEXA_CONSENSUS_CONSENSUS_H

#include "chain.h"
#include "script/interpreter.h"
#include "tweak.h"
#include "uint256.h"

extern CChain chainActive;
extern CTweak<uint64_t> maxSigChecks;
extern CTweak<uint64_t> maxAllowedNetMessage;
extern CTweak<uint64_t> nextMaxBlockSize;

static const unsigned int ONE_MEGABYTE = 1000000;
static const unsigned int ONE_DAY_OF_BLOCKS = 144 * 5; // average number of blocks mined per day

/** Adaptive block size params */
static const uint64_t DEFAULT_NEXT_MAX_BLOCK_SIZE = 100000; // 100KB
static const uint64_t DEFAULT_NEXT_MAX_BLOCK_SIZE_FORK1 = 2 * ONE_MEGABYTE;
static const uint64_t DEFAULT_NEXT_MAX_BLOCK_SIZE_FORK1_REGTEST = 150000; // 150KB
static const uint64_t SHORT_BLOCK_WINDOW = ONE_DAY_OF_BLOCKS * 90; // 90 days of blocks
static const uint64_t LONG_BLOCK_WINDOW = ONE_DAY_OF_BLOCKS * 365; // 365 days of blocks
static const uint64_t SHORT_BLOCK_WINDOW_REGTEST = 150; // used for testing only!
static const uint64_t LONG_BLOCK_WINDOW_REGTEST = 300; // used for testing only!
static const uint64_t SHORT_BLOCK_WINDOW_TESTNET = ONE_DAY_OF_BLOCKS * 7; // 7 days of blocks - used for testing only!
static const uint64_t LONG_BLOCK_WINDOW_TESTNET = ONE_DAY_OF_BLOCKS * 14; // 14 days of blocks - used for testing only!
static const uint64_t BLOCK_SIZE_MULTIPLIER = 10;

/** Largest block possible */
static const uint64_t DEFAULT_LARGEST_BLOCKSIZE_POSSIBLE = 1000 * ONE_MEGABYTE;

/** The maximum allowed number of signature check operations in a 1MB block (network rule), and the suggested max sigops
 * per (MB rounded up) in blocks > 1MB. */
static const unsigned int MAX_TX_SIGCHECK_COUNT = 3000;
/** The maximum suggested length of a transaction */
static const unsigned int DEFAULT_LARGEST_TRANSACTION = ONE_MEGABYTE;
/** The minimum allowed size for a transaction, in bytes */
static const unsigned int MIN_TX_SIZE = 65;
static const unsigned int MAX_TX_NUM_VOUT = 256;
static const unsigned int MAX_TX_NUM_VIN = 256;

/* If the current height is odd, the ancestor block is the current height minus this constant.
   This a a week of blocks at 2 minutes per block.  But since this gap is arbitrary, it is simpler to just define
   the "odd" ancestor to be this constant, regardless of block discovery rate, rather than make it a chain parameter.
*/
static const int64_t ANCESTOR_HASH_IF_ODD = 5040;

/** This is the default max bloom filter size allowed on the network.  In Nexa we have the ability
 *  to communicate to our peer what max bloom filter size we will accept but still observe this value as a default.
 */
static const unsigned int SMALLEST_MAX_BLOOM_FILTER_SIZE = 36000; // bytes

/** Coinbase transaction outputs can only be spent after this number of new blocks (network rule) */
static const int COINBASE_MATURITY = 5000;
static const int COINBASE_MATURITY_TESTNET = 100;

/**
 * Mandatory script verification flags that all new blocks must comply with for
 * them to be valid. (but old blocks may not comply with) Currently just P2SH,
 * but in the future other flags may be added, such as a soft-fork to enforce
 * strict DER encoding.
 *
 * Failing one of these tests may trigger a DoS ban - see CheckInputs() for
 * details.
 */
/* clang-format off */
static const uint32_t MANDATORY_SCRIPT_VERIFY_FLAGS = SCRIPT_VERIFY_P2SH |
                                                      SCRIPT_VERIFY_STRICTENC |
                                                      SCRIPT_ENABLE_SIGHASH_FORKID |
                                                      SCRIPT_VERIFY_LOW_S |
                                                      SCRIPT_VERIFY_NULLFAIL |
                                                      SCRIPT_VERIFY_MINIMALDATA |
                                                      SCRIPT_ALLOW_64_BIT_INTEGERS |
                                                      SCRIPT_ALLOW_NATIVE_INTROSPECTION |
                                                      SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY |
                                                      SCRIPT_VERIFY_CHECKSEQUENCEVERIFY |
                                                      SCRIPT_ENABLE_CHECKDATASIG;

/* clang-format on */

/**
 * The ratio between the maximum allowable block size and the maximum allowable
 * SigChecks (executed signature check operations) in the block, or in other words, how
 * many block bytes per sigcheck. (network rule).
 */
static const uint16_t BLOCK_SIGCHECKS_RATIO = 141;

/**
 * Compute the maximum number of sigchecks that can be contained in a block
 * given the MAXIMUM block size as parameter. The maximum sigchecks scale
 * linearly with the maximum block size and do not depend on the actual
 * block size. The returned value is rounded down (there are no fractional
 * sigchecks so the fractional part is meaningless).
 */
inline uint64_t GetMaxBlockSigChecks(uint64_t nBlockSize)
{
    if (maxSigChecks.Value() > 0)
        return maxSigChecks.Value();
    if (!nextMaxBlockSize.Value())
        assert(nBlockSize >= DEFAULT_NEXT_MAX_BLOCK_SIZE);

    return nBlockSize / BLOCK_SIGCHECKS_RATIO;
}

/** Flags for nSequence and nLockTime locks */
enum
{
    /* Interpret sequence numbers as relative lock-time constraints. */
    LOCKTIME_VERIFY_SEQUENCE = (1 << 0),

    /* Use GetMedianTimePast() instead of nTime for end point timestamp. */
    LOCKTIME_MEDIAN_TIME_PAST = (1 << 1),
};

// Max allowed message assumes that the next block size will be
// the largest message plus 1MB of additional padding.
inline uint64_t GetMaxAllowedNetMessage()
{
    // Used in testing only!
    if (maxAllowedNetMessage.Value())
        return maxAllowedNetMessage.Value();

    // Return the max net message value based on the next
    // expected max block size plus some additional padding
    uint64_t nMaxSize = 0;
    CBlockIndex *tip = chainActive.Tip();
    if (tip)
        nMaxSize = tip->GetNextMaxBlockSize();

    return nMaxSize + ONE_MEGABYTE;
}
#endif // NEXA_CONSENSUS_CONSENSUS_H
