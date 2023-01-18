// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_POLICY_POLICY_H
#define NEXA_POLICY_POLICY_H

#include "consensus/consensus.h"
#include "script/interpreter.h"
#include "script/standard.h"

#include <string>

class CCoinsViewCache;

// Maximum number of mining candidates that this node will remember simultaneously
static const unsigned int DEFAULT_MAX_MINING_CANDIDATES = 10;
// Send an existing mining candidate if a request comes in within this many seconds of its construction
static const unsigned int DEFAULT_MIN_CANDIDATE_INTERVAL = 30;
/** Default for -blockprioritysize for priority or zero/low-fee transactions **/
static const unsigned int DEFAULT_BLOCK_PRIORITY_SIZE = 0;

/** The maximum size for transactions we're willing to relay/mine */
static const unsigned int MAX_STANDARD_TX_SIZE = 100000;

/** Maximum number of signature check operations in an IsStandard() P2SH script */
static const unsigned int MAX_P2SH_SIGOPS = 15;
/** The maximum number of sigops we're willing to relay/mine in a single tx */
static const unsigned int MAX_STANDARD_TX_SIGOPS = MAX_TX_SIGOPS_COUNT / 5;
/** Default for -cache.maxMemPool, maximum megabytes of mempool memory usage */
static const unsigned int DEFAULT_MAX_MEMPOOL_SIZE = 300;
/** Dust threshold in satoshis. Historically this value was calculated as
 *  minRelayTxFee/1000 * 546. However now we just allow the operator to set
 *  a simple dust threshold independant of any other value or relay fee.
 */
static const unsigned int DEFAULT_DUST_THRESHOLD = 546;

/**
 * Standard script verification flags that standard transactions will comply
 * with. However scripts violating these flags may still be present in valid
 * blocks and we must accept those blocks.
 */

/* clang-format off */
static const unsigned int STANDARD_SCRIPT_VERIFY_FLAGS = MANDATORY_SCRIPT_VERIFY_FLAGS |
                                                         SCRIPT_VERIFY_DERSIG |
                                                         SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS |
                                                         SCRIPT_VERIFY_CLEANSTACK |
                                                         SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY |
                                                         SCRIPT_VERIFY_CHECKSEQUENCEVERIFY |
                                                         SCRIPT_VERIFY_SIGPUSHONLY |
                                                         SCRIPT_ENABLE_CHECKDATASIG;
/* clang-format on */

/** For convenience, standard but not mandatory verify flags. */
static const unsigned int STANDARD_NOT_MANDATORY_VERIFY_FLAGS =
    STANDARD_SCRIPT_VERIFY_FLAGS & ~MANDATORY_SCRIPT_VERIFY_FLAGS;

/** Used as the flags parameter to sequence and nLocktime checks in non-consensus code. */
static const unsigned int STANDARD_LOCKTIME_VERIFY_FLAGS = LOCKTIME_VERIFY_SEQUENCE | LOCKTIME_MEDIAN_TIME_PAST;

/** largest OP_RETURN, in bytes, allowed */
static const unsigned int MAX_OP_RETURN_RELAY = 223; //! bytes (+1 for OP_RETURN, +2 for the pushdata opcodes)
/** Do we accept OP_RETURN transactions */
static const bool DEFAULT_ACCEPT_DATACARRIER = true;

bool IsStandard(const CScript &scriptPubKey, txnouttype &whichType);
/**
 * Check for standard transaction types
 * @return True if all outputs (scriptPubKeys) use only standard transaction forms
 */
bool IsStandardTx(const CTransactionRef tx, std::string &reason);
/**
 * Check for standard transaction types
 * @param[in] mapInputs    Map of previous transactions that have outputs we're spending
 * @return True if all inputs (scriptSigs) use only standard transaction forms
 */
bool AreInputsStandard(const CTransactionRef tx, const CCoinsViewCache &mapInputs);

#endif // NEXA_POLICY_POLICY_H
