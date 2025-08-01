// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_CHAINPARAMS_H
#define NEXA_CHAINPARAMS_H

#include "chainparamsbase.h"
#include "consensus/params.h"
#include "primitives/block.h"
#include "protocol.h"

#include <vector>

// Fork configuration
/** This specifies the MTP time of the next fork */
extern uint64_t nMiningForkTime;

/** Default for -minrelaytxfee, minimum relay fee for transactions */
static const unsigned int DEFAULT_MIN_RELAY_TX_FEE = 1000;
//! -wallet.maxTxFee default
static const CAmount DEFAULT_TRANSACTION_MAXFEE = 10000 * COIN;
//! Discourage users to set fees higher than this amount (in satoshis) per kB
static const CAmount HIGH_TX_FEE_PER_KB = 1000 * COIN;
//! -wallet.maxTxFee will warn if called with a higher fee than this amount (in satoshis)
static const CAmount HIGH_MAX_TX_FEE = 100 * HIGH_TX_FEE_PER_KB;
/** Default for -cache.maxOrphanTx, maximum number of orphan transactions kept in memory.
 *  A high default is chosen which allows for about 1/10 of the default mempool to
 *  be kept as orphans, assuming 250 byte transactions.  We are essentially disabling
 *  the limiting or orphan transactions by number and using orphan pool bytes as
 *  the limiting factor, while at the same time allowing node operators to
 *  limit by number if transactions if they wish by modifying -cache.maxOrphanTx=<n> if
 *  the have a need to.
 */
static const unsigned int DEFAULT_MAX_ORPHAN_TRANSACTIONS = 1000000;
/** Default for -cache.memoryPoolExpiry, expiration time for mempool transactions in hours */
static const unsigned int DEFAULT_MEMPOOL_EXPIRY = 72;
/** Default for -cache.orphanPoolExpiry, expiration time for orphan pool transactions in hours */
static const unsigned int DEFAULT_ORPHANPOOL_EXPIRY = 4;


struct CDNSSeedData
{
    std::string name, host;
    bool supportsServiceBitsFiltering;
    CDNSSeedData(const std::string &strName, const std::string &strHost, bool supportsServiceBitsFilteringIn = false)
        : name(strName), host(strHost), supportsServiceBitsFiltering(supportsServiceBitsFilteringIn)
    {
    }
};

struct SeedSpec6
{
    uint8_t addr[16];
    uint16_t port;
};

typedef std::map<int, uint256> MapCheckpoints;

struct CCheckpointData
{
    MapCheckpoints mapCheckpoints;
    int64_t nTimeLastCheckpoint;
};

/**
 * CChainParams defines various tweakable parameters of a given instance of the
 * Nexa system. There are three: the main network on which people trade goods
 * and services, the public test network which gets reset from time to time and
 * a regression test mode which is intended for private networks only. It has
 * minimal difficulty to ensure that blocks can be found instantly.
 */
class CChainParams : public CBaseChainParams
{
public:
    const Consensus::Params &GetConsensus() const { return consensus; }
    /** Modifiable consensus parameters added by bip135, is not threadsafe, only use during initializtion */
    Consensus::Params &GetModifiableConsensus() { return consensus; }
    const CMessageHeader::MessageStartChars &MessageStart() const { return pchMessageStart; }
    const CBlock &GenesisBlock() const { return genesis; }
    const std::vector<CDNSSeedData> &DNSSeeds() const { return vSeeds; }
    const std::vector<SeedSpec6> &FixedSeeds() const { return vFixedSeeds; }
    const CCheckpointData &Checkpoints() const { return checkpointData; }
    /** The pre-allocation chunk size for blk?????.dat files */
    uint64_t nBlockFileSize;
    /** The pre-allocation chunk size for rev?????.dat files */
    uint64_t nUndoFileSize;

protected:
    CChainParams() {}
    Consensus::Params consensus;
    CMessageHeader::MessageStartChars pchMessageStart;
    std::vector<CDNSSeedData> vSeeds;
    std::vector<SeedSpec6> vFixedSeeds;
    CBlock genesis;
    CCheckpointData checkpointData;
};

/**
 * Return the currently selected parameters. This won't change after app
 * startup, except for unit tests.
 */
const CChainParams &Params();

/**
 * @returns CChainParams for the given BIP70 chain name.
 */
CChainParams &Params(const std::string &chain);

/**
 * Sets the params returned by Params() to those for the given BIP70 chain name.
 * @throws std::runtime_error when the chain is not supported.
 */
void SelectParams(const std::string &chain);

SatoshiBlock CreateGenesisBlock(CScript prefix,
    const std::string &comment,
    const CScript &genesisOutputScript,
    uint32_t nTime,
    uint32_t nNonce,
    uint32_t nBits,
    int32_t nVersion,
    const CAmount &genesisReward);

/**
 * Return the currently selected parameters. Can be changed by reading in
 * some additional config files (e.g. CSV deployment data)
 *
 * This can only be used during initialization because modification is not threadsafe
 */
CChainParams &ModifiableParams();

#endif // NEXA_CHAINPARAMS_H
