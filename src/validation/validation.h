
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_VALIDATION_H
#define NEXA_VALIDATION_H

#include "chainparams.h"
#include "consensus/validation.h"
#include "forks.h"
#include "parallel.h"
#include "txdebugger.h"
#include "txmempool.h"

// The group token cache can and should be compiled even when the wallet is disabled.
#include "wallet/grouptokencache.h"

/** Default for -blockchain.maxReorgDepth. A value less than zero disables the feature */
static const int DEFAULT_MAX_REORG_DEPTH = -1; // disabled

/** Is express validation turned on/off */
static const bool DEFAULT_XVAL_ENABLED = false;

enum DisconnectResult
{
    DISCONNECT_OK, // All good.
    DISCONNECT_UNCLEAN, // Rolled back, but UTXO set was inconsistent with block.
    DISCONNECT_FAILED // Something else went wrong.
};

/** Context-independent validity checks */
bool CheckBlockHeader(const Consensus::Params &consensusParams,
    const CBlockHeader &block,
    CValidationState &state,
    bool fCheckPOW = true);

/** Context-dependent validity header checks */
bool ContextualCheckBlockHeader(const CChainParams &chainparams,
    const CBlockHeader &block,
    CValidationState &state,
    CBlockIndex *const pindexPrev);

bool AcceptBlockHeader(const CBlockHeader &block,
    CValidationState &state,
    const CChainParams &chainparams,
    CBlockIndex **ppindex = nullptr);

/** Create a new block index entry for a new block or header that has arrived.
 *  This updates setDirtyBlockIndex only.
 */
CBlockIndex *AddToBlockIndex(const CChainParams &chainparams, const CBlockHeader &block);

/** Add a block index entry for a given block hash.
 *  This is used when loading the block index at startup or upgrading the database.
 */
CBlockIndex *InsertBlockIndex(const uint256 &hash);

/** Look up the block index entry for a given block hash. returns nullptr if it does not exist */
CBlockIndex *LookupBlockIndex(const uint256 &hash);

/** Unload database information */
void UnloadBlockIndex();

/** Load the block tree and coins database from disk */
bool LoadBlockIndex();

/** Initialize a new block tree database + block data on disk */
bool InitBlockIndex(const CChainParams &chainparams);

/** Upgrade the block index if needed */
bool UpgradeBlockIndex();

void CheckBlockIndex(const Consensus::Params &consensusParams);

/**
 * Check whether all inputs of this transaction are valid (no double spends, scripts & sigs, amounts)
 * This does not modify the UTXO set. If pvChecks is not nullptr, script checks are pushed onto it
 * instead of being performed inline.
 */
bool CheckInputs(const CTransactionRef &tx,
    CValidationState &state,
    const CCoinsViewCache &inputs,
    const CCoinsViewCache &readonlyinputs,
    bool fScriptChecks,
    const unsigned int flags,
    bool cacheStore,
    ValidationResourceTracker *resourceTracker,
    const CChainParams &chainparams,
    std::vector<CScriptCheck> *pvChecks = nullptr,
    unsigned char *sighashType = nullptr,
    CValidationDebugger *debugger = nullptr);

/** Remove invalidity status from a block and its descendants. */
bool ReconsiderBlock(CValidationState &state, CBlockIndex *pindex);

/** Check a block is completely valid from start to finish (only works on top of our current best block, with cs_main
 * held) */
bool TestBlockValidity(CValidationState &state,
    const CChainParams &chainparams,
    const ConstCBlockRef pblock,
    CBlockIndex *pindexPrev,
    bool fCheckPOW = true,
    bool fCheckMerkleRoot = true);

CAmount GetBlockSubsidy(int nHeight, const Consensus::Params &consensusParams);

/** return total number of satoshis minted till nHeight
 */
uint64_t GetCoinsMinted(int nHeight, const Consensus::Params &consensusParams);

/**
 * Determine what nVersion a new block should use.
 */
int32_t ComputeBlockVersion(const CBlockIndex *pindexPrev, const Consensus::Params &params);

CBlockIndex *FindMostWorkChain();

/** Mark a block as invalid. */
bool InvalidateBlock(CValidationState &state, const Consensus::Params &consensusParams, CBlockIndex *pindex);

void InvalidChainFound(CBlockIndex *pindexNew);

/** Context-dependent validity block checks */
bool ContextualCheckBlock(ConstCBlockRef pblock, CValidationState &state, CBlockIndex *pindexPrev);

/** returns the blocksize if block is valid.  Otherwise 0 */
bool CheckBlock(const Consensus::Params &consensusParams,
    ConstCBlockRef pblock,
    CValidationState &state,
    bool fCheckPOW = true,
    bool fCheckMerkleRoot = true);

/** Mark a block as having its data received and checked (up to BLOCK_VALID_TRANSACTIONS). */
bool ReceivedBlockTransactions(ConstCBlockRef pblock,
    CValidationState &state,
    CBlockIndex *pindexNew,
    const CDiskBlockPos &pos);

uint32_t GetBlockScriptFlags(const CBlockIndex *pindex, const Consensus::Params &consensusparams);

/** Undo the effects of this block (with given index) on the UTXO set represented by coins.
 *  In case pfClean is provided, operation will try to be tolerant about errors, and *pfClean
 *  will be true if no problems were found. Otherwise, the return value will be false in case
 *  of problems. Note that in any case, coins may be modified. */
DisconnectResult DisconnectBlock(const ConstCBlockRef pblock, const CBlockIndex *pindex, CCoinsViewCache &view);

/** Apply the effects of this block (with given index) on the UTXO set represented by coins */
bool ConnectBlock(ConstCBlockRef pblock,
    CValidationState &state,
    CBlockIndex *pindex,
    CCoinsViewCache &view,
    const CChainParams &chainparams,
    std::map<CGroupTokenID, CAmount> &accumulatedMintages,
    std::map<CGroupTokenID, CAuth> &accumulatedAuthorities,
    bool fJustCheck = false,
    bool fParallel = false);

/** Disconnect the current chainActive.Tip() */
bool DisconnectTip(CValidationState &state, const Consensus::Params &consensusParams, const bool fRollBack = false);

/** Find the best known block, and make it the tip of the block chain.  Locks cs_main and pauses tx admission. */
bool ActivateBestChain(CValidationState &state,
    const CChainParams &chainparams,
    ConstCBlockRef pblock = nullptr,
    bool fParallel = false,
    CNode *pfrom = nullptr);

/** Find the best known block, and make it the tip of the block chain.  Expects that cs_main is taken and
    tx admission is paused. */
bool _ActivateBestChain(CValidationState &state,
    const CChainParams &chainparams,
    ConstCBlockRef pblock = nullptr,
    bool fParallel = false,
    CNode *pfrom = nullptr);
/**
 * Process an incoming block. This only returns after the best known valid
 * block is made active. Note that it does not, however, guarantee that the
 * specific block passed to it has been checked for validity!
 *
 * @param[out]  state   This may be set to an Error state if any error occurred processing it, including during
 * validation/connection/etc of otherwise unrelated blocks during reorganisation; or it may be set to an Invalid state
 * if pblock is itself invalid (but this is not guaranteed even when the block is checked). If you want to *possibly*
 * get feedback on whether pblock is valid, you must also install a CValidationInterface (see validationinterface.h) -
 * this will have its BlockChecked method called whenever *any* block completes validation.
 * @param[in]   pfrom   The node which we are receiving the block from; it is added to mapBlockSource and may be
 * penalised if the block is invalid.
 * @param[in]   pblock  The block we want to process.
 * @param[in]   fForceProcessing Process this block even if unrequested; used for non-network block sources and
 * whitelisted peers.
 * @param[out]  dbp     If pblock is stored to disk (or already there), this will be set to its location.
 * @return True if state.IsValid()
 */
bool ProcessNewBlock(CValidationState &state,
    const CChainParams &chainparams,
    CNode *pfrom,
    ConstCBlockRef pblock,
    bool fForceProcessing,
    CDiskBlockPos *dbp,
    bool fParallel);

//! Check whether the block associated with this index entry is pruned or not.
bool IsBlockPruned(const CBlockIndex *pblockindex);

#endif
