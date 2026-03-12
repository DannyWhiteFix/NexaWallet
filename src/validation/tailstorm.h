// Copyright (c) 2025 The Bitcoin Unlimited developers

#ifndef NEXA_TAILSTORM_H
#define NEXA_TAILSTORM_H

#include "consensus/validation.h"
#include "primitives/block.h"
#include "sync.h"
#include "uint256.h"
#include "validation/dag.h"

#include <cstdint>
#include <utility>
#include <vector>

extern std::atomic<bool> fTailstormEnabled;

class CBlockIndex;

/** current version of miner data held in the block header */
static const uint8_t DEFAULT_MINER_DATA_SUMMARYBLOCK_VERSION = 2;

/** current subblock version held in the block header */
static const uint8_t DEFAULT_MINER_DATA_SUBBLOCK_VERSION = 1;

/** Prune subblocks from the dag if they in this block */
void PruneSubblocks(ConstCBlockRef pblock);

/** Is this block a summary block */
bool IsSummaryBlock(ConstCBlockRef pblock);
bool IsSummaryBlock(const CBlock &block);

/** Is this block a tailstorm summary block */
bool IsTailstormSummaryBlock(ConstCBlockRef pblock);
bool IsTailstormSummaryBlock(const CBlock &block);

/** Store this valid subblock for use in the DAG */
void AcceptSubblock(ConstCBlockRef pblock);

/** Create the miner data field that goes into the block header */
std::vector<uint8_t> GenerateMinerData(const uint32_t tailstorm_k,
    const std::set<CTreeNodeRef> &setBestDag,
    const uint256 &prevOfprevhash);

/** Get a vector of all prev hashes that this block references (subblocks could have more than one). */
std::set<uint256> GetPrevHashes(const CBlockHeader &header);

#endif
