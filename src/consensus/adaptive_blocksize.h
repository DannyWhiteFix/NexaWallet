// Copyright (c) 2021-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ADAPTIVE_BLOCKSIZE_H
#define ADAPTIVE_BLOCKSIZE_H

#include "chain.h"
#include "chainparams.h"
#include "consensus/consensus.h"
#include "uint256.h"

/** Add an element to an already sorted list such that the list remains sorted after the insert of new data.
 *  This sorting mechanism will not maintain the order of equivalents and so can not be used if a "stable sort"
 *  is needed.
 */
void InsertInSortedOrder(uint64_t nBlockSize, std::vector<uint64_t> &vData);

/** Return the next maximum block size allowed */
uint64_t CalculateNextMaxBlockSize(CBlockIndex *pindexPrev, uint64_t nBlockSize);

/** Return the max sigchecks allowed for a specified block size */
uint64_t GetMaxBlockSigChecks(uint64_t nBlockSize);

/** Caculated the median value from a vector of values */
uint64_t CalculateMedian(std::vector<uint64_t> &vData);

/** Gather new block size data into sorted and unsorted structures and then
 *  use those data structures to find the median value
 */
bool CalculateMedianSize(CBlockIndex *pindexNew,
    uint64_t nBlockSize,
    uint64_t nWindow,
    std::vector<uint64_t> &vSizes,
    std::deque<uint64_t> &vSizes_Unsorted,
    CBlockIndex **pindexTip,
    bool &fRunOnce,
    uint64_t &nMedianSize);

#endif
