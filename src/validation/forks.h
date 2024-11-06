// Copyright (c) 2018-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_FORKS_H
#define NEXA_FORKS_H

#include "chain.h"
#include "chainparams.h"

/** Check if fork1 is activated at a specific block.  Activated means that the new rules are applied in this block
 *
 * return true for [x, +inf)
 *
 * x-1 = first block for which median time past >= activation time
 * x = first block where the new consensus rules are enforced
 **/

bool IsFork1Activated(const CBlockIndex *pindexTip);

/* Check if the next block will enable fork1 */
bool IsFork1Pending(const CBlockIndex *pindexTip);
#endif
