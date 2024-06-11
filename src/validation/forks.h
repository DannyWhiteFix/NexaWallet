// Copyright (c) 2018-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_FORKS_H
#define NEXA_FORKS_H

#include "chain.h"
#include "chainparams.h"

/** Check if fork1 is Enabled at a specific block
 *
 * return true for [x-1, +inf)
 *
 * x-1 = first block for which median time past >= activation time
 * x = first block where the new consensus rules are enforced
 **/

bool IsFork1Enabled(const CBlockIndex *pindexTip);
#endif
