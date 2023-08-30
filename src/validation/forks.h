// Copyright (c) 2018-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_FORKS_H
#define NEXA_FORKS_H

#include "chain.h"
#include "chainparams.h"

/** Check if fork1 is activated at a specific block */
bool IsFork1Enabled(const CBlockIndex *pindexTip);

/** Check if the next block will be the first block, where the new set of rules for fork1 will be enforced */
bool IsFork1Next(const CBlockIndex *pindexTip);

#endif
