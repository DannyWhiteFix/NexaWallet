// Copyright (c) 2018-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "forks.h"

bool IsFork1Activated(const CBlockIndex *pindexTip)
{
    if ((pindexTip == nullptr) || (pindexTip->pprev == nullptr))
    {
        return false;
    }
    // Fork1 enables the in the block AFTER the activation.  This gives us time to clean out the txpool.
    return pindexTip->pprev->GetMedianTimePast() >= (int64_t)nMiningForkTime;
}

bool IsFork1Pending(const CBlockIndex *pindexTip)
{
    if (pindexTip == nullptr)
    {
        return false;
    }
    return !IsFork1Activated(pindexTip) && (pindexTip->GetMedianTimePast() >= (int64_t)nMiningForkTime);
}
