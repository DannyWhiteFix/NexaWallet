// Copyright (c) 2018-2025 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "forks.h"

#include "unlimited.h"

/** Fork1 time MTP >= 12:00:00 PM, March 31st 2025, GMT */
const uint64_t FORK1_ACTIVATION_TIME = 1743422400;

// Fork1 on March 31st 2025
bool IsFork1Activated(const CBlockIndex *pindexTip)
{
    if ((pindexTip == nullptr) || (pindexTip->pprev == nullptr))
    {
        return false;
    }
    // Fork1 enables in the block AFTER the activation.  This gives us time to clean out the txpool.
    return pindexTip->pprev->GetMedianTimePast() >= (int64_t)FORK1_ACTIVATION_TIME;
}

// Fork1 on March 31st 2025
bool IsFork1Pending(const CBlockIndex *pindexTip)
{
    if (pindexTip == nullptr)
    {
        return false;
    }
    return !IsFork1Activated(pindexTip) && (pindexTip->GetMedianTimePast() >= (int64_t)FORK1_ACTIVATION_TIME);
}

bool IsFork2Activated(const CBlockIndex *pindexTip)
{
    if ((pindexTip == nullptr) || (pindexTip->pprev == nullptr))
    {
        return false;
    }

    if (Params().NetworkIDString() == CBaseChainParams::STORMTEST && pindexTip->height() > 2)
    {
        return true;
    }
    if (pindexTip->pprev->GetMedianTimePast() >= (int64_t)miningForkTime.Value())
    {
        return true;
    }

    return false;
}

bool IsFork2Pending(const CBlockIndex *pindexTip)
{
    if (pindexTip == nullptr)
    {
        return false;
    }

    if (Params().NetworkIDString() == CBaseChainParams::STORMTEST && pindexTip->height() == 2)
    {
        return true;
    }
    if (!IsFork2Activated(pindexTip) && (pindexTip->GetMedianTimePast() >= (int64_t)miningForkTime.Value()))
    {
        return true;
    }

    return false;
}
