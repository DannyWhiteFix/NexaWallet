// Copyright (c) 2021-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "consensus/adaptive_blocksize.h"
#include "validation/forks.h"

CCriticalSection cs_median;
std::vector<uint64_t> vSizesShortWindow GUARDED_BY(cs_median);
std::vector<uint64_t> vSizesLongWindow GUARDED_BY(cs_median);
std::deque<uint64_t> vSizesShortWindow_Unsorted GUARDED_BY(cs_median);
std::deque<uint64_t> vSizesLongWindow_Unsorted GUARDED_BY(cs_median);
bool fRunOnceLongWindow GUARDED_BY(cs_median) = true;
bool fRunOnceShortWindow GUARDED_BY(cs_median) = true;
static CBlockIndex *pindexTip_ShortWindow GUARDED_BY(cs_median) = nullptr;
static CBlockIndex *pindexTip_LongWindow GUARDED_BY(cs_median) = nullptr;

static bool IsSorted(std::vector<uint64_t> &vData)
{
#ifdef DEBUG
    return std::is_sorted(vData.begin(), vData.end());
#else
    return true;
#endif
}

uint64_t CalculateMedian(std::vector<uint64_t> &vData)
{
    LOCK(cs_median);

    if (!(vData.size() % 2) || vData.empty())
        throw std::runtime_error("Data size does not contain an odd number of elements");

    // Assert that data must already be sorted before we try to add another element. This takes
    // so only run this in debug mode.
    DbgAssert(IsSorted(vData), );

    std::vector<uint64_t>::iterator it = vData.begin();
    std::advance(it, (vData.size() - 1) / 2);
    return *it;
}

void InsertInSortedOrder(uint64_t nBlockSize, std::vector<uint64_t> &vData)
{
    // This feature is used to quickly add a new data element to an already sorted list
    // while preserving the sort order after the insert is complete.

    LOCK(cs_median);

    // Assert that data must already be sorted before we try to add another element. This takes
    // time so only run this in debug mode.
    DbgAssert(IsSorted(vData), );

    auto it = std::lower_bound(vData.begin(), vData.end(), nBlockSize);
    vData.insert(it, nBlockSize);

    // Make sure the data is still sorted (Only run in debug mode).
    DbgAssert(IsSorted(vData), );
}

bool CalculateMedianSize(CBlockIndex *pindexNew,
    uint64_t nBlockSize,
    uint64_t nWindow,
    std::vector<uint64_t> &vSizes,
    std::deque<uint64_t> &vSizes_Unsorted,
    CBlockIndex **pindexTip,
    bool &fRunOnce,
    uint64_t &nMedianSize)
{
    LOCK(cs_median);

    // If we don't have the same previous blockindex then we must have switched
    // chains so we need to rebuild the data for the entire window if it exists.
    if (pindexNew && pindexNew->pprev != *pindexTip)
    {
        vSizes.clear();
        vSizes_Unsorted.clear();

        vSizes.insert(vSizes.begin(), nBlockSize);
        vSizes_Unsorted.push_front(nBlockSize);

        if (pindexNew->pprev)
        {
            CBlockIndex *pindex = pindexNew->pprev;
            for (uint64_t i = 1; i <= nWindow; i++)
            {
                vSizes.insert(vSizes.begin(), pindex->GetBlockSize());
                vSizes_Unsorted.push_front(pindex->GetBlockSize());

                if (!pindex->pprev)
                {
                    break;
                }
                pindex = pindex->pprev;
            }
        }

        // Once we rebuild the data then sort it just this once. Any
        // more data that gets added will get added in sorted order.
        std::sort(vSizes.begin(), vSizes.end());
    }
    else
    {
        // We make the cutoff here at nWindow-1 rather than nWindow.
        if (vSizes.size() < nWindow)
        {
            vSizes.push_back(nBlockSize);
        }
        else
        {
            // Just sort the first time calling this function. After the first sort all data
            // should be inserted in sorted order.
            if (fRunOnce)
            {
                assert(vSizes.size() == nWindow);
                std::sort(vSizes.begin(), vSizes.end());
                fRunOnce = false;
            }

            InsertInSortedOrder(nBlockSize, vSizes);
        }

        vSizes_Unsorted.push_back(nBlockSize);
    }

    // update *pindexTip for the next call to CaculateMedianSize()
    *pindexTip = pindexNew;

    // Calculate the median value if we've met our window target
    assert(vSizes_Unsorted.size() == vSizes.size());
    assert(vSizes.size() <= nWindow + 1);
    if (vSizes.size() == nWindow + 1)
    {
        try
        {
            nMedianSize = CalculateMedian(vSizes);
        }
        catch (...)
        {
            assert("Incorrect number of elements for median size calculation");
        }

        // remove the oldest value
        uint64_t nSizeToRemove = vSizes_Unsorted.front();
        auto it = std::find(vSizes.begin(), vSizes.end(), nSizeToRemove);
        assert(it != vSizes.end());
        {
            vSizes.erase(it);
            vSizes_Unsorted.pop_front();
        }

        assert(vSizes.size() == nWindow);
        assert(vSizes_Unsorted.size() == nWindow);

        return true;
    }

    return false;
}

uint64_t CalculateNextMaxBlockSize(CBlockIndex *pindexPrev, uint64_t nBlockSize)
{
    uint64_t nBlockSizeMultiplier = Params().GetConsensus().nBlockSizeMultiplier;

    uint64_t nNextMaxBlockSize = 0;
    if (IsFork1Enabled(pindexPrev))
        nNextMaxBlockSize = Params().GetConsensus().nNextMaxBlockSize;
    else
        nNextMaxBlockSize = DEFAULT_NEXT_MAX_BLOCK_SIZE;

    if (!pindexPrev)
        return nNextMaxBlockSize;

    // Find the median blocksize values for both long and short windows. Whichever median is highest we will use to
    // determine the next max blocksize.
    uint64_t nMedianShortWindow = 0;
    bool fShortWindow = CalculateMedianSize(pindexPrev, nBlockSize, Params().GetConsensus().nShortBlockWindow,
        vSizesShortWindow, vSizesShortWindow_Unsorted, &pindexTip_ShortWindow, fRunOnceShortWindow, nMedianShortWindow);
    uint64_t nMedianLongWindow = 0;
    bool fLongWindow = CalculateMedianSize(pindexPrev, nBlockSize, Params().GetConsensus().nLongBlockWindow,
        vSizesLongWindow, vSizesLongWindow_Unsorted, &pindexTip_LongWindow, fRunOnceLongWindow, nMedianLongWindow);

    // In general we will have both the long and short window median values, however during the initial mining
    // of the new chain we may not yet have either the short window or both short and long window median values.
    if (fLongWindow && fShortWindow)
    {
        LOG(VALIDATION, "Validation: 90/365 days median block size: %" PRIu64 "/%" PRIu64, nMedianShortWindow,
            nMedianLongWindow);
        nNextMaxBlockSize = std::max(nMedianShortWindow, nMedianLongWindow) * nBlockSizeMultiplier;
    }
    else if (fShortWindow)
    {
        LOG(VALIDATION, "Validation: 90 days median block size: %" PRIu64, nMedianShortWindow);
        nNextMaxBlockSize = nMedianShortWindow * nBlockSizeMultiplier;
    }
    LOG(VALIDATION, "Validation: Next maximum block size candidate (bytes): %" PRIu64, nNextMaxBlockSize);

    // use the default value if next max size is too small.
    if (IsFork1Enabled(pindexPrev))
    {
        nNextMaxBlockSize = std::max(nNextMaxBlockSize, Params().GetConsensus().nNextMaxBlockSize);
    }
    else
    {
        nNextMaxBlockSize = std::max(nNextMaxBlockSize, DEFAULT_NEXT_MAX_BLOCK_SIZE);
    }

    // make sure we are not over the maximum allowed
    nNextMaxBlockSize = std::min(nNextMaxBlockSize, DEFAULT_LARGEST_BLOCKSIZE_POSSIBLE);

    return nNextMaxBlockSize;
}
