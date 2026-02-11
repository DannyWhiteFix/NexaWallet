// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Copyright (c) 2015-2023 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chain.h"
#include "main.h"

using namespace std;

std::string ToString(BlockStatus s)
{
    std::string ret;
    auto tmp = s & BlockStatus::BLOCK_VALID_MASK;
    if (tmp == BLOCK_VALID_HEADER)
        ret = "valid header";
    else if (tmp == BLOCK_VALID_TREE)
        ret = "valid header & tree";
    else if (tmp == BLOCK_VALID_TRANSACTIONS)
        ret = "valid header, tree, and transactions";
    else if (tmp == BLOCK_VALID_CHAIN)
        ret = "valid header, tree, transactions, and chain";
    else if (tmp == BLOCK_VALID_SCRIPTS)
        ret = "valid header, tree, transactions, chain, and scripts";
    else
        ret = "unvalidated";
    ret += "; ";
    if (s & BLOCK_HAVE_DATA)
        ret += "has data";
    if (s & BLOCK_HAVE_UNDO)
        ret += ", has undo";

    if (s & BLOCK_FAILED_VALID)
        ret += ", failed validity";
    if (s & BLOCK_FAILED_CHILD)
        ret += ", bad parent";
    ret += "; ";
    if (s & BLOCK_PROCESSED)
        ret += "processed";
    if (s & BLOCK_LINKED)
        ret += ", linked";
    return ret;
}

/**
 * CChain implementation
 */
void CChain::SetTip(CBlockIndex *pindex)
{
    WRITELOCK(cs_chainLock);
    if (pindex == nullptr)
    {
        vChain.clear();
        tip = nullptr;
        return;
    }
    vChain.resize(pindex->height() + 1);
    tip = pindex;
    while (pindex && vChain[pindex->height()] != pindex)
    {
        vChain[pindex->height()] = pindex;
        pindex = pindex->pprev;
    }
}

CBlockLocator CChain::GetLocator(const CBlockIndex *pindex) const
{
    int nStep = 1;
    std::vector<uint256> vHave;
    vHave.reserve(32);

    READLOCK(cs_chainLock);
    if (!pindex)
        pindex = Tip();
    while (pindex)
    {
        vHave.push_back(pindex->GetBlockHash());
        // Stop when we have added the genesis block.
        if (pindex->height() == 0)
            break;
        // Exponentially larger steps back, plus the genesis block.
        int nHeight = std::max(((int)pindex->height()) - nStep, 0);
        if (_Contains(pindex))
        {
            // Use O(1) CChain index if possible.
            pindex = vChain[nHeight];
        }
        else
        {
            // Otherwise, use O(log n) skiplist.
            pindex = pindex->GetAncestor(nHeight);
        }
        if (vHave.size() > 10)
            nStep *= 2;
    }

    return CBlockLocator(vHave);
}

const CBlockIndex *CChain::FindFork(const CBlockIndex *pindex) const
{
    READLOCK(cs_chainLock);
    if (pindex == nullptr)
    {
        return nullptr;
    }
    if (pindex->height() > Height())
        pindex = pindex->GetAncestor(Height());
    while (pindex && !_Contains(pindex))
        pindex = pindex->pprev;
    return pindex;
}

/** Turn the lowest '1' bit in the binary representation of a number into a '0'. */
int static inline InvertLowestOne(int n) { return n & (n - 1); }
/** Compute what height to jump back to with the CBlockIndex::pskip pointer. */
int static inline GetSkipHeight(int height)
{
    if (height < 2)
        return 0;

    // Determine which height to jump back to. Any number strictly lower than height is acceptable,
    // but the following expression seems to perform well in simulations (max 110 steps to go back
    // up to 2**18 blocks).
    return (height & 1) ? InvertLowestOne(InvertLowestOne(height - 1)) + 1 : InvertLowestOne(height);
}

/** Compute what height to jump back to for the ancestor hash in blocks.  This implements both a linear and
    exponential backup.

    If the height is even, drop the least significant bit that is set to 1 (easily calculated by n & (n-1)) and
    use that as the height. This tends to "funnel" ancestor hops into blocks whose height is a power of 2.

    If the current height is odd, the above algorithm would result in the same block as hashPrevBlock.  So instead go
    back 5040 blocks (or to the genesis block).

    Header-validating nodes therefore do not need to keep the full history of old headers.
 */
int64_t GetConsensusAncestorHeight(int64_t height)
{
    if (height < 2)
        return 0;

    return (height & 1) ? max((int64_t)0, height - ANCESTOR_HASH_IF_ODD) : InvertLowestOne(height);
}

/* This API is currently unused
CBlockIndex *CBlockIndex::GetConsensusAncestor()
{
    int myHeight = height();
    // Ancestor of the genesis block is nothing
    if (myHeight == 0)
        return nullptr;
    return GetAncestor(GetConsensusAncestorHeight(myHeight));
}
*/

const CBlockIndex *CBlockIndex::GetChildsConsensusAncestor() const
{
    int childHeight = height() + 1;
    return GetAncestor(GetConsensusAncestorHeight(childHeight));
}

CBlockIndex *CBlockIndex::GetAncestor(int ansHeight)
{
    int heightWalk = height();
    if (ansHeight > heightWalk || ansHeight < 0)
        return nullptr;

    CBlockIndex *pindexWalk = this;
    while (heightWalk > ansHeight)
    {
        int heightSkip = GetSkipHeight(heightWalk);
        int heightSkipPrev = GetSkipHeight(heightWalk - 1);
        if (pindexWalk->pskip != nullptr &&
            (heightSkip == ansHeight ||
                (heightSkip > ansHeight && !(heightSkipPrev < heightSkip - 2 && heightSkipPrev >= ansHeight))))
        {
            // Only follow pskip if pprev->pskip isn't better than pskip->pprev.
            pindexWalk = pindexWalk->pskip;
            heightWalk = heightSkip;
        }
        else
        {
            assert(pindexWalk->pprev);
            pindexWalk = pindexWalk->pprev;
            heightWalk--;
        }
    }
    return pindexWalk;
}

const CBlockIndex *CBlockIndex::GetAncestor(int height) const
{
    return const_cast<CBlockIndex *>(this)->GetAncestor(height);
}

void CBlockIndex::BuildSkip()
{
    if (pprev)
    {
        pskip = pprev->GetAncestor(GetSkipHeight(height()));
    }
}

std::string CBlockFileInfo::ToString() const
{
    return strprintf("CBlockFileInfo(blocks=%u, size=%u, heights=%u...%u, time=%s...%s)", nBlocks, nSize, nHeightFirst,
        nHeightLast, FormatISO8601Date(nTimeFirst), FormatISO8601Date(nTimeLast));
}

const CBlockIndex *LastCommonAncestor(const CBlockIndex *pa, const CBlockIndex *pb)
{
    if (pa->height() > pb->height())
    {
        pa = pa->GetAncestor(pb->height());
    }
    else if (pb->height() > pa->height())
    {
        pb = pb->GetAncestor(pa->height());
    }

    while (pa != pb && pa && pb)
    {
        pa = pa->pprev;
        pb = pb->pprev;
    }

    // Eventually all chain branches meet at the genesis block.
    assert(pa == pb);
    return pa;
}

bool AreOnTheSameFork(const CBlockIndex *pa, const CBlockIndex *pb)
{
    // The common ancestor needs to be either pa (pb is a child of pa) or pb (pa
    // is a child of pb).
    const CBlockIndex *pindexCommon = LastCommonAncestor(pa, pb);
    return pindexCommon == pa || pindexCommon == pb;
}

int64_t GetBlockWorkEquivalentTime(const CBlockIndex &to,
    const CBlockIndex &from,
    const CBlockIndex &tip,
    const Consensus::Params &params)
{
    arith_uint256 r;
    int sign = 1;
    if (to.chainWork() > from.chainWork())
    {
        r = to.chainWork() - from.chainWork();
    }
    else
    {
        r = from.chainWork() - to.chainWork();
        sign = -1;
    }
    r = r * arith_uint256(params.nPowTargetSpacing) / GetBlockWork(tip);
    if (r.bits() > 63)
    {
        return sign * std::numeric_limits<int64_t>::max();
    }
    return sign * r.GetLow64();
}

arith_uint256 GetBlockWork(const CBlockIndex &block) { return GetWorkForDifficultyBits(block.tgtBits()); }
