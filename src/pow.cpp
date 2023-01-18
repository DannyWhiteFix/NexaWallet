// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Copyright (c) 2017 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "pow.h"

#include "arith_uint256.h"
#include "chain.h"
#include "primitives/block.h"
#include "uint256.h"
#include "util.h"
#include "validation/forks.h"
static std::atomic<const CBlockIndex *> cachedAnchor{nullptr};

void ResetASERTAnchorBlockCache() noexcept { cachedAnchor = nullptr; }
const CBlockIndex *GetASERTAnchorBlockCache() noexcept { return cachedAnchor.load(); }
/**
 * Returns a pointer to the anchor block used for ASERT.
 * As anchor we use the first block for which IsNov2020Activated() returns true.
 * This block happens to be the last block which was mined under the old DAA
 * rules.
 *
 * This function is meant to be removed some time after the upgrade, once
 * the anchor block is deeply buried, and behind a hard-coded checkpoint.
 *
 * Preconditions: - pindex must not be nullptr
 *                - pindex must satisfy: IsNov2020Activated(params, pindex) == true
 * Postcondition: Returns a pointer to the first (lowest) block for which
 *                IsNov2020Activated is true, and for which IsNov2020ACtivated(pprev)
 *                is false (or for which pprev is nullptr). The return value may
 *                be pindex itself.
 */
static const CBlockIndex *GetASERTAnchorBlock(const CBlockIndex *const pindex, const Consensus::Params &params)
{
    assert(pindex);

    // - We check if we have a cached result, and if we do and it is really the
    //   ancestor of pindex, then we return it.
    //
    // - If we do not or if the cached result is not the ancestor of pindex,
    //   then we proceed with the more expensive walk back to find the ASERT
    //   anchor block.
    //
    // CBlockIndex::GetAncestor() is reasonably efficient; it uses CBlockIndex::pskip
    // Note that if pindex == cachedAnchor, GetAncestor() here will return cachedAnchor,
    // which is what we want.
    const CBlockIndex *lastCached = cachedAnchor.load();
    if (lastCached && pindex->GetAncestor(lastCached->height()) == lastCached)
    {
        return lastCached;
    }
    // Slow path: walk back to genesis, and then use it as our anchor block.
    const CBlockIndex *anchor = pindex;
    while (anchor->pprev)
    {
        // first, skip backwards
        // The below code leverages CBlockIndex::pskip to walk back efficiently.
        if ((anchor->pskip != nullptr))
        {
            // skip backward
            anchor = anchor->pskip;
            continue; // continue skipping
        }
        anchor = anchor->pprev;
    }

    // Overwrite the cache with the anchor we found. More likely than not, the next
    // time we are asked to validate a header it will be part of same / similar chain, not
    // some other unrelated chain with a totally different anchor.
    cachedAnchor = anchor;
    return anchor;
}


/**
 * Compute the next required proof of work using an absolutely scheduled
 * exponentially weighted target (ASERT).
 *
 * With ASERT, we define an ideal schedule for block issuance (e.g. 1 block every 600 seconds), and we calculate the
 * difficulty based on how far the most recent block's timestamp is ahead of or behind that schedule.
 * We set our targets (difficulty) exponentially. For every [nHalfLife] seconds ahead of or behind schedule we get, we
 * double or halve the difficulty.
 */
uint32_t GetNextASERTWorkRequired(const CBlockIndex *pindexPrev,
    const CBlockHeader *pblock,
    const Consensus::Params &params,
    const CBlockIndex *pindexAnchorBlock) noexcept
{
    // This cannot handle the genesis block and early blocks in general.
    assert(pindexPrev != nullptr);

    // Anchor block is the block on which all ASERT scheduling calculations are based.
    // It too must exist, and it must have a valid parent.
    assert(pindexAnchorBlock != nullptr);

    // We make no further assumptions other than the height of the prev block must be >= that of the anchor block.
    assert(pindexPrev->height() >= pindexAnchorBlock->height());

    const arith_uint256 powLimit = UintToArith256(params.powLimit);

    // Special difficulty rule for testnet
    // If the new block's timestamp is more than 2* 10 minutes then allow
    // mining of a min-difficulty block.
    if (params.fPowAllowMinDifficultyBlocks &&
        (pblock->GetBlockTime() > pindexPrev->GetBlockTime() + 2 * params.nPowTargetSpacing))
    {
        return UintToArith256(params.powLimit).GetCompact();
    }

    // For nTimeDiff calculation, the timestamp of the parent to the anchor block is used,
    // as per the absolute formulation of ASERT.
    // This is somewhat counterintuitive since it is referred to as the anchor timestamp, but
    // as per the formula the timestamp of block M-1 must be used if the anchor is M.
    if (pindexPrev->pprev == nullptr)
        return powLimit.GetCompact(); // Start at very low difficulty
    assert(pindexPrev->pprev != nullptr);
    // Note: time difference is to parent of anchor block (or to anchor block itself iff anchor is genesis).
    //       (according to absolute formulation of ASERT)
    const auto anchorTime =
        pindexAnchorBlock->pprev ? pindexAnchorBlock->pprev->GetBlockTime() : pindexAnchorBlock->GetBlockTime();
    const int64_t nTimeDiff = pindexPrev->GetBlockTime() - anchorTime;
    // Height difference is from current block to anchor block
    const int64_t nHeightDiff = pindexPrev->height() - pindexAnchorBlock->height();
    const arith_uint256 refBlockTarget = arith_uint256().SetCompact(pindexAnchorBlock->header.nBits);
    // Do the actual target adaptation calculation in separate
    // CalculateASERT() function
    arith_uint256 nextTarget = CalculateASERT(
        refBlockTarget, params.nPowTargetSpacing, nTimeDiff, nHeightDiff, powLimit, params.nASERTHalfLife);

    // CalculateASERT() already clamps to powLimit.
    return nextTarget.GetCompact();
}

// ASERT calculation function.
// Clamps to powLimit.
arith_uint256 CalculateASERT(const arith_uint256 &refTarget,
    const int64_t nPowTargetSpacing,
    const int64_t nTimeDiff,
    const int64_t nHeightDiff,
    const arith_uint256 &powLimit,
    const int64_t nHalfLife) noexcept
{
    // Input target must never be zero nor exceed powLimit.
    assert(refTarget > 0);
    assert(refTarget <= powLimit);

    // We need some leading zero bits in powLimit in order to have room to handle
    // overflows easily. 32 leading zero bits is more than enough.
    // (broken if starting from genesis block with more difficult POW, so using 20 leading 0 bits)
    assert((powLimit >> 236) == 0);

    // Height diff should NOT be negative.
    assert(nHeightDiff >= 0);

    // It will be helpful when reading what follows, to remember that
    // nextTarget is adapted from anchor block target value.

    // Ultimately, we want to approximate the following ASERT formula, using only integer (fixed-point) math:
    //     new_target = old_target * 2^((blocks_time - IDEAL_BLOCK_TIME * (height_diff + 1)) / nHalfLife)

    // First, we'll calculate the exponent:
    assert(llabs(nTimeDiff - nPowTargetSpacing * nHeightDiff) < (1ll << (63 - 16)));
    const int64_t exponent = ((nTimeDiff - nPowTargetSpacing * (nHeightDiff + 1)) * 65536) / nHalfLife;

    // Next, we use the 2^x = 2 * 2^(x-1) identity to shift our exponent into the [0, 1) interval.
    // The truncated exponent tells us how many shifts we need to do
    // Note1: This needs to be a right shift. Right shift rounds downward (floored division),
    //        whereas integer division in C++ rounds towards zero (truncated division).
    // Note2: This algorithm uses arithmetic shifts of negative numbers. This
    //        is unpecified but very common behavior for C++ compilers before
    //        C++20, and standard with C++20. We must check this behavior e.g.
    //        using static_assert.
    static_assert(int64_t(-1) >> 1 == int64_t(-1), "ASERT algorithm needs arithmetic shift support");

    // Now we compute an approximated target * 2^(exponent/65536.0)

    // First decompose exponent into 'integer' and 'fractional' parts:
    int64_t shifts = exponent >> 16;
    const uint64_t frac = uint16_t(exponent);
    assert(exponent == (shifts * 65536) + (int64_t)frac);

    // multiply target by 65536 * 2^(fractional part)
    // 2^x ~= (1 + 0.695502049*x + 0.2262698*x**2 + 0.0782318*x**3) for 0 <= x < 1
    // Error versus actual 2^x is less than 0.013%.
    const uint32_t factor =
        65536 +
        ((+195766423245049ull * frac + 971821376ull * frac * frac + 5127ull * frac * frac * frac + (1ull << 47)) >> 48);
    // this is always < 2^241 since refTarget < 2^224
    arith_uint256 nextTarget = refTarget * factor;

    // multiply by 2^(integer part) / 65536
    shifts -= 16;
    if (shifts <= 0)
    {
        nextTarget >>= -shifts;
    }
    else
    {
        // Detect overflow that would discard high bits
        const auto nextTargetShifted = nextTarget << shifts;
        if ((nextTargetShifted >> shifts) != nextTarget)
        {
            // If we had wider integers, the final value of nextTarget would
            // be >= 2^256 so it would have just ended up as powLimit anyway.
            nextTarget = powLimit;
        }
        else
        {
            // Shifting produced no overflow, can assign value
            nextTarget = nextTargetShifted;
        }
    }

    if (nextTarget == 0)
    {
        // 0 is not a valid target, but 1 is.
        nextTarget = arith_uint256(1);
    }
    else if (nextTarget > powLimit)
    {
        nextTarget = powLimit;
    }
    // we return from only 1 place for copy elision
    return nextTarget;
}


#include "crypto/sha256.h"
#include "key.h"

uint32_t GetNextWorkRequired(const CBlockIndex *pindexPrev, const CBlockHeader *pblock, const Consensus::Params &params)
{
    // Genesis block
    if (pindexPrev == nullptr)
    {
        return UintToArith256(params.powLimit).GetCompact();
    }

    // Special rule for regtest: we never retarget.
    if (params.fPowNoRetargeting)
    {
        return pindexPrev->tgtBits();
    }

    const CBlockIndex *panchorBlock = GetASERTAnchorBlock(pindexPrev, params);
    return GetNextASERTWorkRequired(pindexPrev, pblock, params, panchorBlock);
}


static uint256 sha256(uint256 data)
{
    uint256 ret;
    CSHA256 sha;
    sha.Write(data.begin(), 256 / 8);
    sha.Finalize(ret.begin());
    return ret;
}

bool MineBlock(CBlockHeader &blockHeader, unsigned long int tries, const Consensus::Params &cparams)
{
    assert(blockHeader.size != 0); // Size must be properly calculated before we can figure out the hash
    unsigned long int count = 0;
    for (unsigned int x = 0; x < 8; x++)
        if (x < blockHeader.nonce.size())
            count = count | (blockHeader.nonce[x] << (x * 8));

    uint256 headerCommitment = blockHeader.GetMiningHeaderCommitment();

    while (tries > 0)
    {
        uint256 mhash = ::GetMiningHash(headerCommitment, blockHeader.nonce);
        if (CheckProofOfWork(mhash, blockHeader.nBits, cparams))
        {
            // printf("pow hash: %s\n", mhash.GetHex().c_str());
            return true;
        }
        ++count;
        for (unsigned int x = 0; x < 8; x++)
            if (x < blockHeader.nonce.size())
                blockHeader.nonce[x] = (count >> (x * 8)) & 255;
        tries--;
    }
    return false;
}


bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params &params)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    if (params.powAlgorithm == 1)
    {
        // This algorithm uses the hash as a priv key to sign sha256(hash) using deterministic k.
        // This means that any hardware optimization will need to implement signature generation.
        // What we really want is signature validation to be implemented in hardware, so more thought needs to
        // happen.
        uint256 h1 = sha256(hash);
        CKey k; // Use hash as a private key
        k.Set(hash.begin(), hash.end(), false);
        if (!k.IsValid())
            return false; // If we can't POW fails
        std::vector<uint8_t> vchSig;
        if (!k.SignSchnorr(h1, vchSig))
            return false; // Sign sha256(hash) with hash

        // sha256 the signed data to get back to 32 bytes
        CSHA256 sha;
        sha.Write(&vchSig[0], vchSig.size());
        sha.Finalize(hash.begin());
    }

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit))
        return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}

arith_uint256 GetBlockProof(const CBlockIndex &block) { return GetWorkForDifficultyBits(block.tgtBits()); }
int64_t GetBlockProofEquivalentTime(const CBlockIndex &to,
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
    r = r * arith_uint256(params.nPowTargetSpacing) / GetBlockProof(tip);
    if (r.bits() > 63)
    {
        return sign * std::numeric_limits<int64_t>::max();
    }
    return sign * r.GetLow64();
}
