// Copyright (c) 2025 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#include "validation/headervalidation.h"
#include "consensus/validation.h"
#include "pow.h"
#include "timedata.h"
#include "validation/tailstorm.h"

bool CheckTailstormSummaryBlockProofOfWork(const Consensus::Params &consensusParams,
    const CBlockHeader &block,
    CValidationState &state)
{
    // Grab the subblock POW proofs and other data out of pblock->minerData to use in verification
    auto ret = ParseSummaryBlockMinerData(block.minerData);

    // A summary block must reference K-1 subblocks, -1 because it is *itself* a subblock.
    if ((ret.vSubblockProofs.size() != consensusParams.tailstorm_k - 1) &&
        (ret.vSubblockProofs.size() != (ret.nUncles + ret.nSubblocks)))
    {
        return state.DoS(100,
            error(
                "CheckSummaryBlockHeader: summary has incorrect number of subblocks: %ld", ret.vSubblockProofs.size()),
            REJECT_INVALID, "bad-blk-wrong-number-of-subblocks");
    }

    // Each subblock must have nBits work in them.  So the total work in this summary block is really
    // work(nBits) * # of subblocks.
    //
    // First check the summary block's subblock.
    //
    // Then check the subblocks in the minerData field and if they fail to validate then fall through
    // and try them again as uncles.  To verify the work of included uncle blocks we need the prev hash of the prevhash.
    if (!CheckProofOfWork(block.GetMiningHash(), block.hashPrevBlock, block.nBits, consensusParams))
    {
        return state.DoS(50, error("CheckTailstormSummaryBlockHeader(): proof of work failed - high hash"),
            REJECT_INVALID, "bad-blk-subblock-high-hash");
    }

    std::set<uint256> setExists;
    uint32_t nSubblocksFound = 0;
    uint32_t nUnclesFound = 0;
    for (const auto &pair : ret.vSubblockProofs)
    {
        const auto &miningHeaderCommitment = pair.first;
        const auto &nonce = pair.second;
        uint256 powHash = GetMiningHash(miningHeaderCommitment, nonce);

        if (!CheckProofOfWork(powHash, block.hashPrevBlock, ret.nBitsSubblock, consensusParams))
        {
            // If it fails then check again with the prevhash of the prevhash in case it's from an uncle
            if (!CheckProofOfWork(powHash, ret.prevOfprevhash, ret.nBitsUncle, consensusParams))
            {
                return state.DoS(50, error("CheckTailstormSummaryBlockHeader(): proof of work failed - high hash"),
                    REJECT_INVALID, "bad-blk-subblock-high-hash");
            }
            nUnclesFound++;
        }
        else
        {
            nSubblocksFound++;
        }

        // Check for repeats
        if (setExists.count(powHash))
        {
            return state.DoS(50,
                error("CheckTailstormSummaryBlockHeader(): proof of work failed - dup mining commitment"),
                REJECT_INVALID, "bad-blk-duplicate-mining-commitment");
        }
        else
        {
            setExists.insert(powHash);
        }
    }

    // Check that the stated counts for subblocks and uncles in the minerData field are correct
    if ((ret.nBitsUncle != ret.nBitsSubblock) && (ret.nUncles != nUnclesFound || ret.nSubblocks != nSubblocksFound))
    {
        return state.DoS(50,
            error("CheckTailstormSummaryBlockHeader(): proof of work failed - uncle or subblocks counts did not match"),
            REJECT_INVALID, "bad-blk-invalid-uncle-or-subblock-count");
    }

    return true;
}
bool CheckBlockHeader(const Consensus::Params &consensusParams,
    const CBlockHeader &block,
    CValidationState &state,
    bool fCheckPOW)
{
    // Block size can not be zero
    if (block.size == 0)
    {
        return state.DoS(100, error("%s: block size can not be zero", __func__), REJECT_INVALID, "bad-size");
    }
    // Must be above GetMiningHash which asserts if nonce is too big
    if (block.nonce.size() > CBlockHeader::MAX_NONCE_SIZE)
    {
        return state.DoS(100, error("%s: nonce too large", __func__), REJECT_INVALID, "bad-nonce");
    }
    // Check proof of work matches claimed amount
    uint256 miningHash = block.GetMiningHash();
    if (fCheckPOW)
    {
        if (GetMinerDataVersion(block.minerData) == DEFAULT_MINER_DATA_SUMMARYBLOCK_VERSION)
        {
            if (!CheckTailstormSummaryBlockProofOfWork(consensusParams, block, state))
                return false;
        }
        else
        {
            uint256 prevhash;
            if (GetMinerDataVersion(block.minerData) == DEFAULT_MINER_DATA_SUBBLOCK_VERSION)
                prevhash = block.hashPrevBlock;

            if (!CheckProofOfWork(miningHash, prevhash, block.nBits, consensusParams))
                return state.DoS(
                    50, error("CheckBlockHeader(): proof of work failed - high hash"), REJECT_INVALID, "high-hash");
        }
    }

    // Light wallets can check this themselves if they care, but a light client should not be rejecting a header
    // based on time -- its more likely that the light client's time is incorrect
#ifndef LIGHT
    // Check timestamp
    if (block.GetBlockTime() > GetAdjustedTime() + 2 * 60 * 60)
        return state.Invalid(
            error("CheckBlockHeader(): block timestamp too far in the future"), REJECT_INVALID, "time-too-new");
#endif

    if (block.utxoCommitment.size() != 0)
    {
        return state.DoS(
            100, error("%s: premature utxo commitment use", __func__), REJECT_INVALID, "bad-utxo-commitment");
    }
    return true;
}
