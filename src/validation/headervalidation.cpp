// Copyright (c) 2025 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#include "validation/headervalidation.h"
#include "consensus/validation.h"
#include "pow.h"
#include "timedata.h"
#include "validation/tailstorm.h"

static bool CheckTailstormSummaryBlockProofOfWork(const Consensus::Params &consensusParams,
    const CBlockHeader &block,
    CValidationState &state)
{
    // tailstorm grab the subblock POW proofs out of pblock->minerData and verify them
    auto subblockProofs = ParseMinerData(block.minerData);
    // A summary block must reference K-1 subblocks, -1 because it is *itself* a subblock.
    if (subblockProofs.size() != consensusParams.tailstorm_k - 1)
    {
        return state.DoS(100,
            error("CheckSummaryBlockHeader: summary has incorrect number of subblocks: %ld", subblockProofs.size()),
            REJECT_INVALID, "bad-blk-wrong-number-of-subblocks");
    }
    // And each subblock must have nBits work in them.  So the total work in this summary block is really
    // work(nBits) * # of subblocks.

    std::set<uint256> setExists;
    for (const auto &pair : subblockProofs)
    {
        const auto &miningHeaderCommitment = pair.first;
        const auto &nonce = pair.second;

        // TODO: INSECURE the parent (summary) block hash needs to be part of this function, or an attacker can
        // reuse old subblocks.
        uint256 powHash = GetMiningHash(miningHeaderCommitment, nonce);

        if (!CheckProofOfWork(powHash, block.nBits, consensusParams))
        {
            return state.DoS(50, error("CheckSummaryBlockHeader(): proof of work failed"), REJECT_INVALID,
                "bad-blk-subblock-high-hash");
        }

        // Check for repeats
        if (setExists.count(miningHeaderCommitment))
        {
            return state.DoS(50, error("CheckSummaryBlockHeader(): proof of work failed"), REJECT_INVALID,
                "bad-blk-duplicate-mining-commitment");
        }
        else
        {
            setExists.insert(miningHeaderCommitment);
        }
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
            if (!CheckProofOfWork(miningHash, block.nBits, consensusParams))
                return state.DoS(50, error("CheckBlockHeader(): proof of work failed"), REJECT_INVALID, "high-hash");
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
