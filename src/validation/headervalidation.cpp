// Copyright (c) 2023 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#include "consensus/validation.h"
#include "pow.h"
#include "timedata.h"

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
    if (fCheckPOW && !CheckProofOfWork(miningHash, block.nBits, consensusParams))
        return state.DoS(50, error("CheckBlockHeader(): proof of work failed"), REJECT_INVALID, "high-hash");

        // Light wallets can check this themselves if they care, but a light client should not be rejecting a header
        // based on time -- its more likely that the light client's time is incorrect
#ifndef LIGHT
    // Check timestamp
    if (block.GetBlockTime() > GetAdjustedTime() + 2 * 60 * 60)
        return state.Invalid(
            error("CheckBlockHeader(): block timestamp too far in the future"), REJECT_INVALID, "time-too-new");
#endif

    if (block.minerData.size() != 0)
    {
        return state.DoS(100, error("%s: premature miner data use", __func__), REJECT_INVALID, "bad-miner-data");
    }
    if (block.utxoCommitment.size() != 0)
    {
        return state.DoS(
            100, error("%s: premature utxo commitment use", __func__), REJECT_INVALID, "bad-utxo-commitment");
    }
    return true;
}


bool CheckSummaryBlockHeader(const Consensus::Params &consensusParams,
    const ConstCBlockRef pblock,
    CValidationState &state,
    bool fCheckPOW)
{
    // tailstorm grab the subblock POW proofs out of pblock->minerData and verify them
    if (fCheckPOW)
    {
        auto subblockProofs = ParseMinerData(pblock->minerData);
        // A summary block must reference K-1 subblocks, -1 because it is *itself* a subblock.
        // TODO: For simplicity, the code requires the exact # of subblocks to be referenced, although I suppose
        // referencing more is possible, and might be better if they happen to exist.
        if (subblockProofs.size() != consensusParams.tailstormSubblocks - 1)
        {
            return state.DoS(100, error("CheckSummaryBlockHeader: summary block does not have enough subblocks"),
                REJECT_INVALID, "bad-blk-too-few-subblocks");
        }
        // And each subblock must have nBits work in them.  So the total work in this summary block is really
        // work(nBits) * # of subblocks.

        // TODO Make sure no subblock proofs are repeats!  Mining header commitment MUST be unique.
        for (const auto &pair : subblockProofs)
        {
            const auto &miningHeaderCommitment = pair.first;
            const auto &nonce = pair.second;

            // TODO: INSECURE the parent (summary) block hash needs to be part of this function, or an attacker can
            // reuse old subblocks.
            uint256 powHash = GetMiningHash(miningHeaderCommitment, nonce);

            if (!CheckProofOfWork(powHash, pblock->nBits, consensusParams))
                return state.DoS(50, error("CheckBlockHeader(): proof of work failed"), REJECT_INVALID,
                    "bad-blk-subblock-high-hash");
        }
    }
    return true;
}
