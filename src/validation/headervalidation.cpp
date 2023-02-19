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
#ifndef ANDROID
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
