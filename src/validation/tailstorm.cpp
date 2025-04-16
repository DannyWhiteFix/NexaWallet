// Copyright (c) 2025 The Bitcoin Unlimited developers

#ifndef NEXA_TAILSTORM_H
#define NEXA_TAILSTORM_H

#include "chainparams.h"
#include "consensus/validation.h"
#include "forks.h"
#include "parallel.h"
#include "txdebugger.h"
#include "txmempool.h"
#include "versionbits.h"
#include "tailstorm.h"

/** Gets the subblock information (mining header commitments) out of the block header's minerdata field.
    This is stored as an array of pairs.  Each pair is the subblocks mining header commitment and the nonce.
    This is all and the minimum that we need to prove the PoW of that subblock, since it must match the target
    specified by this block's nBits fields (all subblocks have to have the same PoW target).

    If this block references enough subblocks to make a summary block, then it IS the summary block, and its
    transaction list needs to be the full transaction list rather than additional tx on top of referenced subblocks.
 */
std::vector<std::pair<uint256, std::vector<uint8_t> > > parseMinerData(const std::vector<unsigned char>& data)
{
    std::vector<std::pair<uint256, std::vector<uint8_t> > > ret;
    if (data.size() == 0) return ret;
    CDataStream ds(data, SER_NETWORK, PROTOCOL_VERSION);
    ds >> ret;
    return ret;
}

bool CheckSummaryBlockHeader(const Consensus::Params &consensusParams,
    const ConstCBlockRef pblock,
    CValidationState &state,
    bool fCheckPOW)
{
    // tailstorm TODO grab the subblock POW proofs out of pblock->minerData and verify them
    if (fCheckPOW)
    {
        auto subblockProofs = parseMinerData(pblock->minerData);
        if (subblockProofs.size() != consensusParams.tailstormSubblocks)
        {
            return state.DoS(100, error("CheckSummaryBlockHeader: summary block does not have enough subblocks"), REJECT_INVALID, "bad-blk-too-few-subblocks");
        }
    }
    return true;
}


#endif
