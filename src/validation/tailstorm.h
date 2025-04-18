// Copyright (c) 2025 The Bitcoin Unlimited developers

#include "uint256.h"
#include "primitives/block.h"
#include "consensus/validation.h"

#include <cstdint>
#include <vector>
#include <utility>

/** Gets the subblock information (mining header commitments) out of the block header's minerdata field.
    This is stored as an array of pairs.  Each pair is the subblocks mining header commitment and the nonce.
    This is all and the minimum that we need to prove the PoW of that subblock, since it must match the target
    specified by this block's nBits fields (all subblocks have to have the same PoW target).

    If this block references enough subblocks to make a summary block, then it IS the summary block, and its
    transaction list needs to be the full transaction list rather than additional tx on top of referenced subblocks.
 */
std::vector<std::pair<uint256, std::vector<uint8_t> > > ParseMinerData(const std::vector<unsigned char>& data);

/** Context-independent summary block validity checks.
    Do any additional (context-free) checks on this block header so make sure it is a valid summary block.
    It is expected that this block has already been check to have a valid header.

    Since this is a context-free check, the transactions in this block are NOT checked to be consistent with
    its referenced subblocks' transactions.
*/
// in headervalidation.cpp
//bool CheckSummaryBlockHeader(const Consensus::Params &consensusParams,
//    const ConstCBlockRef pblock,
//    CValidationState &state,
//    bool fCheckPOW);

/** Is this subblock a summary block (does it meet the total PoW required)? */
bool IsSummaryBlock(ConstCBlockRef blk, CBlockIndex* prev);


/** Store this valid subblock for use in the DAG */
void AcceptSubblock(ConstCBlockRef pblock);
