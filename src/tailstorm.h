// Copyright (c) 2025 The Bitcoin Unlimited developers

#include "uint256.h"
#include "primitives/block.h"
#include "consensus/validation.h"
#include "sync.h"

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
std::vector<std::pair<uint256, std::vector<uint8_t> > > parseMinerData(const std::vector<unsigned char>& data);

/** Context-independent summary block validity checks.
    Do any additional (context-free) checks on this block header so make sure it is a valid summary block.
    It is expected that this block has already been check to have a valid header.

    Since this is a context-free check, the transactions in this block are NOT checked to be consistent with
    its referenced subblocks' transactions.
*/
bool CheckSummaryBlockHeader(const Consensus::Params &consensusParams,
    const ConstCBlockRef pblock,
    CValidationState &state,
    bool fCheckPOW);

/** Wrapping a CBlock because I think there might be more data to store,
    but if not this class could be removed
*/
class SubblockMapItem
{
public:
    ConstCBlockRef subblock;
    SubblockMapItem() {}
    SubblockMapItem(const ConstCBlockRef& sb):subblock(sb) {}
};


/** Do not access these directly as part of the tailstorm API.
 */
extern CCriticalSection cs_mapSubblocks;
extern std::map<uint256, SubblockMapItem> mapSubblocks GUARDED_BY(cs_mapSubblocks);
