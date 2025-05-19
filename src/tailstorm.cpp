// Copyright (c) 2025 The Bitcoin Unlimited developers

#ifndef NEXA_TAILSTORM_H
#define NEXA_TAILSTORM_H

#include "chainparams.h"
#include "consensus/validation.h"
#include "datastream.h"
#include "pow.h"
#include "sync.h"
#include "tailstorm.h"

extern bool forceTemplateRecalc;

/**
   Subblocks are not stored persistently.  They are just stored here in RAM.

   If a block not being added to the tip, its transactions no longer need to be consistent with its subblocks'
   transactions (by definition).  This makes it unnecessary to save old subblocks to verify blockchain correctness.

   Subblocks still need to have valid PoW, but this can be verified solely by the data in minerData.

   This works because subblocks have 2 purposes: Bobtail (low-variance mining) and Storm (announcing partial PoW
   blocks to indicate tx inclusion probability).  Bobtail is proven by the data in minerData; from this data
   we know that it took on average X work to find the block.  But the Storm data is not relevant once the
   (summary) block has been discovered (the tx either got into the block or not, all Storm-based probabilistic
   assessments of that collapse into the boolean fact).

   It does not matter if old subblocks contain complete lies about pending transactions (that are left out of
   the block); the (summary) blockchain upholds all chain properties, just like it would if subblocks did not
   exist.  An attacker can create a competing chain with invalid (old) subblocks.  But they cannot use those old
   subblocks to their advantage because the tx inclusion probability has already collapsed into true or false in
   the block.

   The only issue would be whether using illegal subblocks somehow makes it easier for an attacker to mine the
   block (defeating the Bobtail part of Tailstorm).  Changing the content to make computation simpler makes no sense
   because the mining algorithm functions over arbitrary bytes and uses a cryptographic hash.  It is impossible to
   predict the output from any input.

   But reusing prior subblock solutions, or intermediate work, is a concern.

   To prevent subblock reuse, the PoW algorithm must be verified using the cryptographic hash of the parent
   (summary) block.  This unique data must be injected at the beginning of the PoW computation and be part of the
   majority of the effort to prevent an intermediate work attack.  However, this statement says nothing about the
   quantity of the data.  Let us propose 2 work and cryptographically strong functions F(x) and S(x), where F runs
   several orders of magnitude faster than S (and let us use "><" as byte array interleave*, and "." as concatenation).
   A space efficient secure algorithm would be S(F(subblock) . parent hash).  Since F(subblock) also contains the
   (entropy inserting) parent hash it could be used as the block identifier.

   To recast this as a search, S(x) could be "find an x such that F(x) < target", and we could introduce some nonce
   data into x (as is traditional in blockchain PoW).

   Let us attempt to avoid providing the bare nonce for subblock PoW validation purposes, because this would mean
   that every block must provide the nonce of every subblock.

   Consider packing it into the first part of the final hash:
   Pack = F0(nonce >< subblock)
   PoW = F1(parent hash >< Pack) < target
   The block provides Pack for each subblock (the parent hash is the same as the block's parent hash so is known).
   
   In this case, an attacker could simply choose random values for Pack (skipping the F(subblock >< nonce) computation).
   This reduces their PoW work to F(D >< parent hash) < target.

   To ensure that an attacker fork must compute approximately the same work as the main chain, it is therefore
   important the the effort to compute Pack is << that of PoW, if the nonce is placed into Pack().

   Ok the above has some caveats so let's flesh out the option where we provide the nonce:
   Pack = F0(subblock)
   PoW = F1((nonce >< parent hash) . Pack)
   The block provides the nonce and pack for each subblock.
   
   It is expected that Pack is precomputed by honest nodes, so there is little benefit to an attacker to use
   random numbers (we interleave the nonce with the parent hash to reduce the attacker's ability to precompute
   an F(nonce) intermediate state for many nonces.  We do NOT interleave Pack, so that choosing a random number
   does not provide an attacker "free bits" to match F(nonce >< random number) against precomputed states.

   Note that in the above cases, if Pack contains a cryptographically secure hash function, it is a good candidate
   for the identifier -- this allows the PoW function (which is F1(...F0(...)...) to be complex without impacting the
   use of cryptographic hash functions as data pointers.

   TODO: For maximum compatibility with the old PoW algorithm, we will store both the sublblock
   MiningHeaderCommitment (basically Pack above) and the nonce in the block.  However when the PoW is changed,
   we should consider packing the nonce and the MiningHeaderCommitment into a single hash.

   * Why interleave:  Byte interleaving (F("ABC", "DEF") -> F("ADBECF")) ensures that if one of the two parameters
     are held constant or precomputed, the intermediate state of this computation of cannot be used.
 */

CCriticalSection cs_mapSubblocks;
std::map<uint256, SubblockMapItem> mapSubblocks GUARDED_BY(cs_mapSubblocks);

void AcceptSubblock(ConstCBlockRef pblock)
{
    LOCK(cs_mapSubblocks);
    mapSubblocks[pblock->SubblockId()] = SubblockMapItem(pblock);
}

std::vector<uint8_t> assembleSubBlocks(uint64_t heightPrevBlock, uint256 hashPrevBlock, int maxSubblocks,
    int tailstormEnforceCorrectSubblocks)
{
    int subblocks = 0;
    uint8_t minerDataVersion = 1;
    std::vector<std::pair<uint256, std::vector<uint8_t> > > sbs;
    LOCK(cs_mapSubblocks);
    for (auto it = mapSubblocks.begin(); it != mapSubblocks.end(); )
    {

        auto& subblock = it->second.subblock;
        // TODO keep these around for validation and INV purposes
        // until they exceed
        // heightPrevBlock is the height of the subblock ancestor, so any sibling subblock should be heightPrevBlock+1
        if (subblock->height <= heightPrevBlock - tailstormEnforceCorrectSubblocks)  // its so old we should forget about it
        {
            it = mapSubblocks.erase(it);
        }
        else
        {
            // Its on this fork
            if (hashPrevBlock == subblock->hashPrevBlock)
            {
                sbs.push_back(std::pair(subblock->GetMiningHeaderCommitment(),subblock->nonce));
                subblocks++;
                if (subblocks == maxSubblocks-1) break;
            }
            ++it;
        }
    }

    if (sbs.size() == 0) return std::vector<uint8_t>();
    CDataStream ds(SER_NETWORK, PROTOCOL_VERSION);
    ds.reserve(1 + maxSubblocks*(32+16));
    ds << minerDataVersion << sbs;
    return std::vector<uint8_t>(ds.begin(),ds.end());
}

/** Gets the subblock information (mining header commitments) out of the block header's minerdata field.
    This is stored as an array of pairs.  Each pair is the subblocks mining header commitment and the nonce.
    This is all and the minimum that we need to prove the PoW of that subblock, since it must match the target
    specified by this block's nBits fields (all subblocks have to have the same PoW target).

    If this block references enough subblocks to make a summary block, then it IS the summary block, and its
    transaction list needs to be the full transaction list rather than additional tx on top of referenced subblocks.
    @returns vector of pairs of subblocks mining header commitment and the nonce
 */
std::vector<std::pair<uint256, std::vector<uint8_t> > > ParseMinerData(const std::vector<unsigned char>& data)
{
    std::vector<std::pair<uint256, std::vector<uint8_t> > > ret;
    if (data.size() == 0) return ret;
    uint8_t minerDataVersion = 0;
    CDataStream ds(data, SER_NETWORK, PROTOCOL_VERSION);
    ds >> minerDataVersion >> ret;
    return ret;
}


#endif
