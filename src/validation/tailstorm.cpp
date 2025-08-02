// Copyright (c) 2025 The Bitcoin Unlimited developers

#include "validation/tailstorm.h"
#include "chain.h"
#include "chainparams.h"
#include "consensus/validation.h"
#include "datastream.h"
#include "net.h"
#include "pow.h"
#include "sync.h"

extern CChain chainActive;
extern CBlockIndex *pindexBestHeader;
extern std::atomic<bool> forceTemplateRecalc;
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

void PruneSubblocks(ConstCBlockRef pblock)
{
    if (pblock)
    {
        // Prune subblocks but leave enough for checking and enforcing the validity
        // of summary blocks up to the enforce depth.
        if (pindexBestHeader != nullptr)
        {
            const uint32_t nBlockHeight =
                std::max((uint32_t)pindexBestHeader->height(), pblock->GetBlockHeader().height);
            const uint32_t nHeightToPrune = nBlockHeight > DEPTH_TO_ENFORCE_CORRECT_SUBBLOCKS ?
                                                nBlockHeight - DEPTH_TO_ENFORCE_CORRECT_SUBBLOCKS - 1 :
                                                0;

            LOCK(tailstormForest.cs_forest);
            tailstormForest.ClearByHeight(nHeightToPrune);
        }
    }
}

bool IsSummaryBlock(ConstCBlockRef pblock) { return IsSummaryBlock(*pblock); }
bool IsSummaryBlock(const CBlock &block)
{
    if (GetMinerDataVersion(block.minerData) != DEFAULT_MINER_DATA_SUBBLOCK_VERSION)
    {
        return true;
    }
    return false;
}

bool IsTailstormSummaryBlock(ConstCBlockRef pblock) { return IsTailstormSummaryBlock(*pblock); }
bool IsTailstormSummaryBlock(const CBlock &block)
{
    return (GetMinerDataVersion(block.minerData) == DEFAULT_MINER_DATA_SUMMARYBLOCK_VERSION);
}

void AcceptSubblock(ConstCBlockRef pblock)
{
    if (!pblock)
        return;

    bool fCheckForReorg = false;
    std::set<uint256> setToAnnounce;
    {
        LOCK(tailstormForest.cs_forest);

        // Insert new subblock into dag
        if (tailstormForest._Insert(pblock))
        {
            fCheckForReorg = true;

            // Process Orphans
            setToAnnounce = tailstormForest.ProcessOrphans();
            setToAnnounce.insert(pblock->GetHash());

            // Check for subblocks to prune
            PruneSubblocks(pblock);

            forceTemplateRecalc.store(true);
        }
        else
            LOG(DAG, "Insert subblock failed : %s\n", pblock->GetHash().ToString());
    }

    // Announce accepted subblocks to other peers
    if (!setToAnnounce.empty())
    {
        LOCK(cs_vNodes);
        for (const uint256 &_hash : setToAnnounce)
        {
            for (CNode *pnode : vNodes)
            {
                pnode->PushSubblockHash(_hash);
            }
        }
    }

    // Check that we're on the best dag and if not then
    // initiate a re-org over to the summary block that has
    // the best dag connected to it.
    //
    // NOTE: you can not put this call to CheckForReorg() in the above
    // code block where the cs_forest lock is taken. This will cause
    // a lockorder issue with cs_main.
    if (fCheckForReorg)
    {
        tailstormForest.CheckForReorg();
        tailstormForest.Check();
    }

    LOG(DAG, "Completed AcceptSubblock : %s", pblock->GetHash().ToString());
}

std::vector<uint8_t> GenerateMinerData(uint32_t tailstorm_k, std::set<CTreeNodeRef> &setBestDag)
{
    std::vector<std::pair<uint256, std::vector<uint8_t> > > vMinerData;
    uint8_t nMinerDataVersion = 0;
    if (setBestDag.size() < (size_t)tailstorm_k - 1)
    {
        nMinerDataVersion = DEFAULT_MINER_DATA_SUBBLOCK_VERSION;
    }
    else
    {
        nMinerDataVersion = DEFAULT_MINER_DATA_SUMMARYBLOCK_VERSION;
        for (CTreeNodeRef node : setBestDag)
        {
            vMinerData.push_back(std::pair(node->subblock->GetMiningHeaderCommitment(), node->subblock->nonce));
        }
    }

    CDataStream ds(SER_NETWORK, PROTOCOL_VERSION);
    ds.reserve(1 + vMinerData.size() * (32 + CBlockHeader::MAX_NONCE_SIZE));
    ds << nMinerDataVersion << vMinerData;

    return std::vector<uint8_t>(ds.begin(), ds.end());
}
