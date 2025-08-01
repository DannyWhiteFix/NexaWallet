// Copyright (c) 2015-2025 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Unit tests for block index handling

#include "blockstorage/blockstorage.h"
#include "chainparams.h"
#include "main.h"
#include "miner.h"
#include "validation/validation.h"

#include "test/test_nexa.h"
#include "test/testutil.h"

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(blockindex_tests, TestingSetup)

// Test that the trimming of headers from the block index,
// and test whether the headers are either present or null.
// Only recent entries in the block index should have headers actually
// stored in RAM, otherwise they should be null and only accessible
// directly from the database.
BOOST_AUTO_TEST_CASE(header_handling)
{
    // Setup index
    const CChainParams &chainparams = Params(CBaseChainParams::REGTEST);
    {
        LOCK(cs_main);
        UnloadBlockIndex();
        chainActive.reset();
        InitBlockIndex(chainparams);
    }

    assert(chainActive.Tip()->GetBlockHash() == chainparams.GetConsensus().hashGenesisBlock);
    CScript scriptPubKey = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f"
                                                 "6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f")
                                     << OP_CHECKSIG;

    LOCK(cs_main);
    bool fBlockDownload = false;
    IsInitialBlockDownloadInit(&fBlockDownload);
    fCheckpointsEnabled = false;

    // Grab initial template:
    std::unique_ptr<CBlockTemplate> pblocktemplate(new CBlockTemplate());
    BOOST_CHECK(pblocktemplate = BlockAssembler(chainparams).CreateNewBlock(scriptPubKey));

    // Create index entries right up to the flush point which would be 2 times DEFAULT_HEADERS_TO_KEEP_IN_RAM
    // which in this case is 200 entries.
    for (unsigned int i = 0; i < 199; i++)
    {
        CBlockRef pblock = pblocktemplate->block;
        auto tip = chainActive.Tip();
        pblock->nTime = tip->GetMedianTimePast() + 1000;
        pblock->hashPrevBlock = tip->GetBlockHash();
        pblock->hashAncestor = tip->GetChildsConsensusAncestor()->GetBlockHash();
        BOOST_CHECK(pblock->hashAncestor != uint256());
        CMutableTransaction txCoinbase(*pblock->vtx[0]);
        txCoinbase.nVersion = 0;
        txCoinbase.vout[1].scriptPubKey = CScript() << OP_RETURN << (tip->height() + 1) << OP_0;
        txCoinbase.vout[0].scriptPubKey = CScript();
        pblock->vtx[0] = MakeTransactionRef(std::move(txCoinbase));
        pblock->height = tip->height() + 1;
        pblock->nBits = GetNextWorkRequired(tip, pblock.get(), chainparams.GetConsensus());
        pblock->chainWork = ArithToUint256(tip->chainWork() + GetWorkForDifficultyBits(pblock->nBits));
        pblock->txCount = 1;

        pblock->UpdateHeader();
        CBlockIndex *pindex = AddToBlockIndex(chainparams, *pblock);

        // Check we have the header when we first create the index value
        BOOST_CHECK(!pindex->IsHeaderNull());
        BOOST_CHECK(pindex->GetBlockHeader().height == pblock->height);
        BOOST_CHECK(pindex->GetBlockHeader().nBits == pblock->nBits);

        chainActive.SetTip(pindex);
    }

    // Flush state to disk and check header status
    // Nothing should have been flushed (everthing should still be in setDirtyBlockIndex)
    // and all headers should still be present in the block index.
    BOOST_CHECK(setHeadersToTrim.size() == 99);
    CValidationState state;
    FlushStateToDisk(state, FLUSH_STATE_IF_NEEDED);
    {
        // Nothing got flushed
        BOOST_CHECK(setDirtyBlockIndex.size() == 199);

        // Check all headers are present still after flushing
        uint32_t nChainHeight = chainActive.Height();
        for (auto iter : mapBlockIndex)
        {
            if ((nChainHeight - iter.second->nHeight) < (2 * DEFAULT_HEADERS_TO_KEEP_IN_RAM))
            {
                BOOST_CHECK(!iter.second->IsHeaderNull());
            }
            else
            {
                BOOST_CHECK(iter.second->IsHeaderNull());
            }
        }
        BOOST_CHECK(setHeadersToTrim.size() == 99);
    }

    // Add one more index entry and then flush state.
    // Only the most recent 100 index entries should still have headers, all others
    // should be nulled.
    {
        CBlockRef pblock = pblocktemplate->block;
        auto tip = chainActive.Tip();
        pblock->nTime = tip->GetMedianTimePast() + 1000;
        pblock->hashPrevBlock = tip->GetBlockHash();
        pblock->hashAncestor = tip->GetChildsConsensusAncestor()->GetBlockHash();
        BOOST_CHECK(pblock->hashAncestor != uint256());
        CMutableTransaction txCoinbase(*pblock->vtx[0]);
        txCoinbase.nVersion = 0;
        txCoinbase.vout[1].scriptPubKey = CScript() << OP_RETURN << (tip->height() + 1) << OP_0;
        txCoinbase.vout[0].scriptPubKey = CScript();
        pblock->vtx[0] = MakeTransactionRef(std::move(txCoinbase));
        pblock->height = tip->height() + 1;
        pblock->nBits = GetNextWorkRequired(tip, pblock.get(), chainparams.GetConsensus());
        pblock->chainWork = ArithToUint256(tip->chainWork() + GetWorkForDifficultyBits(pblock->nBits));
        pblock->txCount = 1;

        pblock->UpdateHeader();
        CBlockIndex *pindex = AddToBlockIndex(chainparams, *pblock);

        // Check we have the header when we first create the index value
        BOOST_CHECK(!pindex->IsHeaderNull());
        BOOST_CHECK(pindex->GetBlockHeader().height == pblock->height);
        BOOST_CHECK(pindex->GetBlockHeader().nBits == pblock->nBits);

        chainActive.SetTip(pindex);
    }
    BOOST_CHECK(setHeadersToTrim.size() == 100);
    FlushStateToDisk(state, FLUSH_STATE_IF_NEEDED);
    {
        // Everthing got flushed
        BOOST_CHECK(setDirtyBlockIndex.size() == 0);

        // Check all headers are present still after flushing
        uint32_t nChainHeight = chainActive.Height();
        for (auto &iter : mapBlockIndex)
        {
            const uint32_t &nHeight = iter.second->nHeight;
            if (nHeight == 0 || (nChainHeight - nHeight) < DEFAULT_HEADERS_TO_KEEP_IN_RAM)
            {
                BOOST_CHECK(!iter.second->IsHeaderNull());
            }
            else
            {
                BOOST_CHECK(iter.second->IsHeaderNull());
            }
        }
        BOOST_CHECK(setHeadersToTrim.size() == 0);
    }

    // Add 5000 more entries before flushing.
    // Only the most recent 100 index entries should still have headers, all others
    // should be nulled.
    for (unsigned int i = 0; i < 5000; ++i)
    {
        CBlockRef pblock = pblocktemplate->block;
        auto tip = chainActive.Tip();
        pblock->nTime = tip->GetMedianTimePast() + 1000;
        pblock->hashPrevBlock = tip->GetBlockHash();
        pblock->hashAncestor = tip->GetChildsConsensusAncestor()->GetBlockHash();
        BOOST_CHECK(pblock->hashAncestor != uint256());
        CMutableTransaction txCoinbase(*pblock->vtx[0]);
        txCoinbase.nVersion = 0;
        txCoinbase.vout[1].scriptPubKey = CScript() << OP_RETURN << (tip->height() + 1) << OP_0;
        txCoinbase.vout[0].scriptPubKey = CScript();
        pblock->vtx[0] = MakeTransactionRef(std::move(txCoinbase));
        pblock->height = tip->height() + 1;
        pblock->nBits = GetNextWorkRequired(tip, pblock.get(), chainparams.GetConsensus());
        pblock->chainWork = ArithToUint256(tip->chainWork() + GetWorkForDifficultyBits(pblock->nBits));
        pblock->txCount = 1;

        pblock->UpdateHeader();
        CBlockIndex *pindex = AddToBlockIndex(chainparams, *pblock);

        // Check we have the header when we first create the index value
        BOOST_CHECK(!pindex->IsHeaderNull());
        BOOST_CHECK(pindex->GetBlockHeader().height == pblock->height);
        BOOST_CHECK(pindex->GetBlockHeader().nBits == pblock->nBits);

        chainActive.SetTip(pindex);
    }

    BOOST_CHECK(setHeadersToTrim.size() == 5000);
    FlushStateToDisk(state, FLUSH_STATE_IF_NEEDED);
    {
        // Everthing got flushed
        BOOST_CHECK(setDirtyBlockIndex.size() == 0);

        // Check all headers are present still after flushing
        uint32_t nChainHeight = chainActive.Height();
        for (auto &iter : mapBlockIndex)
        {
            const uint32_t &nHeight = iter.second->nHeight;
            if (nHeight == 0 || (nChainHeight - nHeight) < DEFAULT_HEADERS_TO_KEEP_IN_RAM)
            {
                BOOST_CHECK(!iter.second->IsHeaderNull());
            }
            else
            {
                BOOST_CHECK(iter.second->IsHeaderNull());
            }
        }
        BOOST_CHECK(setHeadersToTrim.size() == 0);
    }

    // Add 1111 more entries before flushing.
    // Only the most recent 100 index entries should still have headers, all others
    // should be nulled.
    for (unsigned int i = 0; i < 1111; ++i)
    {
        CBlockRef pblock = pblocktemplate->block;
        auto tip = chainActive.Tip();
        pblock->nTime = tip->GetMedianTimePast() + 1000;
        pblock->hashPrevBlock = tip->GetBlockHash();
        pblock->hashAncestor = tip->GetChildsConsensusAncestor()->GetBlockHash();
        BOOST_CHECK(pblock->hashAncestor != uint256());
        CMutableTransaction txCoinbase(*pblock->vtx[0]);
        txCoinbase.nVersion = 0;
        txCoinbase.vout[1].scriptPubKey = CScript() << OP_RETURN << (tip->height() + 1) << OP_0;
        txCoinbase.vout[0].scriptPubKey = CScript();
        pblock->vtx[0] = MakeTransactionRef(std::move(txCoinbase));
        pblock->height = tip->height() + 1;
        pblock->nBits = GetNextWorkRequired(tip, pblock.get(), chainparams.GetConsensus());
        pblock->chainWork = ArithToUint256(tip->chainWork() + GetWorkForDifficultyBits(pblock->nBits));
        pblock->txCount = 1;

        pblock->UpdateHeader();
        CBlockIndex *pindex = AddToBlockIndex(chainparams, *pblock);

        // Check we have the header when we first create the index value
        BOOST_CHECK(!pindex->IsHeaderNull());
        BOOST_CHECK(pindex->GetBlockHeader().height == pblock->height);
        BOOST_CHECK(pindex->GetBlockHeader().nBits == pblock->nBits);

        chainActive.SetTip(pindex);
    }

    BOOST_CHECK(setHeadersToTrim.size() == 1111);
    FlushStateToDisk(state, FLUSH_STATE_IF_NEEDED);
    {
        // Everthing got flushed
        BOOST_CHECK(setDirtyBlockIndex.size() == 0);

        // Check all headers are present still after flushing
        uint32_t nChainHeight = chainActive.Height();
        for (auto &iter : mapBlockIndex)
        {
            const uint32_t &nHeight = iter.second->nHeight;
            if (nHeight == 0 || (nChainHeight - nHeight) < DEFAULT_HEADERS_TO_KEEP_IN_RAM)
            {
                BOOST_CHECK(!iter.second->IsHeaderNull());
            }
            else
            {
                BOOST_CHECK(iter.second->IsHeaderNull());
            }
        }
        BOOST_CHECK(setHeadersToTrim.size() == 0);
    }

    // Try to access headers.
    // Loop through looking for random headers, which may or may not be in the
    // blockindex RAM, however, we should always get a header, whether it came
    // from RAM or disk.
    FastRandomContext ctx;
    const size_t nSkipRange = mapBlockIndex.size(); // spot check the entire index
    for (int i = 0; i <= 100; i++)
    {
        uint64_t nSkipTo = std::max((uint64_t)1, ctx.randrange(nSkipRange));
        auto iter = mapBlockIndex.begin();
        std::advance(iter, nSkipTo);
        CBlockHeader header = iter->second->GetBlockHeader();
        BOOST_CHECK(header.IsNull() != true);
    }

    // Must reset this to "true" or you'll cause a thread to hang in the main test loop.
    fCheckpointsEnabled = true;
}

BOOST_AUTO_TEST_SUITE_END()
