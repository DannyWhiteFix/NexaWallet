// Copyright (c) 2013-2015 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "clientversion.h"
#include "consensus/validation.h"
#include "primitives/block.h"
#include "test/test_nexa.h"
#include "utiltime.h"
#include "validation/validation.h"

#include <cstdio>

#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>
#include <boost/test/unit_test.hpp>

bool LockAndContextualCheckBlock(const ConstCBlockRef pblock, CValidationState &state)
{
    LOCK(cs_main);
    return ContextualCheckBlock(pblock, state, nullptr);
}

BOOST_FIXTURE_TEST_SUITE(checkblock_tests, BasicTestingSetup)


BOOST_AUTO_TEST_CASE(BasicTestBlock)
{
    CBlock block = TestBlock1();
    CBlockRef pblock = MakeBlockRef(block);
    CValidationState state;
    BOOST_CHECK_MESSAGE(!pblock->fChecked, "Block was already checked");
    BOOST_CHECK_MESSAGE(CheckBlock(Params().GetConsensus(), pblock, state), "Basic CheckBlock failed");
    BOOST_CHECK_MESSAGE(!state.IsInvalid(), "Basic CheckBlock state failed");
    // TODO: to re-enable checking of contextualblockcheck we need a pindexPrev which we can not do in this test
    //       using a random block from the mainnet blockchain. To re-enable this test we would have to modify
    //       ContextualCheckBlock such that we pass in the params that are derived from the block index.
    // BOOST_CHECK_MESSAGE(LockAndContextualCheckBlock(pblock, state, pindexPrev), "Contextual CheckBlock failed");

    // Run the test again. fChecked would have been set to true and so that same results should be received.
    CValidationState state1;
    BOOST_CHECK_MESSAGE(pblock->fChecked, "fChecked was not set to true");
    BOOST_CHECK_MESSAGE(CheckBlock(Params().GetConsensus(), pblock, state1), "Basic CheckBlock failed");
    BOOST_CHECK_MESSAGE(!state1.IsInvalid(), "Basic CheckBlock state failed");

    // Run test on another block that will fail CheckBlock().  Then run it again to verify we get the same result.
    // The purpose is to ensure that the fChecked flag returns false both times.
    //
    // Remove all transactions from block.vtx which should cause the merkleroot check to fail however
    // the state should not be INVALID.
    CBlock block2 = TestBlock2();
    pblock = MakeBlockRef(block2);
    CValidationState state2;
    pblock->vtx.clear();
    BOOST_CHECK_MESSAGE(
        !CheckBlock(Params().GetConsensus(), pblock, state2), "CheckBlock did not fail when it should have");
    BOOST_CHECK_MESSAGE(
        !state2.IsInvalid(), "Merkleroot check has failed. Returned an Invalid state when it should not have.");
    BOOST_CHECK_MESSAGE(!pblock->fChecked, "Block was already checked"); // fChecked should be false

    // run it again
    BOOST_CHECK_MESSAGE(
        !CheckBlock(Params().GetConsensus(), pblock, state2), "CheckBlock did not fail when it should have");
    BOOST_CHECK_MESSAGE(
        !state2.IsInvalid(), "Merkleroot check has failed. Returned an Invalid state when it should not have.");
    BOOST_CHECK_MESSAGE(!pblock->fChecked, "Block was already checked"); // fChecked should be false

    // Null the block so the header check should fail this time rather than the merkleroot check.
    CBlock block3 = TestBlock3();
    pblock = MakeBlockRef(block3);
    CValidationState state3;
    pblock->SetNull();
    BOOST_CHECK_MESSAGE(
        !CheckBlock(Params().GetConsensus(), pblock, state3), "CheckBlock did not fail when it should have");
    BOOST_CHECK_MESSAGE(state3.IsInvalid(), "CheckBlock did not fail when it should have.");
    BOOST_CHECK_MESSAGE(!pblock->fChecked, "Block was already checked"); // fChecked should be false

    // run it again
    BOOST_CHECK_MESSAGE(
        !CheckBlock(Params().GetConsensus(), pblock, state3), "CheckBlock did not fail when it should have");
    BOOST_CHECK_MESSAGE(state3.IsInvalid(), "CheckBlock did not fail when it should have.");
    BOOST_CHECK_MESSAGE(!pblock->fChecked, "Block was already checked"); // fChecked should be false
}

BOOST_AUTO_TEST_CASE(MerkleRootFailure)
{
    // Check various scenarios for getting a merkle root check to fail in CheckBlock()
    CBlock block = TestBlock2();
    CBlockRef pblock = MakeBlockRef(block);

    // Do a basic check
    CValidationState state1;
    BOOST_CHECK_MESSAGE(!pblock->fChecked, "Block was already checked");
    BOOST_CHECK_MESSAGE(CheckBlock(Params().GetConsensus(), pblock, state1), "Basic CheckBlock failed");
    BOOST_CHECK_MESSAGE(!state1.IsInvalid(), "Basic CheckBlock state failed");

    // Remove one transaction from block.vtx, malleate the signature and then add the
    // malleated txn back to the block.  This should cause the merkleroot check to fail however
    // the state should not be INVALID.
    CValidationState state1a;
    CTransactionRef ptx = pblock->vtx.back();
    CMutableTransaction mtx(*ptx);
    mtx.vin[0].scriptSig = CScript();
    const CTransaction tx(mtx);

    pblock->vtx.pop_back();
    pblock->vtx.push_back(MakeTransactionRef(tx));

    pblock->fChecked = false; // reset so that we don't bypass CheckBlock() the second time.
    BOOST_CHECK_MESSAGE(!pblock->fChecked, "Block was already checked");
    BOOST_CHECK_MESSAGE(
        !CheckBlock(Params().GetConsensus(), pblock, state1a), "CheckBlock did not fail when it should have");
    BOOST_CHECK_MESSAGE(
        !state1a.IsInvalid(), "Merkleroot check has failed. Returned an Invalid state when it should not have.");

    // Remove one transaction (the one we malleated above) from block.vtx which should cause the merkleroot check
    // to fail however the state should not return INVALID, but only with error.
    CValidationState state2;
    pblock->vtx.pop_back();
    pblock->fChecked = false; // reset so that we don't bypass CheckBlock() the second time.
    BOOST_CHECK_MESSAGE(!pblock->fChecked, "Block was already checked");
    BOOST_CHECK_MESSAGE(
        !CheckBlock(Params().GetConsensus(), pblock, state2), "CheckBlock did not fail when it should have");
    BOOST_CHECK_MESSAGE(
        !state2.IsInvalid(), "Merkleroot check has failed. Returned an Invalid state when it should not have.");

    // Add a duplicate transaction to block.vtx
    CValidationState state2a;
    CTransactionRef ptx2 = pblock->vtx.back();
    pblock->vtx.push_back(ptx2);
    pblock->fChecked = false; // reset so that we don't bypass CheckBlock() the second time.
    BOOST_CHECK_MESSAGE(!pblock->fChecked, "Block was already checked");
    BOOST_CHECK_MESSAGE(
        !CheckBlock(Params().GetConsensus(), pblock, state2a), "CheckBlock did not fail when it should have");
    BOOST_CHECK_MESSAGE(
        !state2a.IsInvalid(), "Merkleroot check has failed. Returned an Invalid state when it should not have.");

    // Remove all transactions from block.vtx which should cause the merkleroot check to fail however
    // the state should not be INVALID.
    CValidationState state3;
    pblock->vtx.clear();
    pblock->fChecked = false; // reset so that we don't bypass CheckBlock() the second time.
    BOOST_CHECK_MESSAGE(!pblock->fChecked, "Block was already checked");
    BOOST_CHECK_MESSAGE(
        !CheckBlock(Params().GetConsensus(), pblock, state3), "CheckBlock did not fail when it should have");
    BOOST_CHECK_MESSAGE(
        !state3.IsInvalid(), "Merkleroot check has failed. Returned an Invalid state when it should not have.");
}

BOOST_AUTO_TEST_SUITE_END()
