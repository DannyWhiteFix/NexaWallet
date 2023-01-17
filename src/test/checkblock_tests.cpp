// Copyright (c) 2013-2015 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "clientversion.h"
#include "consensus/validation.h"
#include "main.h" // For CheckBlock
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


BOOST_AUTO_TEST_CASE(TestBlock)
{
    CBlock block = TestBlock1();
    CBlockRef pblock = MakeBlockRef(block);
    CValidationState state;
    BOOST_CHECK_MESSAGE(CheckBlock(Params().GetConsensus(), pblock, state), "Basic CheckBlock failed");
    // TODO: to re-enable checking of contextualblockcheck we need a pindexPrev which we can not do in this test
    //       using a random block from the mainnet blockchain. To re-enable this test we would have to modify
    //       ContextualCheckBlock such that we pass in the params that are derived from the block index.
    // BOOST_CHECK_MESSAGE(LockAndContextualCheckBlock(pblock, state, pindexPrev), "Contextual CheckBlock failed");
}

BOOST_AUTO_TEST_SUITE_END()
