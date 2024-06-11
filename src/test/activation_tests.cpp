// Copyright (c) 2019 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <config.h>
#include <validation/forks.h>

#include <test/test_nexa.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(activation_tests, BasicTestingSetup)

static void SetMTP(std::array<CBlockIndex, 12> &blocks, int64_t mtp)
{
    size_t len = blocks.size();

    for (size_t i = 0; i < len; ++i)
    {
        blocks[i].header.nTime = mtp + (i - (len / 2));
    }

    assert(blocks.back().GetMedianTimePast() == mtp);
}

BOOST_AUTO_TEST_CASE(isfork1enabled)
{
    const CChainParams config = Params(CBaseChainParams::REGTEST);
    CBlockIndex prev;

    // Enable when next activation decided
    const auto activation = config.GetConsensus().nextForkActivationTime;

    BOOST_CHECK(!IsFork1Enabled(nullptr));

    std::array<CBlockIndex, 12> blocks;
    for (size_t i = 1; i < blocks.size(); ++i)
    {
        blocks[i].pprev = &blocks[i - 1];
    }

    SetMTP(blocks, activation - 1);
    BOOST_CHECK(!IsFork1Enabled(&blocks.back()));

    SetMTP(blocks, activation);
    BOOST_CHECK(IsFork1Enabled(&blocks.back()));
    BOOST_CHECK(IsFork1Enabled(&blocks.back()) && !(IsFork1Enabled(&blocks.end()[-2])));

    SetMTP(blocks, activation + 1);
    BOOST_CHECK(IsFork1Enabled(&blocks.back()));
    BOOST_CHECK(!(IsFork1Enabled(&blocks.back()) && !(IsFork1Enabled(&blocks.end()[-2]))));
}

BOOST_AUTO_TEST_SUITE_END()
