// Copyright (c) 2016-2022 The Bitcoin Unlimited Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "blockrelay/thinblock.h"
#include "bloom.h"
#include "chainparams.h"
#include "main.h"
#include "primitives/block.h"
#include "random.h"
#include "serialize.h"
#include "streams.h"
#include "txmempool.h"
#include "uint256.h"
#include "unlimited.h"
#include "util.h"
#include "utilstrencodings.h"
#include "version.h"

#include "test/test_nexa.h"

#include <boost/test/unit_test.hpp>
#include <sstream>
#include <string.h>


BOOST_FIXTURE_TEST_SUITE(thinblock_tests, TestingSetup)

BOOST_AUTO_TEST_CASE(thinblock_test)
{
    CBloomFilter filter;
    std::vector<uint256> vOrphanHashes;
    CAddress addr1(ipaddress(0xa0b0c001, 10000));
    CNode dummyNode1(INVALID_SOCKET, addr1, "", true);
    CBlock block = TestBlock1();

    // Create 10 random hashes to seed the orphanhash vector.  This way we will create a bloom filter
    // with a size of 10 elements.
    std::string hash = "3fba505b48865fccda4e248cecc39d5dfbc6b8ef7b4adc9cd27242c1193c714";
    for (int i = 0; i < 10; i++)
    {
        std::stringstream ss;
        ss << i;
        hash.append(ss.str());
        uint256 random_hash = uint256S(hash);
        vOrphanHashes.push_back(random_hash);
    }
    BuildSeededBloomFilter(filter, vOrphanHashes, block.GetHash(), &dummyNode1, true);

    /* empty filter */
    CThinBlock thinblock(block, filter);
    CXThinBlock xthinblock(block, &filter);
    BOOST_CHECK_EQUAL(290UL, thinblock.vMissingTx.size());
    BOOST_CHECK_EQUAL(290UL, xthinblock.vMissingTx.size());

    /* insert txid not in block */
    const uint256 random_hash = uint256S("3fba505b48865fccda4e248cecc39d5dfbc6b8ef7b4adc9cd27242c1193c7133");
    filter.insert(random_hash);
    CThinBlock thinblock1(block, filter);
    CXThinBlock xthinblock1(block, &filter);
    BOOST_CHECK_EQUAL(290UL, thinblock1.vMissingTx.size());
    BOOST_CHECK_EQUAL(290UL, xthinblock1.vMissingTx.size());

    /* insert txid in block */
    const uint256 hash_in_block = block.vtx[1]->GetId();
    filter.insert(hash_in_block);
    CThinBlock thinblock2(block, filter);
    CXThinBlock xthinblock2(block, &filter);
    BOOST_CHECK_EQUAL(289UL, thinblock2.vMissingTx.size());
    BOOST_CHECK_EQUAL(289UL, xthinblock2.vMissingTx.size());

    /*collision test*/
    BOOST_CHECK(!xthinblock2.collision);
    block.vtx.push_back(block.vtx[1]); // duplicate tx
    filter.clear();
    CXThinBlock xthinblock3(block, &filter);
    BOOST_CHECK(xthinblock3.collision);


    //  Add tests using a non-deterministic bloom filter which may
    //  or may not yeild a false positive.
    CBloomFilter filter1;
    BuildSeededBloomFilter(filter1, vOrphanHashes, block.GetHash(), &dummyNode1, false);

    /* empty filter */
    CBlock block1 = TestBlock1();
    CThinBlock thinblock4(block1, filter1);
    CXThinBlock xthinblock4(block1, &filter1);
    BOOST_CHECK(thinblock4.vMissingTx.size() >= 288 && thinblock4.vMissingTx.size() <= 290);
    BOOST_CHECK(xthinblock4.vMissingTx.size() >= 288 && xthinblock4.vMissingTx.size() <= 290);

    /* insert txid not in block */
    const uint256 random_hash1 = uint256S("3fba505b48865fccda4e248cecc39d5dfbc6b8ef7b4adc9cd27242c1193c7132");
    filter1.insert(random_hash1);
    CThinBlock thinblock5(block1, filter1);
    CXThinBlock xthinblock5(block1, &filter1);
    BOOST_CHECK(thinblock5.vMissingTx.size() >= 288 && thinblock5.vMissingTx.size() <= 290);
    BOOST_CHECK(xthinblock5.vMissingTx.size() >= 288 && xthinblock5.vMissingTx.size() <= 290);

    /* insert txid in block */
    const uint256 hash_in_block1 = block.vtx[1]->GetId();
    filter1.insert(hash_in_block1);
    CThinBlock thinblock6(block1, filter1);
    CXThinBlock xthinblock6(block1, &filter1);
    BOOST_CHECK(thinblock6.vMissingTx.size() >= 287 && thinblock6.vMissingTx.size() <= 289);
    BOOST_CHECK(xthinblock6.vMissingTx.size() >= 287 && xthinblock6.vMissingTx.size() <= 289);

    /*collision test*/
    BOOST_CHECK(!xthinblock6.collision);
    block.vtx.push_back(block1.vtx[1]); // duplicate tx
    filter1.clear();
    CXThinBlock xthinblock7(block, &filter1);
    BOOST_CHECK(xthinblock7.collision);
}

BOOST_AUTO_TEST_SUITE_END()
