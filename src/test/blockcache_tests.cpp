// Copyright (c) 2016-2022 The Bitcoin Unlimited Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "blockstorage/blockcache.h"
#include "chainparams.h"
#include "main.h"
#include "miner.h"
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

CBlock cache_testblock1()
{
    CDataStream stream(
        ParseHex(
            "2a09b21809314e85a11018b1bc87df11fa82cbfa201e8a0c7576b5fe4066dffaffff7f200000000000000000000000000000000000"
            "00000000000000000000000000000068be98307e8996803aaafb2a77f267f44af8908e0262073dbe49081b7faa4cf95eec2f610200"
            "00000000000000000000000000000000000000000000000000000000000000fc000000000000000100000000030000000101000000"
            "010000000000000000000000000000000000000000000000000000000000000000ffffffff055200000100ffffffff0100ca9a3b00"
            "000000232102d392a4b72ece58ad9fdaa04c8e2a1606f33038595787db413010a6f570628d2eac00000000"),
        SER_NETWORK, PROTOCOL_VERSION);
    CBlock block;
    stream >> block;
    return block;
};

CBlock cache_testblock2()
{
    CDataStream stream(
        ParseHex(
            "4a96014ff4723adab09735dfcd25006bb5124f6169f1ef65a67f5834d166438bffff7f200000000000000000000000000000000000"
            "00000000000000000000000000000074f382d5e1511759229380f6a8e87a054e37a1759869adb6ef3f2d5569c5c68c54ed2f616400"
            "00000000000000000000000000000000000000000000000000000000000000fc000000000000000100000000030200000101000000"
            "010000000000000000000000000000000000000000000000000000000000000000ffffffff050164000000ffffffff0100ca9a3b00"
            "000000232103e57c28ba3d768ae9ad05194f972a4b0a4e5e8d9406cb521e871bf90094ef4118ac00000000"),
        SER_NETWORK, PROTOCOL_VERSION);
    CBlock block;
    stream >> block;
    return block;
};

CBlock cache_testblock3()
{
    CDataStream stream(
        ParseHex(
            "56d437b9b3dd0f28fb3223c8a89e43ba471ff6b035c552b26896488a1670a7a3ffff7f200000000000000000000000000000000000"
            "000000000000000000000000000000b94b61e6b6ad030ad02aad875b210cad2caca80ad954c181c6d4c547eb52dbd65fec2f610400"
            "00000000000000000000000000000000000000000000000000000000000000fc000000000000000100000000030000000101000000"
            "010000000000000000000000000000000000000000000000000000000000000000ffffffff055400000100ffffffff0100ca9a3b00"
            "000000232102d392a4b72ece58ad9fdaa04c8e2a1606f33038595787db413010a6f570628d2eac00000000"),
        SER_NETWORK, PROTOCOL_VERSION);
    CBlock block;
    stream >> block;
    return block;
};

BOOST_FIXTURE_TEST_SUITE(blockcache_tests, TestingSetup)

BOOST_AUTO_TEST_CASE(cache_tests)
{
    CBlockCache localcache;
    localcache.Init();
    IsChainNearlySyncdSet(false);

    // Create a new block and add it to the block cache
    CBlockRef pNewBlock1 = MakeBlockRef(cache_testblock1());
    localcache.AddBlock(pNewBlock1, 1);

    // Retrieve the block from the cache
    const ConstCBlockRef pBlockCache1 = localcache.GetBlock(pNewBlock1->GetHash());
    if (pBlockCache1)
    {
        BOOST_CHECK(pBlockCache1->GetHash() == pNewBlock1->GetHash());
    }
    else
    {
        throw std::runtime_error(
            std::string("Could not find block1 in blockcache for ") + HexStr(pNewBlock1->GetHash()));
    }

    // Create two new blocks and add it to the block cache
    CBlockRef pNewBlock2 = MakeBlockRef(cache_testblock2());
    localcache.AddBlock(pNewBlock2, 2);
    CBlockRef pNewBlock3 = MakeBlockRef(cache_testblock3());
    localcache.AddBlock(pNewBlock3, 3);

    // Retrieve block2 from the cache
    const ConstCBlockRef pBlockCache2 = localcache.GetBlock(pNewBlock2->GetHash());
    if (pBlockCache2)
    {
        BOOST_CHECK(pBlockCache2->GetHash() == pNewBlock2->GetHash());
    }
    else
    {
        throw std::runtime_error(
            std::string("Could not find block2 in blockcache for ") + HexStr(pNewBlock2->GetHash()));
    }

    // Retrieve block3 from the cache
    const ConstCBlockRef pBlockCache3 = localcache.GetBlock(pNewBlock3->GetHash());
    if (pBlockCache3)
    {
        BOOST_CHECK(pBlockCache3->GetHash() == pNewBlock3->GetHash());
    }
    else
    {
        throw std::runtime_error(
            std::string("Could not find block3 in blockcache for ") + HexStr(pNewBlock3->GetHash()));
    }

    // Check all blocks are not the same
    BOOST_CHECK(pBlockCache1->GetHash() != pBlockCache2->GetHash());
    BOOST_CHECK(pBlockCache1->GetHash() != pBlockCache3->GetHash());
    BOOST_CHECK(pBlockCache2->GetHash() != pBlockCache3->GetHash());

    // Erase a block and check it is erased
    localcache.EraseBlock(pNewBlock1->GetHash());
    const ConstCBlockRef pBlockCacheNull = localcache.GetBlock(pNewBlock1->GetHash());
    BOOST_CHECK(pBlockCacheNull == nullptr);
}

BOOST_AUTO_TEST_SUITE_END()
