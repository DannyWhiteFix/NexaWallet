// Copyright (c) 2012-2015 The Bitcoin Core developers
// Copyright (c) 2015-2023 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "bloom.h"

#include "base58.h"
#include "clientversion.h"
#include "consensus/merkle.h"
#include "key.h"
#include "merkleblock.h"
#include "random.h"
#include "serialize.h"
#include "streams.h"
#include "test/test_nexa.h"
#include "testutil.h"
#include "uint256.h"
#include "util.h"
#include "utilstrencodings.h"
#include <algorithm>
#include <vector>

#include <boost/test/unit_test.hpp>
#include <boost/tuple/tuple.hpp>

using namespace std;

BOOST_FIXTURE_TEST_SUITE(bloom_tests, BasicTestingSetup)

// Access protected members of the Bloom filter
class CBloomFilterAccess : public CBloomFilter
{
public:
    int hashFuncs() { return nHashFuncs; }
    CBloomFilterAccess(unsigned int _nElements, double _nFPRate, unsigned int _nTweak, unsigned char _nFlagsIn)
        : CBloomFilter(_nElements, _nFPRate, _nTweak, _nFlagsIn)
    {
    }
};

BOOST_AUTO_TEST_CASE(bloom_extreme_cases)
{
    CBloomFilterAccess filter(1000000, 0.0000001, 0, BLOOM_UPDATE_NONE);
    BOOST_CHECK(filter.hashFuncs() == 1);
}

BOOST_AUTO_TEST_CASE(bloom_create_insert_serialize)
{
    CBloomFilter filter(3, 0.01, 0, BLOOM_UPDATE_ALL);

    filter.insert(ParseHex("99108ad8ed9bb6274d3980bab5a85c048f0950c8"));
    BOOST_CHECK_MESSAGE(filter.contains(ParseHex("99108ad8ed9bb6274d3980bab5a85c048f0950c8")),
        "BloomFilter doesn't contain just-inserted object!");
    // One bit different in first byte
    BOOST_CHECK_MESSAGE(!filter.contains(ParseHex("19108ad8ed9bb6274d3980bab5a85c048f0950c8")),
        "BloomFilter contains something it shouldn't!");

    filter.insert(ParseHex("b5a2c786d9ef4658287ced5914b37a1b4aa32eee"));
    BOOST_CHECK_MESSAGE(filter.contains(ParseHex("b5a2c786d9ef4658287ced5914b37a1b4aa32eee")),
        "BloomFilter doesn't contain just-inserted object (2)!");

    filter.insert(ParseHex("b9300670b4c5366e95b2699e8b18bc75e5f729c5"));
    BOOST_CHECK_MESSAGE(filter.contains(ParseHex("b9300670b4c5366e95b2699e8b18bc75e5f729c5")),
        "BloomFilter doesn't contain just-inserted object (3)!");

    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << filter;

    vector<unsigned char> vch = ParseHex("03614e9b050000000000000001");
    vector<char> expected(vch.size());

    for (unsigned int i = 0; i < vch.size(); i++)
        expected[i] = (char)vch[i];

    BOOST_CHECK_EQUAL_COLLECTIONS(stream.begin(), stream.end(), expected.begin(), expected.end());

    BOOST_CHECK_MESSAGE(filter.contains(ParseHex("99108ad8ed9bb6274d3980bab5a85c048f0950c8")),
        "BloomFilter doesn't contain just-inserted object!");
    filter.clear();
    BOOST_CHECK_MESSAGE(
        !filter.contains(ParseHex("99108ad8ed9bb6274d3980bab5a85c048f0950c8")), "BloomFilter should be empty!");
}

BOOST_AUTO_TEST_CASE(bloom_create_insert_serialize_with_tweak)
{
    // Same test as bloom_create_insert_serialize, but we add a nTweak of 100
    CBloomFilter filter(3, 0.01, 2147483649UL, BLOOM_UPDATE_ALL);

    filter.insert(ParseHex("99108ad8ed9bb6274d3980bab5a85c048f0950c8"));
    BOOST_CHECK_MESSAGE(filter.contains(ParseHex("99108ad8ed9bb6274d3980bab5a85c048f0950c8")),
        "BloomFilter doesn't contain just-inserted object!");
    // One bit different in first byte
    BOOST_CHECK_MESSAGE(!filter.contains(ParseHex("19108ad8ed9bb6274d3980bab5a85c048f0950c8")),
        "BloomFilter contains something it shouldn't!");

    filter.insert(ParseHex("b5a2c786d9ef4658287ced5914b37a1b4aa32eee"));
    BOOST_CHECK_MESSAGE(filter.contains(ParseHex("b5a2c786d9ef4658287ced5914b37a1b4aa32eee")),
        "BloomFilter doesn't contain just-inserted object (2)!");

    filter.insert(ParseHex("b9300670b4c5366e95b2699e8b18bc75e5f729c5"));
    BOOST_CHECK_MESSAGE(filter.contains(ParseHex("b9300670b4c5366e95b2699e8b18bc75e5f729c5")),
        "BloomFilter doesn't contain just-inserted object (3)!");

    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << filter;

    vector<unsigned char> vch = ParseHex("03ce4299050000000100008001");
    vector<char> expected(vch.size());

    for (unsigned int i = 0; i < vch.size(); i++)
        expected[i] = (char)vch[i];

    BOOST_CHECK_EQUAL_COLLECTIONS(stream.begin(), stream.end(), expected.begin(), expected.end());
}

BOOST_AUTO_TEST_CASE(bloom_create_insert_key)
{
    string strSecret = string("6EMSbgeLVqYap1cACuMCAhjaoReZh8U94bXRnoURQD63TYEfT1Bx");
    CBitcoinSecret vchSecret;
    BOOST_CHECK(vchSecret.SetString(Params(), strSecret));

    CKey key = vchSecret.GetKey();
    CPubKey pubkey = key.GetPubKey();
    vector<unsigned char> vchPubKey(pubkey.begin(), pubkey.end());

    CBloomFilter filter(2, 0.001, 0, BLOOM_UPDATE_ALL);
    filter.insert(vchPubKey);
    uint160 hash = pubkey.GetID();
    filter.insert(vector<unsigned char>(hash.begin(), hash.end()));

    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << filter;

    vector<unsigned char> vch = ParseHex("03c06e4f080000000000000001");
    vector<char> expected(vch.size());

    for (unsigned int i = 0; i < vch.size(); i++)
        expected[i] = (char)vch[i];
    BOOST_CHECK_EQUAL_COLLECTIONS(stream.begin(), stream.end(), expected.begin(), expected.end());
}

BOOST_AUTO_TEST_CASE(bloom_match)
{
    CTransaction tx = tx1x1(COutPoint(InsecureRand256(), 0), CScript() << OP_1, 10);
    // stream >> tx;
    const CTransactionRef ptx = MakeTransactionRef(tx);


    CTransaction spendingTx = tx1x1(tx.OutpointAt(0), CScript() << OP_1, 10);
    // spendStream >> spendingTx;

    CBloomFilter filter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(ptx->GetIdem());
    BOOST_CHECK_MESSAGE(filter.IsRelevantAndUpdate(ptx), "Simple Bloom filter didn't match tx hash");

#if 0 /* TODO replace these hard codings */
    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    // byte-reversed tx hash
    filter.insert(ParseHex("6bff7fcd4f8565ef406dd5d63d4ff94f318fe82027fd4dc451b04474019f74b4"));
    BOOST_CHECK_MESSAGE(
        filter.IsRelevantAndUpdate(ptx), "Simple Bloom filter didn't match manually serialized tx hash");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(ParseHex("30450220070aca44506c5cef3a16ed519d7c3c39f8aab192c4e1c90d065f37b8a4af6141022100a8e160b856c2d"
                           "43d27d8fba71e5aef6405b8643ac4cb7cb3c462aced7f14711a01"));
    BOOST_CHECK_MESSAGE(filter.IsRelevantAndUpdate(ptx), "Simple Bloom filter didn't match input signature");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(ParseHex("046d11fee51b0e60666d5049a9101a72741df480b96ee26488a4d3466b95c9a40ac5eeef87e10a5cd336c19a845"
                           "65f80fa6c547957b7700ff4dfbdefe76036c339"));
    BOOST_CHECK_MESSAGE(filter.IsRelevantAndUpdate(ptx), "Simple Bloom filter didn't match input pub key");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(ParseHex("04943fdd508053c75000106d3bc6e2754dbcff19"));
    BOOST_CHECK_MESSAGE(filter.IsRelevantAndUpdate(ptx), "Simple Bloom filter didn't match output address");
    BOOST_CHECK_MESSAGE(
        filter.IsRelevantAndUpdate(MakeTransactionRef(spendingTx)), "Simple Bloom filter didn't add output");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(ParseHex("04943fdd508053c75000106d3bc6e2754dbcff19"));
    BOOST_CHECK_MESSAGE(filter.MatchAndInsertOutpoints(ptx), "Simple Bloom filter didn't match output address");
    BOOST_CHECK_MESSAGE(
        !filter.MatchAndInsertOutpoints(MakeTransactionRef(spendingTx)), "Simple Bloom filter matched unrelated output");
    BOOST_CHECK_MESSAGE(filter.MatchInputs(MakeTransactionRef(spendingTx)), "Simple Bloom filter didn't add output");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(ParseHex("a266436d2965547608b9e15d9032a7b9d64fa431"));
    BOOST_CHECK_MESSAGE(filter.IsRelevantAndUpdate(ptx), "Simple Bloom filter didn't match output address");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(COutPoint(uint256S("0x90c122d70786e899529d71dbeba91ba216982fb6ba58f3bdaab65e73b7e9260b"), 0));
    BOOST_CHECK_MESSAGE(filter.IsRelevantAndUpdate(ptx), "Simple Bloom filter didn't match COutPoint");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    COutPoint prevOutPoint(uint256S("0x90c122d70786e899529d71dbeba91ba216982fb6ba58f3bdaab65e73b7e9260b"), 0);
    {
        vector<unsigned char> data(32);
        memcpy(&data[0], prevOutPoint.hash.begin(), 32);
        filter.insert(data);
    }
    BOOST_CHECK_MESSAGE(
        filter.IsRelevantAndUpdate(ptx), "Simple Bloom filter didn't match manually serialized COutPoint");
#endif

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(uint256S("00000009e784f32f62ef849763d4f45b98e07ba658647343b915ff832b110436"));
    BOOST_CHECK_MESSAGE(!filter.IsRelevantAndUpdate(ptx), "Simple Bloom filter matched random tx hash");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(ParseHex("0000006d2965547608b9e15d9032a7b9d64fa431"));
    BOOST_CHECK_MESSAGE(!filter.IsRelevantAndUpdate(ptx), "Simple Bloom filter matched random address");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(COutPoint(uint256S("0x90c122d70786e899529d71dbeba91ba216982fb6ba58f3bdaab65e73b7e9260b"), 1));
    BOOST_CHECK_MESSAGE(
        !filter.IsRelevantAndUpdate(ptx), "Simple Bloom filter matched COutPoint for an output we didn't care about");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(COutPoint(uint256S("0x000000d70786e899529d71dbeba91ba216982fb6ba58f3bdaab65e73b7e9260b"), 0));
    BOOST_CHECK_MESSAGE(
        !filter.IsRelevantAndUpdate(ptx), "Simple Bloom filter matched COutPoint for an output we didn't care about");
}


BOOST_AUTO_TEST_CASE(merkle_block_1)
{
    // Random real block (6ffe14863fdc8c09660027074a8b013a261d190d91225592393f2d64f8c25f56)
    // With 9 txes
    CBlock block = TestBlock4();

    CBloomFilter filter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    // Match the last transaction
    filter.insert(uint256S("0xe0d6d1dc15326839c9e9fc4c745cf6dd1d0d78186ed2cd520934ad9f935988a8"));

    CMerkleBlock merkleBlock(block, filter);
    BOOST_CHECK(merkleBlock.header.GetHash() == block.GetHash());

    BOOST_CHECK(merkleBlock.vMatchedTxn.size() == 1);
    pair<unsigned int, uint256> pair = merkleBlock.vMatchedTxn[0];

    BOOST_CHECK(merkleBlock.vMatchedTxn[0].second ==
                uint256S("0xe0d6d1dc15326839c9e9fc4c745cf6dd1d0d78186ed2cd520934ad9f935988a8"));
    BOOST_CHECK(merkleBlock.vMatchedTxn[0].first == 8);

    vector<uint256> vMatched;
    vector<unsigned int> vIndex;
    BOOST_CHECK(merkleBlock.txn.ExtractMatches(vMatched, vIndex) == block.hashMerkleRoot);
    BOOST_CHECK(vMatched.size() == merkleBlock.vMatchedTxn.size());
    for (unsigned int i = 0; i < vMatched.size(); i++)
        BOOST_CHECK(vMatched[i] == merkleBlock.vMatchedTxn[i].second);

    // Also match the 8th transaction
    filter.insert(uint256S("0xcd6dfbb0bbdeb6c86316c20141c831fd555d25c54286f67902aee707c901468a"));
    merkleBlock = CMerkleBlock(block, filter);
    BOOST_CHECK(merkleBlock.header.GetHash() == block.GetHash());

    BOOST_CHECK(merkleBlock.vMatchedTxn.size() == 2);

    BOOST_CHECK(merkleBlock.vMatchedTxn[1] == pair);

    BOOST_CHECK(merkleBlock.vMatchedTxn[0].second ==
                uint256S("0xcd6dfbb0bbdeb6c86316c20141c831fd555d25c54286f67902aee707c901468a"));
    BOOST_CHECK(merkleBlock.vMatchedTxn[0].first == 7);

    BOOST_CHECK(merkleBlock.txn.ExtractMatches(vMatched, vIndex) == block.hashMerkleRoot);
    BOOST_CHECK(vMatched.size() == merkleBlock.vMatchedTxn.size());
    for (unsigned int i = 0; i < vMatched.size(); i++)
        BOOST_CHECK(vMatched[i] == merkleBlock.vMatchedTxn[i].second);
}

BOOST_AUTO_TEST_CASE(merkle_block_2)
{
    // Random real block (7efbd25a904baaa26ca7d93023381f4f77f040527957afac21cb21c87dbce1b5)
    // With 4 txes
    CBlock block = TestBlock2();

    CBloomFilter filter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    // Match the first transaction
    filter.insert(uint256S("0x1af3653189a1015f0e156012f65a76c8168440cd6055c9322474d7c54d83ca3b"));

    CMerkleBlock merkleBlock(block, filter);
    BOOST_CHECK(merkleBlock.header.GetHash() == block.GetHash());

    BOOST_CHECK(merkleBlock.vMatchedTxn.size() == 1);
    // pair<unsigned int, uint256> pair = merkleBlock.vMatchedTxn[0];

    BOOST_CHECK(merkleBlock.vMatchedTxn[0].second ==
                uint256S("0x1af3653189a1015f0e156012f65a76c8168440cd6055c9322474d7c54d83ca3b"));
    BOOST_CHECK(merkleBlock.vMatchedTxn[0].first == 0);

    vector<uint256> vMatched;
    vector<unsigned int> vIndex;
    BOOST_CHECK(merkleBlock.txn.ExtractMatches(vMatched, vIndex) == block.hashMerkleRoot);
    BOOST_CHECK(vMatched.size() == merkleBlock.vMatchedTxn.size());
    for (unsigned int i = 0; i < vMatched.size(); i++)
        BOOST_CHECK(vMatched[i] == merkleBlock.vMatchedTxn[i].second);

#if 0
    // Match an output from the second transaction (the pubkey for address 1DZTzaBHUDM7T3QvUKBz4qXMRpkg8jsfB5)
    // This should match the third transaction because it spends the output matched
    // It also matches the fourth transaction, which spends to the pubkey again
    filter.insert(ParseHex("044a656f065871a353f216ca26cef8dde2f03e8c16202d2e8ad769f02032cb86a5eb5e56842e92e19141d60a019"
                           "28f8dd2c875a390f67c1f6c94cfc617c0ea45af"));

    merkleBlock = CMerkleBlock(block, filter);
    BOOST_CHECK(merkleBlock.header.GetHash() == block.GetHash());

    BOOST_CHECK(merkleBlock.vMatchedTxn.size() == 4);

    BOOST_CHECK(pair == merkleBlock.vMatchedTxn[0]);

    BOOST_CHECK(merkleBlock.vMatchedTxn[1].second ==
                uint256S("0x28204cad1d7fc1d199e8ef4fa22f182de6258a3eaafe1bbe56ebdcacd3069a5f"));
    BOOST_CHECK(merkleBlock.vMatchedTxn[1].first == 1);

    BOOST_CHECK(merkleBlock.vMatchedTxn[2].second ==
                uint256S("0x6b0f8a73a56c04b519f1883e8aafda643ba61a30bd1439969df21bea5f4e27e2"));
    BOOST_CHECK(merkleBlock.vMatchedTxn[2].first == 2);

    BOOST_CHECK(merkleBlock.vMatchedTxn[3].second ==
                uint256S("0x3c1d7e82342158e4109df2e0b6348b6e84e403d8b4046d7007663ace63cddb23"));
    BOOST_CHECK(merkleBlock.vMatchedTxn[3].first == 3);

    BOOST_CHECK(merkleBlock.txn.ExtractMatches(vMatched, vIndex) == block.hashMerkleRoot);
    BOOST_CHECK(vMatched.size() == merkleBlock.vMatchedTxn.size());
    for (unsigned int i = 0; i < vMatched.size(); i++)
        BOOST_CHECK(vMatched[i] == merkleBlock.vMatchedTxn[i].second);
#endif
}
// TODO build nextchain blocks and replicate these tests
#if 0

BOOST_AUTO_TEST_CASE(merkle_block_2_reversed)
{
    // Like merkle_block_2 except this block gets its transactions reversed in
    // order to check non-topological processing.
    // Random real block
    // (000000005a4ded781e667e06ceefafb71410b511fe0d5adc3e5a27ecbec34ae6)
    // With 4 txes
    CBlock block;
    CDataStream stream(ParseHex("0100000075616236cc2126035fadb38deb65b9102cc2c41c09cdf29fc051906800"
                                "000000fe7d5e12ef0ff901f6050211249919b1c0653771832b3a80c66cea42847f"
                                "0ae1d4d26e49ffff001d00f0a44104010000000100000000000000000000000000"
                                "00000000000000000000000000000000000000ffffffff0804ffff001d029105ff"
                                "ffffff0100f2052a010000004341046d8709a041d34357697dfcb30a9d05900a62"
                                "94078012bf3bb09c6f9b525f1d16d5503d7905db1ada9501446ea00728668fc571"
                                "9aa80be2fdfc8a858a4dbdd4fbac00000000010000000255605dc6f5c3dc148b6d"
                                "a58442b0b2cd422be385eab2ebea4119ee9c268d28350000000049483045022100"
                                "aa46504baa86df8a33b1192b1b9367b4d729dc41e389f2c04f3e5c7f0559aae702"
                                "205e82253a54bf5c4f65b7428551554b2045167d6d206dfe6a2e198127d3f7df15"
                                "01ffffffff55605dc6f5c3dc148b6da58442b0b2cd422be385eab2ebea4119ee9c"
                                "268d2835010000004847304402202329484c35fa9d6bb32a55a70c0982f606ce0e"
                                "3634b69006138683bcd12cbb6602200c28feb1e2555c3210f1dddb299738b4ff8b"
                                "be9667b68cb8764b5ac17b7adf0001ffffffff0200e1f505000000004341046a07"
                                "65b5865641ce08dd39690aade26dfbf5511430ca428a3089261361cef170e3929a"
                                "68aee3d8d4848b0c5111b0a37b82b86ad559fd2a745b44d8e8d9dfdc0cac00180d"
                                "8f000000004341044a656f065871a353f216ca26cef8dde2f03e8c16202d2e8ad7"
                                "69f02032cb86a5eb5e56842e92e19141d60a01928f8dd2c875a390f67c1f6c94cf"
                                "c617c0ea45afac0000000001000000025f9a06d3acdceb56be1bfeaa3e8a25e62d"
                                "182fa24fefe899d1c17f1dad4c2028000000004847304402205d6058484157235b"
                                "06028c30736c15613a28bdb768ee628094ca8b0030d4d6eb0220328789c9a2ec27"
                                "ddaec0ad5ef58efded42e6ea17c2e1ce838f3d6913f5e95db601ffffffff5f9a06"
                                "d3acdceb56be1bfeaa3e8a25e62d182fa24fefe899d1c17f1dad4c202801000000"
                                "4a493046022100c45af050d3cea806cedd0ab22520c53ebe63b987b8954146cdca"
                                "42487b84bdd6022100b9b027716a6b59e640da50a864d6dd8a0ef24c76ce62391f"
                                "a3eabaf4d2886d2d01ffffffff0200e1f505000000004341046a0765b5865641ce"
                                "08dd39690aade26dfbf5511430ca428a3089261361cef170e3929a68aee3d8d484"
                                "8b0c5111b0a37b82b86ad559fd2a745b44d8e8d9dfdc0cac00180d8f0000000043"
                                "41046a0765b5865641ce08dd39690aade26dfbf5511430ca428a3089261361cef1"
                                "70e3929a68aee3d8d4848b0c5111b0a37b82b86ad559fd2a745b44d8e8d9dfdc0c"
                                "ac000000000100000002e2274e5fea1bf29d963914bd301aa63b64daaf8a3e88f1"
                                "19b5046ca5738a0f6b0000000048473044022016e7a727a061ea2254a6c358376a"
                                "aa617ac537eb836c77d646ebda4c748aac8b0220192ce28bf9f2c06a6467e6531e"
                                "27648d2b3e2e2bae85159c9242939840295ba501ffffffffe2274e5fea1bf29d96"
                                "3914bd301aa63b64daaf8a3e88f119b5046ca5738a0f6b010000004a4930460221"
                                "00b7a1a755588d4190118936e15cd217d133b0e4a53c3c15924010d5648d8925c9"
                                "022100aaef031874db2114f2d869ac2de4ae53908fbfea5b2b1862e181626bb900"
                                "5c9f01ffffffff0200e1f505000000004341044a656f065871a353f216ca26cef8"
                                "dde2f03e8c16202d2e8ad769f02032cb86a5eb5e56842e92e19141d60a01928f8d"
                                "d2c875a390f67c1f6c94cfc617c0ea45afac00180d8f000000004341046a0765b5"
                                "865641ce08dd39690aade26dfbf5511430ca428a3089261361cef170e3929a68ae"
                                "e3d8d4848b0c5111b0a37b82b86ad559fd2a745b44d8e8d9dfdc0cac00000000"),
        SER_NETWORK, PROTOCOL_VERSION);
    stream >> block;

    // Reverse the transactions and recalculate merkle root. The remainder of
    // this test is the same as merkle_block_2 above except the transaction
    // indices get reversed too.
    std::reverse(block.vtx.begin(), block.vtx.end());
    block.hashMerkleRoot = BlockMerkleRoot(block);

    CBloomFilter filter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    // Match the fourth (was first) transaction
    filter.insert(uint256S("0xe980fe9f792d014e73b95203dc1335c5f9ce19ac537a419e6df5b47aecb93b70"));

    CMerkleBlock merkleBlock(block, filter);
    BOOST_CHECK(merkleBlock.header.GetHash() == block.GetHash());

    BOOST_CHECK(merkleBlock.vMatchedTxn.size() == 1);
    std::pair<unsigned int, uint256> pair = merkleBlock.vMatchedTxn[0];

    BOOST_CHECK(merkleBlock.vMatchedTxn[0].second == uint256S("0xe980fe9f792d014e73b95203dc1335c5f9ce19ac537a419e6df"
                                                              "5b47aecb93b70"));
    BOOST_CHECK(merkleBlock.vMatchedTxn[0].first == 3);

    std::vector<uint256> vMatched;
    std::vector<unsigned int> vIndex;
    BOOST_CHECK(merkleBlock.txn.ExtractMatches(vMatched, vIndex) == block.hashMerkleRoot);
    BOOST_CHECK(vMatched.size() == merkleBlock.vMatchedTxn.size());
    for (size_t i = 0; i < vMatched.size(); i++)
    {
        BOOST_CHECK(vMatched[i] == merkleBlock.vMatchedTxn[i].second);
    }

    // Match an output from the third (was second) transaction (the pubkey for
    // address 1DZTzaBHUDM7T3QvUKBz4qXMRpkg8jsfB5) This should match the second
    // (was third) transaction because it spends the output matched
    // It also matches the first (was fourth) transaction, which spends to the
    // pubkey again
    filter.insert(ParseHex("044a656f065871a353f216ca26cef8dde2f03e8c16202d2e8ad"
                           "769f02032cb86a5eb5e56842e92e19141d60a01928f8dd2c875"
                           "a390f67c1f6c94cfc617c0ea45af"));

    merkleBlock = CMerkleBlock(block, filter);
    BOOST_CHECK(merkleBlock.header.GetHash() == block.GetHash());

    BOOST_CHECK(merkleBlock.vMatchedTxn.size() == 4);

    BOOST_CHECK(merkleBlock.vMatchedTxn[0].second == uint256S("0x3c1d7e82342158e4109df2e0b6348b6e84e403d8b4046d70076"
                                                              "63ace63cddb23"));
    BOOST_CHECK(merkleBlock.vMatchedTxn[0].first == 0);

    BOOST_CHECK(merkleBlock.vMatchedTxn[1].second == uint256S("0x6b0f8a73a56c04b519f1883e8aafda643ba61a30bd1439969df"
                                                              "21bea5f4e27e2"));
    BOOST_CHECK(merkleBlock.vMatchedTxn[1].first == 1);

    BOOST_CHECK(merkleBlock.vMatchedTxn[2].second == uint256S("0x28204cad1d7fc1d199e8ef4fa22f182de6258a3eaafe1bbe56e"
                                                              "bdcacd3069a5f"));
    BOOST_CHECK(merkleBlock.vMatchedTxn[2].first == 2);

    BOOST_CHECK(pair == merkleBlock.vMatchedTxn[3]);

    BOOST_CHECK(merkleBlock.txn.ExtractMatches(vMatched, vIndex) == block.hashMerkleRoot);
    BOOST_CHECK(vMatched.size() == merkleBlock.vMatchedTxn.size());
    for (size_t i = 0; i < vMatched.size(); i++)
    {
        BOOST_CHECK(vMatched[i] == merkleBlock.vMatchedTxn[i].second);
    }
}

BOOST_AUTO_TEST_CASE(merkle_block_2_with_update_none)
{

    // Random real block (000000005a4ded781e667e06ceefafb71410b511fe0d5adc3e5a27ecbec34ae6)
    // With 4 txes
    CBlock block;
    CDataStream stream(
        ParseHex("0100000075616236cc2126035fadb38deb65b9102cc2c41c09cdf29fc051906800000000fe7d5e12ef0ff901f605021124991"
                 "9b1c0653771832b3a80c66cea42847f0ae1d4d26e49ffff001d00f0a441040100000001000000000000000000000000000000"
                 "0000000000000000000000000000000000ffffffff0804ffff001d029105ffffffff0100f2052a010000004341046d8709a04"
                 "1d34357697dfcb30a9d05900a6294078012bf3bb09c6f9b525f1d16d5503d7905db1ada9501446ea00728668fc5719aa80be2"
                 "fdfc8a858a4dbdd4fbac00000000010000000255605dc6f5c3dc148b6da58442b0b2cd422be385eab2ebea4119ee9c268d283"
                 "50000000049483045022100aa46504baa86df8a33b1192b1b9367b4d729dc41e389f2c04f3e5c7f0559aae702205e82253a54"
                 "bf5c4f65b7428551554b2045167d6d206dfe6a2e198127d3f7df1501ffffffff55605dc6f5c3dc148b6da58442b0b2cd422be"
                 "385eab2ebea4119ee9c268d2835010000004847304402202329484c35fa9d6bb32a55a70c0982f606ce0e3634b69006138683"
                 "bcd12cbb6602200c28feb1e2555c3210f1dddb299738b4ff8bbe9667b68cb8764b5ac17b7adf0001ffffffff0200e1f505000"
                 "000004341046a0765b5865641ce08dd39690aade26dfbf5511430ca428a3089261361cef170e3929a68aee3d8d4848b0c5111"
                 "b0a37b82b86ad559fd2a745b44d8e8d9dfdc0cac00180d8f000000004341044a656f065871a353f216ca26cef8dde2f03e8c1"
                 "6202d2e8ad769f02032cb86a5eb5e56842e92e19141d60a01928f8dd2c875a390f67c1f6c94cfc617c0ea45afac0000000001"
                 "000000025f9a06d3acdceb56be1bfeaa3e8a25e62d182fa24fefe899d1c17f1dad4c2028000000004847304402205d6058484"
                 "157235b06028c30736c15613a28bdb768ee628094ca8b0030d4d6eb0220328789c9a2ec27ddaec0ad5ef58efded42e6ea17c2"
                 "e1ce838f3d6913f5e95db601ffffffff5f9a06d3acdceb56be1bfeaa3e8a25e62d182fa24fefe899d1c17f1dad4c202801000"
                 "0004a493046022100c45af050d3cea806cedd0ab22520c53ebe63b987b8954146cdca42487b84bdd6022100b9b027716a6b59"
                 "e640da50a864d6dd8a0ef24c76ce62391fa3eabaf4d2886d2d01ffffffff0200e1f505000000004341046a0765b5865641ce0"
                 "8dd39690aade26dfbf5511430ca428a3089261361cef170e3929a68aee3d8d4848b0c5111b0a37b82b86ad559fd2a745b44d8"
                 "e8d9dfdc0cac00180d8f000000004341046a0765b5865641ce08dd39690aade26dfbf5511430ca428a3089261361cef170e39"
                 "29a68aee3d8d4848b0c5111b0a37b82b86ad559fd2a745b44d8e8d9dfdc0cac000000000100000002e2274e5fea1bf29d9639"
                 "14bd301aa63b64daaf8a3e88f119b5046ca5738a0f6b0000000048473044022016e7a727a061ea2254a6c358376aaa617ac53"
                 "7eb836c77d646ebda4c748aac8b0220192ce28bf9f2c06a6467e6531e27648d2b3e2e2bae85159c9242939840295ba501ffff"
                 "ffffe2274e5fea1bf29d963914bd301aa63b64daaf8a3e88f119b5046ca5738a0f6b010000004a493046022100b7a1a755588"
                 "d4190118936e15cd217d133b0e4a53c3c15924010d5648d8925c9022100aaef031874db2114f2d869ac2de4ae53908fbfea5b"
                 "2b1862e181626bb9005c9f01ffffffff0200e1f505000000004341044a656f065871a353f216ca26cef8dde2f03e8c16202d2"
                 "e8ad769f02032cb86a5eb5e56842e92e19141d60a01928f8dd2c875a390f67c1f6c94cfc617c0ea45afac00180d8f00000000"
                 "4341046a0765b5865641ce08dd39690aade26dfbf5511430ca428a3089261361cef170e3929a68aee3d8d4848b0c5111b0a37"
                 "b82b86ad559fd2a745b44d8e8d9dfdc0cac00000000"),
        SER_NETWORK, PROTOCOL_VERSION);
    stream >> block;

    CBloomFilter filter(10, 0.000001, 0, BLOOM_UPDATE_NONE);
    // Match the first transaction
    filter.insert(uint256S("0xe980fe9f792d014e73b95203dc1335c5f9ce19ac537a419e6df5b47aecb93b70"));

    CMerkleBlock merkleBlock(block, filter);
    BOOST_CHECK(merkleBlock.header.GetHash() == block.GetHash());

    BOOST_CHECK(merkleBlock.vMatchedTxn.size() == 1);
    pair<unsigned int, uint256> pair = merkleBlock.vMatchedTxn[0];

    BOOST_CHECK(merkleBlock.vMatchedTxn[0].second ==
                uint256S("0xe980fe9f792d014e73b95203dc1335c5f9ce19ac537a419e6df5b47aecb93b70"));
    BOOST_CHECK(merkleBlock.vMatchedTxn[0].first == 0);

    vector<uint256> vMatched;
    vector<unsigned int> vIndex;
    BOOST_CHECK(merkleBlock.txn.ExtractMatches(vMatched, vIndex) == block.hashMerkleRoot);
    BOOST_CHECK(vMatched.size() == merkleBlock.vMatchedTxn.size());
    for (unsigned int i = 0; i < vMatched.size(); i++)
        BOOST_CHECK(vMatched[i] == merkleBlock.vMatchedTxn[i].second);

    // Match an output from the second transaction (the pubkey for address 1DZTzaBHUDM7T3QvUKBz4qXMRpkg8jsfB5)
    // This should not match the third transaction though it spends the output matched
    // It will match the fourth transaction, which has another pay-to-pubkey output to the same address
    filter.insert(ParseHex("044a656f065871a353f216ca26cef8dde2f03e8c16202d2e8ad769f02032cb86a5eb5e56842e92e19141d60a019"
                           "28f8dd2c875a390f67c1f6c94cfc617c0ea45af"));

    merkleBlock = CMerkleBlock(block, filter);
    BOOST_CHECK(merkleBlock.header.GetHash() == block.GetHash());

    BOOST_CHECK(merkleBlock.vMatchedTxn.size() == 3);

    BOOST_CHECK(pair == merkleBlock.vMatchedTxn[0]);

    BOOST_CHECK(merkleBlock.vMatchedTxn[1].second ==
                uint256S("0x28204cad1d7fc1d199e8ef4fa22f182de6258a3eaafe1bbe56ebdcacd3069a5f"));
    BOOST_CHECK(merkleBlock.vMatchedTxn[1].first == 1);

    BOOST_CHECK(merkleBlock.vMatchedTxn[2].second ==
                uint256S("0x3c1d7e82342158e4109df2e0b6348b6e84e403d8b4046d7007663ace63cddb23"));
    BOOST_CHECK(merkleBlock.vMatchedTxn[2].first == 3);

    BOOST_CHECK(merkleBlock.txn.ExtractMatches(vMatched, vIndex) == block.hashMerkleRoot);
    BOOST_CHECK(vMatched.size() == merkleBlock.vMatchedTxn.size());
    for (unsigned int i = 0; i < vMatched.size(); i++)
        BOOST_CHECK(vMatched[i] == merkleBlock.vMatchedTxn[i].second);
}

BOOST_AUTO_TEST_CASE(merkle_block_3_and_serialize)
{
    // Random real block (000000000000dab0130bbcc991d3d7ae6b81aa6f50a798888dfe62337458dc45)
    // With one tx
    CBlock block;
    CDataStream stream(
        ParseHex("0100000079cda856b143d9db2c1caff01d1aecc8630d30625d10e8b4b8b0000000000000b50cc069d6a3e33e3ff84a5c41d9d"
                 "3febe7c770fdcc96b2c3ff60abe184f196367291b4d4c86041b8fa45d63010100000001000000000000000000000000000000"
                 "0000000000000000000000000000000000ffffffff08044c86041b020a02ffffffff0100f2052a01000000434104ecd3229b0"
                 "571c3be876feaac0442a9f13c5a572742927af1dc623353ecf8c202225f64868137a18cdd85cbbb4c74fbccfd4f49639cf1bd"
                 "c94a5672bb15ad5d4cac00000000"),
        SER_NETWORK, PROTOCOL_VERSION);
    stream >> block;

    CBloomFilter filter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    // Match the only transaction
    filter.insert(uint256S("0x63194f18be0af63f2c6bc9dc0f777cbefed3d9415c4af83f3ee3a3d669c00cb5"));

    CMerkleBlock merkleBlock(block, filter);
    BOOST_CHECK(merkleBlock.header.GetHash() == block.GetHash());

    BOOST_CHECK(merkleBlock.vMatchedTxn.size() == 1);

    BOOST_CHECK(merkleBlock.vMatchedTxn[0].second ==
                uint256S("0x63194f18be0af63f2c6bc9dc0f777cbefed3d9415c4af83f3ee3a3d669c00cb5"));
    BOOST_CHECK(merkleBlock.vMatchedTxn[0].first == 0);

    vector<uint256> vMatched;
    vector<unsigned int> vIndex;
    BOOST_CHECK(merkleBlock.txn.ExtractMatches(vMatched, vIndex) == block.hashMerkleRoot);
    BOOST_CHECK(vMatched.size() == merkleBlock.vMatchedTxn.size());
    for (unsigned int i = 0; i < vMatched.size(); i++)
        BOOST_CHECK(vMatched[i] == merkleBlock.vMatchedTxn[i].second);

    CDataStream merkleStream(SER_NETWORK, PROTOCOL_VERSION);
    merkleStream << merkleBlock;

    vector<unsigned char> vch =
        ParseHex("0100000079cda856b143d9db2c1caff01d1aecc8630d30625d10e8b4b8b0000000000000b50cc069d6a3e33e3ff84a5c41d9d"
                 "3febe7c770fdcc96b2c3ff60abe184f196367291b4d4c86041b8fa45d630100000001b50cc069d6a3e33e3ff84a5c41d9d3fe"
                 "be7c770fdcc96b2c3ff60abe184f19630101");
    vector<char> expected(vch.size());

    for (unsigned int i = 0; i < vch.size(); i++)
        expected[i] = (char)vch[i];

    BOOST_CHECK_EQUAL_COLLECTIONS(expected.begin(), expected.end(), merkleStream.begin(), merkleStream.end());
}
#endif
BOOST_AUTO_TEST_CASE(merkle_block_4)
{
    // Random real block (a246f6fdd8bc24d763cbfc0d8bb7acd347e17f2c87929a295f9720a6bcc333e1)
    // With 7 txes
    CBlock block = TestBlock3();

    CBloomFilter filter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    // Match the last transaction
    filter.insert(uint256S("0xf916360dd3f1831f47ed3623a07c41daec8aabdcecf7fb735c66de837b1e5523"));

    CMerkleBlock merkleBlock(block, filter);
    BOOST_CHECK(merkleBlock.header.GetHash() == block.GetHash());

    BOOST_CHECK(merkleBlock.vMatchedTxn.size() == 1);
    pair<unsigned int, uint256> pair = merkleBlock.vMatchedTxn[0];

    BOOST_CHECK(merkleBlock.vMatchedTxn[0].second ==
                uint256S("0xf916360dd3f1831f47ed3623a07c41daec8aabdcecf7fb735c66de837b1e5523"));
    BOOST_CHECK(merkleBlock.vMatchedTxn[0].first == 6);

    vector<uint256> vMatched;
    vector<unsigned int> vIndex;
    BOOST_CHECK(merkleBlock.txn.ExtractMatches(vMatched, vIndex) == block.hashMerkleRoot);
    BOOST_CHECK(vMatched.size() == merkleBlock.vMatchedTxn.size());
    for (unsigned int i = 0; i < vMatched.size(); i++)
        BOOST_CHECK(vMatched[i] == merkleBlock.vMatchedTxn[i].second);

    // Also match the 4th transaction
    filter.insert(uint256S("0x95b9684bacfe190f3735330cf589f01ba29afbef045a005ffe3b6328843ab02b"));
    merkleBlock = CMerkleBlock(block, filter);
    BOOST_CHECK(merkleBlock.header.GetHash() == block.GetHash());

    BOOST_CHECK(merkleBlock.vMatchedTxn.size() == 2);

    BOOST_CHECK(merkleBlock.vMatchedTxn[0].second ==
                uint256S("0x95b9684bacfe190f3735330cf589f01ba29afbef045a005ffe3b6328843ab02b"));
    BOOST_CHECK(merkleBlock.vMatchedTxn[0].first == 3);

    BOOST_CHECK(merkleBlock.vMatchedTxn[1] == pair);

    BOOST_CHECK(merkleBlock.txn.ExtractMatches(vMatched, vIndex) == block.hashMerkleRoot);
    BOOST_CHECK(vMatched.size() == merkleBlock.vMatchedTxn.size());
    for (unsigned int i = 0; i < vMatched.size(); i++)
        BOOST_CHECK(vMatched[i] == merkleBlock.vMatchedTxn[i].second);
}
#if 0

BOOST_AUTO_TEST_CASE(merkle_block_4_test_p2pubkey_only)
{
    // Random real block (000000000000b731f2eef9e8c63173adfb07e41bd53eb0ef0a6b720d6cb6dea4)
    // With 7 txes
    CBlock block;
    CDataStream stream(
        ParseHex(
            "0100000082bb869cf3a793432a66e826e05a6fc37469f8efb7421dc880670100000000007f16c5962e8bd963659c793ce370d95f09"
            "3bc7e367117b3c30c1f8fdd0d9728776381b4d4c86041b554b85290701000000010000000000000000000000000000000000000000"
            "000000000000000000000000ffffffff07044c86041b0136ffffffff0100f2052a01000000434104eaafc2314def4ca98ac970241b"
            "cab022b9c1e1f4ea423a20f134c876f2c01ec0f0dd5b2e86e7168cefe0d81113c3807420ce13ad1357231a2252247d97a46a91ac00"
            "0000000100000001bcad20a6a29827d1424f08989255120bf7f3e9e3cdaaa6bb31b0737fe048724300000000494830450220356e83"
            "4b046cadc0f8ebb5a8a017b02de59c86305403dad52cd77b55af062ea10221009253cd6c119d4729b77c978e1e2aa19f5ea6e0e52b"
            "3f16e32fa608cd5bab753901ffffffff02008d380c010000001976a9142b4b8072ecbba129b6453c63e129e643207249ca88ac0065"
            "cd1d000000001976a9141b8dd13b994bcfc787b32aeadf58ccb3615cbd5488ac000000000100000003fdacf9b3eb077412e7a968d2"
            "e4f11b9a9dee312d666187ed77ee7d26af16cb0b000000008c493046022100ea1608e70911ca0de5af51ba57ad23b9a51db8d28f82"
            "c53563c56a05c20f5a87022100a8bdc8b4a8acc8634c6b420410150775eb7f2474f5615f7fccd65af30f310fbf01410465fdf49e29"
            "b06b9a1582287b6279014f834edc317695d125ef623c1cc3aaece245bd69fcad7508666e9c74a49dc9056d5fc14338ef38118dc4af"
            "ae5fe2c585caffffffff309e1913634ecb50f3c4f83e96e70b2df071b497b8973a3e75429df397b5af83000000004948304502202b"
            "db79c596a9ffc24e96f4386199aba386e9bc7b6071516e2b51dda942b3a1ed022100c53a857e76b724fc14d45311eac5019650d415"
            "c3abb5428f3aae16d8e69bec2301ffffffff2089e33491695080c9edc18a428f7d834db5b6d372df13ce2b1b0e0cbcb1e6c1000000"
            "0049483045022100d4ce67c5896ee251c810ac1ff9ceccd328b497c8f553ab6e08431e7d40bad6b5022033119c0c2b7d792d31f118"
            "7779c7bd95aefd93d90a715586d73801d9b47471c601ffffffff0100714460030000001976a914c7b55141d097ea5df7a0ed330cf7"
            "94376e53ec8d88ac0000000001000000045bf0e214aa4069a3e792ecee1e1bf0c1d397cde8dd08138f4b72a0068174344700000000"
            "8b48304502200c45de8c4f3e2c1821f2fc878cba97b1e6f8807d94930713aa1c86a67b9bf1e40221008581abfef2e30f957815fc89"
            "978423746b2086375ca8ecf359c85c2a5b7c88ad01410462bb73f76ca0994fcb8b4271e6fb7561f5c0f9ca0cf6485261c4a0dc894f"
            "4ab844c6cdfb97cd0b60ffb5018ffd6238f4d87270efb1d3ae37079b794a92d7ec95ffffffffd669f7d7958d40fc59d2253d88e0f2"
            "48e29b599c80bbcec344a83dda5f9aa72c000000008a473044022078124c8beeaa825f9e0b30bff96e564dd859432f2d0cb3b72d3d"
            "5d93d38d7e930220691d233b6c0f995be5acb03d70a7f7a65b6bc9bdd426260f38a1346669507a3601410462bb73f76ca0994fcb8b"
            "4271e6fb7561f5c0f9ca0cf6485261c4a0dc894f4ab844c6cdfb97cd0b60ffb5018ffd6238f4d87270efb1d3ae37079b794a92d7ec"
            "95fffffffff878af0d93f5229a68166cf051fd372bb7a537232946e0a46f53636b4dafdaa4000000008c493046022100c717d17145"
            "51663f69c3c5759bdbb3a0fcd3fab023abc0e522fe6440de35d8290221008d9cbe25bffc44af2b18e81c58eb37293fd7fe1c2e7b46"
            "fc37ee8c96c50ab1e201410462bb73f76ca0994fcb8b4271e6fb7561f5c0f9ca0cf6485261c4a0dc894f4ab844c6cdfb97cd0b60ff"
            "b5018ffd6238f4d87270efb1d3ae37079b794a92d7ec95ffffffff27f2b668859cd7f2f894aa0fd2d9e60963bcd07c88973f425f99"
            "9b8cbfd7a1e2000000008c493046022100e00847147cbf517bcc2f502f3ddc6d284358d102ed20d47a8aa788a62f0db780022100d1"
            "7b2d6fa84dcaf1c95d88d7e7c30385aecf415588d749afd3ec81f6022cecd701410462bb73f76ca0994fcb8b4271e6fb7561f5c0f9"
            "ca0cf6485261c4a0dc894f4ab844c6cdfb97cd0b60ffb5018ffd6238f4d87270efb1d3ae37079b794a92d7ec95ffffffff0100c817"
            "a8040000001976a914b6efd80d99179f4f4ff6f4dd0a007d018c385d2188ac000000000100000001834537b2f1ce8ef9373a258e10"
            "545ce5a50b758df616cd4356e0032554ebd3c4000000008b483045022100e68f422dd7c34fdce11eeb4509ddae38201773dd62f284"
            "e8aa9d96f85099d0b002202243bd399ff96b649a0fad05fa759d6a882f0af8c90cf7632c2840c29070aec20141045e58067e815c2f"
            "464c6a2a15f987758374203895710c2d452442e28496ff38ba8f5fd901dc20e29e88477167fe4fc299bf818fd0d9e1632d467b2a3d"
            "9503b1aaffffffff0280d7e636030000001976a914f34c3e10eb387efe872acb614c89e78bfca7815d88ac404b4c00000000001976"
            "a914a84e272933aaf87e1715d7786c51dfaeb5b65a6f88ac00000000010000000143ac81c8e6f6ef307dfe17f3d906d999e23e0189"
            "fda838c5510d850927e03ae7000000008c4930460221009c87c344760a64cb8ae6685a3eec2c1ac1bed5b88c87de51acd0e124f266"
            "c16602210082d07c037359c3a257b5c63ebd90f5a5edf97b2ac1c434b08ca998839f346dd40141040ba7e521fa7946d12edbb1d1e9"
            "5a15c34bd4398195e86433c92b431cd315f455fe30032ede69cad9d1e1ed6c3c4ec0dbfced53438c625462afb792dcb098544bffff"
            "ffff0240420f00000000001976a9144676d1b820d63ec272f1900d59d43bc6463d96f888ac40420f00000000001976a914648d0434"
            "1d00d7968b3405c034adc38d4d8fb9bd88ac00000000010000000248cc917501ea5c55f4a8d2009c0567c40cfe037c2e71af017d0a"
            "452ff705e3f1000000008b483045022100bf5fdc86dc5f08a5d5c8e43a8c9d5b1ed8c65562e280007b52b133021acd9acc02205e32"
            "5d613e555f772802bf413d36ba807892ed1a690a77811d3033b3de226e0a01410429fa713b124484cb2bd7b5557b2c0b9df7b2b1fe"
            "e61825eadc5ae6c37a9920d38bfccdc7dc3cb0c47d7b173dbc9db8d37db0a33ae487982c59c6f8606e9d1791ffffffff41ed70551d"
            "d7e841883ab8f0b16bf04176b7d1480e4f0af9f3d4c3595768d068000000008b4830450221008513ad65187b903aed1102d1d0c476"
            "88127658c51106753fed0151ce9c16b80902201432b9ebcb87bd04ceb2de66035fbbaf4bf8b00d1cfe41f1a1f7338f9ad79d210141"
            "049d4cf80125bf50be1709f718c07ad15d0fc612b7da1f5570dddc35f2a352f0f27c978b06820edca9ef982c35fda2d255afba3400"
            "68c5035552368bc7200c1488ffffffff0100093d00000000001976a9148edb68822f1ad580b043c7b3df2e400f8699eb4888ac0000"
            "0000"),
        SER_NETWORK, PROTOCOL_VERSION);
    stream >> block;

    CBloomFilter filter(10, 0.000001, 0, BLOOM_UPDATE_P2PUBKEY_ONLY);
    // Match the generation pubkey
    filter.insert(ParseHex("04eaafc2314def4ca98ac970241bcab022b9c1e1f4ea423a20f134c876f2c01ec0f0dd5b2e86e7168cefe0d8111"
                           "3c3807420ce13ad1357231a2252247d97a46a91"));
    // ...and the output address of the 4th transaction
    filter.insert(ParseHex("b6efd80d99179f4f4ff6f4dd0a007d018c385d21"));

    CMerkleBlock merkleBlock(block, filter);
    BOOST_CHECK(merkleBlock.header.GetHash() == block.GetHash());

    // We should match the generation outpoint
    BOOST_CHECK(
        filter.contains(COutPoint(uint256S("0x147caa76786596590baa4e98f5d9f48b86c7765e489f7a6ff3360fe5c674360b"), 0)));
    // ... but not the 4th transaction's output (its not pay-2-pubkey)
    BOOST_CHECK(
        !filter.contains(COutPoint(uint256S("0x02981fa052f0481dbc5868f4fc2166035a10f27a03cfd2de67326471df5bc041"), 0)));
}

BOOST_AUTO_TEST_CASE(merkle_block_4_test_update_none)
{
    // Random real block (000000000000b731f2eef9e8c63173adfb07e41bd53eb0ef0a6b720d6cb6dea4)
    // With 7 txes
    CBlock block;
    CDataStream stream(
        ParseHex(
            "0100000082bb869cf3a793432a66e826e05a6fc37469f8efb7421dc880670100000000007f16c5962e8bd963659c793ce370d95f09"
            "3bc7e367117b3c30c1f8fdd0d9728776381b4d4c86041b554b85290701000000010000000000000000000000000000000000000000"
            "000000000000000000000000ffffffff07044c86041b0136ffffffff0100f2052a01000000434104eaafc2314def4ca98ac970241b"
            "cab022b9c1e1f4ea423a20f134c876f2c01ec0f0dd5b2e86e7168cefe0d81113c3807420ce13ad1357231a2252247d97a46a91ac00"
            "0000000100000001bcad20a6a29827d1424f08989255120bf7f3e9e3cdaaa6bb31b0737fe048724300000000494830450220356e83"
            "4b046cadc0f8ebb5a8a017b02de59c86305403dad52cd77b55af062ea10221009253cd6c119d4729b77c978e1e2aa19f5ea6e0e52b"
            "3f16e32fa608cd5bab753901ffffffff02008d380c010000001976a9142b4b8072ecbba129b6453c63e129e643207249ca88ac0065"
            "cd1d000000001976a9141b8dd13b994bcfc787b32aeadf58ccb3615cbd5488ac000000000100000003fdacf9b3eb077412e7a968d2"
            "e4f11b9a9dee312d666187ed77ee7d26af16cb0b000000008c493046022100ea1608e70911ca0de5af51ba57ad23b9a51db8d28f82"
            "c53563c56a05c20f5a87022100a8bdc8b4a8acc8634c6b420410150775eb7f2474f5615f7fccd65af30f310fbf01410465fdf49e29"
            "b06b9a1582287b6279014f834edc317695d125ef623c1cc3aaece245bd69fcad7508666e9c74a49dc9056d5fc14338ef38118dc4af"
            "ae5fe2c585caffffffff309e1913634ecb50f3c4f83e96e70b2df071b497b8973a3e75429df397b5af83000000004948304502202b"
            "db79c596a9ffc24e96f4386199aba386e9bc7b6071516e2b51dda942b3a1ed022100c53a857e76b724fc14d45311eac5019650d415"
            "c3abb5428f3aae16d8e69bec2301ffffffff2089e33491695080c9edc18a428f7d834db5b6d372df13ce2b1b0e0cbcb1e6c1000000"
            "0049483045022100d4ce67c5896ee251c810ac1ff9ceccd328b497c8f553ab6e08431e7d40bad6b5022033119c0c2b7d792d31f118"
            "7779c7bd95aefd93d90a715586d73801d9b47471c601ffffffff0100714460030000001976a914c7b55141d097ea5df7a0ed330cf7"
            "94376e53ec8d88ac0000000001000000045bf0e214aa4069a3e792ecee1e1bf0c1d397cde8dd08138f4b72a0068174344700000000"
            "8b48304502200c45de8c4f3e2c1821f2fc878cba97b1e6f8807d94930713aa1c86a67b9bf1e40221008581abfef2e30f957815fc89"
            "978423746b2086375ca8ecf359c85c2a5b7c88ad01410462bb73f76ca0994fcb8b4271e6fb7561f5c0f9ca0cf6485261c4a0dc894f"
            "4ab844c6cdfb97cd0b60ffb5018ffd6238f4d87270efb1d3ae37079b794a92d7ec95ffffffffd669f7d7958d40fc59d2253d88e0f2"
            "48e29b599c80bbcec344a83dda5f9aa72c000000008a473044022078124c8beeaa825f9e0b30bff96e564dd859432f2d0cb3b72d3d"
            "5d93d38d7e930220691d233b6c0f995be5acb03d70a7f7a65b6bc9bdd426260f38a1346669507a3601410462bb73f76ca0994fcb8b"
            "4271e6fb7561f5c0f9ca0cf6485261c4a0dc894f4ab844c6cdfb97cd0b60ffb5018ffd6238f4d87270efb1d3ae37079b794a92d7ec"
            "95fffffffff878af0d93f5229a68166cf051fd372bb7a537232946e0a46f53636b4dafdaa4000000008c493046022100c717d17145"
            "51663f69c3c5759bdbb3a0fcd3fab023abc0e522fe6440de35d8290221008d9cbe25bffc44af2b18e81c58eb37293fd7fe1c2e7b46"
            "fc37ee8c96c50ab1e201410462bb73f76ca0994fcb8b4271e6fb7561f5c0f9ca0cf6485261c4a0dc894f4ab844c6cdfb97cd0b60ff"
            "b5018ffd6238f4d87270efb1d3ae37079b794a92d7ec95ffffffff27f2b668859cd7f2f894aa0fd2d9e60963bcd07c88973f425f99"
            "9b8cbfd7a1e2000000008c493046022100e00847147cbf517bcc2f502f3ddc6d284358d102ed20d47a8aa788a62f0db780022100d1"
            "7b2d6fa84dcaf1c95d88d7e7c30385aecf415588d749afd3ec81f6022cecd701410462bb73f76ca0994fcb8b4271e6fb7561f5c0f9"
            "ca0cf6485261c4a0dc894f4ab844c6cdfb97cd0b60ffb5018ffd6238f4d87270efb1d3ae37079b794a92d7ec95ffffffff0100c817"
            "a8040000001976a914b6efd80d99179f4f4ff6f4dd0a007d018c385d2188ac000000000100000001834537b2f1ce8ef9373a258e10"
            "545ce5a50b758df616cd4356e0032554ebd3c4000000008b483045022100e68f422dd7c34fdce11eeb4509ddae38201773dd62f284"
            "e8aa9d96f85099d0b002202243bd399ff96b649a0fad05fa759d6a882f0af8c90cf7632c2840c29070aec20141045e58067e815c2f"
            "464c6a2a15f987758374203895710c2d452442e28496ff38ba8f5fd901dc20e29e88477167fe4fc299bf818fd0d9e1632d467b2a3d"
            "9503b1aaffffffff0280d7e636030000001976a914f34c3e10eb387efe872acb614c89e78bfca7815d88ac404b4c00000000001976"
            "a914a84e272933aaf87e1715d7786c51dfaeb5b65a6f88ac00000000010000000143ac81c8e6f6ef307dfe17f3d906d999e23e0189"
            "fda838c5510d850927e03ae7000000008c4930460221009c87c344760a64cb8ae6685a3eec2c1ac1bed5b88c87de51acd0e124f266"
            "c16602210082d07c037359c3a257b5c63ebd90f5a5edf97b2ac1c434b08ca998839f346dd40141040ba7e521fa7946d12edbb1d1e9"
            "5a15c34bd4398195e86433c92b431cd315f455fe30032ede69cad9d1e1ed6c3c4ec0dbfced53438c625462afb792dcb098544bffff"
            "ffff0240420f00000000001976a9144676d1b820d63ec272f1900d59d43bc6463d96f888ac40420f00000000001976a914648d0434"
            "1d00d7968b3405c034adc38d4d8fb9bd88ac00000000010000000248cc917501ea5c55f4a8d2009c0567c40cfe037c2e71af017d0a"
            "452ff705e3f1000000008b483045022100bf5fdc86dc5f08a5d5c8e43a8c9d5b1ed8c65562e280007b52b133021acd9acc02205e32"
            "5d613e555f772802bf413d36ba807892ed1a690a77811d3033b3de226e0a01410429fa713b124484cb2bd7b5557b2c0b9df7b2b1fe"
            "e61825eadc5ae6c37a9920d38bfccdc7dc3cb0c47d7b173dbc9db8d37db0a33ae487982c59c6f8606e9d1791ffffffff41ed70551d"
            "d7e841883ab8f0b16bf04176b7d1480e4f0af9f3d4c3595768d068000000008b4830450221008513ad65187b903aed1102d1d0c476"
            "88127658c51106753fed0151ce9c16b80902201432b9ebcb87bd04ceb2de66035fbbaf4bf8b00d1cfe41f1a1f7338f9ad79d210141"
            "049d4cf80125bf50be1709f718c07ad15d0fc612b7da1f5570dddc35f2a352f0f27c978b06820edca9ef982c35fda2d255afba3400"
            "68c5035552368bc7200c1488ffffffff0100093d00000000001976a9148edb68822f1ad580b043c7b3df2e400f8699eb4888ac0000"
            "0000"),
        SER_NETWORK, PROTOCOL_VERSION);
    stream >> block;

    CBloomFilter filter(10, 0.000001, 0, BLOOM_UPDATE_NONE);
    // Match the generation pubkey
    filter.insert(ParseHex("04eaafc2314def4ca98ac970241bcab022b9c1e1f4ea423a20f134c876f2c01ec0f0dd5b2e86e7168cefe0d8111"
                           "3c3807420ce13ad1357231a2252247d97a46a91"));
    // ...and the output address of the 4th transaction
    filter.insert(ParseHex("b6efd80d99179f4f4ff6f4dd0a007d018c385d21"));

    CMerkleBlock merkleBlock(block, filter);
    BOOST_CHECK(merkleBlock.header.GetHash() == block.GetHash());

    // We shouldn't match any outpoints (UPDATE_NONE)
    BOOST_CHECK(
        !filter.contains(COutPoint(uint256S("0x147caa76786596590baa4e98f5d9f48b86c7765e489f7a6ff3360fe5c674360b"), 0)));
    BOOST_CHECK(
        !filter.contains(COutPoint(uint256S("0x02981fa052f0481dbc5868f4fc2166035a10f27a03cfd2de67326471df5bc041"), 0)));
}
#endif

static std::vector<unsigned char> RandomData()
{
    uint256 r = InsecureRand256();
    return std::vector<unsigned char>(r.begin(), r.end());
}

BOOST_AUTO_TEST_CASE(rolling_bloom)
{
    // last-100-entry, 1% false positive:
    CRollingBloomFilter rb1(100, 0.01);

    // Overfill:
    static const int DATASIZE = 399;
    std::vector<unsigned char> data[DATASIZE];
    for (int i = 0; i < DATASIZE; i++)
    {
        data[i] = RandomData();
        rb1.insert(data[i]);
    }
    // Last 100 guaranteed to be remembered:
    for (int i = 299; i < DATASIZE; i++)
    {
        BOOST_CHECK(rb1.contains(data[i]));
    }

    // false positive rate is 1%, so we should get about 100 hits if
    // testing 10,000 random keys. We get worst-case false positive
    // behavior when the filter is as full as possible, which is
    // when we've inserted one minus an integer multiple of nElement*2.
    unsigned int nHits = 0;
    for (int i = 0; i < 10000; i++)
    {
        if (rb1.contains(RandomData()))
            ++nHits;
    }
    // Run test_nexa with --log_level=message to see BOOST_TEST_MESSAGEs:
    BOOST_TEST_MESSAGE("RollingBloomFilter got " << nHits << " false positives (~100 expected)");

    // Insanely unlikely to get a fp count outside this range:
    BOOST_CHECK(nHits > 25);
    BOOST_CHECK(nHits < 175);

    BOOST_CHECK(rb1.contains(data[DATASIZE - 1]));
    rb1.reset();
    BOOST_CHECK(!rb1.contains(data[DATASIZE - 1]));

    // Now roll through data, make sure last 100 entries
    // are always remembered:
    for (int i = 0; i < DATASIZE; i++)
    {
        if (i >= 100)
            BOOST_CHECK(rb1.contains(data[i - 100]));
        rb1.insert(data[i]);
        BOOST_CHECK(rb1.contains(data[i]));
    }

    // Insert 999 more random entries:
    for (int i = 0; i < 999; i++)
    {
        std::vector<unsigned char> d = RandomData();
        rb1.insert(d);
        BOOST_CHECK(rb1.contains(d));
    }
    // Sanity check to make sure the filter isn't just filling up:
    nHits = 0;
    for (int i = 0; i < DATASIZE; i++)
    {
        if (rb1.contains(data[i]))
            ++nHits;
    }
    // Expect about 5 false positives, more than 100 means
    // something is definitely broken.
    BOOST_TEST_MESSAGE("RollingBloomFilter got " << nHits << " false positives (~5 expected)");
    BOOST_CHECK(nHits < 100);

    // last-1000-entry, 0.01% false positive:
    CRollingBloomFilter rb2(1000, 0.001);
    for (int i = 0; i < DATASIZE; i++)
    {
        rb2.insert(data[i]);
    }
    // ... room for all of them:
    for (int i = 0; i < DATASIZE; i++)
    {
        BOOST_CHECK(rb2.contains(data[i]));
    }
}

BOOST_AUTO_TEST_CASE(bloom_full_and_size_tests)
{
    {
        // FP rate of 1.0 will create an empty, zero-element bloom filter
        CBloomFilter filter(1, 1.0, 0, BLOOM_UPDATE_ALL);
        BOOST_CHECK(filter.IsFull());
        filter.insert(ParseHex("00"));
    }

    {
        // a filter with good parameters should be non-full upon construction
        CBloomFilter filter(8, 0.01, 0, BLOOM_UPDATE_ALL);
        BOOST_CHECK(!filter.IsFull());
    }

    {
        // constructing bloom filters without any empty elements should work
        // and yield non-full filters as nElements will be set to 1
        CBloomFilter filter(0, 0.01, 0, BLOOM_UPDATE_ALL);
        BOOST_CHECK(!filter.IsFull());
    }

    {
        // default empty filter is full
        CBloomFilter filter;
        BOOST_CHECK(filter.IsFull());
    }

    {
        // deserialization of empty filter should indicate it is full
        // (test for implicit UpdateEmptyFull)
        CBloomFilter filter;
        CDataStream stream(ParseHex("00000000000000000000"), SER_NETWORK, PROTOCOL_VERSION);
        stream >> filter;
        BOOST_CHECK(filter.IsFull());
        BOOST_CHECK(filter.IsWithinSizeConstraints());
    }

    {
        // deserialization of one-element empty filter should be non-full
        // (test for implicit UpdateEmptyFull)
        CBloomFilter filter;
        CDataStream stream(ParseHex("0100000000000000000000"), SER_NETWORK, PROTOCOL_VERSION);
        stream >> filter;
        BOOST_CHECK(!filter.IsFull());
        BOOST_CHECK(filter.IsWithinSizeConstraints());
    }

    {
        // deserialization of one-element full filter should indicate fullness
        // (test for implicit UpdateEmptyFull)
        CBloomFilter filter;
        CDataStream stream(ParseHex("01ff000000000000000000"), SER_NETWORK, PROTOCOL_VERSION);
        stream >> filter;
        BOOST_CHECK(filter.IsFull());
        BOOST_CHECK(filter.IsWithinSizeConstraints());
    }
    {
        // deserialization of large empty filter
        // (test for implicit UpdateEmptyFull, size constraint check)
        CBloomFilter filter;
        CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);

        vector<unsigned char> vch(1U << 20); // too large filter
        stream << vch;
        stream << 0U; // nHashFuncs
        stream << 0U; // nTweak
        stream << (unsigned char)0; // nFlags

        stream >> filter;
        BOOST_CHECK(!filter.IsFull());
        BOOST_CHECK(!filter.IsWithinSizeConstraints());
    }

    {
        // deserialization of large full filter
        // (test for implicit UpdateEmptyFull, size constraint check)
        CBloomFilter filter;
        CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);

        vector<unsigned char> vch(1U << 20, 0xff); // too large filter
        stream << vch;
        stream << 0U; // nHashFuncs
        stream << 0U; // nTweak
        stream << (unsigned char)0; // nFlags


        stream >> filter;
        BOOST_CHECK(filter.IsFull());
        BOOST_CHECK(!filter.IsWithinSizeConstraints());
    }

    {
        // deserialization of empty filter with too many hash functions
        // (to check size constraint check)
        CBloomFilter filter;
        CDataStream stream(ParseHex("0000ffffff0000000000"), SER_NETWORK, PROTOCOL_VERSION);
        stream >> filter;
        BOOST_CHECK(!filter.IsWithinSizeConstraints());
    }

    {
        // a rolling bloom filter can be constructed with much larger size than a regular one
        CRollingBloomFilter rollbloom(120000, 0.000001);
        // printf("Roll Bloom filter size: %u\n", rollbloom.vDataSize());
        BOOST_CHECK(rollbloom.vDataSize() > 150000);
    }

    {
        // a regular one, not so much
        CBloomFilter filter(120000, 0.000001, 0, 0);
        // printf("Bloom filter size: %u\n", filter.vDataSize());
        BOOST_CHECK(filter.vDataSize() < 50000);
    }
}
BOOST_AUTO_TEST_SUITE_END()
