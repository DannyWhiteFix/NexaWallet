// Copyright (c) 2019-2023 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include "test/test_nexa.h"
#include "test/testutil.h"
#include "txlookup.h"

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(txlookup_tests, BasicTestingSetup);

BOOST_AUTO_TEST_CASE(ctor_lookup)
{
    CBlock block;
    for (size_t i = 0; i < 100; ++i)
    {
        block.vtx.push_back(MakeTransactionRef(CreateRandomTx()));
    }
    std::sort(
        begin(block.vtx) + 1, end(block.vtx), [](const auto &a, const auto &b) { return a->GetId() < b->GetId(); });

    for (size_t i = 0; i < 100; i += 10)
    {
        BOOST_CHECK_EQUAL(i, static_cast<size_t>(FindTxPosition(block, block.vtx[i]->GetId())));
    }
}

BOOST_AUTO_TEST_CASE(maprelay_lookup)
{
    CMapRelay maprelay;

    // Create transactions and add to maprelay
    CMutableTransaction tx1 = CMutableTransaction();
    tx1.vout.resize(1);
    tx1.vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx1.vout[0].nValue = 5 * COIN;
    CDataStream ss1(SER_NETWORK, PROTOCOL_VERSION);
    ss1 << tx1;
    maprelay.Add(tx1.GetId(), std::make_shared<CDataStream>(ss1));

    CMutableTransaction tx2 = CMutableTransaction();
    tx2.vout.resize(1);
    tx2.vout[0].scriptPubKey = CScript() << OP_13 << OP_EQUAL;
    tx2.vout[0].nValue = 50 * COIN;
    CDataStream ss2(SER_NETWORK, PROTOCOL_VERSION);
    ss2 << tx2;
    maprelay.Add(tx2.GetId(), std::make_shared<CDataStream>(ss2));

    CMutableTransaction tx3 = CMutableTransaction();
    tx3.vout.resize(1);
    tx3.vout[0].scriptPubKey = CScript() << OP_13 << OP_EQUAL;
    tx3.vout[0].nValue = 500 * COIN;
    CDataStream ss3(SER_NETWORK, PROTOCOL_VERSION);
    ss3 << tx3;

    BOOST_CHECK(tx1.GetId() != tx2.GetId());
    BOOST_CHECK(tx1.GetId() != tx3.GetId());
    BOOST_CHECK(tx2.GetId() != tx3.GetId());

    // Lookup these transactions and return datastreams
    BOOST_CHECK(maprelay.Find(tx1.GetId()).size() == 1);
    BOOST_CHECK(maprelay.Find(tx2.GetId()).size() == 1);
    BOOST_CHECK(maprelay.Find(tx3.GetId()).size() == 0);

    // Deserialize a datastream and manipulate the transaction and check whether it was the same
    // one that we stored.
    CMutableTransaction temp;
    std::shared_ptr<CDataStream> pFind1;
    auto vFind1 = maprelay.Find(tx1.GetId());
    *(vFind1[0]) >> temp;
    BOOST_CHECK(temp.GetId() == tx1.GetId());

    // Trim the transaction from the maprelay and try to look it up again
    maxTxPool.Set(0);
    maprelay.Expire();
    BOOST_CHECK(maprelay.Find(tx1.GetId()).empty());
    BOOST_CHECK(maprelay.Find(tx2.GetId()).empty());

    // Add a transaction to maprelay and then expire it by time
    // and then try to look it up.
    maxTxPool.Set(100);
    uint64_t nStartTime = GetTime();

    // Add txns
    SetMockTime(nStartTime);
    maprelay.Add(tx1.GetId(), std::make_shared<CDataStream>(ss1));
    SetMockTime(nStartTime + 1);
    maprelay.Add(tx2.GetId(), std::make_shared<CDataStream>(ss2));

    // Call Expire and then lookup this transaction. It should still exist because the
    // expire time has not passed.
    maprelay.Expire();
    BOOST_CHECK(maprelay.Find(tx1.GetId()).size() == 1);

    // Move clock ahead to one second before it would be expired and call Expire
    SetMockTime(nStartTime + CMapRelay::DEFAULT_EXPIRE_TIME);
    maprelay.Expire();
    BOOST_CHECK(maprelay.Find(tx1.GetId()).size() == 1);
    BOOST_CHECK(maprelay.Find(tx2.GetId()).size() == 1);

    // Move the clock ahead one more second, call Expire, and the first entry should have been expired
    SetMockTime(nStartTime + CMapRelay::DEFAULT_EXPIRE_TIME + 1);
    maprelay.Expire();
    BOOST_CHECK(maprelay.Find(tx1.GetId()).empty());
    BOOST_CHECK(maprelay.Find(tx2.GetId()).size() == 1);

    // Move the clock ahead an additional second, call Expire, and both entries should have been expired
    SetMockTime(nStartTime + CMapRelay::DEFAULT_EXPIRE_TIME + 2);
    maprelay.Expire();
    BOOST_CHECK(maprelay.Find(tx1.GetId()).empty());
    BOOST_CHECK(maprelay.Find(tx2.GetId()).empty());

    // Add a transaction id multiple times to maprelay but pointing at
    // different underlying transactions. They should be found.
    nStartTime = GetTime();
    SetMockTime(nStartTime);
    maprelay.Add(tx1.GetId(), std::make_shared<CDataStream>(ss1));
    BOOST_CHECK(maprelay.Find(tx1.GetId()).size() == 1);
    SetMockTime(nStartTime + 5);
    maprelay.Add(tx1.GetId(), std::make_shared<CDataStream>(ss2));
    BOOST_CHECK(maprelay.Find(tx1.GetId()).size() == 2); // should be found twice
    SetMockTime(nStartTime + 10);
    maprelay.Add(tx1.GetId(), std::make_shared<CDataStream>(ss3));
    BOOST_CHECK(maprelay.Find(tx1.GetId()).size() == 3); // should be found thrice

    // now show that as we expire them the entries thare are identical remain
    // if they haven't hit their expiry time yet.
    SetMockTime(nStartTime + CMapRelay::DEFAULT_EXPIRE_TIME + 1);
    maprelay.Expire();
    BOOST_CHECK_EQUAL(maprelay.Find(tx1.GetId()).size(), 2);
    SetMockTime(nStartTime + CMapRelay::DEFAULT_EXPIRE_TIME + 6);
    maprelay.Expire();
    BOOST_CHECK_EQUAL(maprelay.Find(tx1.GetId()).size(), 1);
    SetMockTime(nStartTime + CMapRelay::DEFAULT_EXPIRE_TIME + 11);
    maprelay.Expire();
    BOOST_CHECK_EQUAL(maprelay.Find(tx1.GetId()).size(), 0);
}

BOOST_AUTO_TEST_SUITE_END();
