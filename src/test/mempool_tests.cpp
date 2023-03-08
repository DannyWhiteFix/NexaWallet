// Copyright (c) 2011-2015 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "txmempool.h"
#include "util.h"

#include "test/test_nexa.h"

#include <boost/test/unit_test.hpp>
#include <list>
#include <vector>

extern CCoinsViewCache *pcoinsTip;
extern std::atomic<bool> fMempoolTests;

struct MempoolData
{
    uint256 hash;

    // Ancestor counters
    uint64_t nCountWithAncestors = 0;
    uint64_t nSizeWithAncestors = 0;
    uint64_t nSigopsWithAncestors = 0;
    uint64_t nFeesWithAncestors = 0;
    bool fDirty = false;
};

void CheckAncestors(MempoolData &expected_result, CTxMemPool &pool)
{
    CTxMemPool::TxIdIter iter = pool.mapTx.find(expected_result.hash);
    if (iter == pool.mapTx.end())
    {
        printf("ERROR: tx %s not found in mempool\n", expected_result.hash.ToString().c_str());
        throw;
    }
    BOOST_CHECK_EQUAL(iter->GetCountWithAncestors(), expected_result.nCountWithAncestors);
    BOOST_CHECK_EQUAL(iter->GetSizeWithAncestors(), expected_result.nSizeWithAncestors);
    BOOST_CHECK_EQUAL(iter->GetSigOpCountWithAncestors(), expected_result.nSigopsWithAncestors);
    BOOST_CHECK_EQUAL(iter->GetModFeesWithAncestors(), static_cast<long long>(expected_result.nFeesWithAncestors));
    BOOST_CHECK_EQUAL(iter->IsDirty(), expected_result.fDirty);
}

void VerifyTxNotInMempool(MempoolData &expected_result, CTxMemPool &pool)
{
    CTxMemPool::TxIdIter iter = pool.mapTx.find(expected_result.hash);
    if (iter != pool.mapTx.end())
    {
        printf("ERROR: tx %s was found in mempool when it should not be\n", expected_result.hash.ToString().c_str());
        throw;
    }
}

BOOST_FIXTURE_TEST_SUITE(mempool_tests, TestingSetup)

BOOST_AUTO_TEST_CASE(MempoolUpdateChainStateTest)
{
    // Indicate we're doing the mempool tests. This will prevent the auto updating ancestor state for
    // the entire txn chains, which will allow us to test these shorter chains for their dirty and non-dirty states.
    fMempoolTests.store(true);

    TestMemPoolEntryHelper entry;
    CTxMemPool pool;
    pool.clear();

    /* Create a complex set of chained transactions and then update their state after removing some from the mempool.
       (The numbers indicate the tx number, ie. 1 == tx1)

    Chain1:

    1      2   3      4
    |      |   |      |
    5      6   7      8
     \    /     \    /
      \  /       \  /
       9          10      20
       | \        |       /
       |  \______ 11 ____/
       |          |\
       12         | \
      /|\        13 14      19
     / | \        | /       /
    15 16 17      18 ______/

    */

    // Chain:1 Transactions

    // tx1
    CMutableTransaction tx1 = CMutableTransaction();
    tx1.vout.resize(1);
    tx1.vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx1.vout[0].nValue = 1 * COIN; // Different values makes each tx hash unique (since there are no prevs)
    pool.addUnchecked(entry.Fee(1000LL).Priority(10.0).SigOps(1).FromTx(tx1));

    // tx2
    CMutableTransaction tx2 = CMutableTransaction();
    tx2.vout.resize(1);
    tx2.vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx2.vout[0].nValue = 2 * COIN;
    pool.addUnchecked(entry.Fee(2000LL).Priority(10.0).SigOps(1).FromTx(tx2));

    // tx3
    CMutableTransaction tx3 = CMutableTransaction();
    tx3.vout.resize(1);
    tx3.vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx3.vout[0].nValue = 3 * COIN;
    pool.addUnchecked(entry.Fee(3000LL).Priority(10.0).SigOps(1).FromTx(tx3));

    // tx4
    CMutableTransaction tx4 = CMutableTransaction();
    tx4.vout.resize(1);
    tx4.vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx4.vout[0].nValue = 4 * COIN;
    pool.addUnchecked(entry.Fee(4000LL).Priority(10.0).SigOps(1).FromTx(tx4));


    // tx5 - child of tx1
    CMutableTransaction tx5 = CMutableTransaction();
    tx5.vin.resize(1);
    tx5.vin[0].scriptSig = CScript() << OP_11;
    tx5.vin[0].prevout = tx1.OutpointAt(0);
    tx5.vout.resize(1);
    tx5.vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx5.vout[0].nValue = 1 * COIN;
    pool.addUnchecked(entry.Fee(1000LL).Priority(10.0).SigOps(1).FromTx(tx5));


    // tx6 - child of tx2
    CMutableTransaction tx6 = CMutableTransaction();
    tx6.vin.resize(1);
    tx6.vin[0].scriptSig = CScript() << OP_11;
    tx6.vin[0].prevout = tx2.OutpointAt(0);
    tx6.vout.resize(1);
    tx6.vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx6.vout[0].nValue = 2 * COIN;
    pool.addUnchecked(entry.Fee(2000LL).Priority(10.0).SigOps(1).FromTx(tx6));

    // tx7 - child of tx3
    CMutableTransaction tx7 = CMutableTransaction();
    tx7.vin.resize(1);
    tx7.vin[0].scriptSig = CScript() << OP_11;
    tx7.vin[0].prevout = tx3.OutpointAt(0);
    tx7.vout.resize(1);
    tx7.vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx7.vout[0].nValue = 3 * COIN;
    pool.addUnchecked(entry.Fee(3000LL).Priority(10.0).SigOps(1).FromTx(tx7));


    // tx8 - child of tx4
    CMutableTransaction tx8 = CMutableTransaction();
    tx8.vin.resize(1);
    tx8.vin[0].scriptSig = CScript() << OP_11;
    tx8.vin[0].prevout = tx4.OutpointAt(0);
    tx8.vout.resize(1);
    tx8.vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx8.vout[0].nValue = 4 * COIN;
    pool.addUnchecked(entry.Fee(4000LL).Priority(10.0).SigOps(1).Name("tx8").FromTx(tx8));

    // tx9 - child of tx5 and tx6 and has two outputs
    CMutableTransaction tx9 = CMutableTransaction();
    tx9.vin.resize(2);
    tx9.vin[0].scriptSig = CScript() << OP_11;
    tx9.vin[0].prevout = tx5.OutpointAt(0);
    tx9.vin[1].scriptSig = CScript() << OP_11;
    tx9.vin[1].prevout = tx6.OutpointAt(0);
    tx9.vout.resize(2);
    tx9.vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx9.vout[0].nValue = 1 * COIN;
    tx9.vout[1].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx9.vout[1].nValue = 2 * COIN;
    pool.addUnchecked(entry.Fee(3000LL).Priority(10.0).SigOps(1).Name("tx9").FromTx(tx9));

    // tx10 - child of tx7 and tx8 and has one output
    CMutableTransaction tx10 = CMutableTransaction();
    tx10.vin.resize(2);
    tx10.vin[0].scriptSig = CScript() << OP_11;
    tx10.vin[0].prevout = tx7.OutpointAt(0);
    tx10.vin[1].scriptSig = CScript() << OP_11;
    tx10.vin[1].prevout = tx8.OutpointAt(0);
    tx10.vout.resize(1);
    tx10.vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx10.vout[0].nValue = 7 * COIN;
    pool.addUnchecked(entry.Fee(7000LL).SigOps(1).FromTx(tx10));

    // tx20
    CMutableTransaction tx20 = CMutableTransaction();
    tx20.vout.resize(1);
    tx20.vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx20.vout[0].nValue = 5 * COIN;
    pool.addUnchecked(entry.Fee(5000LL).Priority(10.0).SigOps(1).FromTx(tx20));

    // tx11 - child of tx9, tx10 and tx20, and has two outputs
    CMutableTransaction tx11 = CMutableTransaction();
    tx11.vin.resize(3);
    tx11.vin[0].scriptSig = CScript() << OP_11;
    tx11.vin[0].prevout = tx9.OutpointAt(1);
    tx11.vin[1].scriptSig = CScript() << OP_11;
    tx11.vin[1].prevout = tx10.OutpointAt(0);
    tx11.vin[2].scriptSig = CScript() << OP_11;
    tx11.vin[2].prevout = tx20.OutpointAt(0);
    tx11.vout.resize(2);
    tx11.vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx11.vout[0].nValue = 1 * COIN;
    tx11.vout[1].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx11.vout[1].nValue = 2 * COIN;
    pool.addUnchecked(entry.Fee(10000LL).SigOps(1).FromTx(tx11));

    // tx12 - child of tx9 and has three outputs
    CMutableTransaction tx12 = CMutableTransaction();
    tx12.vin.resize(1);
    tx12.vin[0].scriptSig = CScript() << OP_11;
    tx12.vin[0].prevout = tx9.OutpointAt(0);
    tx12.vout.resize(3);
    tx12.vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx12.vout[0].nValue = .5 * COIN;
    tx12.vout[1].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx12.vout[1].nValue = .2 * COIN;
    tx12.vout[2].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx12.vout[2].nValue = .3 * COIN;
    pool.addUnchecked(entry.Fee(1000LL).Priority(10.0).SigOps(1).FromTx(tx12));

    // tx13 - child of tx11 and has one output
    CMutableTransaction tx13 = CMutableTransaction();
    tx13.vin.resize(1);
    tx13.vin[0].scriptSig = CScript() << OP_11;
    tx13.vin[0].prevout = tx11.OutpointAt(0);
    tx13.vout.resize(1);
    tx13.vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx13.vout[0].nValue = 1 * COIN;
    pool.addUnchecked(entry.Fee(1000LL).SigOps(1).FromTx(tx13));


    // tx14 - child of tx11 and has one output
    CMutableTransaction tx14 = CMutableTransaction();
    tx14.vin.resize(1);
    tx14.vin[0].scriptSig = CScript() << OP_11;
    tx14.vin[0].prevout = tx11.OutpointAt(1);
    tx14.vout.resize(1);
    tx14.vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx14.vout[0].nValue = 1 * COIN;
    pool.addUnchecked(entry.Fee(1000LL).SigOps(1).FromTx(tx14));

    // tx15 - child of tx12
    CMutableTransaction tx15 = CMutableTransaction();
    tx15.vin.resize(1);
    tx15.vin[0].scriptSig = CScript() << OP_11;
    tx15.vin[0].prevout = tx12.OutpointAt(0);
    tx15.vout.resize(1);
    tx15.vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx15.vout[0].nValue = 1 * COIN;
    pool.addUnchecked(entry.Fee(500LL).SigOps(1).FromTx(tx15));

    // tx16 - child of tx12
    CMutableTransaction tx16 = CMutableTransaction();
    tx16.vin.resize(1);
    tx16.vin[0].scriptSig = CScript() << OP_11;
    tx16.vin[0].prevout = tx12.OutpointAt(1);
    tx16.vout.resize(1);
    tx16.vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx16.vout[0].nValue = 1 * COIN;
    pool.addUnchecked(entry.Fee(200LL).SigOps(1).FromTx(tx16));

    // tx17 - child of tx12
    CMutableTransaction tx17 = CMutableTransaction();
    tx17.vin.resize(1);
    tx17.vin[0].scriptSig = CScript() << OP_11;
    tx17.vin[0].prevout = tx12.OutpointAt(2);
    tx17.vout.resize(1);
    tx17.vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx17.vout[0].nValue = 1 * COIN;
    pool.addUnchecked(entry.Fee(300LL).SigOps(1).FromTx(tx17));

    // tx19
    CMutableTransaction tx19 = CMutableTransaction();
    tx19.vout.resize(1);
    tx19.vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx19.vout[0].nValue = 6 * COIN;
    pool.addUnchecked(entry.Fee(6000LL).Priority(10.0).SigOps(1).FromTx(tx19));


    // tx18 - child of tx13, tx14 and 19, and has two outputs
    CMutableTransaction tx18 = CMutableTransaction();
    tx18.vin.resize(3);
    tx18.vin[0].scriptSig = CScript() << OP_11;
    tx18.vin[0].prevout = tx13.OutpointAt(0);
    tx18.vin[1].scriptSig = CScript() << OP_11;
    tx18.vin[1].prevout = tx14.OutpointAt(0);
    tx18.vin[2].scriptSig = CScript() << OP_11;
    tx18.vin[2].prevout = tx19.OutpointAt(0);
    tx18.vout.resize(2);
    tx18.vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx18.vout[0].nValue = 1 * COIN;
    tx18.vout[1].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx18.vout[1].nValue = 2 * COIN;
    pool.addUnchecked(entry.Fee(2000LL).SigOps(1).FromTx(tx18));


    // Chain:2 Transactions
    /*

                            21                     27
                            |                      /
            ________________22_______________     /
           /         /      |      \         \   28
          /         /       23      \         \  /
         /         /       / \       \         \/
        31        32      24 25      33        29
         \         \       \ /       /         /\
          \         \       26      /         /  \
           \         \      |      /         /    \
           34_________\_____35____/_________/     30
                           / \
                          36 37
                           \ /
                            38
    */

    // tx21
    CMutableTransaction tx21 = CMutableTransaction();
    tx21.vout.resize(1);
    tx21.vout[0].scriptPubKey = CScript();
    tx21.vout[0].nValue = 100 * COIN;
    pool.addUnchecked(entry.Fee(100000LL).Priority(10.0).SigOps(1).FromTx(tx21));


    // tx22 - child of tx21 and has 5 outputs
    CMutableTransaction tx22 = CMutableTransaction();
    tx22.vin.resize(1);
    tx22.vin[0].scriptSig = CScript();
    tx22.vin[0].prevout = tx21.OutpointAt(0);
    tx22.vout.resize(5);
    tx22.vout[0].scriptPubKey = CScript();
    tx22.vout[0].nValue = 20 * COIN;
    tx22.vout[1].scriptPubKey = CScript();
    tx22.vout[1].nValue = 20 * COIN;
    tx22.vout[2].scriptPubKey = CScript();
    tx22.vout[2].nValue = 20 * COIN;
    tx22.vout[3].scriptPubKey = CScript();
    tx22.vout[3].nValue = 20 * COIN;
    tx22.vout[4].scriptPubKey = CScript();
    tx22.vout[4].nValue = 20 * COIN;
    pool.addUnchecked(entry.Fee(100000LL).Priority(10.0).SigOps(1).FromTx(tx22));


    // tx23 - child of tx22 and has two outputs
    CMutableTransaction tx23 = CMutableTransaction();
    tx23.vin.resize(1);
    tx23.vin[0].scriptSig = CScript();
    tx23.vin[0].prevout = tx22.OutpointAt(2);
    tx23.vout.resize(2);
    tx23.vout[0].scriptPubKey = CScript();
    tx23.vout[0].nValue = 10 * COIN;
    tx23.vout[1].scriptPubKey = CScript();
    tx23.vout[1].nValue = 10 * COIN;
    pool.addUnchecked(entry.Fee(20000LL).Priority(10.0).SigOps(1).FromTx(tx23));

    // tx24 - child of tx23 and has one output
    CMutableTransaction tx24 = CMutableTransaction();
    tx24.vin.resize(1);
    tx24.vin[0].scriptSig = CScript();
    tx24.vin[0].prevout = tx23.OutpointAt(0);
    tx24.vout.resize(1);
    tx24.vout[0].scriptPubKey = CScript();
    tx24.vout[0].nValue = 10 * COIN;
    pool.addUnchecked(entry.Fee(10000LL).SigOps(1).FromTx(tx24));

    // tx25 - child of tx23 and has one output
    CMutableTransaction tx25 = CMutableTransaction();
    tx25.vin.resize(1);
    tx25.vin[0].scriptSig = CScript();
    tx25.vin[0].prevout = tx23.OutpointAt(1);
    tx25.vout.resize(1);
    tx25.vout[0].scriptPubKey = CScript();
    tx25.vout[0].nValue = 10 * COIN;
    pool.addUnchecked(entry.Fee(10000LL).SigOps(1).FromTx(tx25));

    // tx26 - child of tx24 and tx25 and has one output
    CMutableTransaction tx26 = CMutableTransaction();
    tx26.vin.resize(2);
    tx26.vin[0].scriptSig = CScript();
    tx26.vin[0].prevout = tx24.OutpointAt(0);
    tx26.vin[1].scriptSig = CScript();
    tx26.vin[1].prevout = tx25.OutpointAt(0);
    tx26.vout.resize(1);
    tx26.vout[0].scriptPubKey = CScript();
    tx26.vout[0].nValue = 20 * COIN;
    pool.addUnchecked(entry.Fee(20000LL).SigOps(1).FromTx(tx26));

    // tx27
    CMutableTransaction tx27 = CMutableTransaction();
    tx27.vout.resize(1);
    tx27.vout[0].scriptPubKey = CScript();
    tx27.vout[0].nValue = 101 * COIN;
    pool.addUnchecked(entry.Fee(101000LL).Priority(10.0).SigOps(1).FromTx(tx27));

    // tx28 - child of tx27 and has one output
    CMutableTransaction tx28 = CMutableTransaction();
    tx28.vin.resize(1);
    tx28.vin[0].scriptSig = CScript();
    tx28.vin[0].prevout = tx27.OutpointAt(0);
    tx28.vout.resize(1);
    tx28.vout[0].scriptPubKey = CScript();
    tx28.vout[0].nValue = 101 * COIN;
    pool.addUnchecked(entry.Fee(101000LL).SigOps(1).FromTx(tx28));

    // tx29 - child of tx22 and tx28 and has two outputs
    CMutableTransaction tx29 = CMutableTransaction();
    tx29.vin.resize(2);
    tx29.vin[0].scriptSig = CScript();
    tx29.vin[0].prevout = tx22.OutpointAt(4);
    tx29.vin[1].scriptSig = CScript();
    tx29.vin[1].prevout = tx28.OutpointAt(0);
    tx29.vout.resize(2);
    tx29.vout[0].scriptPubKey = CScript();
    tx29.vout[0].nValue = 100 * COIN;
    tx29.vout[1].scriptPubKey = CScript();
    tx29.vout[1].nValue = 101 * COIN;
    pool.addUnchecked(entry.Fee(201000LL).Priority(10.0).SigOps(1).FromTx(tx29));

    // tx30 - child of tx29 and has one output
    CMutableTransaction tx30 = CMutableTransaction();
    tx30.vin.resize(1);
    tx30.vin[0].scriptSig = CScript();
    tx30.vin[0].prevout = tx29.OutpointAt(1);
    tx30.vout.resize(1);
    tx30.vout[0].scriptPubKey = CScript();
    tx30.vout[0].nValue = 101 * COIN;
    pool.addUnchecked(entry.Fee(101000LL).SigOps(1).FromTx(tx30));

    // tx31 - child of tx22 and has one output
    CMutableTransaction tx31 = CMutableTransaction();
    tx31.vin.resize(1);
    tx31.vin[0].scriptSig = CScript();
    tx31.vin[0].prevout = tx22.OutpointAt(0);
    tx31.vout.resize(1);
    tx31.vout[0].scriptPubKey = CScript();
    tx31.vout[0].nValue = 20 * COIN;
    pool.addUnchecked(entry.Fee(20000LL).SigOps(1).FromTx(tx31));

    // tx32 - child of tx22 and has one output
    CMutableTransaction tx32 = CMutableTransaction();
    tx32.vin.resize(1);
    tx32.vin[0].scriptSig = CScript();
    tx32.vin[0].prevout = tx22.OutpointAt(1);
    tx32.vout.resize(1);
    tx32.vout[0].scriptPubKey = CScript();
    tx32.vout[0].nValue = 20 * COIN;
    pool.addUnchecked(entry.Fee(20000LL).SigOps(1).FromTx(tx32));

    // tx33 - child of tx22 and has one output
    CMutableTransaction tx33 = CMutableTransaction();
    tx33.vin.resize(1);
    tx33.vin[0].scriptSig = CScript();
    tx33.vin[0].prevout = tx22.OutpointAt(3);
    tx33.vout.resize(1);
    tx33.vout[0].scriptPubKey = CScript();
    tx33.vout[0].nValue = 20 * COIN;
    pool.addUnchecked(entry.Fee(20000LL).SigOps(1).FromTx(tx33));

    // tx34 - child of tx31 and has one output
    CMutableTransaction tx34 = CMutableTransaction();
    tx34.vin.resize(1);
    tx34.vin[0].scriptSig = CScript();
    tx34.vin[0].prevout = tx31.OutpointAt(0);
    tx34.vout.resize(1);
    tx34.vout[0].scriptPubKey = CScript();
    tx34.vout[0].nValue = 20 * COIN;
    pool.addUnchecked(entry.Fee(20000LL).SigOps(1).FromTx(tx34));

    // tx35 - child of tx26, tx29, tx32, tx33, tx34 and has two outputs
    CMutableTransaction tx35 = CMutableTransaction();
    tx35.vin.resize(5);
    tx35.vin[0].scriptSig = CScript();
    tx35.vin[0].prevout = tx26.OutpointAt(0);
    tx35.vin[1].scriptSig = CScript();
    tx35.vin[1].prevout = tx29.OutpointAt(0);
    tx35.vin[2].scriptSig = CScript();
    tx35.vin[2].prevout = tx32.OutpointAt(0);
    tx35.vin[3].scriptSig = CScript();
    tx35.vin[3].prevout = tx33.OutpointAt(0);
    tx35.vin[4].scriptSig = CScript();
    tx35.vin[4].prevout = tx34.OutpointAt(0);
    tx35.vout.resize(2);
    tx35.vout[0].scriptPubKey = CScript();
    tx35.vout[0].nValue = 200 * COIN;
    tx35.vout[1].scriptPubKey = CScript();
    tx35.vout[1].nValue = 81 * COIN;
    pool.addUnchecked(entry.Fee(281000LL).Priority(10.0).SigOps(1).FromTx(tx35));

    // tx36 - child of tx35 and has one output
    CMutableTransaction tx36 = CMutableTransaction();
    tx36.vin.resize(1);
    tx36.vin[0].scriptSig = CScript();
    tx36.vin[0].prevout = tx35.OutpointAt(0);
    tx36.vout.resize(1);
    tx36.vout[0].scriptPubKey = CScript();
    tx36.vout[0].nValue = 200 * COIN;
    pool.addUnchecked(entry.Fee(200000LL).SigOps(1).FromTx(tx36));

    // tx37 - child of tx35 and has one output
    CMutableTransaction tx37 = CMutableTransaction();
    tx37.vin.resize(1);
    tx37.vin[0].scriptSig = CScript();
    tx37.vin[0].prevout = tx35.OutpointAt(1);
    tx37.vout.resize(1);
    tx37.vout[0].scriptPubKey = CScript();
    tx37.vout[0].nValue = 81 * COIN;
    pool.addUnchecked(entry.Fee(81000LL).SigOps(1).FromTx(tx37));

    // tx38 - child of tx36 and tx37 and has one output
    CMutableTransaction tx38 = CMutableTransaction();
    tx38.vin.resize(2);
    tx38.vin[0].scriptSig = CScript();
    tx38.vin[0].prevout = tx36.OutpointAt(0);
    tx38.vin[1].scriptSig = CScript();
    tx38.vin[1].prevout = tx37.OutpointAt(0);
    tx38.vout.resize(1);
    tx38.vout[0].scriptPubKey = CScript();
    tx38.vout[0].nValue = 281 * COIN;
    pool.addUnchecked(entry.Fee(2810000LL).SigOps(1).FromTx(tx38));

    /*  Simple chain with the purpose to test and edge condition where txchaintips become decendants of other
        txchaintips. We will mine tx39, tx44, and tx47 which means that there will be
        three txchaintips, one at tx41, one at tx42, and one at 45, with both 42 and 45 in the same chain as 41,
        thus being an edge condition we have to account for.

    Chain3:  we will mine txn 39, 44 and 47

           44
           /
    39 40 41
     \ | / \
      \|/   \   47
       42   46  /
       |     \ /
       43    45
       |       \
       48      49

    */

    // tx39
    CMutableTransaction tx39 = CMutableTransaction();
    tx39.vout.resize(1);
    tx39.vout[0].scriptPubKey = CScript() << OP_11;
    tx39.vout[0].nValue = 1 * COIN;
    pool.addUnchecked(entry.Fee(1000LL).Priority(10.0).SigOps(1).FromTx(tx39));

    // tx40
    CMutableTransaction tx40 = CMutableTransaction();
    tx40.vout.resize(1);
    tx40.vout[0].scriptPubKey = CScript() << OP_11;
    tx40.vout[0].nValue = 2 * COIN;
    pool.addUnchecked(entry.Fee(2000LL).Priority(10.0).SigOps(1).FromTx(tx40));

    // tx44
    CMutableTransaction tx44 = CMutableTransaction();
    tx44.vout.resize(1);
    tx44.vout[0].scriptPubKey = CScript() << OP_11;
    tx44.vout[0].nValue = 4 * COIN;
    pool.addUnchecked(entry.Fee(4000LL).Priority(10.0).SigOps(1).FromTx(tx44));

    // tx41
    CMutableTransaction tx41 = CMutableTransaction();
    tx41.vin.resize(1);
    tx41.vin[0].scriptSig = CScript();
    tx41.vin[0].prevout = tx44.OutpointAt(0);
    tx41.vout.resize(2);
    tx41.vout[0].scriptPubKey = CScript() << OP_11;
    tx41.vout[0].nValue = 3 * COIN;
    tx41.vout[1].scriptPubKey = CScript() << OP_11;
    tx41.vout[1].nValue = 3 * COIN;
    pool.addUnchecked(entry.Fee(6000LL).Priority(10.0).SigOps(1).FromTx(tx41));

    // tx42 - child of tx39, tx40 and tx41 and has one output
    CMutableTransaction tx42 = CMutableTransaction();
    tx42.vin.resize(3);
    tx42.vin[0].scriptSig = CScript();
    tx42.vin[0].prevout = tx39.OutpointAt(0);
    tx42.vin[1].scriptSig = CScript();
    tx42.vin[1].prevout = tx40.OutpointAt(0);
    tx42.vin[2].scriptSig = CScript();
    tx42.vin[2].prevout = tx41.OutpointAt(0);
    tx42.vout.resize(1);
    tx42.vout[0].scriptPubKey = CScript();
    tx42.vout[0].nValue = 6 * COIN;
    pool.addUnchecked(entry.Fee(6000LL).SigOps(1).FromTx(tx42));

    // tx43 - child of tx42 and has one output
    CMutableTransaction tx43 = CMutableTransaction();
    tx43.vin.resize(1);
    tx43.vin[0].scriptSig = CScript();
    tx43.vin[0].prevout = tx42.OutpointAt(0);
    tx43.vout.resize(1);
    tx43.vout[0].scriptPubKey = CScript();
    tx43.vout[0].nValue = 12 * COIN;
    pool.addUnchecked(entry.Fee(12000LL).SigOps(1).FromTx(tx43));

    // tx48 child of tx43
    CMutableTransaction tx48 = CMutableTransaction();
    tx48.vin.resize(1);
    tx48.vin[0].scriptSig = CScript();
    tx48.vin[0].prevout = tx43.OutpointAt(0);
    tx48.vout.resize(1);
    tx48.vout[0].scriptPubKey = CScript();
    tx48.vout[0].nValue = 15 * COIN;
    pool.addUnchecked(entry.Fee(15000LL).Priority(10.0).SigOps(1).FromTx(tx48));

    // tx47
    CMutableTransaction tx47 = CMutableTransaction();
    tx47.vout.resize(1);
    tx47.vout[0].scriptPubKey = CScript();
    tx47.vout[0].nValue = 10 * COIN;
    pool.addUnchecked(entry.Fee(10000LL).Priority(10.0).SigOps(1).FromTx(tx47));

    // tx46 child of tx41
    CMutableTransaction tx46 = CMutableTransaction();
    tx46.vin.resize(1);
    tx46.vin[0].scriptSig = CScript();
    tx46.vin[0].prevout = tx41.OutpointAt(1);
    tx46.vout.resize(1);
    tx46.vout[0].scriptPubKey = CScript();
    tx46.vout[0].nValue = 3 * COIN;
    pool.addUnchecked(entry.Fee(3000LL).Priority(10.0).SigOps(1).FromTx(tx46));


    // tx45 - child of tx46 and tx47 and has one output
    CMutableTransaction tx45 = CMutableTransaction();
    tx45.vin.resize(2);
    tx45.vin[0].scriptSig = CScript();
    tx45.vin[0].prevout = tx46.OutpointAt(0);
    tx45.vin[1].scriptSig = CScript();
    tx45.vin[1].prevout = tx47.OutpointAt(0);
    tx45.vout.resize(1);
    tx45.vout[0].scriptPubKey = CScript();
    tx45.vout[0].nValue = 12 * COIN;
    pool.addUnchecked(entry.Fee(12000LL).SigOps(1).FromTx(tx45));

    // tx49 child of tx45
    CMutableTransaction tx49 = CMutableTransaction();
    tx49.vin.resize(1);
    tx49.vin[0].scriptSig = CScript();
    tx49.vin[0].prevout = tx45.OutpointAt(0);
    tx49.vout.resize(1);
    tx49.vout[0].scriptPubKey = CScript();
    tx49.vout[0].nValue = 14 * COIN;
    pool.addUnchecked(entry.Fee(14000LL).Priority(10.0).SigOps(1).FromTx(tx49));

    // Validate the current state is correct
    /* clang-format off */
    BOOST_CHECK_EQUAL(pool.size(), 49UL);
    std::vector<MempoolData> txns_expected =
    {
        // Chain1:
        {tx1.GetId(), 1, 19, 1, 1000},
        {tx2.GetId(), 1, 19, 1, 2000},
        {tx3.GetId(), 1, 19, 1, 3000},
        {tx4.GetId(), 1, 19, 1, 4000},
        {tx5.GetId(), 2, 85, 2, 2000},
        {tx6.GetId(), 2, 85, 2, 4000},
        {tx7.GetId(), 2, 85, 2, 6000},
        {tx8.GetId(), 2, 85, 2, 8000},
        {tx9.GetId(), 5, 295, 5, 9000, true},
        {tx10.GetId(), 5, 283, 5, 21000, true},
        {tx11.GetId(), 12, 769, 12, 45000, true},
        {tx12.GetId(), 6, 385, 6, 10000, true},
        {tx13.GetId(), 13, 835, 13, 46000, true},
        {tx14.GetId(), 13, 835, 13, 46000, true},
        {tx15.GetId(), 7, 451, 7, 10500, true},
        {tx16.GetId(), 7, 451, 7, 10200, true},
        {tx17.GetId(), 7, 451, 7, 10300, true},
        {tx18.GetId(), 28, 1861, 28, 100000, true},
        {tx19.GetId(), 1, 19, 1, 6000},
        {tx20.GetId(), 1, 19, 1, 5000},

        // Chain2:
        {tx21.GetId(), 1, 17, 1, 100000},
        {tx22.GetId(), 2, 120, 2, 200000},
        {tx23.GetId(), 3, 193, 3, 220000},
        {tx24.GetId(), 4, 256, 4, 230000},
        {tx25.GetId(), 4, 256, 4, 230000},
        {tx26.GetId(), 9, 621, 9, 480000, true},
        {tx27.GetId(), 1, 17, 1, 101000},
        {tx28.GetId(), 2, 80, 2, 202000},
        {tx29.GetId(), 5, 319, 5, 603000, true},
        {tx30.GetId(), 6, 382, 6, 704000, true},
        {tx31.GetId(), 3, 183, 3, 220000},
        {tx32.GetId(), 3, 183, 3, 220000},
        {tx33.GetId(), 3, 183, 3, 220000},
        {tx34.GetId(), 4, 246, 4, 240000},
        {tx35.GetId(), 25, 1809, 25, 2044000, true},
        {tx36.GetId(), 26, 1872, 26, 2244000, true},
        {tx37.GetId(), 26, 1872, 26, 2125000, true},
        {tx38.GetId(), 53, 3853, 53, 7179000, true},

        // Chain3:
        {tx39.GetId(), 1, 18, 1, 1000},
        {tx40.GetId(), 1, 18, 1, 2000},
        {tx41.GetId(), 2, 93, 2, 10000},
        {tx42.GetId(), 5, 284, 5, 19000, true},
        {tx43.GetId(), 6, 347, 6, 31000, true},
        {tx44.GetId(), 1, 18, 1, 4000},
        {tx45.GetId(), 5, 282, 5, 35000, true},
        {tx46.GetId(), 3, 156, 3, 13000},
        {tx47.GetId(), 1, 17, 1, 10000},
        {tx48.GetId(), 7, 410, 7, 46000, true},
        {tx49.GetId(), 6, 345, 6, 49000, true}
    };
    /* clang-format on */
    for (size_t i = 0; i < txns_expected.size(); i++)
    {
        CTxMemPool::TxIdIter iter = pool.mapTx.find(txns_expected[i].hash);
        if (iter == pool.mapTx.end())
        {
            printf("ERROR: tx %s not found in mempool\n", txns_expected[i].hash.ToString().c_str());
            throw;
        }

        /*
        printf(
            "tx%ld countwanc %ld sizewanc %ld sigopswanc %u feeswanc %ld\n",
            i + 1, iter->GetCountWithAncestors(), iter->GetSizeWithAncestors(), iter->GetSigOpCountWithAncestors(),
            iter->GetModFeesWithAncestors());
        printf("tx%d: hash %s\n", (int)(i + 1), iter->GetTx().GetHash().ToString().c_str());
        */

        CheckAncestors(txns_expected[i], pool);
    }

    /* Check that we can find the correct txn chaintips */
    CTxMemPool::mapEntryHistory mapTxnChainTips;
    CTxMemPool::TxIdIter it;

    {
        READLOCK(pool.cs_txmempool);
        mapTxnChainTips.clear();
        it = pool.mapTx.find(tx1.GetId());
        BOOST_CHECK(it != pool.mapTx.end());
        if (it != pool.mapTx.end())
        {
            pool.CalculateTxnChainTips(it, mapTxnChainTips);
            BOOST_CHECK(mapTxnChainTips.size() == 0);
        }

        mapTxnChainTips.clear();
        it = pool.mapTx.find(tx11.GetId());
        BOOST_CHECK(it != pool.mapTx.end());
        if (it != pool.mapTx.end())
        {
            pool.CalculateTxnChainTips(it, mapTxnChainTips);
            BOOST_CHECK(mapTxnChainTips.size() == 5);

            BOOST_CHECK(mapTxnChainTips.count(pool.mapTx.find(tx1.GetId())) == 1);
            BOOST_CHECK(mapTxnChainTips.count(pool.mapTx.find(tx2.GetId())) == 1);
            BOOST_CHECK(mapTxnChainTips.count(pool.mapTx.find(tx3.GetId())) == 1);
            BOOST_CHECK(mapTxnChainTips.count(pool.mapTx.find(tx4.GetId())) == 1);
            BOOST_CHECK(mapTxnChainTips.count(pool.mapTx.find(tx20.GetId())) == 1);
        }

        mapTxnChainTips.clear();
        it = pool.mapTx.find(tx16.GetId());
        BOOST_CHECK(it != pool.mapTx.end());
        if (it != pool.mapTx.end())
        {
            pool.CalculateTxnChainTips(it, mapTxnChainTips);
            BOOST_CHECK(mapTxnChainTips.size() == 2);

            BOOST_CHECK(mapTxnChainTips.count(pool.mapTx.find(tx1.GetId())) == 1);
            BOOST_CHECK(mapTxnChainTips.count(pool.mapTx.find(tx2.GetId())) == 1);
        }

        mapTxnChainTips.clear();
        it = pool.mapTx.find(tx18.GetId());
        BOOST_CHECK(it != pool.mapTx.end());
        if (it != pool.mapTx.end())
        {
            pool.CalculateTxnChainTips(it, mapTxnChainTips);
            BOOST_CHECK(mapTxnChainTips.size() == 6);

            BOOST_CHECK(mapTxnChainTips.count(pool.mapTx.find(tx1.GetId())) == 1);
            BOOST_CHECK(mapTxnChainTips.count(pool.mapTx.find(tx2.GetId())) == 1);
            BOOST_CHECK(mapTxnChainTips.count(pool.mapTx.find(tx3.GetId())) == 1);
            BOOST_CHECK(mapTxnChainTips.count(pool.mapTx.find(tx4.GetId())) == 1);
            BOOST_CHECK(mapTxnChainTips.count(pool.mapTx.find(tx19.GetId())) == 1);
            BOOST_CHECK(mapTxnChainTips.count(pool.mapTx.find(tx20.GetId())) == 1);
        }

        mapTxnChainTips.clear();
        it = pool.mapTx.find(tx26.GetId());
        BOOST_CHECK(it != pool.mapTx.end());
        if (it != pool.mapTx.end())
        {
            pool.CalculateTxnChainTips(it, mapTxnChainTips);
            BOOST_CHECK(mapTxnChainTips.size() == 1);

            BOOST_CHECK(mapTxnChainTips.count(pool.mapTx.find(tx21.GetId())) == 1);
        }

        mapTxnChainTips.clear();
        it = pool.mapTx.find(tx38.GetId());
        BOOST_CHECK(it != pool.mapTx.end());
        if (it != pool.mapTx.end())
        {
            pool.CalculateTxnChainTips(it, mapTxnChainTips);
            BOOST_CHECK(mapTxnChainTips.size() == 2);

            BOOST_CHECK(mapTxnChainTips.count(pool.mapTx.find(tx21.GetId())) == 1);
            BOOST_CHECK(mapTxnChainTips.count(pool.mapTx.find(tx27.GetId())) == 1);
        }

        mapTxnChainTips.clear();
        it = pool.mapTx.find(tx42.GetId());
        BOOST_CHECK(it != pool.mapTx.end());
        if (it != pool.mapTx.end())
        {
            pool.CalculateTxnChainTips(it, mapTxnChainTips);
            BOOST_CHECK(mapTxnChainTips.size() == 3);

            BOOST_CHECK(mapTxnChainTips.count(pool.mapTx.find(tx39.GetId())) == 1);
            BOOST_CHECK(mapTxnChainTips.count(pool.mapTx.find(tx40.GetId())) == 1);
            BOOST_CHECK(mapTxnChainTips.count(pool.mapTx.find(tx44.GetId())) == 1);
        }

        mapTxnChainTips.clear();
        it = pool.mapTx.find(tx48.GetId());
        BOOST_CHECK(it != pool.mapTx.end());
        if (it != pool.mapTx.end())
        {
            pool.CalculateTxnChainTips(it, mapTxnChainTips);
            BOOST_CHECK(mapTxnChainTips.size() == 3);

            BOOST_CHECK(mapTxnChainTips.count(pool.mapTx.find(tx39.GetId())) == 1);
            BOOST_CHECK(mapTxnChainTips.count(pool.mapTx.find(tx40.GetId())) == 1);
            BOOST_CHECK(mapTxnChainTips.count(pool.mapTx.find(tx44.GetId())) == 1);
        }

        mapTxnChainTips.clear();
        it = pool.mapTx.find(tx49.GetId());
        BOOST_CHECK(it != pool.mapTx.end());
        if (it != pool.mapTx.end())
        {
            pool.CalculateTxnChainTips(it, mapTxnChainTips);
            BOOST_CHECK(mapTxnChainTips.size() == 2);

            BOOST_CHECK(mapTxnChainTips.count(pool.mapTx.find(tx44.GetId())) == 1);
            BOOST_CHECK(mapTxnChainTips.count(pool.mapTx.find(tx47.GetId())) == 1);
        }
    }

    /* Do a removeforblock using tx1,tx2,tx3 and tx4 as having been mined and are in the block

    The Resulting in mempool chain should appear as shown below:

    Chain1:

    5      6   7      8
     \    /     \    /
      \  /       \  /
       9          10      20 (unmined chain so it has no entry in txnchaintips)
       | \        |       /
       |  \______ 11 ____/
       |          |\
       12         | \
      /|\        13 14     19 (unmined chain so it has no entry in txnchaintips)
     / | \        | /       /
    15 16 17      18 ______/


    Chain2:
                                                   27 (unmined chain so it has no entry in txnchaintips)
                                                   /
            ________________22_______________     /
           /         /      |      \         \   28
          /         /       23      \         \  /
         /         /       / \       \         \/
        31        32      24 25      33        29
         \         \       \ /       /         /\
          \         \       26      /         /  \
           \         \      |      /         /    \
           34_________\_____35____/_________/     30
                           / \
                          36 37
                           \ /
                            38


    Chain3:


       40 41   (39,44 and 47 were mined with 40 remaining an unmined chain, and 42,41,and 45 become txnchaintips)
       | / \
       |/   \
       42   46
       |     \
       43    45
       |       \
       48      49

    */

    // Add txns that will be mined
    std::vector<CTransactionRef> vtx;
    // Chain1:
    vtx.push_back(MakeTransactionRef(tx1));
    vtx.push_back(MakeTransactionRef(tx2));
    vtx.push_back(MakeTransactionRef(tx3));
    vtx.push_back(MakeTransactionRef(tx4));
    // Chain2:
    vtx.push_back(MakeTransactionRef(tx21));
    // Chain3:
    vtx.push_back(MakeTransactionRef(tx39));
    vtx.push_back(MakeTransactionRef(tx44));
    vtx.push_back(MakeTransactionRef(tx47));

    // Now assume they were mined and do a removeForBlock()
    std::list<CTransactionRef> dummy;
    pool.removeForBlock(vtx, 1, dummy, false);
    BOOST_CHECK_EQUAL(pool.size(), 41UL);

    // Validate the new state is correct
    //
    // After our first removeForBlock() all the transaction chain states that were dirty
    // will have been updated correctly and this will be true from this point onward.

    /* clang-format off */
    std::vector<MempoolData> txns_result =
    {
        // Chain1:
        {tx1.GetId(), 0, 0, 0, 0},
        {tx2.GetId(), 0, 0, 0, 0},
        {tx3.GetId(), 0, 0, 0, 0},
        {tx4.GetId(), 0, 0, 0, 0},

        {tx5.GetId(), 1, 66, 1, 1000},
        {tx6.GetId(), 1, 66, 1, 2000},
        {tx7.GetId(), 1, 66, 1, 3000},
        {tx8.GetId(), 1, 66, 1, 4000},
        {tx9.GetId(), 3, 257, 3, 6000},
        {tx10.GetId(), 3, 245, 3, 14000},
        {tx11.GetId(), 8, 693, 8, 35000},
        {tx12.GetId(), 4, 347, 4, 7000},
        {tx13.GetId(), 9, 759, 9, 36000},
        {tx14.GetId(), 9, 759, 9, 36000},
        {tx15.GetId(), 5, 413, 5, 7500},
        {tx16.GetId(), 5, 413, 5, 7200},
        {tx17.GetId(), 5, 413, 5, 7300},
        {tx18.GetId(), 12, 1016, 12, 45000},
        {tx19.GetId(), 1, 19, 1, 6000},
        {tx20.GetId(), 1, 19, 1, 5000},

        // Chain2:
        {tx21.GetId(), 0, 0, 0, 0},

        {tx22.GetId(), 1, 103, 1, 100000},
        {tx23.GetId(), 2, 176, 2, 120000},
        {tx24.GetId(), 3, 239, 3, 130000},
        {tx25.GetId(), 3, 239, 3, 130000},
        {tx26.GetId(), 5, 411, 5, 160000},
        {tx27.GetId(), 1, 17, 1, 101000},
        {tx28.GetId(), 2, 80, 2, 202000},
        {tx29.GetId(), 4, 302, 4, 503000},
        {tx30.GetId(), 5, 365, 5, 604000},
        {tx31.GetId(), 2, 166, 2, 120000},
        {tx32.GetId(), 2, 166, 2, 120000},
        {tx33.GetId(), 2, 166, 2, 120000},
        {tx34.GetId(), 3, 229, 3, 140000},
        {tx35.GetId(), 13, 1119, 13, 924000},
        {tx36.GetId(), 14, 1182, 14, 1124000},
        {tx37.GetId(), 14, 1182, 14, 1005000},
        {tx38.GetId(), 16, 1354, 16, 4015000},

        // Chain3:
        {tx39.GetId(), 0, 0, 0, 0},
        {tx40.GetId(), 1, 18, 1, 2000},
        {tx41.GetId(), 1, 75, 1, 6000},
        {tx42.GetId(), 3, 248, 3, 14000},
        {tx43.GetId(), 4, 311, 4, 26000},
        {tx44.GetId(), 0, 0, 0, 0},
        {tx45.GetId(), 3, 247, 3, 21000},
        {tx46.GetId(), 2, 138, 2, 9000},
        {tx47.GetId(), 0, 0, 0, 0},
        {tx48.GetId(), 5, 374, 5, 41000},
        {tx49.GetId(), 4, 310, 4, 35000}
    };
    /* clang-format on */

    for (size_t i = 0; i < txns_result.size(); i++)
    {
        if (i < 4 || i == 20 || i == 38 || i == 43 || i == 46)
        {
            VerifyTxNotInMempool(txns_result[i], pool);
            continue;
        }
        CheckAncestors(txns_result[i], pool);
    }

    // Mine two transactions which end up giving us the same txnchaintip.
    vtx.push_back(MakeTransactionRef(tx40));
    vtx.push_back(MakeTransactionRef(tx41));
    pool.removeForBlock(vtx, 1, dummy, false);
    BOOST_CHECK_EQUAL(pool.size(), 39UL);


    /* clang-format off */
    std::vector<MempoolData> txns_result2 =
    {
        // Chain3:
        {tx39.GetId(), 0, 0, 0, 0},
        {tx40.GetId(), 0, 0, 0, 0},
        {tx41.GetId(), 0, 0, 0, 0},
        {tx42.GetId(), 1, 155, 1, 6000},
        {tx43.GetId(), 2, 218, 2, 18000},
        {tx44.GetId(), 0, 0, 0, 0},
        {tx45.GetId(), 2, 172, 2, 15000},
        {tx46.GetId(), 1, 63, 1, 3000},
        {tx47.GetId(), 0, 0, 0, 0},
        {tx48.GetId(), 3, 281, 3, 33000},
        {tx49.GetId(), 3, 235, 3, 29000}
    };
    /* clang-format on */

    for (size_t i = 0; i < txns_result2.size(); i++)
    {
        if (i <= 2 || i == 5 || i == 8)
        {
            VerifyTxNotInMempool(txns_result2[i], pool);
            continue;
        }

        CheckAncestors(txns_result2[i], pool);
    }

    // Starting to simulate mining all the rest of the transactions in the chains defined in the
    // above tests and following that with a mempool consistency
    vtx.push_back(MakeTransactionRef(tx5));
    vtx.push_back(MakeTransactionRef(tx6));
    vtx.push_back(MakeTransactionRef(tx7));
    pool.removeForBlock(vtx, 1, dummy, false);
    BOOST_CHECK_EQUAL(pool.size(), 36UL);

    /* clang-format off */
    std::vector<MempoolData> txns_result3 =
    {
        // Chain1:
        {tx1.GetId(), 0, 0, 0, 0},
        {tx2.GetId(), 0, 0, 0, 0},
        {tx3.GetId(), 0, 0, 0, 0},
        {tx4.GetId(), 0, 0, 0, 0},
        {tx5.GetId(), 0, 0, 0, 0},
        {tx6.GetId(), 0, 0, 0, 0},
        {tx7.GetId(), 0, 0, 0, 0},

        {tx8.GetId(), 1, 66, 1, 4000},
        {tx9.GetId(), 1, 125, 1, 3000},
        {tx10.GetId(), 2, 179, 2, 11000},
        {tx11.GetId(), 5, 495, 5, 29000},
        {tx12.GetId(), 2, 215, 2, 4000},
        {tx13.GetId(), 6, 561, 6, 30000},
        {tx14.GetId(), 6, 561, 6, 30000},
        {tx15.GetId(), 3, 281, 3, 4500},
        {tx16.GetId(), 3, 281, 3, 4200},
        {tx17.GetId(), 3, 281, 3, 4300},
        {tx18.GetId(), 9, 818, 9, 39000},
        {tx19.GetId(), 1, 19, 1, 6000},
        {tx20.GetId(), 1, 19, 1, 5000},
    };
    /* clang-format on */

    for (size_t i = 0; i < txns_result3.size(); i++)
    {
        if (i < 7)
        {
            VerifyTxNotInMempool(txns_result3[i], pool);
            continue;
        }
        CheckAncestors(txns_result3[i], pool);
    }


    vtx.push_back(MakeTransactionRef(tx8));
    vtx.push_back(MakeTransactionRef(tx9));
    vtx.push_back(MakeTransactionRef(tx10));
    pool.removeForBlock(vtx, 1, dummy, false);
    BOOST_CHECK_EQUAL(pool.size(), 33UL);

    /* clang-format off */
    std::vector<MempoolData> txns_result4 =
    {
        // Chain1:
        {tx1.GetId(), 0, 0, 0, 0},
        {tx2.GetId(), 0, 0, 0, 0},
        {tx3.GetId(), 0, 0, 0, 0},
        {tx4.GetId(), 0, 0, 0, 0},
        {tx5.GetId(), 0, 0, 0, 0},
        {tx6.GetId(), 0, 0, 0, 0},
        {tx7.GetId(), 0, 0, 0, 0},
        {tx8.GetId(), 0, 0, 0, 0},
        {tx9.GetId(), 0, 0, 0, 0},
        {tx10.GetId(), 0, 0, 0, 0},

        {tx11.GetId(), 2, 191, 2, 15000},
        {tx12.GetId(), 1, 90, 1, 1000},
        {tx13.GetId(), 3, 257, 3, 16000},
        {tx14.GetId(), 3, 257, 3, 16000},
        {tx15.GetId(), 2, 156, 2, 1500},
        {tx16.GetId(), 2, 156, 2, 1200},
        {tx17.GetId(), 2, 156, 2, 1300},
        {tx18.GetId(), 6, 514, 6, 25000},
        {tx19.GetId(), 1, 19, 1, 6000},
        {tx20.GetId(), 1, 19, 1, 5000},
    };
    /* clang-format on */

    for (size_t i = 0; i < txns_result4.size(); i++)
    {
        if (i < 10)
        {
            VerifyTxNotInMempool(txns_result4[i], pool);
            continue;
        }
        CheckAncestors(txns_result4[i], pool);
    }


    vtx.push_back(MakeTransactionRef(tx11));
    vtx.push_back(MakeTransactionRef(tx14));
    vtx.push_back(MakeTransactionRef(tx20));
    pool.removeForBlock(vtx, 1, dummy, false);
    BOOST_CHECK_EQUAL(pool.size(), 30UL);

    /* clang-format off */
    std::vector<MempoolData> txns_result5 =
    {
        // Chain1:
        {tx1.GetId(), 0, 0, 0, 0},
        {tx2.GetId(), 0, 0, 0, 0},
        {tx3.GetId(), 0, 0, 0, 0},
        {tx4.GetId(), 0, 0, 0, 0},
        {tx5.GetId(), 0, 0, 0, 0},
        {tx6.GetId(), 0, 0, 0, 0},
        {tx7.GetId(), 0, 0, 0, 0},
        {tx8.GetId(), 0, 0, 0, 0},
        {tx9.GetId(), 0, 0, 0, 0},
        {tx10.GetId(), 0, 0, 0, 0},
        {tx11.GetId(), 0, 0, 0, 0},
        {tx12.GetId(), 1, 90, 1, 1000},
        {tx13.GetId(), 1, 66, 1, 1000},
        {tx14.GetId(), 0, 0, 0, 0},
        {tx15.GetId(), 2, 156, 2, 1500},
        {tx16.GetId(), 2, 156, 2, 1200},
        {tx17.GetId(), 2, 156, 2, 1300},
        {tx18.GetId(), 3, 257, 3, 9000},
        {tx19.GetId(), 1, 19, 1, 6000},
        {tx20.GetId(), 0, 0, 0, 0}
    };
    /* clang-format on */

    for (size_t i = 0; i < txns_result5.size(); i++)
    {
        if (i < 11 || i == 13 || i == 19)
        {
            VerifyTxNotInMempool(txns_result5[i], pool);
            continue;
        }
        CheckAncestors(txns_result5[i], pool);
    }

    vtx.push_back(MakeTransactionRef(tx12));
    vtx.push_back(MakeTransactionRef(tx13));
    vtx.push_back(MakeTransactionRef(tx15));
    pool.removeForBlock(vtx, 1, dummy, false);
    BOOST_CHECK_EQUAL(pool.size(), 27UL);

    /* clang-format off */
    std::vector<MempoolData> txns_result6 =
    {
        // Chain1:
        {tx1.GetId(), 0, 0, 0, 0},
        {tx2.GetId(), 0, 0, 0, 0},
        {tx3.GetId(), 0, 0, 0, 0},
        {tx4.GetId(), 0, 0, 0, 0},
        {tx5.GetId(), 0, 0, 0, 0},
        {tx6.GetId(), 0, 0, 0, 0},
        {tx7.GetId(), 0, 0, 0, 0},
        {tx8.GetId(), 0, 0, 0, 0},
        {tx9.GetId(), 0, 0, 0, 0},
        {tx10.GetId(), 0, 0, 0, 0},
        {tx11.GetId(), 0, 0, 0, 0},
        {tx12.GetId(), 0, 0, 0, 0},
        {tx13.GetId(), 0, 0, 0, 0},
        {tx14.GetId(), 0, 0, 0, 0},
        {tx15.GetId(), 0, 0, 0, 0},
        {tx16.GetId(), 1, 66, 1, 200},
        {tx17.GetId(), 1, 66, 1, 300},
        {tx18.GetId(), 2, 191, 2, 8000},
        {tx19.GetId(), 1, 19, 1, 6000},
        {tx20.GetId(), 0, 0, 0, 0}
    };
    /* clang-format on */

    for (size_t i = 0; i < txns_result6.size(); i++)
    {
        if (i < 15 || i == 19)
        {
            VerifyTxNotInMempool(txns_result6[i], pool);
            continue;
        }
        CheckAncestors(txns_result6[i], pool);
    }

    // The following is one of the most important edge conditions. Where we remove the first transaction
    // in a graph that has an enclosure. An enclosure being where a transaction has many outputs
    // and eventually results in other transactions that are inputs to a single transactions.
    /*
       for example:
                            22
                            |
                            23
                           / \
                          24 25
                           \ /
                            26

       after mining 22 and 23 becomes:


                          24 25
                           \ /
                            26
    */

    vtx.push_back(MakeTransactionRef(tx22));
    vtx.push_back(MakeTransactionRef(tx23));
    pool.removeForBlock(vtx, 1, dummy, false);
    BOOST_CHECK_EQUAL(pool.size(), 25UL);

    /* clang-format off */
    std::vector<MempoolData> txns_result7 =
    {
        // Chain2:
        {tx21.GetId(), 0, 0, 0, 0},
        {tx22.GetId(), 0, 0, 0, 0},
        {tx23.GetId(), 0, 0, 0, 0},

        {tx24.GetId(), 1, 63, 1, 10000},
        {tx25.GetId(), 1, 63, 1, 10000},
        {tx26.GetId(), 3, 235, 3, 40000},
        {tx27.GetId(), 1, 17, 1, 101000},
        {tx28.GetId(), 2, 80, 2, 202000},
        {tx29.GetId(), 3, 199, 3, 403000},
        {tx30.GetId(), 4, 262, 4, 504000},
        {tx31.GetId(), 1, 63, 1, 20000},
        {tx32.GetId(), 1, 63, 1, 20000},
        {tx33.GetId(), 1, 63, 1, 20000},
        {tx34.GetId(), 2, 126, 2, 40000},
        {tx35.GetId(), 11, 943, 11, 804000},
        {tx36.GetId(), 12, 1006, 12, 1004000},
        {tx37.GetId(), 12, 1006, 12, 885000},
        {tx38.GetId(), 14, 1178, 14, 3895000},
    };
    /* clang-format on */

    for (size_t i = 0; i < txns_result7.size(); i++)
    {
        if (i <= 2)
        {
            VerifyTxNotInMempool(txns_result7[i], pool);
            continue;
        }
        CheckAncestors(txns_result7[i], pool);
    }


    vtx.push_back(MakeTransactionRef(tx31));
    vtx.push_back(MakeTransactionRef(tx33));
    vtx.push_back(MakeTransactionRef(tx34));
    pool.removeForBlock(vtx, 1, dummy, false);
    BOOST_CHECK_EQUAL(pool.size(), 22UL);

    /* clang-format off */
    std::vector<MempoolData> txns_result8 =
    {
        // Chain2:
        {tx21.GetId(), 0, 0, 0, 0},
        {tx22.GetId(), 0, 0, 0, 0},
        {tx23.GetId(), 0, 0, 0, 0},
        {tx24.GetId(), 1, 63, 1, 10000},
        {tx25.GetId(), 1, 63, 1, 10000},
        {tx26.GetId(), 3, 235, 3, 40000},
        {tx27.GetId(), 1, 17, 1, 101000},
        {tx28.GetId(), 2, 80, 2, 202000},
        {tx29.GetId(), 3, 199, 3, 403000},
        {tx30.GetId(), 4, 262, 4, 504000},
        {tx31.GetId(), 0, 0, 0, 0},
        {tx32.GetId(), 1, 63, 1, 20000},
        {tx33.GetId(), 0, 0, 0, 0},
        {tx34.GetId(), 0, 0, 0, 0},
        {tx35.GetId(), 8, 754, 8, 744000},
        {tx36.GetId(), 9, 817, 9, 944000},
        {tx37.GetId(), 9, 817, 9, 825000},
        {tx38.GetId(), 11, 989, 11, 3835000},
    };
    /* clang-format on */

    for (size_t i = 0; i < txns_result8.size(); i++)
    {
        if (i <= 2 || i == 10 || i == 12 || i == 13)
        {
            VerifyTxNotInMempool(txns_result8[i], pool);
            continue;
        }
        CheckAncestors(txns_result8[i], pool);
    }

    vtx.push_back(MakeTransactionRef(tx24));
    vtx.push_back(MakeTransactionRef(tx25));
    vtx.push_back(MakeTransactionRef(tx27));
    vtx.push_back(MakeTransactionRef(tx28));
    pool.removeForBlock(vtx, 1, dummy, false);
    BOOST_CHECK_EQUAL(pool.size(), 18UL);

    /* clang-format off */
    std::vector<MempoolData> txns_result9 =
    {
        // Chain2:
        {tx21.GetId(), 0, 0, 0, 0},
        {tx22.GetId(), 0, 0, 0, 0},
        {tx23.GetId(), 0, 0, 0, 0},
        {tx24.GetId(), 0, 0, 0, 0},
        {tx25.GetId(), 0, 0, 0, 0},
        {tx26.GetId(), 1, 109, 1, 20000},
        {tx27.GetId(), 0, 0, 0, 0},
        {tx28.GetId(), 0, 0, 0, 0},
        {tx29.GetId(), 1, 119, 1, 201000},
        {tx30.GetId(), 2, 182, 2, 302000},
        {tx31.GetId(), 0, 0, 0, 0},
        {tx32.GetId(), 1, 63, 1, 20000},
        {tx33.GetId(), 0, 0, 0, 0},
        {tx34.GetId(), 0, 0, 0, 0},
        {tx35.GetId(), 4, 548, 4, 522000},
        {tx36.GetId(), 5, 611, 5, 722000},
        {tx37.GetId(), 5, 611, 5, 603000},
        {tx38.GetId(), 7, 783, 7, 3613000},
    };
    pool.removeForBlock(vtx, 1, dummy, false);
    BOOST_CHECK_EQUAL(pool.size(), 18UL);

    /* clang-format on */

    for (size_t i = 0; i < txns_result9.size(); i++)
    {
        if (i <= 4 || i == 6 || i == 7 || i == 10 || i == 12 || i == 13)
        {
            VerifyTxNotInMempool(txns_result9[i], pool);
            continue;
        }
        CheckAncestors(txns_result9[i], pool);
    }

    vtx.push_back(MakeTransactionRef(tx26));
    vtx.push_back(MakeTransactionRef(tx29));
    vtx.push_back(MakeTransactionRef(tx32));
    vtx.push_back(MakeTransactionRef(tx35));
    pool.removeForBlock(vtx, 1, dummy, false);
    BOOST_CHECK_EQUAL(pool.size(), 14UL);

    /* clang-format off */
    std::vector<MempoolData> txns_result10 =
    {
        // Chain2:
        {tx21.GetId(), 0, 0, 0, 0},
        {tx22.GetId(), 0, 0, 0, 0},
        {tx23.GetId(), 0, 0, 0, 0},
        {tx24.GetId(), 0, 0, 0, 0},
        {tx25.GetId(), 0, 0, 0, 0},
        {tx26.GetId(), 0, 0, 0, 0},
        {tx27.GetId(), 0, 0, 0, 0},
        {tx28.GetId(), 0, 0, 0, 0},
        {tx29.GetId(), 0, 0, 0, 0},
        {tx30.GetId(), 1, 63, 1, 101000},
        {tx31.GetId(), 0, 0, 0, 0},
        {tx32.GetId(), 0, 0, 0, 0},
        {tx33.GetId(), 0, 0, 0, 0},
        {tx34.GetId(), 0, 0, 0, 0},
        {tx35.GetId(), 0, 0, 0, 0},
        {tx36.GetId(), 1, 63, 1, 200000},
        {tx37.GetId(), 1, 63, 1, 81000},
        {tx38.GetId(), 3, 235, 3, 3091000},
    };
    /* clang-format on */

    for (size_t i = 0; i < txns_result10.size(); i++)
    {
        if (i <= 8 || (i >= 10 && i <= 14))
        {
            VerifyTxNotInMempool(txns_result10[i], pool);
            continue;
        }

        /*
        printf(
            "tx%ld countwanc %ld sizewanc %ld sigopswanc %u feeswanc %ld\n",
            i + 1, iter->GetCountWithAncestors(), iter->GetSizeWithAncestors(), iter->GetSigOpCountWithAncestors(),
            iter->GetModFeesWithAncestors());
        printf("tx%d: hash %s\n", (int)(i + 1), iter->GetTx().GetId().ToString().c_str());
        */

        CheckAncestors(txns_result10[i], pool);
    }


    // Resubmit all transactions from chain2 to the mempool but with the mempool test flag off
    // This should result in all transactions being updated correctly and not be dirty
    fMempoolTests.store(false);

    // Remove rest of the transactions from the mempool
    vtx.push_back(MakeTransactionRef(tx16));
    vtx.push_back(MakeTransactionRef(tx17));
    vtx.push_back(MakeTransactionRef(tx18));
    vtx.push_back(MakeTransactionRef(tx19));
    vtx.push_back(MakeTransactionRef(tx26));
    vtx.push_back(MakeTransactionRef(tx29));
    vtx.push_back(MakeTransactionRef(tx30));
    vtx.push_back(MakeTransactionRef(tx32));
    vtx.push_back(MakeTransactionRef(tx35));
    vtx.push_back(MakeTransactionRef(tx36));
    vtx.push_back(MakeTransactionRef(tx37));
    vtx.push_back(MakeTransactionRef(tx38));
    vtx.push_back(MakeTransactionRef(tx42));
    vtx.push_back(MakeTransactionRef(tx43));
    vtx.push_back(MakeTransactionRef(tx44));
    vtx.push_back(MakeTransactionRef(tx45));
    vtx.push_back(MakeTransactionRef(tx46));
    vtx.push_back(MakeTransactionRef(tx47));
    vtx.push_back(MakeTransactionRef(tx48));
    vtx.push_back(MakeTransactionRef(tx49));
    pool.removeForBlock(vtx, 1, dummy, false);
    BOOST_CHECK_EQUAL(pool.size(), 0UL);


    /*
    Chain1:

    1      2   3      4
    |      |   |      |
    5      6   7      8
     \    /     \    /
      \  /       \  /
       9          10      20
       | \        |       /
       |  \______ 11 ____/
       |          |\
       12         | \
      /|\        13 14      19
     / | \        | /       /
    15 16 17      18 ______/

    */

    // Chain:1 Transactions

    // tx1
    pool.addUnchecked(entry.Fee(1000LL).Priority(10.0).SigOps(1).FromTx(tx1));

    // tx2
    pool.addUnchecked(entry.Fee(2000LL).Priority(10.0).SigOps(1).FromTx(tx2));

    // tx3
    pool.addUnchecked(entry.Fee(3000LL).Priority(10.0).SigOps(1).FromTx(tx3));

    // tx4
    pool.addUnchecked(entry.Fee(4000LL).Priority(10.0).SigOps(1).FromTx(tx4));

    // tx5 - child of tx1
    pool.addUnchecked(entry.Fee(1000LL).Priority(10.0).SigOps(1).FromTx(tx5));

    // tx6 - child of tx2
    pool.addUnchecked(entry.Fee(2000LL).Priority(10.0).SigOps(1).FromTx(tx6));

    // tx7 - child of tx3
    pool.addUnchecked(entry.Fee(3000LL).Priority(10.0).SigOps(1).FromTx(tx7));

    // tx8 - child of tx4
    pool.addUnchecked(entry.Fee(4000LL).Priority(10.0).SigOps(1).FromTx(tx8));

    // tx9 - child of tx5 and tx6 and has two outputs
    pool.addUnchecked(entry.Fee(3000LL).Priority(10.0).SigOps(1).FromTx(tx9));

    // tx10 - child of tx7 and tx8 and has one output
    pool.addUnchecked(entry.Fee(7000LL).SigOps(1).FromTx(tx10));

    // tx20
    pool.addUnchecked(entry.Fee(5000LL).Priority(10.0).SigOps(1).FromTx(tx20));

    // tx11 - child of tx9, tx10 and tx20, and has two outputs
    pool.addUnchecked(entry.Fee(10000LL).SigOps(1).FromTx(tx11));

    // tx12 - child of tx9 and has three outputs
    pool.addUnchecked(entry.Fee(1000LL).Priority(10.0).SigOps(1).FromTx(tx12));

    // tx13 - child of tx11 and has one output
    pool.addUnchecked(entry.Fee(1000LL).SigOps(1).FromTx(tx13));

    // tx14 - child of tx11 and has one output
    pool.addUnchecked(entry.Fee(1000LL).SigOps(1).FromTx(tx14));

    // tx15 - child of tx12
    pool.addUnchecked(entry.Fee(500LL).SigOps(1).FromTx(tx15));

    // tx16 - child of tx12
    pool.addUnchecked(entry.Fee(200LL).SigOps(1).FromTx(tx16));

    // tx17 - child of tx12
    pool.addUnchecked(entry.Fee(300LL).SigOps(1).FromTx(tx17));

    // tx19
    pool.addUnchecked(entry.Fee(6000LL).Priority(10.0).SigOps(1).FromTx(tx19));

    // tx18 - child of tx13, tx14 and 19, and has two outputs
    pool.addUnchecked(entry.Fee(2000LL).SigOps(1).FromTx(tx18));


    // Chain:2 Transactions
    /*

                            21                     27
                            |                      /
            ________________22_______________     /
           /         /      |      \         \   28
          /         /       23      \         \  /
         /         /       / \       \         \/
        31        32      24 25      33        29
         \         \       \ /       /         /\
          \         \       26      /         /  \
           \         \      |      /         /    \
           34_________\_____35____/_________/     30
                           / \
                          36 37
                           \ /
                            38
    */

    // tx21
    pool.addUnchecked(entry.Fee(100000LL).Priority(10.0).SigOps(1).FromTx(tx21));

    // tx22 - child of tx21 and has 5 outputs
    pool.addUnchecked(entry.Fee(100000LL).Priority(10.0).SigOps(1).FromTx(tx22));

    // tx23 - child of tx22 and has two outputs
    pool.addUnchecked(entry.Fee(20000LL).Priority(10.0).SigOps(1).FromTx(tx23));

    // tx24 - child of tx23 and has one output
    pool.addUnchecked(entry.Fee(10000LL).SigOps(1).FromTx(tx24));

    // tx25 - child of tx23 and has one output
    pool.addUnchecked(entry.Fee(10000LL).SigOps(1).FromTx(tx25));

    // tx26 - child of tx24 and tx25 and has one output
    pool.addUnchecked(entry.Fee(20000LL).SigOps(1).FromTx(tx26));

    // tx27
    pool.addUnchecked(entry.Fee(101000LL).Priority(10.0).SigOps(1).FromTx(tx27));

    // tx28 - child of tx27 and has one output
    pool.addUnchecked(entry.Fee(101000LL).SigOps(1).FromTx(tx28));

    // tx29 - child of tx22 and tx28 and has two outputs
    pool.addUnchecked(entry.Fee(201000LL).Priority(10.0).SigOps(1).FromTx(tx29));

    // tx30 - child of tx29 and has one output
    pool.addUnchecked(entry.Fee(101000LL).SigOps(1).FromTx(tx30));

    // tx31 - child of tx22 and has one output
    pool.addUnchecked(entry.Fee(20000LL).SigOps(1).FromTx(tx31));

    // tx32 - child of tx22 and has one output
    pool.addUnchecked(entry.Fee(20000LL).SigOps(1).FromTx(tx32));

    // tx33 - child of tx22 and has one output
    pool.addUnchecked(entry.Fee(20000LL).SigOps(1).FromTx(tx33));

    // tx34 - child of tx31 and has one output
    pool.addUnchecked(entry.Fee(20000LL).SigOps(1).FromTx(tx34));

    // tx35 - child of tx26, tx29, tx32, tx33, tx34 and has two outputs
    pool.addUnchecked(entry.Fee(281000LL).Priority(10.0).SigOps(1).FromTx(tx35));

    // tx36 - child of tx35 and has one output
    pool.addUnchecked(entry.Fee(200000LL).SigOps(1).FromTx(tx36));

    // tx37 - child of tx35 and has one output
    pool.addUnchecked(entry.Fee(81000LL).SigOps(1).FromTx(tx37));

    // tx38 - child of tx36 and tx37 and has one output
    pool.addUnchecked(entry.Fee(2810000LL).SigOps(1).FromTx(tx38));

    /*
    Chain3:  we will mine txn 39, 44 and 47

           44
           /
    39 40 41
     \ | / \
      \|/   \   47
       42   46  /
       |     \ /
       43    45
       |       \
       48      49

    */

    // tx39
    pool.addUnchecked(entry.Fee(1000LL).Priority(10.0).SigOps(1).FromTx(tx39));

    // tx40
    pool.addUnchecked(entry.Fee(2000LL).Priority(10.0).SigOps(1).FromTx(tx40));

    // tx44
    pool.addUnchecked(entry.Fee(4000LL).Priority(10.0).SigOps(1).FromTx(tx44));

    // tx41
    pool.addUnchecked(entry.Fee(6000LL).Priority(10.0).SigOps(1).FromTx(tx41));

    // tx42 - child of tx39, tx40 and tx41 and has one output
    pool.addUnchecked(entry.Fee(6000LL).SigOps(1).FromTx(tx42));

    // tx43 - child of tx42 and has one output
    pool.addUnchecked(entry.Fee(12000LL).SigOps(1).FromTx(tx43));

    // tx48 child of tx43
    pool.addUnchecked(entry.Fee(15000LL).Priority(10.0).SigOps(1).FromTx(tx48));

    // tx47
    pool.addUnchecked(entry.Fee(10000LL).Priority(10.0).SigOps(1).FromTx(tx47));

    // tx46 child of tx41
    pool.addUnchecked(entry.Fee(3000LL).Priority(10.0).SigOps(1).FromTx(tx46));

    // tx45 - child of tx46 and tx47 and has one output
    pool.addUnchecked(entry.Fee(12000LL).SigOps(1).FromTx(tx45));

    // tx49 child of tx45
    pool.addUnchecked(entry.Fee(14000LL).Priority(10.0).SigOps(1).FromTx(tx49));

    // Validate the current state is correct
    /* clang-format off */
    BOOST_CHECK_EQUAL(pool.size(), 49UL);
    std::vector<MempoolData> txns_fully_updated =
    {
        // Chain1:
        {tx1.GetId(), 1, 19, 1, 1000},
        {tx2.GetId(), 1, 19, 1, 2000},
        {tx3.GetId(), 1, 19, 1, 3000},
        {tx4.GetId(), 1, 19, 1, 4000},
        {tx5.GetId(), 2, 85, 2, 2000},
        {tx6.GetId(), 2, 85, 2, 4000},
        {tx7.GetId(), 2, 85, 2, 6000},
        {tx8.GetId(), 2, 85, 2, 8000},
        {tx9.GetId(), 5, 295, 5, 9000},
        {tx10.GetId(), 5, 283, 5, 21000},
        {tx11.GetId(), 12, 769, 12, 45000},
        {tx12.GetId(), 6, 385, 6, 10000},
        {tx13.GetId(), 13, 835, 13, 46000},
        {tx14.GetId(), 13, 835, 13, 46000},
        {tx15.GetId(), 7, 451, 7, 10500},
        {tx16.GetId(), 7, 451, 7, 10200},
        {tx17.GetId(), 7, 451, 7, 10300},
        {tx18.GetId(), 16, 1092, 16, 55000},
        {tx19.GetId(), 1, 19, 1, 6000},
        {tx20.GetId(), 1, 19, 1, 5000},

        // Chain2:
        {tx21.GetId(), 1, 17, 1, 100000},
        {tx22.GetId(), 2, 120, 2, 200000},
        {tx23.GetId(), 3, 193, 3, 220000},
        {tx24.GetId(), 4, 256, 4, 230000},
        {tx25.GetId(), 4, 256, 4, 230000},
        {tx26.GetId(), 6, 428, 6, 260000},
        {tx27.GetId(), 1, 17, 1, 101000},
        {tx28.GetId(), 2, 80, 2, 202000},
        {tx29.GetId(), 5, 319, 5, 603000},
        {tx30.GetId(), 6, 382, 6, 704000},
        {tx31.GetId(), 3, 183, 3, 220000},
        {tx32.GetId(), 3, 183, 3, 220000},
        {tx33.GetId(), 3, 183, 3, 220000},
        {tx34.GetId(), 4, 246, 4, 240000},
        {tx35.GetId(), 14, 1136, 14, 1024000},
        {tx36.GetId(), 15, 1199, 15, 1224000},
        {tx37.GetId(), 15, 1199, 15, 1105000},
        {tx38.GetId(), 17, 1371, 17, 4115000},

        // Chain3:
        {tx39.GetId(), 1, 18, 1, 1000},
        {tx40.GetId(), 1, 18, 1, 2000},
        {tx41.GetId(), 2, 93, 2, 10000},
        {tx42.GetId(), 5, 284, 5, 19000},
        {tx43.GetId(), 6, 347, 6, 31000},
        {tx44.GetId(), 1, 18, 1, 4000},
        {tx45.GetId(), 5, 282, 5, 35000},
        {tx46.GetId(), 3, 156, 3, 13000},
        {tx47.GetId(), 1, 17, 1, 10000},
        {tx48.GetId(), 7, 410, 7, 46000},
        {tx49.GetId(), 6, 345, 6, 49000}
    };
    /* clang-format on */
    for (size_t i = 0; i < txns_fully_updated.size(); i++)
    {
        CTxMemPool::TxIdIter iter = pool.mapTx.find(txns_fully_updated[i].hash);
        if (iter == pool.mapTx.end())
        {
            printf("ERROR: tx %s not found in mempool\n", txns_fully_updated[i].hash.ToString().c_str());
            throw;
        }
        CheckAncestors(txns_fully_updated[i], pool);
    }
}


BOOST_AUTO_TEST_CASE(MempoolRemoveTest)
{
    // Test CTxMemPool::remove functionality

    TestMemPoolEntryHelper entry;
    // Parent transaction with three children,
    // and three grand-children:
    CMutableTransaction txParent;
    txParent.vin.resize(1);
    txParent.vin[0].scriptSig = CScript() << OP_11;
    txParent.vout.resize(3);
    for (int i = 0; i < 3; i++)
    {
        txParent.vout[i].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
        txParent.vout[i].nValue = 33000LL;
    }
    CMutableTransaction txChild[3];
    for (int i = 0; i < 3; i++)
    {
        txChild[i].vin.resize(1);
        txChild[i].vin[0].scriptSig = CScript() << OP_11;
        txChild[i].vin[0].prevout = txParent.OutpointAt(i);
        txChild[i].vout.resize(1);
        txChild[i].vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
        txChild[i].vout[0].nValue = 11000LL;
    }
    CMutableTransaction txGrandChild[3];
    for (int i = 0; i < 3; i++)
    {
        txGrandChild[i].vin.resize(1);
        txGrandChild[i].vin[0].scriptSig = CScript() << OP_11;
        txGrandChild[i].vin[0].prevout = txChild[i].OutpointAt(0);
        txGrandChild[i].vout.resize(1);
        txGrandChild[i].vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
        txGrandChild[i].vout[0].nValue = 11000LL;
    }


    CTxMemPool testPool;
    std::list<CTransactionRef> removed;

    // Nothing in pool, remove should do nothing:
    testPool.removeRecursive(txParent, removed);
    BOOST_CHECK_EQUAL(removed.size(), 0UL);

    // Just the parent:
    testPool.addUnchecked(entry.FromTx(txParent));
    testPool.removeRecursive(txParent, removed);
    BOOST_CHECK_EQUAL(removed.size(), 1UL);
    removed.clear();

    // Parent, children, grandchildren:
    testPool.addUnchecked(entry.FromTx(txParent));
    for (int i = 0; i < 3; i++)
    {
        testPool.addUnchecked(entry.FromTx(txChild[i]));
        testPool.addUnchecked(entry.FromTx(txGrandChild[i]));
    }
    // Remove Child[0], GrandChild[0] should be removed:
    testPool.removeRecursive(txChild[0], removed);
    BOOST_CHECK_EQUAL(removed.size(), 2UL);
    removed.clear();
    // ... make sure grandchild and child are gone:
    testPool.removeRecursive(txGrandChild[0], removed);
    BOOST_CHECK_EQUAL(removed.size(), 0UL);
    testPool.removeRecursive(txChild[0], removed);
    BOOST_CHECK_EQUAL(removed.size(), 0UL);
    // Remove parent, all children/grandchildren should go:
    testPool.removeRecursive(txParent, removed);
    BOOST_CHECK_EQUAL(removed.size(), 5UL);
    BOOST_CHECK_EQUAL(testPool.size(), 0UL);
    removed.clear();

    // Add children and grandchildren, but NOT the parent (simulate the parent being in a block)
    for (int i = 0; i < 3; i++)
    {
        testPool.addUnchecked(entry.FromTx(txChild[i]));
        testPool.addUnchecked(entry.FromTx(txGrandChild[i]));
    }
    // Now remove the parent, as might happen if a block-re-org occurs but the parent cannot be
    // put into the mempool (maybe because it is non-standard):
    testPool.removeRecursive(txParent, removed);
    BOOST_CHECK_EQUAL(removed.size(), 6UL);
    BOOST_CHECK_EQUAL(testPool.size(), 0UL);
    removed.clear();
}

template <typename name>
void CheckSort(CTxMemPool &pool, std::vector<std::string> &sortedOrder)
{
    BOOST_CHECK_EQUAL(pool.size(), sortedOrder.size());
    typename CTxMemPool::indexed_transaction_set::index<name>::type::iterator it = pool.mapTx.get<name>().begin();
    int count = 0;
    for (; it != pool.mapTx.get<name>().end(); ++it, ++count)
    {
        BOOST_CHECK_EQUAL(it->GetTx().GetId().ToString(), sortedOrder[count]);
    }
}

template <typename name>
void _CheckSort(CTxMemPool &pool, std::vector<std::string> &sortedOrder)
{
    BOOST_CHECK_EQUAL(pool._size(), sortedOrder.size());
    typename CTxMemPool::indexed_transaction_set::index<name>::type::iterator it = pool.mapTx.get<name>().begin();
    int count = 0;
    for (; it != pool.mapTx.get<name>().end(); ++it, ++count)
    {
        BOOST_CHECK_EQUAL(it->GetTx().GetId().ToString(), sortedOrder[count]);
    }
}

BOOST_AUTO_TEST_CASE(MempoolAncestorIndexingTest)
{
    CTxMemPool pool;
    TestMemPoolEntryHelper entry;
    entry.hadNoDependencies = true;

    /* 3rd highest fee */
    CMutableTransaction tx1 = CMutableTransaction();
    tx1.vout.resize(1);
    tx1.vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx1.vout[0].nValue = 10 * COIN;
    pool.addUnchecked(entry.Fee(10000LL).Time(GetTime() + 1).Priority(10.0).FromTx(tx1));

    /* highest fee */
    CMutableTransaction tx2 = CMutableTransaction();
    tx2.vout.resize(1);
    tx2.vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx2.vout[0].nValue = 2 * COIN;
    pool.addUnchecked(entry.Fee(20000LL).Time(GetTime() + 2).Priority(9.0).FromTx(tx2));
    uint64_t tx2Size = ::GetSerializeSize(tx2, SER_NETWORK, PROTOCOL_VERSION);

    /* lowest fee */
    CMutableTransaction tx3 = CMutableTransaction();
    tx3.vout.resize(1);
    tx3.vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx3.vout[0].nValue = 5 * COIN;
    pool.addUnchecked(entry.Fee(0LL).Time(GetTime() + 3).Priority(100.0).FromTx(tx3));

    /* 2nd highest fee */
    CMutableTransaction tx4 = CMutableTransaction();
    tx4.vout.resize(1);
    tx4.vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx4.vout[0].nValue = 6 * COIN;
    pool.addUnchecked(entry.Fee(15000LL).Time(GetTime() + 4).Priority(1.0).FromTx(tx4));

    /* equal fee rate to tx1, but newer */
    CMutableTransaction tx5 = CMutableTransaction();
    tx5.vout.resize(1);
    tx5.vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx5.vout[0].nValue = 11 * COIN;
    pool.addUnchecked(entry.Fee(10000LL).Time(GetTime() + 5).FromTx(tx5));
    BOOST_CHECK_EQUAL(pool.size(), 5UL);

    std::vector<std::string> sortedOrder;
    sortedOrder.resize(5);
    sortedOrder[0] = tx2.GetId().ToString(); // 20000
    sortedOrder[1] = tx4.GetId().ToString(); // 15000
    // tx1 and tx5 are both 10000
    // Ties are broken by timestamp, so determine which
    // time comes first.
    sortedOrder[2] = tx1.GetId().ToString();
    sortedOrder[3] = tx5.GetId().ToString();
    sortedOrder[4] = tx3.GetId().ToString(); // 0

    CheckSort<ancestor_score>(pool, sortedOrder);

    /* low fee parent with high fee child */
    /* tx6 (0) -> tx7 (high) */
    CMutableTransaction tx6 = CMutableTransaction();
    tx6.vout.resize(1);
    tx6.vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx6.vout[0].nValue = 20 * COIN;
    uint64_t tx6Size = ::GetSerializeSize(tx6, SER_NETWORK, PROTOCOL_VERSION);

    pool.addUnchecked(entry.Fee(0LL).Time(GetTime() + 6).FromTx(tx6));
    BOOST_CHECK_EQUAL(pool.size(), 6UL);
    // Ties are broken by time
    sortedOrder.push_back(tx6.GetId().ToString());
    CheckSort<ancestor_score>(pool, sortedOrder);

    CMutableTransaction tx7 = CMutableTransaction();
    tx7.vin.resize(1);
    tx7.vin[0].prevout = COutPoint(tx6.GetIdem(), 0);
    tx7.vin[0].scriptSig = CScript() << OP_11;
    tx7.vout.resize(1);
    tx7.vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx7.vout[0].nValue = 10 * COIN;
    uint64_t tx7Size = ::GetSerializeSize(tx7, SER_NETWORK, PROTOCOL_VERSION);

    /* set the fee to just below tx2's feerate when including ancestor */
    CAmount fee = (20000 / tx2Size) * (tx7Size + tx6Size) - 1;

    // CTxMemPoolEntry entry7(tx7, fee, 2, 10.0, 1, true);
    pool.addUnchecked(entry.Fee(fee).Time(GetTime() + 7).FromTx(tx7));
    BOOST_CHECK_EQUAL(pool.size(), 7UL);
    sortedOrder.insert(sortedOrder.begin() + 1, tx7.GetId().ToString());
    CheckSort<ancestor_score>(pool, sortedOrder);

    /* after tx6 is mined, tx7 should move up in the sort */
    std::vector<CTransactionRef> vtx;
    vtx.push_back(MakeTransactionRef(tx6));
    std::list<CTransactionRef> dummy;
    pool.removeForBlock(vtx, 1, dummy, false);

    sortedOrder.erase(sortedOrder.begin() + 1);
    // Ties are broken by time
    sortedOrder.pop_back();
    sortedOrder.insert(sortedOrder.begin(), tx7.GetId().ToString());
    CheckSort<ancestor_score>(pool, sortedOrder);
}


BOOST_AUTO_TEST_CASE(MempoolSizeLimitTest)
{
    CTxMemPool pool;
    std::vector<COutPoint> vNoSpendsRemaining;
    TestMemPoolEntryHelper entry;
    entry.dPriority = 10.0;

    CMutableTransaction tx1 = CMutableTransaction();
    tx1.vin.resize(1);
    tx1.vin[0].scriptSig = CScript() << OP_1;
    tx1.vout.resize(1);
    tx1.vout[0].scriptPubKey = CScript() << OP_1 << OP_EQUAL;
    tx1.vout[0].nValue = 10 * COIN;
    pool.addUnchecked(entry.Fee(10000LL).FromTx(tx1, &pool));

    CMutableTransaction tx2 = CMutableTransaction();
    tx2.vin.resize(1);
    tx2.vin[0].scriptSig = CScript() << OP_2;
    tx2.vout.resize(1);
    tx2.vout[0].scriptPubKey = CScript() << OP_2 << OP_EQUAL;
    tx2.vout[0].nValue = 10 * COIN;
    pool.addUnchecked(entry.Fee(5000LL).FromTx(tx2, &pool));

    vNoSpendsRemaining.clear();
    pool.TrimToSize(pool.DynamicMemoryUsage(), &vNoSpendsRemaining, true); // should do nothing
    BOOST_CHECK(pool.exists(tx1.GetId()));
    BOOST_CHECK(pool.exists(tx2.GetId()));
    BOOST_CHECK(pool.size() == 2);

    vNoSpendsRemaining.clear();
    pool.TrimToSize(pool.DynamicMemoryUsage() * 3 / 4, &vNoSpendsRemaining, true);
    BOOST_CHECK(!pool.exists(tx1.GetId()));
    BOOST_CHECK(pool.exists(tx2.GetId()));
    BOOST_CHECK(pool.size() == 1);

    pool.addUnchecked(entry.FromTx(tx2, &pool));
    CMutableTransaction tx3 = CMutableTransaction();
    tx3.vin.resize(1);
    tx3.vin[0].prevout = COutPoint(tx2.GetIdem(), 0);
    tx3.vin[0].scriptSig = CScript() << OP_2;
    tx3.vout.resize(1);
    tx3.vout[0].scriptPubKey = CScript() << OP_3 << OP_EQUAL;
    tx3.vout[0].nValue = 10 * COIN;
    pool.addUnchecked(entry.Fee(20000LL).FromTx(tx3, &pool));

    // mempool is limited to tx2's size in memory usage, so nothing fits
    pool.TrimToSize(::GetSerializeSize(CTransaction(tx2), SER_NETWORK, PROTOCOL_VERSION));
    BOOST_CHECK(!pool.exists(tx1.GetId()));
    BOOST_CHECK(!pool.exists(tx2.GetId()));
    BOOST_CHECK(!pool.exists(tx3.GetId()));
    BOOST_CHECK(pool.size() == 0);

    CFeeRate maxFeeRateRemoved(25000, ::GetSerializeSize(CTransaction(tx3), SER_NETWORK, PROTOCOL_VERSION) +
                                          ::GetSerializeSize(CTransaction(tx2), SER_NETWORK, PROTOCOL_VERSION));

    CMutableTransaction tx4 = CMutableTransaction();
    tx4.vin.resize(2);
    tx4.vin[0].prevout.SetNull();
    tx4.vin[0].scriptSig = CScript() << OP_4;
    tx4.vin[1].prevout.SetNull();
    tx4.vin[1].scriptSig = CScript() << OP_4;
    tx4.vout.resize(2);
    tx4.vout[0].scriptPubKey = CScript() << OP_4 << OP_EQUAL;
    tx4.vout[0].nValue = 10 * COIN;
    tx4.vout[1].scriptPubKey = CScript() << OP_4 << OP_EQUAL;
    tx4.vout[1].nValue = 10 * COIN;

    CMutableTransaction tx5 = CMutableTransaction();
    tx5.vin.resize(2);
    tx5.vin[0].prevout = COutPoint(tx4.GetIdem(), 0);
    tx5.vin[0].scriptSig = CScript() << OP_4;
    tx5.vin[1].prevout.SetNull();
    tx5.vin[1].scriptSig = CScript() << OP_5;
    tx5.vout.resize(2);
    tx5.vout[0].scriptPubKey = CScript() << OP_5 << OP_EQUAL;
    tx5.vout[0].nValue = 10 * COIN;
    tx5.vout[1].scriptPubKey = CScript() << OP_5 << OP_EQUAL;
    tx5.vout[1].nValue = 10 * COIN;

    CMutableTransaction tx6 = CMutableTransaction();
    tx6.vin.resize(2);
    tx6.vin[0].prevout = COutPoint(tx4.GetIdem(), 1);
    tx6.vin[0].scriptSig = CScript() << OP_4;
    tx6.vin[1].prevout.SetNull();
    tx6.vin[1].scriptSig = CScript() << OP_6;
    tx6.vout.resize(2);
    tx6.vout[0].scriptPubKey = CScript() << OP_6 << OP_EQUAL;
    tx6.vout[0].nValue = 10 * COIN;
    tx6.vout[1].scriptPubKey = CScript() << OP_6 << OP_EQUAL;
    tx6.vout[1].nValue = 10 * COIN;

    CMutableTransaction tx7 = CMutableTransaction();
    tx7.vin.resize(2);
    tx7.vin[0].prevout = COutPoint(tx5.GetIdem(), 0);
    tx7.vin[0].scriptSig = CScript() << OP_5;
    tx7.vin[1].prevout = COutPoint(tx6.GetIdem(), 0);
    tx7.vin[1].scriptSig = CScript() << OP_6;
    tx7.vout.resize(2);
    tx7.vout[0].scriptPubKey = CScript() << OP_7 << OP_EQUAL;
    tx7.vout[0].nValue = 10 * COIN;
    tx7.vout[1].scriptPubKey = CScript() << OP_7 << OP_EQUAL;
    tx7.vout[1].nValue = 10 * COIN;

    pool.addUnchecked(entry.Fee(7000LL).FromTx(tx4, &pool));
    pool.addUnchecked(entry.Fee(1000LL).FromTx(tx5, &pool));
    pool.addUnchecked(entry.Fee(1100LL).FromTx(tx6, &pool));
    pool.addUnchecked(entry.Fee(9000LL).FromTx(tx7, &pool));

    // we only require this removes both tx6 and tx7 because tx6 is chosen which then also removes the decendant tx7.
    vNoSpendsRemaining.clear();
    pool.TrimToSize(pool.DynamicMemoryUsage() - 1, &vNoSpendsRemaining, true);
    BOOST_CHECK(pool.exists(tx4.GetId()));
    BOOST_CHECK(pool.exists(tx5.GetId()));
    BOOST_CHECK(!pool.exists(tx6.GetId()));
    BOOST_CHECK(!pool.exists(tx7.GetId()));
    BOOST_CHECK(pool.size() == 2);

    if (!pool.exists(tx5.GetId()))
    {
        pool.addUnchecked(entry.Fee(1000LL).FromTx(tx5, &pool));
    }
    pool.addUnchecked(entry.Fee(9000LL).FromTx(tx7, &pool));

    // should maximize mempool size by only removing tx5 and its decendants
    pool.TrimToSize(pool.DynamicMemoryUsage() / 2, &vNoSpendsRemaining, true);
    BOOST_CHECK(pool.exists(tx4.GetId()));
    BOOST_CHECK(!pool.exists(tx5.GetId()));
    BOOST_CHECK(!pool.exists(tx6.GetId()));
    BOOST_CHECK(!pool.exists(tx7.GetId()));
    BOOST_CHECK(pool.size() == 1);

    // Add two single txns that are not chained and then trim the pool by 1 byte.
    pool.clear();
    pool.addUnchecked(entry.Fee(10000LL).FromTx(tx1, &pool));
    pool.addUnchecked(entry.Fee(7000LL).FromTx(tx4, &pool));
    vNoSpendsRemaining.clear();
    pool.TrimToSize(pool.DynamicMemoryUsage() - 1, &vNoSpendsRemaining, true);
    BOOST_CHECK(!pool.exists(tx1.GetId()));
    BOOST_CHECK(pool.exists(tx4.GetId()));
    BOOST_CHECK(pool.size() == 1); // tx1 should be trimmed from the pool

    // Add a chain of 10 txns and trim. Only the very last txn in the chain should be removed
    pool.clear();
    pool.addUnchecked(entry.Fee(10000LL).FromTx(tx1, &pool));

    // Make a txn we can used for chaining
    CMutableTransaction tx;
    uint256 hash;
    tx.vin.resize(1);
    tx.vin[0].scriptSig = CScript();
    tx.vin[0].prevout = tx1.OutpointAt(0);
    tx.vout.resize(1);
    tx.vout[0].nValue = 5000000000LL;

    // Create a chain of transactions with varying fees applied to the descendants. This will create a chain
    // of descendant packages.
    uint256 lastHash;
    for (unsigned int i = 1; i <= 9; ++i)
    {
        int nFee = 1000;
        tx.vout[0].nValue -= nFee;
        hash = tx.GetIdem();
        lastHash = tx.GetId();
        bool spendsCoinbase = false;
        pool.addUnchecked(entry.Fee(nFee).Time(GetTime() + i).SpendsCoinbase(spendsCoinbase).SigOps(1).FromTx(tx));
        tx.vin[0].prevout = COutPoint(hash, 0);
    }
    BOOST_CHECK(pool.size() == 10);
    pool.TrimToSize(pool.DynamicMemoryUsage() - 1, &vNoSpendsRemaining, false);
    BOOST_CHECK(pool.size() == 9); // only the 10nth should be trimmed from the pool
    BOOST_CHECK(!pool.exists(lastHash)); // last hash should not exist

    // Add a chain of 100 txns and trim. At most the very last 4 txns in the chain should be removed
    pool.clear();
    pool.addUnchecked(entry.Fee(10000LL).FromTx(tx1, &pool));

    // Store all hashes so we can check them for existence later
    std::vector<uint256> vHashes;
    vHashes.push_back(tx1.GetId());

    // Make a txn we can used for chaining
    tx.vin.resize(1);
    tx.vin[0].scriptSig = CScript();
    tx.vin[0].prevout = tx1.OutpointAt(0);
    tx.vout.resize(1);
    tx.vout[0].nValue = 5000000000LL;

    // Create a chain of transactions with varying fees applied to the descendants. This will create a chain
    // of descendant packages.
    for (unsigned int i = 1; i <= 99; ++i)
    {
        int nFee = 1000;
        tx.vout[0].nValue -= nFee;
        hash = tx.GetIdem();
        vHashes.push_back(tx.GetId());
        bool spendsCoinbase = false;
        pool.addUnchecked(entry.Fee(nFee).Time(GetTime() + i).SpendsCoinbase(spendsCoinbase).SigOps(1).FromTx(tx));
        tx.vin[0].prevout = COutPoint(hash, 0);
    }

    BOOST_CHECK(pool.size() == 100);
    pool.TrimToSize(pool.DynamicMemoryUsage() - 1, &vNoSpendsRemaining, false);

    // The chain will have been trimmed anywhere from 1 to 10% of that last
    // part of the chain. But at least 1 transaction, the very last in the chain,
    // will have been removed.
    BOOST_CHECK(pool.size() >= 90 && pool.size() < 100);
    for (size_t i = 0; i < (vHashes.size() - 10); i++) // first 90 hashes should exist
        BOOST_CHECK(pool.exists(vHashes[i]));
    BOOST_CHECK(!pool.exists(vHashes[vHashes.size() - 1])); // at minimum the last hash should not exist

    // Create a chain of transactions with varying fees applied to the descendants. This will create a chain
    // of descendant packages.
    //
    // Then prioritise the very last transaction.  Result: no transactions should be trimmed
    pool.clear();
    vHashes.clear();

    // Make a txn we can used for chaining
    tx.vin.resize(1);
    tx.vin[0].scriptSig = CScript();
    tx.vin[0].prevout = tx1.OutpointAt(0);
    tx.vout.resize(1);
    tx.vout[0].nValue = 5000000000LL;

    for (unsigned int i = 1; i <= 100; ++i)
    {
        int nFee = 1000;
        tx.vout[0].nValue -= nFee;
        hash = tx.GetIdem();
        vHashes.push_back(tx.GetId());
        bool spendsCoinbase = false;
        pool.addUnchecked(entry.Fee(nFee).Time(GetTime() + i).SpendsCoinbase(spendsCoinbase).SigOps(1).FromTx(tx));
        tx.vin[0].prevout = COutPoint(hash, 0);
    }
    // prioritise the last transaction so that no transactions will be removed when trimmed
    pool.PrioritiseTransaction(vHashes[99], 0, 1000);

    BOOST_CHECK_EQUAL(pool.size(), 100UL);
    pool.TrimToSize(0, &vNoSpendsRemaining, false);

    // nothing should have been removed
    BOOST_CHECK_EQUAL(pool.size(), 100UL);
    for (size_t i = 0; i < vHashes.size(); i++) // all hashes should exist
        BOOST_CHECK(pool.exists(vHashes[i]));

    // remove the priority
    pool.PrioritiseTransaction(vHashes[99], 0, -1000);
    BOOST_CHECK_EQUAL(pool.size(), 100UL);

    // without the priority the chain will now be seen as just any chain and so last hash should have been removed
    pool.TrimToSize(pool.DynamicMemoryUsage() - 1, &vNoSpendsRemaining, false);
    for (size_t i = 0; i < (vHashes.size() - 10); i++) // first 90 hashes should exist
        BOOST_CHECK(pool.exists(vHashes[i]));
    BOOST_CHECK(!pool.exists(vHashes[vHashes.size() - 1])); // at minimum the last hash should not exist


    // Prioritise a few transactions (by fee) in the chain  and make sure they still remain after the trim.
    // After trimming txpool to zero make sure that all txns after the last prioritised txn are removed.
    pool.PrioritiseTransaction(vHashes[50], 0, 1000);
    pool.PrioritiseTransaction(vHashes[40], 0, 5000);
    pool.PrioritiseTransaction(vHashes[30], 0, 3000);
    pool.TrimToSize(0, &vNoSpendsRemaining, false);
    BOOST_CHECK_EQUAL(pool.size(), 51UL);
    BOOST_CHECK_EQUAL(vHashes.size(), 100UL);
    for (size_t i = 0; i <= 50; i++) // should exist
        BOOST_CHECK(pool.exists(vHashes[i]));
    for (size_t i = 51; i < vHashes.size(); i++) // should not exist
        BOOST_CHECK(!pool.exists(vHashes[i]));
    vHashes.erase(vHashes.begin() + 51, vHashes.end());
    BOOST_CHECK_EQUAL(vHashes.size(), pool.size());

    // remove the priorities
    pool.PrioritiseTransaction(vHashes[50], 0, -1000);
    pool.PrioritiseTransaction(vHashes[40], 0, -5000);
    pool.PrioritiseTransaction(vHashes[30], 0, -3000);

    // without the priority the chain will now be seen as just any chain and so last hash should have been removed
    pool.TrimToSize(pool.DynamicMemoryUsage() - 1, &vNoSpendsRemaining, false);
    for (size_t i = 0; i < (vHashes.size() - 5); i++)
        BOOST_CHECK(pool.exists(vHashes[i]));
    BOOST_CHECK(!pool.exists(vHashes[vHashes.size() - 1])); // at minimum the last hash should not exist

    pool.clear();
    vHashes.clear();

    // Make a txn we can used for chaining
    tx.vin.resize(1);
    tx.vin[0].scriptSig = CScript();
    tx.vin[0].prevout = tx1.OutpointAt(0);
    tx.vout.resize(1);
    tx.vout[0].nValue = 5000000000LL;

    for (unsigned int i = 1; i <= 100; ++i)
    {
        int nFee = 1000;
        tx.vout[0].nValue -= nFee;
        hash = tx.GetIdem();
        vHashes.push_back(tx.GetId());
        bool spendsCoinbase = false;
        pool.addUnchecked(entry.Fee(nFee).Time(GetTime() + i).SpendsCoinbase(spendsCoinbase).SigOps(1).FromTx(tx));
        tx.vin[0].prevout = COutPoint(hash, 0);
    }

    // Prioritise a few transactions (by priority delta) in the chain  and make sure they still remain after the trim.
    // After trimming txpool to zero make sure that all txns after the last prioritised txn are removed.
    pool.PrioritiseTransaction(vHashes[95], 1e10, 0);
    pool.PrioritiseTransaction(vHashes[20], 1e11, 0);
    pool.TrimToSize(0, &vNoSpendsRemaining, false);
    BOOST_CHECK_EQUAL(pool.size(), 96UL);
    for (size_t i = 0; i <= 95; i++) // should exist
        BOOST_CHECK(pool.exists(vHashes[i]));
    for (size_t i = 96; i < vHashes.size(); i++) // should not exist
        BOOST_CHECK(!pool.exists(vHashes[i]));
    vHashes.erase(vHashes.begin() + 96, vHashes.end());
    BOOST_CHECK_EQUAL(vHashes.size(), pool.size());

    // remove the priorities
    pool.PrioritiseTransaction(vHashes[95], -1e10, 0);
    pool.PrioritiseTransaction(vHashes[20], -1e11, 0);
    BOOST_CHECK_EQUAL(pool.size(), 96UL);
    BOOST_CHECK_EQUAL(vHashes.size(), pool.size());
    pool.TrimToSize(pool.DynamicMemoryUsage() - 1, &vNoSpendsRemaining, false);

    // without the priority the chain will now be seen as just any chain and so last hash should have been removed
    vHashes.erase(vHashes.begin() + 96, vHashes.end());
    for (size_t i = 0; i < (vHashes.size() - 10); i++)
        BOOST_CHECK(pool.exists(vHashes[i]));
    BOOST_CHECK(!pool.exists(vHashes[vHashes.size() - 1])); // at minimum the last hash should not exist
}

BOOST_AUTO_TEST_SUITE_END()
