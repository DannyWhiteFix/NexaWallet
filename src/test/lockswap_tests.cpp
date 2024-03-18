// Copyright (c) 2023-2024 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "test/test_nexa.h"

#include "datastream.h"
#include "net.h"


#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(lockswap_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(lockswap_test)
{
    // Create a simple test object to use in the test
    uint256 hash;
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << hash;
    uint32_t stream_size = ss.size();

    // Create a lockswap queue
    CLockSwapQ<CDataStream> Q;

    // Add items to the queue and make consistency checks along the way.
    BOOST_CHECK_EQUAL(Q.empty(), true);

    Q.push_back(ss);
    BOOST_CHECK_EQUAL(Q.empty(), false);
    BOOST_CHECK_EQUAL(Q.totalbytes(), stream_size);
    BOOST_CHECK_EQUAL(Q.size(), 1);

    Q.push_back(ss);
    BOOST_CHECK_EQUAL(Q.empty(), false);
    BOOST_CHECK_EQUAL(Q.totalbytes(), stream_size * 2);
    BOOST_CHECK_EQUAL(Q.size(), 2);

    Q.push_back(ss);
    BOOST_CHECK_EQUAL(Q.empty(), false);
    BOOST_CHECK_EQUAL(Q.totalbytes(), stream_size * 3);
    BOOST_CHECK_EQUAL(Q.size(), 3);

    Q.push_back(ss);
    BOOST_CHECK_EQUAL(Q.empty(), false);
    BOOST_CHECK_EQUAL(Q.totalbytes(), stream_size * 4);
    BOOST_CHECK_EQUAL(Q.size(), 4);

    // Pop items from the queue and make consistency checks
    CDataStream ss_pop(SER_NETWORK, PROTOCOL_VERSION);

    BOOST_CHECK_EQUAL(Q.pop_front(ss_pop), true);
    BOOST_CHECK_EQUAL(Q.empty(), false);
    BOOST_CHECK_EQUAL(Q.totalbytes(), stream_size * 3);
    BOOST_CHECK_EQUAL(Q.size(), 3);

    BOOST_CHECK_EQUAL(Q.pop_front(ss_pop), true);
    BOOST_CHECK_EQUAL(Q.empty(), false);
    BOOST_CHECK_EQUAL(Q.totalbytes(), stream_size * 2);
    BOOST_CHECK_EQUAL(Q.size(), 2);

    BOOST_CHECK_EQUAL(Q.pop_front(ss_pop), true);
    BOOST_CHECK_EQUAL(Q.empty(), false);
    BOOST_CHECK_EQUAL(Q.totalbytes(), stream_size * 1);
    BOOST_CHECK_EQUAL(Q.size(), 1);

    BOOST_CHECK_EQUAL(Q.pop_front(ss_pop), true);
    BOOST_CHECK_EQUAL(Q.empty(), true);
    BOOST_CHECK_EQUAL(Q.totalbytes(), stream_size * 0);
    BOOST_CHECK_EQUAL(Q.size(), 0);

    // Try to pop and empty Q. It should fail gracefullhy.
    BOOST_CHECK_EQUAL(Q.pop_front(ss_pop), false);
    BOOST_CHECK_EQUAL(Q.empty(), true);
    BOOST_CHECK_EQUAL(Q.totalbytes(), stream_size * 0);
    BOOST_CHECK_EQUAL(Q.size(), 0);


    // Add and remove and add and remove items.
    Q.push_back(ss);
    BOOST_CHECK_EQUAL(Q.empty(), false);
    BOOST_CHECK_EQUAL(Q.totalbytes(), stream_size);
    BOOST_CHECK_EQUAL(Q.size(), 1);

    Q.push_back(ss);
    BOOST_CHECK_EQUAL(Q.empty(), false);
    BOOST_CHECK_EQUAL(Q.totalbytes(), stream_size * 2);
    BOOST_CHECK_EQUAL(Q.size(), 2);

    Q.push_back(ss);
    BOOST_CHECK_EQUAL(Q.empty(), false);
    BOOST_CHECK_EQUAL(Q.totalbytes(), stream_size * 3);
    BOOST_CHECK_EQUAL(Q.size(), 3);

    BOOST_CHECK_EQUAL(Q.pop_front(ss_pop), true);
    BOOST_CHECK_EQUAL(Q.empty(), false);
    BOOST_CHECK_EQUAL(Q.totalbytes(), stream_size * 2);
    BOOST_CHECK_EQUAL(Q.size(), 2);

    Q.push_back(ss);
    BOOST_CHECK_EQUAL(Q.empty(), false);
    BOOST_CHECK_EQUAL(Q.totalbytes(), stream_size * 3);
    BOOST_CHECK_EQUAL(Q.size(), 3);

    Q.push_back(ss);
    BOOST_CHECK_EQUAL(Q.empty(), false);
    BOOST_CHECK_EQUAL(Q.totalbytes(), stream_size * 4);
    BOOST_CHECK_EQUAL(Q.size(), 4);

    BOOST_CHECK_EQUAL(Q.pop_front(ss_pop), true);
    BOOST_CHECK_EQUAL(Q.empty(), false);
    BOOST_CHECK_EQUAL(Q.totalbytes(), stream_size * 3);
    BOOST_CHECK_EQUAL(Q.size(), 3);

    BOOST_CHECK_EQUAL(Q.pop_front(ss_pop), true);
    BOOST_CHECK_EQUAL(Q.empty(), false);
    BOOST_CHECK_EQUAL(Q.totalbytes(), stream_size * 2);
    BOOST_CHECK_EQUAL(Q.size(), 2);

    Q.push_back(ss);
    BOOST_CHECK_EQUAL(Q.empty(), false);
    BOOST_CHECK_EQUAL(Q.totalbytes(), stream_size * 3);
    BOOST_CHECK_EQUAL(Q.size(), 3);

    Q.push_back(ss);
    BOOST_CHECK_EQUAL(Q.empty(), false);
    BOOST_CHECK_EQUAL(Q.totalbytes(), stream_size * 4);
    BOOST_CHECK_EQUAL(Q.size(), 4);

    // now clear
    Q.clear();
    BOOST_CHECK_EQUAL(Q.empty(), true);
    BOOST_CHECK_EQUAL(Q.totalbytes(), 0);
    BOOST_CHECK_EQUAL(Q.size(), 0);


    // Do a larger test
    int nIterations = 2000;
    for (int i = 1; i <= nIterations; i++)
    {
        Q.push_back(ss);
        BOOST_CHECK_EQUAL(Q.empty(), false);
        BOOST_CHECK_EQUAL(Q.totalbytes(), stream_size * i);
        BOOST_CHECK_EQUAL(Q.size(), i);
    }

    for (int i = 1; i <= nIterations; i++)
    {
        BOOST_CHECK_EQUAL(Q.pop_front(ss_pop), true);
        if (i < nIterations)
        {
            BOOST_CHECK_EQUAL(Q.empty(), false);
        }
        else
        {
            BOOST_CHECK_EQUAL(Q.empty(), true);
        }
        BOOST_CHECK_EQUAL(Q.totalbytes(), stream_size * (nIterations - i));
        BOOST_CHECK_EQUAL(Q.size(), (nIterations - i));
    }
}

BOOST_AUTO_TEST_SUITE_END()
