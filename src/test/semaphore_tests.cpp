// Copyright (c) 2019 The Bitcoin developers
// Copyright (c) 2019-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "sync.h"

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(semaphore_tests);

BOOST_AUTO_TEST_CASE(semaphore_test1)
{
    // Create a semaphore with 5 slots
    CSemaphore *sem = new CSemaphore(5);

    // use up all the slots
    CSemaphoreGrant grant1(*sem, false);
    BOOST_CHECK(grant1 == true);
    CSemaphoreGrant grant2(*sem, false);
    BOOST_CHECK(grant2 == true);
    CSemaphoreGrant grant3(*sem, false);
    BOOST_CHECK(grant3 == true);
    CSemaphoreGrant grant4(*sem, false);
    BOOST_CHECK(grant4 == true);
    CSemaphoreGrant grant5(*sem, false);
    BOOST_CHECK(grant5 == true);

    // try to use up an extra slot. You should not get a grant.
    {
        CSemaphoreGrant grant6(*sem, true);
        BOOST_CHECK(grant6 == false);
    }

    // Resize the semaphore and try to aquire more grants
    sem->resize(7);
    CSemaphoreGrant grant6(*sem, false);
    BOOST_CHECK(grant6 == true);
    CSemaphoreGrant grant7(*sem, false);
    BOOST_CHECK(grant7 == true);

    // try to use up an extra slot. You should not get a grant.
    CSemaphoreGrant grant8(*sem, true);
    BOOST_CHECK(grant8 == false);

    // reduce the size of the semaphore
    sem->resize(4);

    // try to use up an extra slot. You should not get a grant.
    {
        CSemaphoreGrant grant5a(*sem, true);
        BOOST_CHECK(grant5a == false);
    }

    // Release 3 grants and try again. Still you should not get one
    grant7.Release();
    grant6.Release();
    grant5.Release();
    {
        CSemaphoreGrant grant4a(*sem, true);
        BOOST_CHECK(grant4a == false);
    }

    // Release one more and then try. You should get a grant.
    grant4.Release();
    {
        CSemaphoreGrant grant4a(*sem, true);
        BOOST_CHECK(grant4a == true);
    }
}

BOOST_AUTO_TEST_SUITE_END();
