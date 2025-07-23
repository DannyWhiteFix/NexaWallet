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
    BOOST_CHECK_EQUAL(sem->available(), 5);

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

    BOOST_CHECK_EQUAL(sem->available(), 0);

    // try to use up an extra slot. You should not get a grant.
    {
        CSemaphoreGrant grant6(*sem, true);
        BOOST_CHECK(grant6 == false);
    }

    // Resize the semaphore and try to aquire more grants
    sem->resize(7);
    BOOST_CHECK_EQUAL(sem->available(), 2);

    CSemaphoreGrant grant6(*sem, false);
    BOOST_CHECK(grant6 == true);
    CSemaphoreGrant grant7(*sem, false);
    BOOST_CHECK(grant7 == true);
    BOOST_CHECK_EQUAL(sem->available(), 0);

    // try to use up an extra slot. You should not get a grant.
    CSemaphoreGrant grant8(*sem, true);
    BOOST_CHECK(grant8 == false);

    // reduce the size of the semaphore which will cause
    // the semaphore "value" parameter to go to negative 3.
    sem->resize(4);
    BOOST_CHECK_EQUAL(sem->available(), -3);

    // try to use up an extra slot. You should not get a grant.
    CSemaphoreGrant grant5a(*sem, true);
    BOOST_CHECK(grant5a == false);

    // Resize twice more which should not do anything.
    sem->resize(4);
    sem->resize(4);
    BOOST_CHECK_EQUAL(sem->available(), -3);

    // Release 3 grants and try again. This will cause the semaphore "value"
    // parameter to go back to zero. So you should still not get a grant.
    grant7.Release();
    grant6.Release();
    grant5.Release();
    BOOST_CHECK_EQUAL(sem->available(), 0);
    CSemaphoreGrant grant4a(*sem, true);
    BOOST_CHECK(grant4a == false);

    // Release one more and then try which causes the semaphore "value" parameter
    // to go to "1", meaning one grant would be available.
    grant4.Release();
    BOOST_CHECK_EQUAL(sem->available(), 1);
    CSemaphoreGrant grant4b(*sem, true);
    BOOST_CHECK(grant4b == true);
    BOOST_CHECK_EQUAL(sem->available(), 0);

    // Resize to a higher value and check for available slots.
    sem->resize(14);
    BOOST_CHECK_EQUAL(sem->available(), 10);
}

BOOST_AUTO_TEST_SUITE_END();
