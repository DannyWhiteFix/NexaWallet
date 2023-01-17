// Copyright (c) 2012-2015 The Bitcoin Core developers
// Copyright (c) 2015-2021 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "main.h"
#include "wallet/wallet.h"
#include "wallet/walletdb.h"

#include "wallet/test/wallet_test_fixture.h"

#include <stdint.h>

#include <boost/test/unit_test.hpp>

extern CWallet* pwalletMain;

BOOST_FIXTURE_TEST_SUITE(accounting_tests, WalletTestingSetup)

BOOST_AUTO_TEST_CASE(acc_orderupgrade)
{
    // Wallets start upgraded, so functionality not needed
    BOOST_CHECK(true);
}

BOOST_AUTO_TEST_SUITE_END()
