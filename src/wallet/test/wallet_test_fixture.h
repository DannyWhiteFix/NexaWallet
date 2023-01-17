// Copyright (c) 2016 The Bitcoin Core developers
// Copyright (c) 2016-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_WALLET_TEST_WALLET_TEST_FIXTURE_H
#define NEXA_WALLET_TEST_WALLET_TEST_FIXTURE_H

#include "test/test_nexa.h"

/** Testing setup and teardown for wallet.
 */
struct WalletTestingSetup: public TestingSetup {
    WalletTestingSetup(const std::string& chainName = CBaseChainParams::NEXA);
    ~WalletTestingSetup();
};

#endif // NEXA_WALLET_TEST_WALLET_TEST_FIXTURE_H

