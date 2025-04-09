// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Utility functions shared by unit tests
 */
#ifndef NEXA_TEST_TESTUTIL_H
#define NEXA_TEST_TESTUTIL_H

#include "fs.h"
#include "key.h"
#include "pubkey.h"
#include "script/script.h"
#include "script/standard.h"

struct CMutableTransaction;

fs::path GetTempPath();
CMutableTransaction CreateRandomTx();


// create a pay to public key hash script
CScript p2pkh(const CKeyID &dest);
CScript p2sh(const CScriptID &dest);

CScript sign_multisig(const CScript scriptPubKey,
    const std::vector<CKey> &keys,
    const CMutableTransaction &transaction,
    int whichIn,
    uint32_t whichSigBitmap);

// Create basic transactions.  All functions assume that the input amount is the sum of the output amounts
CTransaction tx1x1(const COutPoint &utxo, const CScript &txo, CAmount amt);
CTransaction tx1x2(const COutPoint &utxo, const CScript &txo, CAmount amt, const CScript &txo2, CAmount amt2);
CTransaction tx1x3(const COutPoint &utxo,
    const CScript &txo,
    CAmount amt,
    const CScript &txo2,
    CAmount amt2,
    const CScript &txo3,
    CAmount amt3);

// Signs
CTransaction tx1x1(const COutPoint &utxo,
    const CScript &txo,
    CAmount amt,
    const CKey &key,
    const CScript &prevOutScript);

CTransaction tx1x1(const CTransaction &prevtx, int prevout, const CScript &txo, CAmount amt, const CKey &key);

CTransaction tx1x1_p2sh_of_p2pkh(const CTransaction &prevtx,
    int prevout,
    const CScript &txo,
    CAmount amt,
    const CKey &key,
    const CScript &redeemScript);


CTransaction tx1x2(const CTransaction &prevtx,
    int prevout,
    const CScript &txo0,
    CAmount amt0,
    const CScript &txo1,
    CAmount amt1,
    const CKey &key,
    bool p2pkh = true);

#endif // NEXA_TEST_TESTUTIL_H
