// Copyright (c) 2011-2013 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "base58.h" // Freeze CBitcoinAddress
#include "chain.h" // Freeze CBlockIndex
#include "dstencode.h"
#include "key.h"
#include "keystore.h"
#include "policy/policy.h"
#include "script/interpreter.h"
#include "script/ismine.h"
#include "script/script.h"
#include "script/script_error.h"
#include "script/sign.h"
#include "test/test_nexa.h"
#include "test/testutil.h"
#include "uint256.h"

#ifdef ENABLE_WALLET
#include "wallet/wallet.h" // Freeze wallet test
#endif

#include <boost/test/unit_test.hpp>

using namespace std;

typedef vector<unsigned char> valtype;

BOOST_FIXTURE_TEST_SUITE(multisig_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(multisig_verify)
{
    unsigned int flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_STRICTENC | SCRIPT_ENABLE_SIGHASH_FORKID;

    ScriptError err;
    CKey key[4];
    CAmount amount = 0;
    for (int i = 0; i < 4; i++)
        key[i].MakeNewKey(true);

    CScript a_and_b;
    a_and_b << OP_2 << ToByteVector(key[0].GetPubKey()) << ToByteVector(key[1].GetPubKey()) << OP_2 << OP_CHECKMULTISIG;

    CScript a_or_b;
    a_or_b << OP_1 << ToByteVector(key[0].GetPubKey()) << ToByteVector(key[1].GetPubKey()) << OP_2 << OP_CHECKMULTISIG;

    CScript escrow;
    escrow << OP_2 << ToByteVector(key[0].GetPubKey()) << ToByteVector(key[1].GetPubKey())
           << ToByteVector(key[2].GetPubKey()) << OP_3 << OP_CHECKMULTISIG;

    CMutableTransaction txFrom; // Funding transaction
    txFrom.vout.resize(3);
    txFrom.vout[0].scriptPubKey = a_and_b;
    txFrom.vout[0].nValue = 10 * COIN;
    txFrom.vout[1].scriptPubKey = a_or_b;
    txFrom.vout[1].nValue = 10 * COIN;
    txFrom.vout[2].scriptPubKey = escrow;
    txFrom.vout[2].nValue = 10 * COIN;

    CMutableTransaction txTo[3]; // Spending transaction
    for (int i = 0; i < 3; i++)
    {
        txTo[i].vin.resize(1);
        txTo[i].vout.resize(1);
        txTo[i].vin[0] = txFrom.SpendOutput(i);
        txTo[i].vout[0].nValue = 1;
    }

    vector<CKey> keys;
    CScript s;

    // Test a AND b:
    keys.assign(1, key[0]);
    keys.push_back(key[1]);
    s = sign_multisig(a_and_b, keys, txTo[0], 0, 3);
    amount = txTo[0].vin[0].amount;
    MutableTransactionSignatureChecker tsc(&txTo[0], 0, amount, flags);
    // test isn't going to use any prevout introspection so just pass no coins there
    ScriptImportedState sis(&tsc);
    BOOST_CHECK(VerifyScript(s, a_and_b, flags, sis, &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));

    for (int i = 0; i < 4; i++)
    {
        keys.assign(1, key[i]);
        s = sign_multisig(a_and_b, keys, txTo[0], 0, 3);
        BOOST_CHECK_MESSAGE(!VerifyScript(s, a_and_b, flags, sis, &err), strprintf("a&b 1: %d", i));
        BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_INVALID_STACK_OPERATION, ScriptErrorString(err));

        // Check that the multisig doesn't work (because the pubkey is wrong)
        keys.assign(1, key[1]);
        keys.push_back(key[i]);
        s = sign_multisig(a_and_b, keys, txTo[0], 0, 3);
        BOOST_CHECK_MESSAGE(!VerifyScript(s, a_and_b, flags, sis, &err), strprintf("a&b 2: %d", i));
        BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_CHECKMULTISIGVERIFY, ScriptErrorString(err));

        // check soft failure
        keys.assign(1, key[1]);
        keys.push_back(key[i]);
        s = sign_multisig(a_and_b, keys, txTo[0], 0, 0);
        BOOST_CHECK_MESSAGE(!VerifyScript(s, a_and_b, flags, sis, &err), strprintf("a&b 2: %d", i));
        BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_EVAL_FALSE, ScriptErrorString(err));
    }

    amount = txTo[1].vin[0].amount;
    MutableTransactionSignatureChecker tsc1(&txTo[1], 0, amount, flags);
    ScriptImportedState sis1(&tsc1);
    // Test a OR b:
    for (int i = 0; i < 4; i++)
    {
        keys.assign(1, key[i]);
        // (1<<i)&3 sets bit 0 if i is 0, bit 1 if i is 1 (correct pubkey selection) and then clears all
        // bits for 2 and 3, which triggers a soft failure
        s = sign_multisig(a_or_b, keys, txTo[1], 0, (1 << i) & 3);
        if (i == 0 || i == 1)
        {
            BOOST_CHECK_MESSAGE(VerifyScript(s, a_or_b, flags, sis1, &err), strprintf("a|b: %d", i));
            BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));
        }
        else
        {
            BOOST_CHECK_MESSAGE(!VerifyScript(s, a_or_b, flags, sis1, &err), strprintf("a|b: %d", i));
            BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_EVAL_FALSE, ScriptErrorString(err));

            // Try real multisig failure, by setting the check bits to nonzero
            s = sign_multisig(a_or_b, keys, txTo[1], 0, (1 << (i - 2)) & 3);
            BOOST_CHECK_MESSAGE(!VerifyScript(s, a_or_b, flags, sis1, &err), strprintf("a|b: %d", i));
            BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_CHECKMULTISIGVERIFY, ScriptErrorString(err));
        }
    }

    // Try a badly formatted signature in the multisig
    vector<uint8_t> vchSig;
    uint256 blankHash;
    BOOST_CHECK(key[0].SignSchnorr(blankHash, vchSig));
    defaultSigHashType.appendToSig(vchSig);
    vchSig.resize(vchSig.size() - 2); // chop off last 2 bytes
    s.clear();
    s << OP_1 << vchSig;
    BOOST_CHECK(!VerifyScript(s, a_or_b, flags, sis1, &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_SIG_NONSCHNORR, ScriptErrorString(err));

    BOOST_CHECK(key[0].SignSchnorr(blankHash, vchSig));
    defaultSigHashType.appendToSig(vchSig);
    vchSig.push_back(0xff); // add an extra byte
    s.clear();
    s << OP_1 << vchSig;
    BOOST_CHECK(!VerifyScript(s, a_or_b, flags, sis1, &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_SIG_HASHTYPE, ScriptErrorString(err));


    amount = txTo[2].vin[0].amount;
    MutableTransactionSignatureChecker tsc2(&txTo[2], 0, amount, flags);
    ScriptImportedState sis2(&tsc2);

    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
        {
            keys.assign(1, key[i]);
            keys.push_back(key[j]);
            s = sign_multisig(escrow, keys, txTo[2], 0, ((1 << i) & 15) | ((1 << j) & 15));
            if (i < j && i < 3 && j < 3)
            {
                BOOST_CHECK_MESSAGE(VerifyScript(s, escrow, flags, sis2, &err), strprintf("escrow 1: %d %d", i, j));
                BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));
            }
            else
            {
                // If i==j you will get bad bit counts because they land on eachother.
                // If anything is 3, you will get a bad bit range because this is 2 of 3 and that's the 4th
                // if j < i the order will be wrong so you'll get a sig error
                BOOST_CHECK_MESSAGE(!VerifyScript(s, escrow, flags, sis2, &err), strprintf("escrow 2: %d %d", i, j));
                BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_INVALID_BIT_RANGE || err == SCRIPT_ERR_INVALID_BIT_COUNT ||
                                        err == SCRIPT_ERR_CHECKMULTISIGVERIFY,
                    ScriptErrorString(err));
            }
        }
}

BOOST_AUTO_TEST_CASE(multisig_IsStandard)
{
    CKey key[4];
    for (int i = 0; i < 4; i++)
        key[i].MakeNewKey(true);

    txnouttype whichType;

    CScript a_and_b;
    a_and_b << OP_2 << ToByteVector(key[0].GetPubKey()) << ToByteVector(key[1].GetPubKey()) << OP_2 << OP_CHECKMULTISIG;
    BOOST_CHECK(::IsStandard(a_and_b, whichType));

    CScript a_or_b;
    a_or_b << OP_1 << ToByteVector(key[0].GetPubKey()) << ToByteVector(key[1].GetPubKey()) << OP_2 << OP_CHECKMULTISIG;
    BOOST_CHECK(::IsStandard(a_or_b, whichType));

    CScript escrow;
    escrow << OP_2 << ToByteVector(key[0].GetPubKey()) << ToByteVector(key[1].GetPubKey())
           << ToByteVector(key[2].GetPubKey()) << OP_3 << OP_CHECKMULTISIG;
    BOOST_CHECK(::IsStandard(escrow, whichType));

    CScript one_of_four;
    one_of_four << OP_1 << ToByteVector(key[0].GetPubKey()) << ToByteVector(key[1].GetPubKey())
                << ToByteVector(key[2].GetPubKey()) << ToByteVector(key[3].GetPubKey()) << OP_4 << OP_CHECKMULTISIG;
    BOOST_CHECK(!::IsStandard(one_of_four, whichType));

    CScript malformed[6];
    malformed[0] << OP_3 << ToByteVector(key[0].GetPubKey()) << ToByteVector(key[1].GetPubKey()) << OP_2
                 << OP_CHECKMULTISIG;
    malformed[1] << OP_2 << ToByteVector(key[0].GetPubKey()) << ToByteVector(key[1].GetPubKey()) << OP_3
                 << OP_CHECKMULTISIG;
    malformed[2] << OP_0 << ToByteVector(key[0].GetPubKey()) << ToByteVector(key[1].GetPubKey()) << OP_2
                 << OP_CHECKMULTISIG;
    malformed[3] << OP_1 << ToByteVector(key[0].GetPubKey()) << ToByteVector(key[1].GetPubKey()) << OP_0
                 << OP_CHECKMULTISIG;
    malformed[4] << OP_1 << ToByteVector(key[0].GetPubKey()) << ToByteVector(key[1].GetPubKey()) << OP_CHECKMULTISIG;
    malformed[5] << OP_1 << ToByteVector(key[0].GetPubKey()) << ToByteVector(key[1].GetPubKey());

    for (int i = 0; i < 6; i++)
        BOOST_CHECK(!::IsStandard(malformed[i], whichType));
}

BOOST_AUTO_TEST_CASE(multisig_Sign)
{
    // Test SignSignature() (and therefore the version of Solver() that signs transactions)
    CBasicKeyStore keystore;
    CKey key[4];
    for (int i = 0; i < 4; i++)
    {
        key[i].MakeNewKey(true);
        keystore.AddKey(key[i]);
    }

    CScript a_and_b;
    a_and_b << OP_2 << ToByteVector(key[0].GetPubKey()) << ToByteVector(key[1].GetPubKey()) << OP_2 << OP_CHECKMULTISIG;

    CScript a_or_b;
    a_or_b << OP_1 << ToByteVector(key[0].GetPubKey()) << ToByteVector(key[1].GetPubKey()) << OP_2 << OP_CHECKMULTISIG;

    CScript escrow;
    escrow << OP_2 << ToByteVector(key[0].GetPubKey()) << ToByteVector(key[1].GetPubKey())
           << ToByteVector(key[2].GetPubKey()) << OP_3 << OP_CHECKMULTISIG;

    CMutableTransaction txFrom; // Funding transaction
    txFrom.vout.resize(3);
    txFrom.vout[0].scriptPubKey = a_and_b;
    txFrom.vout[0].nValue = 1;
    txFrom.vout[1].scriptPubKey = a_or_b;
    txFrom.vout[1].nValue = 1;
    txFrom.vout[2].scriptPubKey = escrow;
    txFrom.vout[2].nValue = 1;

    CMutableTransaction txTo[3]; // Spending transaction
    for (int i = 0; i < 3; i++)
    {
        txTo[i].vin.resize(1);
        txTo[i].vout.resize(1);
        txTo[i].vin[0].prevout = txFrom.OutpointAt(i);
        txTo[i].vin[0].amount = 1;
        txTo[i].vout[0].nValue = 1;
    }

    for (int i = 0; i < 3; i++)
    {
        BOOST_CHECK_MESSAGE(SignSignature(keystore, txFrom.vout[i], txTo[i], 0), strprintf("SignSignature %d", i));
    }
}

#ifdef ENABLE_WALLET
BOOST_AUTO_TEST_CASE(cltv_freeze)
{
    CKey key[4];
    for (int i = 0; i < 2; i++)
        key[i].MakeNewKey(true);

    // Create and unpack a CLTV script
    vector<valtype> solutions;
    txnouttype whichType;
    vector<CTxDestination> addresses;
    int nRequiredReturn;
    txnouttype type = TX_CLTV;

    // check cltv solve for block
    CPubKey newKey1 = ToByteVector(key[0].GetPubKey());
    CTxDestination newAddr1 = CTxDestination(newKey1.GetID());
    CScriptNum nFreezeLockTime = CScriptNum::fromIntUnchecked(50000);
    CScript s1 = GetScriptForFreeze(nFreezeLockTime, newKey1);

    BOOST_CHECK(Solver(s1, whichType, solutions));
    BOOST_CHECK(whichType == TX_CLTV);
    BOOST_CHECK(solutions.size() == 2);
    BOOST_CHECK(CScriptNum(solutions[0], false, CScriptNum::MAXIMUM_ELEMENT_SIZE_64_BIT) == nFreezeLockTime);

    nRequiredReturn = 0;
    ExtractDestinations(s1, type, addresses, nRequiredReturn);

    for (const CTxDestination &addr : addresses)
        BOOST_CHECK(EncodeDestination(newAddr1) == EncodeDestination(addr));
    BOOST_CHECK(nRequiredReturn == 1);

    // check cltv solve for datetime
    CPubKey newKey2 = ToByteVector(key[0].GetPubKey());
    CTxDestination newAddr2 = CTxDestination(newKey2.GetID());
    nFreezeLockTime = CScriptNum::fromIntUnchecked(1482255731);
    CScript s2 = GetScriptForFreeze(nFreezeLockTime, newKey2);

    BOOST_CHECK(Solver(s2, whichType, solutions));
    BOOST_CHECK(whichType == TX_CLTV);
    BOOST_CHECK(solutions.size() == 2);
    BOOST_CHECK(CScriptNum(solutions[0], false, CScriptNum::MAXIMUM_ELEMENT_SIZE_64_BIT) == nFreezeLockTime);

    nRequiredReturn = 0;
    ExtractDestinations(s2, type, addresses, nRequiredReturn);

    for (const CTxDestination &addr : addresses)
        BOOST_CHECK(newAddr2 == addr);

    BOOST_CHECK(nRequiredReturn == 1);
}

BOOST_AUTO_TEST_CASE(opreturn_send)
{
    CKey key[4];
    for (int i = 0; i < 2; i++)
        key[i].MakeNewKey(true);

    CBasicKeyStore keystore;

    // Create and unpack a LABELPUBLIC script
    vector<valtype> solutions;
    txnouttype whichType;
    vector<CTxDestination> addresses;

    string inMsg = "hello world", outMsg = "";
    CScript s = GetScriptLabelPublic(inMsg);
    outMsg = getLabelPublic(s);
    BOOST_CHECK(inMsg == outMsg);
    BOOST_CHECK(Solver(s, whichType, solutions));
    BOOST_CHECK(whichType == TX_LABELPUBLIC);
    BOOST_CHECK(solutions.size() == 2);

    inMsg = "hello world hello world hello world hello world hello world"
            "hello world hello world";
    s.clear();
    s = GetScriptLabelPublic(inMsg);
    outMsg = getLabelPublic(s);
    BOOST_CHECK(inMsg == outMsg);
    BOOST_CHECK(Solver(s, whichType, solutions));
    BOOST_CHECK(whichType == TX_LABELPUBLIC);

    inMsg = "hello world hello world hello world hello world hello world"
            "hello world hello world hello world hello world hello world"
            "hello world hello world hello world hello world hello world"
            "hello world hello world";
    s.clear();
    s = GetScriptLabelPublic(inMsg);
    outMsg = getLabelPublic(s);
    BOOST_CHECK(inMsg == outMsg);
    BOOST_CHECK(Solver(s, whichType, solutions));
    BOOST_CHECK(whichType == TX_LABELPUBLIC);
    BOOST_CHECK(solutions.size() == 2);
}
#endif
BOOST_AUTO_TEST_SUITE_END()
