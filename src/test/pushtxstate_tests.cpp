// Copyright (c) 2020 G. Andrew Stone
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include "consensus/tx_verify.h"
#include "core_io.h"
#include "script/interpreter.h"
#include "script/pushtxstate.h"
#include "script/script.h"
#include "script/scripttemplate.h"
#include "scriptnum10.h"
#include "test/test_nexa.h"

#include <boost/test/unit_test.hpp>
#include <stdint.h>

BOOST_FIXTURE_TEST_SUITE(pushtxstate_tests, BasicTestingSetup)

void testScript(const CScript &s,
    const CMutableTransaction *tx,
    const std::vector<CTxOut> &coins,
    unsigned int inputIdx,
    bool expectedRet,
    bool expectedStackTF,
    ScriptError expectedError)
{
    unsigned int flags = SCRIPT_ENABLE_SIGHASH_FORKID;
    CTransactionRef txref = MakeTransactionRef(*tx);
    CValidationState state;
    // Fill the validation state with derived data about this transaction
    {
        // Construct a view of all the supplied coins
        CCoinsView coinsDummy;
        CCoinsViewCache prevouts(&coinsDummy);
        for (size_t i = 0; i < coins.size(); i++)
        {
            // We assume that the passed coins are in the proper order so their outpoint is what is specified
            // in the tx.  We further assume height 1 and not coinbase.  These fields are not accessible from scripts
            // so should not affect execution.
            prevouts.AddCoin(tx->vin[i].prevout, Coin(coins[i], 1, false), false);
        }

        if (!Consensus::CheckTxInputs(txref, state, prevouts, prevouts, Params()))
        {
            assert(0); // Test malfunction
        }
        if (!CheckGroupTokens(*tx, state, prevouts, prevouts))
        {
            assert(0); // Test malfunction
        }
    }

    TransactionSignatureChecker checker(txref.get(), inputIdx, flags);
    ScriptImportedState sis(&checker, txref, state, coins, inputIdx);

    ScriptMachine sm(0, sis, 0xffffffff, 0xffffffff);
    bool ret = sm.Eval(s);
    BOOST_CHECK_MESSAGE(
        ret == expectedRet, "Received " << ret << " expected " << expectedError << " for script: " << FormatScript(s));
    if (expectedRet)
    {
        BOOST_CHECK(sm.getStack().size() == 1);
        BOOST_CHECK(((bool)sm.getStack()[0]) == expectedStackTF);
    }
    else
    {
        BOOST_CHECK_MESSAGE(sm.getError() == expectedError,
            "got: " << ScriptErrorString(sm.getError()) << " (" << sm.getError() << ")");
    }
}

void testScript(const CScript &s,
    const CMutableTransaction *tx,
    const std::vector<CTxOut> &coins,
    unsigned int inputIdx = 0,
    bool expectedStackTF = true)
{
    testScript(s, tx, coins, inputIdx, true, expectedStackTF, SCRIPT_ERR_OK);
}
void testScript(const CScript &s,
    const CMutableTransaction *tx,
    const std::vector<CTxOut> &coins,
    unsigned int inputIdx,
    ScriptError expectedError)
{
    testScript(s, tx, coins, inputIdx, false, false, expectedError);
}


BOOST_AUTO_TEST_CASE(pushtxstate)
{
    CScript s;
    CMutableTransaction tx;
    CScript simpleConstraint = CScript() << OP_1;
    std::vector<CTxOut> coins;
    tx.vout.push_back(CTxOut(12345678, simpleConstraint));

    coins.push_back(CTxOut(23456789, simpleConstraint));
    tx.vin.push_back(CTxIn(COutPoint(InsecureRand256()), 23456789));
    s = CScript() << PushTxStateSpecifier::TX_INCOMING_AMOUNT << OP_PUSH_TX_STATE << 23456789 << OP_EQUAL;
    testScript(s, &tx, coins);
    s = CScript() << PushTxStateSpecifier::TX_OUTGOING_AMOUNT << OP_PUSH_TX_STATE << 12345678 << OP_EQUAL;
    testScript(s, &tx, coins);
    coins.push_back(CTxOut(34567890, simpleConstraint));
    tx.vin.push_back(CTxIn(COutPoint(InsecureRand256()), 34567890));
    tx.vout.push_back(CTxOut(45678901, simpleConstraint));

    s = CScript() << PushTxStateSpecifier::TX_INCOMING_AMOUNT << OP_PUSH_TX_STATE << (23456789 + 34567890) << OP_EQUAL;
    testScript(s, &tx, coins);
    s = CScript() << PushTxStateSpecifier::TX_OUTGOING_AMOUNT << OP_PUSH_TX_STATE << (12345678 + 45678901) << OP_EQUAL;
    testScript(s, &tx, coins);
    // testScript(s, &tx, 0, 0, false);

    // impossible if s is the constraint script because s changes the hash which changes dependent tx input.
    s = CScript() << PushTxStateSpecifier::TX_ID << OP_PUSH_TX_STATE << tx.GetId() << OP_EQUAL;
    testScript(s, &tx, coins);
    s = CScript() << PushTxStateSpecifier::TX_IDEM << OP_PUSH_TX_STATE << tx.GetIdem() << OP_EQUAL;
    testScript(s, &tx, coins);
}

// create a group pay to OP_1
CScript successConstraint = CScript() << OP_1 << OP_DROP;
VchType successConstraintHash = VchHash160(ToByteVector(successConstraint));
CScript gp2op1(const CGroupTokenID &group, CAmount amt)
{
    CScript script = ScriptTemplateOutput(successConstraintHash, VchType(), VchType(), group, amt);
    return script;
}

CScript op1op1 = CScript() << OP_1 << OP_DROP << OP_1 << OP_DROP;
VchType op1op1Hash = VchHash(ToByteVector(op1op1));
CScript tmplop1op1(const CGroupTokenID &group, CAmount amt)
{
    CScript tmpl = CScript() << OP_1 << OP_DROP << OP_1 << OP_DROP;
    CScript constraint = CScript(ScriptType::TEMPLATE) << group.bytes() << SerializeAmount(amt) << op1op1Hash << OP_0;
    return constraint;
}


void TestAmountsAndCounts(const CMutableTransaction &tx,
    const std::vector<CTxOut> &coins,
    const CGroupTokenID &grp,
    int inAmt,
    int inCnt,
    int outAmt,
    int outCnt)
{
    CScript s;
    s = CScript() << PushTxStateSpecifier::GROUP_INCOMING_AMOUNT << grp.bytes() << OP_CAT << OP_PUSH_TX_STATE << inAmt
                  << OP_EQUAL;
    testScript(s, &tx, coins);

    s = CScript() << PushTxStateSpecifier::GROUP_INCOMING_COUNT << grp.bytes() << OP_CAT << OP_PUSH_TX_STATE << inCnt
                  << OP_EQUAL;
    testScript(s, &tx, coins);

    s = CScript() << PushTxStateSpecifier::GROUP_OUTGOING_AMOUNT << grp.bytes() << OP_CAT << OP_PUSH_TX_STATE << outAmt
                  << OP_EQUAL;
    testScript(s, &tx, coins);

    s = CScript() << PushTxStateSpecifier::GROUP_OUTGOING_COUNT << grp.bytes() << OP_CAT << OP_PUSH_TX_STATE << outCnt
                  << OP_EQUAL;
    testScript(s, &tx, coins);
}

void NegativeTestAmountsAndCounts(const CMutableTransaction &tx,
    const std::vector<CTxOut> &coins,
    const CGroupTokenID &grp)
{
    CScript s;
    VchType tooSmall(31);

    // undefined specifier
    s = CScript() << 255 << OP_PUSH_TX_STATE;
    testScript(s, &tx, coins, 0, SCRIPT_ERR_INVALID_STATE_SPECIFIER);

    // No group
    s = CScript() << PushTxStateSpecifier::GROUP_INCOMING_AMOUNT << OP_PUSH_TX_STATE;
    testScript(s, &tx, coins, 0, SCRIPT_ERR_INVALID_STATE_SPECIFIER);

    // Group must be a minimum of 32 bytes (smaller values are reserved for special use)
    s = CScript() << PushTxStateSpecifier::GROUP_INCOMING_AMOUNT << tooSmall << OP_CAT << OP_PUSH_TX_STATE;
    testScript(s, &tx, coins, 0, SCRIPT_ERR_INVALID_STATE_SPECIFIER);

    // Note larger length groups are subgroups so valid
}

BOOST_AUTO_TEST_CASE(covenantedAndSubgroupPushtxstate)
{
    CScript s;
    CMutableTransaction tx;
    CScript simpleConstraint = CScript() << OP_1;
    std::vector<CTxOut> coins;

    CGroupTokenID grp1(1, GroupTokenIdFlags::COVENANT);
    VchType subgrpbytes(grp1.bytes().begin(), grp1.bytes().end()); // Make this is a subgroup of grp1...
    subgrpbytes.resize(60);
    subgrpbytes[33] = 1;
    CGroupTokenID subgrp(subgrpbytes);

    // Pull in 2 inputs and make sure that the first one is set as the covenant.
    coins.push_back(CTxOut(10, gp2op1(grp1, 100)));
    tx.vin.push_back(CTxIn(COutPoint(InsecureRand256()), 10));
    coins.push_back(CTxOut(10, tmplop1op1(grp1, 200)));
    tx.vin.push_back(CTxIn(COutPoint(InsecureRand256()), 10));
    // Pull in a subgroup and try to use it
    coins.push_back(CTxOut(10, tmplop1op1(subgrp, 200)));
    tx.vin.push_back(CTxIn(COutPoint(InsecureRand256()), 10));

    tx.vout.push_back(CTxOut(10, simpleConstraint));
    tx.vout.push_back(CTxOut(1, gp2op1(grp1, 300)));
    tx.vout.push_back(CTxOut(1, tmplop1op1(subgrp, 200)));

    // ensure that first script is returned as the covenant
    s = CScript() << PushTxStateSpecifier::GROUP_COVENANT_HASH << grp1.bytes() << OP_CAT << OP_PUSH_TX_STATE
                  << successConstraintHash << OP_EQUAL;
    testScript(s, &tx, coins);
    // ensure that 2nd script is NOT returned as the covenant
    s = CScript() << PushTxStateSpecifier::GROUP_COVENANT_HASH << grp1.bytes() << OP_CAT << OP_PUSH_TX_STATE
                  << op1op1Hash << OP_EQUAL << OP_FALSE << OP_EQUAL;
    testScript(s, &tx, coins);

    s = CScript() << PushTxStateSpecifier::GROUP_COVENANT_HASH << subgrp.bytes() << OP_CAT << OP_PUSH_TX_STATE
                  << op1op1Hash << OP_EQUAL;
    testScript(s, &tx, coins);

    // The subgroup counts should not include anything from the parent group,
    // so there will be just the 1 input and output
    TestAmountsAndCounts(tx, coins, subgrp, 200, 1, 200, 1);
    // The parent group counts should not include anything from the subgroup,
    TestAmountsAndCounts(tx, coins, grp1, 300, 2, 300, 1);
}

BOOST_AUTO_TEST_CASE(groupauthoritypushtxstate)
{
    CScript s;
    CMutableTransaction tx;
    CScript simpleConstraint = CScript() << OP_1;
    std::vector<CTxOut> coins;

    CGroupTokenID grp1(1);
    CGroupTokenID grp2(2);
    CGroupTokenID fgrp1(3, GroupTokenIdFlags::HOLDS_NEX);
    CGroupTokenID grpUnused(200);
    VchType grpTooSmall(31);

    int64_t auth1 =
        (int64_t)(GroupAuthorityFlags::AUTHORITY | GroupAuthorityFlags::MINT | GroupAuthorityFlags::SUBGROUP);
    int64_t auth2 = (int64_t)(GroupAuthorityFlags::AUTHORITY | GroupAuthorityFlags::MELT | GroupAuthorityFlags::BATON);
    coins.push_back(CTxOut(10, gp2op1(grp1, auth1)));
    tx.vin.push_back(CTxIn(COutPoint(InsecureRand256()), 10));
    coins.push_back(CTxOut(10, gp2op1(grp2, auth2)));
    tx.vin.push_back(CTxIn(COutPoint(InsecureRand256()), 10));
    coins.push_back(CTxOut(10, gp2op1(grp2, 600)));
    tx.vin.push_back(CTxIn(COutPoint(InsecureRand256()), 10));
    coins.push_back(CTxOut(10000, gp2op1(fgrp1, 0)));
    tx.vin.push_back(CTxIn(COutPoint(InsecureRand256()), 10000));
    coins.push_back(CTxOut(2345, gp2op1(fgrp1, 0)));
    tx.vin.push_back(CTxIn(COutPoint(InsecureRand256()), 2345));

    // Create a tx involving 2 groups with 3 inputs and 4 outputs
    tx.vout.push_back(CTxOut(9, simpleConstraint));
    tx.vout.push_back(CTxOut(1, gp2op1(grp1, 1234)));
    tx.vout.push_back(CTxOut(1, gp2op1(grp1, 1)));
    tx.vout.push_back(CTxOut(1, gp2op1(grp2, 2)));
    tx.vout.push_back(CTxOut(1, gp2op1(grp2, 3)));
    tx.vout.push_back(CTxOut(12345, gp2op1(fgrp1, 0)));
    tx.vout.push_back(CTxOut(1, gp2op1(grp2, auth2))); // Output a child authority

    TestAmountsAndCounts(tx, coins, grp1, 0, 1, 1235, 2); // counts include authorities
    TestAmountsAndCounts(tx, coins, grp2, 600, 2, 5, 3);
    TestAmountsAndCounts(tx, coins, fgrp1, 12345, 2, 12345, 1); // Fenced groups return fenced BCH not token amounts
    NegativeTestAmountsAndCounts(tx, coins, grp2);

    // ensure that the authority is returned in inputs
    s = CScript() << PushTxStateSpecifier::GROUP_NTH_INPUT << 0 << 2 << OP_NUM2BIN << OP_CAT << grp2.bytes() << OP_CAT
                  << OP_PUSH_TX_STATE << 1 << OP_EQUAL;
    testScript(s, &tx, coins);
    // ensure that the authority is returned in outputs too
    s = CScript() << PushTxStateSpecifier::GROUP_NTH_OUTPUT << 2 << 2 << OP_NUM2BIN << OP_CAT << grp2.bytes() << OP_CAT
                  << OP_PUSH_TX_STATE << 6 << OP_EQUAL;
    testScript(s, &tx, coins);
}


BOOST_AUTO_TEST_CASE(grouppushtxstate)
{
    CScript s;
    CMutableTransaction tx;
    CScript simpleConstraint = CScript() << OP_1;
    std::vector<CTxOut> coins;

    CGroupTokenID grp1(1);
    CGroupTokenID grp2(2);
    CGroupTokenID fgrp1(3, GroupTokenIdFlags::HOLDS_NEX);
    CGroupTokenID grpUnused(200);
    VchType grpTooSmall(31);


    // Create a tx involving 2 groups with 3 inputs and 4 outputs
    tx.vout.push_back(CTxOut(1, simpleConstraint));
    tx.vout.push_back(CTxOut(1, gp2op1(grp1, 7)));
    tx.vout.push_back(CTxOut(1, gp2op1(grp2, 1)));
    tx.vout.push_back(CTxOut(1, gp2op1(grp2, 2)));
    tx.vout.push_back(CTxOut(1, gp2op1(grp2, 3)));

    coins.push_back(CTxOut(10, gp2op1(grp1, 3)));
    tx.vin.push_back(CTxIn(COutPoint(InsecureRand256()), 10));
    coins.push_back(CTxOut(10, gp2op1(grp1, 4)));
    tx.vin.push_back(CTxIn(COutPoint(InsecureRand256()), 10));
    coins.push_back(CTxOut(10, gp2op1(grp2, 6)));
    tx.vin.push_back(CTxIn(COutPoint(InsecureRand256()), 10));

    TestAmountsAndCounts(tx, coins, grp1, 7, 2, 7, 1);
    TestAmountsAndCounts(tx, coins, grp2, 6, 1, 6, 3);
    TestAmountsAndCounts(tx, coins, grpUnused, 0, 0, 0, 0);
    NegativeTestAmountsAndCounts(tx, coins, grp2);

    // the 0th input for grp1 is index 0
    s = CScript() << PushTxStateSpecifier::GROUP_NTH_INPUT << 0 << 2 << OP_NUM2BIN << OP_CAT << grp1.bytes() << OP_CAT
                  << OP_PUSH_TX_STATE << 0 << OP_EQUAL;
    testScript(s, &tx, coins);
    // the 1th input for grp1 is index 1
    s = CScript() << PushTxStateSpecifier::GROUP_NTH_INPUT << 1 << 2 << OP_NUM2BIN << OP_CAT << grp1.bytes() << OP_CAT
                  << OP_PUSH_TX_STATE << 1 << OP_EQUAL;
    testScript(s, &tx, coins);

    // the 0th input for grp2 is index 2
    s = CScript() << PushTxStateSpecifier::GROUP_NTH_INPUT << 0 << 2 << OP_NUM2BIN << OP_CAT << grp2.bytes() << OP_CAT
                  << OP_PUSH_TX_STATE << 2 << OP_EQUAL;
    testScript(s, &tx, coins);

    // the 1th input for grp2 does not exist
    s = CScript() << PushTxStateSpecifier::GROUP_NTH_INPUT << 1 << 2 << OP_NUM2BIN << OP_CAT << grp2.bytes() << OP_CAT
                  << OP_PUSH_TX_STATE << 2 << OP_EQUAL;
    testScript(s, &tx, coins, 0, SCRIPT_ERR_INVALID_STATE_SPECIFIER);

    // group too few bytes
    s = CScript() << PushTxStateSpecifier::GROUP_NTH_INPUT << 1 << 2 << OP_NUM2BIN << OP_CAT << grpTooSmall << OP_CAT
                  << OP_PUSH_TX_STATE << 2 << OP_EQUAL;
    testScript(s, &tx, coins, 0, SCRIPT_ERR_INVALID_STATE_SPECIFIER);

    // Forget the group
    s = CScript() << PushTxStateSpecifier::GROUP_NTH_INPUT << 1 << 2 << OP_NUM2BIN << OP_CAT << OP_PUSH_TX_STATE << 2
                  << OP_EQUAL;
    testScript(s, &tx, coins, 0, SCRIPT_ERR_INVALID_STATE_SPECIFIER);


    // the 0th output for grp1 is index 0
    s = CScript() << PushTxStateSpecifier::GROUP_NTH_OUTPUT << 0 << 2 << OP_NUM2BIN << OP_CAT << grp1.bytes() << OP_CAT
                  << OP_PUSH_TX_STATE << 1 << OP_EQUAL;
    testScript(s, &tx, coins);
    // the 1th output for grp1 does not exist
    s = CScript() << PushTxStateSpecifier::GROUP_NTH_OUTPUT << 1 << 2 << OP_NUM2BIN << OP_CAT << grp1.bytes() << OP_CAT
                  << OP_PUSH_TX_STATE << 1 << OP_EQUAL;
    testScript(s, &tx, coins, 0, SCRIPT_ERR_INVALID_STATE_SPECIFIER);

    // the 0th output for grp2 is index 2
    s = CScript() << PushTxStateSpecifier::GROUP_NTH_OUTPUT << 0 << 2 << OP_NUM2BIN << OP_CAT << grp2.bytes() << OP_CAT
                  << OP_PUSH_TX_STATE << 2 << OP_EQUAL;
    testScript(s, &tx, coins);

    // the 1th output for grp2 is index 3
    s = CScript() << PushTxStateSpecifier::GROUP_NTH_OUTPUT << 1 << 2 << OP_NUM2BIN << OP_CAT << grp2.bytes() << OP_CAT
                  << OP_PUSH_TX_STATE << 3 << OP_EQUAL;
    testScript(s, &tx, coins);

    // the 2th output for grp2 is index 4
    s = CScript() << PushTxStateSpecifier::GROUP_NTH_OUTPUT << 2 << 2 << OP_NUM2BIN << OP_CAT << grp2.bytes() << OP_CAT
                  << OP_PUSH_TX_STATE << 4 << OP_EQUAL;
    testScript(s, &tx, coins);

    // group too few bytes
    s = CScript() << PushTxStateSpecifier::GROUP_NTH_OUTPUT << 1 << 2 << OP_NUM2BIN << OP_CAT << grpTooSmall << OP_CAT
                  << OP_PUSH_TX_STATE << 2 << OP_EQUAL;
    testScript(s, &tx, coins, 0, SCRIPT_ERR_INVALID_STATE_SPECIFIER);

    // Forget the group
    s = CScript() << PushTxStateSpecifier::GROUP_NTH_OUTPUT << 1 << 2 << OP_NUM2BIN << OP_CAT << OP_PUSH_TX_STATE << 2
                  << OP_EQUAL;
    testScript(s, &tx, coins, 0, SCRIPT_ERR_INVALID_STATE_SPECIFIER);
}


BOOST_AUTO_TEST_SUITE_END()
