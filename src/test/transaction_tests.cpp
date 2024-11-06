// Copyright (c) 2011-2015 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "data/tx_invalid.json.h"
#include "data/tx_valid.json.h"
#include "test/test_nexa.h"

#include "clientversion.h"
#include "consensus/tx_verify.h"
#include "consensus/validation.h"
#include "core_io.h"
#include "key.h"
#include "keystore.h"
#include "main.h" // For CheckTransaction
#include "policy/policy.h"
#include "script/script.h"
#include "script/script_error.h"
#include "test/scriptflags.h"
#include "test/testutil.h"
#include "tweak.h"
#include "utilstrencodings.h"

#include <map>
#include <string>

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/test/unit_test.hpp>

#include <univalue.h>

extern CTweak<bool> enforceMinTxSize;
extern CTweak<uint32_t> dataCarrierSize;

using namespace std;

// In script_tests.cpp
extern UniValue read_json(const std::string &jsondata);

BOOST_FIXTURE_TEST_SUITE(transaction_tests, TestChain100Setup)


#if 0 // TODO: add hard-coded test vectors based on the new transaction format
BOOST_AUTO_TEST_CASE(tx_valid)
{
    enforceMinTxSize.Set(false);

    // Read tests from test/data/tx_valid.json
    // Format is an array of arrays
    // Inner arrays are either [ "comment" ]
    // or [[[prevout hash, prevout index, prevout scriptPubKey], [input 2], ...],"], serializedTransaction, verifyFlags
    // ... where all scripts are stringified scripts.
    //
    // verifyFlags is a comma separated list of script verification flags to apply, or "NONE"
    UniValue tests = read_json(std::string(json_tests::tx_valid, json_tests::tx_valid + sizeof(json_tests::tx_valid)));

    for (unsigned int idx = 0; idx < tests.size(); idx++)
    {
        UniValue test = tests[idx];
        string strTest = test.write();
        if (test[0].isArray())
        {
            if (test.size() != 3 || !test[1].isStr() || !test[2].isStr())
            {
                BOOST_ERROR("Bad test: " << strTest);
                continue;
            }

            map<COutPoint, CScript> mapprevOutScriptPubKeys;
            std::map<COutPoint, int64_t> mapprevOutValues;
            UniValue inputs = test[0].get_array();
            bool fValid = true;
            for (unsigned int inpIdx = 0; inpIdx < inputs.size(); inpIdx++)
            {
                const UniValue &input = inputs[inpIdx];
                if (!input.isArray())
                {
                    fValid = false;
                    break;
                }
                UniValue vinput = input.get_array();
                if (vinput.size() != 3)
                {
                    fValid = false;
                    break;
                }

                COutPoint outpoint(uint256S(vinput[0].get_str()), vinput[1].get_int());
                mapprevOutScriptPubKeys[outpoint] = ParseScript(vinput[2].get_str());
                if (vinput.size() >= 4)
                {
                    mapprevOutValues[outpoint] = vinput[3].get_int64();
                }
            }
            if (!fValid)
            {
                BOOST_ERROR("Bad test: " << strTest);
                continue;
            }

            string transaction = test[1].get_str();
            CDataStream stream(ParseHex(transaction), SER_NETWORK, PROTOCOL_VERSION);
            CTransaction tx;
            stream >> tx;

            CValidationState state;
            CTransactionRef txref = MakeTransactionRef(tx);
            BOOST_CHECK_MESSAGE(CheckTransaction(txref, state), strTest);
            BOOST_CHECK(state.IsValid());

            for (unsigned int i = 0; i < tx.vin.size(); i++)
            {
                if (!mapprevOutScriptPubKeys.count(tx.vin[i].prevout))
                {
                    BOOST_ERROR("Bad test: " << strTest);
                    break;
                }

                CAmount amount = 0;
                if (mapprevOutValues.count(tx.vin[i].prevout))
                {
                    amount = mapprevOutValues[tx.vin[i].prevout];
                }

                unsigned int verify_flags = ParseScriptFlags(test[2].get_str());
                //TransactionSignatureChecker tsc(&tx, i, amount, verify_flags);
                NearlyAlwaysGoodSignatureChecker tsc(verify_flags);
                ScriptImportedState sis(&tsc, txref, std::vector<CTxOut>(), i, amount);
                // TODO: ptschip - get valid Schnorr signed transactions to be tested into the json data file.
                //                 Could use some of these valid ECDSA transactions to prove that they will not be
                //                 accepted.
                // BOOST_CHECK_MESSAGE(VerifyScript(tx.vin[i].scriptSig, mapprevOutScriptPubKeys[tx.vin[i].prevout],
                //                        verify_flags, MAX_OPS_PER_SCRIPT, sis, &err),
                //    strTest);
                // BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));
            }
        }
    }

    enforceMinTxSize.Set(true);
}
#endif


BOOST_AUTO_TEST_CASE(dynamic_tx_validity_fork1)
{
    CMutableTransaction tx;
    CTransactionRef txref;
    CKey k;
    k.MakeNewKey(true);
    CPubKey pk = k.GetPubKey();
    CScript simpleConstraint = CScript() << OP_1;
    CScript dataConstraint = CScript() << OP_RETURN << OP_1;
    CScript p2shConstraint = p2sh(CScriptID(simpleConstraint));
    CScript pubkeyConstraint = CScript() << ToByteVector(pk) << OP_CHECKSIG;
    CScript p2pkhConstraint = p2pkh(CKeyID());
    CValidationState state;

    auto tip = chainActive.Tip();
    const CChainParams &cp = Params();

    // Small pre-fork1 test to make sure it doesn't prematurely activate
    tx.vout.push_back(CTxOut(1, simpleConstraint));
    txref = MakeTransactionRef(tx);
    BOOST_CHECK_MESSAGE(ContextualCheckTransaction(txref, state, tip, cp), "fork1 is incorrectly active");
    BOOST_CHECK(state.IsValid());

    // Fake trigger fork1
    auto oldForkTime = nMiningForkTime;
    nMiningForkTime = 0;
    BOOST_CHECK(IsFork1Activated(tip));

    state.SetNull(); // try the above test again, fork1 activated
    BOOST_CHECK_MESSAGE(!ContextualCheckTransaction(txref, state, tip, cp), "output script unconstrained by fork1");
    BOOST_CHECK(!state.IsValid());

    state.SetNull();
    tx.vout[0] = CTxOut(0, dataConstraint);
    txref = MakeTransactionRef(tx);
    BOOST_CHECK_MESSAGE(ContextualCheckTransaction(txref, state, tip, cp), "output script fork1 should allow data");
    BOOST_CHECK(state.IsValid());

    state.SetNull();
    tx.vout[0] = CTxOut(1, p2shConstraint);
    txref = MakeTransactionRef(tx);
    BOOST_CHECK_MESSAGE(
        ContextualCheckTransaction(txref, state, tip, cp), "output script fork1 allows p2sh on regtest");
    BOOST_CHECK(state.IsValid());

    state.SetNull();
    tx.vout[0] = CTxOut(1, pubkeyConstraint);
    txref = MakeTransactionRef(tx);
    BOOST_CHECK_MESSAGE(!ContextualCheckTransaction(txref, state, tip, cp), "output script fork1 not allow pubkey");
    BOOST_CHECK(!state.IsValid());

    state.SetNull();
    tx.vout[0] = CTxOut(1, p2pkhConstraint);
    txref = MakeTransactionRef(tx);
    BOOST_CHECK_MESSAGE(ContextualCheckTransaction(txref, state, tip, cp), "output script fork1 should allow p2pkh");
    BOOST_CHECK(state.IsValid());


    VchType goodSizes[] = {{20}, {32}};
    goodSizes[0].resize(20);
    goodSizes[1].resize(32);

    VchType badSizes[] = {{4}, {8}, {19}, {33}};
    badSizes[0].resize(4);
    badSizes[1].resize(8);
    badSizes[2].resize(19);
    badSizes[3].resize(33);

    for (const auto &v : badSizes)
    {
        state.SetNull();
        CScript st = CScript(ScriptType::TEMPLATE) << OP_0 << v << goodSizes[0];
        tx.vout[0] = CTxOut(10, st);
        txref = MakeTransactionRef(tx);
        BOOST_CHECK_MESSAGE(
            !ContextualCheckTransaction(txref, state, tip, cp), "output script bad script template size");
        BOOST_CHECK(!state.IsValid());

        state.SetNull();
        st = CScript(ScriptType::TEMPLATE) << OP_0 << goodSizes[0] << v;
        tx.vout[0] = CTxOut(10, st);
        txref = MakeTransactionRef(tx);
        BOOST_CHECK_MESSAGE(!ContextualCheckTransaction(txref, state, tip, cp), "output script bad args hash size");
        BOOST_CHECK(!state.IsValid());
    }

    state.SetNull();

    CScript st = CScript(ScriptType::TEMPLATE) << OP_0 << OP_1 << goodSizes[0];
    tx.vout[0] = CTxOut(10, st);
    txref = MakeTransactionRef(tx);
    BOOST_CHECK_MESSAGE(ContextualCheckTransaction(txref, state, tip, cp), "output script good well known");
    BOOST_CHECK(state.IsValid());

    for (const auto &v : goodSizes)
    {
        state.SetNull();
        st = CScript(ScriptType::TEMPLATE) << OP_0 << v << v;
        tx.vout[0] = CTxOut(10, st);
        txref = MakeTransactionRef(tx);
        BOOST_CHECK_MESSAGE(
            ContextualCheckTransaction(txref, state, tip, cp), "output script good script template & args size");
        BOOST_CHECK(state.IsValid());
    }

    nMiningForkTime = oldForkTime;
}

// Invalid transactions generated dynamically by this test
BOOST_AUTO_TEST_CASE(dynamic_tx_validity)
{
    CMutableTransaction tx;
    CTransactionRef txref;
    CScript simpleConstraint = CScript() << OP_1;
    CScript simpleBigConstraint =
        CScript() << OP_1 << OP_DROP << OP_1 << OP_DROP << OP_1 << OP_DROP << OP_1 << OP_DROP << OP_1 << OP_DROP << OP_1
                  << OP_DROP << OP_1 << OP_DROP << OP_1 << OP_DROP << OP_1 << OP_DROP << OP_1 << OP_DROP << OP_1
                  << OP_DROP << OP_1 << OP_DROP << OP_1 << OP_DROP << OP_1 << OP_DROP << OP_1 << OP_DROP << OP_1
                  << OP_DROP << OP_1 << OP_DROP << OP_1 << OP_DROP << OP_1 << OP_DROP << OP_1 << OP_DROP << OP_1
                  << OP_DROP << OP_1 << OP_DROP << OP_1 << OP_DROP << OP_1 << OP_DROP << OP_1 << OP_DROP << OP_1
                  << OP_DROP << OP_1 << OP_DROP << OP_1 << OP_DROP << OP_1 << OP_DROP << OP_1 << OP_DROP << OP_1
                  << OP_DROP << OP_1 << OP_DROP << OP_1 << OP_DROP << OP_1 << OP_DROP << OP_1 << OP_DROP << OP_1
                  << OP_DROP << OP_1 << OP_DROP << OP_1 << OP_DROP << OP_1 << OP_DROP << OP_1 << OP_DROP << OP_1
                  << OP_DROP << OP_1 << OP_DROP << OP_1 << OP_DROP << OP_1 << OP_DROP << OP_1 << OP_DROP << OP_1
                  << OP_DROP << OP_1 << OP_DROP << OP_1 << OP_DROP << OP_1 << OP_DROP << OP_1 << OP_DROP << OP_1
                  << OP_DROP << OP_1 << OP_DROP << OP_1 << OP_DROP << OP_1 << OP_DROP << OP_1 << OP_DROP << OP_1
                  << OP_DROP << OP_1 << OP_DROP << OP_1 << OP_DROP << OP_1 << OP_DROP << OP_1 << OP_DROP << OP_1
                  << OP_DROP << OP_1 << OP_DROP << OP_1 << OP_DROP << OP_1 << OP_DROP << OP_1;

    // Check vout rules in a coinbase

    // Check that a coinbase with no inputs and no outputs fails
    CValidationState state;
    txref = MakeTransactionRef(tx);
    BOOST_CHECK_MESSAGE(!CheckTransaction(txref, state), "coinbase no vouts");
    BOOST_CHECK(!state.IsValid());

    state = CValidationState();
    // Check that a coinbase without OP_RETURN fails
    tx.vout.push_back(CTxOut(1, simpleBigConstraint));
    txref = MakeTransactionRef(tx);
    BOOST_CHECK_MESSAGE(!CheckTransaction(txref, state), "coinbase no op_return");
    BOOST_CHECK(!state.IsValid());

    state = CValidationState();
    // Fill out the maximum vouts
    for (unsigned int i = 0; i < MAX_TX_NUM_VOUT - 2; i++)
    {
        tx.vout.push_back(CTxOut(1, simpleConstraint));
    }
    tx.vout.push_back(CTxOut(0, CScript() << OP_RETURN));
    // tx should be ok
    txref = MakeTransactionRef(tx);
    BOOST_CHECK_MESSAGE(CheckTransaction(txref, state), "at max vouts");
    BOOST_CHECK(state.IsValid());

    state = CValidationState();
    // check that version greater than current version fails
    tx.nVersion = CTransaction::CURRENT_VERSION + 1;
    txref = MakeTransactionRef(tx);
    BOOST_CHECK_MESSAGE(!CheckTransaction(txref, state), "tx version too high");
    BOOST_CHECK(!state.IsValid());
    BOOST_CHECK(state.GetRejectReason() == "bad-txns-version");
    tx.nVersion = CTransaction::CURRENT_VERSION;
    state = CValidationState();

    // Check that 1 more vout causes a tx failure
    tx.vout.push_back(CTxOut(1, CScript() << OP_RETURN));
    txref = MakeTransactionRef(tx);
    BOOST_CHECK_MESSAGE(!CheckTransaction(txref, state), "max vouts exceeded");
    BOOST_CHECK(!state.IsValid());
    BOOST_CHECK(state.GetRejectReason() == "bad-txns-too-many-vout");

    state = CValidationState();

    // Check vout rules in a normal tx

    // need at least 1 input for the tx to be considered not a coinbase...
    tx.vin.push_back(CTxIn(COutPoint(InsecureRand256()), 100));

    tx.vout.resize(MAX_TX_NUM_VOUT);
    txref = MakeTransactionRef(tx);
    BOOST_CHECK_MESSAGE(CheckTransaction(txref, state), "at max vouts");
    BOOST_CHECK(state.IsValid());

    // Check that 1 more vout causes a tx failure
    tx.vout.push_back(CTxOut(1, simpleConstraint));
    txref = MakeTransactionRef(tx);
    BOOST_CHECK_MESSAGE(!CheckTransaction(txref, state), "max vouts exceeded");
    BOOST_CHECK(!state.IsValid());
    BOOST_CHECK(state.GetRejectReason() == "bad-txns-too-many-vout");

    // OK now check input count restrictions
    state = CValidationState();
    tx.vout.resize(MAX_TX_NUM_VOUT);
    // Fill out the maximum vins
    while (tx.vin.size() < MAX_TX_NUM_VIN)
    {
        tx.vin.push_back(CTxIn(COutPoint(InsecureRand256()), 100));
    }

    txref = MakeTransactionRef(tx);
    BOOST_CHECK_MESSAGE(CheckTransaction(txref, state), "at max vins");
    BOOST_CHECK(state.IsValid());

    /* Uncomment to regenerate this transaction for inclusion into the python test code.  It will make a different
       tx every time since some of the data is random
    */
    /*
    printf("Huge TX for testpynode.py:\n");
    std::string s = txref->HexStr();
    for(size_t i=0; i< s.length(); i+=150)
    {
        printf("'%s',\n", s.substr(i, 150).c_str());
    }
    printf("Idem: %s\n", txref->GetIdem().GetHex().c_str());
    printf("Id: %s\n", txref->GetId().GetHex().c_str());
    */

    auto tmptype = tx.vout[5].type;
    tx.vout[5].type = 2;
    txref = MakeTransactionRef(tx);
    BOOST_CHECK_MESSAGE(!CheckTransaction(txref, state), "txout type invalid");
    BOOST_CHECK(!state.IsValid());
    BOOST_CHECK(state.GetRejectReason() == "bad-txns-invalid-txout-type");
    tx.vout[5].type = tmptype;
    state.SetNull();

    tmptype = tx.vin[5].type;
    tx.vin[5].type = 2;
    txref = MakeTransactionRef(tx);
    BOOST_CHECK_MESSAGE(!CheckTransaction(txref, state), "txin type invalid");
    BOOST_CHECK(!state.IsValid());
    BOOST_CHECK(state.GetRejectReason() == "bad-txns-invalid-txin-type");
    tx.vin[5].type = tmptype;
    state.SetNull();

    // bad readonly input (has a non zero sequence)
    tmptype = tx.vin[5].type;
    uint32_t tmpsequence = tx.vin[5].nSequence;
    CScript tmpsig = tx.vin[5].scriptSig;
    tx.vin[5].amount = 0;
    tx.vin[5].type = 1; // READ ONLY with a sequence is invalid
    tx.vin[5].nSequence = 10;
    tx.vin[5].scriptSig = CScript();
    txref = MakeTransactionRef(tx);
    BOOST_CHECK_MESSAGE(!CheckTransaction(txref, state), "txin type invalid");
    BOOST_CHECK(!state.IsValid());
    BOOST_CHECK(state.GetRejectReason() == "bad-txns-invalid-readonly-sequence");
    tx.vin[5].type = tmptype;
    tx.vin[5].nSequence = tmpsequence;
    tx.vin[5].scriptSig = tmpsig;
    state.SetNull();

    // verify amount is 0 for readonly
    tx.vin[5].type = 1;
    tx.vin[5].scriptSig = CScript();
    tx.vin[5].amount = 1;
    tx.vin[5].nSequence = 0;
    txref = MakeTransactionRef(tx);
    BOOST_CHECK(!CheckTransaction(txref, state));
    BOOST_CHECK(!state.IsValid());
    BOOST_CHECK(state.GetRejectReason() == "bad-txns-nonzero-readonly-amount");
    state.SetNull();
    tx.vin[5].amount = 0;
    txref = MakeTransactionRef(tx);
    BOOST_CHECK(CheckTransaction(txref, state));
    BOOST_CHECK(state.IsValid());

    state.SetNull();

    // valid readonly input either with or without a scriptSig
    tx.vin[5].type = 1; // READ ONLY without a scriptsig is valid
    tx.vin[5].scriptSig = CScript();
    tx.vin[5].nSequence = 0;
    tx.vin[5].amount = 0;
    txref = MakeTransactionRef(tx);
    BOOST_CHECK(CheckTransaction(txref, state));
    BOOST_CHECK(state.IsValid());
    tx.vin[5].scriptSig = CScript() << OP_1;
    BOOST_CHECK(CheckTransaction(txref, state));
    BOOST_CHECK(state.IsValid());
    tx.vin[5].type = tmptype;
    tx.vin[5].nSequence = tmpsequence;
    tx.vin[5].scriptSig = tmpsig;

    state.SetNull();

    // same as above but use CTxIn SetReadOnly method
    // valid readonly input
    tmptype = tx.vin[5].type;
    tmpsequence = tx.vin[5].nSequence;
    tmpsig = tx.vin[5].scriptSig;
    tx.vin[5].SetReadOnly();
    tx.vin[5].scriptSig = CScript();
    tx.vin[5].nSequence = 0;
    tx.vin[5].amount = 0;
    txref = MakeTransactionRef(tx);
    BOOST_CHECK(CheckTransaction(txref, state));
    BOOST_CHECK(state.IsValid());

    // check repeated RO and consumed input
    auto old4 = tx.vin[4];
    tx.vin[4].prevout = tx.vin[5].prevout;
    tx.vin[4].scriptSig = tmpsig;
    txref = MakeTransactionRef(tx);
    BOOST_CHECK(!CheckTransaction(txref, state));
    BOOST_CHECK(!state.IsValid());
    BOOST_CHECK(state.GetRejectReason() == "bad-txns-inputs-duplicate");

    // check repeated RO
    tx.vin[4].SetReadOnly();
    tx.vin[4].scriptSig = CScript();
    tx.vin[4].nSequence = 0;
    tx.vin[4].amount = 0;
    txref = MakeTransactionRef(tx);
    BOOST_CHECK(!CheckTransaction(txref, state));
    BOOST_CHECK(!state.IsValid());
    BOOST_CHECK(state.GetRejectReason() == "bad-txns-inputs-duplicate");

    tx.vin[4] = old4;
    tx.vin[5].type = tmptype;
    tx.vin[5].nSequence = tmpsequence;
    tx.vin[5].scriptSig = tmpsig;
    state.SetNull();

    // Check that 1 more vout causes a tx failure
    tx.vin.push_back(CTxIn(COutPoint(InsecureRand256()), 100));
    txref = MakeTransactionRef(tx);
    BOOST_CHECK_MESSAGE(!CheckTransaction(txref, state), "max vins exceeded");
    BOOST_CHECK(!state.IsValid());
    BOOST_CHECK(state.GetRejectReason() == "bad-txns-too-many-vin");
}

#if 0 // TODO: add hard-coded test vectors based on the new transaction format
BOOST_AUTO_TEST_CASE(tx_invalid)
{
    // Read tests from test/data/tx_invalid.json
    // Format is an array of arrays
    // Inner arrays are either [ "comment" ]
    // or [[[prevout hash, prevout index, prevout scriptPubKey], [input 2], ...],"], serializedTransaction, verifyFlags
    // ... where all scripts are stringified scripts.
    //
    // verifyFlags is a comma separated list of script verification flags to apply, or "NONE"
    UniValue tests =
        read_json(std::string(json_tests::tx_invalid, json_tests::tx_invalid + sizeof(json_tests::tx_invalid)));

    ScriptError err = SCRIPT_ERR_OK;
    for (unsigned int idx = 0; idx < tests.size(); idx++)
    {
        UniValue test = tests[idx];
        string strTest = test.write();
        if (test[0].isArray())
        {
            if (test.size() != 3 || !test[1].isStr() || !test[2].isStr())
            {
                BOOST_ERROR("Bad test: " << strTest);
                continue;
            }

            map<COutPoint, CScript> mapprevOutScriptPubKeys;
            std::map<COutPoint, int64_t> mapprevOutValues;
            UniValue inputs = test[0].get_array();
            bool fValid = true;
            for (unsigned int inpIdx = 0; inpIdx < inputs.size(); inpIdx++)
            {
                const UniValue &input = inputs[inpIdx];
                if (!input.isArray())
                {
                    fValid = false;
                    break;
                }
                UniValue vinput = input.get_array();
                if (vinput.size() != 3)
                {
                    fValid = false;
                    break;
                }

                COutPoint outpoint(uint256S(vinput[0].get_str()), vinput[1].get_int());
                mapprevOutScriptPubKeys[outpoint] = ParseScript(vinput[2].get_str());
                if (vinput.size() >= 4)
                {
                    mapprevOutValues[outpoint] = vinput[3].get_int64();
                }
            }
            if (!fValid)
            {
                BOOST_ERROR("Bad test: " << strTest);
                continue;
            }

            string transaction = test[1].get_str();
            CDataStream stream(ParseHex(transaction), SER_NETWORK, PROTOCOL_VERSION);
            CTransaction tx;
            stream >> tx;

            CTransactionRef txref = MakeTransactionRef(tx);

            CValidationState state;
            fValid = CheckTransaction(txref, state) && state.IsValid();

            for (unsigned int i = 0; i < tx.vin.size() && fValid; i++)
            {
                if (!mapprevOutScriptPubKeys.count(tx.vin[i].prevout))
                {
                    BOOST_ERROR("Bad test: " << strTest);
                    break;
                }

                CAmount amount = 0;
                if (mapprevOutValues.count(tx.vin[i].prevout))
                {
                    amount = mapprevOutValues[tx.vin[i].prevout];
                }

                unsigned int verify_flags = ParseScriptFlags(test[2].get_str());
                TransactionSignatureChecker tsc(&tx, i, amount, verify_flags);
                ScriptImportedState sis(&tsc, txref, std::vector<CTxOut>(), i, amount);
                fValid = VerifyScript(tx.vin[i].scriptSig, mapprevOutScriptPubKeys[tx.vin[i].prevout], verify_flags,
                    MAX_OPS_PER_SCRIPT, sis, &err);
            }
            BOOST_CHECK_MESSAGE(!fValid, strTest);
            BOOST_CHECK_MESSAGE(err != SCRIPT_ERR_OK, ScriptErrorString(err));
        }
    }
}
#endif

BOOST_AUTO_TEST_CASE(basic_transaction_tests)
{
    CValidationState state;
#if 0 // TODO when we grab test vector transactions
    // Random real transaction (e2769b09e784f32f62ef849763d4f45b98e07ba658647343b915ff832b110436)
    unsigned char ch[] = {0x01, 0x00, 0x00, 0x00, 0x01, 0x6b, 0xff, 0x7f, 0xcd, 0x4f, 0x85, 0x65, 0xef, 0x40, 0x6d,
        0xd5, 0xd6, 0x3d, 0x4f, 0xf9, 0x4f, 0x31, 0x8f, 0xe8, 0x20, 0x27, 0xfd, 0x4d, 0xc4, 0x51, 0xb0, 0x44, 0x74,
        0x01, 0x9f, 0x74, 0xb4, 0x00, 0x00, 0x00, 0x00, 0x8c, 0x49, 0x30, 0x46, 0x02, 0x21, 0x00, 0xda, 0x0d, 0xc6,
        0xae, 0xce, 0xfe, 0x1e, 0x06, 0xef, 0xdf, 0x05, 0x77, 0x37, 0x57, 0xde, 0xb1, 0x68, 0x82, 0x09, 0x30, 0xe3,
        0xb0, 0xd0, 0x3f, 0x46, 0xf5, 0xfc, 0xf1, 0x50, 0xbf, 0x99, 0x0c, 0x02, 0x21, 0x00, 0xd2, 0x5b, 0x5c, 0x87,
        0x04, 0x00, 0x76, 0xe4, 0xf2, 0x53, 0xf8, 0x26, 0x2e, 0x76, 0x3e, 0x2d, 0xd5, 0x1e, 0x7f, 0xf0, 0xbe, 0x15,
        0x77, 0x27, 0xc4, 0xbc, 0x42, 0x80, 0x7f, 0x17, 0xbd, 0x39, 0x01, 0x41, 0x04, 0xe6, 0xc2, 0x6e, 0xf6, 0x7d,
        0xc6, 0x10, 0xd2, 0xcd, 0x19, 0x24, 0x84, 0x78, 0x9a, 0x6c, 0xf9, 0xae, 0xa9, 0x93, 0x0b, 0x94, 0x4b, 0x7e,
        0x2d, 0xb5, 0x34, 0x2b, 0x9d, 0x9e, 0x5b, 0x9f, 0xf7, 0x9a, 0xff, 0x9a, 0x2e, 0xe1, 0x97, 0x8d, 0xd7, 0xfd,
        0x01, 0xdf, 0xc5, 0x22, 0xee, 0x02, 0x28, 0x3d, 0x3b, 0x06, 0xa9, 0xd0, 0x3a, 0xcf, 0x80, 0x96, 0x96, 0x8d,
        0x7d, 0xbb, 0x0f, 0x91, 0x78, 0xff, 0xff, 0xff, 0xff, 0x02, 0x8b, 0xa7, 0x94, 0x0e, 0x00, 0x00, 0x00, 0x00,
        0x19, 0x76, 0xa9, 0x14, 0xba, 0xde, 0xec, 0xfd, 0xef, 0x05, 0x07, 0x24, 0x7f, 0xc8, 0xf7, 0x42, 0x41, 0xd7,
        0x3b, 0xc0, 0x39, 0x97, 0x2d, 0x7b, 0x88, 0xac, 0x40, 0x94, 0xa8, 0x02, 0x00, 0x00, 0x00, 0x00, 0x19, 0x76,
        0xa9, 0x14, 0xc1, 0x09, 0x32, 0x48, 0x3f, 0xec, 0x93, 0xed, 0x51, 0xf5, 0xfe, 0x95, 0xe7, 0x25, 0x59, 0xf2,
        0xcc, 0x70, 0x43, 0xf9, 0x88, 0xac, 0x00, 0x00, 0x00, 0x00, 0x00};
    vector<unsigned char> vch(ch, ch + sizeof(ch) - 1);
    CDataStream stream(vch, SER_DISK, CLIENT_VERSION);
    CMutableTransaction tx;
    stream >> tx;
    BOOST_CHECK_MESSAGE(CheckTransaction(MakeTransactionRef(CTransaction(tx)), state) && state.IsValid(),
        "Simple deserialized transaction should be valid.");
#endif

    auto tx1 = CreateRandomTx();
    // Check that duplicate txins fail
    tx1.vin.push_back(tx1.vin[0]);
    BOOST_CHECK_MESSAGE(!CheckTransaction(MakeTransactionRef(CTransaction(tx1)), state) || !state.IsValid(),
        "Transaction with duplicate txins should be invalid.");
}

//
// Helper: create two dummy transactions, each with
// two outputs.  The first has 11 and 50 CENT outputs
// paid to a TX_PUBKEY, the second 21 and 22 CENT outputs
// paid to a TX_PUBKEYHASH.
//
static std::vector<CMutableTransaction> SetupDummyInputs(CBasicKeyStore &keystoreRet, CCoinsViewCache &coinsRet)
{
    std::vector<CMutableTransaction> dummyTransactions;
    dummyTransactions.resize(2);

    // Add some keys to the keystore:
    CKey key[4];
    for (int i = 0; i < 4; i++)
    {
        key[i].MakeNewKey(i % 2);
        keystoreRet.AddKey(key[i]);
    }

    // Create some dummy input transactions
    dummyTransactions[0].vout.resize(2);
    dummyTransactions[0].vout[0].nValue = 11 * CENT;
    dummyTransactions[0].vout[0].scriptPubKey << ToByteVector(key[0].GetPubKey()) << OP_CHECKSIG;
    dummyTransactions[0].vout[1].nValue = 50 * CENT;
    dummyTransactions[0].vout[1].scriptPubKey << ToByteVector(key[1].GetPubKey()) << OP_CHECKSIG;
    AddCoins(coinsRet, dummyTransactions[0], 0);

    dummyTransactions[1].vout.resize(2);
    dummyTransactions[1].vout[0].nValue = 21 * CENT;
    dummyTransactions[1].vout[0].scriptPubKey = GetScriptForDestination(key[2].GetPubKey().GetID());
    dummyTransactions[1].vout[1].nValue = 22 * CENT;
    dummyTransactions[1].vout[1].scriptPubKey = GetScriptForDestination(key[3].GetPubKey().GetID());
    AddCoins(coinsRet, dummyTransactions[1], 0);

    return dummyTransactions;
}

BOOST_AUTO_TEST_CASE(test_Get)
{
    CBasicKeyStore keystore;
    CCoinsView coinsDummy;
    CCoinsViewCache coins(&coinsDummy);
    std::vector<CMutableTransaction> dummyTransactions = SetupDummyInputs(keystore, coins);

    CMutableTransaction t1;
    t1.vin.resize(3);
    t1.vin[0] = dummyTransactions[0].SpendOutput(1);
    t1.vin[0].scriptSig << std::vector<unsigned char>(65, 0);
    t1.vin[1] = dummyTransactions[1].SpendOutput(0);
    t1.vin[1].scriptSig << std::vector<unsigned char>(65, 0) << std::vector<unsigned char>(33, 4);
    t1.vin[2] = dummyTransactions[1].SpendOutput(1);
    t1.vin[2].scriptSig << std::vector<unsigned char>(65, 0) << std::vector<unsigned char>(33, 4);
    t1.vout.resize(2);
    t1.vout[0].nValue = 90 * CENT;
    t1.vout[0].scriptPubKey << OP_1;

    BOOST_CHECK(AreInputsStandard(MakeTransactionRef(CTransaction(t1)), coins));
    BOOST_CHECK_EQUAL(coins.GetValueIn(t1), (50 + 21 + 22) * CENT);
}


BOOST_AUTO_TEST_CASE(test_IsStandard)
{
    LOCK(cs_main);
    CBasicKeyStore keystore;
    CCoinsView coinsDummy;
    CCoinsViewCache coins(&coinsDummy);
    std::vector<CMutableTransaction> dummyTransactions = SetupDummyInputs(keystore, coins);

    CMutableTransaction t;
    t.vin.resize(1);
    t.vin[0] = dummyTransactions[0].SpendOutput(1);
    t.vin[0].scriptSig << std::vector<unsigned char>(65, 0);
    t.vout.resize(1);
    t.vout[0].nValue = 90 * COIN;
    CKey key;
    key.MakeNewKey(true);
    t.vout[0].scriptPubKey = GetScriptForDestination(key.GetPubKey().GetID());

    string reason;
    BOOST_CHECK(IsStandardTx(MakeTransactionRef(CTransaction(t)), reason));

    // Check dust with default threshold:
    dustThreshold.Set(DEFAULT_DUST_THRESHOLD);
    // dust:
    t.vout[0].nValue = dustThreshold.Value() - 1;
    BOOST_CHECK(!IsStandardTx(MakeTransactionRef(CTransaction(t)), reason));
    // not dust:
    t.vout[0].nValue = dustThreshold.Value();
    BOOST_CHECK(IsStandardTx(MakeTransactionRef(CTransaction(t)), reason));

    // Check dust with odd threshold
    dustThreshold.Set(1234);
    // dust:
    t.vout[0].nValue = 1234 - 1;
    BOOST_CHECK(!IsStandardTx(MakeTransactionRef(CTransaction(t)), reason));
    // not dust:
    t.vout[0].nValue = 1234;
    BOOST_CHECK(IsStandardTx(MakeTransactionRef(CTransaction(t)), reason));
    dustThreshold.Set(DEFAULT_DUST_THRESHOLD);

    t.vout[0].scriptPubKey = CScript() << OP_1;
    BOOST_CHECK(!IsStandardTx(MakeTransactionRef(CTransaction(t)), reason));
    BOOST_CHECK(CTransaction(t).HasData() == false);

    // Check max LabelPublic: MAX_OP_RETURN_RELAY-2 byte TX_NULL_DATA
    dataCarrierSize.Set(MAX_OP_RETURN_RELAY);
    uint64_t someNumber = 17; // serializes to 2 bytes which is important to make the total script the desired len
    t.vout[0].scriptPubKey = CScript() << OP_RETURN << CScriptNum::fromIntUnchecked(someNumber)
                                       << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962"
                                                   "e0ea1f61deb649f6bc3f4cef3804678afdb0fe5548271967f1a671"
                                                   "e0ea1f61deb649f6bc3f4cef3804678afdb0fe5548271967f1a671"
                                                   "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962"
                                                   "30b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38ce"
                                                   "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962"
                                                   "30b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38ce"
                                                   "30b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef7105"
                                                   "2312");
    BOOST_CHECK_EQUAL(MAX_OP_RETURN_RELAY, t.vout[0].scriptPubKey.size());
    BOOST_CHECK(IsStandardTx(MakeTransactionRef(CTransaction(t)), reason));

    // MAX_OP_RETURN_RELAY-byte TX_NULL_DATA in multiple outputs (standard after May 2021 Network Upgrade)
    t.vout.resize(3);
    t.vout[0].scriptPubKey = CScript() << OP_RETURN << ParseHex("646578784062697477617463682e636f2092c558ed52c56d");
    t.vout[1].scriptPubKey = CScript() << OP_RETURN << ParseHex("8dd14ca76226bc936a84820d898443873eb03d8854b21fa3");
    t.vout[2].scriptPubKey = CScript() << OP_RETURN
                                       << ParseHex("952b99a2981873e74509281730d78a21786d34a38bd1ebab"
                                                   "822fad42278f7f4420db6ab1fd2b6826148d4f73bb41ec2d"
                                                   "40a6d5793d66e17074a0c56a8a7df21062308f483dd6e38d"
                                                   "53609d350038df0a1b2a9ac8332016e0b904f66880dd0108"
                                                   "81c4e8074cce8e4ad6c77cb3460e01bf0e7e811b5f945f83"
                                                   "732ba6677520a893d75d9a966cb8f85dc301656b1635c631"
                                                   "f5d00d4adf73f2dd112ca75cf19754651909becfbe65aed1");
    BOOST_CHECK_EQUAL(MAX_OP_RETURN_RELAY,
        t.vout[0].scriptPubKey.size() + t.vout[1].scriptPubKey.size() + t.vout[2].scriptPubKey.size());
    BOOST_CHECK(IsStandardTx(MakeTransactionRef(CTransaction(t)), reason));

    // MAX_OP_RETURN_RELAY+1-byte TX_NULL_DATA in multiple outputs (non-standard)
    t.vout[2].scriptPubKey = CScript() << OP_RETURN
                                       << ParseHex("952b99a2981873e74509281730d78a21786d34a38bd1ebab"
                                                   "822fad42278f7f4420db6ab1fd2b6826148d4f73bb41ec2d"
                                                   "40a6d5793d66e17074a0c56a8a7df21062308f483dd6e38d"
                                                   "53609d350038df0a1b2a9ac8332016e0b904f66880dd0108"
                                                   "81c4e8074cce8e4ad6c77cb3460e01bf0e7e811b5f945f83"
                                                   "732ba6677520a893d75d9a966cb8f85dc301656b1635c631"
                                                   "f5d00d4adf73f2dd112ca75cf19754651909becfbe65aed1"
                                                   "3a");
    BOOST_CHECK_EQUAL(MAX_OP_RETURN_RELAY + 1,
        t.vout[0].scriptPubKey.size() + t.vout[1].scriptPubKey.size() + t.vout[2].scriptPubKey.size());
    BOOST_CHECK(!IsStandardTx(MakeTransactionRef(CTransaction(t)), reason));

    // TODO: The following check may not be applicible post May 2021 upgrade
    // Check that 2 public labels are not allowed
    t.vout.resize(2);
    t.vout[1].scriptPubKey = CScript() << OP_RETURN << CScriptNum::fromIntUnchecked(someNumber)
                                       << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962"
                                                   "e0ea1f61deb649f6bc3f4cef3804678afdb0fe5548271967f1a671"
                                                   "e0ea1f61deb649f6bc3f4cef3804678afdb0fe5548271967f1a671"
                                                   "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962"
                                                   "30b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38ce"
                                                   "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962"
                                                   "30b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38ce"
                                                   "30b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef7105"
                                                   "2312");
    BOOST_CHECK(!IsStandardTx(MakeTransactionRef(CTransaction(t)), reason));

    // Check that 1 pub label and 1 normal data is not allowed
    t.vout[1].scriptPubKey = CScript() << OP_RETURN
                                       << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962"
                                                   "e0ea1f61deb649f6bc3f4cef3804678afdb0fe5548271967f1a671"
                                                   "e0ea1f61deb649f6bc3f4cef3804678afdb0fe5548271967f1a671"
                                                   "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962"
                                                   "30b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38ce"
                                                   "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962"
                                                   "30b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38ce"
                                                   "30b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef7105"
                                                   "2312");
    BOOST_CHECK(!IsStandardTx(MakeTransactionRef(CTransaction(t)), reason));
    t.vout.resize(1);


    // Check max LabelPublic: MAX_OP_RETURN_RELAY-byte TX_NULL_DATA
    // MAX_OP_RETURN_RELAY+1-2 -byte TX_NULL_DATA (non-standard)
    t.vout[0].scriptPubKey = CScript() << OP_RETURN << CScriptNum::fromIntUnchecked(someNumber)
                                       << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962"
                                                   "e0ea1f61deb649f6bc3f4cef3804678afdb0fe5548271967f1a671"
                                                   "e0ea1f61deb649f6bc3f4cef3804678afdb0fe5548271967f1a671"
                                                   "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962"
                                                   "30b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38ce"
                                                   "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962"
                                                   "30b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38ce"
                                                   "30b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef7105"
                                                   "2312ac");
    BOOST_CHECK_EQUAL(MAX_OP_RETURN_RELAY + 1, t.vout[0].scriptPubKey.size());
    BOOST_CHECK(!IsStandardTx(MakeTransactionRef(CTransaction(t)), reason));

    // Check when a custom value is used for -relay.dataCarrierSize .
    dataCarrierSize.Set(90);

    // Max user provided payload size in multiple outputs is standard
    // after the May 2021 Network Upgrade.
    t.vout.resize(2);
    t.vout[1].nValue = 0;
    t.vout[0].scriptPubKey = CScript() << OP_RETURN
                                       << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909"
                                                   "a67962e0ea1f61deb649f6bc3f4cef3804678afdb0fe5548");
    t.vout[1].scriptPubKey = CScript() << OP_RETURN
                                       << ParseHex("271967f1a67130b7105cd6a828e03909a67962e0ea1f61de"
                                                   "b649f6bc3f4cef3877696e646578");
    BOOST_CHECK_EQUAL(t.vout[0].scriptPubKey.size() + t.vout[1].scriptPubKey.size(), 90U);
    BOOST_CHECK(IsStandardTx(MakeTransactionRef(CTransaction(t)), reason));

    // Max user provided payload size + 1 in multiple outputs is non-standard
    // even after the May 2021 Network Upgrade.
    t.vout[1].scriptPubKey = CScript() << OP_RETURN
                                       << ParseHex("271967f1a67130b7105cd6a828e03909a67962e0ea1f61de"
                                                   "b649f6bc3f4cef3877696e64657878");
    BOOST_CHECK_EQUAL(t.vout[0].scriptPubKey.size() + t.vout[1].scriptPubKey.size(), 91U);
    BOOST_CHECK(!IsStandardTx(MakeTransactionRef(CTransaction(t)), reason));

    // Reset datacarriersize back to default [standard] size
    dataCarrierSize.Set(MAX_OP_RETURN_RELAY);
    t.vout.resize(1);

    // MAX_OP_RETURN_RELAY-byte TX_NULL_DATA (standard)
    t.vout[0].scriptPubKey = CScript() << OP_RETURN
                                       << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962"
                                                   "e0ea1f61deb649f6bc3f4cef3804678afdb0fe5548271967f1a671"
                                                   "e0ea1f61deb649f6bc3f4cef3804678afdb0fe5548271967f1a671"
                                                   "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962"
                                                   "30b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38ce"
                                                   "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962"
                                                   "30b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38ce"
                                                   "30b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef7105"
                                                   "2312acbd");
    BOOST_CHECK_EQUAL(MAX_OP_RETURN_RELAY, t.vout[0].scriptPubKey.size());
    BOOST_CHECK(IsStandardTx(MakeTransactionRef(CTransaction(t)), reason));

    // MAX_OP_RETURN_RELAY+1-byte TX_NULL_DATA (non-standard)
    t.vout[0].scriptPubKey = CScript() << OP_RETURN
                                       << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962"
                                                   "e0ea1f61deb649f6bc3f4cef3804678afdb0fe5548271967f1a671"
                                                   "e0ea1f61deb649f6bc3f4cef3804678afdb0fe5548271967f1a671"
                                                   "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962"
                                                   "30b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38ce"
                                                   "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962"
                                                   "30b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38ce"
                                                   "30b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef7105"
                                                   "2312acbdab");
    BOOST_CHECK_EQUAL(MAX_OP_RETURN_RELAY + 1, t.vout[0].scriptPubKey.size());
    BOOST_CHECK(!IsStandardTx(MakeTransactionRef(CTransaction(t)), reason));

    BOOST_CHECK(CTransaction(t).HasData(2969406055) == false); // dataID (first data after op_return) too long
    t.vout[0].scriptPubKey = CScript() << OP_RETURN << ParseHex("678afdb0");
    BOOST_CHECK(CTransaction(t).HasData() == true);
    BOOST_CHECK(CTransaction(t).HasData(2969406055) == true);
    BOOST_CHECK(CTransaction(t).HasData(12345678) == false); // wrong dataID

    // Data payload can be encoded in any way...
    t.vout[0].scriptPubKey = CScript() << OP_RETURN << ParseHex("");
    BOOST_CHECK(IsStandardTx(MakeTransactionRef(CTransaction(t)), reason));
    t.vout[0].scriptPubKey = CScript() << OP_RETURN << ParseHex("00") << ParseHex("01");
    BOOST_CHECK(IsStandardTx(MakeTransactionRef(CTransaction(t)), reason));
    // OP_RESERVED *is* considered to be a PUSHDATA type opcode by IsPushOnly()!
    t.vout[0].scriptPubKey = CScript() << OP_RETURN << OP_RESERVED << -1 << 0 << ParseHex("01") << 2 << 3 << 4 << 5 << 6
                                       << 7 << 8 << 9 << 10 << 11 << 12 << 13 << 14 << 15 << 16;
    BOOST_CHECK(IsStandardTx(MakeTransactionRef(CTransaction(t)), reason));
    BOOST_CHECK(CTransaction(t).HasData() == true);
    BOOST_CHECK(CTransaction(t).HasData(1) == false);

    t.vout[0].scriptPubKey =
        CScript() << OP_RETURN << 0 << ParseHex("01") << 2
                  << ParseHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    BOOST_CHECK(IsStandardTx(MakeTransactionRef(CTransaction(t)), reason));

    // ...so long as it only contains PUSHDATA's or OP_RETURNs
    t.vout[0].scriptPubKey = CScript() << OP_RETURN << OP_RETURN;
    BOOST_CHECK(IsStandardTx(MakeTransactionRef(CTransaction(t)), reason));

    t.vout[0].scriptPubKey = CScript() << OP_ADD << OP_RETURN;
    BOOST_CHECK(!IsStandardTx(MakeTransactionRef(CTransaction(t)), reason));

    // TX_NULL_DATA w/o PUSHDATA
    t.vout.resize(1);
    t.vout[0].scriptPubKey = CScript() << OP_RETURN;
    BOOST_CHECK(IsStandardTx(MakeTransactionRef(CTransaction(t)), reason));

    // Only one TX_NULL_DATA permitted in all cases, until the May 2021 network upgrade
    t.vout.resize(2);
    t.vout[0].scriptPubKey =
        CScript() << OP_RETURN
                  << ParseHex("04578afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38");
    t.vout[1].scriptPubKey =
        CScript() << OP_RETURN
                  << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38");
    BOOST_CHECK(IsStandardTx(MakeTransactionRef(CTransaction(t)), reason));
    BOOST_CHECK(CTransaction(t).HasData() == true);

    t.vout[0].scriptPubKey =
        CScript() << OP_RETURN
                  << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38");
    t.vout[1].scriptPubKey = CScript() << OP_RETURN;
    BOOST_CHECK(IsStandardTx(MakeTransactionRef(CTransaction(t)), reason));

    t.vout[0].scriptPubKey = CScript() << OP_RETURN;
    t.vout[1].scriptPubKey = CScript() << OP_RETURN;
    BOOST_CHECK(IsStandardTx(MakeTransactionRef(CTransaction(t)), reason));
    BOOST_CHECK(CTransaction(t).HasData() == true);
    BOOST_CHECK(CTransaction(t).HasData(1) == false);

    // Check two op_returns have data...
    // this is nonstandard until the May 2021 network upgrade, but we check it anyway
    t.vout[0].scriptPubKey = CScript() << OP_RETURN << ParseHex("04578afd");
    t.vout[1].scriptPubKey = CScript() << OP_RETURN << ParseHex("04678afd");

    BOOST_CHECK(CTransaction(t).HasData() == true);
    BOOST_CHECK(CTransaction(t).HasData(4253701892) == true); // make sure both vouts are checked
    BOOST_CHECK(CTransaction(t).HasData(4253705988) == true);
    BOOST_CHECK(CTransaction(t).HasData(4253705989) == false);

    // Every OP_RETURN output script without data pushes is one byte long,
    // so the maximum number of outputs will be nMaxDatacarrierBytes.
    t.vout.resize(dataCarrierSize.Value() + 1);
    for (auto &out : t.vout)
    {
        out.nValue = 0;
        out.scriptPubKey = CScript() << OP_RETURN;
    }
    BOOST_CHECK(!IsStandardTx(MakeTransactionRef(CTransaction(t)), reason));

    t.vout.pop_back();
    BOOST_CHECK(IsStandardTx(MakeTransactionRef(CTransaction(t)), reason));
}

BOOST_AUTO_TEST_CASE(large_transaction_tests)
{
    // Random valid large transaction with 125 inputs
#if 0 // TODO include hex transaction when stabilized
    std::string raw_tx = "";

    CTransaction tx;
    BOOST_CHECK(DecodeHexTx(tx, raw_tx) == true);

    CValidationState state;
    BOOST_CHECK_MESSAGE(CheckTransaction(MakeTransactionRef(tx), state) && state.IsValid(),
        "Simple deserialized transaction should be valid.");

    // Check that duplicate txins fail
    CMutableTransaction mtx(tx);
    mtx.vin.push_back(tx.vin[0]);
    BOOST_CHECK_MESSAGE(!CheckTransaction(MakeTransactionRef(CTransaction(mtx)), state) || !state.IsValid(),
        "Transaction with duplicate txins should be invalid.");
#endif
}

BOOST_AUTO_TEST_SUITE_END()
