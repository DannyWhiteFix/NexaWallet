// Copyright (c) 2012-2015 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "consensus/tx_verify.h"
#include "key.h"
#include "keystore.h"
#include "policy/policy.h"
#include "script/ismine.h"
#include "script/script.h"
#include "script/script_error.h"
#include "script/sign.h"
#include "test/test_nexa.h"
#include "validation/parallel.h"

#include <vector>

#include <boost/test/unit_test.hpp>

using namespace std;

// Helpers:
static std::vector<unsigned char> Serialize(const CScript &s)
{
    std::vector<unsigned char> sSerialized(s.begin(), s.end());
    return sSerialized;
}

static bool Verify(const CScript &scriptSig, const CScript &scriptPubKey, bool fStrict, ScriptError &err)
{
    // Create dummy to/from transactions:
    CMutableTransaction txFrom;
    txFrom.vout.resize(1);
    txFrom.vout[0].scriptPubKey = scriptPubKey;
    txFrom.vout[0].nValue = 1;

    CMutableTransaction txTo;
    txTo.vin.resize(1);
    txTo.vout.resize(1);
    txTo.vin[0] = txFrom.SpendOutput(0);
    txTo.vin[0].scriptSig = scriptSig;
    txTo.vout[0].nValue = 1;

    unsigned int flags = fStrict ? SCRIPT_VERIFY_P2SH : SCRIPT_VERIFY_NONE;
    MutableTransactionSignatureChecker tsc(&txTo, 0, txFrom.vout[0].nValue, flags);
    // None of these tests rely on introspection of the validation data so its ok to pass bad data.
    ScriptImportedState sis(&tsc, MakeTransactionRef(txTo), CValidationState(), std::vector<CTxOut>(), 0);

    return VerifyScript(scriptSig, scriptPubKey, flags, sis, &err);
}


BOOST_FIXTURE_TEST_SUITE(script_P2SH_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(sign)
{
    LOCK(cs_main);
    std::string popNetwork = Params().NetworkIDString();
    SelectParams("regtest"); // P2SH disabled on nexa mainnet
    // Pay-to-script-hash looks like this:
    // scriptSig:    <sig> <sig...> <serialized_script>
    // scriptPubKey: HASH160 <hash> EQUAL

    // Test SignSignature() (and therefore the version of Solver() that signs transactions)
    CBasicKeyStore keystore;
    CKey key[4];
    for (int i = 0; i < 4; i++)
    {
        key[i].MakeNewKey(true);
        keystore.AddKey(key[i]);
    }

    // 8 Scripts: checking all combinations of
    // different keys, straight/P2SH, pubkey/pubkeyhash
    CScript standardScripts[4];
    standardScripts[0] << ToByteVector(key[0].GetPubKey()) << OP_CHECKSIG;
    standardScripts[1] = GetScriptForDestination(key[1].GetPubKey().GetID());
    standardScripts[2] << ToByteVector(key[1].GetPubKey()) << OP_CHECKSIG;
    standardScripts[3] = GetScriptForDestination(key[2].GetPubKey().GetID());
    CScript evalScripts[4];
    for (int i = 0; i < 4; i++)
    {
        keystore.AddCScript(standardScripts[i]);
        evalScripts[i] = GetScriptForDestination(CScriptID(standardScripts[i]));
    }

    CMutableTransaction txFrom; // Funding transaction:
    string reason;
    txFrom.vout.resize(8);
    for (int i = 0; i < 4; i++)
    {
        txFrom.vout[i].scriptPubKey = evalScripts[i];
        txFrom.vout[i].nValue = 10 * COIN;
        txFrom.vout[i + 4].scriptPubKey = standardScripts[i];
        txFrom.vout[i + 4].nValue = 10 * COIN;
    }
    BOOST_CHECK(IsStandardTx(MakeTransactionRef(CTransaction(txFrom)), reason));

    CMutableTransaction txTo[8]; // Spending transactions
    for (int i = 0; i < 8; i++)
    {
        txTo[i].vin.resize(1);
        txTo[i].vout.resize(1);
        txTo[i].vin[0] = txFrom.SpendOutput(i);
        txTo[i].vout[0].nValue = 1;
#ifdef ENABLE_WALLET
        BOOST_CHECK_MESSAGE(IsMine(keystore, txFrom.vout[i].scriptPubKey, 0), strprintf("IsMine %d", i));
#endif
    }
    for (int i = 0; i < 8; i++)
    {
        BOOST_CHECK_MESSAGE(SignSignature(keystore, txFrom.vout[i], txTo[i], 0), strprintf("SignSignature %d", i));
    }
    // All of the above should be OK, and the txTos have valid signatures
    // Check to make sure signature verification fails if we use the wrong ScriptSig:
    for (int i = 0; i < 8; i++)
        for (int j = 0; j < 8; j++)
        {
            CScript sigSave = txTo[i].vin[0].scriptSig;
            const CTxOut *output = txFrom.PrevOut(txTo[i].vin[0].prevout);
            assert(output != nullptr);
            txTo[i].vin[0].scriptSig = txTo[j].vin[0].scriptSig;
            txTo[i].vin[0].amount = output->nValue;
            bool sigOK = CScriptCheck(nullptr, output->scriptPubKey, output->nValue, txTo[i], std::vector<CTxOut>(), 0,
                SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_STRICTENC | SCRIPT_ENABLE_SIGHASH_FORKID, false)();
            if (i == j)
                BOOST_CHECK_MESSAGE(sigOK, strprintf("VerifySignature %d %d", i, j));
            else
                BOOST_CHECK_MESSAGE(!sigOK, strprintf("VerifySignature %d %d", i, j));
            txTo[i].vin[0].scriptSig = sigSave;
        }

    SelectParams(popNetwork); // P2SH disabled on nexa mainnet
}

BOOST_AUTO_TEST_CASE(norecurse)
{
    std::string popNetwork = Params().NetworkIDString();
    SelectParams("regtest"); // P2SH disabled on nexa mainnet

    ScriptError err;
    // Make sure only the outer pay-to-script-hash does the
    // extra-validation thing:
    CScript invalidAsScript;
    invalidAsScript << OP_INVALIDOPCODE << OP_INVALIDOPCODE;

    CScript p2sh = GetScriptForDestination(CScriptID(invalidAsScript));

    CScript scriptSig;
    scriptSig << Serialize(invalidAsScript);

    // Should not verify, because it will try to execute OP_INVALIDOPCODE
    BOOST_CHECK(!Verify(scriptSig, p2sh, true, err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_BAD_OPCODE, ScriptErrorString(err));

    // Try to recur, and verification should succeed because
    // the inner HASH160 <> EQUAL should only check the hash:
    CScript p2sh2 = GetScriptForDestination(CScriptID(p2sh));
    CScript scriptSig2;
    scriptSig2 << Serialize(invalidAsScript) << Serialize(p2sh);

    BOOST_CHECK(Verify(scriptSig2, p2sh2, true, err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));
    SelectParams(popNetwork); // P2SH disabled on nexa mainnet
}

BOOST_AUTO_TEST_CASE(set)
{
    LOCK(cs_main);
    std::string popNetwork = Params().NetworkIDString();
    SelectParams("regtest"); // P2SH disabled on nexa mainnet

    // Test the CScript::Set* methods
    CBasicKeyStore keystore;
    CKey key[4];
    std::vector<CPubKey> keys;
    for (int i = 0; i < 4; i++)
    {
        key[i].MakeNewKey(true);
        keystore.AddKey(key[i]);
        keys.push_back(key[i].GetPubKey());
    }

    CScript inner[4];
    inner[0] = GetScriptForDestination(key[0].GetPubKey().GetID());
    inner[1] = GetScriptForMultisig(2, std::vector<CPubKey>(keys.begin(), keys.begin() + 2));
    inner[2] = GetScriptForMultisig(1, std::vector<CPubKey>(keys.begin(), keys.begin() + 2));
    inner[3] = GetScriptForMultisig(2, std::vector<CPubKey>(keys.begin(), keys.begin() + 3));

    CScript outer[4];
    for (int i = 0; i < 4; i++)
    {
        outer[i] = GetScriptForDestination(CScriptID(inner[i]));
        keystore.AddCScript(inner[i]);
    }

    CMutableTransaction txFrom; // Funding transaction:
    string reason;
    txFrom.vout.resize(4);
    for (int i = 0; i < 4; i++)
    {
        txFrom.vout[i].scriptPubKey = outer[i];
        txFrom.vout[i].nValue = 10 * COIN;
    }
    BOOST_CHECK(IsStandardTx(MakeTransactionRef(CTransaction(txFrom)), reason));

    CMutableTransaction txTo[4]; // Spending transactions
    for (int i = 0; i < 4; i++)
    {
        txTo[i].vin.resize(1);
        txTo[i].vout.resize(1);
        txTo[i].vin[0] = txFrom.SpendOutput(i);
        txTo[i].vout[0].nValue = 10 * COIN;
        txTo[i].vout[0].scriptPubKey = inner[i];
#ifdef ENABLE_WALLET
        BOOST_CHECK_MESSAGE(IsMine(keystore, txFrom.vout[i].scriptPubKey, 0), strprintf("IsMine %d", i));
#endif
    }
    for (int i = 0; i < 4; i++)
    {
        BOOST_CHECK_MESSAGE(SignSignature(keystore, txFrom.vout[i], txTo[i], 0), strprintf("SignSignature %d", i));
        BOOST_CHECK_MESSAGE(
            IsStandardTx(MakeTransactionRef(CTransaction(txTo[i])), reason), strprintf("txTo[%d].IsStandard", i));
        BOOST_CHECK_MESSAGE(
            IsStandardTx(MakeTransactionRef(CTransaction(txTo[i])), reason), strprintf("txTo[%d].IsStandard", i));
        BOOST_CHECK_MESSAGE(
            IsStandardTx(MakeTransactionRef(CTransaction(txTo[i])), reason), strprintf("txTo[%d].IsStandard", i));
    }
    SelectParams(popNetwork); // P2SH disabled on nexa mainnet
}

BOOST_AUTO_TEST_CASE(is)
{
    // Test CScript::IsPayToScriptHash()
    uint160 dummy;
    CScript p2sh;
    p2sh << OP_HASH160 << ToByteVector(dummy) << OP_EQUAL;
    BOOST_CHECK(p2sh.IsPayToScriptHash());

    // Not considered pay-to-script-hash if using one of the OP_PUSHDATA opcodes:
    static const unsigned char direct[] = {
        OP_HASH160, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, OP_EQUAL};
    BOOST_CHECK(CScript(direct, direct + sizeof(direct)).IsPayToScriptHash());
    static const unsigned char pushdata1[] = {
        OP_HASH160, OP_PUSHDATA1, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, OP_EQUAL};
    BOOST_CHECK(!CScript(pushdata1, pushdata1 + sizeof(pushdata1)).IsPayToScriptHash());
    static const unsigned char pushdata2[] = {
        OP_HASH160, OP_PUSHDATA2, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, OP_EQUAL};
    BOOST_CHECK(!CScript(pushdata2, pushdata2 + sizeof(pushdata2)).IsPayToScriptHash());
    static const unsigned char pushdata4[] = {
        OP_HASH160, OP_PUSHDATA4, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, OP_EQUAL};
    BOOST_CHECK(!CScript(pushdata4, pushdata4 + sizeof(pushdata4)).IsPayToScriptHash());

    CScript not_p2sh;
    BOOST_CHECK(!not_p2sh.IsPayToScriptHash());

    not_p2sh.clear();
    not_p2sh << OP_HASH160 << ToByteVector(dummy) << ToByteVector(dummy) << OP_EQUAL;
    BOOST_CHECK(!not_p2sh.IsPayToScriptHash());

    not_p2sh.clear();
    not_p2sh << OP_NOP << ToByteVector(dummy) << OP_EQUAL;
    BOOST_CHECK(!not_p2sh.IsPayToScriptHash());

    not_p2sh.clear();
    not_p2sh << OP_HASH160 << ToByteVector(dummy) << OP_CHECKSIG;
    BOOST_CHECK(!not_p2sh.IsPayToScriptHash());
}

BOOST_AUTO_TEST_CASE(AreInputsStandard)
{
    LOCK(cs_main);
    std::string popNetwork = Params().NetworkIDString();
    SelectParams("regtest"); // P2SH disabled on nexa mainnet

    CCoinsView coinsDummy;
    CCoinsViewCache coins(&coinsDummy);
    CBasicKeyStore keystore;
    CKey key[6];
    vector<CPubKey> keys;
    for (int i = 0; i < 6; i++)
    {
        key[i].MakeNewKey(true);
        keystore.AddKey(key[i]);
    }
    for (int i = 0; i < 3; i++)
        keys.push_back(key[i].GetPubKey());

    CMutableTransaction txFrom;
    txFrom.vout.resize(7);

    // First three are standard:
    CScript pay1 = GetScriptForDestination(key[0].GetPubKey().GetID());
    keystore.AddCScript(pay1);
    CScript pay1of3 = GetScriptForMultisig(1, keys);

    txFrom.vout[0].scriptPubKey = GetScriptForDestination(CScriptID(pay1)); // P2SH (OP_CHECKSIG)
    txFrom.vout[0].nValue = 1000;
    txFrom.vout[1].scriptPubKey = pay1; // ordinary OP_CHECKSIG
    txFrom.vout[1].nValue = 2000;
    txFrom.vout[2].scriptPubKey = pay1of3; // ordinary OP_CHECKMULTISIG
    txFrom.vout[2].nValue = 3000;

    // vout[3] is complicated 1-of-3 AND 2-of-3
    // ... that is OK if wrapped in P2SH:
    CScript oneAndTwo;
    oneAndTwo << OP_1 << ToByteVector(key[0].GetPubKey()) << ToByteVector(key[1].GetPubKey())
              << ToByteVector(key[2].GetPubKey());
    oneAndTwo << OP_3 << OP_CHECKMULTISIGVERIFY;
    oneAndTwo << OP_2 << ToByteVector(key[3].GetPubKey()) << ToByteVector(key[4].GetPubKey())
              << ToByteVector(key[5].GetPubKey());
    oneAndTwo << OP_3 << OP_CHECKMULTISIG;
    keystore.AddCScript(oneAndTwo);
    txFrom.vout[3].scriptPubKey = GetScriptForDestination(CScriptID(oneAndTwo));
    txFrom.vout[3].nValue = 4000;

    // vout[4] is max sigops:
    CScript fifteenSigops;
    fifteenSigops << OP_1;
    for (unsigned i = 0; i < MAX_P2SH_SIGOPS; i++)
        fifteenSigops << ToByteVector(key[i % 3].GetPubKey());
    fifteenSigops << OP_15 << OP_CHECKMULTISIG;
    keystore.AddCScript(fifteenSigops);
    txFrom.vout[4].scriptPubKey = GetScriptForDestination(CScriptID(fifteenSigops));
    txFrom.vout[4].nValue = 5000;

    // vout[5/6] are non-standard because they exceed MAX_P2SH_SIGOPS
    CScript sixteenSigops;
    sixteenSigops << OP_16 << OP_CHECKMULTISIG;
    keystore.AddCScript(sixteenSigops);
    txFrom.vout[5].scriptPubKey = GetScriptForDestination(CScriptID(fifteenSigops));
    txFrom.vout[5].nValue = 5000;
    CScript twentySigops;
    twentySigops << OP_CHECKMULTISIG;
    keystore.AddCScript(twentySigops);
    txFrom.vout[6].scriptPubKey = GetScriptForDestination(CScriptID(twentySigops));
    txFrom.vout[6].nValue = 6000;

    AddCoins(coins, txFrom, 0);

    CMutableTransaction txTo;
    txTo.vout.resize(1);
    txTo.vout[0].scriptPubKey = GetScriptForDestination(key[1].GetPubKey().GetID());

    txTo.vin.resize(5);
    for (int i = 0; i < 5; i++)
    {
        txTo.vin[i] = txFrom.SpendOutput(i);
    }
    // OutpointAt here matches the for loop above
    BOOST_CHECK(SignSignature(keystore, txFrom.vout[0], txTo, 0));
    BOOST_CHECK(SignSignature(keystore, txFrom.vout[1], txTo, 1));
    BOOST_CHECK(SignSignature(keystore, txFrom.vout[2], txTo, 2));
    // SignSignature doesn't know how to sign these. We're
    // not testing validating signatures, so just create
    // dummy signatures that DO include the correct P2SH scripts:
    txTo.vin[3].scriptSig << OP_11 << OP_11 << vector<unsigned char>(oneAndTwo.begin(), oneAndTwo.end());
    txTo.vin[4].scriptSig << vector<unsigned char>(fifteenSigops.begin(), fifteenSigops.end());

    BOOST_CHECK(::AreInputsStandard(MakeTransactionRef(CTransaction(txTo)), coins));
    // 22 P2SH sigops for all inputs (1 for vin[0], 6 for vin[3], 15 for vin[4]
    BOOST_CHECK_EQUAL(
        GetP2SHSigOpCount(MakeTransactionRef(CTransaction(txTo)), coins, STANDARD_SCRIPT_VERIFY_FLAGS), 22U);
    // Check that no sigops show up when P2SH is not activated.
    BOOST_CHECK_EQUAL(GetP2SHSigOpCount(MakeTransactionRef(CTransaction(txTo)), coins, SCRIPT_VERIFY_NONE), 0U);

    CMutableTransaction txToNonStd1;
    txToNonStd1.vout.resize(1);
    txToNonStd1.vout[0].scriptPubKey = GetScriptForDestination(key[1].GetPubKey().GetID());
    txToNonStd1.vout[0].nValue = 1000;
    txToNonStd1.vin.resize(1);
    txToNonStd1.vin[0] = txFrom.SpendOutput(5);
    txToNonStd1.vin[0].scriptSig << vector<unsigned char>(sixteenSigops.begin(), sixteenSigops.end());

    BOOST_CHECK(::AreInputsStandard(MakeTransactionRef(CTransaction(txToNonStd1)), coins));
    BOOST_CHECK_EQUAL(
        GetP2SHSigOpCount(MakeTransactionRef(CTransaction(txToNonStd1)), coins, STANDARD_SCRIPT_VERIFY_FLAGS), 16U);
    // Check that no sigops show up when P2SH is not activated.
    BOOST_CHECK_EQUAL(GetP2SHSigOpCount(MakeTransactionRef(CTransaction(txToNonStd1)), coins, SCRIPT_VERIFY_NONE), 0U);

    CMutableTransaction txToNonStd2;
    txToNonStd2.vout.resize(1);
    txToNonStd2.vout[0].scriptPubKey = GetScriptForDestination(key[1].GetPubKey().GetID());
    txToNonStd2.vout[0].nValue = 1000;
    txToNonStd2.vin.resize(1);
    txToNonStd2.vin[0] = txFrom.SpendOutput(6);
    txToNonStd2.vin[0].scriptSig << vector<unsigned char>(twentySigops.begin(), twentySigops.end());

    BOOST_CHECK(::AreInputsStandard(MakeTransactionRef(CTransaction(txToNonStd2)), coins));
    BOOST_CHECK_EQUAL(
        GetP2SHSigOpCount(MakeTransactionRef(CTransaction(txToNonStd2)), coins, STANDARD_SCRIPT_VERIFY_FLAGS), 20U);
    // Check that no sigops show up when P2SH is not activated.
    BOOST_CHECK_EQUAL(GetP2SHSigOpCount(MakeTransactionRef(CTransaction(txToNonStd2)), coins, SCRIPT_VERIFY_NONE), 0U);
    SelectParams(popNetwork); // P2SH disabled on nexa mainnet
}

BOOST_AUTO_TEST_SUITE_END()
