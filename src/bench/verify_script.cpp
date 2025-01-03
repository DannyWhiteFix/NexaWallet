// Copyright (c) 2016 The Bitcoin Core developers
// Copyright (c) 2016-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "bench.h"
#include "key.h"
#if defined(HAVE_CONSENSUS_LIB)
#include "script/bitcoinconsensus.h"
#endif
#include "consensus/consensus.h"
#include "consensus/validation.h"
#include "script/script.h"
#include "script/sign.h"
#include "streams.h"

#include <array>

// FIXME: Dedup with BuildCreditingTransaction in test/script_tests.cpp.
static CMutableTransaction BuildCreditingTransaction(const CScript &scriptPubKey)
{
    CMutableTransaction txCredit;
    txCredit.nVersion = 0;
    txCredit.nLockTime = 0;
    txCredit.vin.resize(1);
    txCredit.vout.resize(1);
    txCredit.vin[0].prevout.SetNull();
    txCredit.vin[0].amount = 1;
    txCredit.vin[0].scriptSig = CScript() << CScriptNum::fromIntUnchecked(0) << CScriptNum::fromIntUnchecked(0);
    txCredit.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    txCredit.vout[0].scriptPubKey = scriptPubKey;
    txCredit.vout[0].nValue = 1;

    return txCredit;
}

// FIXME: Dedup with BuildSpendingTransaction in test/script_tests.cpp.
static CMutableTransaction BuildSpendingTransaction(const CScript &scriptSig, const CMutableTransaction &txCredit)
{
    CMutableTransaction txSpend;
    txSpend.nVersion = 0;
    txSpend.nLockTime = 0;
    txSpend.vin.resize(1);
    txSpend.vout.resize(1);
    txSpend.vin[0].prevout = txCredit.OutpointAt(0);
    txSpend.vin[0].amount = txCredit.vout[0].nValue;
    txSpend.vin[0].scriptSig = scriptSig;
    txSpend.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    txSpend.vout[0].scriptPubKey = CScript();
    txSpend.vout[0].nValue = txCredit.vout[0].nValue;

    return txSpend;
}

CMutableTransaction BuildTemplateCreditingTransaction(const CScript &constraintScript,
    const CScript &argsScript,
    const CScript &visibleArgs,
    CAmount nValue)
{
    CMutableTransaction txCredit;
    txCredit.nVersion = 1;
    txCredit.nLockTime = 0;
    txCredit.vin.resize(1);
    txCredit.vout.resize(1);
    // This one is basically just a fake since this tx does not need to actually connect with a parent
    txCredit.vin[0].prevout.SetNull();
    txCredit.vin[0].scriptSig = CScript() << CScriptNum::fromIntUnchecked(0) << CScriptNum::fromIntUnchecked(0);
    txCredit.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    txCredit.vin[0].amount = nValue;
    // We will access this one
    txCredit.vout[0].scriptPubKey = ScriptTemplateLock(constraintScript, argsScript, visibleArgs);
    txCredit.vout[0].nValue = nValue;
    txCredit.vout[0].type = CTxOut::TEMPLATE;
    return txCredit;
}

CMutableTransaction BuildTemplateSpendingTransaction(const CScript &constraintScript,
    const CScript &argsScript,
    const CScript &satisfierScript,
    const CMutableTransaction &txCredit)
{
    CMutableTransaction txSpend;
    txSpend.nVersion = 1;
    txSpend.nLockTime = 0;
    txSpend.vin.resize(1);
    txSpend.vout.resize(1);
    txSpend.vin[0] = txCredit.SpendOutput(0);

    txSpend.vin[0].scriptSig = ScriptTemplateUnlock(constraintScript, satisfierScript, argsScript);
    txSpend.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    txSpend.vout[0].scriptPubKey = CScript();
    txSpend.vout[0].nValue = txCredit.vout[0].nValue;
    return txSpend;
}

CMutableTransaction BuildTemplateCreditingTransaction(uint64_t wkTemplate,
    const CScript &argsScript,
    const CScript &visibleArgs,
    CAmount nValue)
{
    CMutableTransaction txCredit;
    txCredit.nVersion = 1;
    txCredit.nLockTime = 0;
    txCredit.vin.resize(1);
    txCredit.vout.resize(1);
    // This one is basically just a fake since this tx does not need to actually connect with a parent
    txCredit.vin[0].prevout.SetNull();
    txCredit.vin[0].scriptSig = CScript() << CScriptNum::fromIntUnchecked(0) << CScriptNum::fromIntUnchecked(0);
    txCredit.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    txCredit.vin[0].amount = nValue;
    // We will access this one
    txCredit.vout[0].scriptPubKey =
        ScriptWellKnownTemplateLock(wkTemplate, argsScript.Hash160(), visibleArgs.ToVch(), NoGroup, 0);
    txCredit.vout[0].nValue = nValue;
    txCredit.vout[0].type = CTxOut::TEMPLATE;
    return txCredit;
}

CMutableTransaction BuildTemplateSpendingTransaction(uint64_t wkTemplate,
    const CScript &argsScript,
    const CScript &satisfierScript,
    const CMutableTransaction &txCredit)
{
    CMutableTransaction txSpend;
    txSpend.nVersion = 1;
    txSpend.nLockTime = 0;
    txSpend.vin.resize(1);
    txSpend.vout.resize(1);
    txSpend.vin[0] = txCredit.SpendOutput(0);

    txSpend.vin[0].scriptSig = ScriptWellKnownTemplateUnlock(wkTemplate, satisfierScript, argsScript);
    txSpend.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    txSpend.vout[0].scriptPubKey = CScript();
    txSpend.vout[0].nValue = txCredit.vout[0].nValue;
    return txSpend;
}


// Microbenchmark for verification of a basic P2SH script. Can be easily
// modified to measure performance of other types of scripts.
static void ScriptVerifySig(benchmark::State &state)
{
    const ECCVerifyHandle verify_handle;
    ECC_Start();

    const int flags = SCRIPT_VERIFY_P2SH;

    // Keypair.
    CKey key;
    static const std::array<unsigned char, 32> vchKey = {
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}};
    key.Set(vchKey.begin(), vchKey.end(), false);
    CPubKey pubkey = key.GetPubKey();
    uint160 pubkeyHash;
    CHash160().Write(pubkey.begin(), pubkey.size()).Finalize(pubkeyHash.begin());

    // Script.
    CScript scriptPubKey = CScript() << ToByteVector(pubkeyHash);
    CScript scriptSig;
    CScript witScriptPubkey = CScript() << OP_DUP << OP_HASH160 << ToByteVector(pubkeyHash) << OP_EQUALVERIFY
                                        << OP_CHECKSIG;
    const CMutableTransaction &txCredit = BuildCreditingTransaction(scriptPubKey);
    CMutableTransaction txSpend = BuildSpendingTransaction(scriptSig, txCredit);
    CScript &ssig = txSpend.vin[0].scriptSig;
    uint256 sighash = SignatureHash(witScriptPubkey, txSpend, 0, defaultSigHashType, txCredit.vout[0].nValue);
    assert(sighash != SIGNATURE_HASH_ERROR);
    std::vector<unsigned char> sig1;
    key.SignSchnorr(sighash, sig1);
    defaultSigHashType.appendToSig(sig1);
    auto pubkeyvec = ToByteVector(pubkey);
    sig1.insert(sig1.end(), pubkeyvec.begin(), pubkeyvec.end());
    ssig = CScript() << sig1;

    // Benchmark.
    MutableTransactionSignatureChecker tsc(&txSpend, 0, txCredit.vout[0].nValue);
    ScriptImportedState sis(&tsc, MakeTransactionRef(txSpend), CValidationState(), {txCredit.vout[0]}, 0);
    while (state.KeepRunning())
    {
        ScriptError err;
        bool success = VerifyScript(txSpend.vin[0].scriptSig, txCredit.vout[0].scriptPubKey, flags, sis, &err);
        assert(err == SCRIPT_ERR_OK);
        assert(success);
    }
    ECC_Stop();
}

static ScriptImportedState SetupTemplateEval()
{
    static const unsigned int flags = POST_UPGRADE_MANDATORY_SCRIPT_VERIFY_FLAGS;

    CScript satisfy;
    satisfy << OP_NOP;
    CScript empty;

    // Build a crediting and spending transaction against a dummy constraint
    CScript constraint;
    constraint << OP_NOP;
    CScript args = CScript() << OP_2 << OP_3;
    CMutableTransaction txFrom = BuildTemplateCreditingTransaction(constraint, args, empty, 1);
    CMutableTransaction txTo = BuildTemplateSpendingTransaction(constraint, args, empty, txFrom);

    auto sis = ScriptImportedStateSig(&txTo, 0, txFrom.vout[0].nValue, flags);
    sis.spentCoins.push_back(txFrom.vout[0]);
    return sis;
}


// Microbenchmark for verification of a basic template script. Can be easily
// modified to measure performance of other types of scripts.
static void ScriptInfiniteLoop(benchmark::State &state)
{
    static const unsigned int flags = POST_UPGRADE_MANDATORY_SCRIPT_VERIFY_FLAGS;
    auto trk = ScriptMachineResourceTracker();
    auto tops = MAX_OPS_PER_SCRIPT_TEMPLATE;
    auto sops = MAX_OPS_PER_SCRIPT;
    auto sis = SetupTemplateEval();
    CScript empty;
    ScriptError err;
    CScript st = CScript() << OP_1 << OP_JUMP;
    while (state.KeepRunning())
    {
        trk.clear();
        auto vfy = VerifyTemplate(st, empty, empty, flags, tops, sops, sis, &err, &trk);
        assert(!vfy);
        assert(err == SCRIPT_ERR_OP_COUNT);
    }
}

// Microbenchmark for verification of a basic template script. Can be easily
// modified to measure performance of other types of scripts.
static void ScriptInfiniteBignum(benchmark::State &state)
{
    static const unsigned int flags = POST_UPGRADE_MANDATORY_SCRIPT_VERIFY_FLAGS;
    auto trk = ScriptMachineResourceTracker();
    auto tops = MAX_OPS_PER_SCRIPT_TEMPLATE;
    auto sops = MAX_OPS_PER_SCRIPT;
    auto sis = SetupTemplateEval();
    CScript empty;
    ScriptError err;
    CScript st = CScript() << ParseHex("2ffcfffffeffffffffffffffffffffffffffffffffffffffffffffffffffffff00")
                           << OP_SETBMD << OP_3 << OP_BIN2BIGNUM << OP_5 << OP_BIN2BIGNUM << OP_MUL << OP_DUP << OP_3
                           << OP_JUMP;
    while (state.KeepRunning())
    {
        trk.clear();
        auto vfy = VerifyTemplate(st, empty, empty, flags, tops, sops, sis, &err, &trk);
        assert(!vfy);
        assert(err == SCRIPT_ERR_OP_COUNT);
    }
}

const unsigned char vchKey0[32] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
struct KeyData
{
    CKey key0;
    CPubKey pubkey0;

    KeyData()
    {
        key0.Set(vchKey0, vchKey0 + 32, false);
        pubkey0 = key0.GetPubKey();
    }
};


// Microbenchmark for verification of a basic template script. Can be easily
// modified to measure performance of other types of scripts.
static void ScriptInfiniteSigcheck(benchmark::State &state)
{
    const ECCVerifyHandle verify_handle;
    ECC_Start();
    KeyData keys;
    static const unsigned int flags = POST_UPGRADE_MANDATORY_SCRIPT_VERIFY_FLAGS;
    auto trk = ScriptMachineResourceTracker();
    auto tops = MAX_OPS_PER_SCRIPT_TEMPLATE;
    auto sops = MAX_OPS_PER_SCRIPT;
    CScript empty;
    ScriptError err;

    StackItem message(ParseHex("FFFF"));
    StackItem vchHash(VchStack, 32);
    CSHA256().Write(message.data().data(), message.size()).Finalize(vchHash.mdata().data());
    uint256 messageHash(vchHash.data());
    StackItem validsig;
    keys.key0.SignSchnorr(messageHash, validsig.mdata());
    CScript st = CScript() << validsig.data() << message.data() << ToByteVector(keys.pubkey0) << OP_CHECKDATASIG
                           << OP_DROP;
    st << st.size() + 3 << OP_JUMP; // jump back to the beginning


    CScript satisfy;
    satisfy << OP_NOP;
    // Build a crediting and spending transaction against a dummy constraint
    CScript constraint;
    constraint << OP_NOP;
    CScript args = CScript() << OP_2 << OP_3;
    CMutableTransaction txFrom = BuildTemplateCreditingTransaction(constraint, args, empty, 1);
    CMutableTransaction txTo = BuildTemplateSpendingTransaction(constraint, args, empty, txFrom);

    CValidationState vs;
    MutableTransactionSignatureChecker tsc(&txTo, 0, txFrom.vout[0].nValue);
    auto sis = ScriptImportedState(&tsc, MakeTransactionRef(txTo), vs, {txFrom.vout[0]}, 0);
    sis.spentCoins.push_back(txFrom.vout[0]);

    // But then actually try it against other scripts by calling VerifyTemplate directly with other constraint scripts
    while (state.KeepRunning())
    {
        trk.clear();
        auto vfy = VerifyTemplate(st, empty, empty, flags, tops, sops, sis, &err, &trk);
        assert(!vfy);
        assert(err == SCRIPT_ERR_SIGCHECKS_LIMIT_EXCEEDED);
    }
    ECC_Stop();
}


static void ScriptVerifyNestedIf(benchmark::State &state)
{
    Stack stack;
    CScript script;
    for (int i = 0; i < 100; ++i)
    {
        script << OP_1 << OP_IF;
    }
    for (int i = 0; i < 1000; ++i)
    {
        script << OP_1;
    }
    for (int i = 0; i < 100; ++i)
    {
        script << OP_ENDIF;
    }
    while (state.KeepRunning())
    {
        auto stack_copy = stack;
        ScriptError error;
        bool ret = EvalScript(stack_copy, script, 0, MAX_OPS_PER_SCRIPT, ScriptImportedState(), &error);
        assert(ret);
    }
}

BENCHMARK(ScriptInfiniteLoop, 50);
BENCHMARK(ScriptInfiniteBignum, 50);
BENCHMARK(ScriptInfiniteSigcheck, 50);
BENCHMARK(ScriptVerifySig, 6300);
BENCHMARK(ScriptVerifyNestedIf, 100);
