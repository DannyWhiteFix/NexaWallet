// Copyright (c) 2018 The Bitcoin developers
// Copyright (c) 2018-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "test/test_nexa.h"

#include "policy/policy.h"
#include "script/interpreter.h"
#include "unlimited.h"

#include <boost/test/unit_test.hpp>

#include <array>

typedef StackItem valtype;
typedef Stack stacktype;

BOOST_FIXTURE_TEST_SUITE(checkdatasig_tests, BasicTestingSetup)

std::array<uint32_t, 3> flagset{{0, STANDARD_SCRIPT_VERIFY_FLAGS, MANDATORY_SCRIPT_VERIFY_FLAGS}};

// clang-format off
const uint8_t vchPrivkey[32] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
// clang-format on

struct KeyData
{
    CKey privkey, privkeyC;
    CPubKey pubkey, pubkeyC, pubkeyH;

    KeyData()
    {
        privkey.Set(vchPrivkey, vchPrivkey + 32, false);
        privkeyC.Set(vchPrivkey, vchPrivkey + 32, true);
        pubkey = privkey.GetPubKey();
        pubkeyH = privkey.GetPubKey();
        pubkeyC = privkeyC.GetPubKey();
        *const_cast<uint8_t *>(&pubkeyH[0]) = 0x06 | (pubkeyH[64] & 1);
    }
};

static void CheckError(uint32_t flags, const stacktype &original_stack, const CScript &script, ScriptError expected)
{
    ScriptError err = SCRIPT_ERR_OK;
    stacktype stack{original_stack};
    // Note that this returns false for CHECKSIG, whereas an empty ScriptImportedState() errors out with missing data
    BaseSignatureChecker checker;
    ScriptImportedState sis(&checker);
    bool r = EvalScript(stack, script, flags, MAX_OPS_PER_SCRIPT, sis, &err);
    BOOST_CHECK(!r);
    BOOST_CHECK_EQUAL(err, expected);
}

static void CheckPass(uint32_t flags, const stacktype &original_stack, const CScript &script, const stacktype &expected)
{
    ScriptError err = SCRIPT_ERR_OK;
    stacktype stack{original_stack};
    // Note that this returns false for CHECKSIG, whereas an empty ScriptImportedState() errors out with missing data
    BaseSignatureChecker checker;
    ScriptImportedState sis(&checker);
    bool r = EvalScript(stack, script, flags, MAX_OPS_PER_SCRIPT, sis, &err);
    BOOST_CHECK(r);
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
    BOOST_CHECK(stack == expected);
}

/**
 * General utility functions to check for script passing/failing.
 */
static void CheckTestResultForAllFlags(const stacktype &original_stack,
    const CScript &script,
    const stacktype &expected)
{
    for (uint32_t flags : flagset)
    {
        // The script executes as expected regardless of whether or not
        // SCRIPT_ENABLE_CHECKDATASIG flag is passed.
        CheckPass(flags & ~SCRIPT_ENABLE_CHECKDATASIG, original_stack, script, expected);
        CheckPass(flags | SCRIPT_ENABLE_CHECKDATASIG, original_stack, script, expected);
    }
}

static void CheckErrorForAllFlags(const stacktype &original_stack, const CScript &script, ScriptError expected)
{
    for (uint32_t flags : flagset)
    {
        // The script generates the proper error regardless of whether or not
        // SCRIPT_ENABLE_CHECKDATASIG flag is passed.
        CheckError(flags & ~SCRIPT_ENABLE_CHECKDATASIG, original_stack, script, expected);
        CheckError(flags | SCRIPT_ENABLE_CHECKDATASIG, original_stack, script, expected);
    }
}

BOOST_AUTO_TEST_CASE(checkdatasig_test)
{
    // Empty stack.
    CheckErrorForAllFlags({}, CScript() << OP_CHECKDATASIG, SCRIPT_ERR_INVALID_STACK_OPERATION);
    CheckErrorForAllFlags({{0x00}}, CScript() << OP_CHECKDATASIG, SCRIPT_ERR_INVALID_STACK_OPERATION);
    CheckErrorForAllFlags({{0x00}, {0x00}}, CScript() << OP_CHECKDATASIG, SCRIPT_ERR_INVALID_STACK_OPERATION);
    CheckErrorForAllFlags({}, CScript() << OP_CHECKDATASIGVERIFY, SCRIPT_ERR_INVALID_STACK_OPERATION);
    CheckErrorForAllFlags({{0x00}}, CScript() << OP_CHECKDATASIGVERIFY, SCRIPT_ERR_INVALID_STACK_OPERATION);
    CheckErrorForAllFlags({{0x00}, {0x00}}, CScript() << OP_CHECKDATASIGVERIFY, SCRIPT_ERR_INVALID_STACK_OPERATION);

    // Check various pubkey encoding.
    const valtype message{};
    valtype vchHash(VchStack, 32);
    CSHA256().Write(message.data().data(), message.size()).Finalize(vchHash.mdata().data());
    uint256 messageHash(vchHash.data());

    KeyData kd;
    valtype pubkey = ToByteVector(kd.pubkey);
    valtype pubkeyC = ToByteVector(kd.pubkeyC);
    valtype pubkeyH = ToByteVector(kd.pubkeyH);

    CheckTestResultForAllFlags({{}, message, pubkey}, CScript() << OP_CHECKDATASIG, {{}});
    CheckTestResultForAllFlags({{}, message, pubkeyC}, CScript() << OP_CHECKDATASIG, {{}});
    CheckErrorForAllFlags({{}, message, pubkey}, CScript() << OP_CHECKDATASIGVERIFY, SCRIPT_ERR_CHECKDATASIGVERIFY);
    CheckErrorForAllFlags({{}, message, pubkeyC}, CScript() << OP_CHECKDATASIGVERIFY, SCRIPT_ERR_CHECKDATASIGVERIFY);

    // Flags dependent checks.
    const CScript script = CScript() << OP_CHECKDATASIG << OP_NOT << OP_VERIFY;
    const CScript scriptverify = CScript() << OP_CHECKDATASIGVERIFY;

    // Check valid signatures (as in the signature format is valid).
    valtype validsig;
    kd.privkey.SignSchnorr(messageHash, validsig.mdata());

    CheckTestResultForAllFlags({validsig, message, pubkey}, CScript() << OP_CHECKDATASIG, {{0x01}});
    CheckTestResultForAllFlags({validsig, message, pubkey}, CScript() << OP_CHECKDATASIGVERIFY, {});

    // clang-format off
    const valtype minimalsig{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01};

    VchType badsigdata;
    badsigdata.resize(64);
    badsigdata[0] = 1;
    valtype badsig(badsigdata);
    // clang-format on

    // If we add many more flags, this loop can get too expensive, but we can
    // rewrite in the future to randomly pick a set of flags to evaluate.
    for (uint32_t flags = 0; flags < (1U << 17); flags++)
    {
        // Make sure we activate the opcodes.
        flags |= SCRIPT_ENABLE_CHECKDATASIG;

        if (flags & SCRIPT_VERIFY_STRICTENC)
        {
            // When strict encoding is enforced, hybrid key are invalid.
            CheckError(flags, {{}, message, pubkeyH}, script, SCRIPT_ERR_PUBKEYTYPE);
            CheckError(flags, {{}, message, pubkeyH}, scriptverify, SCRIPT_ERR_PUBKEYTYPE);
        }
        else
        {
            // When strict encoding is not enforced, hybrid key are valid.
            CheckPass(flags, {{}, message, pubkeyH}, script, {});
            CheckError(flags, {{}, message, pubkeyH}, scriptverify, SCRIPT_ERR_CHECKDATASIGVERIFY);
        }

        if (flags & SCRIPT_VERIFY_NULLFAIL)
        {
            // When strict encoding is enforced, hybrid key are invalid.
            CheckError(flags, {minimalsig, message, pubkey}, script, SCRIPT_ERR_SIG_NULLFAIL);
            CheckError(flags, {minimalsig, message, pubkey}, scriptverify, SCRIPT_ERR_SIG_NULLFAIL);

            // Invalid message cause checkdatasig to fail.
            CheckError(flags, {validsig, {0x01}, pubkey}, script, SCRIPT_ERR_SIG_NULLFAIL);
            CheckError(flags, {validsig, {0x01}, pubkey}, scriptverify, SCRIPT_ERR_SIG_NULLFAIL);
        }
        else
        {
            // When nullfail is not enforced, invalid signature are just false.
            CheckPass(flags, {badsig, message, pubkey}, script, {});
            CheckError(flags, {badsig, message, pubkey}, scriptverify, SCRIPT_ERR_CHECKDATASIGVERIFY);

            // Invalid message cause checkdatasig to fail.
            CheckPass(flags, {validsig, {0x01}, pubkey}, script, {});
            CheckError(flags, {validsig, {0x01}, pubkey}, scriptverify, SCRIPT_ERR_CHECKDATASIGVERIFY);
        }
    }
}

BOOST_AUTO_TEST_CASE(checkdatasig_inclusion_in_standard_and_mandatory_flags)
{
    BOOST_CHECK(STANDARD_SCRIPT_VERIFY_FLAGS & SCRIPT_ENABLE_CHECKDATASIG);
    BOOST_CHECK(!(MANDATORY_SCRIPT_VERIFY_FLAGS & SCRIPT_ENABLE_CHECKDATASIG));
}

BOOST_AUTO_TEST_CASE(checkdatasig_opcode_formatting)
{
    BOOST_CHECK_EQUAL(GetOpName(OP_CHECKDATASIG), "OP_CHECKDATASIG");
    BOOST_CHECK_EQUAL(GetOpName(OP_CHECKDATASIGVERIFY), "OP_CHECKDATASIGVERIFY");
}
BOOST_AUTO_TEST_SUITE_END()
