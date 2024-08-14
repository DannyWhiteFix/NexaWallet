// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "data/script_tests.json.h"

#include "core_io.h"
#include "key.h"
#include "keystore.h"
#include "rpc/server.h"
#include "script/script.h"
#include "script/script_error.h"
#include "script/sighashtype.h"
#include "script/sign.h"
#include "test/scriptflags.h"
#include "test/test_nexa.h"
#include "test/testutil.h"
#include "unlimited.h"
#include "util.h"
#include "utilstrencodings.h"

#if defined(HAVE_CONSENSUS_LIB)
#include "script/bitcoinconsensus.h"
#endif

#include <fstream>
#include <stdint.h>
#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

#include <univalue.h>


BOOST_FIXTURE_TEST_SUITE(script_op_roll_pick_tests, BasicTestingSetup)

void print_stack(const Stack &stack)
{
    const size_t size = stack.size();
    printf("Stack (right is top, left is bottom): ");
    for (size_t i = 0; i < size; ++i)
    {
        printf("%s ", stack[i].hex().c_str());
    }
    printf("\n");
}

std::vector<uint8_t> StackToVch(const Stack &stack)
{
    std::vector<uint8_t> ret = {};
    const size_t size = stack.size();
    for (size_t i = 0; i < size; ++i)
    {
        std::vector<uint8_t> data = stack[i].data();
        ret.insert(ret.end(), data.begin(), data.end());
    }
    return ret;
}

void ResetTest(std::vector<uint8_t> &expected, std::vector<uint8_t> &vchStack, ScriptMachine &sm)
{
    expected.clear();
    vchStack.clear();
    sm.Reset();
}

BOOST_AUTO_TEST_CASE(script_op_roll_positive_no_flag)
{
    // OP_ROLL 0, no-op
    std::vector<uint8_t> expected = {9, 7, 5, 3, 1};
    CScript testScript = CScript() << 9 << 7 << 5 << 3 << 1 << 0 << OP_ROLL;
    ScriptMachine sm(0, ScriptImportedState(), 0xffffffff, 0xffffffff);
    bool result = sm.Eval(testScript);
    BOOST_CHECK(result);
    std::vector<uint8_t> vchStack = StackToVch(sm.getStack());
    BOOST_CHECK(vchStack == expected);
    ResetTest(expected, vchStack, sm);

    // OP_ROLL 1
    expected = {9, 7, 5, 1, 3};
    testScript = CScript() << 9 << 7 << 5 << 3 << 1 << 1 << OP_ROLL;
    result = sm.Eval(testScript);
    BOOST_CHECK(result);
    vchStack = StackToVch(sm.getStack());
    BOOST_CHECK(vchStack == expected);
    ResetTest(expected, vchStack, sm);

    // OP_ROLL 2
    expected = {9, 7, 3, 1, 5};
    testScript = CScript() << 9 << 7 << 5 << 3 << 1 << 2 << OP_ROLL;
    result = sm.Eval(testScript);
    BOOST_CHECK(result);
    vchStack = StackToVch(sm.getStack());
    BOOST_CHECK(vchStack == expected);
    ResetTest(expected, vchStack, sm);

    // OP_ROLL 3
    expected = {9, 5, 3, 1, 7};
    testScript = CScript() << 9 << 7 << 5 << 3 << 1 << 3 << OP_ROLL;
    result = sm.Eval(testScript);
    BOOST_CHECK(result);
    vchStack = StackToVch(sm.getStack());
    BOOST_CHECK(vchStack == expected);
    ResetTest(expected, vchStack, sm);

    // OP_ROLL 4
    expected = {7, 5, 3, 1, 9};
    testScript = CScript() << 9 << 7 << 5 << 3 << 1 << 4 << OP_ROLL;
    result = sm.Eval(testScript);
    BOOST_CHECK(result);
    vchStack = StackToVch(sm.getStack());
    BOOST_CHECK(vchStack == expected);
    ResetTest(expected, vchStack, sm);

    // OP_ROLL 5 - equal .size()
    testScript = CScript() << 9 << 7 << 5 << 3 << 1 << 5 << OP_ROLL;
    result = sm.Eval(testScript);
    BOOST_CHECK_EQUAL(result, false);
    BOOST_CHECK_EQUAL(sm.getError(), SCRIPT_ERR_INVALID_STACK_OPERATION);
    sm.Reset();

    // OP_ROLL 6 - > .size()
    testScript = CScript() << 9 << 7 << 5 << 3 << 1 << 6 << OP_ROLL;
    result = sm.Eval(testScript);
    BOOST_CHECK_EQUAL(result, false);
    BOOST_CHECK_EQUAL(sm.getError(), SCRIPT_ERR_INVALID_STACK_OPERATION);
    ResetTest(expected, vchStack, sm);
}

BOOST_AUTO_TEST_CASE(script_op_roll_positive_with_flag)
{
    // OP_ROLL 0, no-op
    std::vector<uint8_t> expected = {9, 7, 5, 3, 1};
    CScript testScript = CScript() << 9 << 7 << 5 << 3 << 1 << 0 << OP_ROLL;
    ScriptMachine sm(0 | SCRIPT_NEG_OP_ROLL_OP_PICK, ScriptImportedState(), 0xffffffff, 0xffffffff);
    bool result = sm.Eval(testScript);
    BOOST_CHECK(result);
    std::vector<uint8_t> vchStack = StackToVch(sm.getStack());
    BOOST_CHECK(vchStack == expected);
    ResetTest(expected, vchStack, sm);

    // OP_ROLL 1
    expected = {9, 7, 5, 1, 3};
    testScript = CScript() << 9 << 7 << 5 << 3 << 1 << 1 << OP_ROLL;
    result = sm.Eval(testScript);
    BOOST_CHECK(result);
    vchStack = StackToVch(sm.getStack());
    BOOST_CHECK(vchStack == expected);
    ResetTest(expected, vchStack, sm);

    // OP_ROLL 2
    expected = {9, 7, 3, 1, 5};
    testScript = CScript() << 9 << 7 << 5 << 3 << 1 << 2 << OP_ROLL;
    result = sm.Eval(testScript);
    BOOST_CHECK(result);
    vchStack = StackToVch(sm.getStack());
    BOOST_CHECK(vchStack == expected);
    ResetTest(expected, vchStack, sm);

    // OP_ROLL 3
    expected = {9, 5, 3, 1, 7};
    testScript = CScript() << 9 << 7 << 5 << 3 << 1 << 3 << OP_ROLL;
    result = sm.Eval(testScript);
    BOOST_CHECK(result);
    vchStack = StackToVch(sm.getStack());
    BOOST_CHECK(vchStack == expected);
    ResetTest(expected, vchStack, sm);

    // OP_ROLL 4
    expected = {7, 5, 3, 1, 9};
    testScript = CScript() << 9 << 7 << 5 << 3 << 1 << 4 << OP_ROLL;
    result = sm.Eval(testScript);
    BOOST_CHECK(result);
    vchStack = StackToVch(sm.getStack());
    BOOST_CHECK(vchStack == expected);
    ResetTest(expected, vchStack, sm);

    // OP_ROLL 5 - equal .size()
    testScript = CScript() << 9 << 7 << 5 << 3 << 1 << 5 << OP_ROLL;
    result = sm.Eval(testScript);
    BOOST_CHECK_EQUAL(result, false);
    BOOST_CHECK_EQUAL(sm.getError(), SCRIPT_ERR_INVALID_STACK_OPERATION);
    sm.Reset();

    // OP_ROLL 6 - > .size()
    testScript = CScript() << 9 << 7 << 5 << 3 << 1 << 6 << OP_ROLL;
    result = sm.Eval(testScript);
    BOOST_CHECK_EQUAL(result, false);
    BOOST_CHECK_EQUAL(sm.getError(), SCRIPT_ERR_INVALID_STACK_OPERATION);
    ResetTest(expected, vchStack, sm);
}

BOOST_AUTO_TEST_CASE(script_op_roll_negative_no_flag)
{
    // OP_ROLL -1
    std::vector<uint8_t> expected = {9, 7, 5, 3, 1};
    std::vector<uint8_t> vchStack;
    CScript testScript = CScript() << 9 << 7 << 5 << 3 << 1 << 1 << OP_NEGATE << OP_ROLL;
    ScriptMachine sm(0, ScriptImportedState(), 0xffffffff, 0xffffffff);
    bool result = sm.Eval(testScript);
    BOOST_CHECK(result == false);
    BOOST_CHECK_EQUAL(sm.getError(), SCRIPT_ERR_INVALID_STACK_OPERATION);
    ResetTest(expected, vchStack, sm);

    // OP_ROLL -2
    expected = {9, 7, 5, 1, 3};
    testScript = CScript() << 9 << 7 << 5 << 3 << 1 << 2 << OP_NEGATE << OP_ROLL;
    result = sm.Eval(testScript);
    BOOST_CHECK(result == false);
    BOOST_CHECK_EQUAL(sm.getError(), SCRIPT_ERR_INVALID_STACK_OPERATION);
    ResetTest(expected, vchStack, sm);

    // OP_ROLL -3
    expected = {9, 7, 1, 5, 3};
    testScript = CScript() << 9 << 7 << 5 << 3 << 1 << 3 << OP_NEGATE << OP_ROLL;
    result = sm.Eval(testScript);
    BOOST_CHECK(result == false);
    BOOST_CHECK_EQUAL(sm.getError(), SCRIPT_ERR_INVALID_STACK_OPERATION);
    ResetTest(expected, vchStack, sm);

    // OP_ROLL -4
    expected = {9, 1, 7, 5, 3,};
    testScript = CScript() << 9 << 7 << 5 << 3 << 1 << 4 << OP_NEGATE << OP_ROLL;
    result = sm.Eval(testScript);
    BOOST_CHECK(result == false);
    BOOST_CHECK_EQUAL(sm.getError(), SCRIPT_ERR_INVALID_STACK_OPERATION);
    ResetTest(expected, vchStack, sm);

    // OP_ROLL 5 - equal .size()
    expected = {1, 9, 7, 5, 3,};
    testScript = CScript() << 9 << 7 << 5 << 3 << 1 << 5 << OP_NEGATE << OP_ROLL;
    result = sm.Eval(testScript);
    BOOST_CHECK(result == false);
    BOOST_CHECK_EQUAL(sm.getError(), SCRIPT_ERR_INVALID_STACK_OPERATION);
    ResetTest(expected, vchStack, sm);

    // OP_ROLL 6 - > .size()
    testScript = CScript() << 9 << 7 << 5 << 3 << 1 << 6 << OP_NEGATE << OP_ROLL;
    result = sm.Eval(testScript);
    BOOST_CHECK_EQUAL(result, false);
    BOOST_CHECK_EQUAL(sm.getError(), SCRIPT_ERR_INVALID_STACK_OPERATION);
    ResetTest(expected, vchStack, sm);
}

BOOST_AUTO_TEST_CASE(script_op_roll_negative_with_flag)
{
    // OP_ROLL 0, no-op
    std::vector<uint8_t> expected = {9, 7, 5, 3, 1};
    CScript testScript = CScript() << 9 << 7 << 5 << 3 << 1 << 0 << OP_NEGATE << OP_ROLL;
    ScriptMachine sm(0 | SCRIPT_NEG_OP_ROLL_OP_PICK, ScriptImportedState(), 0xffffffff, 0xffffffff);
    bool result = sm.Eval(testScript);
    BOOST_CHECK(result);
    std::vector<uint8_t> vchStack = StackToVch(sm.getStack());
    BOOST_CHECK(vchStack == expected);
    ResetTest(expected, vchStack, sm);

    // OP_ROLL -1
    expected = {9, 7, 5, 3, 1};
    testScript = CScript() << 9 << 7 << 5 << 3 << 1 << 1 << OP_NEGATE << OP_ROLL;
    result = sm.Eval(testScript);
    BOOST_CHECK(result);
    vchStack = StackToVch(sm.getStack());
    BOOST_CHECK(vchStack == expected);
    ResetTest(expected, vchStack, sm);

    // OP_ROLL -2
    expected = {9, 7, 5, 1, 3};
    testScript = CScript() << 9 << 7 << 5 << 3 << 1 << 2 << OP_NEGATE << OP_ROLL;
    result = sm.Eval(testScript);
    BOOST_CHECK(result);
    vchStack = StackToVch(sm.getStack());
    BOOST_CHECK(vchStack == expected);
    ResetTest(expected, vchStack, sm);

    // OP_ROLL -3
    expected = {9, 7, 1, 5, 3};
    testScript = CScript() << 9 << 7 << 5 << 3 << 1 << 3 << OP_NEGATE << OP_ROLL;
    result = sm.Eval(testScript);
    BOOST_CHECK(result);
    vchStack = StackToVch(sm.getStack());
    BOOST_CHECK(vchStack == expected);
    ResetTest(expected, vchStack, sm);

    // OP_ROLL -4
    expected = {9, 1, 7, 5, 3,};
    testScript = CScript() << 9 << 7 << 5 << 3 << 1 << 4 << OP_NEGATE << OP_ROLL;
    result = sm.Eval(testScript);
    BOOST_CHECK(result);
    vchStack = StackToVch(sm.getStack());
    BOOST_CHECK(vchStack == expected);
    ResetTest(expected, vchStack, sm);

    // OP_ROLL 5 - equal .size()
    expected = {1, 9, 7, 5, 3,};
    testScript = CScript() << 9 << 7 << 5 << 3 << 1 << 5 << OP_NEGATE << OP_ROLL;
    result = sm.Eval(testScript);
    BOOST_CHECK(result);
    vchStack = StackToVch(sm.getStack());
    BOOST_CHECK(vchStack == expected);
    ResetTest(expected, vchStack, sm);

    // OP_ROLL 6 - > .size()
    testScript = CScript() << 9 << 7 << 5 << 3 << 1 << 6 << OP_NEGATE << OP_ROLL;
    result = sm.Eval(testScript);
    BOOST_CHECK_EQUAL(result, false);
    BOOST_CHECK_EQUAL(sm.getError(), SCRIPT_ERR_INVALID_STACK_OPERATION);
    ResetTest(expected, vchStack, sm);
}

BOOST_AUTO_TEST_CASE(script_op_pick_positive_no_flag)
{
    // OP_PICK 0
    std::vector<uint8_t> expected = {9, 7, 5, 3, 1, 1};
    CScript testScript = CScript() << 9 << 7 << 5 << 3 << 1 << 0 << OP_PICK;
    ScriptMachine sm(0, ScriptImportedState(), 0xffffffff, 0xffffffff);
    bool result = sm.Eval(testScript);
    BOOST_CHECK(result);
    std::vector<uint8_t> vchStack = StackToVch(sm.getStack());
    BOOST_CHECK(vchStack == expected);
    ResetTest(expected, vchStack, sm);

    // OP_PICK 1
    expected = {9, 7, 5, 3, 1, 3};
    testScript = CScript() << 9 << 7 << 5 << 3 << 1 << 1 << OP_PICK;
    result = sm.Eval(testScript);
    BOOST_CHECK(result);
    vchStack = StackToVch(sm.getStack());
    BOOST_CHECK(vchStack == expected);
    ResetTest(expected, vchStack, sm);

    // OP_PICK 2
    expected = {9, 7, 5, 3, 1, 5};
    testScript = CScript() << 9 << 7 << 5 << 3 << 1 << 2 << OP_PICK;
    result = sm.Eval(testScript);
    BOOST_CHECK(result);
    vchStack = StackToVch(sm.getStack());
    BOOST_CHECK(vchStack == expected);
    ResetTest(expected, vchStack, sm);

    // OP_PICK 3
    expected = {9, 7, 5, 3, 1, 7};
    testScript = CScript() << 9 << 7 << 5 << 3 << 1 << 3 << OP_PICK;
    result = sm.Eval(testScript);
    BOOST_CHECK(result);
    vchStack = StackToVch(sm.getStack());
    BOOST_CHECK(vchStack == expected);
    ResetTest(expected, vchStack, sm);

    // OP_PICK 4
    expected = {9, 7, 5, 3, 1, 9};
    testScript = CScript() << 9 << 7 << 5 << 3 << 1 << 4 << OP_PICK;
    result = sm.Eval(testScript);
    BOOST_CHECK(result);
    vchStack = StackToVch(sm.getStack());
    BOOST_CHECK(vchStack == expected);
    ResetTest(expected, vchStack, sm);

    // OP_PICK 5 - equal .size()
    testScript = CScript() << 9 << 7 << 5 << 3 << 1 << 5 << OP_PICK;
    result = sm.Eval(testScript);
    BOOST_CHECK_EQUAL(result, false);
    BOOST_CHECK_EQUAL(sm.getError(), SCRIPT_ERR_INVALID_STACK_OPERATION);
    ResetTest(expected, vchStack, sm);

    // OP_PICK 6 - > .size()
    testScript = CScript() << 9 << 7 << 5 << 3 << 1 << 6 << OP_PICK;
    result = sm.Eval(testScript);
    BOOST_CHECK_EQUAL(result, false);
    BOOST_CHECK_EQUAL(sm.getError(), SCRIPT_ERR_INVALID_STACK_OPERATION);
    ResetTest(expected, vchStack, sm);
}

BOOST_AUTO_TEST_CASE(script_op_pick_positive_with_flag)
{
    // OP_PICK 0
    std::vector<uint8_t> expected = {9, 7, 5, 3, 1, 1};
    CScript testScript = CScript() << 9 << 7 << 5 << 3 << 1 << 0 << OP_PICK;
    ScriptMachine sm(0 | SCRIPT_NEG_OP_ROLL_OP_PICK, ScriptImportedState(), 0xffffffff, 0xffffffff);
    bool result = sm.Eval(testScript);
    BOOST_CHECK(result);
    std::vector<uint8_t> vchStack = StackToVch(sm.getStack());
    BOOST_CHECK(vchStack == expected);
    ResetTest(expected, vchStack, sm);

    // OP_PICK 1
    expected = {9, 7, 5, 3, 1, 3};
    testScript = CScript() << 9 << 7 << 5 << 3 << 1 << 1 << OP_PICK;
    result = sm.Eval(testScript);
    BOOST_CHECK(result);
    vchStack = StackToVch(sm.getStack());
    BOOST_CHECK(vchStack == expected);
    ResetTest(expected, vchStack, sm);

    // OP_PICK 2
    expected = {9, 7, 5, 3, 1, 5};
    testScript = CScript() << 9 << 7 << 5 << 3 << 1 << 2 << OP_PICK;
    result = sm.Eval(testScript);
    BOOST_CHECK(result);
    vchStack = StackToVch(sm.getStack());
    BOOST_CHECK(vchStack == expected);
    ResetTest(expected, vchStack, sm);

    // OP_PICK 3
    expected = {9, 7, 5, 3, 1, 7};
    testScript = CScript() << 9 << 7 << 5 << 3 << 1 << 3 << OP_PICK;
    result = sm.Eval(testScript);
    BOOST_CHECK(result);
    vchStack = StackToVch(sm.getStack());
    BOOST_CHECK(vchStack == expected);
    ResetTest(expected, vchStack, sm);

    // OP_PICK 4
    expected = {9, 7, 5, 3, 1, 9};
    testScript = CScript() << 9 << 7 << 5 << 3 << 1 << 4 << OP_PICK;
    result = sm.Eval(testScript);
    BOOST_CHECK(result);
    vchStack = StackToVch(sm.getStack());
    BOOST_CHECK(vchStack == expected);
    ResetTest(expected, vchStack, sm);

    // OP_PICK 5 - equal .size()
    testScript = CScript() << 9 << 7 << 5 << 3 << 1 << 5 << OP_PICK;
    result = sm.Eval(testScript);
    BOOST_CHECK_EQUAL(result, false);
    BOOST_CHECK_EQUAL(sm.getError(), SCRIPT_ERR_INVALID_STACK_OPERATION);
    ResetTest(expected, vchStack, sm);

    // OP_PICK 6 - > .size()
    testScript = CScript() << 9 << 7 << 5 << 3 << 1 << 6 << OP_PICK;
    result = sm.Eval(testScript);
    BOOST_CHECK_EQUAL(result, false);
    BOOST_CHECK_EQUAL(sm.getError(), SCRIPT_ERR_INVALID_STACK_OPERATION);
    ResetTest(expected, vchStack, sm);
}

BOOST_AUTO_TEST_CASE(script_op_pick_negative_no_flag)
{
    // OP_PICK -1
    std::vector<uint8_t>  expected = {9, 7, 5, 3, 1, 1,};
    std::vector<uint8_t> vchStack;
    CScript  testScript = CScript() << 9 << 7 << 5 << 3 << 1 << 1 << OP_NEGATE << OP_PICK;
    ScriptMachine sm(0, ScriptImportedState(), 0xffffffff, 0xffffffff);
    bool result = sm.Eval(testScript);
    BOOST_CHECK(result == false);
    BOOST_CHECK_EQUAL(sm.getError(), SCRIPT_ERR_INVALID_STACK_OPERATION);
    ResetTest(expected, vchStack, sm);

    // OP_PICK -2
    expected = {9, 7, 5, 1, 3, 1};
    testScript = CScript() << 9 << 7 << 5 << 3 << 1 << 2 << OP_NEGATE << OP_PICK;
    result = sm.Eval(testScript);
    BOOST_CHECK(result == false);
    BOOST_CHECK_EQUAL(sm.getError(), SCRIPT_ERR_INVALID_STACK_OPERATION);
    ResetTest(expected, vchStack, sm);

    // OP_PICK -3
    expected = {9, 7, 1, 5, 3, 1};
    testScript = CScript() << 9 << 7 << 5 << 3 << 1 << 3 << OP_NEGATE << OP_PICK;
    result = sm.Eval(testScript);
    BOOST_CHECK(result == false);
    BOOST_CHECK_EQUAL(sm.getError(), SCRIPT_ERR_INVALID_STACK_OPERATION);
    ResetTest(expected, vchStack, sm);

    // OP_PICK -4
    expected = {9, 1, 7, 5, 3, 1};
    testScript = CScript() << 9 << 7 << 5 << 3 << 1 << 4 << OP_NEGATE << OP_PICK;
    result = sm.Eval(testScript);
    BOOST_CHECK(result == false);
    BOOST_CHECK_EQUAL(sm.getError(), SCRIPT_ERR_INVALID_STACK_OPERATION);
    ResetTest(expected, vchStack, sm);

    // OP_PICK -5 - equal .size()
    expected = {1, 9, 7, 5, 3, 1};
    testScript = CScript() << 9 << 7 << 5 << 3 << 1 << 5 << OP_NEGATE << OP_PICK;
    result = sm.Eval(testScript);
    BOOST_CHECK(result == false);
    BOOST_CHECK_EQUAL(sm.getError(), SCRIPT_ERR_INVALID_STACK_OPERATION);
    ResetTest(expected, vchStack, sm);

    // OP_PICK -6 - > .size()
    testScript = CScript() << 9 << 7 << 5 << 3 << 1 << 6 << OP_NEGATE << OP_PICK;
    result = sm.Eval(testScript);
    BOOST_CHECK_EQUAL(result, false);
    BOOST_CHECK_EQUAL(sm.getError(), SCRIPT_ERR_INVALID_STACK_OPERATION);
    ResetTest(expected, vchStack, sm);
}

BOOST_AUTO_TEST_CASE(script_op_pick_negative_with_flag)
{
    // OP_PICK 0
    std::vector<uint8_t> expected = {9, 7, 5, 3, 1, 1};
    CScript testScript = CScript() << 9 << 7 << 5 << 3 << 1 << 0 << OP_NEGATE << OP_PICK;
    ScriptMachine sm(0 | SCRIPT_NEG_OP_ROLL_OP_PICK, ScriptImportedState(), 0xffffffff, 0xffffffff);
    bool result = sm.Eval(testScript);
    BOOST_CHECK(result);
    std::vector<uint8_t> vchStack = StackToVch(sm.getStack());
    BOOST_CHECK(vchStack == expected);
    ResetTest(expected, vchStack, sm);

    // OP_PICK -1
    expected = {9, 7, 5, 3, 1, 1,};
    testScript = CScript() << 9 << 7 << 5 << 3 << 1 << 1 << OP_NEGATE << OP_PICK;
    result = sm.Eval(testScript);
    BOOST_CHECK(result);
    vchStack = StackToVch(sm.getStack());
    BOOST_CHECK(vchStack == expected);
    ResetTest(expected, vchStack, sm);

    // OP_PICK -2
    expected = {9, 7, 5, 1, 3, 1};
    testScript = CScript() << 9 << 7 << 5 << 3 << 1 << 2 << OP_NEGATE << OP_PICK;
    result = sm.Eval(testScript);
    BOOST_CHECK(result);
    vchStack = StackToVch(sm.getStack());
    BOOST_CHECK(vchStack == expected);
    ResetTest(expected, vchStack, sm);

    // OP_PICK -3
    expected = {9, 7, 1, 5, 3, 1};
    testScript = CScript() << 9 << 7 << 5 << 3 << 1 << 3 << OP_NEGATE << OP_PICK;
    result = sm.Eval(testScript);
    BOOST_CHECK(result);
    vchStack = StackToVch(sm.getStack());
    BOOST_CHECK(vchStack == expected);
    ResetTest(expected, vchStack, sm);

    // OP_PICK -4
    expected = {9, 1, 7, 5, 3, 1};
    testScript = CScript() << 9 << 7 << 5 << 3 << 1 << 4 << OP_NEGATE << OP_PICK;
    result = sm.Eval(testScript);
    BOOST_CHECK(result);
    vchStack = StackToVch(sm.getStack());
    BOOST_CHECK(vchStack == expected);
    ResetTest(expected, vchStack, sm);

    // OP_PICK -5 - equal .size()
    expected = {1, 9, 7, 5, 3, 1};
    testScript = CScript() << 9 << 7 << 5 << 3 << 1 << 5 << OP_NEGATE << OP_PICK;
    result = sm.Eval(testScript);
    BOOST_CHECK(result);
    vchStack = StackToVch(sm.getStack());
    BOOST_CHECK(vchStack == expected);
    ResetTest(expected, vchStack, sm);

    // OP_PICK -6 - > .size()
    testScript = CScript() << 9 << 7 << 5 << 3 << 1 << 6 << OP_NEGATE << OP_PICK;
    result = sm.Eval(testScript);
    BOOST_CHECK_EQUAL(result, false);
    BOOST_CHECK_EQUAL(sm.getError(), SCRIPT_ERR_INVALID_STACK_OPERATION);
    ResetTest(expected, vchStack, sm);
}

BOOST_AUTO_TEST_SUITE_END()
