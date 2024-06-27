// Copyright (c) 2012-2015 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "consensus/tx_verify.h"
#include "key.h"
#include "policy/policy.h"
#include "pubkey.h"
#include "script/script.h"
#include "script/sighashtype.h"
#include "script/standard.h"
#include "test/test_nexa.h"
#include "uint256.h"
#include "unlimited.h"

#include <vector>

#include <boost/test/unit_test.hpp>

using namespace std;

// Helpers:
#define _STR(x) #x
#define STR(x) _STR(x)

#define FILE_LINE __FILE__ ":" STR(__LINE__)

static std::vector<unsigned char> Serialize(const CScript &s)
{
    std::vector<unsigned char> sSerialized(s.begin(), s.end());
    return sSerialized;
}

BOOST_FIXTURE_TEST_SUITE(scriptresource_tests, BasicTestingSetup)


void CheckScriptResources(const CScript &script, unsigned int expectedMaxStack, const std::string &errLog)
{
    const uint32_t flags = POST_UPGRADE_MANDATORY_SCRIPT_VERIFY_FLAGS;
    ScriptImportedState sis;
    ScriptMachine sm(flags, sis, std::numeric_limits<unsigned int>::max(), std::numeric_limits<unsigned int>::max());
    sm.maxScriptSize = MAX_SCRIPT_TEMPLATE_SIZE;
    sm.Eval(script);
    BOOST_CHECK(sm.getError() == SCRIPT_ERR_OK);
    auto &stats = sm.getStats();
    std::stringstream expected;
    expected << ".  Got: " << stats.maxStackBytes << " Expected: " << expectedMaxStack;
    BOOST_CHECK_MESSAGE(stats.maxStackBytes == expectedMaxStack, errLog + expected.str());
}

#define CHECK(script, expectedMaxStack) \
    CheckScriptResources(script, expectedMaxStack, std::string("Actual error at: " FILE_LINE))

BOOST_AUTO_TEST_CASE(TestScriptResources)
{
    uint160 dummy;
    const CScript s1 = CScript() << OP_1 << ToByteVector(dummy) << ToByteVector(dummy) << OP_2;
    CHECK(s1, 1 + 20 + 20 + 1);

    // true takes the if side
    const CScript s2 = CScript() << OP_1 << OP_IF << OP_1 << OP_1 << OP_ELSE << OP_1 << OP_1 << OP_1 << OP_ENDIF;
    CHECK(s2, 2);

    // since its false it should take the else side
    const CScript s3 = CScript() << OP_0 << OP_IF << OP_1 << OP_1 << OP_ELSE << OP_1 << OP_1 << OP_1 << OP_ENDIF;
    CHECK(s3, 3);

    // Check all the push opcodes
    for (unsigned int i = 0; i < 70001; i += 250)
    {
        VchType v(i, 0xa5);
        const CScript s = CScript() << v;
        BOOST_CHECK(s.size() > i);
        CHECK(s, i);

        // Check dup and dup2 with large sized pushes
        const CScript sdup = CScript() << v << OP_DUP;
        CHECK(sdup, 2 * i);

        const CScript sdup2 = CScript() << v << OP_DUP << OP_2DUP;
        CHECK(sdup2, 4 * i);
    }

    CScript exec1 = CScript() << OP_DUP << OP_DUP; // just code that extends the stack
    CScript execAlt = CScript() << OP_DUP << OP_TOALTSTACK << OP_DUP; // just code that extends the stack
    CScript execExec = CScript() << OP_9 << OP_9 << OP_2SWAP << OP_1 << OP_0 << OP_EXEC;

    std::vector<std::pair<int, CScript> > tests = {
        {0, CScript() << OP_0 << OP_0}, // OP_0 is actually represented by nothing
        {2, CScript() << OP_2 << OP_1 << OP_DROP}, // Verify high-water mark
        {2, CScript() << OP_2 << OP_1 << OP_DROP << OP_DROP << OP_3},

        {6, CScript() << OP_1 << VchType(4, 0xa5) << OP_OVER}, {9, CScript() << VchType(4, 0xa5) << OP_1 << OP_OVER},

        {20, CScript() << VchType(10, 0xa5) << OP_DUP << OP_CAT}, // Verify CAT (does not change size)

        {5, CScript() << OP_2 << VchType(4, 0xa5) << OP_SWAP}, // Verify swap
        {13, CScript() << OP_2 << VchType(5, 0xa5) << OP_1 << VchType(6, 0xa5) << OP_2SWAP}, // Verify swap2

        // verify altstack is counted.
        {15, CScript() << VchType(5, 0xa5) << OP_DUP << OP_TOALTSTACK << OP_DUP},

        // verify bignum
        // convert the biggest 2 byte number into a bignum squared makes 2 bytes + 1 sign byte
        {3, CScript() << 0xFFFF << OP_BIN2BIGNUM},
        // convert the biggest 2 byte number into a bignum squared makes 4 bytes + 1 sign byte, again makes
        // 8 bytes + 1 sign byte
        //                  2           3             6         5         10        9
        {10, CScript() << 0xFFFF << OP_BIN2BIGNUM << OP_DUP << OP_MUL << OP_DUP << OP_MUL},

        // verify opexec
        {30, CScript() << Serialize(exec1) << VchType(10, 0xa5) << OP_1 << OP_0 << OP_EXEC},
        // verify opexec that uses its own altstack
        {30, CScript() << Serialize(execAlt) << VchType(10, 0xa5) << OP_1 << OP_0 << OP_EXEC},
        // Something on the parent stack is added in
        {31, CScript() << OP_1 << Serialize(exec1) << VchType(10, 0xa5) << OP_1 << OP_0 << OP_EXEC},
        // All 3 OP_9s are extra bytes on parent execution stacks (which count) and the innermost double OP_DUP
        // creates 3 copies of the 10 byte object resulting in 33 bytes.
        {33, CScript() << OP_9 << Serialize(execExec) << VchType(10, 0xa5) << Serialize(exec1) << OP_2 << OP_0
                       << OP_EXEC}};

    for (const auto &t : tests)
    {
        CHECK(t.second, t.first);
    }
}


BOOST_AUTO_TEST_SUITE_END()
