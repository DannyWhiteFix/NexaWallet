// Copyright (c) 2018 The Bitcoin developers
// Copyright (c) 2018-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "script/sighashtype.h"
#include "test/test_nexa.h"

#include <boost/test/unit_test.hpp>

#include <set>

BOOST_FIXTURE_TEST_SUITE(sighashtype_tests, BasicTestingSetup)


static void CheckSigHashType(SigHashType t,
    bool isDefined,
    bool isAll,
    bool hasNoInputs = false,
    bool hasNoOutputs = false,
    bool hasAnyoneCanPay = false,
    bool has2Outputs = false)
{
    BOOST_CHECK_EQUAL(t.isDefined(), isDefined);
    BOOST_CHECK_EQUAL(t.hasAll(), isAll);
    BOOST_CHECK_EQUAL(t.hasNoInputs(), hasNoInputs);
    BOOST_CHECK_EQUAL(t.hasNoOutputs(), hasNoOutputs);
    BOOST_CHECK_EQUAL(t.hasAnyoneCanPay(), hasAnyoneCanPay);
    if (has2Outputs)
    {
        std::string s = t.ToString();
        BOOST_CHECK(s.find("1_2_OUT") != std::string::npos); // we hard coded the output indexes for this test
    }
}


BOOST_AUTO_TEST_CASE(sighash_construction_test)
{
    // Check default values.
    CheckSigHashType(SigHashType(), true, true);

    // Check all possible permutations.
    // std::set<SigHashType::Input> inpTypes{};

    for (SigHashType::Input inp = SigHashType::Input::ALL; inp <= SigHashType::Input::LAST_VALID; ++inp)
    {
        for (SigHashType::Output out = SigHashType::Output::ALL; out <= SigHashType::Output::LAST_VALID; ++out)
        {
            bool hasNoInputs = false;
            bool hasNoOutputs = false;
            bool anyoneCanPay = false;
            bool has2Outputs = false;
            bool hasAll = false;
            SigHashType t;
            if ((inp == SigHashType::Input::ALL) && (out == SigHashType::Output::ALL))
            {
                t.setAll();
                hasAll = true;
            }
            else
            {
                switch (inp)
                {
                case SigHashType::Input::ALL:
                    break;
                case SigHashType::Input::FIRSTN:
                    t.setFirstNIn(0); // Test the specific 0 inputs case because we have a hasXX api for that
                    hasNoInputs = true;
                    break;
                case SigHashType::Input::THISIN:
                    t.withAnyoneCanPay();
                    anyoneCanPay = true;
                    break;
                }
                switch (out)
                {
                case SigHashType::Output::ALL:
                    break;
                case SigHashType::Output::FIRSTN:
                    t.setFirstNOut(0); // Test the specific 0 outputs case because we have a hasXX api for that
                    hasNoOutputs = true;
                    break;
                case SigHashType::Output::TWO:
                    t.set2Outs(1, 2);
                    has2Outputs = true;
                }
            }
            CheckSigHashType(t, true, hasAll, hasNoInputs, hasNoOutputs, anyoneCanPay, has2Outputs);
        }
    }
}


BOOST_AUTO_TEST_CASE(sighash_serialization_test)
{
    std::vector<unsigned char> v;
    v.reserve(64 + 4);
    for (unsigned int i = 0; i < 256; i++)
    {
        for (unsigned int j = 1; j < 4; j++)
        {
            // create a fake signature and append many different sighashtype combinations
            // we try every sighashtype byte and then append different length sighash data afterwards.
            // since the data has no illegal values (outside of the context of a specific transaction), we just use 0
            v.resize(64 + j);
            v[64] = i;
            for (unsigned int k = 1; k < j; k++)
                v[k] = 0; // fill with dummy values

            SigHashType t(v);

            if (t.isDefined())
            {
                uint8_t up = i >> 4;
                uint8_t lo = i & 0xf;
                BOOST_CHECK(up <= static_cast<uint8_t>(SigHashType::Input::LAST_VALID));
                BOOST_CHECK(lo <= static_cast<uint8_t>(SigHashType::Output::LAST_VALID));

                SigHashType::Input inp = static_cast<SigHashType::Input>(up);
                SigHashType::Output out = static_cast<SigHashType::Output>(lo);
                unsigned int sz = 1; // 1 sighashtype byte
                if (inp == SigHashType::Input::FIRSTN)
                    sz++; // 1 byte, N
                if (out == SigHashType::Output::FIRSTN)
                    sz++; // 1 byte, N
                if (out == SigHashType::Output::TWO)
                    sz += 2; // 2 bytes, A and B
                BOOST_CHECK(j == sz); // Check that any defined sighashtype has the right number of extra bytes
            }
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
