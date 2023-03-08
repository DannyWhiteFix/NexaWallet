// Copyright (c) 2013-2015 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "consensus/tx_verify.h"
#include "consensus/validation.h"
#include "data/sighash.json.h"
#include "hashwrapper.h"
#include "main.h" // For CheckTransaction
#include "script/interpreter.h"
#include "script/script.h"
#include "script/sighashtype.h"
#include "serialize.h"
#include "streams.h"
#include "test/test_nexa.h"
#include "tweak.h"
#include "util.h"
#include "utilstrencodings.h"
#include "version.h"

#include <iostream>

#include <boost/test/unit_test.hpp>

#include <univalue.h>

extern CTweak<bool> enforceMinTxSize;
extern UniValue read_json(const std::string &jsondata);

class HackSigHashType : public SigHashType
{
public:
    explicit HackSigHashType(uint8_t val) : SigHashType()
    {
        valid = true; // Force bad sighashtypes
        inp = static_cast<SigHashType::Input>((val >> 4) & 255);
        out = static_cast<SigHashType::Output>(val & 255);
    }
};


BOOST_FIXTURE_TEST_SUITE(sighash_tests, BasicTestingSetup)


#if 0 // hard coded test change with new tx format
// Goal: check that SignatureHash generates correct hash
BOOST_AUTO_TEST_CASE(sighash_from_data)
{
    enforceMinTxSize.Set(false);

    UniValue tests = read_json(std::string(json_tests::sighash, json_tests::sighash + sizeof(json_tests::sighash)));
    for (unsigned int idx = 0; idx < tests.size(); idx++)
    {
        UniValue test = tests[idx];
        std::string strTest = test.write();
        if (test.size() < 1) // Allow for extra stuff (useful for comments)
        {
            BOOST_ERROR("Bad test: " << strTest);
            continue;
        }
        if (test.size() == 1)
            continue; // comment

        std::string raw_tx, raw_script, sigHashHex;
        int nIn, nHashType;
        uint256 sh;
        CTransaction tx;
        CScript scriptCode = CScript();

        try
        {
            // deserialize test data
            raw_tx = test[0].get_str();
            raw_script = test[1].get_str();
            nIn = test[2].get_int();
            nHashType = test[3].get_int();
            sigHashHex = test[4].get_str();

            CDataStream stream(ParseHex(raw_tx), SER_NETWORK, PROTOCOL_VERSION);
            stream >> tx;

            CValidationState state;
            BOOST_CHECK_MESSAGE(CheckTransaction(MakeTransactionRef(tx), state), strTest);
            BOOST_CHECK(state.IsValid());

            std::vector<unsigned char> raw = ParseHex(raw_script);
            scriptCode.insert(scriptCode.end(), raw.begin(), raw.end());
        }
        catch (...)
        {
            BOOST_ERROR("Bad test, couldn't deserialize data: " << strTest);
            continue;
        }

        sh = SignatureHash(scriptCode, tx, nIn, nHashType, 0, 0);
        assert(sh != SIGNATURE_HASH_ERROR);
        BOOST_CHECK_MESSAGE(sh.GetHex() == sigHashHex, strTest);
    }

    enforceMinTxSize.Set(true);
}
#endif

BOOST_AUTO_TEST_CASE(sighash_test_fail)
{
    CScript scriptCode = CScript();
    CTransaction tx;
    const int nIn = 1;
    const HackSigHashType sigHashType(6);
    // should fail because nIn point is invalid
    // Note that this basically broken behavior of SignatureHashLegacy()
    uint256 hash = SignatureHash(scriptCode, tx, nIn, sigHashType, 0, 0);
    BOOST_CHECK(hash == SIGNATURE_HASH_ERROR);
}
BOOST_AUTO_TEST_SUITE_END()
