// Copyright (c) 2017 The Bitcoin developers
// Copyright (c) 2017-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "base58.h"  // for bitpay encoding
#include "chainparams.h"
#include "config.h"
#include "dstencode.h"
#include "test/test_nexa.h"

#include <boost/test/unit_test.hpp>

namespace {

class DstCfgDummy : public DummyConfig {
public:
    DstCfgDummy() : useCashAddr(false) {}
    void SetCashAddrEncoding(bool b) override { useCashAddr = b; }
    bool UseCashAddrEncoding() const override { return useCashAddr; }

private:
    bool useCashAddr;
};

} // anon ns

BOOST_FIXTURE_TEST_SUITE(dstencode_tests, BasicTestingSetup)

#if 0  // prints out example addresses with every possible prefix, useful for choosing a new prefix
class CChainParamsPub:public CChainParams
{
public:
    std::vector<uint8_t>* ModPrefix() { return base58Prefixes; }
};

BOOST_AUTO_TEST_CASE(findAprefix)
{
    std::vector<uint8_t> hash = {118, 160, 64,  83,  189, 160, 168,
                                 139, 218, 81,  119, 184, 106, 21,
                                 195, 178, 159, 85,  152, 115};

    const CTxDestination dstKey = CKeyID(uint160(hash));
    const CTxDestination dstScript = CScriptID(uint160(hash));
    const CTxDestination dstTemplate = ScriptTemplateDestination(P2pktOutput(hash));

    CChainParamsPub params = *((CChainParamsPub*) &Params(CBaseChainParams::NEXA));
    DstCfgDummy cfg;

    for (int i=0;i<255;i++)
    {
        printf("%d\n", i);
        params.ModPrefix()[CChainParams::SCRIPT_TEMPLATE_ADDRESS][0] = i;
        cfg.SetCashAddrEncoding(true);
        std::string tmp = EncodeDestination(dstTemplate, params, cfg);
        printf("  %s\n", tmp.c_str());

        cfg.SetCashAddrEncoding(false);
        tmp = EncodeDestination(dstTemplate, params, cfg);
        printf("  %s\n", tmp.c_str());
    }
}
#endif

BOOST_AUTO_TEST_CASE(test_addresses) {
    std::vector<uint8_t> hash = {118, 160, 64,  83,  189, 160, 168,
                                 139, 218, 81,  119, 184, 106, 21,
                                 195, 178, 159, 85,  152, 115};

    const CTxDestination dstKey = CKeyID(uint160(hash));
    const CTxDestination dstScript = CScriptID(uint160(hash));

    std::string cashaddr_pubkey =
        "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a";
    std::string cashaddr_script =
        "bitcoincash:ppm2qsznhks23z7629mms6s4cwef74vcwvn0h829pq";
    std::string base58_pubkey = "1BpEi6DfDAUFd7GtittLSdBeYJvcoaVggu";
    std::string base58_script = "3CWFddi6m4ndiGyKqzYvsFYagqDLPVMTzC";

    {
    const CChainParams &params = Params(CBaseChainParams::LEGACY_UNIT_TESTS);
    DstCfgDummy cfg;

    // Check encoding
    cfg.SetCashAddrEncoding(true);
    BOOST_CHECK_EQUAL(cashaddr_pubkey, EncodeDestination(dstKey, params, cfg));
    BOOST_CHECK_EQUAL(cashaddr_script,
                      EncodeDestination(dstScript, params, cfg));

    cfg.SetCashAddrEncoding(false);
    BOOST_CHECK_EQUAL(base58_pubkey, EncodeDestination(dstKey, params, cfg));
    BOOST_CHECK_EQUAL(base58_script, EncodeDestination(dstScript, params, cfg));

    // Check decoding
    BOOST_CHECK(dstKey == DecodeDestination(cashaddr_pubkey, params));
    BOOST_CHECK(dstScript == DecodeDestination(cashaddr_script, params));
    BOOST_CHECK(dstKey == DecodeDestination(base58_pubkey, params));
    BOOST_CHECK(dstScript == DecodeDestination(base58_script, params));

    // Validation
    BOOST_CHECK(IsValidDestinationString(cashaddr_pubkey, params));
    BOOST_CHECK(IsValidDestinationString(cashaddr_script, params));
    BOOST_CHECK(IsValidDestinationString(base58_pubkey, params));
    BOOST_CHECK(IsValidDestinationString(base58_script, params));
    BOOST_CHECK(!IsValidDestinationString("notvalid", params));

    }

    std::vector<uint8_t> grouphash = {18, 60, 4,  3,  89, 60, 68,
                                  39, 18, 1,  19, 84, 06, 21,
                                  194, 177, 155, 84,  151, 114,
                                  1,2,3,4,5,6,
                                  7,8,9,10,11,12};

        const CChainParams &params = Params(CBaseChainParams::NEXA);
        DstCfgDummy cfg;
        
    {
        const CTxDestination dstTemplate = ScriptTemplateDestination(P2pktOutput(hash));
        printf("Simple pay to pubkey template\n");

        cfg.SetCashAddrEncoding(true);
        std::string tmp = EncodeDestination(dstTemplate, params, cfg);
        printf("  %s\n", tmp.c_str());
        BOOST_CHECK(dstTemplate == DecodeDestination(tmp, params));

        cfg.SetCashAddrEncoding(false);
        tmp = EncodeDestination(dstTemplate, params, cfg);
        printf("  %s\n", tmp.c_str());
        BOOST_CHECK(dstTemplate == DecodeDestination(tmp, params));
    }
    {
        printf("Grouped pay to pubkey template\n");
        const CTxDestination dstTemplate = ScriptTemplateDestination(P2pktOutput(hash, grouphash));

        cfg.SetCashAddrEncoding(true);
        std::string tmp = EncodeDestination(dstTemplate, params, cfg);
        printf("  %s\n", tmp.c_str());
        BOOST_CHECK(dstTemplate == DecodeDestination(tmp, params));

        cfg.SetCashAddrEncoding(false);
        tmp = EncodeDestination(dstTemplate, params, cfg);
        printf("  %s\n", tmp.c_str());
        BOOST_CHECK(dstTemplate == DecodeDestination(tmp, params));
    }

    std::vector<uint8_t> hash2 = {18, 60, 4,  3,  89, 60, 68,
                                      39, 18, 1,  19, 84, 06, 21,
                                      194, 177, 155, 84,  151, 114 };

    {

        const CTxDestination dstTemplate = ScriptTemplateDestination(ScriptTemplateOutput(hash, hash2));

        printf("Pay to contract template with args\n");

        cfg.SetCashAddrEncoding(true);
        std::string tmp = EncodeDestination(dstTemplate, params, cfg);
        printf("  %s\n", tmp.c_str());
        BOOST_CHECK(dstTemplate == DecodeDestination(tmp, params));

        cfg.SetCashAddrEncoding(false);
        tmp = EncodeDestination(dstTemplate, params, cfg);
        printf("  %s\n", tmp.c_str());
        BOOST_CHECK(dstTemplate == DecodeDestination(tmp, params));
    }

    {

        const CTxDestination dstTemplate = ScriptTemplateDestination(ScriptTemplateOutput(hash));

        printf("Pay to contract template with no args\n");

        cfg.SetCashAddrEncoding(true);
        std::string tmp = EncodeDestination(dstTemplate, params, cfg);
        printf("  %s\n", tmp.c_str());
        BOOST_CHECK(dstTemplate == DecodeDestination(tmp, params));

        cfg.SetCashAddrEncoding(false);
        tmp = EncodeDestination(dstTemplate, params, cfg);
        printf("  %s\n", tmp.c_str());
        BOOST_CHECK(dstTemplate == DecodeDestination(tmp, params));
    }

    {
        const CTxDestination dstTemplate = ScriptTemplateDestination(ScriptTemplateOutput(hash, hash2, grouphash));

        printf("Grouped pay to template with args\n");

        cfg.SetCashAddrEncoding(true);
        std::string tmp = EncodeDestination(dstTemplate, params, cfg);
        printf("  %s\n", tmp.c_str());
        auto decode = DecodeDestination(tmp, params);
        BOOST_CHECK(dstTemplate == decode);

        cfg.SetCashAddrEncoding(false);
        tmp = EncodeDestination(dstTemplate, params, cfg);
        printf("  %s\n", tmp.c_str());
        BOOST_CHECK(dstTemplate == DecodeDestination(tmp, params));
    }
}

BOOST_AUTO_TEST_SUITE_END()
