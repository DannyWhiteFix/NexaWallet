// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparamsbase.h"

#include "tinyformat.h"
#include "util.h"

#include <assert.h>

const std::string CBaseChainParams::LEGACY_UNIT_TESTS = "main";
const std::string CBaseChainParams::TESTNET = "test";
const std::string CBaseChainParams::SCALENET = "scale";
const std::string CBaseChainParams::REGTEST = "regtest";
const std::string CBaseChainParams::NEXA = "nexa";

/**
 * Main network
 */
class CBaseMainParams : public CBaseChainParams
{
public:
    CBaseMainParams() { nRPCPort = 7227; }
};
static CBaseMainParams mainParams;


/**
 * Testnet (v3)
 */
class CBaseTestNetParams : public CBaseChainParams
{
public:
    CBaseTestNetParams()
    {
        nRPCPort = 7229;
        strDataDir = "testnet";
    }
};
static CBaseTestNetParams testNetParams;


/**
 * Scaling Network
 */
class CBaseScaleNetParams : public CBaseChainParams
{
public:
    CBaseScaleNetParams()
    {
        nRPCPort = 38332;
        strDataDir = "scalenet";
    }
};
static CBaseScaleNetParams scaleNetParams;

/*
 * Regression test
 */
class CBaseRegTestParams : public CBaseChainParams
{
public:
    CBaseRegTestParams()
    {
        nRPCPort = 18332;
        strDataDir = "regtest";
    }
};
static CBaseRegTestParams regTestParams;

/**
 * Nexa
 */
class CBaseNexaParams : public CBaseChainParams
{
public:
    CBaseNexaParams() { nRPCPort = 7227; }
};
static CBaseNexaParams nexaParams;

static CBaseChainParams *pCurrentBaseParams = 0;

const CBaseChainParams &BaseParams()
{
    assert(pCurrentBaseParams);
    return *pCurrentBaseParams;
}

CBaseChainParams &BaseParams(const std::string &chain)
{
    if (chain == CBaseChainParams::LEGACY_UNIT_TESTS)
        return mainParams;
    else if (chain == CBaseChainParams::TESTNET)
        return testNetParams;
    else if (chain == CBaseChainParams::SCALENET)
        return scaleNetParams;
    else if (chain == CBaseChainParams::REGTEST)
        return regTestParams;
    else if (chain == CBaseChainParams::NEXA)
        return nexaParams;
    else
        throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectBaseParams(const std::string &chain) { pCurrentBaseParams = &BaseParams(chain); }
std::string ChainNameFromCommandLine()
{
    uint64_t num_selected = 0;
    bool fRegTest = GetBoolArg("-regtest", false);
    num_selected += fRegTest;
    bool fTestNet = GetBoolArg("-testnet", false);
    num_selected += fTestNet;
    bool fScaleNet = GetBoolArg("-scalenet", false);
    num_selected += fScaleNet;
    bool fNexa = GetBoolArg("-nexa", false);
    num_selected += fNexa;

    if (num_selected > 1)
        throw std::runtime_error("Invalid combination of -regtest, -testnet, -scalenet");
    if (fRegTest)
        return CBaseChainParams::REGTEST;
    if (fTestNet)
        return CBaseChainParams::TESTNET;
    if (fScaleNet)
        return CBaseChainParams::SCALENET;
    if (fNexa)
        return CBaseChainParams::NEXA;

    // default on this branch is nexa
    return CBaseChainParams::NEXA;
}

bool AreBaseParamsConfigured() { return pCurrentBaseParams != nullptr; }
