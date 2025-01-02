// Copyright (c) 2014-2015 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_CHAINPARAMSBASE_H
#define NEXA_CHAINPARAMSBASE_H

#include <cstdint>
#include <string>
#include <vector>

enum
{
    NEXA_PORT = 7228,
    NEXA_TESTNET_PORT = 7230,
    BTCBCH_DEFAULT_MAINNET_PORT = 8333,
    BTCBCH_TESTNET_PORT = 18333,
    DEFAULT_REGTESTNET_PORT = 18444,
    BTCBCH_TESTNET4_PORT = 28333,
    BTCBCH_SCALENET_PORT = 38333,
};

/**
 * CBaseChainParams defines the base parameters (shared between nexa-cli and nexad)
 * of a given instance of the Nexa system.
 */
class CBaseChainParams
{
public:
    /** BIP70 chain name strings */
    static const std::string LEGACY_UNIT_TESTS;
    static const std::string TESTNET;
    static const std::string SCALENET;
    static const std::string REGTEST;
    static const std::string NEXA;

    enum Base58Type
    {
        PUBKEY_ADDRESS,
        SCRIPT_ADDRESS,
        SECRET_KEY,
        EXT_PUBLIC_KEY,
        EXT_SECRET_KEY,
        SCRIPT_TEMPLATE_ADDRESS,

        MAX_BASE58_TYPES
    };

    const std::string &DataDir() const { return strDataDir; }
    int RPCPort() const { return nRPCPort; }

    int GetDefaultPort() const { return nDefaultPort; }
    uint64_t PruneAfterHeight() const { return nPruneAfterHeight; }
    /** Make miner stop after a block is found. In RPC, don't return until nGenProcLimit blocks are generated */
    bool MineBlocksOnDemand() const { return fMineBlocksOnDemand; }
    /** In the future use NetworkIDString() for RPC fields */
    bool TestnetToBeDeprecatedFieldRPC() const { return fTestnetToBeDeprecatedFieldRPC; }
    /** Return the BIP70 network string (main, test or regtest) */
    std::string NetworkIDString() const { return strNetworkID; }
    const std::vector<uint8_t> &Base58Prefix(Base58Type type) const { return base58Prefixes[type]; }
    const std::string &CashAddrPrefix() const { return cashaddrPrefix; }

    /** Make miner wait to have peers to avoid wasting work */
    bool MiningRequiresPeers() const { return fMiningRequiresPeers; }
    /** Default value for -checkmempool and -checkblockindex argument and checkwallet */
    bool DefaultConsistencyChecks() const { return fDefaultConsistencyChecks; }
    /** Policy: Filter transactions that do not match well-defined patterns */
    bool RequireStandard() const;
    bool SetRequireStandard(bool fAcceptNonStandard);

protected:
    CBaseChainParams() {}
    int nRPCPort;
    std::string strDataDir;

    std::string strNetworkID;
    int nDefaultPort;
    uint64_t nPruneAfterHeight;
    bool fMiningRequiresPeers;
    bool fDefaultConsistencyChecks;
    bool fRequireStandard;
    bool fMineBlocksOnDemand;
    bool fTestnetToBeDeprecatedFieldRPC;
    std::vector<uint8_t> base58Prefixes[MAX_BASE58_TYPES];
    std::string cashaddrPrefix;

public:
    CBaseChainParams(const char *dataDir, int rpcPort) : nRPCPort(rpcPort), strDataDir(dataDir) {}
    CBaseChainParams(const std::string &dataDir, int rpcPort) : nRPCPort(rpcPort), strDataDir(dataDir) {}
};

/**
 * Main network (Fake mainnet)
 */
class CBaseMainParams : public CBaseChainParams
{
public:
    CBaseMainParams()
    {
        nRPCPort = 7227;

        strNetworkID = "main"; // Do not use the const string because of ctor execution order issues
        nDefaultPort = BTCBCH_DEFAULT_MAINNET_PORT;
        nPruneAfterHeight = 100000;
        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = false;
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 0);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 5);
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 128);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};
        cashaddrPrefix = "bitcoincash";
    }
};

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

        strNetworkID = "testnet"; // Do not use the const string because of ctor execution order issues
        nDefaultPort = NEXA_TESTNET_PORT;
        nPruneAfterHeight = 100000;
        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<uint8_t>(1, 111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<uint8_t>(1, 196);
        base58Prefixes[SECRET_KEY] = std::vector<uint8_t>(1, 239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};
        base58Prefixes[SCRIPT_TEMPLATE_ADDRESS] = std::vector<unsigned char>(1, 8);
        cashaddrPrefix = "nexatest";
    }
};

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

        strNetworkID = "regtest"; // Do not use the const string because of ctor execution order issues
        nDefaultPort = DEFAULT_REGTESTNET_PORT;
        nPruneAfterHeight = 1000;
        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<uint8_t>(1, 111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<uint8_t>(1, 196);
        base58Prefixes[SECRET_KEY] = std::vector<uint8_t>(1, 239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};
        base58Prefixes[SCRIPT_TEMPLATE_ADDRESS] = std::vector<unsigned char>(1, 8);
        cashaddrPrefix = "nexareg";
    }
};

/**
 * Nexa
 */
class CBaseNexaParams : public CBaseChainParams
{
public:
    CBaseNexaParams()
    {
        nRPCPort = 7227;

        strNetworkID = "nexa"; // Do not use the const string because of ctor execution order issues
        nDefaultPort = NEXA_PORT;
        nPruneAfterHeight = 100000;
        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = false;
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 25); // P2PKH addresses begin with B
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 68); // P2SH  addresses begin with U
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 35); // WIF   format begins with 2B or 2C
        base58Prefixes[EXT_PUBLIC_KEY] = {0x42, 0x69, 0x67, 0x20};
        base58Prefixes[EXT_SECRET_KEY] = {0x42, 0x6c, 0x6b, 0x73};
        // use 8 for prefix of N in base58
        // 19 for n in bech32
        base58Prefixes[SCRIPT_TEMPLATE_ADDRESS] = std::vector<unsigned char>(1, 8);
        cashaddrPrefix = strNetworkID;
    }
};

/**
 * Return the currently selected parameters. This won't change after app
 * startup, except for unit tests.
 */
const CBaseChainParams &BaseParams();

CBaseChainParams &BaseParams(const std::string &chain);

/** Sets the params returned by Params() to those for the given network. */
void SelectBaseParams(const std::string &chain);

/**
 * Looks for -regtest, -testnet and returns the appropriate BIP70 chain name.
 * @return CBaseChainParams::MAX_NETWORK_TYPES if an invalid combination is given. CBaseChainParams::NEXA by
 * default.
 */
std::string ChainNameFromCommandLine();

/**
 * Return true if SelectBaseParamsFromCommandLine() has been called to select
 * a network.
 */
bool AreBaseParamsConfigured();

#endif // NEXA_CHAINPARAMSBASE_H
