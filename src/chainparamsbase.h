// Copyright (c) 2014-2015 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_CHAINPARAMSBASE_H
#define NEXA_CHAINPARAMSBASE_H

#include <string>
#include <vector>

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

    const std::string &DataDir() const { return strDataDir; }
    int RPCPort() const { return nRPCPort; }

protected:
    CBaseChainParams() {}
    int nRPCPort;
    std::string strDataDir;

public:
    CBaseChainParams(const char *dataDir, int rpcPort) : nRPCPort(rpcPort), strDataDir(dataDir) {}
    CBaseChainParams(const std::string &dataDir, int rpcPort) : nRPCPort(rpcPort), strDataDir(dataDir) {}
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
