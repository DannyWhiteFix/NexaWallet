// Copyright (c) 2016 The Bitcoin Core developers
// Copyright (c) 2016-2023 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_WALLET_RPCWALLET_H
#define NEXA_WALLET_RPCWALLET_H

class CRPCTable;

void RegisterWalletRPCCommands(CRPCTable &tableRPC);

/** Sign a message using a wallets private key */
bool SignMessage(const UniValue &params, UniValue &sig, std::string &error);

#endif // NEXA_WALLET_RPCWALLET_H
