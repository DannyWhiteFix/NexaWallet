// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_SCRIPT_STANDARD_H
#define NEXA_SCRIPT_STANDARD_H

#include "consensus/grouptokens.h"
#include "script/destinations.h"
#include "script/interpreter.h"
#include "script/scripttemplate.h"
#include "streams.h"
#include "uint256.h"

#include <stdint.h>

class CScript;

enum txnouttype
{
    TX_NONSTANDARD,
    // 'standard' transaction types:
    TX_PUBKEY,
    TX_PUBKEYHASH,
    TX_SCRIPTHASH,
    TX_MULTISIG,
    TX_LABELPUBLIC,
    TX_NULL_DATA,
    TX_GRP_PUBKEYHASH,
    TX_GRP_SCRIPTHASH,
    TX_SCRIPT_TEMPLATE
};

const char *GetTxnOutputType(txnouttype t);

bool ExtendedSolver(const CScript &scriptPubKey,
    txnouttype &typeRet,
    std::vector<std::vector<unsigned char> > &vSolutionsRet,
    CGroupTokenInfo &grp);
bool Solver(const CScript &scriptPubKey, txnouttype &typeRet, std::vector<std::vector<unsigned char> > &vSolutionsRet);
bool ExtractDestination(const CScript &scriptPubKey, CTxDestination &addressRet);
bool ExtractDestinationAndType(const CScript &scriptPubKey, CTxDestination &addressRet, txnouttype &whichType);
bool ExtractDestinations(const CScript &scriptPubKey,
    txnouttype &typeRet,
    std::vector<CTxDestination> &addressRet,
    int &nRequiredRet);

const char *GetTxnOutputType(txnouttype t);

CScript GetScriptForDestination(const CTxDestination &dest);
CScript GetScriptForRawPubKey(const CPubKey &pubkey);
CScript GetScriptForMultisig(int nRequired, const std::vector<CPubKey> &keys);
CScript GetScriptLabelPublic(const std::string &labelPublic);


#endif // NEXA_SCRIPT_STANDARD_H
