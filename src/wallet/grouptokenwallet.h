// Copyright (c) 2016-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef TOKEN_GROUP_RPC_H
#define TOKEN_GROUP_RPC_H

#include "chainparams.h"
#include "coins.h"
#include "consensus/grouptokens.h"
#include "consensus/validation.h"
#include "pubkey.h"
#include "script/standard.h"
#include "wallet/wallet.h"

#include <unordered_map>

/** Pass a group and a destination address (or CNoDestination) to get the balance of all outputs in the group
 *  or all outputs in that group and on that destination address.
 */
CAmount GetGroupBalance(const CGroupTokenID &grpID, const CTxDestination &dest, const CWallet *wallet);

//* Returns a mapping of groupID->balance
void GetAllGroupBalances(const CWallet *wallet, std::unordered_map<CGroupTokenID, CAmount> &balances);

//* Send a token
bool GroupSend(CWalletTx &wtxNew,
    const CGroupTokenID &grpID,
    const std::vector<CRecipient> &outputs,
    CAmount totalNeeded,
    CWallet *wallet,
    std::string *strError = nullptr,
    bool fRPC = true);

//* Construct a token transaction
bool ConstructTx(CWalletTx &wtxNew,
    const std::vector<COutput> &chosenCoins,
    const std::vector<CRecipient> &outputs,
    CAmount totalAvailable,
    CAmount totalNeeded,
    CAmount totalGroupedAvailable,
    CAmount totalGroupedNeeded,
    CGroupTokenID grpID,
    CWallet *wallet,
    std::string *strError = nullptr,
    bool fRPC = true);

// Token group helper functions -- not members because they use objects not available in the consensus lib
//* Initialize the group id from an address
CGroupTokenID GetGroupToken(const CTxDestination &id);
//* Initialize a group ID from a string representation
CGroupTokenID GetGroupToken(const std::string &cashAddrGrpId, const CChainParams &params = Params());

CTxDestination ControllingAddress(const CGroupTokenID &grp, txnouttype addrType);

//* Calculate a group ID based on the provided inputs.  Pass and empty script to opRetTokDesc if there is not
// going to be an OP_RETURN output in the transaction.
CGroupTokenID findGroupId(const COutPoint &input,
    CScript opRetTokDesc,
    GroupTokenIdFlags flags,
    GroupAuthorityFlags authorityFlags,
    uint64_t &nonce);

//* Group script helper function
CScript GetScriptForDestination(const CTxDestination &dest, const CGroupTokenID &group, const CAmount &amount);

//* Create and retrieve token descriptions using an OP_RETURN
std::vector<std::vector<unsigned char> > ParseGroupDescParams(const UniValue &params, unsigned int &curparam);
std::vector<std::string> GetTokenDescription(const CScript &script);
CScript BuildTokenDescScript(const std::vector<std::vector<unsigned char> > &desc);

void GetAllGroupDescriptions(const CWallet *wallet,
    std::unordered_map<CGroupTokenID, std::vector<std::string> > &desc,
    const CGroupTokenID &grpID);

// A cache class for storing token descriptions with a finite sized cached.
class CTokenDescCache
{
private:
    mutable CCriticalSection cs_tokencache;

    /** an in memory cache of blocks */
    std::map<const CGroupTokenID, const std::vector<std::string> > cache GUARDED_BY(cs_tokencache);

    /** Maximum number of cache elements */
    size_t nMaxCacheSize GUARDED_BY(cs_tokencache) = 1000;

public:
    CTokenDescCache(){};

    /** Add a token description to the cache */
    void AddTokenDesc(const CGroupTokenID &_grpID, const std::vector<std::string> &_desc);

    /** Find and return a token description from the cache */
    const std::vector<std::string> GetTokenDesc(const CGroupTokenID &_grpID);

    /** Remove a token description from the cache */
    void EraseTokenDesc(const CGroupTokenID &_grpID);

    /** Find token descriptions from new transactions, that have arrived either
     *  through txadmission or from new blocks, and store them to cache
     */
    void ProcessTokenDescriptions(CTransactionRef ptx);
};
extern CTokenDescCache tokencache;

#endif
