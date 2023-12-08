// Copyright (c) 2016-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef TOKEN_CACHE_H
#define TOKEN_CACHE_H

#include "consensus/grouptokens.h"
#include "sync.h"

static const unsigned int DEFAULT_OP_RETURN_GROUP_ID = 88888888;

// Retrieve token descriptions using an OP_RETURN
std::vector<std::string> GetTokenDescription(const CScript &script);


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

// A cache class for storing token mintages with a finite sized cached.
class CTokenMintCache
{
private:
    mutable CCriticalSection cs_tokenmint;

    /** an in memory cache of blocks */
    std::map<const CGroupTokenID, CAmount> cache GUARDED_BY(cs_tokenmint);

    /** Maximum number of cache elements */
    size_t nMaxCacheSize GUARDED_BY(cs_tokenmint) = 10000;

    /** Add to the in memory cache */
    void AddToCache(const CGroupTokenID &_grpID, const CAmount _mint);

    /** Add a token mintage to the database and cache */
    void AddTokenMint(const CGroupTokenID &_grpID, const CAmount _mint);

    /** Delete a token mintage (melt) from the database and cache */
    void RemoveTokenMint(const CGroupTokenID &_grpID, const CAmount _melt);

public:
    CTokenMintCache(){};

    /** Find and return a token mintage description from the cache */
    uint64_t GetTokenMint(const CGroupTokenID &_grpID);

    /** Find token mintages from new transactions that have arrived either
     *  through txadmission or from new blocks, and save them to apply when
     *  and if the block is confirmed.
     */
    void AccumulateTokenMintages(CTransactionRef ptx,
        CCoinsViewCache &view,
        std::map<CGroupTokenID, CAmount> &accumulatedMintages);

    /** Add the saved token mints and melts, and apply them to the cache and the mintage database */
    void ApplyTokenMintages(std::map<CGroupTokenID, CAmount> &accumulatedMintages);
    /** Remove the saved token mints and melts, and apply them to the cache and the mintage database */
    void RemoveTokenMintages(std::map<CGroupTokenID, CAmount> &accumulatedMintages);
};
extern CTokenMintCache tokenmint;

#endif
