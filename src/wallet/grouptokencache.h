// Copyright (c) 2016-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef TOKEN_CACHE_H
#define TOKEN_CACHE_H

#include "consensus/grouptokens.h"
#include "dstencode.h"
#include "sync.h"
#include "utilgrouptoken.h"


// Empty description vector
static const unsigned int DESC_ENTRY_SIZE = 10;
static const std::vector<std::string> vDefaultDesc{"", "", "", "", "0", "0", "0", "0", "0", "0"};

// Accumulate token authorities and mintages which can then be apply to their respective caches
// Returns false if the view did not contain the correct coins.  False should never be returned
// if the transaction is valid -- it implies that the tx is a doublespend or spends nonexistent
// inputs.
bool AccumulateTokenData(CTransactionRef ptx,
    CCoinsViewCache &view,
    std::map<CGroupTokenID, CAuth> &accumulatedAuthorities,
    std::map<CGroupTokenID, CAmount> &accumulatedMintages);

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
    CTokenDescCache() { assert(vDefaultDesc.size() == DESC_ENTRY_SIZE); };

    /** Add a token description to the cache */
    void AddTokenDesc(const CGroupTokenID &_grpID, const std::vector<std::string> &_desc);

    /** Find and return a token description from the cache */
    const std::vector<std::string> GetTokenDesc(const CGroupTokenID &_grpID);

    /** Remove a token description from the cache */
    void EraseTokenDesc(const CGroupTokenID &_grpID);

    /** Set the sync flag.
     * This sync flag indicates whether we created the tokendesc db from the genesis block or not.
     */
    void SetSyncFlag(const bool fSet);

    /** Get the sync flag. */
    bool GetSyncFlag();

    /** Find token descriptions from new transactions, that have arrived either
     *  through txadmission or from new blocks, and store them to cache
     */
    CGroupTokenInfo ProcessTokenDescriptions(CTransactionRef ptx);

    /** Apply the accumulated token authories and add them to the cache and database */
    void ApplyTokenAuthorities(std::map<CGroupTokenID, CAuth> &accumulatedAuthoriies);
    /** Remove the accumulated token authories and remove them to the cache and database */
    void RemoveTokenAuthorities(std::map<CGroupTokenID, CAuth> &accumulatedAuthorities);
};
extern CTokenDescCache tokencache;

// A cache class for storing token mintages with a finite sized cached.
class CTokenMintCache
{
private:
    typedef std::pair<uint64_t, std::string> mint_entry;

    mutable CCriticalSection cs_tokenmint;

    /** an in memory cache of blocks */
    std::map<const CGroupTokenID, mint_entry> cache GUARDED_BY(cs_tokenmint);

    /** Maximum number of cache elements */
    size_t nMaxCacheSize GUARDED_BY(cs_tokenmint) = 10000;

    /** Add to the in memory cache */
    void AddToCache(const CGroupTokenID &_grpID, const mint_entry &entry);

    /** Add a token mintage to the database and cache */
    void AddTokenMint(const CGroupTokenID &_grpID, const CAmount _mint);

    /** Delete a token mintage (melt) from the database and cache */
    void RemoveTokenMint(const CGroupTokenID &_grpID, const CAmount _melt);

public:
    CTokenMintCache(){};

    /** Add the genesis info to the mintage database */
    void AddTokenGenesis(const CGroupTokenID &_grpID, const mint_entry &entry);

    /** Find and return a token mintage description from the cache */
    mint_entry GetTokenMint(const CGroupTokenID &_grpID);

    /** Find and return a token genesis pubkey from the cache */
    std::string GetTokenGenesis(const CGroupTokenID &_grpID);

    /** Add the saved token mints and melts, and apply them to the cache and the mintage database */
    void ApplyTokenMintages(std::map<CGroupTokenID, CAmount> &accumulatedMintages);
    /** Remove the saved token mints and melts, and apply them to the cache and the mintage database */
    void RemoveTokenMintages(std::map<CGroupTokenID, CAmount> &accumulatedMintages);

    /** Set the sync flag.
     * This sync flag indicates whether we created the tokendesc db from the genesis block or not.
     */
    void SetSyncFlag(const bool fSet);

    /** Get the sync flag. */
    bool GetSyncFlag();
};
extern CTokenMintCache tokenmint;

// Token info object which gets returned via GETDATA and CNetMessage::TOKENINFO request
class CTokenInfo
{
public:
    std::vector<uint8_t> groupId;
    std::string name;
    std::string ticker;
    std::string url;
    uint256 hash;
    uint32_t decimals;
    std::string genesisAddress;

public:
    CTokenInfo(){};

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(groupId);
        READWRITE(name);
        READWRITE(ticker);
        READWRITE(url);
        READWRITE(hash);
        READWRITE(decimals);
        READWRITE(genesisAddress);
    }
};

#endif
