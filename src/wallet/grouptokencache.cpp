// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include "wallet/grouptokencache.h"
#include "consensus/grouptokens.h"
#include "main.h"

std::vector<std::string> GetTokenDescription(const CScript &script)
{
    std::vector<std::string> vTokenDesc;

    CScript::const_iterator pc = script.begin();
    opcodetype op;
    std::vector<unsigned char> vchRet;

    // Check we have an op_return
    script.GetOp(pc, op, vchRet);
    if (op != OP_RETURN)
        return {};

    // Check for correct group id
    script.GetOp(pc, op, vchRet);
    uint32_t grpId;
    std::stringstream ss;
    std::reverse(vchRet.begin(), vchRet.end());
    ss << std::hex << HexStr(vchRet);
    ss >> grpId;
    if (grpId != DEFAULT_OP_RETURN_GROUP_ID)
        return {};

    // Get labels
    int count = 0;
    while (script.GetOp(pc, op, vchRet))
    {
        if (op != OP_0)
        {
            if (count != 4)
            {
                if (count == 3)
                {
                    // Convert hash stored as a vector of unsigned chars to a string.
                    uint256 hash(&vchRet.data()[0]);
                    vTokenDesc.push_back(hash.ToString());
                }
                else
                {
                    std::string s(vchRet.begin(), vchRet.end());
                    vTokenDesc.push_back(s);
                }
            }
            else // 5th parameter in op return is the number of decimals
            {
                uint8_t amt;
                if (0 <= op && op <= OP_PUSHDATA4)
                {
                    amt = CScriptNum(vchRet, false, CScriptNum::MAXIMUM_ELEMENT_SIZE_64_BIT).getint64();
                }
                else if (op == 0)
                    amt = 0;
                else
                    amt = op - OP_1 + 1;
                vTokenDesc.push_back(std::to_string(amt));
            }
        }
        else
            vTokenDesc.push_back("");
        count++;
    }

    return vTokenDesc;
}


// Token Description Cache methods
void CTokenDescCache::AddTokenDesc(const CGroupTokenID &_grpID, const std::vector<std::string> &_desc)
{
    // When we add a token description we add it only to the database but not the cache.  We instead
    // add values to the cache when reading from the database, when needed. This way we only fill the in
    // memory cache with values we know are needed for the token wallet.  These values would be pulled
    // into the cache during node startup so there is no real performance loss during normal wallet use.
    LOCK(cs_tokencache);
    ptokenDesc->WriteDesc(_grpID, _desc);
}

const std::vector<std::string> CTokenDescCache::GetTokenDesc(const CGroupTokenID &_grpID)
{
    std::vector<std::string> _desc;

    LOCK(cs_tokencache);
    if (cache.count(_grpID))
    {
        return cache[_grpID];
    }
    else if (ptokenDesc->ReadDesc(_grpID, _desc))
    {
        // Limit the size of cache.  If the cache size is exceeded, which is unlikely, then
        // we don't add any more values to the cache and we rather get descrptions directly
        // from the database.
        if (cache.size() <= nMaxCacheSize)
        {
            cache.emplace(_grpID, _desc);
        }
        return _desc;
    }
    else
    {
        return {};
    }
}

void CTokenDescCache::EraseTokenDesc(const CGroupTokenID &_grpID)
{
    LOCK(cs_tokencache);
    cache.erase(_grpID);
}

void CTokenDescCache::SetSyncFlag(const bool fSet)
{
    LOCK(cs_tokencache);
    ptokenDesc->WriteSyncFlag(fSet);
}

bool CTokenDescCache::GetSyncFlag()
{
    bool fSet = false;
    LOCK(cs_tokencache);
    ptokenDesc->ReadSyncFlag(fSet);

    return fSet;
}

void CTokenDescCache::ProcessTokenDescriptions(CTransactionRef ptx)
{
    for (size_t i = 0; i < ptx->vout.size(); i++)
    {
        const CTxOut &out = ptx->vout[i];
        CGroupTokenInfo tg(out.scriptPubKey);
        if ((tg.associatedGroup != NoGroup) && tg.isAuthority())
        {
            // If we have an authority then we have to check all the outputs again for an OP_RETURN
            for (size_t j = 0; j < ptx->vout.size(); j++)
            {
                if (i == j) // skip the one we already checked in the upper loop
                    continue;

                // find op_return associated with the tx if there is one
                const CTxOut &out2 = ptx->vout[j];
                if (out2.scriptPubKey[0] == OP_RETURN)
                {
                    const auto tokenDesc = GetTokenDescription(out2.scriptPubKey);
                    AddTokenDesc(tg.associatedGroup, tokenDesc);
                    break;
                }
            }

            break;
        }
    }
}

// Token Mint Cache methods
void CTokenMintCache::AddToCache(const CGroupTokenID &_grpID, const CAmount _mint)
{
    AssertLockHeld(cs_tokenmint);

    // Limit the size of cache.  If the cache size is exceeded, which is unlikely, then
    // we erase the first value and add the new one to the cache. This way any items with
    // high cache hits will always be in memory since mintage lookups could become quite
    // common for some type of tokens such as "game itmes" used multiplayer video games.
    while (cache.size() >= nMaxCacheSize)
    {
        // remove a random element
        auto iter = cache.begin();
        std::advance(iter, GetRand(cache.size() - 1));
        cache.erase(iter);
    }
    cache[_grpID] = _mint;
}

void CTokenMintCache::AddTokenMint(const CGroupTokenID &_grpID, const CAmount _mint)
{
    LOCK(cs_tokenmint);
    CAmount nCurrentMint = GetTokenMint(_grpID) + _mint;
    if (nCurrentMint > 0)
    {
        AddToCache(_grpID, nCurrentMint);
        ptokenMint->WriteMint(_grpID, nCurrentMint);
    }
}

void CTokenMintCache::RemoveTokenMint(const CGroupTokenID &_grpID, const CAmount _melt)
{
    LOCK(cs_tokenmint);
    CAmount nCurrentMint = GetTokenMint(_grpID);
    if (nCurrentMint >= _melt)
    {
        nCurrentMint -= _melt;
    }
    else
    {
        DbgAssert(nCurrentMint >= _melt, );
        return;
    }

    AddToCache(_grpID, nCurrentMint);
    ptokenMint->WriteMint(_grpID, nCurrentMint);
}

uint64_t CTokenMintCache::GetTokenMint(const CGroupTokenID &_grpID)
{
    CAmount nMint;

    LOCK(cs_tokenmint);
    if (cache.count(_grpID))
    {
        return cache[_grpID];
    }
    else if (ptokenMint->ReadMint(_grpID, nMint))
    {
        AddToCache(_grpID, nMint);
        return nMint;
    }
    else
    {
        return 0;
    }
}

void CTokenMintCache::AccumulateTokenMintages(CTransactionRef ptx,
    CCoinsViewCache &view,
    std::map<CGroupTokenID, CAmount> &accumulatedMintages)
{
    struct Amounts
    {
        CAmount nTokenInputs = 0;
        CAmount nTokenOutputs = 0;
    };
    std::map<CGroupTokenID, Amounts> mintages;

    // Get the inputs
    for (const CTxIn &txin : ptx->vin)
    {
        Coin coin;
        view.GetCoin(txin.prevout, coin);
        if (!coin.IsSpent())
        {
            const CTxOut &txout = coin.out;
            CGroupTokenInfo tg(txout);
            if (tg.associatedGroup != NoGroup && !tg.isAuthority())
            {
                mintages[tg.associatedGroup].nTokenInputs += tg.quantity;
            }
        }
        else
        {
            DbgAssert(!coin.IsSpent(), );
        }
    }

    // Get the outputs.
    for (size_t i = 0; i < ptx->vout.size(); i++)
    {
        const CTxOut &out = ptx->vout[i];
        CGroupTokenInfo tg(out.scriptPubKey);
        if ((tg.associatedGroup != NoGroup) && !tg.isAuthority())
        {
            mintages[tg.associatedGroup].nTokenOutputs += tg.quantity;
        }
    }

    // If inputs for a group id equals zero and ouputs > 0, then it's a MINT.
    // if intputs > outputs, then it's a MELT.
    for (auto &it : mintages)
    {
        CAmount &nTokenInputs = it.second.nTokenInputs;
        CAmount &nTokenOutputs = it.second.nTokenOutputs;

        // Check for Mint
        if (nTokenInputs == 0 && nTokenOutputs > 0)
        {
            if (!accumulatedMintages.count(it.first))
                accumulatedMintages[it.first] = nTokenOutputs;
            else
                accumulatedMintages[it.first] += nTokenOutputs;
        }

        // Check for Melt
        if (nTokenInputs > nTokenOutputs)
        {
            CAmount nMeltAmount = nTokenInputs - nTokenOutputs;
            if (!accumulatedMintages.count(it.first))
                accumulatedMintages[it.first] = -nMeltAmount;
            else
                accumulatedMintages[it.first] -= nMeltAmount;
        }
    }
}

void CTokenMintCache::ApplyTokenMintages(std::map<CGroupTokenID, CAmount> &accumulatedMintages)
{
    for (auto &it : accumulatedMintages)
    {
        if (it.second > 0)
            AddTokenMint(it.first, it.second);
        else
            RemoveTokenMint(it.first, abs(it.second));
    }
}

void CTokenMintCache::RemoveTokenMintages(std::map<CGroupTokenID, CAmount> &accumulatedMintages)
{
    for (auto &it : accumulatedMintages)
    {
        if (it.second > 0)
            RemoveTokenMint(it.first, it.second);
        else
            AddTokenMint(it.first, abs(it.second));
    }
}

void CTokenMintCache::SetSyncFlag(const bool fSet)
{
    LOCK(cs_tokenmint);
    ptokenDesc->WriteSyncFlag(fSet);
}

bool CTokenMintCache::GetSyncFlag()
{
    bool fSet = false;
    LOCK(cs_tokenmint);
    ptokenDesc->ReadSyncFlag(fSet);

    return fSet;
}
