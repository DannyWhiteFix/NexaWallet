// Copyright (c) 2012-2015 The Bitcoin Core developers
// Copyright (c) 2015-2021 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "coins.h"

#include "consensus/consensus.h"
#include "consensus/validation.h"
#include "memusage.h"
#include "random.h"
#include "undo.h"
#include "util.h"

#include <assert.h>
Coin emptyCoin;
bool CCoinsView::GetCoin(const COutPoint &outpoint, Coin &coin) const { return false; }
bool CCoinsView::HaveCoin(const COutPoint &outpoint) const { return false; }
uint256 CCoinsView::_GetBestBlock() const { return uint256(); }
bool CCoinsView::BatchWrite(CCoinsMap &mapCoins,
    const uint256 &hashBlock,
    const uint64_t nBestCoinHeight,
    size_t &nChildCachedCoinsUsage)
{
    return false;
}
CCoinsViewCursor *CCoinsView::Cursor() const { return nullptr; }
CCoinsViewBacked::CCoinsViewBacked(CCoinsView *viewIn) : base(viewIn) {}
bool CCoinsViewBacked::GetCoin(const COutPoint &outpoint, Coin &coin) const { return base->GetCoin(outpoint, coin); }
bool CCoinsViewBacked::HaveCoin(const COutPoint &outpoint) const { return base->HaveCoin(outpoint); }
uint256 CCoinsViewBacked::_GetBestBlock() const { return base->GetBestBlock(); }
void CCoinsViewBacked::SetBackend(CCoinsView &viewIn) { base = &viewIn; }
bool CCoinsViewBacked::BatchWrite(CCoinsMap &mapCoins,
    const uint256 &hashBlock,
    const uint64_t nBestCoinHeight,
    size_t &nChildCachedCoinsUsage)
{
    return base->BatchWrite(mapCoins, hashBlock, nBestCoinHeight, nChildCachedCoinsUsage);
}
CCoinsViewCursor *CCoinsViewBacked::Cursor() const { return base->Cursor(); }
size_t CCoinsViewBacked::EstimateSize() const { return base->EstimateSize(); }
SaltedOutpointHasher::SaltedOutpointHasher()
    : k0(GetRand(std::numeric_limits<uint64_t>::max())), k1(GetRand(std::numeric_limits<uint64_t>::max()))
{
}

CCoinsViewCache::CCoinsViewCache(CCoinsView *baseIn) : CCoinsViewBacked(baseIn), nBestCoinHeight(0), cachedCoinsUsage(0)
{
}

size_t CCoinsViewCache::DynamicMemoryUsage() const
{
    READLOCK(cs_utxo);
    return memusage::DynamicUsage(cacheCoins) + cachedCoinsUsage;
}
size_t CCoinsViewCache::_DynamicMemoryUsage() const { return memusage::DynamicUsage(cacheCoins) + cachedCoinsUsage; }
size_t CCoinsViewCache::ResetCachedCoinUsage() const
{
    bool drifted = false;
    size_t newCachedCoinsUsage = 0;
    {
        READLOCK(cs_utxo);
        for (CCoinsMap::iterator it = cacheCoins.begin(); it != cacheCoins.end(); it++)
            newCachedCoinsUsage += it->second.coin.DynamicMemoryUsage();
        drifted = (cachedCoinsUsage != newCachedCoinsUsage);
    }
    if (drifted)
    {
        error(
            "Resetting: cachedCoinsUsage has drifted - before %lld after %lld", cachedCoinsUsage, newCachedCoinsUsage);
        cachedCoinsUsage = newCachedCoinsUsage;
    }
    return newCachedCoinsUsage;
}

CCoinsMap::iterator CCoinsViewCache::FetchCoin(const COutPoint &outpoint, CDeferredSharedLocker *lock) const
{
    // When fetching a coin, we only need the shared lock if the coin exists in the cache.
    // So we have the Locker object take the shared lock and return with the read lock held if the coin was in cache.
    {
        if (lock)
            lock->lock_shared();
        CCoinsMap::iterator it = cacheCoins.find(outpoint);
        if (it != cacheCoins.end())
            return it;
        if (lock)
            lock->unlock();
    }
    Coin tmp;
    if (!base->GetCoin(outpoint, tmp))
        return cacheCoins.end();

    // But if the coin is NOT in the cache, we need to grab the exclusive lock in order to modify the cache
    if (lock)
        lock->lock();
    CCoinsMap::iterator ret =
        cacheCoins
            .emplace(std::piecewise_construct, std::forward_as_tuple(outpoint), std::forward_as_tuple(std::move(tmp)))
            .first;
    if (ret->second.coin.IsSpent())
    {
        // The parent only has an empty entry for this outpoint; we can consider our
        // version as fresh.
        ret->second.flags = CCoinsCacheEntry::FRESH;
    }
    cachedCoinsUsage += ret->second.coin.DynamicMemoryUsage();

    if (nBestCoinHeight < ret->second.coin.nHeight)
        nBestCoinHeight = ret->second.coin.nHeight;

    return ret;
}

bool CCoinsViewCache::GetCoin(const COutPoint &outpoint, Coin &coin) const
{
    CDeferredSharedLocker lock(cs_utxo);
    CCoinsMap::const_iterator it = FetchCoin(outpoint, &lock);
    if (it != cacheCoins.end())
    {
        coin = it->second.coin;
        return true;
    }
    return false;
}

bool CCoinsViewCache::GetCoinFromCache(const COutPoint &outpoint, Coin &coin) const
{
    READLOCK(cs_utxo);
    CCoinsMap::iterator it = cacheCoins.find(outpoint);
    if (it != cacheCoins.end())
    {
        coin = it->second.coin;
        return true;
    }
    return false;
}

void CCoinsViewCache::AddCoin(const COutPoint &outpoint, Coin &&coin, bool possible_overwrite)
{
    WRITELOCK(cs_utxo);
    assert(!coin.IsSpent());
    if (coin.out.scriptPubKey.IsUnspendable())
        return;
    CCoinsMap::iterator it;
    bool inserted;
    std::tie(it, inserted) =
        cacheCoins.emplace(std::piecewise_construct, std::forward_as_tuple(outpoint), std::tuple<>());
    bool fresh = false;
    if (!inserted)
    {
        cachedCoinsUsage -= it->second.coin.DynamicMemoryUsage();
    }
    if (!possible_overwrite)
    {
        if (!it->second.coin.IsSpent())
        {
            throw std::logic_error("Adding new coin that replaces non-pruned entry");
        }
        fresh = !(it->second.flags & CCoinsCacheEntry::DIRTY);
    }
    it->second.coin = std::move(coin);
    it->second.flags |= CCoinsCacheEntry::DIRTY | (fresh ? CCoinsCacheEntry::FRESH : 0);
    cachedCoinsUsage += it->second.coin.DynamicMemoryUsage();
    if (nBestCoinHeight < it->second.coin.nHeight)
        nBestCoinHeight = it->second.coin.nHeight;
}

bool CCoinsViewCache::SpendCoin(const COutPoint &outpoint, Coin *moveout)
{
    WRITELOCK(cs_utxo);
    CCoinsMap::iterator it = FetchCoin(outpoint, nullptr);
    if (it == cacheCoins.end())
        return false;
    bool alreadySpent = it->second.coin.IsSpent();
    // LOGA("Spend coin %s: %s", outpoint.GetHex(), alreadySpent ? "but alreadySpent" : "currently unspent");
    cachedCoinsUsage -= it->second.coin.DynamicMemoryUsage();
    if (moveout)
    {
        *moveout = std::move(it->second.coin);
    }
    if (it->second.flags & CCoinsCacheEntry::FRESH)
    {
        cacheCoins.erase(it);
    }
    else
    {
        it->second.flags |= CCoinsCacheEntry::DIRTY;
        it->second.coin.Clear();
    }
    return !alreadySpent;
}

static const Coin coinEmpty;

const Coin &CCoinsViewCache::_AccessCoin(const COutPoint &outpoint) const
{
    AssertLockHeld(cs_utxo);
    CCoinsMap::const_iterator it = FetchCoin(outpoint, nullptr);
    if (it == cacheCoins.end())
    {
        return coinEmpty;
    }
    else
    {
        return it->second.coin;
    }
}

bool CCoinsViewCache::HaveCoin(const COutPoint &outpoint) const
{
    CDeferredSharedLocker lock(cs_utxo);
    CCoinsMap::const_iterator it = FetchCoin(outpoint, &lock);
    return (it != cacheCoins.end() && !it->second.coin.IsSpent());
}

bool CCoinsViewCache::GetCoinFromDB(const COutPoint &outpoint) const
{
    Coin coin;
    if (!base->GetCoin(outpoint, coin))
        return false;

    WRITELOCK(cs_utxo);
    CCoinsMap::iterator ret =
        cacheCoins
            .emplace(std::piecewise_construct, std::forward_as_tuple(outpoint), std::forward_as_tuple(std::move(coin)))
            .first;
    if (ret->second.coin.IsSpent())
    {
        // The parent only has an empty entry for this outpoint; we can consider our
        // version as fresh.
        ret->second.flags = CCoinsCacheEntry::FRESH;
    }
    cachedCoinsUsage += ret->second.coin.DynamicMemoryUsage();

    if (nBestCoinHeight < ret->second.coin.nHeight)
        nBestCoinHeight = ret->second.coin.nHeight;

    return !ret->second.coin.IsSpent();
}

bool CCoinsViewCache::HaveCoinInCache(const COutPoint &outpoint, bool &fSpent) const
{
    READLOCK(cs_utxo);
    CCoinsMap::const_iterator it = cacheCoins.find(outpoint);
    bool fHave = (it != cacheCoins.end());
    if (fHave)
        fSpent = it->second.coin.IsSpent();
    return fHave;
}

uint256 CCoinsViewCache::GetBestBlock() const
{
    READLOCK(cs_utxo);
    if (hashBlock.IsNull())
        hashBlock = base->GetBestBlock();
    return hashBlock;
}

uint256 CCoinsViewCache::_GetBestBlock() const
{
    if (hashBlock.IsNull())
        hashBlock = base->GetBestBlock();
    return hashBlock;
}

void CCoinsViewCache::SetBestBlock(const uint256 &hashBlockIn)
{
    WRITELOCK(cs_utxo);
    hashBlock = hashBlockIn;
}

bool CCoinsViewCache::BatchWrite(CCoinsMap &mapCoins,
    const uint256 &hashBlockIn,
    const uint64_t nBestCoinHeightIn,
    size_t &nChildCachedCoinsUsage)
{
    WRITELOCK(cs_utxo);
    for (CCoinsMap::iterator it = mapCoins.begin(); it != mapCoins.end();)
    {
        if (it->second.flags & CCoinsCacheEntry::DIRTY)
        { // Ignore non-dirty entries (optimization).
            // Update usage of the child cache before we do any swapping and deleting
            nChildCachedCoinsUsage -= it->second.coin.DynamicMemoryUsage();

            CCoinsMap::iterator itUs = cacheCoins.find(it->first);
            if (itUs == cacheCoins.end())
            {
                // The parent cache does not have an entry, while the child does
                // We can ignore it if it's both FRESH and pruned in the child
                if (!(it->second.flags & CCoinsCacheEntry::FRESH && it->second.coin.IsSpent()))
                {
                    // Otherwise we will need to create it in the parent
                    // and move the data up and mark it as dirty
                    CCoinsCacheEntry &entry = cacheCoins[it->first];
                    entry.coin = std::move(it->second.coin);
                    cachedCoinsUsage += entry.coin.DynamicMemoryUsage();
                    entry.flags = CCoinsCacheEntry::DIRTY;
                    // We can mark it FRESH in the parent if it was FRESH in the child
                    // Otherwise it might have just been flushed from the parent's cache
                    // and already exist in the grandparent
                    if (it->second.flags & CCoinsCacheEntry::FRESH)
                        entry.flags |= CCoinsCacheEntry::FRESH;
                }
            }
            else
            {
                // Assert that the child cache entry was not marked FRESH if the
                // parent cache entry has unspent outputs. If this ever happens,
                // it means the FRESH flag was misapplied and there is a logic
                // error in the calling code.
                if ((it->second.flags & CCoinsCacheEntry::FRESH) && !itUs->second.coin.IsSpent())
                    throw std::logic_error(
                        "FRESH flag misapplied to cache entry for base transaction with spendable outputs");

                // Found the entry in the parent cache
                if ((itUs->second.flags & CCoinsCacheEntry::FRESH) && it->second.coin.IsSpent())
                {
                    // The grandparent does not have an entry, and the child is
                    // modified and being pruned. This means we can just delete
                    // it from the parent.
                    cachedCoinsUsage -= itUs->second.coin.DynamicMemoryUsage();
                    cacheCoins.erase(itUs);
                }
                else
                {
                    // A normal modification.
                    cachedCoinsUsage -= itUs->second.coin.DynamicMemoryUsage();
                    itUs->second.coin = std::move(it->second.coin);
                    cachedCoinsUsage += itUs->second.coin.DynamicMemoryUsage();
                    itUs->second.flags |= CCoinsCacheEntry::DIRTY;
                }
            }

            CCoinsMap::iterator itOld = it++;
            mapCoins.erase(itOld);
        }
        else
            it++;
    }
    hashBlock = hashBlockIn;
    if (nBestCoinHeightIn > nBestCoinHeight)
        nBestCoinHeight = nBestCoinHeightIn;

    return true;
}

bool CCoinsViewCache::Flush()
{
    WRITELOCK(cs_utxo);
    bool fOk = base->BatchWrite(cacheCoins, hashBlock, nBestCoinHeight, cachedCoinsUsage);
    return fOk;
}

void CCoinsViewCache::Trim(size_t nTrimSize) const
{
    WRITELOCK(cs_utxo);

    // Trim to keep the cache from growing unbounded.
    uint64_t nTrimmed = 0;
    auto iter = cacheCoins.begin();
    while (_DynamicMemoryUsage() > nTrimSize)
    {
        if (iter == cacheCoins.end())
            break;

        // Only erase entries that have not been modified
        if (iter->second.flags == 0)
        {
            cachedCoinsUsage -= iter->second.coin.DynamicMemoryUsage();

            iter = cacheCoins.erase(iter);
            nTrimmed++;
        }
        else
            iter++;
    }
    if (nTrimmed > 0)
    {
        LOG(COINDB, "Trimmed %ld from the CoinsViewCache, current size after trim: %ld and dynamic usage %ld bytes\n",
            nTrimmed, cacheCoins.size(), _DynamicMemoryUsage());
    }
}

void CCoinsViewCache::Uncache(const COutPoint &hash)
{
    WRITELOCK(cs_utxo);
    CCoinsMap::iterator it = cacheCoins.find(hash);

    // only uncache coins that are not dirty.
    if (it != cacheCoins.end() && it->second.flags == 0)
    {
        cachedCoinsUsage -= it->second.coin.DynamicMemoryUsage();
        cacheCoins.erase(it);
    }
}

void CCoinsViewCache::UncacheTx(const CTransaction &tx)
{
    for (const CTxIn &txin : tx.vin)
        Uncache(txin.prevout);
}

uint64_t CCoinsViewCache::GetCacheSize() const
{
    READLOCK(cs_utxo);
    return cacheCoins.size();
}

CAmount CCoinsViewCache::GetValueIn(const CTransaction &tx) const
{
    READLOCK(cs_utxo);
    if (tx.IsCoinBase())
        return 0;

    CAmount nResult = 0;
    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        if (!tx.vin[i].IsReadOnly())
            nResult += _AccessCoin(tx.vin[i].prevout).out.nValue;
        else // Cache the coin for later use
            _AccessCoin(tx.vin[i].prevout);
    }
    return nResult;
}

bool CCoinsViewCache::HaveInputs(const CTransaction &tx) const
{
    if (!tx.IsCoinBase())
    {
        for (unsigned int i = 0; i < tx.vin.size(); i++)
        {
            if (!HaveCoin(tx.vin[i].prevout))
            {
                return false;
            }
        }
    }
    return true;
}

bool CCoinsViewCache::CheckInputsOfType(const CTransaction &tx, int type, std::vector<int> *missingIndexes) const
{
    bool ret = true;
    if (missingIndexes)
        missingIndexes->clear();
    if (!tx.IsCoinBase())
    {
        for (unsigned int i = 0; i < tx.vin.size(); i++)
        {
            if ((type == -1) || (((int)tx.vin[i].type) == type))
            {
                if (!HaveCoin(tx.vin[i].prevout))
                {
                    ret = false;
                    if (missingIndexes)
                        missingIndexes->push_back(i);
                    else
                        return false; // If missingIndexes is provided, it checks them all
                }
            }
        }
    }
    return ret;
}


double CCoinsViewCache::GetPriority(const CTransaction &tx,
    int nHeight,
    CAmount &inChainInputValue,
    bool &fSpendsCoinbase) const
{
    inChainInputValue = 0;
    if (tx.IsCoinBase())
    {
        fSpendsCoinbase = false;
        return 0.0;
    }

    READLOCK(cs_utxo);
    fSpendsCoinbase = false;
    double dResult = 0.0;
    for (const CTxIn &txin : tx.vin)
    {
        if (!txin.IsReadOnly())
        {
            const Coin &coin = _AccessCoin(txin.prevout);
            if (coin.IsCoinBase())
            {
                fSpendsCoinbase = true;
            }
            if (coin.IsSpent())
                continue;
            if (coin.nHeight <= nHeight)
            {
                dResult += coin.out.nValue * (nHeight - coin.nHeight);
                inChainInputValue += coin.out.nValue;
            }
        }
    }

    return tx.ComputePriority(dResult);
}


CCoinsViewCursor::~CCoinsViewCursor() {}
static const size_t nMaxOutputsPerBlock =
    DEFAULT_LARGEST_TRANSACTION / ::GetSerializeSize(CTxOut(), SER_NETWORK, PROTOCOL_VERSION);

/* API searches for the first unspent output from this tx.  This is a very odd API.  Useless?
CoinAccessor::CoinAccessor(const CCoinsViewCache &view, const uint256 &txid) : cache(&view), lock(cache->csCacheInsert)
{
    EnterCritical("CCoinsViewCache.cs_utxo", __FILE__, __LINE__, (void *)(&cache->cs_utxo), LockType::SHARED_MUTEX,
        OwnershipType::SHARED);
    cache->cs_utxo.lock_shared();
    coin = &emptyCoin;
    int n=0;
    while (n < nMaxOutputsPerBlock)
    {
        COutPoint iter(txid, n);
        const Coin &alternate = view._AccessCoin(iter);
        if (!alternate.IsSpent())
        {
            coin = &alternate;
            return;
        }
        ++iter.n;
    }
}
*/

CoinAccessor::CoinAccessor(const CCoinsViewCache &cacheObj, const COutPoint &output)
    : cache(&cacheObj), lock(cache->csCacheInsert)
{
    EnterCritical("CCoinsViewCache.cs_utxo", __FILE__, __LINE__, (void *)(&cache->cs_utxo), LockType::SHARED_MUTEX,
        OwnershipType::SHARED);
    cache->cs_utxo.lock_shared();
    it = cache->FetchCoin(output, &lock);
    if (it != cache->cacheCoins.end())
        coin = &it->second.coin;
    else
        coin = &emptyCoin;
}

CoinAccessor::~CoinAccessor()
{
    coin = nullptr;
    cache->cs_utxo.unlock_shared();
    LeaveCritical(&cache->cs_utxo);
}


CoinModifier::CoinModifier(const CCoinsViewCache &cacheObj, const COutPoint &output) : cache(&cacheObj)
{
    EnterCritical("CCoinsViewCache.cs_utxo", __FILE__, __LINE__, (void *)(&cache->cs_utxo), LockType::SHARED_MUTEX,
        OwnershipType::EXCLUSIVE);
    cache->cs_utxo.lock();
    it = cache->FetchCoin(output, nullptr);
    if (it != cache->cacheCoins.end())
        coin = &it->second.coin;
    else
        coin = &emptyCoin;
}

CoinModifier::~CoinModifier()
{
    coin = nullptr;
    cache->cs_utxo.unlock();
    LeaveCritical(&cache->cs_utxo);
}

void AddCoins(CCoinsViewCache &cache, const CTransaction &tx, int nHeight)
{
    bool fCoinbase = tx.IsCoinBase();
    const uint256 txidem = tx.GetIdem();
    for (size_t i = 0; i < tx.vout.size(); ++i)
    {
        // Pass fCoinbase as the possible_overwrite flag to AddCoin, in order to correctly
        // deal with the pre-BIP30 occurrances of duplicate coinbase transactions.
        // LOGA("Add coin %s.%d  (%s)", txidem.GetHex(), i, COutPoint(txidem, i).GetHex());
        cache.AddCoin(COutPoint(txidem, i), Coin(tx.vout[i], nHeight, fCoinbase), fCoinbase);
    }
}

bool SpendCoins(const CTransaction &tx, CCoinsViewCache &inputs, CTxUndo &txundo, int nHeight)
{
    // mark inputs spent
    if (!tx.IsCoinBase())
    {
        txundo.vprevout.reserve(tx.vin.size());
        for (const CTxIn &txin : tx.vin)
        {
            if (txin.IsReadOnly())
            {
                txundo.vprevout.emplace_back(); // Provide a placeholder in the undo list
            }
            else
            {
                txundo.vprevout.emplace_back();
                // LOGA("SpendCoins: Spent %s", txin.prevout.GetHex());
                if (!inputs.SpendCoin(txin.prevout, &txundo.vprevout.back()))
                {
                    return false;
                }
            }
        }
    }
    return true;
}

void UpdateCoins(const CTransaction &tx, CCoinsViewCache &inputs, CTxUndo &txundo, int nHeight)
{
    // mark inputs spent
    SpendCoins(tx, inputs, txundo, nHeight);
    // add outputs
    AddCoins(inputs, tx, nHeight);
}

void UpdateCoins(const CTransaction &tx, CCoinsViewCache &inputs, int nHeight)
{
    CTxUndo txundo;
    UpdateCoins(tx, inputs, txundo, nHeight);
}
