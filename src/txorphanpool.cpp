// Copyright (c) 2018-2022 The Bitcoin Unlimited developers
// Copyright (c) 2018 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "txorphanpool.h"

#include "init.h"
#include "main.h"
#include "timedata.h"
#include "txadmission.h"
#include "util.h"
#include "utiltime.h"

CTxOrphanPool::CTxOrphanPool() : nPoolBytes(0) { nLastOrphanCheck.store(GetTime()); };

bool CTxOrphanPool::AlreadyHaveOrphan(const uint256 &hash)
{
    READLOCK(cs_orphanpool);
    if (mapOrphans.count(hash))
        return true;
    return false;
}

bool CTxOrphanPool::AddOrphanTx(const CTransactionRef ptx, NodeId peer)
{
    AssertWriteLockHeld(cs_orphanpool);

    if (mapOrphans.empty() && mapNonFinals.empty())
        DbgAssert(nPoolBytes == 0, nPoolBytes = 0);

    const uint256 &hash = ptx->GetId();
    if (mapOrphans.count(hash))
        return false;

    // Ignore orphans larger than the largest txn size allowed.
    if (ptx->GetTxSize() > MAX_STANDARD_TX_SIZE)
    {
        LOG(MEMPOOL, "ignoring large orphan tx (size: %u, hash: %s)\n", ptx->GetTxSize(), hash.ToString());
        return false;
    }

    uint64_t nTxMemoryUsed = RecursiveDynamicUsage(*ptx) + sizeof(ptx);
    mapOrphans.emplace(hash, COrphanTx{ptx, peer, GetTime(), nTxMemoryUsed});
    for (const CTxIn &txin : ptx->vin)
        mapOrphansByPrev[txin.prevout.hash].insert(hash);

    nPoolBytes += nTxMemoryUsed;
    LOG(MEMPOOL, "stored orphan tx %s bytes:%ld (mapsz %u prevsz %u), orphan pool bytes:%ld\n", hash.ToString(),
        nTxMemoryUsed, mapOrphans.size(), mapOrphansByPrev.size(), nPoolBytes);
    return true;
}

bool CTxOrphanPool::AddNonFinalTx(const CTransactionRef ptx, NodeId peer)
{
    AssertWriteLockHeld(cs_orphanpool);

    if (mapNonFinals.empty() && mapOrphans.empty())
        DbgAssert(nPoolBytes == 0, nPoolBytes = 0);

    const uint256 &hash = ptx->GetId();
    if (mapNonFinals.count(hash))
        return false;

    // Ignore non-finals larger than the largest txn size allowed.
    if (ptx->GetTxSize() > MAX_STANDARD_TX_SIZE)
    {
        LOG(MEMPOOL, "ignoring large non-final tx (size: %u, hash: %s)\n", ptx->GetTxSize(), hash.ToString());
        return false;
    }

    uint64_t nTxMemoryUsed = RecursiveDynamicUsage(*ptx) + sizeof(ptx);
    mapNonFinals.emplace(hash, COrphanTx{ptx, peer, GetTime(), nTxMemoryUsed});

    nPoolBytes += nTxMemoryUsed;
    LOG(MEMPOOL, "stored non-final tx %s bytes:%ld (mapsz %u), orphan pool bytes:%ld\n", hash.ToString(), nTxMemoryUsed,
        mapNonFinals.size(), nPoolBytes);
    return true;
}

bool CTxOrphanPool::EraseOrphanTx(const uint256 &hash)
{
    AssertWriteLockHeld(cs_orphanpool);

    std::map<uint256, COrphanTx>::iterator it = mapOrphans.find(hash);
    if (it == mapOrphans.end())
        return false;
    for (const CTxIn &txin : it->second.ptx->vin)
    {
        std::map<uint256, std::set<uint256> >::iterator itPrev = mapOrphansByPrev.find(txin.prevout.hash);
        if (itPrev == mapOrphansByPrev.end())
            continue;
        itPrev->second.erase(hash);
        if (itPrev->second.empty())
            mapOrphansByPrev.erase(itPrev);
    }

    nPoolBytes -= it->second.nOrphanTxSize;
    LOG(MEMPOOL, "Erased orphan tx %s of size %ld bytes, orphan pool bytes:%ld\n", it->second.ptx->GetId().ToString(),
        it->second.nOrphanTxSize, nPoolBytes);
    mapOrphans.erase(it);
    return true;
}

bool CTxOrphanPool::EraseNonFinalTx(const uint256 &hash)
{
    AssertWriteLockHeld(cs_orphanpool);

    std::map<uint256, COrphanTx>::iterator it = mapNonFinals.find(hash);
    if (it == mapNonFinals.end())
        return false;

    nPoolBytes -= it->second.nOrphanTxSize;
    LOG(MEMPOOL, "Erased non-final tx %s of size %ld bytes, orphan pool bytes:%ld\n",
        it->second.ptx->GetId().ToString(), it->second.nOrphanTxSize, nPoolBytes);
    mapNonFinals.erase(it);
    return true;
}

void CTxOrphanPool::EraseByTime()
{
    // Because we have to iterate through the entire orphan cache which can be large we don't want to check this
    // every time a tx enters the mempool but just once every 5 minutes is good enough.
    int64_t now = GetTime();
    if (now < nLastOrphanCheck.load() + 5 * 60)
        return;
    nLastOrphanCheck.store(now);

    WRITELOCK(cs_orphanpool);
    int64_t nOrphanTxCutoffTime = 0;
    nOrphanTxCutoffTime = now - orphanPoolExpiry.Value() * 60 * 60;

    // remove orphans
    std::map<uint256, COrphanTx>::iterator iter = mapOrphans.begin();
    while (iter != mapOrphans.end())
    {
        std::map<uint256, COrphanTx>::iterator mi = iter++; // increment to avoid iterator becoming invalid
        int64_t nEntryTime = mi->second.nEntryTime;
        if (nEntryTime < nOrphanTxCutoffTime)
        {
            // Uncache any coins that may exist for orphans that will be erased
            pcoinsTip->UncacheTx(*mi->second.ptx);

            const uint256 &txHash = mi->second.ptx->GetId();
            EraseOrphanTx(txHash);
            LOG(MEMPOOL, "Erased old orphan tx %s of age %d seconds\n", txHash.ToString(), now - nEntryTime);
        }
    }

    // remove non-finals
    std::map<uint256, COrphanTx>::iterator iter2 = mapNonFinals.begin();
    while (iter2 != mapNonFinals.end())
    {
        std::map<uint256, COrphanTx>::iterator mi = iter2++; // increment to avoid iterator becoming invalid
        int64_t nEntryTime = mi->second.nEntryTime;
        if (nEntryTime < nOrphanTxCutoffTime)
        {
            // Uncache any coins that may exist for orphans that will be erased
            pcoinsTip->UncacheTx(*mi->second.ptx);

            const uint256 &txHash = mi->second.ptx->GetId();
            EraseNonFinalTx(txHash);
            LOG(MEMPOOL, "Erased old non-final tx %s of age %d seconds\n", txHash.ToString(), now - nEntryTime);
        }
    }
}

unsigned int CTxOrphanPool::LimitPoolSize(unsigned int nMaxItems, uint64_t nMaxBytes)
{
    AssertWriteLockHeld(cs_orphanpool);

    // Limit the orphan pool size by either number of transactions or the max orphan pool size allowed.
    // Limiting by pool size to 1/10th the size of the maxmempool alone is not enough because the total number
    // of txns in the pool can adversely effect the size of the bloom filter in a get_xthin message.
    unsigned int nEvicted = 0;
    while (mapOrphans.size() > nMaxItems || nPoolBytes > nMaxBytes)
    {
        if (mapOrphans.empty())
            break;

        // Evict a random orphan:
        uint256 randomhash = GetRandHash();
        std::map<uint256, COrphanTx>::iterator it = mapOrphans.lower_bound(randomhash);
        if (it == mapOrphans.end())
            it = mapOrphans.begin();
        if (it == mapOrphans.end())
            break;

        // Uncache any coins that may exist for orphans that will be erased
        pcoinsTip->UncacheTx(*it->second.ptx);

        EraseOrphanTx(it->first);
        ++nEvicted;
    }
    while (mapNonFinals.size() > nMaxItems || nPoolBytes > nMaxBytes)
    {
        if (mapNonFinals.empty())
            break;

        // Evict a random non-final:
        uint256 randomhash = GetRandHash();
        std::map<uint256, COrphanTx>::iterator it = mapNonFinals.lower_bound(randomhash);
        if (it == mapNonFinals.end())
            it = mapNonFinals.begin();
        if (it == mapNonFinals.end())
            break;

        // Uncache any coins that may exist for orphans that will be erased
        pcoinsTip->UncacheTx(*it->second.ptx);

        EraseOrphanTx(it->first);
        ++nEvicted;
    }
    return nEvicted;
}

void CTxOrphanPool::QueryIds(std::vector<uint256> &vHashes)
{
    READLOCK(cs_orphanpool);
    for (auto &it : mapOrphans)
        vHashes.push_back(it.first);
}

void CTxOrphanPool::RemoveForBlock(const std::vector<CTransactionRef> &vtx)
{
    WRITELOCK(cs_orphanpool);
    if (mapOrphans.empty() && mapNonFinals.empty())
        return;

    for (auto &tx : vtx)
    {
        const uint256 &hash = tx->GetId();
        EraseOrphanTx(hash);
        EraseNonFinalTx(hash);
    }
}

std::vector<CTxOrphanPool::COrphanTx> CTxOrphanPool::AllTxPoolInfo() const
{
    AssertLockHeld(orphanpool.cs_orphanpool);
    std::vector<COrphanTx> vInfo;
    vInfo.reserve(mapOrphans.size());
    for (auto &it : mapOrphans)
        vInfo.push_back(it.second);
    for (auto &it : mapNonFinals)
        vInfo.push_back(it.second);

    return vInfo;
}


static const uint64_t ORPHANPOOL_DUMP_VERSION = 1;
bool CTxOrphanPool::LoadOrphanPool()
{
    uint64_t nExpiryTimeout = orphanPoolExpiry.Value() * 60 * 60;
    FILE *fileOrphanpool = fopen((GetDataDir() / "orphanpool.dat").string().c_str(), "rb");
    if (!fileOrphanpool)
    {
        LOGA("Failed to open orphanpool file from disk. Continuing anyway.\n");
        return false;
    }
    CAutoFile file(fileOrphanpool, SER_DISK, CLIENT_VERSION);
    if (file.IsNull())
    {
        LOGA("Failed to open orphanpool file from disk. Continuing anyway.\n");
        return false;
    }

    uint64_t count = 0;
    uint64_t skipped = 0;
    uint64_t nNow = GetTime();

    try
    {
        uint64_t version;
        file >> version;
        if (version != ORPHANPOOL_DUMP_VERSION)
        {
            return false;
        }
        uint64_t num;
        file >> num;
        while (num--)
        {
            CTransaction tx;
            uint64_t nTime;
            file >> tx;
            file >> nTime;

            if (nTime + nExpiryTimeout > nNow)
            {
                CTxInputData txd;
                txd.tx = MakeTransactionRef(tx);
                txd.msgCookie = 0;
                EnqueueTxForAdmission(txd);
                ++count;
            }
            else
            {
                ++skipped;
            }

            if (ShutdownRequested())
                return false;
        }
    }
    catch (const std::exception &e)
    {
        LOGA("Failed to deserialize orphanpool data on disk: %s. Continuing anyway.\n", e.what());
        return false;
    }

    LOGA("Imported orphanpool transactions from disk: %i successes, %i expired\n", count, skipped);
    return true;
}

bool CTxOrphanPool::DumpOrphanPool()
{
    uint64_t start = GetStopwatchMicros();

    std::vector<COrphanTx> vInfo;
    {
        READLOCK(cs_orphanpool);
        vInfo = AllTxPoolInfo();
    }

    uint64_t mid = GetStopwatchMicros();

    try
    {
        FILE *fileOrphanpool = fopen((GetDataDir() / "orphanpool.dat.new").string().c_str(), "wb");
        if (!fileOrphanpool)
        {
            LOGA("Failed to dump orphanpool, failed to open orphanpool file from disk. Continuing anyway.\n");
            return false;
        }

        CAutoFile file(fileOrphanpool, SER_DISK, CLIENT_VERSION);

        uint64_t version = ORPHANPOOL_DUMP_VERSION;
        file << version;

        file << (uint64_t)vInfo.size();
        for (const auto &i : vInfo)
        {
            file << *(i.ptx);
            file << (uint64_t)i.nEntryTime;
        }

        FileCommit(file.Get());
        file.fclose();
        RenameOver(GetDataDir() / "orphanpool.dat.new", GetDataDir() / "orphanpool.dat");
        uint64_t last = GetStopwatchMicros();
        LOGA("Dumped orphanpool: %gs to copy, %gs to dump\n", (mid - start) * 0.000001, (last - mid) * 0.000001);
    }
    catch (const std::exception &e)
    {
        LOGA("Failed to dump orphanpool: %s. Continuing anyway.\n", e.what());
        return false;
    }
    return true;
}
