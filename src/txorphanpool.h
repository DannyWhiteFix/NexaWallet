// Copyright (c) 2018 The Bitcoin developers
// Copyright (c) 2018-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_TX_ORPHANPOOL
#define NEXA_TX_ORPHANPOOL

#include "net.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "sync.h"
#include "uint256.h"

#include <map>
#include <set>
#include <stdint.h>

extern CTweak<uint32_t> maxOrphanPool;
extern CTweak<uint32_t> orphanPoolExpiry;

class CTxOrphanPool
{
public:
    // General orphan pool READ/WRITE lock
    CSharedCriticalSection cs_orphanpool;

private:
    //! Used in EraseOrphansByTime() to track when the last time was we checked the cache for anything to delete
    std::atomic<int64_t> nLastOrphanCheck;

public:
    //! Current in memory footprint of all txns in the overall pool of orphans and non-finals
    uint64_t nPoolBytes GUARDED_BY(cs_orphanpool);

    struct COrphanTx
    {
        CTransactionRef ptx;
        NodeId fromPeer;
        int64_t nEntryTime;
        uint64_t nOrphanTxSize;
    };

    // Used for storing and tracking orphans
    std::map<uint256, COrphanTx> mapOrphans GUARDED_BY(cs_orphanpool);
    std::map<uint256, std::set<uint256> > mapOrphansByPrev GUARDED_BY(cs_orphanpool);

    // Used for storing and tracking non-final txns
    std::map<uint256, COrphanTx> mapNonFinals GUARDED_BY(cs_orphanpool);

    // Used for syncronizing post block processing of the orphan pool
    CCriticalSection cs_blockprocessing;
    std::deque<ConstCBlockRef> vPostBlockProcessing GUARDED_BY(cs_blockprocessing);

    CCriticalSection cs_processorphans;
    std::deque<std::vector<CTransactionRef> > vProcessOrphans GUARDED_BY(cs_processorphans);

    CTxOrphanPool();

    //! Do we already have this orphan in the orphan pool
    bool AlreadyHaveOrphan(const uint256 &txid);

    //! Add a transaction to the orphan pool - these can be true orphans or non-final txns.
    bool AddOrphanTx(const CTransactionRef ptx, NodeId peer);
    bool AddNonFinalTx(const CTransactionRef ptx, NodeId peer);

    //! Erase an orphan or non-final tx from the orphan pool
    //! @return true if an orphan matching the hash was found in the orphanpool and successfully erased.
    bool EraseOrphanTx(const uint256 &hash);
    bool EraseNonFinalTx(const uint256 &hash);

    //! Expire old orphans and non-finals from the pool
    void EraseByTime();

    //! Limit the pool size by either number of transactions (items) or max bytes allowed.
    unsigned int LimitPoolSize(unsigned int nMaxItems, uint64_t nMaxBytes);

    //! Return all the transaction hashes for transactions currently in the orphan pool.
    void QueryIds(std::vector<uint256> &vHashes);

    //! Set the last orphan check time (used in testing only)
    void _SetLastOrphanCheck(int64_t nTime)
    {
        AssertLockHeld(cs_orphanpool);
        nLastOrphanCheck = nTime;
    }
    //! Current number of transactions in the pool
    uint64_t GetPoolSize()
    {
        READLOCK(cs_orphanpool);
        return mapOrphans.size() + mapNonFinals.size();
    }

    //! Pool bytes used
    uint64_t GetPoolBytes()
    {
        READLOCK(cs_orphanpool);
        return nPoolBytes;
    }

    //! Remove all orphans and non-finals from the pool that are in this group of transactions
    void RemoveForBlock(const std::vector<CTransactionRef> &vtx);

    //! Clear the pool
    void clear()
    {
        WRITELOCK(cs_orphanpool);
        mapOrphans.clear();
        mapOrphansByPrev.clear();
        mapNonFinals.clear();
        nPoolBytes = 0;
    }

private:
    //! Return all the orphan pool data structures so they can be saved to disk
    std::vector<CTxOrphanPool::COrphanTx> AllTxPoolInfo() const;

public:
    //! Load the orphan pool from disk
    bool LoadOrphanPool();

    //! Save the orphan pool to disk
    bool DumpOrphanPool();
};
extern CTxOrphanPool orphanpool;

uint64_t ProcessOrphans(const std::vector<CTransactionRef> &vWorkQueue);

#endif
