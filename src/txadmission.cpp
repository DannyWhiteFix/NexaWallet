// Copyright (c) 2018-2023 The Bitcoin Unlimited developers
// Copyright (C) 2019-2020 Tom Zander <tomz@freedommail.ch>
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "txadmission.h"
#include "blockstorage/blockstorage.h"
#include "connmgr.h"
#include "consensus/tx_verify.h"
#include "core_io.h"
#include "dosman.h"
#include "fastfilter.h"
#include "init.h"
#include "main.h"
#include "net.h"
#include "policy/mempool.h"
#include "requestManager.h"
#include "respend/dsproof.h"
#include "respend/dsproofstorage.h"
#include "respend/respenddetector.h"
#include "threadgroup.h"
#include "timedata.h"
#include "txadmission.h"
#include "txmempool.h"
#include "txorphanpool.h"
#include "unlimited.h"
#include "util.h"
#include "utiltime.h"
#include "validation/dag.h"
#include "validation/forks.h"
#include "validation/tailstorm.h"
#include "validation/validation.h"
#include "validationinterface.h"

// The group token cache can and should be compiled even when the wallet is disabled.
#include "wallet/grouptokencache.h"

#ifdef ENABLE_WALLET
#include "wallet/grouptokenwallet.h"
#include "wallet/wallet.h"
#endif

#include <boost/algorithm/string/case_conv.hpp>
#include <boost/thread/thread.hpp>
#include <map>
#include <mutex>
#include <string>
#include <vector>

extern CTweak<uint32_t> minRelayFee;
extern CTweak<uint32_t> limitFreeRelay;

extern bool fRelayPriority;
extern CRollingFastFilter<32 * 1024 * 1024> filterTransactionKnown; // guarded by cs_txKnown

using namespace std;

static void TestConflictEnqueueTx(CTxInputData &txd, bool fOrphan = false);

// The average commit batch size is used to limit the quantity of transactions that are moved from the defer queue
// onto the inqueue.  Without this, if received transactions far outstrip processing capacity, transactions can be
// shuffled between the in queue and the defer queue with little progress being made.
const uint64_t minCommitBatchSize = 10000;

// avgCommitBatchSize is write protected by cs_CommitQ and is wrapped in std::atomic for reads.
std::atomic<uint64_t> avgCommitBatchSize(0);

#ifdef ENABLE_WALLET
// Post block processing for syncing with wallets
CCriticalSection cs_walletprocessing;
std::deque<CSyncWithWallets> vPostBlockProcessing GUARDED_BY(cs_walletprocessing);
#endif

void ThreadCommitToMempool();

CTransactionRef CommitQGet(const uint256 hash)
{
    // search by transaction id
    LOCK(cs_commitQ);
    auto it = txCommitQ->find(hash);
    if (it == txCommitQ->end())
        return nullptr;
    return it->entry.GetSharedTx();
}

std::vector<CTransactionRef> CommitQGet(const uint64_t cheaphash)
{
    std::vector<CTransactionRef> vTx;

    LOCK(cs_commitQ);
    auto values = txCommitQ->get<txid_shortid>().equal_range(cheaphash);
    while (values.first != values.second)
    {
        vTx.push_back(values.first->entry.GetSharedTx());
        values.first++;
    }
    return vTx;
}

void InitTxAdmission()
{
    if (txCommitQ == nullptr)
        txCommitQ = new CIndexedCommitQ();
}

void StartTxAdmissionThreads()
{
    // Start incoming transaction processing threads
    for (unsigned int i = 0; i < numTxAdmissionThreads.Value(); i++)
    {
        threadGroup.create_thread(&ThreadTxAdmission);
    }

    // Start tx commitment thread
    threadGroup.create_thread(&ThreadCommitToMempool);

    // Start mempool transaction rate statistics processing thread
    threadGroup.create_thread(&ThreadUpdateTransactionRateStatistics);
}

void StopTxAdmission()
{
    cvTxInQ.notify_all();
    cvCommitQ.notify_all();
}

void FlushTxAdmission()
{
    bool empty = false;
    int64_t nStart = GetTime();
    uint64_t nLastOrphanQSize = 0;
    while (!empty)
    {
        CORRAL(txProcessingCorral, CORRAL_TX_PAUSE);
        {
            // Block everything and check if queues are empty and if not
            // then continue processing until they are or we hit the timeout.
            LOCK(csTxInQ);
            empty = txInQ.empty() && txDeferQ.empty();
            if (empty && txOrphanQ.empty())
                break;

            nLastOrphanQSize = txOrphanQ.size();
        }

        // Commit to mempool again. There may be orphans that need processing
        // and the commitQ and txDeferQ may still have entries.
        CommitTxToMempool(CORRAL_TX_PAUSE);

        // The orphan pool may never clear out if there are true orphans present, so break
        // from this loop if there is no progress in clearing them out.
        //
        // Also break from the loop if the timeout is reached. It could happen under high tps that
        // the txInQ is never empty or rather keeps getting entries added just as we release the CORRAL
        // on the next iteration of this loop; and we can't just hold the CORRAL the entire time through
        // this loop because we need to allow the orphans to get processed to get into the txpool.
        LOCK(csTxInQ);
        if ((empty && txOrphanQ.empty()) || (empty && nLastOrphanQSize == txOrphanQ.size()) || GetTime() - nStart > 10)
            break;
    }
}

// Put the tx on the tx admission queue for processing
void EnqueueTxForAdmission(CTxInputData &txd, bool fOrphan)
{
    LOCK(csTxInQ);

    // Otherwise go ahead and put them on the queue
    TestConflictEnqueueTx(txd, fOrphan);
}

static void TestConflictEnqueueTx(CTxInputData &txd, bool fOrphan)
{
    AssertLockHeld(csTxInQ);

    bool conflict = false;
    for (auto &inp : txd.tx->vin)
    {
        // Read only inputs cannot conflict with existing tx because they are valid in a block that contains a
        // tx spending the read only input
        if (inp.IsReadOnly())
            continue;

        if (!incomingConflicts.checkAndSet(inp.prevout.hash))
        {
            conflict = true;
            break;
        }
    }

    // If there is no conflict then the transaction is ready for validation and can be placed in the processing
    // queue. However, if there is a conflict then this could be a double spend, so defer the transaction until the
    // transaction it conflicts with has been fully processed.
    if (!conflict)
    {
        // Add this transaction onto the processing queue.  Orphans are added to a separate
        // queue so they can be processed first. This way as other txns that arrive and depend
        // on this orphan will not cause the orphan pool to get filled up further.
        if (fOrphan)
        {
            txOrphanQ.push(txd);
        }
        else
        {
            txInQ.push(txd);
        }
        cvTxInQ.notify_one();
        // LOG(MEMPOOL, "Enqueue for processing %x\n", txd.tx->GetId().ToString());
    }
    else
    {
        LOG(MEMPOOL, "Fastfilter collision, deferred %x\n", txd.tx->GetId().ToString());
        txDeferQ.push(txd);

        // By notifying the commitQ, the deferred queue can be processed right way which helps
        // to forward double spends as quickly as possible.
        cvCommitQ.notify_one();
    }
}

unsigned int TxAlreadyHave(const CInv &inv) { return TxAlreadyHave(inv.type, inv.hash); }
unsigned int TxAlreadyHave(const int type, const uint256 &hash)
{
    switch (type)
    {
    case MSG_TX:
    {
        if (txRecentlyInBlock.contains(hash))
            return 1;
        if (recentRejects.contains(hash))
            return 2;

        {
            LOCK(cs_commitQ);
            const auto &elem = txCommitQ->find(hash);
            if (elem != txCommitQ->end())
            {
                return 3;
            }
        }
        if (mempool.exists(hash))
            return 4;
        if (orphanpool.AlreadyHaveOrphan(hash))
            return 5;

        return 0;
    }
    case MSG_DOUBLESPENDPROOF:
        return mempool.doubleSpendProofStorage()->exists(hash) ||
               mempool.doubleSpendProofStorage()->isRecentlyRejectedProof(hash);
    }
    DbgAssert(0, return false); // this fn should only be called if CInv is a tx
}
unsigned int TxMayAlreadyHave(const int type, const uint256 &hash)
{
    // AlreadyHaveTx() is a large source of lock contention when the system is under load.  This lock contention
    // is coming from the several different locks that may need to be aquired to confim that we have the tx already.
    // To get around this lock contention we can track transactions already seen in a filter which can be queried
    // and since in "almost all" cases we would not have seen this transaction yet, we can return right away and
    // only rarely have to take any locks on the commit queue, mempool and or the orphanpool.
    bool fMaybeHaveTx = false;
    {
        if (filterTransactionKnown.contains(hash))
            fMaybeHaveTx = true;
    }
    if (fMaybeHaveTx)
    {
        return TxAlreadyHave(type, hash);
    }

    return 0;
}

void ThreadCommitToMempool()
{
    while (shutdown_threads.load() == false)
    {
        {
            nexa_unique_lock<nexa_mutex> lock(cs_CommitQCondVar);
            do
            {
                cvCommitQ.wait_for(lock, nexa_time::milliseconds(2000));
                if (shutdown_threads.load() == true)
                {
                    return;
                }

#ifdef ENABLE_WALLET
                // If a block was just received then break from this loop and
                // commit transactions right away so we can process for transactions
                {
                    LOCK(cs_walletprocessing);
                    if (!vPostBlockProcessing.empty())
                    {
                        break;
                    }
                }
#else
                // If a block was just received then break from this loop and
                // commit transactions right away so we can process for orphans
                {
                    LOCK(orphanpool.cs_blockprocessing);
                    if (!orphanpool.vPostBlockProcessing.empty())
                    {
                        break;
                    }
                }
#endif
                {
                    LOCK(orphanpool.cs_processorphans);
                    if (!orphanpool.vProcessOrphans.empty())
                    {
                        break;
                    }
                }
            } while (txCommitQ->empty() && txDeferQ.empty());
        }

        {
            if (shutdown_threads.load() == true)
            {
                return;
            }

            // Commit the transactions to the txpool and then release the Corral before going through
            // the final processes of checking txpool size and flushing any coins if needed. We can
            // also do any other final checks outside of the Corral.
            {
                CommitTxToMempool(CORRAL_TX_COMMITMENT);
            }

            LOG(MEMPOOL, "MemoryPool sz %u txn, %u kB\n", mempool.size(), mempool.DynamicMemoryUsage() / 1000);
            LimitMempoolSize(mempool, maxTxPool.Value() * ONE_MEGABYTE, txPoolExpiry.Value() * 60 * 60);

            // The flush to disk above is only periodic therefore we need to check if we need to trim
            // any excess from the cache.
            if (pcoinsTip->DynamicMemoryUsage() > (size_t)nCoinCacheMaxSize)
                pcoinsTip->Trim(nCoinCacheMaxSize * .95);
        }
    }
}

void LimitMempoolSize(CTxMemPool &pool, size_t limit, unsigned long age)
{
    std::vector<COutPoint> vCoinsToUncache;
    int expired = pool.Expire(GetTime() - age, vCoinsToUncache);
    for (const COutPoint &txin : vCoinsToUncache)
        pcoinsTip->Uncache(txin);
    if (expired != 0)
        LOG(MEMPOOL, "Expired %i transactions from the memory pool\n", expired);

    std::vector<COutPoint> vNoSpendsRemaining;
    pool.TrimToSize(limit, &vNoSpendsRemaining, false);
    for (const COutPoint &removed : vNoSpendsRemaining)
        pcoinsTip->Uncache(removed);
}

void CommitTxToMempool(int nCorral)
{
    // Now process the transactions that are currently in the commitQ and need to be
    // synced with the wallet. This is the only time we need to hold the Corral
    // so that we don't interfere with any blocks that may be processing at the same
    // time.
    {
        CORRAL(txProcessingCorral, nCorral);
        _CommitTxToMempool();

        // NOTE: In -regtest consistency checking is on by default and this markedly affects performance,
        //       particuarly when loading a great deal of orphan transactions. If doing any performance testing
        //       on -regest remember to turn off consistency checking for the mempool and blockindex.
        mempool.check(pcoinsTip);
    }

#ifdef ENABLE_WALLET
    // Sync transactions with the wallet.  These could be from a newly arrived block
    // a disconnect/rollback or from transactions arriving in the txpool.
    while (true)
    {
        CSyncWithWallets syncwallet;
        {
            LOCK(cs_walletprocessing);
            if (vPostBlockProcessing.empty())
                break;
            syncwallet = vPostBlockProcessing.front();
            vPostBlockProcessing.pop_front();
        }

        // Process conflicts first, if any
        if (syncwallet.ptxConflicted != nullptr && !syncwallet.ptxConflicted->empty())
        {
            int64_t nStart = GetStopwatchMicros();
            for (CTransactionRef &ptx : *syncwallet.ptxConflicted)
            {
                SyncWithWallets(ptx, nullptr, -1);
            }
            int64_t nEnd = GetStopwatchMicros();
            LOG(BENCH, "Sync with wallets - processed Conflicted Txns in: %.2fms\n", (nEnd - nStart) * 0.001);
        }

        // ...then the block
        if (syncwallet.pblock != nullptr)
        {
            int64_t nStart = GetStopwatchMicros();
            int txIdx = 0;
            for (const auto &ptx : syncwallet.pblock->vtx)
            {
                if (!syncwallet.fSetIndex)
                {
                    SyncWithWallets(ptx, nullptr, -1);
                }
                else
                {
                    SyncWithWallets(ptx, syncwallet.pblock, txIdx);
                    txIdx++;
                }
            }
            int64_t nEnd = GetStopwatchMicros();
            LOG(BENCH, "Sync with wallets - processed block: %s in: %.2fms\n", syncwallet.pblock->GetHash().ToString(),
                (nEnd - nStart) * 0.001);
        }
    }
#endif

    // Process orphanpool for any recently connected blocks
    while (true)
    {
        ConstCBlockRef pblock;
        {
            LOCK(orphanpool.cs_blockprocessing);
            if (orphanpool.vPostBlockProcessing.empty())
                break;
            pblock = std::move(orphanpool.vPostBlockProcessing.front());
            orphanpool.vPostBlockProcessing.pop_front();
        }
        int64_t nStart = GetStopwatchMicros();
        orphanpool.RemoveForBlock(pblock->vtx);
        ProcessOrphans(pblock->vtx);
        int64_t nEnd = GetStopwatchMicros();
        LOG(BENCH, "Processed block %s for orphans in: %.2fms\n", pblock->GetHash().ToString(),
            (nEnd - nStart) * 0.001);
    }

    // Process orphans for any recent transactions added to the txpool
    while (true)
    {
        std::vector<CTransactionRef> vWhatChanged;
        {
            LOCK(orphanpool.cs_processorphans);
            if (orphanpool.vProcessOrphans.empty())
                break;
            vWhatChanged = std::move(orphanpool.vProcessOrphans.front());
            orphanpool.vProcessOrphans.pop_front();
        }

        ProcessOrphans(vWhatChanged);
    }
}
void _CommitTxToMempool()
{
    // Committing the tx to the mempool takes time.  We can continue to validate non-conflicting tx during this time.
    // To do so, before the transactions are finally commited to the mempool the txCommitQ pointer is copied
    // to txCommitQFinal so that the lock on txCommitQ can be released and processing can continue.
    // However, the incomingConflicts detector is not reset until all the transactions are committed to the mempool.
    CIndexedCommitQ *txCommitQFinal = nullptr;

    {
        std::vector<CTransactionRef> vWhatChanged;

        // We must hold the mempool lock for the duration because we want to be sure that we don't end up
        // doing this loop in the middle of a reorg where we might be clearing the mempool.
        WRITELOCK(mempool.cs_txmempool);

        {
            LOCK(cs_commitQ);
            avgCommitBatchSize = (avgCommitBatchSize * 24 + txCommitQ->size()) / 25;
            txCommitQFinal = txCommitQ;
            txCommitQ = new CIndexedCommitQ();
        }

        // These transactions have already been validated so store them directly into the mempool.
        // And store them in the order they were received.
        auto it = txCommitQFinal->get<entry_time>().begin();
        while (it != txCommitQFinal->get<entry_time>().end())
        {
            mempool._addUnchecked(it->entry, !IsInitialBlockDownload());
            vWhatChanged.push_back(it->entry.GetSharedTx());
            it++;
        }

        LOCK(orphanpool.cs_processorphans);
        orphanpool.vProcessOrphans.push_back(std::move(vWhatChanged));
    }

#ifdef ENABLE_WALLET
    // ... and finally do the commit Q.  This way new transactions that enter the mempool
    // and which depend on those in any recent block will be added with a later timestamp.
    auto it = txCommitQFinal->get<entry_time>().begin();
    while (it != txCommitQFinal->get<entry_time>().end())
    {
        SyncWithWallets(it->entry.GetSharedTx(), nullptr, -1);
        it++;
    }
#endif
    txCommitQFinal->clear();
    delete txCommitQFinal;

    // Process the defer queue and retest for incoming conflicts if necessary
    {
        LOCK(csTxInQ);
        // Clear the filter of incoming conflicts, and put all queued tx on the deferred queue since
        // they've been deferred
        incomingConflicts.reset();
        // LOG(MEMPOOL, "txadmission incoming filter reset.  Current txInQ size: %ld. Current txOrphanQ size: %ld\n",
        //    txInQ.size(), txOrphanQ.size());

        // Swap out all the queues into temporaries and then process them in order of txDeferQ, txOrphanQ and
        // then txInQ.
        std::queue<CTxInputData> temp_txDeferQ;
        std::queue<CTxInputData> temp_txOrphanQ;
        std::queue<CTxInputData> temp_txInQ;

        std::swap(txDeferQ, temp_txDeferQ);
        std::swap(txOrphanQ, temp_txOrphanQ);
        std::swap(txInQ, temp_txInQ);

        // Special Case: We MUST push the first item in the defer queue to the input queue without checking it
        // against incoming conflicts.  This is fine because the first insert into an empty incomingConflicts must
        // succeed. A transaction's inputs could cause a false positive match against each other.  By pushing the first
        // deferred tx without checking, we can still use the efficient fastfilter checkAndSet function for most queue
        // filter checking but mop up the extremely rare tx whose inputs have false positive matches here.
        if (!temp_txDeferQ.empty())
        {
            const CTxInputData &first = temp_txDeferQ.front();

            for (const auto &inp : first.tx->vin)
            {
                incomingConflicts.insert(inp.prevout.hash);
            }
            txInQ.push(std::move(first));
            temp_txDeferQ.pop();

            cvTxInQ.notify_one();
        }

        uint64_t count = 0;
        uint64_t maxmove = std::max(avgCommitBatchSize * 2, minCommitBatchSize);
        // LOG(MEMPOOL, "txdeferQ, size %ld\n", temp_txDeferQ.size());
        while ((!temp_txDeferQ.empty()) && (count < maxmove))
        {
            // const uint256 &hash = temp_txDeferQ.front().tx->GetId();
            // LOG(MEMPOOL, "attempt enqueue deferred %s\n", hash.ToString());
            count++;
            TestConflictEnqueueTx(temp_txDeferQ.front(), false);
            temp_txDeferQ.pop();
        }
        // LOG(MEMPOOL, "txOrphanQ, size %ld\n", temp_txOrphanQ.size());
        while ((!temp_txOrphanQ.empty()) && (count < maxmove))
        {
            // const uint256 &hash = temp_txOrphanQ.front().tx->GetId();
            // LOG(MEMPOOL, "attempt enqueue orphan %s\n", hash.ToString());
            count++;
            TestConflictEnqueueTx(temp_txOrphanQ.front(), false);
            temp_txOrphanQ.pop();
        }
        // LOG(MEMPOOL, "txInQ, size %ld\n", temp_txInQ.size());
        while ((!temp_txInQ.empty()) && (count < maxmove))
        {
            // const uint256 &hash = temp_txInQ.front().tx->GetId();
            // LOG(MEMPOOL, "attempt enqueue txn %s\n", hash.ToString());
            count++;
            TestConflictEnqueueTx(temp_txInQ.front(), false);
            temp_txInQ.pop();
        }

        // Now that we've tried to enqueue everything again there may be some
        // that didn't make it. This should be rare if ever, but we have to
        // move them back to the txDeferQ.
        while (!temp_txDeferQ.empty())
        {
            txDeferQ.push(std::move(temp_txDeferQ.front()));
            temp_txDeferQ.pop();
        }
        while (!temp_txOrphanQ.empty())
        {
            txDeferQ.push(std::move(temp_txOrphanQ.front()));
            temp_txOrphanQ.pop();
        }
        while (!temp_txInQ.empty())
        {
            txDeferQ.push(std::move(temp_txInQ.front()));
            temp_txInQ.pop();
        }
    }

    return;
}

void ThreadTxAdmission()
{
    while (shutdown_threads.load() == false)
    {
        // Process at most this many transactions before letting the commit thread take over
        uint32_t nThreadsTweak = numTxAdmissionThreads.Value();
        uint64_t maxTxPerRound = std::max((uint64_t)1000, mempool.GetInstantaneousTxPerSec() / nThreadsTweak);

        // Start or Stop threads as determined by the numTxAdmissionThreads tweak
        {
            static CCriticalSection cs_threads;
            static uint32_t numThreads GUARDED_BY(cs_threads) = nThreadsTweak;
            LOCK(cs_threads);
            if (numThreads >= 1 && numThreads > nThreadsTweak)
            {
                // Kill this thread
                numThreads--;
                LOGA("Stopping a tx admission thread: Current admission threads are %d\n", numThreads);

                return;
            }
            else if (numThreads < nThreadsTweak)
            {
                // Launch another thread
                numThreads++;
                threadGroup.create_thread(&ThreadTxAdmission);
                LOGA("Starting a new tx admission thread: Current admission threads are %d\n", numThreads);
            }
        }

        // Loop processing starts here
        bool acceptedSomething = false;
        if (shutdown_threads.load() == true)
        {
            return;
        }

        bool fMissingInputs = false;
        CValidationState state;
        CTxInputData txd;

        {
            CCriticalBlock lock(csTxInQ, "csTxInQ", __FILE__, __LINE__, LockType::RECURSIVE_MUTEX);
            while (txInQ.empty() && txOrphanQ.empty() && shutdown_threads.load() == false)
            {
                if (shutdown_threads.load() == true)
                {
                    return;
                }
                cvTxInQ.wait(csTxInQ);
            }
            if (shutdown_threads.load() == true)
            {
                return;
            }
        }

        {
            CORRAL(txProcessingCorral, CORRAL_TX_PROCESSING);

            bool fOrphansEmpty = false;
            for (uint64_t txPerRoundCount = 0; txPerRoundCount < maxTxPerRound; txPerRoundCount++)
            {
                // tx must be popped within the TX_PROCESSING corral or the state break between processing
                // and commitment will not be clean
                bool fIsOrphan = false;
                {
                    CCriticalBlock lock(csTxInQ, "csTxInQ", __FILE__, __LINE__, LockType::RECURSIVE_MUTEX);

                    if (!txOrphanQ.empty())
                    {
                        txd = std::move(txOrphanQ.front());
                        txOrphanQ.pop();
                        fIsOrphan = true;

                        // If the orphanQ is empty after processing at least one of them,
                        // then We need to run the commitQ processing, so that we can get the txns
                        // into the mempool and which will allow us to process the next batch of orphans.
                        if (txOrphanQ.empty())
                        {
                            fOrphansEmpty = true;
                        }
                    }
                    else if (!txInQ.empty())
                    {
                        txd = std::move(txInQ.front());
                        txInQ.pop();
                    }
                    else
                    {
                        break;
                    }
                }

                CTransactionRef tx = txd.tx;
                CInv inv(MSG_TX, tx->GetId());

                if (fIsOrphan || !TxMayAlreadyHave(MSG_TX, tx->GetId()))
                {
                    std::vector<COutPoint> vCoinsToUncache;
                    bool isRespend = false;
                    if (ParallelAcceptToMemoryPool(mempool, state, tx, true, &fMissingInputs, false,
                            TransactionClass::DEFAULT, vCoinsToUncache, &isRespend, nullptr))
                    {
                        acceptedSomething = true;
                        RelayTransaction(tx);

                        // LOG(MEMPOOL, "Accepted tx: peer=%s: accepted %s onto Q\n", txd.nodeName,
                        //    tx->GetHash().ToString());
                    }
                    else
                    {
                        LOG(MEMPOOL, "Rejected tx: %s(%d) %s: %s. peer %s  hash %s \n", state.GetRejectReason(),
                            state.GetRejectCode(), fMissingInputs ? "orphan" : "", state.GetDebugMessage(),
                            txd.nodeName, tx->GetId().ToString());

                        if (fMissingInputs || state.GetRejectCode() == REJECT_NONFINAL)
                        {
                            WRITELOCK(orphanpool.cs_orphanpool);
                            if (fMissingInputs)
                                orphanpool.AddOrphanTx(tx, txd.nodeId);
                            else
                                orphanpool.AddNonFinalTx(tx, txd.nodeId);

                            // DoS prevention: do not allow the pool size to grow unbounded
                            const uint64_t nMaxOrphanPoolSize = maxTxPool.Value() * ONE_MEGABYTE / 10;
                            unsigned int nEvicted = orphanpool.LimitPoolSize(maxOrphanPool.Value(), nMaxOrphanPoolSize);
                            if (nEvicted > 0)
                                LOG(MEMPOOL, "mapOrphan overflow, removed %u tx\n", nEvicted);
                        }
                        else
                        {
                            recentRejects.insert(tx->GetId());

                            if (txd.whitelisted && fWhiteListForceRelay)
                            {
                                // Always relay transactions received from whitelisted peers, even
                                // if they were already in the mempool or rejected from it due
                                // to policy, allowing the node to function as a gateway for
                                // nodes hidden behind it.
                                //
                                // Never relay transactions that we would assign a non-zero DoS
                                // score for, as we expect peers to do the same with us in that
                                // case.
                                int nDoS = 0;
                                if (!state.IsInvalid(nDoS) || nDoS == 0)
                                {
                                    LOGA("Force relaying tx %s from whitelisted peer=%s\n", tx->GetId().ToString(),
                                        txd.nodeName);
                                    RelayTransaction(tx);
                                }
                                else
                                {
                                    LOGA("Not relaying invalid transaction %s from whitelisted peer=%s (%s)\n",
                                        tx->GetId().ToString(), txd.nodeName, state.GetLogString());
                                }
                            }
                            // If the problem wasn't that the tx is an orphan, then uncache the inputs since we likely
                            // won't
                            // need them again.
                            for (const COutPoint &remove : vCoinsToUncache)
                                pcoinsTip->Uncache(remove);
                        }
                    }

                    // We want to send a reject if the transaction might be an orphan because it could just as
                    // easily be already spent.
                    int nDoS = 0;
                    bool invalid = state.IsInvalid(nDoS);
                    if (invalid || fMissingInputs)
                    {
                        if (invalid)
                            LOG(MEMPOOL, "%s from peer=%s was not accepted: %s\ntx: %s", tx->GetId().ToString(),
                                txd.nodeName, state.GetLogString(), EncodeHexTx(*tx));
                        // Never send AcceptToMemoryPool's internal codes over P2P
                        unsigned char rejectCode = fMissingInputs ? REJECT_ORPHAN : state.GetRejectCode();
                        if (rejectCode < REJECT_INTERNAL)
                        {
                            CNodeRef from = connmgr->FindNodeFromId(txd.nodeId);
                            // Send a reject if we know who this tx came from, AND the tx is invalid or
                            // its an orphan and the node is a light client.  We need to tell light clients about
                            // orphans because an orphan may also be already-spent or just completely made up.
                            // The light client should not show this transaction unless its in a full node's txpool.
                            if (from && (invalid || from->fClient))
                            {
                                std::string strCommand = NetMsgType::TX;
                                from->PushMessageWithCookie(NetMsgType::REJECT, txd.msgCookie | 0xFFFF, strCommand,
                                    rejectCode, state.GetRejectReason().substr(0, MAX_REJECT_MESSAGE_LENGTH), inv.hash);
                                if (nDoS > 0)
                                {
                                    dosMan.Misbehaving(from.get(), nDoS, BanReasonInvalidOrMissingInputs);
                                }
                            }
                        }
                    }

                    // Mark this transaction as known. We've seen it and processed it in some way.
                    filterTransactionKnown.insert(inv.hash);
                }
                if (fOrphansEmpty)
                    break;
            } // end for
            if (acceptedSomething)
            {
                cvCommitQ.notify_all();
            }
        } // end corral
    } // end while
}


bool AcceptToMemoryPool(CTxMemPool &pool,
    CValidationState &state,
    const CTransactionRef &tx,
    bool fLimitFree,
    bool *pfMissingInputs,
    bool fRejectAbsurdFee,
    TransactionClass allowedTx)
{
    std::vector<COutPoint> vCoinsToUncache;
    bool res = false;

    {
        // pause parallel tx entry and commit all txns to the pool so that there are no
        // other threads running txadmission and to ensure that the mempool state is current.
        CORRAL(txProcessingCorral, CORRAL_TX_PAUSE);
        _CommitTxToMempool();

        // This lock is here to serialize AcceptToMemoryPool(). This must be done because
        // we do not enqueue the transaction prior to calling this function, as we do with
        // the normal multi-threaded tx admission.
        static CCriticalSection cs_accept;
        LOCK(cs_accept);

        bool isRespend = false;
        bool missingInputs = false;
        res = ParallelAcceptToMemoryPool(pool, state, tx, fLimitFree, &missingInputs, fRejectAbsurdFee, allowedTx,
            vCoinsToUncache, &isRespend, nullptr);

        // Uncache any coins for txns that failed to enter the mempool and were NOT orphan txns
        if (isRespend || (!res && !missingInputs))
        {
            for (const COutPoint &remove : vCoinsToUncache)
                pcoinsTip->Uncache(remove);
        }

        // Do this commit inside the cs_accept lock to ensure that this function retains its original sequential
        // behavior
        if (res)
            _CommitTxToMempool();

        if (pfMissingInputs)
            *pfMissingInputs = missingInputs;
    }
    if (res)
    {
        RelayTransaction(tx);
        LimitMempoolSize(mempool, maxTxPool.Value() * ONE_MEGABYTE, txPoolExpiry.Value() * 60 * 60);
    }
    return res;
}

bool ParallelAcceptToMemoryPool(CTxMemPool &pool,
    CValidationState &state,
    const CTransactionRef &tx,
    bool fLimitFree,
    bool *pfMissingInputs,
    bool fRejectAbsurdFee,
    TransactionClass allowedTx,
    std::vector<COutPoint> &vCoinsToUncache,
    bool *isRespend,
    CValidationDebugger *debugger)
{
    const CChainParams &chainparams = Params();

    if (isRespend)
        *isRespend = false;
    unsigned int nSigOps = 0;
    ValidationResourceTracker resourceTracker;
    unsigned int nSize = 0;
    uint64_t start = GetStopwatch();
    if (pfMissingInputs)
        *pfMissingInputs = false;

    if (debugger)
    {
        debugger->txid = tx->GetId().ToString();
    }

    if (!CheckTransaction(tx, state) || !ContextualCheckTransaction(tx, state, chainActive.Tip(), chainparams))
    {
        if (state.GetDebugMessage() == "")
            state.SetDebugMessage("CheckTransaction failed");
        if (debugger)
        {
            debugger->AddInvalidReason(state.GetRejectReason());
            state = CValidationState();
            debugger->mineable = false;
            // assume a tx that does not pass validation is non standard and not future mineable
            debugger->futureMineable = false;
            debugger->standard = false;
        }
        else
        {
            return false;
        }
    }

    // Coinbase is only valid in a block, not as a loose transaction
    if (tx->IsCoinBase())
    {
        if (debugger)
        {
            debugger->AddInvalidReason("Coinbase is only valid in a block, not as a loose transaction");
            debugger->mineable = false;
            debugger->futureMineable = false;
        }
        else
        {
            return state.DoS(100, false, REJECT_INVALID, "coinbase");
        }
    }

    // Reject nonstandard transactions if so configured.
    // (-testnet/-regtest allow nonstandard, and explicit submission via RPC)
    std::string reason;
    bool fRequireStandard = chainparams.RequireStandard();

    if (allowedTx == TransactionClass::STANDARD)
    {
        fRequireStandard = true;
    }
    else if (allowedTx == TransactionClass::NONSTANDARD)
    {
        fRequireStandard = false;
    }
    if (fRequireStandard && !IsStandardTx(tx, reason))
    {
        if (debugger)
        {
            debugger->AddInvalidReason(reason);
            // if we require standard, a non standard tx is not mineable or future mineable
            debugger->mineable = false;
            debugger->futureMineable = false;
            debugger->standard = false;
        }
        else
        {
            state.SetDebugMessage("IsStandardTx failed");
            return state.DoS(0, false, REJECT_NONSTANDARD, reason);
        }
    }

    uint32_t flags = STANDARD_SCRIPT_VERIFY_FLAGS;

    CBlockIndex *tip = chainActive.Tip();
    if (IsFork1Activated(tip) || IsFork1Pending(tip))
    {
        flags = POST_UPGRADE_MANDATORY_SCRIPT_VERIFY_FLAGS;
    }

    // Only accept nLockTime-using transactions that can be mined in the next
    // block; we don't want our mempool filled up with transactions that can't
    // be mined yet.
    if (!CheckFinalTx(tx, STANDARD_LOCKTIME_VERIFY_FLAGS))
    {
        if (debugger)
        {
            debugger->AddInvalidReason("non-final");
            // non final is not mineable now but may be in the future
            debugger->mineable = false;
        }
        else
        {
            return state.DoS(0, false, REJECT_NONFINAL, "non-final");
        }
    }

    // Make sure tx size is acceptable
    {
        if (tx->GetTxSize() < MIN_TX_SIZE)
        {
            if (debugger)
            {
                debugger->AddInvalidReason("txn-undersize");
                debugger->mineable = false;
                debugger->futureMineable = false;
            }
            else
            {
                return state.DoS(0, false, REJECT_INVALID, "txn-undersize");
            }
        }
    }

    // Is it already in the memory pool?
    const uint256 &id = tx->GetId();
    const uint256 &idem = tx->GetIdem();
    if (pool.idemExists(idem))
    {
        if (debugger)
        {
            debugger->AddInvalidReason("txn-already-in-mempool");
        }
        else
        {
            return state.Invalid(false, REJECT_ALREADY_KNOWN, "txn-already-in-mempool");
        }
    }

    // Check for conflicts with in-memory transactions and triggers actions at
    // end of scope (relay tx, sync wallet, etc)
    respend::RespendDetector respend(pool, tx);
    *isRespend = respend.IsRespend();

    if (respend.IsRespend() && !respend.IsInteresting())
    {
        if (debugger)
        {
            std::string conflicts("txn-txpool-conflict:");
            for (auto &c : respend.getConflicts())
            {
                conflicts.append(" ");
                conflicts.append(c.GetHex());
            }
            debugger->AddInvalidReason(conflicts);
            debugger->mineable = false;
            debugger->futureMineable = false;
        }
        else
        {
            // Tx is a respend, and it's not an interesting one (we don't care to
            // validate it further)
            return state.Invalid(false, REJECT_CONFLICT, "txn-txpool-conflict");
        }
    }
    {
        // view is used for storing normal coins
        CCoinsView dummy;
        CCoinsViewCache view(&dummy);

        // coinstip is used for storing read only inputs
        CCoinsView dummy2;
        CCoinsViewCache coinstip(&dummy2);

        CAmount nValueIn = 0;
        LockPoints lp;

        CAmount nValueOut = 0;
        CAmount nFees = 0;
        CAmount nModifiedFees = 0;
        {
            READLOCK(pool.cs_txmempool);
            CCoinsViewCache *ptip = fTailstormEnabled ? tailstormForest.pcoinsDag : pcoinsTip;
            CCoinsViewMemPool viewMemPool(ptip, mempool);
            view.SetBackend(viewMemPool);
            coinstip.SetBackend(*ptip);

            // do all inputs exist?
            if (pfMissingInputs)
            {
                *pfMissingInputs = false;
                int inIdx = 0;
                for (const CTxIn &txin : tx->vin)
                {
                    // At this point we begin to collect coins that are potential candidates for uncaching because as
                    // soon as we make the call below to view.HaveCoin() any missing coins will be pulled into cache.
                    // Therefore, any coin in this transaction that is not already in cache will be tracked here such
                    // that if this transaction fails to enter the memory pool, we will then uncache those coins that
                    // were not already present, unless the transaction is an orphan.
                    //
                    // We still want to keep orphantx coins in the event the orphantx is finally accepted into the
                    // mempool or shows up in a block that is mined.  Therefore if pfMissingInputs returns true then
                    // any coins in vCoinsToUncache will NOT be uncached.

                    bool fSpent = false;
                    bool fMissingOrSpent = false;
                    if (txin.IsReadOnly())
                    {
                        if (!coinstip.HaveCoinInCache(txin.prevout, fSpent))
                        {
                            // Read-only inputs can only refer to confirmed inputs
                            // look in coins (utxo of blockchain tip, not mempool tip)
                            // but ignore whether its spent (read-only spent coins are still accessible in this block).
                            if (!coinstip.GetCoinFromDB(txin.prevout))
                            {
                                state.missingInput = inIdx;
                                fMissingOrSpent = true;
                                LOG(MEMPOOL, "read-only input-does-not-exist: %d:%s\n", inIdx,
                                    txin.prevout.hash.ToString());
                            }
                        }
                    }
                    else
                    {
                        vCoinsToUncache.push_back(txin.prevout);
                        if (!view.HaveCoin(txin.prevout))
                        {
                            state.missingInput = inIdx;
                            fMissingOrSpent = true;
                            LOG(MEMPOOL, "normal input-does-not-exist: %d:%s\n", inIdx, txin.prevout.hash.ToString());
                        }
                    }
                    if (fSpent || fMissingOrSpent)
                    {
                        if (debugger)
                        {
                            debugger->AddInvalidReason(
                                "input-does-not-exist: " + std::to_string(inIdx) + " " + txin.prevout.hash.ToString());
                            // missing inputs are not mineable now. it may be mineable
                            // in the future but it is not certain, assume it will not be
                            debugger->mineable = false;
                            debugger->futureMineable = false;
                        }
                        // fMissingInputs and not state.IsInvalid() is used to detect this condition, don't set
                        // state.Invalid()
                        LOG(MEMPOOL, "input-does-not-exist: %d:%s\n", inIdx, txin.prevout.hash.ToString());
                        *pfMissingInputs = true;
                        if (debugger == nullptr)
                        {
                            break; // There is no point checking any more once one fails, for orphans we will recheck
                        }
                    }
                    inIdx++;
                }
                if (*pfMissingInputs == true)
                {
                    if (debugger)
                    {
                        debugger->AddInvalidReason("inputs-are-missing");
                        // missing inputs are not mineable now. it may be mineable
                        // in the future but it is not certain, assume it will not be
                        debugger->mineable = false;
                        debugger->futureMineable = false;
                        return false;
                    }
                    else
                    {
                        state.SetDebugMessage("inputs-are-missing");
                        return false; // state.Invalid(false, REJECT_MISSING_INPUTS, "bad-txns-missing-inputs", "Inputs
                        // unavailable in ParallelAcceptToMemoryPool", false);
                    }
                }
            }

            // Bring the best block into scope
            view.GetBestBlock();
            coinstip.GetBestBlock();

            nValueIn = tx->GetValueIn();
            // NOTE this view function MUST be executed, so we can cache all inputs, before SetBackend(dummy)
            CAmount viewValueIn = view.GetValueIn(*tx);
            if (nValueIn != viewValueIn)
            {
                if (debugger)
                {
                    debugger->AddInvalidReason(
                        strprintf("inconsistent input value: tx: %d,  UTXO: %d", nValueIn, viewValueIn));
                    debugger->mineable = false;
                    debugger->futureMineable = false;
                }
                else
                {
                    return state.DoS(1, false, REJECT_INVALID, "inconsistent input value");
                }
            }
            // we have all inputs cached now, so switch back to dummy, so we don't need to keep lock on mempool
            view.SetBackend(dummy);
            coinstip.SetBackend(dummy2);

            // Only accept BIP68 sequence locked transactions that can be mined in the next
            // block; we don't want our mempool filled up with transactions that can't
            // be mined yet.
            // Must keep pool.cs for this unless we change CheckSequenceLocks to take a
            // CoinsViewCache instead of create its own
            if (!CheckSequenceLocks(tx, STANDARD_LOCKTIME_VERIFY_FLAGS, &lp, false))
            {
                if (debugger)
                {
                    debugger->AddInvalidReason("non-BIP68-final");
                    // not mineable now but should be in the future
                    debugger->mineable = false;
                }
                else
                {
                    return state.DoS(0, false, REJECT_NONSTANDARD, "non-BIP68-final");
                }
            }

            nValueOut = tx->GetValueOut();
            nFees = viewValueIn - nValueOut;
            LOG(MEMPOOL, "Value In: %d  Out: %d  Fees: %d\n", nValueIn, nValueOut, nFees);
            nModifiedFees = nFees; // nModifiedFees includes any fee deltas from PrioritiseTransaction
            double nPriorityDummy = 0;

            // Search either id or idem for a user-applied priority modifier
            pool._ApplyDeltas(id, nPriorityDummy, nModifiedFees);
            pool._ApplyDeltas(idem, nPriorityDummy, nModifiedFees);
        }

        // Check for non-standard pay-to-script-hash in inputs
        if (fRequireStandard && !AreInputsStandard(tx, view))
        {
            if (debugger)
            {
                debugger->AddInvalidReason("bad-txns-nonstandard-inputs");
                debugger->standard = false;
                // if we require standard and this tx is not standard, we can not
                // mine now or in the future either
                debugger->mineable = false;
                debugger->futureMineable = false;
            }
            else
            {
                return state.Invalid(false, REJECT_NONSTANDARD, "bad-txns-nonstandard-inputs");
            }
        }

        // Get the priority
        //
        // And, keep track of transactions that spend a coinbase, which we re-scan
        // during reorgs to ensure COINBASE_MATURITY is still met.
        CAmount inChainInputValue;
        bool fSpendsCoinbase = false;
        double dPriority = view.GetPriority(*tx, chainActive.Height(), inChainInputValue, fSpendsCoinbase);
        // Check that input script constraints are satisfied
        unsigned char sighashType = 0;
        if (!CheckInputs(tx, state, view, coinstip, true, flags, true, &resourceTracker, chainparams, nullptr,
                &sighashType, debugger))
        {
            if (state.GetDebugMessage() == "")
                state.SetDebugMessage("CheckConsumedInputs failed");

            if (debugger && debugger->InputsCheck1IsValid())
            {
                debugger->AddInvalidReason(state.GetDebugMessage());
                debugger->mineable = false;
                debugger->futureMineable = false;
            }
            else
            {
                LOG(MEMPOOL, "CheckConsumedInputs failed for tx: %s reason: %s\n", id.ToString(),
                    state.GetDebugMessage());
                return false;
            }
        }

        // Check that the transaction doesn't have an excessive number of sigops, making it impossible to mine.
        {
            nSigOps = resourceTracker.GetConsensusSigChecks();
            if (nSigOps > MAX_TX_SIGCHECK_COUNT)
            {
                if (debugger)
                {
                    debugger->AddInvalidReason("bad-txns-too-many-sigchecks");
                    // not mineable now or in the future under the current ruleset
                    debugger->mineable = false;
                    debugger->futureMineable = false;
                }
                else
                {
                    return state.DoS(
                        0, false, REJECT_INVALID, "bad-txns-too-many-sigchecks", false, strprintf("%d", nSigOps));
                }
            }
            // Place sigchecks into the mempool sigops field, since these are not cotemporaneous
            // only show this log for a strange # of sigchecks (typically 1 per input)
            if (nSigOps != tx->vin.size())
                LOG(MEMPOOL, "Tx %s has %d sigchecks\n", id.ToString(), nSigOps);
        }

        // Create a commit data entry
        CTxMemPoolEntry entry(
            tx, nFees, GetTime(), dPriority, chainActive.Height(), inChainInputValue, fSpendsCoinbase, nSigOps, lp);

        nSize = entry.GetTxSize();
        if (fRelayPriority && (nModifiedFees < ::minRelayTxFee.GetFee(nSize)) &&
            (!AllowFree(entry.GetPriority(chainActive.Height() + 1))))
        {
            if (debugger)
            {
                debugger->AddInvalidReason("insufficient-priority");
                debugger->AddInvalidReason("insufficient-fee: need " + std::to_string(minRelayTxFee.GetFee(nSize)) +
                                           " was only " + std::to_string(nModifiedFees));
                debugger->AddInvalidReason("minimum-fee: " + std::to_string(minRelayTxFee.GetFee(nSize)));
                // fees are not a reason to mark something as not mineable, keep current mineable and futureMineable
                // values unchanged
                debugger->standard = false;
            }
            else
            {
                // Require that free transactions have sufficient priority to be mined in the next block.
                LOG(MEMPOOL, "Txn fee %lld (%d - %d), priority fee delta was %lld\n", nFees, nValueIn, nValueOut,
                    nModifiedFees - nFees);
                return state.DoS(0, false, REJECT_INSUFFICIENTFEE, "insufficient priority");
            }
        }
        if (debugger)
        {
            debugger->txMetadata.emplace("size", std::to_string(nSize));
            debugger->txMetadata.emplace("txfee", std::to_string(nModifiedFees));
            debugger->txMetadata.emplace("txfeeneeded", std::to_string(minRelayTxFee.GetFee(nSize)));
        }

        /* Continuously rate-limit free (really, very-low-fee) transactions
         * This mitigates 'penny-flooding' -- sending thousands of free transactions just to
         * be annoying or make others' transactions take longer to confirm. */
        static CCriticalSection cs_limiter;
        {
            LOCK(cs_limiter);

            static int64_t nLastTime = GetTime();
            int64_t nNow = GetTime();
            minRelayTxFee = CFeeRate((CAmount)(minRelayFee.Value()));

            // useful but spammy
            // LOG(MEMPOOL,
            //    "MempoolBytes:%ld LimitFreeRelay:%d FeesSatoshiPerKB:%ld TxBytes:%d "
            //    "TxFees:%ld\n",
            //    pool.GetTotalTxSize(), limitFreeRelay.Value(), nModifiedFees * 1000 / nSize, nSize, nModifiedFees);
            if (fLimitFree && nModifiedFees < ::minRelayTxFee.GetFee(nSize))
            {
                static double dFreeCount = 0;

                // Use an exponentially decaying ~10-minute window:
                dFreeCount *= std::pow(1.0 - 1.0 / 600.0, (double)(nNow - nLastTime));
                nLastTime = nNow;

                // limitFreeRelay is in KB per minute but we multiply it
                //  by an extra 10 because we're using a 10 minute decay window.
                LOG(MEMPOOL, "Rate limit dFreeCount: %g => %g\n", dFreeCount, dFreeCount + nSize);
                if ((dFreeCount + nSize) >= (limitFreeRelay.Value() * 10 * 1000))
                {
                    if (debugger)
                    {
                        debugger->AddInvalidReason("rate limited free transaction");
                        // fees are not a reason to mark something as not mineable, keep current mineable and
                        // futureMineable values unchanged
                        debugger->standard = false;
                    }
                    else
                    {
                        LOG(MEMPOOL, "AcceptToMemoryPool : free transaction %s rejected by rate limiter\n",
                            id.ToString());
                        return state.DoS(0, false, REJECT_INSUFFICIENTFEE, "mempool min fee not met");
                    }
                }
                dFreeCount += nSize;
            }
            else if (nModifiedFees < ::minRelayTxFee.GetFee(nSize))
            {
                if (debugger)
                {
                    debugger->AddInvalidReason("txpool min fee not met");
                    // fees are not a reason to mark something as not mineable, keep current mineable and futureMineable
                    // values unchanged
                    debugger->standard = false;
                }
                else
                {
                    LOG(MEMPOOL, "AcceptToMemoryPool : min fee not met for %s\n", id.ToString());
                    return state.DoS(0, false, REJECT_INSUFFICIENTFEE, "mempool min fee not met");
                }
            }
        }
#ifdef ENABLE_WALLET
        // We calculate the recommended fee by looking at what's in the mempool.  This starts at 0 though for an
        // empty mempool.  So set the minimum "absurd" fee to 10000 satoshies per byte.  If for some reason fees rise
        // above that, you can specify up to 100x what other txns are paying in the mempool
        if (fRejectAbsurdFee && nFees > std::max((int64_t)100L * nSize, maxTxFeeTweak.Value()) * 100)
        {
            if (debugger)
            {
                debugger->AddInvalidReason("absurdly-high-fee");
                // fees are not a reason to mark something as not mineable, keep current mineable and futureMineable
                // values unchanged
                debugger->standard = false;
            }
            else
            {
                return state.Invalid(false, REJECT_HIGHFEE, "absurdly-high-fee",
                    strprintf("%d > %d", nFees, std::max((int64_t)100L * nSize, maxTxFeeTweak.Value()) * 100));
            }
        }
#endif

        // Check for repend before committing the tx to the mempool
        respend.SetValid(true);
        if (respend.IsRespend())
        {
            if (debugger)
            {
                std::string conflicts("txn-txpool-conflict:");
                for (auto &c : respend.getConflicts())
                {
                    conflicts.append(" ");
                    conflicts.append(c.GetHex());
                }
                debugger->AddInvalidReason(conflicts);
            }
            else
            {
                return state.Invalid(false, REJECT_CONFLICT, "txn-txpool-conflict");
            }
        }
        else if (debugger == nullptr)
        {
            // If it's not a respend it may have a reclaimed orphan associated with it
            entry.dsproof = respend.GetDsproof();

            // Add entry to the commit queue
            CTxCommitData eData;
            eData.entry = std::move(entry);
            eData.hash = id;

            LOCK(cs_commitQ);
            (*txCommitQ).insert(eData);
        }
    }
    uint64_t interval = (GetStopwatch() - start) / 1000;
    // typically too much logging, but useful when optimizing tx validation
    LOG(BENCH,
        "ValidateTransaction success, time: %d, txid: %s, len: %d, sigops: %u, Vin: "
        "%llu, Vout: %llu txidem: %s\n",
        interval, tx->GetId().ToString(), nSize, (unsigned int)nSigOps, tx->vin.size(), tx->vout.size(),
        tx->GetIdem().ToString());
    nTxValidationTime << interval;

    // Update txn per second. We must do it here although technically the txn isn't in the mempool yet but
    // rather in the CommitQ. However, if we don't do it here then we'll end up with very bursty and not very
    // realistic processing throughput data.
    mempool.UpdateTransactionsPerSecond();

    return true;
}


TransactionClass ParseTransactionClass(const std::string &s)
{
    std::string low = boost::algorithm::to_lower_copy(s);
    if (low == "nonstandard")
    {
        return TransactionClass::NONSTANDARD;
    }
    if (low == "standard")
    {
        return TransactionClass::STANDARD;
    }
    if (low == "default")
    {
        return TransactionClass::DEFAULT;
    }

    return TransactionClass::INVALID;
}


uint64_t ProcessOrphans(const std::vector<CTransactionRef> &vWorkQueue)
{
    // NOTE: you must not return early since EraseByTime() must always be checked
    std::vector<CTxInputData> vEnqueue;
    {
        READLOCK(orphanpool.cs_orphanpool);
        if (orphanpool.mapOrphans.empty() && orphanpool.mapNonFinals.empty())
        {
            DbgAssert(orphanpool.mapOrphansByPrev.empty(), );
            return 0;
        }

        // Process non-finals adding the changes to vWhatChanged.  We have to add these
        // so that for every non-final added back to the  txpool we can then check to see
        // whether it has any chained orphans associated with it which could also be promoted
        // to the txpool.
        for (auto &it : orphanpool.mapNonFinals)
        {
            // Add the non-final to be enqueued later
            if (CheckFinalTx(it.second.ptx, STANDARD_LOCKTIME_VERIFY_FLAGS))
            {
                CTxInputData txd;
                txd.tx = it.second.ptx;
                txd.nodeId = it.second.fromPeer;
                txd.nodeName = "non-final";
                LOG(MEMPOOL, "Resubmitting non-final tx: %s\n", it.second.ptx->GetId().ToString());
                vEnqueue.push_back(std::move(txd));
            }
        }

        // Recursively process any orphan transactions that depended on this one.
        for (auto tx : vWorkQueue)
        {
            for (unsigned int j = 0; j < tx->vout.size(); j++)
            {
                std::map<uint256, std::set<uint256> >::iterator itByPrev =
                    orphanpool.mapOrphansByPrev.find(tx->OutpointAt(j).hash);
                if (itByPrev != orphanpool.mapOrphansByPrev.end())
                {
                    for (const auto &orphanHash : itByPrev->second)
                    {
                        // Make sure we actually have an entry on the orphan cache. While this should never fail because
                        // we always erase orphans and any mapOrphansByPrev at the same time, still we need
                        // to be sure.
                        bool fOk = true;
                        std::map<uint256, CTxOrphanPool::COrphanTx>::iterator iter =
                            orphanpool.mapOrphans.find(orphanHash);
                        DbgAssert(iter != orphanpool.mapOrphans.end(), fOk = false);
                        if (!fOk)
                            continue;

                        // Add the orphan to be enqueued later
                        {
                            CTxInputData txd;
                            txd.tx = iter->second.ptx;
                            txd.nodeId = iter->second.fromPeer;
                            txd.nodeName = "orphan";
                            LOG(MEMPOOL, "Resubmitting orphan tx: %s\n", orphanHash.ToString());
                            vEnqueue.push_back(std::move(txd));
                        }
                    }
                }
            }
        }
    }

    // First delete the orphans before enqueuing them otherwise we may end up putting them
    // in the queue twice.
    orphanpool.EraseByTime();
    if (!vEnqueue.empty())
    {
        {
            WRITELOCK(orphanpool.cs_orphanpool);
            auto it = vEnqueue.begin();
            while (it != vEnqueue.end())
            {
                // If the orphan was not erased then it must already have been erased/enqueued by another thread
                // so do not enqueue this orphan again.
                bool fErasedOrphan = orphanpool.EraseOrphanTx(it->tx->GetId());
                bool fErasedNonFinal = orphanpool.EraseNonFinalTx(it->tx->GetId());
                if (!fErasedOrphan && !fErasedNonFinal)
                    it = vEnqueue.erase(it);
                else
                    it++;
            }
        }
        for (auto &txd : vEnqueue)
            EnqueueTxForAdmission(txd, true);
    }
    return orphanpool.GetPoolSize();
}


bool CheckSequenceLocks(const CTransactionRef tx, int flags, LockPoints *lp, bool useExistingLockPoints)
{
    AssertLockHeld(mempool.cs_txmempool);

    CBlockIndex *tip = chainActive.Tip();
    CBlockIndex index;
    index.pprev = tip;
    // CheckSequenceLocks() uses chainActive.Height()+1 to evaluate
    // height based locks because when SequenceLocks() is called within
    // ConnectBlock(), the height of the block *being*
    // evaluated is what is used.
    // Thus if we want to know if a transaction can be part of the
    // *next* block, we need to use one more than chainActive.Height()
    index.SetBlockHeaderHeight(tip->height() + 1);

    std::pair<int, int64_t> lockPair;
    if (useExistingLockPoints)
    {
        assert(lp);
        lockPair.first = lp->height;
        lockPair.second = lp->time;
    }
    else
    {
        // ptip contains the UTXO set for chainActive.Tip() or the tailstorm dag tip
        CCoinsViewCache *ptip = fTailstormEnabled ? tailstormForest.pcoinsDag : pcoinsTip;
        CCoinsViewMemPool tmpView(ptip, mempool);
        CCoinsViewMemPool &viewMemPool = tmpView;
        std::vector<int> prevheights;
        prevheights.resize(tx->vin.size());
        for (size_t txinIndex = 0; txinIndex < tx->vin.size(); txinIndex++)
        {
            const CTxIn &txin = tx->vin[txinIndex];
            Coin coin;
            if (!viewMemPool.GetCoin(txin.prevout, coin))
            {
                return error("%s: Missing input", __func__);
            }
            if (coin.nHeight == MEMPOOL_HEIGHT)
            {
                // Assume all mempool transaction confirm in the next block
                prevheights[txinIndex] = tip->height() + 1;
            }
            else
            {
                prevheights[txinIndex] = coin.height();
            }
        }
        lockPair = CalculateSequenceLocks(tx, flags, &prevheights, index);
        if (lp)
        {
            lp->height = lockPair.first;
            lp->time = lockPair.second;
            // Also store the hash of the block with the highest height of
            // all the blocks which have sequence locked prevouts.
            // This hash needs to still be on the chain
            // for these LockPoint calculations to be valid
            // Note: It is impossible to correctly calculate a maxInputBlock
            // if any of the sequence locked inputs depend on unconfirmed txs,
            // except in the special case where the relative lock time/height
            // is 0, which is equivalent to no sequence lock. Since we assume
            // input height of tip+1 for mempool txs and test the resulting
            // lockPair from CalculateSequenceLocks against tip+1.  We know
            // EvaluateSequenceLocks will fail if there was a non-zero sequence
            // lock on a mempool input, so we can use the return value of
            // CheckSequenceLocks to indicate the LockPoints validity
            int maxInputHeight = 0;
            for (int height : prevheights)
            {
                // Can ignore mempool inputs since we'll fail if they had non-zero locks
                if (height != tip->height() + 1)
                {
                    maxInputHeight = std::max(maxInputHeight, height);
                }
            }
            lp->maxInputBlock = tip->GetAncestor(maxInputHeight);
        }
    }
    return EvaluateSequenceLocks(index, lockPair);
}

bool CheckFinalTx(const CTransactionRef tx, int flags) { return CheckFinalTx(tx.get(), flags); }
bool CheckFinalTx(const CTransaction *tx, int flags)
{
    // By convention a negative value for flags indicates that the
    // current network-enforced consensus rules should be used. In
    // a future soft-fork scenario that would mean checking which
    // rules would be enforced for the next block and setting the
    // appropriate flags. At the present time no soft-forks are
    // scheduled, so no flags are set.
    flags = std::max(flags, 0);

    // CheckFinalTx() uses chainActive.Height()+1 to evaluate
    // nLockTime because when IsFinalTx() is called within
    // CBlock::AcceptBlock(), the height of the block *being*
    // evaluated is what is used. Thus if we want to know if a
    // transaction can be part of the *next* block, we need to call
    // IsFinalTx() with one more than chainActive.Height().
    const int64_t nBlockHeight = chainActive.Height() + 1;

    // BIP113 will require that time-locked transactions have nLockTime set to
    // less than the median time of the previous block they're contained in.
    // When the next block is created its previous block will be the current
    // chain tip, so we use that to calculate the median time passed to
    // IsFinalTx() if LOCKTIME_MEDIAN_TIME_PAST is set.
    const int64_t nMedianTimePast = chainActive.Tip()->GetMedianTimePast();
    const int64_t nBlockTime = (flags & LOCKTIME_MEDIAN_TIME_PAST) ? nMedianTimePast : GetAdjustedTime();

    return IsFinalTx(tx, nBlockHeight, nBlockTime);
}
