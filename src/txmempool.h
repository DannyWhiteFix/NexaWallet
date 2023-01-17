// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2023 The Bitcoin Unlimited developers
// Copyright (C) 2019-2020 Tom Zander <tomz@freedommail.ch>
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_TXMEMPOOL_H
#define NEXA_TXMEMPOOL_H

#include <list>
#include <set>
#include <tuple>

#include "amount.h"
#include "coins.h"
#include "primitives/transaction.h"
#include "random.h"
#include "sync.h"

#undef foreach
#include "boost/multi_index/ordered_index.hpp"
#include "boost/multi_index_container.hpp"
#include <boost/thread/locks.hpp>
#include <boost/thread/mutex.hpp>

extern CTweak<uint32_t> txPoolExpiry;
extern CTweak<uint32_t> maxTxPool;
extern CTweak<bool> persistTxPool;

/** Default -cache.persistTxPool */
static const bool DEFAULT_PERSIST_MEMPOOL = true;

class CAutoFile;
class CBlockIndex;
class DoubleSpendProofStorage;
class DoubleSpendProof;

inline double AllowFreeThreshold() { return COIN * 144 / 250; }
inline bool AllowFree(double dPriority)
{
    // Large (in bytes) low-priority (new, small-coin) transactions
    // need a fee.
    return dPriority > AllowFreeThreshold();
}

/** Fake height value used in Coin to signify they are only in the memory pool (since 0.8) */
static const uint32_t MEMPOOL_HEIGHT = 0x7FFFFFFF;
/** Length of time in seconds over which to smooth the tx rate */
static const double TX_RATE_SMOOTHING_SEC = 60;
/** Sample resolution in milliseconds over which to compute the instantaneous transaction rate */
static const int TX_RATE_RESOLUTION_MILLIS = 1000;
/** Update frequency in milliseconds when the statistics will be recomputed
    This must be <= TX_RATE_RESOLUTION_MILLIS */
static const int TX_RATE_UPDATE_FREQUENCY_MILLIS = 250;

/** If our indicated (and possibly dirty) number of ancestors in a transaction chain is less than
 * this value then we'll immediately update the correct and current ancestor chain state
 */
static const uint32_t MAX_UPDATED_CHAIN_STATE = 500;

/** Transaction rate statisics update thread */
void ThreadUpdateTransactionRateStatistics();

/** Dump the txpool to disk. */
bool DumpTxPool();

/** Load the txpool from disk. */
bool LoadTxPool();

struct LockPoints
{
    // Will be set to the blockchain height and median time past
    // values that would be necessary to satisfy all relative locktime
    // constraints (BIP68) of this tx given our view of block chain history
    int height;
    int64_t time;
    // As long as the current chain descends from the highest height block
    // containing one of the inputs used in the calculation, then the cached
    // values are still valid even after a reorg.
    CBlockIndex *maxInputBlock;

    LockPoints() : height(0), time(0), maxInputBlock(nullptr) {}
};

class CTxMemPool;

/** \class CTxMemPoolEntry
 *
 * CTxMemPoolEntry stores data about the correponding transaction, as well
 * as data about all in-mempool transactions that depend on the transaction
 * ("descendant" transactions).
 *
 */

class CTxMemPoolEntry
{
private:
    CTransactionRef tx;
    CAmount nFee; //! Cached to avoid expensive parent-transaction lookups
    size_t nModSize; //! ... and modified size for priority
    size_t nUsageSize; //! ... and total memory usage
    int64_t nTime; //! Local time when entering the mempool
    double entryPriority; //! Priority when entering the mempool
    unsigned int entryHeight; //! Chain height when entering the mempool
    bool hadNoDependencies; //! Not dependent on any other txs when it entered the mempool
    CAmount inChainInputValue; //! Sum of all txin values that are already in blockchain
    bool spendsCoinbase; //! keep track of transactions that spend a coinbase
    unsigned int sigOpCount; //! Legacy sig ops plus P2SH sig op count
    uint64_t runtimeSigOpCount; //! Runtime signature operation count
    uint64_t runtimeSighashBytes; //! Runtime bytes hashed for signature operations
    int64_t feeDelta; //! Used for determining the priority of the transaction for mining in a block
    LockPoints lockPoints; //! Track the height and time at which tx was final

    // Analogous statistics for ancestor transactions
    uint64_t nCountWithAncestors;
    uint64_t nSizeWithAncestors;
    CAmount nModFeesWithAncestors;
    unsigned int nSigOpCountWithAncestors;
    bool fDirty;

public:
    // Naming a tx is useful for tracking during debugging but wastes space.  This code will be left in, commented out
    // for later use.
    // std::string dbgName;
    int dsproof = -1;
    CTxMemPoolEntry();
    CTxMemPoolEntry(const CTransactionRef _tx,
        const CAmount &_nFee,
        int64_t _nTime,
        double _entryPriority,
        unsigned int _entryHeight,
        bool poolHasNoInputsOf,
        CAmount _inChainInputValue,
        bool spendsCoinbase,
        unsigned int nSigOps,
        LockPoints lp);
    CTxMemPoolEntry(const CTxMemPoolEntry &other) = default;
    CTxMemPoolEntry &operator=(const CTxMemPoolEntry &) = default;

    const CTransaction &GetTx() const { return *this->tx; }
    CTransactionRef GetSharedTx() const { return this->tx; }
    /**
     * Fast calculation of lower bound of current priority as update
     * from entry priority. Only inputs that were originally in-chain will age.
     */
    double GetPriority(unsigned int currentHeight) const;
    const CAmount &GetFee() const { return nFee; }
    size_t GetTxSize() const { return this->tx->GetTxSize(); }
    int64_t GetTime() const { return nTime; }
    unsigned int GetHeight() const { return entryHeight; }
    bool WasClearAtEntry() const { return hadNoDependencies; }
    unsigned int GetSigOpCount() const { return sigOpCount; }
    uint64_t GetRuntimeSigOpCount() const { return runtimeSigOpCount; }
    uint64_t GetRuntimeSighashBytes() const { return runtimeSighashBytes; }
    int64_t GetModifiedFee() const { return nFee + feeDelta; }
    int64_t GetFeeDelta() const { return feeDelta; }
    size_t DynamicMemoryUsage() const { return nUsageSize; }
    const LockPoints &GetLockPoints() const { return lockPoints; }
    // Increments the ancestor state values
    void UpdateAncestorState(int64_t modifySize, CAmount modifyFee, int64_t modifyCount, int modifySigOps, bool dirty);
    // Replaces the previous ancestor state with new set of values
    void ReplaceAncestorState(int64_t modifySize, CAmount modifyFee, int64_t modifyCount, int modifySigOps, bool dirty);
    // Updates the fee delta used for mining priority score, and the
    // modified fees with descendants.
    void UpdateFeeDelta(int64_t feeDelta);
    // Update the LockPoints after a reorg
    void UpdateLockPoints(const LockPoints &lp);
    // Update runtime validation resource usage
    void UpdateRuntimeSigOps(uint64_t _runtimeSigOpCount, uint64_t _runtimeSighashBytes);

    bool GetSpendsCoinbase() const { return spendsCoinbase; }
    uint64_t GetCountWithAncestors() const { return nCountWithAncestors; }
    uint64_t GetSizeWithAncestors() const { return nSizeWithAncestors; }
    CAmount GetModFeesWithAncestors() const { return nModFeesWithAncestors; }
    unsigned int GetSigOpCountWithAncestors() const { return nSigOpCountWithAncestors; }
    bool IsDirty() const { return fDirty; }
};

struct update_ancestor_state
{
    update_ancestor_state(int64_t _modifySize, CAmount _modifyFee, int64_t _modifyCount, int _modifySigOps, bool _dirty)
        : modifySize(_modifySize), modifyFee(_modifyFee), modifyCount(_modifyCount), modifySigOps(_modifySigOps),
          dirty(_dirty)
    {
    }

    void operator()(CTxMemPoolEntry &e)
    {
        e.UpdateAncestorState(modifySize, modifyFee, modifyCount, modifySigOps, dirty);
    }

private:
    int64_t modifySize;
    CAmount modifyFee;
    int64_t modifyCount;
    int modifySigOps;
    bool dirty;
};

struct replace_ancestor_state
{
    replace_ancestor_state(int64_t _modifySize,
        CAmount _modifyFee,
        int64_t _modifyCount,
        int _modifySigOps,
        bool _dirty)
        : modifySize(_modifySize), modifyFee(_modifyFee), modifyCount(_modifyCount), modifySigOps(_modifySigOps),
          dirty(_dirty)
    {
    }

    void operator()(CTxMemPoolEntry &e)
    {
        e.ReplaceAncestorState(modifySize, modifyFee, modifyCount, modifySigOps, dirty);
    }

private:
    int64_t modifySize;
    CAmount modifyFee;
    int64_t modifyCount;
    int modifySigOps;
    bool dirty;
};

struct ancestor_state
{
    ancestor_state(int64_t _modifySize, CAmount _modifyFee, int64_t _modifyCount, int _modifySigOps)
        : modifySize(_modifySize), modifyFee(_modifyFee), modifyCount(_modifyCount), modifySigOps(_modifySigOps)
    {
    }

public:
    int64_t modifySize;
    CAmount modifyFee;
    int64_t modifyCount;
    int modifySigOps;
};

struct update_fee_delta
{
    update_fee_delta(int64_t _feeDelta) : feeDelta(_feeDelta) {}
    void operator()(CTxMemPoolEntry &e) const { e.UpdateFeeDelta(feeDelta); }

private:
    int64_t feeDelta;
};

struct update_lock_points
{
    update_lock_points(const LockPoints &_lp) : lp(_lp) {}
    void operator()(CTxMemPoolEntry &e) const { e.UpdateLockPoints(lp); }

private:
    const LockPoints &lp;
};

// extracts a TxMemPoolEntry's transaction idem
struct mempoolentry_txidem
{
    typedef uint256 result_type;
    result_type operator()(const CTxMemPoolEntry &entry) const { return entry.GetTx().GetIdem(); }
};

// extracts a TxMemPoolEntry's transaction id
struct mempoolentry_txid
{
    typedef uint256 result_type;
    result_type operator()(const CTxMemPoolEntry &entry) const { return entry.GetTx().GetId(); }
};

class CompareTxMemPoolEntryByEntryTime
{
public:
    bool operator()(const CTxMemPoolEntry &a, const CTxMemPoolEntry &b) const { return a.GetTime() < b.GetTime(); }
};

class CompareTxMemPoolEntryByAncestorFee
{
public:
    bool operator()(const CTxMemPoolEntry &a, const CTxMemPoolEntry &b) const
    {
        double aFees = a.GetModFeesWithAncestors();
        double aSize = a.GetSizeWithAncestors();

        double bFees = b.GetModFeesWithAncestors();
        double bSize = b.GetSizeWithAncestors();

        // Avoid division by rewriting (a/b > c/d) as (a*d > c*b).
        double f1 = aFees * bSize;
        double f2 = aSize * bFees;

        if (f1 == f2)
        {
            // Sorting by time here does two things when mining CPFP packages. In the case of long
            // packages, it finds the part of the package that fits perfectly into the block, because
            // we won't bail out early due to package insertion failures. Secondly it also preserves some
            // sense of fairness that, all other things begin equal, the first transation to arrive in the
            // mempool has priority over ones that follow.
            return a.GetTime() < b.GetTime();
        }

        return f1 > f2;
    }
};

// Multi_index tag names
struct descendant_score
{
};
struct entry_time
{
};
struct ancestor_score
{
};
struct txidem_tag
{
};

class CBlockPolicyEstimator;

/**
 * Information about a mempool transaction
 */
struct TxMempoolInfo
{
    /** The transaction itself */
    CTransactionRef tx;

    /** The time the transaction entered the mempool */
    int64_t nTime;

    /** The feerate of the transaction */
    CFeeRate feeRate;

    /** The fee delta */
    int64_t feeDelta;
};

/** An inpoint - a combination of a transaction and an index n into its vin */
class CInPoint
{
public:
    CTransactionRef ptx;
    uint32_t n;

    CInPoint() { SetNull(); }
    CInPoint(const CTransactionRef ptxIn, uint32_t nIn)
    {
        ptx = ptxIn;
        n = nIn;
    }
    void SetNull()
    {
        ptx = nullptr;
        n = (uint32_t)-1;
    }
    bool IsNull() const { return (ptx == nullptr && n == (uint32_t)-1); }
    size_t DynamicMemoryUsage() const { return 0; }

    /** returns the outpoint associated with this object */
    COutPoint GetOutPoint() const
    {
        assert(ptx);
        assert(n < ptx->vout.size()); // otherwise its a nonexistent outpoint
        return COutPoint(ptx->GetIdem(), n);
    }

    /** returns the value of this output in satoshis */
    CAmount GetValue() const
    {
        assert(ptx);
        assert(n < ptx->vout.size());
        return ptx->vout[n].nValue;
    }
    /** returns the constraint script */
    CScript GetConstraintScript() const
    {
        assert(ptx);
        assert(n < ptx->vout.size());
        return ptx->vout[n].scriptPubKey;
    }
    /** returns the full txout */
    const CTxOut &GetTxOut() const
    {
        assert(ptx);
        assert(n < ptx->vout.size());
        return ptx->vout[n];
    }
};

class SaltedTxidHasher
{
private:
    /** Salt */
    const uint64_t k0, k1;

public:
    SaltedTxidHasher();

    size_t operator()(const uint256 &txid) const { return SipHashUint256(k0, k1, txid); }
};

/**
 * CTxMemPool stores valid-according-to-the-current-best-chain
 * transactions that may be included in the next block.
 *
 * Transactions are added when they are seen on the network
 * (or created by the local node), but not all transactions seen
 * are added to the pool: if a new transaction double-spends
 * an input of a transaction in the pool, it is dropped,
 * as are non-standard transactions.
 *
 * CTxMemPool::mapTx, and CTxMemPoolEntry bookkeeping:
 *
 * mapTx is a boost::multi_index that sorts the mempool on 4 criteria:
 * - transaction hash
 * - feerate [we use max(feerate of tx, feerate of tx with all descendants)]
 * - time in mempool
 * - mining score (feerate modified by any fee deltas from PrioritiseTransaction)
 *
 * Note: the term "descendant" refers to in-mempool transactions that depend on
 * this one, while "ancestor" refers to in-mempool transactions that a given
 * transaction depends on.
 *
 * In order for the feerate sort to remain correct, we must update transactions
 * in the mempool when new descendants arrive.  To facilitate this, we track
 * the set of in-mempool direct parents and direct children in mapLinks.  Within
 * each CTxMemPoolEntry, we track the size and fees of all descendants.
 *
 * Usually when a new transaction is added to the mempool, it has no in-mempool
 * children (because any such children would be an orphan).  So in
 * addUnchecked(), we:
 * - update a new entry's setMemPoolParents to include all in-mempool parents
 * - update the new entry's direct parents to include the new tx as a child
 * - update all ancestors of the transaction to include the new tx's size/fee
 *
 * When a transaction is removed from the mempool, we must:
 * - update all in-mempool parents to not track the tx in setMemPoolChildren
 * - update all in-mempool children to not include it as a parent
 *
 * Computational limits:
 *
 * Updating all in-mempool ancestors of a newly added transaction can be slow,
 * if no bound exists on how many in-mempool ancestors there may be.
 * CalculateMemPoolAncestors() takes configurable limits that are designed to
 * prevent these calculations from being too CPU intensive.
 *
 * Adding transactions from a disconnected block can be very time consuming,
 * because we don't have a way to limit the number of in-mempool descendants.
 * To bound CPU processing, we limit the amount of work we're willing to do
 * to properly update the descendant information for a tx being added from
 * a disconnected block.  If we would exceed the limit, then we instead mark
 * the entry as "dirty", and set the feerate for sorting purposes to be equal
 * the feerate of the transaction without any descendants.
 *
 */
class CTxMemPool
{
private:
    uint32_t nCheckFrequency; //! Value n means that n times in 2^32 we check.
    unsigned int nTransactionsUpdated;
    CBlockPolicyEstimator *minerPolicyEstimator;

    uint64_t totalTxSize; //! sum of all mempool tx' byte sizes
    uint64_t cachedInnerUsage; //! sum of dynamic memory usage of all the map elements (NOT the maps themselves)

    std::mutex cs_txPerSec;
    double nTxPerSec GUARDED_BY(cs_txPerSec); //! txns per second accepted into the mempool
    double nInstantaneousTxPerSec GUARDED_BY(cs_txPerSec); //! instantaneous (1-second resolution) txns per second
    double nPeakRate GUARDED_BY(cs_txPerSec); //! peak rate since startup for txns per second

    /**
     * Independent atomic so that we can keep a backlog count of transactions that have been added since the last
     * transaction per second rate update calculation without blocking on the lock taken to do that calculation.
     * This is intended to reduce bottlenecking on the cs_txPerSec lock in high-throughput situations
     */
    std::atomic<uint64_t> nBackloggedTxCountForThroughputRate;

public:
    static const int ROLLING_FEE_HALFLIFE = 60 * 60 * 12; // public only for testing

    static const int TXID_CONTAINER_IDX = 0;
    static const int TXIDEM_CONTAINER_IDX = 1;

    typedef boost::multi_index_container<CTxMemPoolEntry,
        boost::multi_index::indexed_by<
            // sorted by txid
            boost::multi_index::ordered_unique<mempoolentry_txid>,
            // sorted by txidem -- 2 tx with same idem but different id necessarily conflict so must not both be in
            boost::multi_index::ordered_unique<boost::multi_index::tag<txidem_tag>, mempoolentry_txidem>,
            // sorted by entry time
            boost::multi_index::ordered_non_unique<boost::multi_index::tag<entry_time>,
                boost::multi_index::identity<CTxMemPoolEntry>,
                CompareTxMemPoolEntryByEntryTime>,
            // sorted by fee rate with ancestors
            boost::multi_index::ordered_non_unique<boost::multi_index::tag<ancestor_score>,
                boost::multi_index::identity<CTxMemPoolEntry>,
                CompareTxMemPoolEntryByAncestorFee> > >
        indexed_transaction_set;

    mutable CSharedCriticalSection cs_txmempool;
    indexed_transaction_set mapTx;
    typedef indexed_transaction_set::nth_index<TXID_CONTAINER_IDX>::type::iterator TxIdIter;
    typedef indexed_transaction_set::nth_index<TXIDEM_CONTAINER_IDX>::type::iterator TxIdemIter;
    struct CompareIteratorById
    {
        bool operator()(const TxIdIter &a, const TxIdIter &b) const { return a->GetTx().GetId() < b->GetTx().GetId(); }
    };
    typedef std::set<TxIdIter, CompareIteratorById> setEntries;
    typedef std::map<TxIdIter, ancestor_state, CTxMemPool::CompareIteratorById> mapEntryHistory;

    /** Return the set of mempool parents for this entry */
    const setEntries &GetMemPoolParents(TxIdIter entry) const;
    const setEntries GetMemPoolParents(const CTransaction &tx) const;
    /** Return the set of mempool children for this entry */
    const setEntries &GetMemPoolChildren(TxIdIter entry) const;

    /**
     * Add a double spend proof we received elsewhere to an existing mempool-entry.
     * Return CTransaction of the mempool entry we added this to.
     */
    CTransactionRef addDoubleSpendProof(const DoubleSpendProof &proof);

    DoubleSpendProofStorage *doubleSpendProofStorage() const;

private:
    typedef std::map<TxIdIter, setEntries, CompareIteratorById> cacheMap;

    struct TxLinks
    {
        setEntries parents;
        setEntries children;
    };

    typedef std::map<TxIdIter, TxLinks, CompareIteratorById> txlinksMap;
    txlinksMap mapLinks;

    void _UpdateParent(TxIdIter entry, TxIdIter parent, bool add);
    void _UpdateChild(TxIdIter entry, TxIdIter child, bool add);

public:
    // Connects an output to the transaction that spends it.
    std::map<COutPoint, CInPoint> mapNextTx;

    // Keeps track of prioritized transactions as a map of priority and fee deltas
    std::map<uint256, std::pair<double, CAmount> > mapDeltas; // uint256 is txId or idem

    // Map an outpoint to the transaction that created it
    typedef std::map<COutPoint, std::pair<uint256, size_t> > OutpointMap;

    OutpointMap outpointMap;


    // Transaction chain tips for dirty chains of transactions
    std::set<uint256> setDirtyTxnChainTips;

    /** Create a new CTxMemPool.
     *  minReasonableRelayFee should be a feerate which is, roughly, somewhere
     *  around what it "costs" to relay a transaction around the network and
     *  below which we would reasonably say a transaction has 0-effective-fee.
     */
    CTxMemPool();
    ~CTxMemPool();

    /** Atomically (with respect to the mempool) call f on each mempool entry, and then clear the mempool.
     * We user a reverse iterator so that in the case of transaction chains we'lll iterate from the beginning
     * of the chain to the end (going from lower ancestor score to higher)
     */
    template <typename Lambda>
    void forEachThenClear(const Lambda &f)
    {
        WRITELOCK(cs_txmempool);
        for (auto it = mapTx.get<ancestor_score>().rbegin(); it != mapTx.get<ancestor_score>().rend(); it--)
        {
            f(*it);
        }
        _clear();
    }
    template <typename Lambda>
    void _forEachThenClear(const Lambda &f)
    {
        AssertWriteLockHeld(cs_txmempool);
        for (auto it = mapTx.get<ancestor_score>().rbegin(); it != mapTx.get<ancestor_score>().rend(); it++)
        {
            f(*it);
        }
        _clear();
    }

    /** Atomically (with respect to the mempool) call f on each mempool entry.
     * We user a reverse iterator so that in the case of transaction chains we'lll iterate from the beginning
     * of the chain to the end (going from lower ancestor score to higher)
     */
    template <typename Lambda>
    void forEach(const Lambda &f)
    {
        WRITELOCK(cs_txmempool);
        for (auto it = mapTx.get<ancestor_score>().rbegin(); it != mapTx.get<ancestor_score>().rend(); it++)
        {
            f(*it);
        }
    }

    /**
     * If sanity-checking is turned on, check makes sure the pool is
     * consistent (does not contain two transactions that spend the same inputs,
     * all inputs are in the mapNextTx array). If sanity-checking is turned off,
     * check does nothing.
     */
    void check(const CCoinsViewCache *pcoins) const;
    void setSanityCheck(double dFrequency = 1.0) { nCheckFrequency = dFrequency * 4294967295.0; }
    // addUnchecked must updated state for all ancestors of a given transaction,
    // to track size/count of descendant transactions
    // bool addUnchecked(const uint256 &hash, const CTxMemPoolEntry &entry, bool fCurrentEstimate = true);
    // bool _addUnchecked(const uint256 &hash, const CTxMemPoolEntry &entry, bool fCurrentEstimate = true);

    bool addUnchecked(const CTxMemPoolEntry &entry, bool fCurrentEstimate = true);
    bool _addUnchecked(const CTxMemPoolEntry &entry, bool fCurrentEstimate = true);

    void removeRecursive(const CTransaction &tx, std::list<CTransactionRef> &removed);
    void _removeRecursive(const CTransaction &tx, std::list<CTransactionRef> &removed);
    void removeForReorg(const CCoinsViewCache *pcoins, unsigned int nMemPoolHeight, int flags);
    void removeConflicts(const CTransaction &tx, std::list<CTransactionRef> &removed);
    void _removeConflicts(const CTransaction &tx, std::list<CTransactionRef> &removed);
    void removeForBlock(const std::vector<CTransactionRef> &vtx,
        uint64_t nBlockHeight,
        std::list<CTransactionRef> &conflicted,
        bool fCurrentEstimate = true);
    void clear();
    void _clear(); // lock free
    /** Return the transaction ids for every transaction in the mempool */
    void queryIds(std::vector<uint256> &vtxid) const;
    /** Nonlocking: Return the transaction ids for every transaction in the mempool */
    void _queryIds(std::vector<uint256> &vtxid) const;
    /** Return the transaction ids for every transaction in the mempool */
    void queryIdems(std::vector<uint256> &vtxid) const;
    /** Nonlocking: Return the transaction ids for every transaction in the mempool */
    void _queryIdems(std::vector<uint256> &vtx) const;
    /** Return transaction references for every transaction in the mempool */
    void queryTxs(std::vector<CTransactionRef> &vtxid) const;
    /** Nonlocking: Return the transaction references for every transaction in the mempool */
    void _queryTxs(std::vector<CTransactionRef> &vtx) const;
    bool isSpent(const COutPoint &outpoint);
    unsigned int GetTransactionsUpdated() const;
    void AddTransactionsUpdated(unsigned int n);
    /**
     * Check that none of this transactions inputs are in the mempool, and thus
     * the tx is not dependent on other mempool transactions to be included in a block.
     */
    bool HasNoInputsOf(const CTransactionRef &tx) const;

    /** Affect CreateNewBlock prioritisation of transactions */
    bool PrioritiseTransaction(const uint256 hash, double dPriorityDelta, const CAmount &nFeeDelta);
    /** These functions don't actually APPLY the deltas.  They just look them up */
    void ApplyDeltas(const uint256 hash, double &dPriorityDelta, CAmount &nFeeDelta) const;
    void _ApplyDeltas(const uint256 hash, double &dPriorityDelta, CAmount &nFeeDelta) const;
    void ClearPrioritisation(const uint256 hash);
    void _ClearPrioritisation(const uint256 hash);

public:
    /** Remove a set of transactions from the mempool.
     *  If a transaction is in this set, then all in-mempool descendants must
     *  also be in the set, unless this transaction is being removed for being
     *  in a block.
     *  Set updateDescendants to true when removing a tx that was in a block, so
     *  that any in-mempool descendants have their ancestor state updated.
     */
    void _RemoveStaged(setEntries &stage);

    /** Resumbit and clear all txns currently in the txCommitQ and txCommitQFinal.
     *  This has the effect of removing and descendants for txns that were already removed
     *  from the mempool
     */
    void ResubmitCommitQ();

    /** When adding transactions from a disconnected block back to the mempool,
     *  new mempool entries may have children in the mempool (which is generally
     *  not the case when otherwise adding transactions).
     *  UpdateTransactionsFromBlock() will find child transactions and update the
     *  descendant state for each transaction in hashesToUpdate (excluding any
     *  child transactions present in hashesToUpdate, which are already accounted
     *  for).  Note: hashesToUpdate should be the set of transactions from the
     *  disconnected block that have been accepted back into the mempool.
     */
    void UpdateTransactionsFromBlock(const std::vector<uint256> &hashesToUpdate);

    /** Try to calculate all in-mempool ancestors of entry.
     *  (these are all calculated including the tx itself)
     *  limitAncestorCount = max number of ancestors
     *  limitAncestorSize = max size of ancestors
     *  errString = populated with error reason if any limits are hit
     *  fSearchForParents = whether to search a tx's vin for in-mempool parents, or
     *    look up parents from mapLinks. Must be true for entries not in the mempool
     *
     *  If you actually want the ancestor set returned, you must READLOCK(this->cs) for the duration of your
     *  use of the returned setEntries.  Therefore only the lockless version returns the ancestor set.
     */
    bool CalculateMemPoolAncestors(const CTxMemPoolEntry &entry,
        uint64_t limitAncestorCount,
        uint64_t limitAncestorSize,
        std::string &errString,
        bool fSearchForParents = true) const;
    bool _CalculateMemPoolAncestors(const CTxMemPoolEntry &entry,
        setEntries &setAncestors,
        uint64_t limitAncestorCount,
        uint64_t limitAncestorSize,
        std::string &errString,
        setEntries *inBlock = nullptr,
        bool fSearchForParents = true) const;

    /** Populate setDescendants with all in-mempool descendants of hash.  Assumes that setDescendants includes
     *  all in-mempool descendants of anything already in it.  */
    void _CalculateDescendants(TxIdIter it, setEntries &setDescendants, mapEntryHistory *mapTxnChainTips = nullptr);

    /** For a given transaction, which may be part of a chain of unconfirmed transactions, find all
     *  the associated transaction chaintips, if any.
     */
    void CalculateTxnChainTips(TxIdIter it, mapEntryHistory &mapTxnChainTips);

    /** Update the ancestor state for the set of supplied transaction chains. This step is done after
     *  a block has finished processing and we have already removed the transactions from the mempool
     */
    void UpdateTxnChainState(mapEntryHistory &mapTxnChainTips);

    /** Update the ancestor state for this transaction only. Ancestor states can be dirty or not but
     *  there are times when we need to ensure they are not dirty, such as, when we do an rpc call
     *  or prioritise a transaction.
     */
    void UpdateTxnChainState(TxIdIter it);

    /** Remove transactions from the mempool until its dynamic size is <= sizelimit.
     *  pvNoSpendsRemaining, if set, will be populated with the list of outpoints
     *  which are not in mempool which no longer have any spends in this mempool.
     */
    void TrimToSize(size_t sizelimit,
        std::vector<COutPoint> *pvNoSpendsRemaining = nullptr,
        bool fDeterministic = false);

    /** Expire all transaction (and their dependencies) in the mempool older than time. Return the number of removed
     * transactions. */
    int Expire(int64_t time, std::vector<COutPoint> &vCoinsToUncache);

    /** Remove a transaction from the mempool.  Returns the number of tx removed, 0 if the passed tx is not in the
        mempool, 1, or > 1 if this tx had dependent tx that also had to be removed */
    int Remove(const uint256 &txidOrIdem, std::vector<COutPoint> *vCoinsToUncache = nullptr);

    /** BU: Every transaction that is accepted into the mempool will call this method to update the current value*/
    void UpdateTransactionsPerSecond();

    /** Obtain current transaction rate statistics
     * Takes a lock on cs_txPerSec
     */
    void GetTransactionRateStatistics(double &smoothedTps, double &instantaneousTps, double &peakTps);

    /** Calculates updated transaction rate statistics by
     * 1. Decay the prior smoothed transaction rate by the time passed since last update
     * 2. Add transactions that have occurred since the last update to the smoothed transaction rate
     * 3. Adjust the instantaneous transaction rate if the minimum resoultion period has passed
     * 4. Update the peak transaction rate if the new instantaneous rate exceeds the prior peak value
     * Takes a lock on cs_txPerSec
     */
    void UpdateTransactionRateStatistics();

    unsigned long size() const
    {
        READLOCK(cs_txmempool);
        return mapTx.size();
    }
    unsigned long _size() const { return mapTx.size(); }
    uint64_t GetTotalTxSize()
    {
        READLOCK(cs_txmempool);
        return totalTxSize;
    }

    bool exists(const uint256 &hash) const
    {
        READLOCK(cs_txmempool);
        return (mapTx.count(hash) != 0);
    }
    bool _exists(const uint256 &hash) const { return (mapTx.count(hash) != 0); }

    bool idemExists(const uint256 &hash) const
    {
        READLOCK(cs_txmempool);
        auto &tainer = mapTx.get<txidem_tag>();
        TxIdemIter idemit = tainer.find(hash);
        if (idemit != tainer.end())
            return true;
        return false;
    }

    bool exists(const COutPoint &outpoint) const;

    CTransactionRef get(const uint256 &hash) const;
    CTransactionRef _get(const uint256 &hash) const;

    // Since this returns an entry, caller must lock, so only _ version is available
    // Checks both Id and Idem
    TxIdIter _getIdIter(const uint256 &hash) const;
    TxIdIter _getIdIter(const COutPoint &outpoint) const;

    // Since this returns an entry, caller must lock, so only _ version is available
    // Checks both Id and Idem
    const CTxMemPoolEntry *_getEntry(const uint256 &hash);

    /** Given a prevout hash, return the transaction and output offset */
    // std::tuple<CTransactionRef, size_t> _getTxIdx(const uint256 &hash) const;
    CInPoint _getTxIdx(const COutPoint &outpoint) const;
    CTxOut _get(const COutPoint &outpoint) const;

    TxMempoolInfo info(const uint256 &hash) const;
    std::vector<TxMempoolInfo> AllTxMempoolInfo() const;

    /** Estimate fee rate needed to get into the next nBlocks */
    CFeeRate estimateFee(int nBlocks) const;

    /** Write/Read estimates to disk */
    bool WriteFeeEstimates(CAutoFile &fileout) const;
    bool ReadFeeEstimates(CAutoFile &filein);

    size_t DynamicMemoryUsage() const;
    size_t _DynamicMemoryUsage() const; // no locks taken

private:
    /** Update ancestors of hash to add/remove it as a descendant transaction. */
    void _UpdateAncestorsOf(bool add, TxIdIter hash);
    /** Set ancestor state for an entry */
    void _UpdateEntryForAncestors(TxIdIter it);
    /** For each transaction being removed, update ancestors and any direct children. */
    void _UpdateForRemoveFromMempool(const setEntries &entriesToRemove);
    /** Sever link between specified transaction and direct children. */
    void UpdateChildrenForRemoval(TxIdIter entry);

    /** Remove a transaction from the mempool
     */
    void removeUnchecked(TxIdIter entry);

    /** Temporary storage for double spend proofs */
    std::unique_ptr<DoubleSpendProofStorage> m_dspStorage;
};

#ifndef ANDROID // limit dependencies (CCoinsView)
/**
 * CCoinsView that brings transactions from a memorypool into view.
 * It does not check for spendings by memory pool transactions.
 */
class CCoinsViewMemPool : public CCoinsViewBacked
{
protected:
    const CTxMemPool &mempool;

public:
    CCoinsViewMemPool(CCoinsView *baseIn, const CTxMemPool &mempoolIn);
    bool GetCoin(const COutPoint &outpoint, Coin &coin) const;
    bool HaveCoin(const COutPoint &outpoint) const;
};
#endif

// We want to sort transactions by coin age priority
typedef std::pair<double, CTxMemPool::TxIdIter> TxCoinAgePriority;

struct TxCoinAgePriorityCompare
{
    bool operator()(const TxCoinAgePriority &a, const TxCoinAgePriority &b)
    {
        // Reverse order to make sort less than
        if (a.first == b.first)
            return CompareTxMemPoolEntryByAncestorFee()(*(b.second), *(a.second));
        return a.first < b.first;
    }
};

#endif // NEXA_TXMEMPOOL_H
