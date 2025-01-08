// Copyright (c) 2016-2023 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_PARALLEL_H
#define NEXA_PARALLEL_H

#include "checkqueue.h"
#include "consensus/validation.h"
#include "main.h"
#include "primitives/block.h"
#include "protocol.h"
#include "script/sigcache.h"
#include "serialize.h"
#include "stat.h"
#include "uint256.h"
#include "util.h"
#include <vector>

#include <thread>

#include <boost/thread.hpp>

static const bool DEFAULT_PV_TESTMODE = false;

/**
 * Class that keeps track of number of signature operations
 * and bytes hashed to compute signature hashes.
 */
class ValidationResourceTracker
{
private:
    mutable CCriticalSection cs_resource_tracker;

    /** counts the number of sigops/potential sigops from the script machine resource tracker */
    uint64_t consensusSigChecks = 0;

public:
    unsigned char sighashtype = 0;

    ValidationResourceTracker() {}
    ValidationResourceTracker(const ValidationResourceTracker &c)
    {
        LOCK(cs_resource_tracker);
        consensusSigChecks = c.consensusSigChecks;
        sighashtype = c.sighashtype;
    }

    /** Update 2020-05-15 sigchecks consensus rule sigop count
        @param ops added to the current count
     */
    void UpdateConsensusSigChecks(uint64_t ops)
    {
        LOCK(cs_resource_tracker);
        consensusSigChecks += ops;
    }

    /** Get 2020-05-15 sigchecks consensus rule sigop count
        @returns current number of sigops */
    uint64_t GetConsensusSigChecks() const
    {
        LOCK(cs_resource_tracker);
        return consensusSigChecks;
    }
};

/**
 * Closure representing one script verification
 * Note that this stores references to the spending transaction
 */
class CScriptCheck
{
protected:
    ValidationResourceTracker *resourceTracker;
    CScript scriptPubKey;
    bool cacheStore;
    ScriptError error;
    CachingTransactionSignatureChecker checker;
    ScriptImportedState sis;

public:
    CScriptCheck() : resourceTracker(nullptr), cacheStore(false), error(SCRIPT_ERR_UNKNOWN_ERROR) {}

    // This constructor is for tests that do not use any introspection opcodes.
    CScriptCheck(ValidationResourceTracker *resourceTrackerIn,
        const CScript &scriptPubKeyIn,
        const CAmount amountInObsolete,
        const CTransaction &txIn,
        const std::vector<CTxOut> &coins,
        unsigned int inputIdx,
        unsigned int nFlagsIn,
        bool cacheIn)
        : resourceTracker(resourceTrackerIn), scriptPubKey(scriptPubKeyIn), cacheStore(cacheIn),
          error(SCRIPT_ERR_UNKNOWN_ERROR), checker(&txIn, inputIdx, txIn.vin[inputIdx].amount, nFlagsIn, cacheStore),
          sis(&checker, MakeTransactionRef(txIn), CValidationState(), coins, inputIdx)
    {
        assert(inputIdx < txIn.vin.size());
    }

    CScriptCheck(ValidationResourceTracker *resourceTrackerIn,
        const CScript &scriptPubKeyIn,
        const CAmount amountIn,
        const CTransactionRef &txIn,
        const std::vector<CTxOut> &coins,
        const CValidationState &validationData,
        unsigned int inputIdx,
        unsigned int nFlagsIn,
        bool cacheIn)
        : resourceTracker(resourceTrackerIn), scriptPubKey(scriptPubKeyIn), cacheStore(cacheIn),
          error(SCRIPT_ERR_UNKNOWN_ERROR),
          checker(&(*txIn), inputIdx, txIn->vin[inputIdx].amount, nFlagsIn, cacheStore),
          sis(&checker, txIn, validationData, coins, inputIdx)
    {
        assert(inputIdx < txIn->vin.size());
    }

    bool operator()();

    void swap(CScriptCheck &check)
    {
        std::swap(resourceTracker, check.resourceTracker);
        scriptPubKey.swap(check.scriptPubKey);
        std::swap(cacheStore, check.cacheStore);
        std::swap(error, check.error);
        std::swap(checker, check.checker);
        std::swap(sis, check.sis);
        // local script state should always point to its own checker so undo the swap of these pointers
        sis.checker = &checker;
        check.sis.checker = &check.checker;
    }

    ScriptError GetScriptError() const { return error; }
};

class CParallelValidation
{
public:
    CCriticalSection cs_blockvalidationthread;

private:
    /** Vector of script check queues */
    std::vector<CCheckQueue<CScriptCheck> *> vQueues;
    /** Number of threads */
    unsigned int nThreads;
    /** All threads currently available */
    boost::thread_group threadGroup;
    /** The semaphore limits the number of parallel validation threads */
    CSemaphore semThreadCount;
    /** The number of threads currently being used for block validation */
    std::atomic<unsigned int> numBlocksValidating{0};

    struct CHandleBlockMsgThreads
    {
        CCheckQueue<CScriptCheck> *pScriptQueue;
        uint256 hash;
        uint256 hashPrevBlock;
        uint32_t nChainWork; // chain work for this block.
        uint32_t nMostWorkOurFork; // most work for the chain we are on.
        uint64_t nSequenceId;
        int64_t nStartTime;
        uint64_t nBlockSize;
        bool fQuit;
        NodeId nodeid;
        bool fIsValidating; // is the block currently in connectblock() and validating inputs
        bool fIsReorgInProgress; // has a re-org to another chain been triggered.
    };
    std::map<boost::thread::id, CHandleBlockMsgThreads> mapBlockValidationThreads GUARDED_BY(cs_blockvalidationthread);

public:
    /**
     * Construct a parallel validator.
     * @param[in] threadCount   The number of script validation threads.  If <= 1 then no separate validation threads
     *                          are created.
     * @param[in] threadGroup   The thread group threads will be created in
     */
    CParallelValidation();

    ~CParallelValidation();

    /** Initialize mapBlockValidationThreads */
    void InitThread(const boost::thread::id this_id,
        const CNode *pfrom,
        ConstCBlockRef pblock,
        const uint256 &hash,
        uint64_t blockSize);

    /** Number of block validation threads currently validating a block */
    unsigned int NumBlocksValidating() { return numBlocksValidating.load(); }
    /** Initialize a PV session */
    bool Initialize(const boost::thread::id this_id, const CBlockIndex *pindex, const bool fParallel);

    /** Cleanup PV threads after one has finished and won the validation race */
    void Cleanup(const ConstCBlockRef pblock, CBlockIndex *pindex);

    /** Send quit to competing threads */
    void QuitCompetingThreads(const uint256 &prevBlockHash);

    /** Is this block already running a validation thread? */
    bool IsAlreadyValidating(const NodeId id, const uint256 blockhash);

    /** Terminate all currently running Block Validation threads, except the passed thread */
    void StopAllValidationThreads(const boost::thread::id this_id = boost::thread::id());
    /** Terminate all currently running Block Validation threads whose chainWork is <= the passed parameter, except the
     * calling thread
     */
    void StopAllValidationThreads(const uint32_t nChainWork);
    void WaitForAllValidationThreadsToStop();

    /** Has parallel block validation been turned on via the config settings */
    bool Enabled();

    /** Clear thread data from mapBlockValidationThreads */
    void Erase(const boost::thread::id this_id);

    /** Quit a block validation thread and associated script validation threads */
    void Quit(std::map<boost::thread::id, CHandleBlockMsgThreads>::iterator iter);

    /** Post the semaphore when the thread exits.  */
    void Post() { semThreadCount.post(); }
    /** Was the fQuit flag set to true which causes the PV thread to exit */
    bool QuitReceived(const boost::thread::id this_id, const bool fParallel);

    /** Used to determine if another thread has already updated the utxo and advance the chain tip */
    bool ChainWorkHasChanged(const arith_uint256 &nStartingChainWork);

    /** Set the correct locks and locking order before returning from a PV session */
    void SetLocks(const bool fParallel);

    /** Is there a re-org in progress */
    void MarkReorgInProgress(const boost::thread::id this_id, const bool fReorg, const bool fParallel);
    bool IsReorgInProgress();
    bool BlockExtendsChain(const ConstCBlockRef pblock);

    /** Update the nMostWorkOurFork when a new header arrives */
    void UpdateMostWorkOurFork(const CBlockHeader &header);

    /** Update the nMostWorkOurFork when a new header arrives */
    uint32_t MaxWorkChainBeingProcessed();

    /** Process a block message */
    void HandleBlockMessage(CNode *pfrom, const std::string &strCommand, ConstCBlockRef pblock, const uint256 &hash);

    /** The number of script validation threads */
    unsigned int ThreadCount() { return nThreads; }
    /** The number of script check queues */
    unsigned int QueueCount();

    /** For newly mined block validation, return the first queue not in use. */
    CCheckQueue<CScriptCheck> *GetScriptCheckQueue();
};

extern std::unique_ptr<CParallelValidation> PV; // Singleton class

#endif // NEXA_PARALLEL_H
