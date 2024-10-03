// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Copyright (C) 2019-2020 Tom Zander <tomz@freedommail.ch>
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "txmempool.h"

#include "consensus/consensus.h"
#include "consensus/tx_verify.h"
#include "consensus/validation.h"
#include "core_io.h"
#include "init.h"
#include "main.h"
#include "policy/fees.h"
#include "respend/dsproof.h"
#include "respend/dsproofstorage.h"
#include "streams.h"
#include "timedata.h"
#include "txadmission.h"
#include "txorphanpool.h"
#include "unlimited.h"
#include "util.h"
#include "utilmoneystr.h"
#include "utiltime.h"
#include "validation/validation.h"
#include "version.h"

#include <mutex>

extern std::atomic<bool> fMempoolTests;

static CTxMemPool::setEntries emptySetEntries;
using namespace std;
CTxMemPoolEntry::CTxMemPoolEntry()
    : tx(), nFee(), nTime(0), entryPriority(0), entryHeight(0), hadNoDependencies(0), inChainInputValue(0),
      spendsCoinbase(false), sigOpCount(0), lockPoints()
{
    nModSize = 0;
    nUsageSize = 0;
    feeDelta = 0;
}

CTxMemPoolEntry::~CTxMemPoolEntry() { tx = nullptr; }

CTxMemPoolEntry::CTxMemPoolEntry(const CTransactionRef _tx,
    const CAmount &_nFee,
    int64_t _nTime,
    double _entryPriority,
    unsigned int _entryHeight,
    bool poolHasNoInputsOf,
    CAmount _inChainInputValue,
    bool _spendsCoinbase,
    unsigned int _sigOps,
    LockPoints lp)
    : tx(_tx), nFee(_nFee), nTime(_nTime), entryPriority(_entryPriority), entryHeight(_entryHeight),
      hadNoDependencies(poolHasNoInputsOf), inChainInputValue(_inChainInputValue), spendsCoinbase(_spendsCoinbase),
      sigOpCount(_sigOps), lockPoints(lp)
{
    nModSize = tx->CalculateModifiedSize(tx->GetTxSize());
    nUsageSize = RecursiveDynamicUsage(*tx);

    CAmount nValueIn = tx->GetValueOut() + nFee;
    DbgAssert(inChainInputValue <= nValueIn, );
    feeDelta = 0;

    nCountWithAncestors = 1;
    nSizeWithAncestors = tx->GetTxSize();
    nModFeesWithAncestors = nFee;
    nSigOpCountWithAncestors = sigOpCount;
    fDirty = false;
}

double CTxMemPoolEntry::GetPriority(unsigned int currentHeight) const
{
    double deltaPriority = ((double)(currentHeight - entryHeight) * inChainInputValue) / nModSize;
    double dResult = entryPriority + deltaPriority;
    if (dResult < 0) // This should only happen if it was called with a height below entry height
        dResult = 0;
    return dResult;
}

void CTxMemPoolEntry::UpdateFeeDelta(int64_t newFeeDelta)
{
    nModFeesWithAncestors += newFeeDelta - feeDelta;
    feeDelta = newFeeDelta;
}

void CTxMemPoolEntry::UpdateLockPoints(const LockPoints &lp) { lockPoints = lp; }
void CTxMemPoolEntry::UpdateRuntimeSigOps(uint64_t _runtimeSigOpCount, uint64_t _runtimeSighashBytes)
{
    runtimeSigOpCount = _runtimeSigOpCount;
    runtimeSighashBytes = _runtimeSighashBytes;
}

// vTxIdsToUpdate is the set of transaction Ids from a disconnected block
// which has been re-added to the mempool.
// for each entry, look for descendants that are outside hashesToUpdate, and
// add fee/size information for such descendants to the parent.
// for each such descendant, also update the ancestor state to include the parent.
void CTxMemPool::UpdateTransactionsFromBlock(const std::vector<uint256> &vTxIdsToUpdate)
{
    WRITELOCK(cs_txmempool);

    // Use a set for lookups into vTxIdsToUpdate (these entries are already
    // accounted for in the state of their ancestors)
    std::set<uint256> setAlreadyIncluded(vTxIdsToUpdate.begin(), vTxIdsToUpdate.end());

    // Iterate in reverse, so that whenever we are looking at a transaction
    // we are sure that all in-mempool descendants have already been processed.
    // This maximizes the benefit of the descendant cache and guarantees that
    // setMemPoolChildren will be updated, an assumption made in
    // UpdateForDescendants.
    for (auto i = vTxIdsToUpdate.rbegin(); i != vTxIdsToUpdate.rend(); i++)
    {
        const uint256 &hash = *i;
        // we cache the in-mempool children to avoid duplicate updates
        setEntries setChildren;
        // calculate children from mapNextTx
        TxIdIter it = mapTx.find(hash);
        if (it == mapTx.end())
        {
            continue;
        }

        // First calculate the children, and update setMemPoolChildren to
        // include them, and update their setMemPoolParents to include this tx.
        for (int j = 0;; j++)
        {
            std::unordered_map<COutPoint, CInPoint, OutPointHasher>::const_iterator iter =
                mapNextTx.find(COutPoint(hash, j));
            if (iter == mapNextTx.end())
                break;
            const uint256 &childHash = iter->second.ptx->GetId();
            TxIdIter childIter = mapTx.find(childHash);
            assert(childIter != mapTx.end());
            // We can skip updating entries we've encountered before or that
            // are in the block (which are already accounted for).
            if (setChildren.insert(childIter).second && !setAlreadyIncluded.count(childHash))
            {
                _UpdateParentChild(it, childIter, true);
            }
        }
    }
}

bool CTxMemPool::CalculateMemPoolAncestors(const CTxMemPoolEntry &entry,
    uint64_t limitAncestorCount,
    uint64_t limitAncestorSize,
    std::string &errString,
    bool fSearchForParents /* = true */) const
{
    READLOCK(cs_txmempool);
    setEntries setAncestors;
    return _CalculateMemPoolAncestors(
        entry, setAncestors, limitAncestorCount, limitAncestorSize, errString, nullptr, fSearchForParents);
}


bool CTxMemPool::_CalculateMemPoolAncestors(const CTxMemPoolEntry &entry,
    setEntries &setAncestors,
    uint64_t limitAncestorCount,
    uint64_t limitAncestorSize,
    std::string &errString,
    setEntries *inBlock /* = nullptr */,
    bool fSearchForParents /* = true */) const
{
    AssertLockHeld(cs_txmempool);

    // inBlock and fSearchForParents can not both be true.
    bool fBothTrue = (inBlock && fSearchForParents);
    DbgAssert(!fBothTrue, );

    setEntries parentHashes;
    const CTransaction &tx = entry.GetTx();

    if (fSearchForParents)
    {
        // Get parents of this transaction that are in the txpool.
        // Our current transaction ("entry") is not yet in the txpool so we can not look for its
        // parents using GetMemPoolParents(). Therefore we need to instead lookup the parents
        // by using the inputs of this transaction.
        for (unsigned int i = 0; i < tx.vin.size(); i++)
        {
            auto prevout = outpointMap.find(tx.vin[i].prevout);
            if (prevout == outpointMap.end())
            {
                continue;
            }
            if (tx.vin[i].IsReadOnly())
            {
                errString = strprintf("TX has a read-only txpool input.  It should NOT be in the txpool!");
                DbgAssert(!tx.vin[i].IsReadOnly(), return false);
            }
            const uint256 &phash = prevout->second.first;
            TxIdIter piter = mapTx.find(phash);
            if (piter != mapTx.end()) // If the parent is still in the txpool...
            {
                parentHashes.insert(piter);
                if (parentHashes.size() + 1 > limitAncestorCount)
                {
                    errString = strprintf(
                        "too many unconfirmed parents: %u [limit: %u]", parentHashes.size(), limitAncestorCount);
                    return false;
                }
            }
        }
    }
    else
    {
        // If we're not searching for parents, we require this to be an
        // entry in the mempool already.
        TxIdIter it = mapTx.iterator_to(entry);
        parentHashes = GetMemPoolParents(it);
    }

    size_t totalSizeWithAncestors = entry.GetTxSize();

    while (!parentHashes.empty())
    {
        auto parentElemIter = parentHashes.begin();
        TxIdIter stageit = *parentHashes.begin();

        // If inBlock then we only return a set of ancestors that have not yet been added to a block.
        //
        // Once we find a parent that is in a block we stop looking further on that ancestor chain, because
        // if that parent is in the block then all of it's ancestors must also be in the block.
        if (inBlock)
        {
            if (!inBlock->count(stageit))
            {
                setAncestors.insert(stageit);
            }
            else
            {
                parentHashes.erase(parentElemIter);
                continue;
            }
        }
        else
        {
            setAncestors.insert(stageit);
        }

        totalSizeWithAncestors += stageit->GetTxSize();

        if (totalSizeWithAncestors > limitAncestorSize)
        {
            errString =
                strprintf(" %u exceeds ancestor size limit [limit: %u]", totalSizeWithAncestors, limitAncestorSize);
            return false;
        }

        const setEntries &setMemPoolParents = GetMemPoolParents(stageit);
        for (const TxIdIter &phash : setMemPoolParents)
        {
            // If this is a new ancestor, add it.
            if (setAncestors.count(phash) == 0)
            {
                parentHashes.insert(phash);
            }

            // removed +1 from test below as per BU: Fix use after free bug
            if (parentHashes.size() + setAncestors.size() > limitAncestorCount)
            {
                setAncestors.insert(parentHashes.begin(), parentHashes.end());
                errString = strprintf("too many unconfirmed ancestors (%u+%u) [limit: %u]", parentHashes.size(),
                    setAncestors.size(), limitAncestorCount);
                return false;
            }
        }

        parentHashes.erase(parentElemIter);
    }

    return true;
}

void CTxMemPool::_UpdateAncestorsOf(bool add, TxIdIter it)
{
    AssertWriteLockHeld(cs_txmempool);
    setEntries setParents = GetMemPoolParents(it);
    // add or remove this tx as a child of each parent
    for (TxIdIter piter : setParents)
    {
        _UpdateParentChild(piter, it, add);
    }
}

void CTxMemPool::_UpdateEntryForAncestors(TxIdIter it)
{
    AssertWriteLockHeld(cs_txmempool);
    int64_t updateCount = 0;
    int64_t updateSize = 0;
    CAmount updateFee = 0;
    int updateSigOps = 0;
    bool fDirty = false;
    bool fParentIsDirty = false;

    setEntries setParents = GetMemPoolParents(it);
    for (TxIdIter parent : setParents)
    {
        updateSize += parent->GetSizeWithAncestors();
        updateFee += parent->GetModFeesWithAncestors();
        updateSigOps += parent->GetSigOpCountWithAncestors();
        updateCount += parent->GetCountWithAncestors();

        if (parent->IsDirty())
            fParentIsDirty = true;
    }

    // If we have more than one parent then we can't really know how many ancestors we
    // have without calling CalulateMemPoolAncestors(), which as transaction chains become
    // longer, has a marked negative performance impact. So rather than do that we mark the transaction
    // state as dirty. Then later we can update the entire chain state all at once, at various
    // defined intervals, and also we can mine any "dirty" chains if there is
    // still space in the block for them.
    if (setParents.size() > 1 || fParentIsDirty)
    {
        // If we're still a small length chain then update the correct chain state. We use a flag
        // fMempoolTests so that we can turn off this auto updating which makes our mempool unit
        // testing easier to do.
        if (updateCount <= MAX_UPDATED_CHAIN_STATE && !fParentIsDirty && fMempoolTests.load() == false)
        {
            size_t nLimitAncestors = MAX_UPDATED_CHAIN_STATE;
            size_t nLimitAncestorSize = std::numeric_limits<uint64_t>::max();
            std::string errString;
            CTxMemPool::setEntries setAncestors;
            _CalculateMemPoolAncestors(*it, setAncestors, nLimitAncestors, nLimitAncestorSize, errString);
            setAncestors.erase(it);

            updateCount = 0;
            updateSize = 0;
            updateFee = 0;
            updateSigOps = 0;
            for (TxIdIter iter : setAncestors)
            {
                updateSize += iter->GetTxSize();
                updateFee += iter->GetFee();
                updateSigOps += iter->GetSigOpCount();
            }
            updateCount = setAncestors.size();

            fDirty = false;
        }
        else
        {
            fDirty = true;

            // If the parents are not dirty then this is a new dirty chaintip and
            // we need to save it for later so that the entire chain state can be
            // properly updated at some point in time.
            if (!fParentIsDirty)
                setDirtyTxnChainTips.insert(it->GetTx().GetId());
        }
    }

    mapTx.modify(it, update_ancestor_state(updateSize, updateFee, updateCount, updateSigOps, fDirty));
}

void CTxMemPool::UpdateChildrenForRemoval(TxIdIter it)
{
    AssertWriteLockHeld(cs_txmempool);
    const setEntries &setMemPoolChildren = GetMemPoolChildren(it);
    // This awkwardness is because the iterator is not stable if it is the element being deleted
    for (auto child = setMemPoolChildren.begin(); child != setMemPoolChildren.end();)
    {
        auto deleteMe = child;
        child++;
        _UpdateParentChild(it, *deleteMe, false);
    }
}

void CTxMemPool::CalculateTxnChainTips(TxIdIter it, mapEntryHistory &mapTxnChainTips)
{
    // Iterate through all the parents of this transaction to find the chaintips. The chaintips
    // will be the transaction/s that has/have no parents.
    AssertLockHeld(cs_txmempool);
    setEntries parents = GetMemPoolParents(it);
    if (parents.empty())
    {
        return;
    }

    while (!parents.empty())
    {
        TxIdIter parentIter = *parents.begin();
        const setEntries &nextParents = GetMemPoolParents(parentIter);
        parents.erase(parents.begin());

        if (nextParents.empty())
        {
            DbgAssert(!parentIter->IsDirty(), );

            // Add the chaintip
            ancestor_state ancestorState(parentIter->GetSizeWithAncestors(), parentIter->GetModFeesWithAncestors(),
                parentIter->GetCountWithAncestors(), parentIter->GetSigOpCountWithAncestors());
            mapTxnChainTips.emplace(parentIter, ancestorState);
        }
        else
            parents.insert(nextParents.begin(), nextParents.end());
    }
}

void CTxMemPool::UpdateTxnChainState(TxIdIter it)
{
    AssertWriteLockHeld(cs_txmempool);
    if (it->IsDirty())
    {
        CTxMemPool::mapEntryHistory mapTxnChainTips;
        mempool.CalculateTxnChainTips(it, mapTxnChainTips);
        if (!mapTxnChainTips.empty())
            mempool.UpdateTxnChainState(mapTxnChainTips);
    }
}

void CTxMemPool::UpdateTxnChainState(mapEntryHistory &mapTxnChainTips)
{
    AssertWriteLockHeld(cs_txmempool);

    // As a starting point, re-calculate all chaintip ancestor states. Although at least one chaintip
    // parent will have been mined there could still be other chaintip parents that were not mined.
    // And mark the ancestor state as not "dirty".
    /*
       Chain prior to being mined:

       tx1        tx2      tx3
         \        |       /
          \______ tx4____/


       Chain after being mined:
       Only tx1 and tx2 are mined leaving tx4 as the chaintip, and tx3 becomes an unmined
       chaintip parent and is not considered a chaintip in the program logic even though clearly
       it is in fact the new chaintip.

                         tx3 (unmined chain so it has no entry in mapTxnChainTips)
                          /
                  tx4____/   (tx4 becomes the chaintip in mapTxnChainTips)

    */

    for (auto iter_tip : mapTxnChainTips)
    {
        uint64_t nNoLimit = std::numeric_limits<uint64_t>::max();
        std::string dummy;
        int64_t nAncestorCount = 0;
        int64_t nAncestorSize = 0;
        int nAncestorSigOps = 0;
        CAmount nAncestorModifiedFee(0);

        setEntries setAncestors;
        setAncestors.insert(iter_tip.first);
        _CalculateMemPoolAncestors(*(iter_tip.first), setAncestors, nNoLimit, nNoLimit, dummy);
        for (auto it : setAncestors)
        {
            nAncestorCount += 1;
            nAncestorSize += it->GetTxSize();
            nAncestorSigOps += it->GetSigOpCount();
            nAncestorModifiedFee += it->GetModifiedFee();
        }
        mapTx.modify(iter_tip.first,
            replace_ancestor_state(nAncestorSize, nAncestorModifiedFee, nAncestorCount, nAncestorSigOps, false));
    }

    // For each txnChainTip find the difference between the new chain tip ancestor state
    // values and old new ancestor state values and apply them to all of the descendants, and
    // mark the new state as not "dirty".
    for (auto iter_tip : mapTxnChainTips)
    {
        // Find difference
        int64_t nAncestorCountDiff = iter_tip.first->GetCountWithAncestors() - iter_tip.second.modifyCount;
        int64_t nAncestorSizeDiff = iter_tip.first->GetSizeWithAncestors() - iter_tip.second.modifySize;
        int nAncestorSigOpsDiff = iter_tip.first->GetSigOpCountWithAncestors() - iter_tip.second.modifySigOps;
        CAmount nAncestorModifiedFeeDiff = iter_tip.first->GetModFeesWithAncestors() - iter_tip.second.modifyFee;

        // Get descendants but stop looking if/when we find another txnchaintip in the descendant tree.
        setEntries setDescendants;
        _CalculateDescendants(iter_tip.first, setDescendants, &mapTxnChainTips);

        // Remove the txnChainTip since it has already been updated
        setDescendants.erase(iter_tip.first);

        // Apply the difference in sorted order
        for (TxIdIter it : setDescendants)
        {
            assert(!mapTxnChainTips.count(it));
            mapTx.modify(it, update_ancestor_state(nAncestorSizeDiff, nAncestorModifiedFeeDiff, nAncestorCountDiff,
                                 nAncestorSigOpsDiff, false));
        }
    }
}

void CTxMemPool::_UpdateForRemoveFromMempool(const setEntries &entriesToRemove)
{
    AssertWriteLockHeld(cs_txmempool);
    for (TxIdIter removeIt : entriesToRemove)
    {
        // Since this is a tx that is already in the mempool, we can call CMPA
        // with fSearchForParents = false.  If the mempool is in a consistent
        // state, then using true or false should both be correct, though false
        // should be a bit faster.
        // However, if we happen to be in the middle of processing a reorg, then
        // the mempool can be in an inconsistent state.  In this case, the set
        // of ancestors reachable via mapLinks will be the same as the set of
        // ancestors whose packages include this transaction, because when we
        // add a new transaction to the mempool in addUnchecked(), we assume it
        // has no children, and in the case of a reorg where that assumption is
        // false, the in-mempool children aren't linked to the in-block tx's
        // until UpdateTransactionsFromBlock() is called.
        // So if we're being called during a reorg, ie before
        // UpdateTransactionsFromBlock() has been called, then mapLinks[] will
        // differ from the set of mempool parents we'd calculate by searching,
        // and it's important that we use the mapLinks[] notion of ancestor
        // transactions as the set of things to update for removal.
        //
        // Note that UpdateAncestorsOf severs the child links that point to
        // removeIt in the entries for the parents of removeIt.  This is
        // fine since we don't need to use the mempool children of any entries
        // to walk back over our ancestors (but we do need the mempool
        // parents!)
        _UpdateAncestorsOf(false, removeIt);
    }
    // After updating all the ancestor sizes, we can now sever the link between each
    // transaction being removed and any mempool children (ie, update setMemPoolParents
    // for each direct child of a transaction being removed).
    for (TxIdIter removeIt : entriesToRemove)
    {
        UpdateChildrenForRemoval(removeIt);
    }
}

void CTxMemPoolEntry::UpdateAncestorState(int64_t modifySize,
    CAmount modifyFee,
    int64_t modifyCount,
    int modifySigOps,
    bool dirty)
{
    // Ancestor state can be modified by subtraction so we use a DbgAssert here to make sure
    // we don't accitdentally trigger these asserts on mainnet.
    nSizeWithAncestors += modifySize;
    DbgAssert(int64_t(nSizeWithAncestors) > 0, );
    nModFeesWithAncestors += modifyFee;
    nCountWithAncestors += modifyCount;
    DbgAssert(int64_t(nCountWithAncestors) > 0, );
    nSigOpCountWithAncestors += modifySigOps;
    DbgAssert(int(nSigOpCountWithAncestors) >= 0, );

    // if (dbgName.size())
    //    printf("%s: Updated Ancestor state: nSizeWithAncestors=%lu nModFeesWithAncestors=%lu
    //    nCountWithAncestors=%lu\n",
    //        dbgName.c_str(), nSizeWithAncestors, nModFeesWithAncestors, nCountWithAncestors);
    fDirty = dirty;
}

void CTxMemPoolEntry::ReplaceAncestorState(int64_t modifySize,
    CAmount modifyFee,
    int64_t modifyCount,
    int modifySigOps,
    bool dirty)
{
    nSizeWithAncestors = modifySize;
    assert(int64_t(nSizeWithAncestors) > 0);
    nModFeesWithAncestors = modifyFee;
    nCountWithAncestors = modifyCount;
    assert(int64_t(nCountWithAncestors) > 0);
    nSigOpCountWithAncestors = modifySigOps;
    assert(int(nSigOpCountWithAncestors) >= 0);

    fDirty = dirty;

    // if (dbgName.size())
    // {
    //    printf("%s: Replace Ancestor state: nSizeWithAncestors=%lu nModFeesWithAncestors=%lu
    //    nCountWithAncestors=%lu\n",
    //        dbgName.c_str(), nSizeWithAncestors, nModFeesWithAncestors, nCountWithAncestors);
    // }
}

CTxMemPool::CTxMemPool() : nTransactionsUpdated(0), m_dspStorage(new DoubleSpendProofStorage())
{
    clear();

    // Sanity checks off by default for performance, because otherwise
    // accepting transactions becomes O(N^2) where N is the number
    // of transactions in the pool
    nCheckFrequency = 0;

    minerPolicyEstimator = new CBlockPolicyEstimator(minRelayTxFee);

    nBackloggedTxCountForThroughputRate = 0;
    nTxPerSec = 0;
    nInstantaneousTxPerSec = 0;
    nPeakRate = 0;
}

CTxMemPool::~CTxMemPool() { delete minerPolicyEstimator; }
bool CTxMemPool::isSpent(const COutPoint &outpoint)
{
    AssertLockHeld(cs_txmempool);
    return mapNextTx.count(outpoint);
}

unsigned int CTxMemPool::GetTransactionsUpdated() const
{
    READLOCK(cs_txmempool);
    return nTransactionsUpdated;
}

void CTxMemPool::AddTransactionsUpdated(unsigned int n)
{
    WRITELOCK(cs_txmempool);
    nTransactionsUpdated += n;
}

bool CTxMemPool::_addUnchecked(const CTxMemPoolEntry &entry, bool fCurrentEstimate)
{
    const uint256 &txid = entry.GetTx().GetId();
    const uint256 &txidem = entry.GetTx().GetIdem();
    // Add to memory pool without checking anything.
    // Used by main.cpp AcceptToMemoryPool(), which DOES do
    // all the appropriate checks.
    AssertWriteLockHeld(cs_txmempool);
    if (mapTx.find(txid) != mapTx.end()) // already inserted
    {
        return true;
    }
    indexed_transaction_set::iterator newit = mapTx.insert(entry).first;
    mapLinks.insert(make_pair(newit, TxLinks()));

    // Update transaction for any feeDelta created by PrioritiseTransaction
    // TODO: refactor so that the fee delta is calculated before inserting
    // into mapTx.  Either id or idem can be used
    std::unordered_map<uint256, std::pair<double, CAmount>, uint256Hasher>::const_iterator pos = mapDeltas.find(txid);
    if (pos == mapDeltas.end())
        pos = mapDeltas.find(txidem);
    if (pos != mapDeltas.end())
    {
        const std::pair<double, CAmount> &deltas = pos->second;
        if (deltas.second)
        {
            mapTx.modify(newit, update_fee_delta(deltas.second));
        }
    }

    // Update cachedInnerUsage to include contained transaction's usage.
    // (When we update the entry for in-mempool parents, memory usage will be
    // further updated.)
    cachedInnerUsage += entry.DynamicMemoryUsage();

    const CTransaction &tx = newit->GetTx();
    const CTransactionRef &txref = newit->GetSharedTx();
    std::set<COutPoint> setParents;
    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        auto &prevout = tx.vin[i].prevout;
        if (tx.vin[i].IsReadOnly())
        {
            auto &deps = mapRoTx[prevout];
            size_t sz = deps.size();
            LOG(MEMPOOL, "starting deps of this UTXO: %d", sz);
            deps.emplace(CInPoint{txref, i});
            if (deps.size() == sz)
            {
                LOG(MEMPOOL, "REPEAT RO ADD");
            }
            LOG(MEMPOOL, "Added RO dependency for TX idem %s to UTXO %s. mapRoTx size: %d, Deps of this UTXO: %d",
                txref->GetIdem().GetHex(), prevout.GetHex(), mapRoTx.size(), deps.size());
            auto &deps2 = mapRoTx[prevout];
            LOG(MEMPOOL, "Recheck Deps of this UTXO: %d", deps2.size());
            for (const auto &it : mapRoTx)
            {
                LOG(MEMPOOL, "RO Entry: %s has %s deps", it.first.GetHex(), it.second.size());
                for (const auto &depsIt : it.second)
                {
                    LOG(MEMPOOL, "   %s:%d", depsIt.ptx->GetIdem().GetHex(), depsIt.n);
                }
            }
        }
        else
        {
            mapNextTx.emplace(tx.vin[i].prevout, CInPoint{txref, i});
        }
        setParents.insert(tx.vin[i].prevout);
    }

    // Connect this transaction's outpoints with this transaction's hash and vout index
    // for easy lookup to see if a transaction spends something in the mempool.
    for (size_t i = 0; i < tx.vout.size(); i++)
    {
        outpointMap.emplace(tx.OutpointAt(i), std::pair<uint256, size_t>(tx.GetId(), i));
    }

    // Don't bother worrying about child transactions of this one.
    // Normal case of a new transaction arriving is that there can't be any
    // children, because such children would be orphans.
    // An exception to that is if a transaction enters that used to be in a block.
    // In that case, our disconnect block logic will clean up the mess we're leaving here.

    // Update ancestors with information about this tx
    for (const auto &prev : setParents)
    {
        auto prevout = outpointMap.find(prev);
        if (prevout == outpointMap.end()) // the previous transaction is not in the mempool
        {
            continue;
        }
        uint256 phash = prevout->second.first;
        TxIdIter pit = mapTx.find(phash);
        if (pit != mapTx.end())
        {
            _UpdateParentChild(pit, newit, true);
        }
    }

    _UpdateAncestorsOf(true, newit);
    _UpdateEntryForAncestors(newit);

    nTransactionsUpdated++;
    totalTxSize += entry.GetTxSize();
    txAdded += 1; // BU
    poolSize() = totalTxSize; // BU
    minerPolicyEstimator->processTransaction(entry, fCurrentEstimate);

    return true;
}

bool CTxMemPool::addUnchecked(const CTxMemPoolEntry &entry, bool fCurrentEstimate)
{
    WRITELOCK(cs_txmempool);
    return _addUnchecked(entry, fCurrentEstimate);
}

void CTxMemPool::removeUnchecked(TxIdIter it)
{
    AssertWriteLockHeld(cs_txmempool);
    if (it->dsproof != -1)
        m_dspStorage->remove(it->dsproof);

    const CTransaction &tx = it->GetTx();
    const CTransactionRef &txref = it->GetSharedTx();
    const uint256 &hash = tx.GetId();
    uint32_t idx = 0;
    for (const CTxIn &txin : tx.vin)
    {
        // A read only input is not spending the input so it is not the one in mapNextTx
        if (txin.IsReadOnly())
        {
            auto entry = mapRoTx.find(txin.prevout);
            if (entry != mapRoTx.end())
            {
                LOG(MEMPOOL, "Removed RO dependency to UTXO %s for txidem: %s", txin.prevout.GetHex(),
                    txref->GetIdem().GetHex());
                // Remove this entry because we are removing this transaction from the txpool
                entry->second.erase(CInPoint{txref, idx});
                // Nothing left so clean up the entire entry
                if (entry->second.size() == 0)
                {
                    LOG(MEMPOOL, "Removed RO dependency to UTXO %s entirely (now empty)", txin.prevout.GetHex());
                    mapRoTx.erase(entry);
                }
            }
        }
        else
        {
            mapNextTx.erase(txin.prevout);
        }
        idx++;
    }
    for (size_t i = 0; i < tx.vout.size(); i++)
    {
        outpointMap.erase(tx.OutpointAt(i));
    }

    totalTxSize -= it->GetTxSize();
    cachedInnerUsage -= it->DynamicMemoryUsage();
    cachedInnerUsage -= memusage::DynamicUsage(mapLinks[it].parents) + memusage::DynamicUsage(mapLinks[it].children);

    // Erase this entry in the parents and children
    auto linksForIt = mapLinks.find(it);
    if (linksForIt != mapLinks.end())
    {
        for (auto &txlink : linksForIt->second.parents)
        {
            if (_UpdateChild(txlink, it, false))
                mapTx.modify(txlink, update_ancestor_state(0, 0, 0, 0, true));
        }
        for (auto &txlink : linksForIt->second.children)
        {
            if (_UpdateParent(txlink, it, false))
                mapTx.modify(txlink, update_ancestor_state(0, 0, 0, 0, true));
        }
    }

    /* This code iterates thru the entire mapLinks cleaning up any references to the element to be deleted.
       It is very inefficient, but is a good check that mapLinks is consistent, so is being left in the code
       commented out. */
#if 0
    for (auto &txlink : mapLinks)
    {
        //if (_UpdateChild(txlink.first, it, false) || _UpdateParent(txlink.first, it, false))
        //{
            // Mark it as dirty
        //    mapTx.modify(txlink.first, update_ancestor_state(0, 0, 0, 0, true));
        //}

        // This code directly does what the prior if clause accomplishes
        int changed = 0;
        auto tmpit = txlink.second.parents.find(it);
        if (tmpit != txlink.second.parents.end())
        {
            txlink.second.parents.erase(tmpit);
            cachedInnerUsage -= memusage::IncrementalDynamicUsage(emptySetEntries);
            changed++;
        }
        tmpit = txlink.second.children.find(it);
        if (tmpit != txlink.second.children.end())
        {
            txlink.second.children.erase(tmpit);
            cachedInnerUsage -= memusage::IncrementalDynamicUsage(emptySetEntries);
            changed++;
        }
        if (changed)
        {
            LOGA("ERROR: STILL HAD TO CLEAN MAPLINKS");
            // Mark it as dirty
            mapTx.modify(txlink.first, update_ancestor_state(0, 0, 0, 0, true));
        }
    }
#endif

    mapLinks.erase(it);
    mapTx.erase(it);
    nTransactionsUpdated++;
    minerPolicyEstimator->removeTx(hash);
}

// Calculates descendants of entry that are not already in setDescendants, and adds to
// setDescendants. Assumes entryit is already a tx in the mempool and setMemPoolChildren
// is correct for tx and all descendants.
// Also assumes that if an entry is in setDescendants already, then all
// in-mempool descendants of it are already in setDescendants as well, so that we
// can save time by not iterating over those entries.
void CTxMemPool::_CalculateDescendants(TxIdIter entryit, setEntries &setDescendants, mapEntryHistory *mapTxnChainTips)
{
    AssertWriteLockHeld(cs_txmempool);
    setEntries stage;
    if (setDescendants.count(entryit) == 0)
    {
        stage.insert(entryit);
    }
    // Traverse down the children of entry, only adding children that are not
    // accounted for in setDescendants already (because those children have either
    // already been walked, or will be walked in this iteration).
    while (!stage.empty())
    {
        const TxIdIter it = *stage.begin();
        setDescendants.insert(it);
        stage.erase(it); // It's ok to erase here because GetMemPoolChildren does not dereference it

        const setEntries &setChildren = GetMemPoolChildren(it);
        for (const TxIdIter &childiter : setChildren)
        {
            if (!setDescendants.count(childiter))
            {
                if (mapTxnChainTips && mapTxnChainTips->count(childiter))
                    continue;

                stage.insert(childiter);
            }
        }
    }
}

void CTxMemPool::removeRecursive(const CTransaction &origTx, std::list<CTransactionRef> &removed)
{
    WRITELOCK(cs_txmempool);
    _removeRecursive(origTx, removed);
}

void CTxMemPool::ResubmitCommitQ()
{
    AssertWriteLockHeld(cs_txmempool);

    // Clear txCommitQ
    {
        LOCK(cs_commitQ);
        for (auto &kv : *txCommitQ)
        {
            CTxInputData txd;
            txd.tx = kv.second.entry.GetSharedTx();
            txd.nodeName = "rollback";
            txd.msgCookie = 0;
            EnqueueTxForAdmission(txd);
        }
        txCommitQ->clear();
    }
}

void CTxMemPool::_removeRecursive(const CTransaction &origTx, std::list<CTransactionRef> &removed)
{
    AssertWriteLockHeld(cs_txmempool);

    // Remove transaction from memory pool
    setEntries txToRemove;
    TxIdIter origit = mapTx.find(origTx.GetId());
    if (origit != mapTx.end())
    {
        txToRemove.insert(origit);
    }
    else
    {
        // When recursively removing but origTx isn't in the mempool
        // be sure to remove any children that are in the pool. This can
        // happen during chain re-orgs if origTx isn't re-accepted into
        // the mempool for any reason.
        for (unsigned int i = 0; i < origTx.vout.size(); i++)
        {
            COutPoint outpt = COutPoint(origTx.GetIdem(), i);
            auto it = mapNextTx.find(outpt);
            if (it != mapNextTx.end())
            {
                TxIdIter nextit = mapTx.find(it->second.ptx->GetId());
                assert(nextit != mapTx.end());
                txToRemove.insert(nextit);
            }
            auto it2 = mapRoTx.find(outpt);
            if (it2 != mapRoTx.end())
            {
                // A read only input MUST NOT refer to an uncommitted transaction, so there cannot be any tx in the
                // pool that imports an output of a tx in the pool
                DbgAssert(false, );
                for (const auto &cinp : it2->second)
                {
                    TxIdIter nextit = mapTx.find(cinp.ptx->GetId());
                    if (nextit != mapTx.end())
                    {
                        LOG(MEMPOOL, "Removing txidem: %s due to consumed read-only input",
                            nextit->GetSharedTx()->GetIdem().GetHex());
                        txToRemove.insert(nextit);
                    }
                }
            }
        }
    }
    setEntries setAllRemoves;
    for (TxIdIter it : txToRemove)
    {
        _CalculateDescendants(it, setAllRemoves);
    }
    for (TxIdIter it : setAllRemoves)
    {
        removed.push_back(it->GetSharedTx());
    }
    _RemoveStaged(setAllRemoves);
    setAllRemoves.clear();

    // As a final step we must resubmit whatever is in the CommitQ and CommitQFinal in case
    // there are any anscestors that were removed from the mempool above.
    ResubmitCommitQ();
}

void CTxMemPool::removeForReorg(const CCoinsViewCache *pcoins, unsigned int nMemPoolHeight, int flags)
{
    // Remove transactions spending a coinbase which are now immature and no-longer-final transactions
    WRITELOCK(cs_txmempool);
    list<CTransaction> transactionsToRemove;
    for (indexed_transaction_set::const_iterator it = mapTx.begin(); it != mapTx.end(); it++)
    {
        const CTransactionRef tx = it->GetSharedTx();
        LockPoints lp = it->GetLockPoints();
        bool validLP = TestLockPointValidity(&lp);
        if (!CheckFinalTx(tx, flags) || !CheckSequenceLocks(tx, flags, &lp, validLP))
        {
            // Note if CheckSequenceLocks fails the LockPoints may still be invalid
            // So it's critical that we remove the tx and not depend on the LockPoints.
            transactionsToRemove.push_back(*tx);
        }
        else if (it->GetSpendsCoinbase())
        {
            for (const CTxIn &txin : tx->vin)
            {
                auto prev = _getTxIdx(txin.prevout);
                if (!prev.IsNull())
                    continue;

                CoinAccessor coin(*pcoins, txin.prevout);
                if (nCheckFrequency != 0)
                    assert(!coin->IsSpent());
                if (coin->IsSpent() || (coin->IsCoinBase() && ((signed long)nMemPoolHeight) - coin->nHeight <
                                                                  Params().GetConsensus().coinbaseMaturity))
                {
                    transactionsToRemove.push_back(*tx);
                    break;
                }
            }
        }
        if (!validLP)
        {
            mapTx.modify(it, update_lock_points(lp));
        }
    }
    for (const CTransaction &tx : transactionsToRemove)
    {
        std::list<CTransactionRef> removed;
        _removeRecursive(tx, removed);
    }
}

/*
void CTxMemPool::removeConflicts(const CTransaction &tx, std::list<CTransactionRef> &removed)
{
    WRITELOCK(cs_txmempool);
    _removeConflicts(tx, removed);
}
*/
void CTxMemPool::_removeConflicts(const CTransaction &tx, std::list<CTransactionRef> &removed)
{
    AssertWriteLockHeld(cs_txmempool);
    // Remove transactions which depend on inputs of tx, recursively
    for (const CTxIn &txin : tx.vin)
    {
        std::unordered_map<COutPoint, CInPoint, OutPointHasher>::iterator it = mapNextTx.find(txin.prevout);
        if (it != mapNextTx.end())
        {
            const CTransaction &txConflict = *it->second.ptx;
            if (txConflict != tx)
            {
                _removeRecursive(txConflict, removed);
            }
        }

        // Since the inputs are consumed, I can no longer reference them in read-only inputs
        // Any tx that used this input as a read only needs to be removed.
        if (!txin.IsReadOnly()) // UTXO is being consumed
        {
            LOG(MEMPOOL, "Consumed UTXO %s. mapRoTx size: %d", txin.prevout.GetHex(), mapRoTx.size());
            auto it2 = mapRoTx.find(txin.prevout);
            if (it2 != mapRoTx.end())
            {
                LOG(MEMPOOL, "  UTXO %s has %d RO children", it2->second.size());
                for (const auto &cinp : it2->second)
                {
                    CTransactionRef txref = cinp.ptx;
                    _removeRecursive(*txref, removed);
                }
                mapRoTx.erase(it2);
            }
        }
    }
}


// transactions need to be removed from the mempool in ancestor-first order so that
// descendant/ancestor counts remain correct.  This is accomplished by looking at the
// data in mapLinks and only removing transactions with no ancestors.
// If a transaction has an ancestor, it is placed on a deferred map: ancestor->descendant list.
// Whenever a tx is removed from the mempool, any of its descendants are placed back onto the
// queue of tx that are removable.
void CTxMemPool::removeForBlock(const std::vector<CTransactionRef> &vtx,
    uint64_t nBlockHeight,
    std::list<CTransactionRef> &conflicts,
    bool fCurrentEstimate)
{
    WRITELOCK(cs_txmempool);

    // Process the block for transasction removal and ancestor state updates.
    // As a first step remove all the txns that are in the block from the mempool by
    // first updating the children for removal of the parent, and also saving the entries
    // for policy estimate updates.  Then in the final loop simply remove all the txns.
    //
    // While we're updating the child transactions prior to removal we can also gather the
    // mapTxnChaiTips.
    mapEntryHistory mapTxnChainTips;
    setEntries setAncestorsFromBlock;
    std::set<uint256> setReadOnlyHashes;
    {
        // Check for readonly ancestors
        // This must be done before removeUnchecked is called because removeUnchecked will wipe out
        // a tx without any checking...
        for (const auto &tx : vtx)
        {
            // Since the inputs are consumed, I can no longer reference them in read-only inputs
            // Any transactions in the pool that use them need to go.
            for (unsigned int i = 0; i < tx->vin.size(); i++)
            {
                if (!tx->vin[i].IsReadOnly()) // UTXO is being consumed
                {
                    LOG(MEMPOOL, "remove for block %d Consumed UTXO %s", nBlockHeight, tx->vin[i].prevout.GetHex());
                    // So remove all txes that use the UTXO
                    auto it2 = mapRoTx.find(tx->vin[i].prevout);
                    if (it2 != mapRoTx.end())
                    {
                        LOG(MEMPOOL, "UTXO %s has %d RO children", it2->second.size());
                        for (const auto &cinp : it2->second)
                        {
                            const uint256 &dephash = cinp.ptx->GetId();
                            setReadOnlyHashes.insert(dephash);
                            LOG(MEMPOOL,
                                "Removing TX id %s (idem: %s) due to spend of readonly dependency %s in input %d",
                                dephash.GetHex(), cinp.ptx->GetIdem().GetHex(), tx->vin[i].prevout.GetHex(), cinp.n);
                        }
                        mapRoTx.erase(it2);
                    }
                }
            }
        }

        LOG(MEMPOOL, "Removing %d read only dependents", setReadOnlyHashes.size());
        for (auto &hash : setReadOnlyHashes)
        {
            auto iter = mapTx.find(hash);
            if (iter != mapTx.end())
            {
                _remove(iter);
            }
        }
        setReadOnlyHashes.clear();


        setEntries setTxnsInBlock;
        for (const auto &tx : vtx)
        {
            const uint256 &hash = tx->GetId();
            TxIdIter it = mapTx.find(hash);
            if (it == mapTx.end())
            {
                continue;
            }

            // Get all ancestors from related to txns in the block. Stop looking if we've already looked up
            // this set of ancestors before; we don't want to be traversing the same part of the ancestor
            // tree more than once.
            if (it->IsDirty() || it->GetCountWithAncestors() > 1)
            {
                uint64_t nNoLimit = std::numeric_limits<uint64_t>::max();
                std::string dummy;
                setEntries setAncestors;
                _CalculateMemPoolAncestors(*it, setAncestors, nNoLimit, nNoLimit, dummy, &setAncestorsFromBlock, false);
                setAncestorsFromBlock.insert(setAncestors.begin(), setAncestors.end());
            }
            setTxnsInBlock.insert(it);

            const setEntries &setMemPoolChildren = GetMemPoolChildren(it);
            // This awkwardness is because the iterator is not stable if it is the element being deleted
            for (auto updateIt = setMemPoolChildren.begin(); updateIt != setMemPoolChildren.end();)
            {
                auto &child = *updateIt;
                // Get the current ancestor state values and save them for later comparison
                ancestor_state ancestorState(child->GetSizeWithAncestors(), child->GetModFeesWithAncestors(),
                    child->GetCountWithAncestors(), child->GetSigOpCountWithAncestors());
                mapTxnChainTips.emplace(child, ancestorState);

                auto deleteMe = child;
                updateIt++;
                // Remove each block entry from the parent map in mapLinks
                _UpdateParentChild(it, deleteMe, false);
            }
        }

        // Add any additional dirty chain tips from set of mempool txn chain tips that need to be
        // updated.
        for (const uint256 &hash : setDirtyTxnChainTips)
        {
            // if the txn still exists then add it to the set of chaintips
            auto it = mapTx.find(hash);
            if (it != mapTx.end())
            {
                ancestor_state ancestorState(it->GetSizeWithAncestors(), it->GetModFeesWithAncestors(),
                    it->GetCountWithAncestors(), it->GetSigOpCountWithAncestors());
                mapTxnChainTips.emplace(it, ancestorState);
            }
        }
        setDirtyTxnChainTips.clear();
        // Before the txs in the new block have been removed from the mempool, update policy estimates
        minerPolicyEstimator->processBlock(nBlockHeight, setTxnsInBlock, fCurrentEstimate);

        // Remove Transactions that were in the block from the mempool.
        for (TxIdIter it : setTxnsInBlock)
        {
            setAncestorsFromBlock.erase(it);
            mapTxnChainTips.erase(it);
            removeUnchecked(it);
        }
        setTxnsInBlock.clear();

        // This is a safeguard in the case where ancestors of transactions in this block have re-entered
        // the mempool, possibly from a re-org. This should never happen and would likely indicate a locking
        // issue if it did.
        if (!setAncestorsFromBlock.empty())
        {
            DbgAssert(!"Ancestors in the mempool when they should not be", );
            for (TxIdIter it : setAncestorsFromBlock)
            {
                removeUnchecked(it);
            }
            setAncestorsFromBlock.clear();
        }
    }

    // For every chain tip walk through their decendants finding any transaction that have more than one parent.
    // These will then need to be considered as chain tips.
    mapEntryHistory mapAdditionalChainTips;
    for (auto iter : mapTxnChainTips)
    {
        // Get descendants but stop looking if/when we find another txnchaintip in the descendant tree.
        setEntries setDescendants;
        _CalculateDescendants(iter.first, setDescendants, &mapTxnChainTips);
        for (TxIdIter dit : setDescendants)
        {
            // Add a new chaintip if there is more than 1 parent.
            if (GetMemPoolParents(dit).size() > 1)
            {
                ancestor_state ancestorState(dit->GetSizeWithAncestors(), dit->GetModFeesWithAncestors(),
                    dit->GetCountWithAncestors(), dit->GetSigOpCountWithAncestors());
                mapAdditionalChainTips.emplace(dit, ancestorState);
            }
        }
    }
    mapTxnChainTips.insert(mapAdditionalChainTips.begin(), mapAdditionalChainTips.end());

    // Update ancestor state for remaining chains
    UpdateTxnChainState(mapTxnChainTips);

    // Remove conflicting tx
    for (const auto &tx : vtx)
    {
        _removeConflicts(*tx, conflicts);
    }

    // With the cs_txmepool lock on, resubmit the txCommitQ so we don't allow txns back into
    // the mempool that may be ancestors of txns that were in the block we just processed.  If we allowed
    // this then the txns would essentialy be orphans within the mempool.
    ResubmitCommitQ();
}

void CTxMemPool::_clear()
{
    AssertWriteLockHeld(cs_txmempool);

    mapLinks.clear();
    mapTx.clear();
    mapNextTx.clear();
    mapRoTx.clear();
    outpointMap.clear();
    // Do not clear mapDeltas because that is user configuration -- these tx may be reentering the mempool
    setDirtyTxnChainTips.clear();
    totalTxSize = 0;
    cachedInnerUsage = 0;
    ++nTransactionsUpdated;
}

void CTxMemPool::clear()
{
    WRITELOCK(cs_txmempool);
    _clear();
}

void CTxMemPool::check(const CCoinsViewCache *pcoins) const
{
    if (nCheckFrequency == 0)
        return;

    if (GetRand(std::numeric_limits<uint32_t>::max()) >= nCheckFrequency)
        return;

    uint64_t checkTotal = 0;
    uint64_t innerUsage = 0;

    READLOCK(cs_txmempool);
    LOG(MEMPOOL, "Checking mempool with %u transactions and %u inputs\n", (unsigned int)mapTx.size(),
        (unsigned int)mapNextTx.size());

    CCoinsViewCache mempoolDuplicate(const_cast<CCoinsViewCache *>(pcoins));

    list<const CTxMemPoolEntry *> waitingOnDependants;
    for (indexed_transaction_set::const_iterator it = mapTx.begin(); it != mapTx.end(); it++)
    {
        unsigned int i = 0;
        checkTotal += it->GetTxSize();
        innerUsage += it->DynamicMemoryUsage();
        const CTransaction &tx = it->GetTx();
        txlinksMap::const_iterator linksiter = mapLinks.find(it);
        assert(linksiter != mapLinks.end());
        const TxLinks &links = linksiter->second;
        innerUsage += memusage::DynamicUsage(links.parents) + memusage::DynamicUsage(links.children);
        bool fDependsWait = false;
        setEntries setParentCheck;
        int64_t parentSizes = 0;
        unsigned int parentSigOpCount = 0;

        bool inMempool = false;
        bool inOutpointMap = false;
        for (const CTxIn &txin : tx.vin)
        {
            if (!txin.IsReadOnly())
            {
                // Check that every mempool transaction's inputs refer to available coins, or other mempool tx's.
                OutpointMap::const_iterator opm = outpointMap.find(txin.prevout);
                if (opm != outpointMap.end())
                {
                    inOutpointMap = true;
                    indexed_transaction_set::const_iterator it2 = mapTx.find(opm->second.first);
                    if (it2 != mapTx.end())
                    {
                        inMempool = true;
                        const CTransaction &tx2 = it2->GetTx();
                        size_t n = opm->second.second;
                        assert(!tx2.vout[n].IsNull());
                        assert(tx2.OutpointAt(n) == txin.prevout);
                        fDependsWait = true;
                        if (setParentCheck.insert(it2).second)
                        {
                            parentSizes += it2->GetTxSize();
                            parentSigOpCount += it2->GetSigOpCount();
                        }
                    }
                }
            }

            if (!inMempool)
            {
                if (txin.IsReadOnly()) // Read only inputs are unaffected by txpool contents
                {
                    if (!pcoinsTip->HaveCoin(txin.prevout))
                    {
                        LOGA("Txpool entry is missing input %d:%s %s", i, txin.prevout.hash.ToString(),
                            inOutpointMap ? "(in outpoints)" : "");
                        LOGA("TX hex: %s", EncodeHexTx(tx));
                        LOGA("TX: %s", tx.ToString());
                    }
                    DbgAssert(pcoinsTip->HaveCoin(txin.prevout), );
                }
                else
                {
                    if (!pcoins->HaveCoin(txin.prevout))
                    {
                        LOGA("Txpool entry is missing input %d:%s %s", i, txin.prevout.hash.ToString(),
                            inOutpointMap ? "(in outpoints)" : "");
                        LOGA("TX hex: %s", EncodeHexTx(tx));
                        LOGA("TX: %s", tx.ToString());
                    }
                    DbgAssert(pcoins->HaveCoin(txin.prevout), );
                }
            }

            if (!txin.IsReadOnly())
            {
                // Check whether its inputs are marked in mapNextTx.
                const auto it3 = mapNextTx.find(txin.prevout);
                assert(it3 != mapNextTx.end());
                assert(it3->second.ptx.get() == &tx);
                assert(it3->second.n == i);
            }
            i++;
        }
        DbgAssert(setParentCheck == GetMemPoolParents(it), );
        // Verify ancestor state is correct.
        if (!it->IsDirty())
        {
            setEntries setAncestors;
            uint64_t nNoLimit = std::numeric_limits<uint64_t>::max();
            std::string dummy;
            _CalculateMemPoolAncestors(*it, setAncestors, nNoLimit, nNoLimit, dummy);
            uint64_t nCountCheck = setAncestors.size() + 1;
            uint64_t nSizeCheck = it->GetTxSize();
            CAmount nFeesCheck = it->GetModifiedFee();
            unsigned int nSigOpCheck = it->GetSigOpCount();

            for (TxIdIter ancestorIt : setAncestors)
            {
                nSizeCheck += ancestorIt->GetTxSize();
                nFeesCheck += ancestorIt->GetModifiedFee();
                nSigOpCheck += ancestorIt->GetSigOpCount();
            }

            if (it->GetCountWithAncestors() != nCountCheck)
            {
                LOG(MEMPOOL, "TXPOOL Consistency check error: GetCountWithAncestors is: %d, calculated %d",
                    it->GetCountWithAncestors(), nCountCheck);
            }
            DbgAssert(it->GetCountWithAncestors() == nCountCheck, );
            if (it->GetSizeWithAncestors() != nSizeCheck)
            {
                LOG(MEMPOOL, "TXPOOL Consistency check error: GetSizeWithAncestors is: %d, calculated %d",
                    it->GetSizeWithAncestors(), nSizeCheck);
            }
            DbgAssert(it->GetSizeWithAncestors() == nSizeCheck, );
            if (it->GetSigOpCountWithAncestors() != nSigOpCheck)
            {
                LOG(MEMPOOL, "TXPOOL Consistency check error: GetSigOpCountWithAncestors is: %d, calculated %d",
                    it->GetSigOpCountWithAncestors(), nSigOpCheck);
            }
            DbgAssert(it->GetSigOpCountWithAncestors() == nSigOpCheck, );
            if (it->GetModFeesWithAncestors() != nFeesCheck)
            {
                LOG(MEMPOOL, "TXPOOL Consistency check error: GetModFeesWithAncestors is: %d, calculated %d",
                    it->GetModFeesWithAncestors(), nFeesCheck);
            }
            DbgAssert(it->GetModFeesWithAncestors() == nFeesCheck, );
        }

        // Check children against mapNextTx
        CTxMemPool::setEntries setChildrenCheck;
        uint64_t childSizes = 0;
        for (unsigned int j = 0; j < tx.vout.size(); j++)
        {
            auto outpoint = tx.OutpointAt(j);
            std::unordered_map<COutPoint, CInPoint, OutPointHasher>::const_iterator next = mapNextTx.find(outpoint);
            if (next != mapNextTx.end())
            {
                TxIdIter childit = mapTx.find(next->second.ptx->GetId());
                assert(childit != mapTx.end()); // mapNextTx points to in-mempool transactions
                if (setChildrenCheck.insert(childit).second)
                {
                    childSizes += childit->GetTxSize();
                }
            }
        }
        auto mempoolChildren = GetMemPoolChildren(it);
        assert(setChildrenCheck == GetMemPoolChildren(it));

        if (fDependsWait)
        {
            waitingOnDependants.push_back(&(*it));
        }
        else
        {
            for (const CTxIn &input : tx.vin)
            {
                if (input.IsReadOnly())
                {
                    if (!pcoins->HaveCoin(input.prevout))
                    {
                        LOG(MEMPOOL, "TXPOOL Consistency check error: checking readonly inputs failed\n");
                        DbgAssert(false, );
                    }
                }
                else
                {
                    if (!mempoolDuplicate.HaveCoin(input.prevout))
                    {
                        LOG(MEMPOOL, "TXPOOL Consistency check error: checking consumed inputs failed\n");
                        DbgAssert(false, );
                    }
                }
            }
            UpdateCoins(tx, mempoolDuplicate, 1000000);
        }
    }
    unsigned int stepsSinceLastRemove = 0;
    while (!waitingOnDependants.empty())
    {
        LOGA("waiting on deps %d", waitingOnDependants.size());
        const CTxMemPoolEntry *entry = waitingOnDependants.front();
        waitingOnDependants.pop_front();
        CValidationState state;
        bool valid = true;
        for (const CTxIn &input : entry->GetTx().vin)
        {
            if (input.IsReadOnly())
            {
                continue;
            }
            if (!mempoolDuplicate.HaveCoin(input.prevout))
            {
                valid = false;
                waitingOnDependants.push_back(entry);
                if (stepsSinceLastRemove >= waitingOnDependants.size())
                {
                    LOGA("TXPOOL Consistency check error: stepsSinceLastRemove < waitingOnDependants (%d < %d)\n",
                        stepsSinceLastRemove, waitingOnDependants.size());
                    DbgAssert(false, );
                    break;
                }
            }
        }
        if (valid == false)
        {
            break;
        }
        // Use the largest maxOps since this code is not meant to validate that constraint
        assert(
            CheckInputs(entry->GetSharedTx(), state, mempoolDuplicate, *pcoinsTip, false, 0, false, nullptr, Params()));
        UpdateCoins(entry->GetTx(), mempoolDuplicate, 1000000);
        stepsSinceLastRemove = 0;
    }
    for (std::unordered_map<COutPoint, CInPoint, OutPointHasher>::const_iterator it = mapNextTx.begin();
         it != mapNextTx.end(); it++)
    {
        const uint256 &hash = it->second.ptx->GetId();
        indexed_transaction_set::const_iterator it2 = mapTx.find(hash);
        const CTransaction &tx = it2->GetTx();
        assert(it2 != mapTx.end()); // Every entry in mapNextTx should point to a mempool entry
        assert(&tx == it->second.ptx.get());
        assert(tx.vin.size() > it->second.n);
        assert(it->first == it->second.ptx->vin[it->second.n].prevout);
    }

    assert(totalTxSize == checkTotal);
    assert(innerUsage == cachedInnerUsage);
}

void CTxMemPool::queryIds(vector<uint256> &vtxid) const
{
    READLOCK(mempool.cs_txmempool);
    _queryIds(vtxid);
}
void CTxMemPool::_queryIds(vector<uint256> &vtxid) const
{
    vtxid.clear();

    AssertLockHeld(cs_txmempool);
    vtxid.reserve(mapTx.size());
    for (indexed_transaction_set::const_iterator mi = mapTx.begin(); mi != mapTx.end(); ++mi)
        vtxid.push_back(mi->GetTx().GetId());
}

void CTxMemPool::queryIdems(vector<uint256> &vtxid) const
{
    READLOCK(mempool.cs_txmempool);
    _queryIdems(vtxid);
}
void CTxMemPool::_queryIdems(vector<uint256> &vtxid) const
{
    vtxid.clear();

    AssertLockHeld(cs_txmempool);
    vtxid.reserve(mapTx.size());
    for (indexed_transaction_set::const_iterator mi = mapTx.begin(); mi != mapTx.end(); ++mi)
        vtxid.push_back(mi->GetTx().GetIdem());
}

void CTxMemPool::queryTxs(vector<CTransactionRef> &vtx) const
{
    READLOCK(mempool.cs_txmempool);
    _queryTxs(vtx);
}
void CTxMemPool::_queryTxs(vector<CTransactionRef> &vtx) const
{
    vtx.clear();

    AssertLockHeld(cs_txmempool);
    vtx.reserve(mapTx.size());
    //    for (indexed_transaction_set::const_iterator mi = mapTx.begin(); mi != mapTx.end(); ++mi)
    for (const auto &entry : mapTx)
        vtx.push_back(entry.GetSharedTx());
}


CFeeRate CTxMemPool::estimateFee(int nBlocks) const
{
    READLOCK(cs_txmempool);
    return minerPolicyEstimator->estimateFee(nBlocks);
}

bool CTxMemPool::WriteFeeEstimates(CAutoFile &fileout) const
{
    try
    {
        READLOCK(cs_txmempool);
        fileout << 109900; // version required to read: 0.10.99 or later
        fileout << CLIENT_VERSION; // version that wrote the file
        minerPolicyEstimator->Write(fileout);
    }
    catch (const std::exception &)
    {
        LOGA("CTxMemPool::WriteFeeEstimates(): unable to write policy estimator data (non-fatal)\n");
        return false;
    }
    return true;
}

bool CTxMemPool::ReadFeeEstimates(CAutoFile &filein)
{
    try
    {
        int nVersionRequired, nVersionThatWrote;
        filein >> nVersionRequired >> nVersionThatWrote;
        if (nVersionRequired > CLIENT_VERSION)
            return error("CTxMemPool::ReadFeeEstimates(): up-version (%d) fee estimate file", nVersionRequired);

        WRITELOCK(cs_txmempool);
        minerPolicyEstimator->Read(filein);
    }
    catch (const std::exception &)
    {
        LOGA("CTxMemPool::ReadFeeEstimates(): unable to read policy estimator data (non-fatal)\n");
        return false;
    }
    return true;
}

const CTxMemPoolEntry *CTxMemPool::_getEntry(const uint256 &hash)
{
    AssertLockHeld(cs_txmempool);
    CTxMemPool::TxIdIter iter = mapTx.find(hash);
    if (iter == mapTx.end())
    {
        auto &tainer = mapTx.get<txidem_tag>();
        TxIdemIter idemit = tainer.find(hash);
        if (idemit != tainer.end())
            return &(*idemit); // not a no-op, converts iter to object then takes pointer
        return nullptr;
    }
    return &(*iter); // not a no-op, converts iter to object then takes pointer
}

const CTxMemPoolEntry *CTxMemPool::_getEntryByOutpoint(const COutPoint &hash)
{
    AssertLockHeld(cs_txmempool);
    OutpointMap::const_iterator opm = outpointMap.find(hash);
    if (opm == outpointMap.end())
        return nullptr;
    return _getEntry(opm->second.first);
}


CTxMemPool::TxIdIter CTxMemPool::_getIdIter(const uint256 &hash) const
{
    AssertLockHeld(cs_txmempool);
    indexed_transaction_set::const_iterator i = mapTx.find(hash);
    if (i == mapTx.end())
    {
        CTxMemPool::TxIdemIter idemit = mapTx.get<txidem_tag>().find(hash);
        return mapTx.project<TXID_CONTAINER_IDX>(idemit);
    }
    return i;
}


CTransactionRef CTxMemPool::_get(const uint256 &hash) const
{
    AssertLockHeld(cs_txmempool);
    indexed_transaction_set::const_iterator i = mapTx.find(hash);
    if (i == mapTx.end())
        return nullptr;
    return i->GetSharedTx();
}

CTxMemPool::TxIdIter CTxMemPool::_getIdIter(const COutPoint &outpoint) const
{
    AssertLockHeld(cs_txmempool);
    OutpointMap::const_iterator opm = outpointMap.find(outpoint);
    if (opm == outpointMap.end())
        return mapTx.end();
    uint256 hash = opm->second.first;
    CTxMemPool::TxIdIter i = mapTx.find(hash);
    return i;
}


CInPoint CTxMemPool::_getTxIdx(const COutPoint &outpoint) const
{
    AssertLockHeld(cs_txmempool);
    OutpointMap::const_iterator opm = outpointMap.find(outpoint);
    if (opm == outpointMap.end())
        return CInPoint();
    uint256 hash = opm->second.first;
    size_t idx = opm->second.second;
    indexed_transaction_set::const_iterator i = mapTx.find(hash);
    if (i == mapTx.end())
        return CInPoint();
    return CInPoint(i->GetSharedTx(), idx);
}

CTxOut CTxMemPool::_get(const COutPoint &outpoint) const
{
    AssertLockHeld(cs_txmempool);
    OutpointMap::const_iterator opm = outpointMap.find(outpoint);
    if (opm == outpointMap.end())
        return CTxOut();
    uint256 hash = opm->second.first;
    size_t idx = opm->second.second;
    indexed_transaction_set::const_iterator i = mapTx.find(hash);
    if (i == mapTx.end())
        return CTxOut();
    if (idx >= i->GetTx().vout.size())
        return CTxOut();
    return i->GetTx().vout[idx];
}


CTransactionRef CTxMemPool::get(const uint256 &hash) const
{
    READLOCK(cs_txmempool);
    return _get(hash);
}

static TxMempoolInfo GetInfo(CTxMemPool::indexed_transaction_set::const_iterator it)
{
    return TxMempoolInfo{
        it->GetSharedTx(), it->GetTime(), CFeeRate(it->GetFee(), it->GetTxSize()), it->GetModifiedFee() - it->GetFee()};
}

std::vector<TxMempoolInfo> CTxMemPool::AllTxMempoolInfo() const
{
    AssertLockHeld(cs_txmempool);
    std::vector<TxMempoolInfo> vInfo;
    vInfo.reserve(mapTx.size());
    for (indexed_transaction_set::const_iterator it = mapTx.begin(); it != mapTx.end(); it++)
    {
        vInfo.push_back(GetInfo(it));
    }
    return vInfo;
}

bool CTxMemPool::PrioritiseTransaction(const uint256 h, double dPriorityDelta, const CAmount &nFeeDelta)
{
    {
        WRITELOCK(cs_txmempool);
        std::pair<double, CAmount> &deltas = mapDeltas[h];
        deltas.first += dPriorityDelta;
        deltas.second += nFeeDelta;
        TxIdIter it = mapTx.find(h);
        if (it == mapTx.end())
        {
            auto &tainer = mapTx.get<txidem_tag>();
            TxIdemIter idemit = tainer.find(h);
            if (idemit != tainer.end())
            {
                it = mapTx.project<TXID_CONTAINER_IDX>(idemit);
            }
        }
        if (it != mapTx.end())
        {
            // If this is part of an unconfirmed chain then update the ancestor chain state first.
            UpdateTxnChainState(it);
            mapTx.modify(it, update_fee_delta(deltas.second));

            // Update all the ancestor state for all the descendants with the new feeDelta
            setEntries setDescendants;
            _CalculateDescendants(it, setDescendants);
            setDescendants.erase(it);
            for (TxIdIter descIt : setDescendants)
                mapTx.modify(descIt, update_ancestor_state(0, nFeeDelta, 0, 0, false));
        }
        else
        {
            return false;
        }
    }
    LOGA("PrioritiseTransaction: %s priority += %f, fee += %d\n", h.ToString().c_str(), dPriorityDelta,
        FormatMoney(nFeeDelta));
    return true;
}

void CTxMemPool::ApplyDeltas(const uint256 hash, double &dPriorityDelta, CAmount &nFeeDelta) const
{
    READLOCK(cs_txmempool);
    _ApplyDeltas(hash, dPriorityDelta, nFeeDelta);
}

void CTxMemPool::_ApplyDeltas(const uint256 hash, double &dPriorityDelta, CAmount &nFeeDelta) const
{
    AssertLockHeld(cs_txmempool);
    std::unordered_map<uint256, std::pair<double, CAmount>, uint256Hasher>::const_iterator pos = mapDeltas.find(hash);
    if (pos == mapDeltas.end())
    {
        return;
    }
    const std::pair<double, CAmount> &deltas = pos->second;
    dPriorityDelta += deltas.first;
    nFeeDelta += deltas.second;
}

void CTxMemPool::ClearPrioritisation(const uint256 hash)
{
    WRITELOCK(cs_txmempool);
    _ClearPrioritisation(hash);
}
void CTxMemPool::_ClearPrioritisation(const uint256 hash)
{
    uint256 h = hash;
    std::unordered_map<uint256, std::pair<double, CAmount>, uint256Hasher>::const_iterator pos = mapDeltas.find(h);
    if (pos == mapDeltas.end())
    {
        // Look for the hash as an idem
        auto &tainer = mapTx.get<txidem_tag>();
        TxIdemIter idemit = tainer.find(hash);
        if (idemit != tainer.end())
        {
            h = idemit->GetTx().GetId();
            pos = mapDeltas.find(h);
            if (pos == mapDeltas.end())
                return;
        }
        else
            return;
    }
    mapDeltas.erase(pos);
}
bool CTxMemPool::HasNoInputsOf(const CTransactionRef &tx) const
{
    for (unsigned int i = 0; i < tx->vin.size(); i++)
        if (exists(tx->vin[i].prevout.hash))
            return false;
    return true;
}

CCoinsViewMemPool::CCoinsViewMemPool(CCoinsView *baseIn, const CTxMemPool &mempoolIn)
    : CCoinsViewBacked(baseIn), mempool(mempoolIn)
{
}

bool CCoinsViewMemPool::GetCoin(const COutPoint &outpoint, Coin &coin) const
{
    AssertLockHeld(mempool.cs_txmempool);

    // If an entry in the mempool exists, always return that one, as it's guaranteed to never
    // conflict with the underlying cache, and it cannot have pruned entries (as it contains full)
    // transactions. First checking the underlying cache risks returning a pruned entry instead.
    CTxOut txout = mempool._get(outpoint);
    if (!txout.IsNull()) // Mempool has it
    {
        coin = Coin(txout, MEMPOOL_HEIGHT, false);
        return true;
    }
    return (base->GetCoin(outpoint, coin) && !coin.IsSpent());
}

bool CCoinsViewMemPool::HaveCoin(const COutPoint &outpoint) const
{
    return mempool.exists(outpoint) || base->HaveCoin(outpoint);
}

bool CTxMemPool::exists(const COutPoint &outpoint) const
{
    READLOCK(cs_txmempool);
    return (outpointMap.count(outpoint) > 0);
}

size_t CTxMemPool::DynamicMemoryUsage(bool fCalcBucketSize)
{
    // Rehash the txpool maps if we are empty. Rehashing will remove the most of the buckets
    // which can be a significant portion (2%-3%) of txpool usage.
    if (mapTx.size() == 0)
    {
        WRITELOCK(cs_txmempool);
        mapNextTx.rehash(0);
        mapDeltas.rehash(0);
        outpointMap.rehash(0);
        mapLinks.rehash(0);
    }

    READLOCK(cs_txmempool);
    // Estimate the overhead of mapTx to be 15 pointers + an allocation, as no exact formula for
    // boost::multi_index_contained is implemented.
    return _DynamicMemoryUsage(fCalcBucketSize);
}

size_t CTxMemPool::_DynamicMemoryUsage(bool fCalcBucketSize)
{
    AssertLockHeld(cs_txmempool);

    // Estimate the overhead of mapTx to be 15 pointers + an allocation, as no exact formula for
    // boost::multi_index_contained is implemented.
    return memusage::MallocUsage(sizeof(CTxMemPoolEntry) + 15 * sizeof(void *)) * mapTx.size() +
           memusage::DynamicUsage(mapNextTx, fCalcBucketSize) + memusage::DynamicUsage(mapDeltas, fCalcBucketSize) +
           memusage::DynamicUsage(mapLinks, fCalcBucketSize) + memusage::DynamicUsage(outpointMap, fCalcBucketSize) +
           cachedInnerUsage;
}

void CTxMemPool::_RemoveStaged(setEntries &stage)
{
    {
        AssertWriteLockHeld(cs_txmempool);
        _UpdateForRemoveFromMempool(stage);
        for (const TxIdIter &it : stage)
        {
            removeUnchecked(it);
        }
    }
}
int CTxMemPool::Expire(int64_t time, std::vector<COutPoint> &vCoinsToUncache)
{
    WRITELOCK(cs_txmempool);
    indexed_transaction_set::index<entry_time>::type::iterator it = mapTx.get<entry_time>().begin();
    setEntries toremove;
    while (it != mapTx.get<entry_time>().end() && it->GetTime() < time)
    {
        toremove.insert(mapTx.project<0>(it));
        it++;
    }
    setEntries stage;
    for (TxIdIter removeit : toremove)
        _CalculateDescendants(removeit, stage);
    for (TxIdIter it2 : stage)
        for (const CTxIn &txin : it2->GetTx().vin)
            vCoinsToUncache.push_back(txin.prevout);

    _RemoveStaged(stage);
    return stage.size();
}

int CTxMemPool::Remove(const uint256 &txhash, std::vector<COutPoint> *vCoinsToUncache)
{
    WRITELOCK(cs_txmempool);
    TxIdIter removeit = mapTx.find(txhash);
    if (removeit == mapTx.end())
    {
        // Didn't find that tx by ID.  Search by Idem
        auto &tainer = mapTx.get<txidem_tag>();
        TxIdemIter idemit = tainer.find(txhash);
        if (idemit == tainer.end())
            return 0;
        // If found get the ID iterator so we can continue to remove
        removeit = mapTx.project<TXID_CONTAINER_IDX>(idemit);
    }

    setEntries stage;
    _CalculateDescendants(removeit, stage);
    if (vCoinsToUncache)
        for (TxIdIter it2 : stage)
            for (const CTxIn &txin : it2->GetTx().vin)
                vCoinsToUncache->push_back(txin.prevout);
    _RemoveStaged(stage);
    return stage.size();
}

int CTxMemPool::_remove(TxIdIter removeit, std::vector<COutPoint> *vCoinsToUncache)
{
    if (removeit == mapTx.end())
        return 0;

    setEntries stage;
    _CalculateDescendants(removeit, stage);
    if (vCoinsToUncache)
        for (TxIdIter it2 : stage)
            for (const CTxIn &txin : it2->GetTx().vin)
                vCoinsToUncache->push_back(txin.prevout);
    _RemoveStaged(stage);
    return stage.size();
}

bool CTxMemPool::_UpdateParentChild(TxIdIter parent, TxIdIter child, bool add)
{
    AssertWriteLockHeld(cs_txmempool);
    bool ret = _UpdateChild(parent, child, add);
    ret |= _UpdateParent(child, parent, add);
    return ret;
}

bool CTxMemPool::_UpdateChild(TxIdIter entry, TxIdIter child, bool add)
{
    setEntries s;
    AssertWriteLockHeld(cs_txmempool);
    if (add && mapLinks[entry].children.insert(child).second)
    {
        cachedInnerUsage += memusage::IncrementalDynamicUsage(s);
        return true;
    }
    else if (!add && mapLinks[entry].children.erase(child))
    {
        cachedInnerUsage -= memusage::IncrementalDynamicUsage(s);
        return true;
    }
    return false;
}

bool CTxMemPool::_UpdateParent(TxIdIter entry, TxIdIter parent, bool add)
{
    setEntries s;
    AssertWriteLockHeld(cs_txmempool);
    if (add && mapLinks[entry].parents.insert(parent).second)
    {
        cachedInnerUsage += memusage::IncrementalDynamicUsage(s);
        return true;
    }
    else if (!add && mapLinks[entry].parents.erase(parent))
    {
        cachedInnerUsage -= memusage::IncrementalDynamicUsage(s);
        return true;
    }
    return false;
}

const CTxMemPool::setEntries &CTxMemPool::GetMemPoolParents(TxIdIter entry) const
{
    AssertLockHeld(cs_txmempool);
    assert(entry != mapTx.end());
    txlinksMap::const_iterator it = mapLinks.find(entry);
    DbgAssert(it != mapLinks.end(), return emptySetEntries);
    return it->second.parents;
}

const CTxMemPool::setEntries CTxMemPool::GetMemPoolParents(const CTransaction &tx) const
{
    AssertLockHeld(cs_txmempool);
    setEntries txparents;
    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        TxIdIter piter = _getIdIter(tx.vin[i].prevout);
        if (piter != mapTx.end())
        {
            txparents.insert(piter);
        }
    }
    return txparents;
}

const CTxMemPool::setEntries &CTxMemPool::GetMemPoolChildren(TxIdIter entry) const
{
    AssertLockHeld(cs_txmempool);
    assert(entry != mapTx.end());
    txlinksMap::const_iterator it = mapLinks.find(entry);
    assert(it != mapLinks.end());
    return it->second.children;
}

CTransactionRef CTxMemPool::addDoubleSpendProof(const DoubleSpendProof &proof)
{
    WRITELOCK(cs_txmempool);
    auto oldTx = mapNextTx.find(proof.Outpoint());
    if (oldTx == mapNextTx.end())
        return CTransactionRef();

    auto iter = mapTx.find(oldTx->second.ptx->GetId());
    assert(mapTx.end() != iter);
    if (iter->dsproof != -1) // A DSProof already exists for this tx.
        return CTransactionRef(); // don't propagate new one.

    auto item = *iter;
    item.dsproof = m_dspStorage->add(proof).second;
    mapTx.replace(iter, item); // Preserves iterator and reference validity
    return _get(oldTx->second.ptx->GetId());
}

DoubleSpendProofStorage *CTxMemPool::doubleSpendProofStorage() const { return m_dspStorage.get(); }
void CTxMemPool::TrimToSize(size_t sizelimit, std::vector<COutPoint> *pvNoSpendsRemaining, bool fDeterministic)
{
    WRITELOCK(cs_txmempool);
    unsigned nTxnRemoved = 0;

    uint16_t attempts = 0;
    FastRandomContext insecure_rand(fDeterministic);
    while (_DynamicMemoryUsage() > sizelimit)
    {
        if (mapTx.size() == 0)
            break;

        // Use the following scope to make sure that the iterator is destroyed and can't be used later
        // because we'll be removing the transaction associated with it.
        uint64_t nAncestors = 0;
        setEntries stage;
        {
            // Pick a random entry to delete
            indexed_transaction_set::index<entry_time>::type::iterator it = mapTx.get<entry_time>().begin();
            auto nEntryToDelete = insecure_rand.randrange((uint64_t)mapTx.size());
            std::advance(it, nEntryToDelete);
            DbgAssert(it != mapTx.get<entry_time>().end(), return);

            // Select the entry and any descendants
            _CalculateDescendants(mapTx.project<0>(it), stage);
            nAncestors = it->GetCountWithAncestors();
        }

        // If the descendant chain to remove is more than 10% of the total
        // chain size, then iterate through the setEntries to find a transaction
        // that be <= 10% of the total. In this way we don't remove an entire
        // chain that may be 100's or 1000's of txns long.
        uint64_t nSizeOfTxnChain = nAncestors + stage.size();
        if (nSizeOfTxnChain >= 10 && (double)nAncestors <= ((double)nSizeOfTxnChain * 0.90))
        {
            for (auto it2 : stage)
            {
                if ((double)it2->GetCountWithAncestors() > ((double)nSizeOfTxnChain * 0.90))
                {
                    stage.clear();
                    _CalculateDescendants(it2, stage);
                    break;
                }
            }
        }
        nTxnRemoved += stage.size();

        // We do not want to remove priority transactions so we must remove any
        // part of the chain which we've selected for removal and that has contains a
        // priority transaction, along with that transactions ancestors.
        setEntries setPriorityTx;
        for (TxIdIter iter : stage)
        {
            auto deltaIter = mapDeltas.find(iter->GetSharedTx()->GetId());
            if (deltaIter != mapDeltas.end())
            {
                // has either the priority or feedelta been modified
                if (deltaIter->second.first != 0 || deltaIter->second.second != 0)
                {
                    setPriorityTx.insert(iter);
                }
            }
        }
        setEntries setPriorityAncestors;
        for (TxIdIter iter : setPriorityTx)
        {
            std::string dummy;
            setEntries setAncestors;
            uint64_t nNoLimit = std::numeric_limits<uint64_t>::max();
            _CalculateMemPoolAncestors(*iter, setAncestors, nNoLimit, nNoLimit, dummy);
            setPriorityAncestors.insert(setAncestors.begin(), setAncestors.end());
        }
        for (auto iter : setPriorityTx)
            stage.erase(iter);
        for (auto iter : setPriorityAncestors)
            stage.erase(iter);

        // Prevent us from getting into an infinite loop if all transactions were removed.
        if (stage.empty())
        {
            if (attempts++ < 10)
                continue;
            else
                return;
        }
        else
        {
            attempts = 0;
        }

        // Remove the transactions, and if applicable, also remove the coins from the coinscache associated
        // with the transactions we just removed.
        std::vector<CTransactionRef> vTxn;
        if (pvNoSpendsRemaining)
        {
            vTxn.reserve(stage.size());
            for (TxIdIter it3 : stage)
                vTxn.push_back(it3->GetSharedTx());
        }
        _RemoveStaged(stage);
        if (pvNoSpendsRemaining)
        {
            for (CTransactionRef &ptx : vTxn)
            {
                for (const CTxIn &txin : ptx->vin)
                {
                    if (_exists(txin.prevout.hash))
                        continue;
                    if (!mapNextTx.count(txin.prevout))
                    {
                        pvNoSpendsRemaining->push_back(txin.prevout);
                    }
                }
            }
        }
    }

    if (nTxnRemoved > 0)
        LOG(MEMPOOL, "Removed %u txn\n", nTxnRemoved);
}

void ThreadUpdateTransactionRateStatistics()
{
    while (shutdown_threads.load() == false)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(TX_RATE_UPDATE_FREQUENCY_MILLIS));
        mempool.UpdateTransactionRateStatistics();
    }
}

void CTxMemPool::UpdateTransactionsPerSecond() { nBackloggedTxCountForThroughputRate++; }
void CTxMemPool::GetTransactionRateStatistics(double &smoothedTps, double &instantaneousTps, double &peakTps)
{
    std::lock_guard<std::mutex> lock(cs_txPerSec);

    smoothedTps = nTxPerSec;
    instantaneousTps = nInstantaneousTxPerSec;
    peakTps = nPeakRate;
}

void CTxMemPool::UpdateTransactionRateStatistics()
{
    std::lock_guard<std::mutex> lock(cs_txPerSec);

    static uint64_t nCount = 0;
    static int64_t nLastTime = GetTime();

    int64_t nNow = GetTime();

    // Don't report the transaction rate for 10 seconds after startup. This gives time for any
    // transations to be processed, from the mempool.dat file stored on disk, which would skew the
    // peak transaction rate.
    const static int64_t nStartTime = GetTime() + 10;
    if (nStartTime > nNow)
    {
        nTxPerSec = 0;
        nInstantaneousTxPerSec = 0;
        nCount = 0;
        nBackloggedTxCountForThroughputRate.exchange(0);
        return;
    }

    // Decay the previous tx rate.
    int64_t nDeltaTime = nNow - nLastTime;
    if (nDeltaTime > 0)
    {
        nTxPerSec -= (nTxPerSec / TX_RATE_SMOOTHING_SEC) * nDeltaTime;
        nLastTime = nNow;
        if (nTxPerSec < 0)
            nTxPerSec = 0;
    }

    // Extract the backlogged transaction count and reset to 0
    uint64_t nPending = nBackloggedTxCountForThroughputRate.exchange(0);
    if (nPending > 0)
    {
        nCount += nPending;
        // The amount that the pending txns will add to the tx rate
        nTxPerSec += nPending / TX_RATE_SMOOTHING_SEC;
    }

    // Calculate the peak rate if we've gone more that 1 second beyond the last sample time.
    // This will give us the finest grain peak rate possible for txns per second.
    static int64_t nLastSampleTime = GetTimeMillis();
    int64_t nCurrentSampleTime = GetTimeMillis();
    if (nCurrentSampleTime > nLastSampleTime + TX_RATE_RESOLUTION_MILLIS)
    {
        nInstantaneousTxPerSec = (double)(nCount * TX_RATE_RESOLUTION_MILLIS) / (nCurrentSampleTime - nLastSampleTime);
        if (nInstantaneousTxPerSec > nPeakRate)
            nPeakRate = nInstantaneousTxPerSec;
        nCount = 0;
        nLastSampleTime = nCurrentSampleTime;
    }
}

SaltedTxidHasher::SaltedTxidHasher()
    : k0(GetRand(std::numeric_limits<uint64_t>::max())), k1(GetRand(std::numeric_limits<uint64_t>::max()))
{
}

static const uint64_t TXPOOL_DUMP_VERSION = 1;
bool LoadTxPool(void)
{
    int64_t nExpiryTimeout = txPoolExpiry.Value() * 60 * 60;
    FILE *fileTxpool = fopen((GetDataDir() / "txpool.dat").string().c_str(), "rb");
    if (!fileTxpool)
    {
        LOGA("Failed to open txpool file from disk. Continuing anyway.\n");
        return false;
    }
    CAutoFile file(fileTxpool, SER_DISK, CLIENT_VERSION);
    if (file.IsNull())
    {
        LOGA("Failed to open txpool file from disk. Continuing anyway.\n");
        return false;
    }

    int64_t count = 0;
    int64_t skipped = 0;
    int64_t nNow = GetTime();

    try
    {
        uint64_t version;
        file >> version;
        if (version != TXPOOL_DUMP_VERSION)
        {
            return false;
        }
        uint64_t num;
        file >> num;
        double prioritydummy = 0;
        while (num--)
        {
            CTransaction tx;
            int64_t nTime;
            int64_t nFeeDelta;
            file >> tx;
            file >> nTime;
            file >> nFeeDelta;

            CAmount amountdelta = nFeeDelta;
            if (amountdelta)
            {
                mempool.PrioritiseTransaction(tx.GetId(), prioritydummy, amountdelta);
            }
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
        std::map<uint256, CAmount> mapDeltas;
        file >> mapDeltas;

        for (const auto &i : mapDeltas)
        {
            mempool.PrioritiseTransaction(i.first, prioritydummy, i.second);
        }
    }
    catch (const std::exception &e)
    {
        LOGA("Failed to deserialize txpool data on disk: %s. Continuing anyway.\n", e.what());
        return false;
    }

    // Because we enqueue the txns we may get some ending up in the orphan pool, so
    // flushing here at the end ensures all orphans will get processed.
    FlushTxAdmission();

    LOGA("Imported txpool transactions from disk: %i successes, %i expired\n", count, skipped);
    return true;
}

bool DumpTxPool(void)
{
    int64_t start = GetStopwatchMicros();

    std::map<uint256, CAmount> mapDeltas;
    std::vector<TxMempoolInfo> vInfo;

    {
        READLOCK(mempool.cs_txmempool);
        for (const auto &i : mempool.mapDeltas)
        {
            mapDeltas[i.first] = i.second.first;
        }
        vInfo = mempool.AllTxMempoolInfo();
    }

    int64_t mid = GetStopwatchMicros();

    try
    {
        FILE *fileTxpool = fopen((GetDataDir() / "txpool.dat.new").string().c_str(), "wb");
        if (!fileTxpool)
        {
            LOGA("Could not dump txpool, failed to open the txpool file from disk. Continuing anyway.\n");
            return false;
        }

        CAutoFile file(fileTxpool, SER_DISK, CLIENT_VERSION);

        uint64_t version = TXPOOL_DUMP_VERSION;
        file << version;

        file << (uint64_t)vInfo.size();
        for (const auto &i : vInfo)
        {
            file << *(i.tx);
            file << (int64_t)i.nTime;
            file << (int64_t)i.feeDelta;
            mapDeltas.erase(i.tx->GetId());
        }

        file << mapDeltas;
        FileCommit(file.Get());
        file.fclose();
        RenameOver(GetDataDir() / "txpool.dat.new", GetDataDir() / "txpool.dat");
        int64_t last = GetStopwatchMicros();
        LOGA("Dumped txpool: %gs to copy, %gs to dump\n", (mid - start) * 0.000001, (last - mid) * 0.000001);
    }
    catch (const std::exception &e)
    {
        LOGA("Failed to dump txpool: %s. Continuing anyway.\n", e.what());
        return false;
    }
    return true;
}

void dbgPrintMempool(CTxMemPool &pool)
{
    std::stringstream s;
    for (auto &it : pool.mapTx)
    {
        s << it.GetTx().ToString() << "\n";
    }
    printf("%s\n", s.str().c_str());
}
