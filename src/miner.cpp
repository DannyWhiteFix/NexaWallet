// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2023 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "miner.h"

#include "amount.h"
#include "chain.h"
#include "chainparams.h"
#include "coins.h"
#include "consensus/adaptive_blocksize.h"
#include "consensus/consensus.h"
#include "consensus/merkle.h"
#include "consensus/tx_verify.h"
#include "consensus/validation.h"
#include "hashwrapper.h"
#include "main.h"
#include "net.h"
#include "policy/policy.h"
#include "pow.h"
#include "primitives/transaction.h"
#include "script/standard.h"
#include "timedata.h"
#include "txmempool.h"
#include "unlimited.h"
#include "util.h"
#include "utilmoneystr.h"
#include "validation/validation.h"
#include "validationinterface.h"

#include <algorithm>
#include <boost/thread.hpp>
#include <boost/tuple/tuple.hpp>
#include <queue>
#include <thread>

// Track timing information for Package mining.
std::atomic<int64_t> nTotalPackage{0};

/** Maximum number of failed attempts to insert a package into a block */
static const unsigned int MAX_PACKAGE_FAILURES = 5;
extern CTweak<unsigned int> xvalTweak;
extern CTweak<uint32_t> dataCarrierSize;
extern CTweak<uint64_t> miningPrioritySize;

/** Hold current block templates size and transaction counts */
extern CCriticalSection csCurrentCandidate;
extern uint64_t nLastBlockTx;
extern uint64_t nLastBlockSize;

using namespace std;

//////////////////////////////////////////////////////////////////////////////
//
// BitcoinMiner
//

//
// Unconfirmed transactions in the memory pool often depend on other
// transactions in the memory pool. When we select transactions from the
// pool, we select by highest priority or fee rate, so we might consider
// transactions that depend on transactions that aren't yet in the block.

int64_t UpdateTime(CBlockHeader *pblock, const Consensus::Params &consensusParams, const CBlockIndex *pindexPrev)
{
    int64_t nOldTime = pblock->nTime;
    int64_t nNewTime = std::max(pindexPrev->GetMedianTimePast() + 1, GetAdjustedTime());

    if (nOldTime < nNewTime)
        pblock->nTime = nNewTime;

    // Updating time can change work required on testnet:
    if (consensusParams.fPowAllowMinDifficultyBlocks)
        pblock->nBits = GetNextWorkRequired(pindexPrev, pblock, consensusParams);

    return nNewTime - nOldTime;
}

BlockAssembler::BlockAssembler(const CChainParams &_chainparams) : chainparams(_chainparams) {}
void BlockAssembler::resetBlock(const CScript &scriptPubKeyIn, int64_t coinbaseSize)
{
    inBlock.clear();

    nBlockSize = reserveBlockSize(scriptPubKeyIn, coinbaseSize);
    nBlockSigOps = COINBASE_RESERVED_SIGOPS;

    // These counters do not include coinbase tx
    nBlockTx = 0;
    nFees = 0;

    lastFewTxs = 0;
    blockFinished = false;

    nBlockMaxSize = 0;
    nBlockMinSize = 0;
    maxSigOpsAllowed = 0;
}

uint64_t BlockAssembler::reserveBlockSize(const CScript &scriptPubKeyIn, int64_t coinbaseSize)
{
    CBlockHeader h;
    uint64_t nHeaderSize, nCoinbaseSize, nCoinbaseReserve;

    // Add the proper block size quantity to the actual size
    // TODO make this a constant when header size stabilizes
    nHeaderSize = ::GetSerializeSize(h, SER_NETWORK, PROTOCOL_VERSION);
    // assert(nHeaderSize == 80);
    // tx count varint - 5 bytes is enough for 4 billion txs; 3 bytes for 65535 txs
    nHeaderSize += TXCOUNT_VARINT_PADDING;
    // height varint - 5 bytes is enough for 4 billion blocks
    nHeaderSize += HEIGHT_VARINT_PADDING;
    // feePoolAmt varints
    nHeaderSize += FEEPOOL_VARINT_PADDING;


    // This serializes with output value, a fixed-length 8 byte field, of zero and height, a serialized CScript
    // signed integer taking up 4 bytes for heights 32768-8388607 (around the year 2167) after which it will use 5
    nCoinbaseSize = ::GetSerializeSize(coinbaseTx(scriptPubKeyIn, 400000, 0), SER_NETWORK, PROTOCOL_VERSION);

    if (coinbaseSize >= 0) // Explicit size of coinbase has been requested
    {
        nCoinbaseReserve = (uint64_t)coinbaseSize;
    }
    else
    {
        nCoinbaseReserve = coinbaseReserve.Value();
    }

    // BU Miners take the block we give them, wipe away our coinbase and add their own.
    // So if their reserve choice is bigger then our coinbase then use that.
    nCoinbaseSize = std::max(nCoinbaseSize, nCoinbaseReserve);

    return nHeaderSize + nCoinbaseSize;
}
CTransactionRef BlockAssembler::coinbaseTx(const CScript &scriptPubKeyIn, int _nHeight, CAmount nValue)
{
    CMutableTransaction tx;

    tx.vin.resize(0);
    tx.vout.resize(2);
    // Coinbase uniquification must be stored in a vout because idem does not cover scriptSig
    const int dataIdx = 1;
    tx.vout[dataIdx] = CTxOut(0, CScript() << OP_RETURN << _nHeight);
    tx.vout[0] = CTxOut(nValue, scriptPubKeyIn);

    // BU005 add block size settings to the coinbase
    std::string cbmsg = FormatCoinbaseMessage(BUComments, minerComment);
    const char *cbcstr = cbmsg.c_str();
    vector<unsigned char> vec(cbcstr, cbcstr + cbmsg.size());
    {
        LOCK(cs_coinbaseFlags);
        COINBASE_FLAGS = CScript() << vec;
        // Chop off any extra data in the COINBASE_FLAGS so the sig does not exceed the max.
        // we can do this because the coinbase is not a "real" script...
        if (tx.vout[dataIdx].scriptPubKey.size() + COINBASE_FLAGS.size() > dataCarrierSize.Value())
        {
            COINBASE_FLAGS.resize(dataCarrierSize.Value() - tx.vout[dataIdx].scriptPubKey.size());
        }

        tx.vout[dataIdx].scriptPubKey = tx.vout[dataIdx].scriptPubKey + COINBASE_FLAGS;
    }

    // Make sure the coinbase is big enough.
    uint64_t nCoinbaseSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
    if (nCoinbaseSize < MIN_TX_SIZE)
    {
        tx.vout[dataIdx].scriptPubKey << std::vector<uint8_t>(MIN_TX_SIZE - nCoinbaseSize - 1);
    }

    return MakeTransactionRef(std::move(tx));
}

struct NumericallyLessTxHashComparator
{
public:
    bool operator()(const CTxMemPoolEntry *a, const CTxMemPoolEntry *b) const
    {
        return a->GetTx().GetId() < b->GetTx().GetId();
    }
};

std::unique_ptr<CBlockTemplate> BlockAssembler::CreateNewBlock(const CScript &scriptPubKeyIn, int64_t coinbaseSize)
{
    resetBlock(scriptPubKeyIn, coinbaseSize);

    // The constructed block template
    std::unique_ptr<CBlockTemplate> pblocktemplate(new CBlockTemplate());

    CBlockRef pblock = pblocktemplate->block;

    // Add dummy coinbase tx as first transaction
    pblock->vtx.emplace_back();
    pblocktemplate->vTxFees.push_back(-1); // updated at end
    pblocktemplate->vTxSigOps.push_back(-1); // updated at end

    LOCK(cs_main);

    // Largest block you're willing to create:
    CBlockIndex *pindexPrev = chainActive.Tip();
    assert(pindexPrev); // can't make a new block if we don't even have the genesis block
    nBlockMaxSize = pindexPrev->GetNextMaxBlockSize();
    if (miningBlockSize.Value() > 0 && nBlockMaxSize > miningBlockSize.Value())
        nBlockMaxSize = miningBlockSize.Value();

    // Minimum block size you want to create; block will be filled with free transactions
    // until there are no more or the block reaches this size:
    nBlockMinSize = std::min(nBlockMaxSize, miningPrioritySize.Value());

    // Maximum sigops allowed in this block based on largest block size we're willing to create.
    maxSigOpsAllowed = GetMaxBlockSigChecks(pindexPrev->GetNextMaxBlockSize());

    {
        READLOCK(mempool.cs_txmempool);
        nHeight = pindexPrev->height() + 1;

        pblock->nTime = GetAdjustedTime();
        pblock->height = nHeight;

        const int64_t nMedianTimePast = pindexPrev->GetMedianTimePast();
        nLockTimeCutoff =
            (STANDARD_LOCKTIME_VERIFY_FLAGS & LOCKTIME_MEDIAN_TIME_PAST) ? nMedianTimePast : pblock->GetBlockTime();

        std::vector<const CTxMemPoolEntry *> vtxe;
        addPriorityTxs(&vtxe);

        // Mine by package (CPFP)
        // We make two passes through addPackageTxs(). The first pass is for
        // transactions and chains that are not dirty, which will likely be the bulk
        // of the block. Then a second quick pass is made to see if any dirty transactions
        // would be able to fill the rest of the block.
        int64_t nStartPackage = GetStopwatchMicros();
        addPackageTxs(&vtxe, false);
        addPackageTxs(&vtxe, true);
        nTotalPackage += GetStopwatchMicros() - nStartPackage;

        {
            LOCK(csCurrentCandidate);
            nLastBlockTx = nBlockTx;
            nLastBlockSize = nBlockSize;
        }
        LOGA("CreateNewBlock: total size %llu txs: %llu of %llu fees: %lld sigops %u\n", nBlockSize, nBlockTx,
            mempool._size(), nFees, nBlockSigOps);


        // sort tx if there are any and the feature is enabled
        std::sort(vtxe.begin(), vtxe.end(), NumericallyLessTxHashComparator());

        for (auto &txe : vtxe)
        {
            pblocktemplate->block->vtx.push_back(txe->GetSharedTx());
            pblocktemplate->vTxFees.push_back(txe->GetFee());
            pblocktemplate->vTxSigOps.push_back(txe->GetSigOpCount());
        }

        // Create coinbase transaction.
        pblock->vtx[0] =
            coinbaseTx(scriptPubKeyIn, nHeight, nFees + GetBlockSubsidy(nHeight, chainparams.GetConsensus()));
        pblocktemplate->vTxFees[0] = -nFees;

        // Fill in header
        pblock->hashPrevBlock = pindexPrev->GetBlockHash();
        pblock->hashAncestor = pindexPrev->GetChildsConsensusAncestor()->GetBlockHash();
        UpdateTime(pblock.get(), chainparams.GetConsensus(), pindexPrev);
        pblock->nBits = GetNextWorkRequired(pindexPrev, pblock.get(), chainparams.GetConsensus());
        pblock->chainWork = ArithToUint256(pindexPrev->chainWork() + GetWorkForDifficultyBits(pblock->nBits));
        pblock->feePoolAmt = 0; // to be used later
        pblocktemplate->vTxSigOps[0] = 0;
    }

    // All the transactions in this block are from the mempool and therefore we can use XVal to speed
    // up the testing of the block validity. Set XVal flag for new blocks to true unless otherwise
    // configured.
    pblock->fXVal = xvalTweak.Value();

    pblock->UpdateHeader(); // fill values like num tx, size, and merkle root
    CValidationState state;
    if (!TestBlockValidity(state, chainparams, pblock, pindexPrev, false, false))
    {
        throw std::runtime_error(strprintf("%s: TestBlockValidity failed: %s", __func__, FormatStateMessage(state)));
    }

    return pblocktemplate;
}

bool BlockAssembler::isStillDependent(CTxMemPool::TxIdIter iter)
{
    for (CTxMemPool::TxIdIter parent : mempool.GetMemPoolParents(iter))
    {
        if (!inBlock.count(parent))
        {
            return true;
        }
    }
    return false;
}

bool BlockAssembler::TestPackageSigOps(uint64_t packageSize, unsigned int packageSigOps)
{
    if (nBlockSigOps + packageSigOps > maxSigOpsAllowed)
        return false;
    return true;
}

// Block size and sigops have already been tested.  Check that all transactions
// are final.
bool BlockAssembler::TestPackageFinality(const CTxMemPool::setEntries &package)
{
    for (const CTxMemPool::TxIdIter it : package)
    {
        if (!IsFinalTx(it->GetSharedTx(), nHeight, nLockTimeCutoff))
            return false;
    }
    return true;
}

// Return true if incremental tx or txs in the block with the given size and sigop count would be
// valid, and false otherwise.  If false, blockFinished and lastFewTxs are updated if appropriate.
bool BlockAssembler::IsIncrementallyGood(uint64_t nExtraSize, unsigned int nExtraSigOps)
{
    if (nBlockSize + nExtraSize > nBlockMaxSize)
    {
        // If the block is so close to full that no more txs will fit
        // or if we've tried more than 50 times to fill remaining space
        // then flag that the block is finished
        if (nBlockSize > nBlockMaxSize - 100 || lastFewTxs > 50)
        {
            blockFinished = true;
            return false;
        }
        // Once we're within 1000 bytes of a full block, only look at 50 more txs
        // to try to fill the remaining space.
        if (nBlockSize > nBlockMaxSize - 1000)
        {
            lastFewTxs++;
        }
        return false;
    }

    if (nBlockSigOps + nExtraSigOps > maxSigOpsAllowed)
    {
        // very close to the limit, so the block is finished.  So a block that is near the sigops limit
        // might be shorter than it could be if the high sigops tx was backed out and other tx added.
        if (nBlockSigOps > maxSigOpsAllowed - 2)
            blockFinished = true;
        return false;
    }

    return true;
}

bool BlockAssembler::TestForBlock(CTxMemPool::TxIdIter iter)
{
    if (!IsFinalTx(iter->GetSharedTx(), nHeight, nLockTimeCutoff))
        return false;

    if (!IsIncrementallyGood(iter->GetTxSize(), iter->GetSigOpCount()))
        return false;

    return true;
}

void BlockAssembler::AddToBlock(std::vector<const CTxMemPoolEntry *> *vtxe, CTxMemPool::TxIdIter iter)
{
    const CTxMemPoolEntry &tmp = *iter;
    vtxe->push_back(&tmp);
    nBlockSize += iter->GetTxSize();
    ++nBlockTx;
    nBlockSigOps += iter->GetSigOpCount();
    nFees += iter->GetFee();
    inBlock.insert(iter);

    bool fPrintPriority = GetBoolArg("-printpriority", DEFAULT_PRINTPRIORITY);
    if (fPrintPriority)
    {
        double dPriority = iter->GetPriority(nHeight);
        CAmount dummy;
        mempool._ApplyDeltas(iter->GetTx().GetId(), dPriority, dummy);
        mempool._ApplyDeltas(iter->GetTx().GetIdem(), dPriority, dummy);
        LOGA("priority %.1f fee %s txid %s\n", dPriority,
            CFeeRate(iter->GetModifiedFee(), iter->GetTxSize()).ToString().c_str(),
            iter->GetTx().GetId().ToString().c_str());
    }
}

void BlockAssembler::SortForBlock(const CTxMemPool::setEntries &package,
    std::vector<CTxMemPool::TxIdIter> &sortedEntries)
{
    // Sort package by ancestor count
    // If a transaction A depends on transaction B, then A's ancestor count
    // must be greater than B's.  So this is sufficient to validly order the
    // transactions for block inclusion.
    sortedEntries.clear();
    sortedEntries.insert(sortedEntries.begin(), package.begin(), package.end());
    std::sort(sortedEntries.begin(), sortedEntries.end(), CompareTxIdIterByAncestorCount());
}

// This transaction selection algorithm orders the mempool based
// on feerate of a transaction including all unconfirmed ancestors.
//
// This is accomplished by considering a group of ancestors as a single transaction. We can call these
// transactions, Ancestor Grouped Transactions (AGT). This approach to grouping allows us to process
// packages orders of magnitude faster than other methods of package mining since we no longer have
// to continuously update the descendant state as we mine part of an unconfirmed chain.
//
// There is a theoretical flaw in this approach which could happen when a block is almost full. We
// could for instance end up including a lower fee transaction as part of an ancestor group when
// in fact it would be better, in terms of fees, to include some other single transaction. This
// would result in slightly less fees (perhaps a few hundred satoshis) rewarded to the miner. However,
// this situation is not likely to be seen for two reasons. One, long unconfirmed chains are typically
// having transactions with all the same fees and Two, the typical child pays for parent scenario has only
// two transactions with the child having the higher fee. And neither of these two types of packages could
// cause any loss of fees with this mining algorithm, when the block is nearly full.
//
// The mining algorithm is surprisingly simple and centers around parsing though the mempools ancestor_score
// index and adding the AGT's into the new block. There is however a pathological case which has to be
// accounted for where a child transaction has less fees per KB than its parent which causes child transactions
// to show up later as we parse though the ancestor index. In this case we then have to recalculate the
// ancestor sigops and package size which can be time consuming given we have to parse through the ancestor
// tree each time. However we get around that by shortcutting the process by parsing through only the portion
// of the tree that is currently not in the block. This shortcutting happens in _CalculateMempoolAncestors()
// where we pass in the inBlock vector of already added transactions. Even so, if we didn't do this shortcutting
// the current algo is still much better than the older method which needed to update calculations for the
// entire descendant tree after each package was added to the block.

void BlockAssembler::addPackageTxs(std::vector<const CTxMemPoolEntry *> *vtxe, bool fAllowDirtyTxns)
{
    AssertLockHeld(mempool.cs_txmempool);

    CTxMemPool::TxIdIter iter;
    uint64_t nPackageFailures = 0;
    for (auto mi = mempool.mapTx.get<ancestor_score>().begin(); mi != mempool.mapTx.get<ancestor_score>().end(); mi++)
    {
        iter = mempool.mapTx.project<0>(mi);

        // Skip txns we know are in the block
        if (inBlock.count(iter) || (fAllowDirtyTxns == false && iter->IsDirty() == true))
        {
            continue;
        }

        uint64_t packageSize = iter->GetSizeWithAncestors();
        CAmount packageFees = iter->GetModFeesWithAncestors();
        // mempool uses same field for sigops and sigchecks
        unsigned int packageSigOps = iter->GetSigOpCountWithAncestors();

        // Get any unconfirmed ancestors of this txn
        CTxMemPool::setEntries ancestors;
        uint64_t nNoLimit = std::numeric_limits<uint64_t>::max();
        std::string dummy;
        mempool._CalculateMemPoolAncestors(*iter, ancestors, nNoLimit, nNoLimit, dummy, &inBlock, false);

        // Include in the package the current txn we're working with
        ancestors.insert(iter);

        // Recalculate sigops and package size, only if there were txns already in the block for
        // this set of ancestors
        if (iter->GetCountWithAncestors() > ancestors.size())
        {
            packageSize = 0;
            packageSigOps = 0;
            for (auto &it : ancestors)
            {
                packageSize += it->GetTxSize();
                packageSigOps += it->GetSigOpCount();
            }
        }

        // Do not add free transactions here. They should only be added in addPriorityTxes()
        if (packageFees < ::minRelayTxFee.GetFee(packageSize))
        {
            return;
        }

        // Test if package fits in the block
        if (nBlockSize + packageSize > nBlockMaxSize)
        {
            if (nBlockSize > nBlockMaxSize * .50)
            {
                nPackageFailures++;
            }

            // If we keep failing then the block must be almost full so bail out here.
            if (nPackageFailures >= MAX_PACKAGE_FAILURES)
                return;
            else
                continue;
        }

        // Test that the package does not exceed sigops limits
        if (!TestPackageSigOps(packageSize, packageSigOps))
        {
            continue;
        }

        // Test if all tx's are Final
        if (!TestPackageFinality(ancestors))
        {
            continue;
        }

        // The Package can now be added to the block.
        for (auto &it : ancestors)
        {
            AddToBlock(vtxe, it);
        }
    }
}

void BlockAssembler::addPriorityTxs(std::vector<const CTxMemPoolEntry *> *vtxe)
{
    // How much of the block should be dedicated to high-priority transactions,
    // included regardless of the fees they pay
    uint64_t nBlockPrioritySize = miningPrioritySize.Value();
    nBlockPrioritySize = std::min(nBlockMaxSize, nBlockPrioritySize);
    if (nBlockPrioritySize == 0)
    {
        return;
    }

    // This vector will be sorted into a priority queue:
    vector<TxCoinAgePriority> vecPriority;
    TxCoinAgePriorityCompare pricomparer;
    std::map<CTxMemPool::TxIdIter, double, CTxMemPool::CompareIteratorById> waitPriMap;
    typedef std::map<CTxMemPool::TxIdIter, double, CTxMemPool::CompareIteratorById>::iterator waitPriIter;
    double actualPriority = -1;

    vecPriority.reserve(mempool.mapTx.size());
    for (CTxMemPool::indexed_transaction_set::iterator mi = mempool.mapTx.begin(); mi != mempool.mapTx.end(); ++mi)
    {
        double dPriority = mi->GetPriority(nHeight);
        CAmount dummy;
        // Check both id and idem for a stored priority adjustment
        mempool._ApplyDeltas(mi->GetTx().GetId(), dPriority, dummy);
        mempool._ApplyDeltas(mi->GetTx().GetIdem(), dPriority, dummy);
        vecPriority.push_back(TxCoinAgePriority(dPriority, mi));
    }
    std::make_heap(vecPriority.begin(), vecPriority.end(), pricomparer);

    // Try adding txns from the priority queue to fill the blockprioritysize
    CTxMemPool::TxIdIter iter;
    while (!vecPriority.empty() && !blockFinished)
    {
        iter = vecPriority.front().second;
        actualPriority = vecPriority.front().first;
        std::pop_heap(vecPriority.begin(), vecPriority.end(), pricomparer);
        vecPriority.pop_back();

        // If tx already in block, skip
        if (inBlock.count(iter))
        {
            DbgAssert(false, ); // shouldn't happen for priority txs
            continue;
        }

        // If tx is dependent on other mempool txs which haven't yet been included
        // then put it in the waitSet
        if (isStillDependent(iter))
        {
            waitPriMap.insert(std::make_pair(iter, actualPriority));
            continue;
        }

        // If this tx fits in the block add it, otherwise keep looping
        if (TestForBlock(iter))
        {
            // If now that this txs is added we've surpassed our desired priority size
            // or have dropped below the AllowFreeThreshold, then we're done adding priority txs
            if (nBlockSize + iter->GetTxSize() > nBlockPrioritySize || !AllowFree(actualPriority))
            {
                return;
            }
            AddToBlock(vtxe, iter);


            // This tx was successfully added, so
            // add transactions that depend on this one to the priority queue to try again
            for (CTxMemPool::TxIdIter child : mempool.GetMemPoolChildren(iter))
            {
                waitPriIter wpiter = waitPriMap.find(child);
                if (wpiter != waitPriMap.end())
                {
                    vecPriority.push_back(TxCoinAgePriority(wpiter->second, child));
                    std::push_heap(vecPriority.begin(), vecPriority.end(), pricomparer);
                    waitPriMap.erase(wpiter);
                }
            }
        }
    }
}
