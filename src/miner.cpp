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
#include "daa.h"
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
#include "validation/tailstorm.h"
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
static const unsigned int MAX_PACKAGE_FAILURES = 1000;
/** The point at which we start triggering for package failures when filling a block */
static const float MAX_BLOCKSIZE_RATIO = 0.95;

extern CTweak<unsigned int> xvalTweak;
extern CTweak<uint32_t> dataCarrierSize;
extern CTweak<uint64_t> miningPrioritySize;
extern CTweak<bool> fastBlockTemplate;

/** Hold current block templates size and transaction counts */
extern CCriticalSection csCurrentCandidate;
extern uint64_t nLastBlockTx;
extern uint64_t nLastBlockSize;

extern bool fPrintPriority;

using namespace std;

//////////////////////////////////////////////////////////////////////////////
//
// BitcoinMiner
//

//
// Unconfirmed transactions in the txpool often depend on other
// transactions in the txpool. When we select transactions from the
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
    {
        if (fTailstormEnabled)
            pblock->nBits = GetNextWorkRequired(pindexPrev, pblock, consensusParams);
        else
            pblock->nBits = GetNextNonTailstormWorkRequired(pindexPrev, pblock, consensusParams);
    }

    return nNewTime - nOldTime;
}

bool ValidateSummaryBlockCoinbase(CAmount nBlockReward, ConstCBlockRef pblock, std::set<CTreeNodeRef> &setBestDag)
{
    CScript scriptPubKeySummaryBlock; // just a placeholder for the summary block

    // Construct vout for the tailstorm Summary block. For now it's just temporary
    // and will be cleared out and reconstructed later when/if the vouts get grouped
    // by their pubkeys.
    std::vector<CTxOut> vout;
    vout.resize(setBestDag.size() + 1);

    // Calculate the scores for each node and divide up the rewards accordingly.
    auto mapScores = GetDagScores(setBestDag);
    uint32_t nSummaryBlockScore = Params().GetConsensus().tailstorm_k - 1;
    uint32_t nTotalScores = nSummaryBlockScore;
    for (auto &mi : mapScores)
    {
        nTotalScores += mi.second;
    }

    int j = 0;
    CAmount nTotalSubsidies = 0;
    for (auto &mi : mapScores)
    {
        vout[j] = mi.first->subblock->vtx[0]->vout[0];
        vout[j].nValue = nBlockReward * mi.second / nTotalScores;
        nTotalSubsidies += vout[j].nValue;
        j++;
    }

    // Add the vout for the Summary blocks' subblock...the final subblock!
    CAmount nSummaryBlockReward = nBlockReward * nSummaryBlockScore / nTotalScores;
    vout[j] = CTxOut(nSummaryBlockReward, scriptPubKeySummaryBlock);
    nTotalSubsidies += vout[j].nValue;
    LOG(DAG, "%s: total subsidies %ld with bestdag vout size %ld", __func__, nTotalSubsidies, vout.size());

    // Adjust the last vout for round off errors. Give any remaining subsidy to the
    // last vout (the SummaryBlock's subblock)
    vout[j].nValue += (nBlockReward - nTotalSubsidies);
    LOG(DAG, "%s: nValue for the summary block itself %ld", __func__, vout[j].nValue);

    // Combine vout's that have the same scriptPubKey. Over time this can save a large amount
    // blockchain diskspace
    std::map<CScript, CTxOut> mapGroupedDagOutputs;
    for (auto &out : vout)
    {
        if (!mapGroupedDagOutputs.count(out.scriptPubKey))
        {
            mapGroupedDagOutputs[out.scriptPubKey] = out;
        }
        else
        {
            mapGroupedDagOutputs[out.scriptPubKey].nValue += out.nValue;
        }
    }

    // Begin to check whether the block's coinbase matches what we just created
    // from the subblocks that were retreived from the dag. We do this by adding
    // the block's coinbase outputs to a map which we'll use to compare to the
    // map of grouped outputs we generated from the subblock bestDag.
    std::map<CScript, CTxOut> mapCoinbaseOutputs;
    for (auto iter = pblock->vtx[0]->vout.begin(); iter < pblock->vtx[0]->vout.end() - 1; iter++)
    {
        const CTxOut &out = *iter;
        if (!mapCoinbaseOutputs.count(out.scriptPubKey))
        {
            mapCoinbaseOutputs[out.scriptPubKey] = out;
        }
        else
        {
            mapCoinbaseOutputs[out.scriptPubKey].nValue += out.nValue;
        }
    }
    LOG(DAG, "%s: coinbase vout size %ld", __func__, pblock->vtx[0]->vout.size());

    // Do the comparison.
    //
    // The output values and pubkeys from the best dag must match what is in the coinbase vout minus
    // the summary blocks own reward.  There is a special case where the miner that mined the summary
    // block also mined "ALL" the subblocks. In such a case, all the best dag coinbase vout pubkeys would
    // be the same and "MUST" match the summary block pubkey the sum total of rewards also matching.
    LOG(DAG, "%s: blockreward: %ld", __func__, nBlockReward);
    CAmount nCoinbaseSummary = 0;

    // Check special case where there is only one summary block coinbase output
    if (mapCoinbaseOutputs.size() == 1)
    {
        for (auto treenode : setBestDag)
        {
            if (!mapCoinbaseOutputs.count(treenode->subblock->vtx[0]->vout[0].scriptPubKey))
            {
                return false;
            }
        }
    }

    for (auto iter : mapCoinbaseOutputs)
    {
        const CScript &pubkey = iter.first;
        if ((mapGroupedDagOutputs.count(pubkey) > 0 && mapCoinbaseOutputs.count(pubkey) > 0 &&
                mapCoinbaseOutputs.size() > 1) &&
            (mapGroupedDagOutputs[pubkey].nValue == mapCoinbaseOutputs[pubkey].nValue))
        {
            mapGroupedDagOutputs.erase(pubkey);
        }
        else
        {
            nCoinbaseSummary += iter.second.nValue;
        }
    }

    // Check the final values which should add up to equal the summary blocks value
    // plus any other values that relate to the same pubkey.
    CAmount nGroupedSummaryValue = 0;
    for (auto iter : mapGroupedDagOutputs)
    {
        nGroupedSummaryValue += iter.second.nValue;
    }
    LOG(DAG, "%s: nGroupedSummaryValue is %ld nCoinbaseSummary is %ld", __func__, nGroupedSummaryValue,
        nCoinbaseSummary);

    return (nGroupedSummaryValue == nCoinbaseSummary);
}

BlockAssembler::BlockAssembler(const CChainParams &_chainparams) : chainparams(_chainparams) {}
void BlockAssembler::resetBlock(const CScript &scriptPubKeyIn, int64_t coinbaseSize, std::set<CTreeNodeRef> *setBestDag)
{
    inBlock.clear();
    nonFinalChains.clear();

    nBlockSize = reserveBlockSize(scriptPubKeyIn, coinbaseSize, setBestDag);
    nBlockSigOps = 0;

    // These counters do not include coinbase tx
    nBlockTx = 0;
    nFees = 0;

    lastFewTxs = 0;
    blockFinished = false;
}

uint64_t BlockAssembler::reserveBlockSize(const CScript &scriptPubKeyIn,
    int64_t coinbaseSize,
    std::set<CTreeNodeRef> *setBestDag)
{
    CBlockHeader h;
    uint64_t nHeaderSize, nCoinbaseSize, nCoinbaseReserve = 0;

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
    // minerData size (minerData version byte, + the dag size * (mininghash size + max nonce size))
    if (fTailstormEnabled)
        nHeaderSize += (1 + (setBestDag->size() * (32 + 16)));


    // This serializes with output value, a fixed-length 8 byte field, of zero and height, a serialized CScript
    // signed integer taking up 4 bytes for heights 32768-8388607 (around the year 2167) after which it will use 5
    //
    // In tailstorm we have to account for a larger coinbase where the summary block coinbase can have up to tailstorm_k
    // number of outputs in the summary block
    nCoinbaseSize =
        ::GetSerializeSize(coinbaseTx(scriptPubKeyIn, 400000, 0, setBestDag), SER_NETWORK, PROTOCOL_VERSION);

    if (coinbaseSize >= 0) // Explicit size of coinbase has been requested
    {
        nCoinbaseReserve = (uint64_t)coinbaseSize;
    }
    else
    {
        nCoinbaseReserve = coinbaseReserve.Value();
    }

    // Miners take the block we give them, wipe away our coinbase and add their own.
    // So if their reserve choice is bigger then our coinbase then use that.
    nCoinbaseSize = std::max(nCoinbaseSize, nCoinbaseReserve);

    return nHeaderSize + nCoinbaseSize;
}
CTransactionRef BlockAssembler::coinbaseTx(const CScript &scriptPubKeyIn,
    int _nHeight,
    CAmount nValue,
    std::set<CTreeNodeRef> *setBestDag)
{
    CMutableTransaction tx;
    tx.vin.resize(0);

    // Create vout for coinbase
    uint32_t dataIdx = 1;
    if (!setBestDag || setBestDag->empty())
    {
        //  Construct vout for the legacy block OR the tailstorm subblock
        tx.vout.resize(dataIdx + 1);
        tx.vout[0] = CTxOut(nValue, scriptPubKeyIn);
    }
    else
    {
        // Construct vout for the tailstorm Summary block. For now it's just temporary
        // and will be cleared out and reconstructed later when/if the vouts get grouped
        // by their pubkeys.
        std::vector<CTxOut> vout;
        vout.resize(setBestDag->size() + 1);

        // Calculate the scores for each node and divide up the rewards accordingly.
        auto mapScores = GetDagScores(*setBestDag);
        uint32_t nSummaryBlockScore = Params().GetConsensus().tailstorm_k - 1;
        uint32_t nTotalScores = nSummaryBlockScore;
        for (auto &mi : mapScores)
        {
            nTotalScores += mi.second;
        }

        int j = 0;
        CAmount nTotalSubsidies = 0;
        for (auto &mi : mapScores)
        {
            vout[j] = mi.first->subblock->vtx[0]->vout[0];
            vout[j].nValue = nValue * mi.second / nTotalScores;
            nTotalSubsidies += vout[j].nValue;
            j++;
        }

        // Add the vout for the Summary blocks' subblock...the final subblock!
        CAmount nSummaryBlockReward = nValue * nSummaryBlockScore / nTotalScores;
        vout[j] = CTxOut(nSummaryBlockReward, scriptPubKeyIn);
        nTotalSubsidies += vout[j].nValue;
        LOG(DAG, "%s: total subsidies %ld with bestdag vout size %ld", __func__, nTotalSubsidies, vout.size());

        // Adjust the last vout for round off errors. Give any remaining subsidy to the
        // last vout (the SummaryBlock's subblock)
        vout[j].nValue += (nValue - nTotalSubsidies);
        LOG(DAG, "%s: nValue for the summary block itself %ld", __func__, vout[j].nValue);

        // Combine vout's that have the same scriptPubKey. Over time this can save a large amount
        // blockchain diskspace
        std::map<CScript, CTxOut> mapGroupedDagOutputs;
        for (auto &out : vout)
        {
            if (!mapGroupedDagOutputs.count(out.scriptPubKey))
            {
                mapGroupedDagOutputs[out.scriptPubKey] = out;
            }
            else
            {
                mapGroupedDagOutputs[out.scriptPubKey].nValue += out.nValue;
            }
        }

        // Construct the final vout for the tailstorm Summary block.
        int i = 0;
        dataIdx = mapGroupedDagOutputs.size();
        tx.vout.resize(dataIdx + 1);
        for (auto iter : mapGroupedDagOutputs)
        {
            tx.vout[i] = iter.second;
            i++;
        }
    }

    // Coinbase uniquification must be stored in a vout because idem does not cover scriptSig
    // NOTE: when tailstorm is enabled subblocks do not really need to be uniquified so using
    // whatever height the subblock has is fine regardless of whether other subblocks have the
    // same height.
    tx.vout[dataIdx] = CTxOut(0, CScript() << OP_RETURN << _nHeight);

    // add block size settings to the coinbase
    std::string cbMsg = FormatCoinbaseMessage(BUComments, minerComment);
    const char *cbCStr = cbMsg.c_str();
    vector<unsigned char> vec(cbCStr, cbCStr + cbMsg.size());
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

struct NumericallyLessVtxHashComparator
{
public:
    bool operator()(const CTransactionRef a, const CTransactionRef b) const { return a->GetId() < b->GetId(); }
};

std::unique_ptr<CBlockTemplate> BlockAssembler::CreateNewBlock(const CScript &scriptPubKeyIn, int64_t coinbaseSize)
{
    const auto &conparams = chainparams.GetConsensus();

    // The constructed block template
    std::unique_ptr<CBlockTemplate> pblocktemplate(new CBlockTemplate());

    CBlockRef pblock = pblocktemplate->block;

    // Add dummy coinbase tx as first transaction
    pblock->vtx.emplace_back();
    pblocktemplate->vTxFees.push_back(-1); // updated at end
    pblocktemplate->vTxSigOps.push_back(-1); // updated at end

    LOCK(cs_main);

    CBlockIndex *pindexPrev = chainActive.Tip();
    assert(pindexPrev); // can't make a new block if we don't even have the genesis block

    // Get the current best tailstorm dag and associated double spends, and for the purpose of syncronization
    // we'll use this same dataset throughout summary block construction.
    //
    // If there are less than tailstorm_k - 1 subblocks in the dag then the assumption is that we're creating a
    // subblock and so the data sets returned will be empty.
    std::set<CTreeNodeRef> setBestDag;
    std::vector<std::map<uint256, CTreeNodeRef> > vDoubleSpendTxns;
    std::map<COutPoint, CTransactionRef> mapInputs;
    tailstormForest.GetBestDagFor(pindexPrev->GetBlockHash(), setBestDag, &vDoubleSpendTxns, &mapInputs);

    // Get the set of invalid double spends which we "DO NOT" want to include in the final summary block.
    std::set<uint256> setTxnExclusions = GetTxnExclusionSet(setBestDag, vDoubleSpendTxns, mapInputs);

    // If tailstorm is enabled then gather all the txid's that are in the best dag so
    // we can filter those out when we add new transactions to a new subblock or summary
    // block template.
    std::set<uint256> setBestDagTxids;
    if (fTailstormEnabled)
    {
        for (auto &treenode : setBestDag)
        {
            const auto &vtx = treenode->subblock->vtx;
            for (size_t i = 1; i < vtx.size(); i++)
            {
                setBestDagTxids.insert(vtx[i]->GetId());
            }
        }

        // Generate the minerData field.
        pblock->minerData = GenerateMinerData(conparams.tailstorm_k, setBestDag);
    }

    // Init the block counters and size the coinbase accordingly.
    if (setBestDag.size() < (size_t)conparams.tailstorm_k - 1)
    {
        // Clearing the setBestDag is done here for a couple of reasons.
        // First, we have already created setBestDagTxids above which gets used latger
        // regardless of the setBestDag, and secondly in the case of a subblock
        // we want the setBestDag cleared so we only create a simple coinbase whereas
        // for a full Summary Block we'd need the setBestDag to create the full and more
        // complex coinbase.
        setBestDag.clear();
    }
    resetBlock(scriptPubKeyIn, coinbaseSize, &setBestDag);

    // Largest block you're willing to create:
    // TODO: in a future optimization we should be able to use up the any remaining space that the summary block
    //       could offer by first adding the dag txns to the summary block template and filling the extra space after.
    //       This would allow us to uncomment the nMaxBlockSize line below. However for now we just set the summary
    //       block size to be the same as any subblock and fill it accordingly.
    // nBlockMaxSize = IsSummaryBlock(pblock) ? pindexPrev->GetNextMaxBlockSize() :
    //                                         pindexPrev->GetNextMaxBlockSize() / conparams.tailstorm_k;
    nBlockMaxSize = IsSummaryBlock(pblock) && !IsTailstormSummaryBlock(pblock) ?
                        pindexPrev->GetNextMaxBlockSize() :
                        pindexPrev->GetNextMaxBlockSize() / conparams.tailstorm_k;

    if (miningBlockSize.Value() > 0)
    {
        // TODO: future optimization as above.
        // nBlockMaxSize =
        //    IsSummaryBlock(pblock) ? miningBlockSize.Value() : miningBlockSize.Value() / conparams.tailstorm_k;
        nBlockMaxSize = IsSummaryBlock(pblock) && !IsTailstormSummaryBlock(pblock) ?
                            miningBlockSize.Value() :
                            miningBlockSize.Value() / conparams.tailstorm_k;
    }

    // Minimum block size you want to create; block will be filled with free transactions
    // until there are no more or the block reaches this size:
    nBlockMinSize = std::min(nBlockMaxSize, miningPrioritySize.Value());

    // Maximum sigops allowed in this block based on largest block size we're willing to create.
    maxSigOpsAllowed = GetMaxBlockSigChecks(pindexPrev->GetNextMaxBlockSize());

    {
        // Load the block template with transactions
        READLOCK(mempool.cs_txmempool);
        nHeight = pindexPrev->height() + 1;

        pblock->nTime = GetAdjustedTime();
        pblock->height = nHeight;

        const int64_t nMedianTimePast = pindexPrev->GetMedianTimePast();
        nLockTimeCutoff =
            (STANDARD_LOCKTIME_VERIFY_FLAGS & LOCKTIME_MEDIAN_TIME_PAST) ? nMedianTimePast : pblock->GetBlockTime();

        std::vector<const CTxMemPoolEntry *> vtxe;
        bool fCreateFastTemplate = fastBlockTemplate.Value();
        // TODO: get fast block template to work with tailstorm summary blocks.  We need to make sure that not only
        // do all the txns from the txpool fit into the block, but that the summary block has all the
        // txns that are in the dag present, and that we have accounted for any double spends as well.
        if (fCreateFastTemplate && !IsTailstormSummaryBlock(pblock))
        {
            // Check if all txpool transactions will fit into a block and also doesn't exceed the sigops limit
            if (((nBlockSize + mempool._GetTotalTxSize()) <= nBlockMaxSize) &&
                (mempool._GetTotalSigOps() <= maxSigOpsAllowed))
            {
                // Dump all contents of txpool into the block
                for (auto iter = mempool.mapTx.begin(); iter != mempool.mapTx.end(); iter++)
                {
                    if (!setBestDagTxids.empty() && setBestDagTxids.count(iter->GetSharedTx()->GetId()))
                        continue;

                    AddToBlock(&vtxe, iter);
                }
            }
            else
            {
                fCreateFastTemplate = false;
            }
        }

        // If fast templates are not on or if the fast template failed for some reason then fall
        // through to the slower method.
        if (!fCreateFastTemplate)
        {
            addPriorityTxs(&vtxe, setBestDagTxids);

            // Mine by package (CPFP)
            // We make two passes through addPackageTxs(). The first pass is for
            // transactions and chains that are not dirty, which will likely be the bulk
            // of the block. Then a second quick pass is made to see if any dirty transactions
            // would be able to fill the rest of the block.
            int64_t nStartPackage = GetStopwatchMicros();
            if (!addPackageTxs(&vtxe, false, setBestDagTxids))
            {
                // Make another pass to add the dirty chains.
                addPackageTxs(&vtxe, true, setBestDagTxids);
            }
            nTotalPackage += GetStopwatchMicros() - nStartPackage;
        }

        // For all block types generate the largest block possible for that block type.
        std::set<uint256> setTxidsInBlock;
        {
            // sort transactions
            if (!fTailstormEnabled || !IsSummaryBlock(pblock))
            {
                std::sort(vtxe.begin(), vtxe.end(), NumericallyLessTxHashComparator());
            }

            // Load the block template
            pblocktemplate->block->vtx.reserve(vtxe.size());
            pblocktemplate->vTxFees.reserve(vtxe.size());
            pblocktemplate->vTxSigOps.reserve(vtxe.size());
            for (auto &txe : vtxe)
            {
                pblocktemplate->block->vtx.push_back(txe->GetSharedTx());
                pblocktemplate->vTxFees.push_back(txe->GetFee());
                pblocktemplate->vTxSigOps.push_back(txe->GetSigOpCount());

                setTxidsInBlock.insert(txe->GetSharedTx()->GetId());
            }
        }

        // If we're creating a tailstorm Summary Block then add in all the Subblock transactions
        // and, avoiding any dupicates and double spends we don't want, update the blocksize and fees collected.
        if (fTailstormEnabled && IsSummaryBlock(pblock))
        {
            uint64_t nBestDagVtxSize = 0;
            CAmount nBestDagFees = 0;
            uint64_t nBestDagTx = 0;

            for (auto &treenode : setBestDag)
            {
                const auto &vtx = treenode->subblock->vtx;
                for (size_t i = 1; i < vtx.size(); i++)
                {
                    // If txns are already in the summary block's "subblock" then don't add them again.
                    if (setTxidsInBlock.count(vtx[i]->GetId()))
                        continue;
                    // If this is a double spend exclusion then don't add this to the block.
                    if (setTxnExclusions.count(vtx[i]->GetId()))
                        continue;

                    pblocktemplate->block->vtx.push_back(vtx[i]);
                    nBestDagTx++;
                    nBestDagVtxSize += ::GetSerializeSize(vtx[i], SER_NETWORK, PROTOCOL_VERSION);
                    nBestDagFees += vtx[i]->GetValueIn() - vtx[i]->GetValueOut();

                    setTxidsInBlock.insert(vtx[i]->GetId());
                }
            }
            nBlockSize += nBestDagVtxSize;
            nFees += nBestDagFees;
            nBlockTx += nBestDagTx;

            std::sort(pblocktemplate->block->vtx.begin() + 1, pblocktemplate->block->vtx.end(),
                NumericallyLessVtxHashComparator());
        }

        // Update the candidate info
        {
            LOCK(csCurrentCandidate);
            nLastBlockTx = nBlockTx;
            nLastBlockSize = nBlockSize;
        }

        // Output appropriate log entry.
        if (IsSummaryBlock(pblock))
        {
            LOGA("Create New Block: total size %llu txs: %llu of txpool %llu fees: %lld sigops %u\n", nBlockSize,
                nBlockTx, mempool._size(), nFees, nBlockSigOps);
        }
        else
        {
            LOGA("Create New Subblock: total size %llu txs: %llu of txpool %llu fees: %lld sigops %u\n", nBlockSize,
                nBlockTx, mempool._size(), nFees, nBlockSigOps);
        }


        // Fill in header
        pblock->hashPrevBlock = pindexPrev->GetBlockHash();

        if (fTailstormEnabled)
            pblock->nBits = GetNextWorkRequired(pindexPrev, pblock.get(), conparams);
        else
            pblock->nBits = GetNextNonTailstormWorkRequired(pindexPrev, pblock.get(), conparams);

        // Create coinbase transaction.
        pblock->vtx[0] = coinbaseTx(scriptPubKeyIn, nHeight, nFees + GetBlockSubsidy(nHeight, conparams), &setBestDag);
        pblocktemplate->vTxFees[0] = -nFees;

        pblock->hashAncestor = pindexPrev->GetChildsConsensusAncestor()->GetBlockHash();
        UpdateTime(pblock.get(), chainparams.GetConsensus(), pindexPrev);

        auto work = GetWorkForDifficultyBits(pblock->nBits);
        work *= pblock->NumSubblocks() + 1;
        pblock->chainWork = ArithToUint256(pindexPrev->chainWork() + work);
        /*
        if (pblock->NumSubblocks() + 1 == conparams.tailstorm_k)
        {
            auto target = FromCompact(pblock->nBits);
            target *= conparams.tailstorm_k;
            auto fullblockTgt = GetNextNonTailstormBlockTarget(pindexPrev, pblock.get(), conparams);
            if (target != fullblockTgt)
            {
                throw std::runtime_error(strprintf("%s: work creation is broken", __func__));
            }
        }
        */

        pblock->feePoolAmt = 0; // to be used later
        pblocktemplate->vTxSigOps[0] = 0;
    }

    // All the transactions in this block are from the mempool and therefore we can use XVal to speed
    // up the testing of the block validity. Set XVal flag for new blocks to true unless otherwise
    // configured.
    pblock->fXVal = xvalTweak.Value();

    // Fill values like num tx, size, and merkle root
    pblock->UpdateHeader();

    // TestBlockValidity is a relatively time consuming process for large blocks so
    // only check block validity when running in regtest.  Once the block is created
    // and applied to the block chain the validity is checked again anyway so it's not
    // really necessary to do it twice, but it can make testing easier and is why it
    // should be left on in regtest mode.
    if (chainparams.NetworkIDString() == CBaseChainParams::REGTEST && fCheckBlockIndex)
    {
        CValidationState state;
        if (!TestBlockValidity(state, chainparams, pblock, pindexPrev, false, false))
        {
            throw std::runtime_error(strprintf("%s: TestBlockValidity failed: %s", __func__, state.GetLogString()));
        }
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
    if (!IsIncrementallyGood(iter->GetTxSize(), iter->GetSigOpCount()))
        return false;

    return true;
}

void BlockAssembler::RemoveFromBlock(std::vector<const CTxMemPoolEntry *> *vtxe, CTxMemPool::TxIdIter iter)
{
    if (!inBlock.count(iter))
        return;

    auto it = std::find(vtxe->begin(), vtxe->end(), &(*iter));
    if (it != vtxe->end())
        vtxe->erase(it);
    else
        return;

    nBlockSize -= iter->GetTxSize();
    --nBlockTx;
    nBlockSigOps -= iter->GetSigOpCount();
    nFees -= iter->GetFee();
    inBlock.erase(iter);
}

void BlockAssembler::AddToBlock(std::vector<const CTxMemPoolEntry *> *vtxe, CTxMemPool::TxIdIter iter)
{
    vtxe->push_back(&(*iter));
    nBlockSize += iter->GetTxSize();
    ++nBlockTx;
    nBlockSigOps += iter->GetSigOpCount();
    nFees += iter->GetFee();
    inBlock.insert(iter);

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
bool BlockAssembler::addPackageTxs(std::vector<const CTxMemPoolEntry *> *vtxe,
    bool fAllowDirtyTxns,
    std::set<uint256> &setBestDagTxids)
{
    AssertLockHeld(mempool.cs_txmempool);

    CTxMemPool::TxIdIter iter;
    uint64_t nPackageFailures = 0;
    bool fHaveDirty = false;
    for (auto mi = mempool.mapTx.get<ancestor_score>().begin(); mi != mempool.mapTx.get<ancestor_score>().end(); mi++)
    {
        iter = mempool.mapTx.project<CTxMemPool::TXID_CONTAINER_IDX>(mi);
        if (iter->IsDirty())
            fHaveDirty = true;

        // Skip txns we know are in the block and also skip if it's dirty but we're not allowing dirty txns.
        if (inBlock.count(iter) || nonFinalChains.count(iter) || (!fAllowDirtyTxns && iter->IsDirty()) ||
            (!setBestDagTxids.empty() && setBestDagTxids.count(iter->GetSharedTx()->GetId())))
        {
            continue;
        }

        uint64_t packageSize = iter->GetSizeWithAncestors();
        CAmount packageFees = iter->GetModFeesWithAncestors();
        // mempool uses same field for sigops and sigchecks
        unsigned int packageSigOps = iter->GetSigOpCountWithAncestors();

        // Get any unconfirmed ancestors of this txn
        //
        // CalculateMemPoolAncestors is a relatively expensive operation so only perform it when
        // absolutely necessary.
        CTxMemPool::setEntries ancestors;
        if (iter->IsDirty() || iter->GetCountWithAncestors() > 1)
        {
            uint64_t nNoLimit = std::numeric_limits<uint64_t>::max();
            std::string dummy;
            mempool._CalculateMemPoolAncestors(*iter, ancestors, nNoLimit, nNoLimit, dummy, &inBlock, false);
        }

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
        //
        // Also, if free transactions are being found here then we've exhausted all possible
        // transactions that could be added so just return.
        if (packageFees < ::minRelayTxFee.GetFee(packageSize))
        {
            return true;
        }

        // Test if package fits in the block
        if (nBlockSize + packageSize > nBlockMaxSize)
        {
            if (nBlockSize > nBlockMaxSize * MAX_BLOCKSIZE_RATIO)
            {
                nPackageFailures++;
            }

            // If we keep failing then the block must be almost full so bail out here.
            if ((nPackageFailures >= MAX_PACKAGE_FAILURES) || (nBlockMaxSize - nBlockSize < MIN_TX_SIZE))
            {
                // Return true because the block is full and we don't need another loop looking
                // for dirty transactions to add because they can't be added anyway.
                return true;
            }
            else
            {
                continue;
            }
        }

        // Test that the package does not exceed sigops limits
        if (!TestPackageSigOps(packageSize, packageSigOps))
        {
            continue;
        }

        // The Package can now be added to the block.
        for (auto &it : ancestors)
        {
            AddToBlock(vtxe, it);
        }
    }

    return !fHaveDirty;
}

void BlockAssembler::addPriorityTxs(std::vector<const CTxMemPoolEntry *> *vtxe, std::set<uint256> &setBestDagTxids)
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
        if (inBlock.count(iter) || (!setBestDagTxids.empty() && setBestDagTxids.count(iter->GetSharedTx()->GetId())))
        {
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
