// Copyright (c) 2020-2025 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "dag.h"

#include "consensus/consensus.h"
#include "daa.h"
#include "requestManager.h"
#include "txadmission.h"
#include "txmempool.h"
#include "txorphanpool.h"
#include "ui_interface.h"
#include "validation/tailstorm.h"
#include "validation/validation.h"

extern bool IsInitialBlockDownload();
extern CCriticalSection cs_main;
extern std::atomic<bool> forceTemplateRecalc;

class CValidationState;

CBlockIndex *LookupBlockIndex(const uint256 &hash);
bool IsSummaryBlock(const CBlock &block);

std::set<uint256> GetPrevHashes(const CBlockHeader &header);

// Find the hash of the tip of the dag which has the best dag height
static CTreeNodeRef FindDagTipNode(std::set<CTreeNodeRef> &dag)
{
    CTreeNodeRef activetip = nullptr;
    unsigned int bestHeight = 0;
    for (auto &node : dag)
    {
        if (node->IsTip())
        {
            // If the dagheight has increased and we're within the tailstorm_k range then set the new active tip.
            if ((node->dagHeight > bestHeight) && (node->nSequenceId < Params().GetConsensus().tailstorm_k))
            {
                activetip = node;
                bestHeight = node->dagHeight;
            }

            // Adjust for when we have multiple subblocks at the same height. We always make
            // the first one we saw the activetip.
            if (node->nSequenceId < activetip->nSequenceId && node->dagHeight == activetip->dagHeight)
            {
                activetip = node;
            }
        }
    }
    return activetip;
}

// Find the hash of the tip of the dag which has the best dag height
static uint256 FindDagTip(std::set<CTreeNodeRef> &dag)
{
    CTreeNodeRef ref = FindDagTipNode(dag);
    if (ref)
        return ref->hash;
    else
        return {};
}

// Find all the ancestor nodes for this node
static std::set<CTreeNodeRef> CalculateAncestors(CTreeNodeRef &node)
{
    std::set<CTreeNodeRef> setAncestors;
    setAncestors.insert(node->setAncestors.begin(), node->setAncestors.end());

    std::set<CTreeNodeRef> setLastAncestors = node->setAncestors;
    std::set<CTreeNodeRef> setNextAncestors;
    while (!setLastAncestors.empty())
    {
        for (auto ancestor : setLastAncestors)
        {
            setNextAncestors.insert(ancestor->setAncestors.begin(), ancestor->setAncestors.end());
        }
        setAncestors.insert(setNextAncestors.begin(), setNextAncestors.end());
        setLastAncestors = setNextAncestors;
        setNextAncestors.clear();
    }

    return setAncestors;
}

// Find all the "valid" descendant nodes for this node.  A valid descendant is one
// which has a dag height of only one more than the previous. Any descendants that are
// more than one height from the previous are not considered "valid" for scoring purposes.
static std::set<CTreeNodeRef> CalculateValidDescendants(CTreeNodeRef &node)
{
    std::set<CTreeNodeRef> setValidDescendants;

    for (auto desc : node->setDescendants)
    {
        // TODO: for now just allow all descenants.  We need more time
        // to evaluate the benfits of not including skipped link descendants.
        // if (desc->dagHeight == node->dagHeight + 1)
        {
            setValidDescendants.insert(desc);
        }
    }

    std::set<CTreeNodeRef> setLastDescendants = setValidDescendants;
    std::set<CTreeNodeRef> setNextDescendants;
    while (!setLastDescendants.empty())
    {
        for (auto _node : setLastDescendants)
        {
            for (auto desc : _node->setDescendants)
            {
                // TODO: for now just allow all descenants.  We need more time
                // to evaluate the benfits of not including skipped link descendants.
                // if (desc->dagHeight == _node->dagHeight + 1)
                {
                    setNextDescendants.insert(desc);
                }
            }
        }
        setValidDescendants.insert(setNextDescendants.begin(), setNextDescendants.end());
        setLastDescendants = setNextDescendants;
        setNextDescendants.clear();
    }

    return setValidDescendants;
}

std::map<CTreeNodeRef, uint32_t> GetDagScores(const std::set<CTreeNodeRef> &setBestDag)
{
    std::set<CTreeNodeRef> setNodesToRecalculate;
    std::map<CTreeNodeRef, uint32_t> mapBestDagScores;
    uint32_t nMaxDagHeight = 0;
    for (auto node : setBestDag)
    {
        // Initialize the map entry if it doesn't already exist.
        mapBestDagScores.emplace(node, 0);

        // Get all ancestors of this node
        std::set<CTreeNodeRef> setAllAncestors = CalculateAncestors(node);

        // initialize the new node with its initial score
        mapBestDagScores[node] += (setAllAncestors.size() + 1);

        // Now search through the ancestors and add "1" to the score
        // of any valid ancestor.
        for (auto ancestor : setAllAncestors)
        {
            // Initialize the map entry if it doesn't already exist.
            mapBestDagScores.emplace(ancestor, 0);

            // Add the score
            mapBestDagScores[ancestor] += 1;
        }

        // Track skipped height nodes since these need to be scored differently
        // then later recaculate the scores for these by finding all ancestors and "valid" decendants.
        // and re-tally the score for those special individual nodes.
        for (auto desc : node->setDescendants)
        {
            if (desc->dagHeight > node->dagHeight + 1)
            {
                setNodesToRecalculate.insert(node);
            }
        }

        // Track the max dagheight. We'll need it later.
        if (node->dagHeight > nMaxDagHeight)
        {
            nMaxDagHeight = node->dagHeight;
        }
    }

    // Re-calculate the scores for the special cases.
    for (auto node : setNodesToRecalculate)
    {
        std::set<CTreeNodeRef> setAncestors = CalculateAncestors(node);
        std::set<CTreeNodeRef> setValidDescendants = CalculateValidDescendants(node);

        mapBestDagScores[node] = setAncestors.size() + setValidDescendants.size() + 1;
    }

    return mapBestDagScores;
}

// Get the current best dag tip for mining on top of
uint256 GetActiveDagTip(std::set<CTreeNodeRef> &dag)
{
    uint256 activetip = FindDagTip(dag);
    if (activetip.IsNull())
    {
        return chainActive.Tip()->GetBlockHash();
    }

    return activetip;
}

std::set<uint256> GetTxnExclusionSet(const std::set<CTreeNodeRef> &setBestDag,
    std::vector<std::map<uint256, CTreeNodeRef> > &_vDoubleSpendTxns,
    std::map<COutPoint, CTransactionRef> &mapInputs)
{
    // Since we'll be modifying values make a local copy.
    auto vDoubleSpendTxns = _vDoubleSpendTxns;

    // Get the set of invalid double spends which we "DO NOT" want to include in the final summary block.
    //
    // We need to remove low score double spends but if there's a tie then we compare the block
    // hashes of the subblock they are in with the high block hash being the transaction we want to keep.
    std::set<uint256> setTxnExclusions;

    auto mapScores = GetDagScores(setBestDag);
    std::map<uint256, uint32_t> mapScoresByTxId;
    for (auto &mi : mapScores)
    {
        for (auto &ptx : mi.first->subblock->vtx)
        {
            if (ptx->IsCoinBase())
                continue;

            mapScoresByTxId.emplace(ptx->GetId(), mi.second);
        }
    }

    // find scores for ds transactions
    // Add lowest scores to a set of txns to exclude.
    // if there's a tie in score then use the txn with the highest block hash.
    for (auto &mapDoubleSpends : vDoubleSpendTxns)
    {
        // Iterate through each map find the highest score txn and also
        // if there's a tie, the one with the highest block hash.
        // Then remove that txn from the map and insert the remaining
        // map values into the exclusion set.
        uint256 hashHighScore;
        uint256 subblockHashHighScore;
        uint32_t nHighScore = 0;
        for (auto &mi : mapDoubleSpends)
        {
            // Pick and set the high score transaction
            uint32_t nScore = 0;
            if (mapScoresByTxId.count(mi.first))
                nScore = mapScoresByTxId[mi.first];

            if (nScore > nHighScore)
            {
                nHighScore = nScore;
                hashHighScore = mi.first;
                subblockHashHighScore = mi.second->hash;
            }
            // If scores are equal then determine which txn to keep.
            // Keep the one that has the highest "subblock" hash.
            else if (nScore == nHighScore)
            {
                if (mi.second->hash > subblockHashHighScore)
                {
                    hashHighScore = mi.first;
                    subblockHashHighScore = mi.second->hash;
                }
            }
        }
        mapDoubleSpends.erase(hashHighScore);

        // Add any descendant txns to the exclusion set regardless of what score
        // subblock they're in.
        std::map<uint256, CTransactionRef> mapDagTxns;
        tailstormForest.GetDagTxns(setBestDag, mapDagTxns);
        for (auto &mi : mapDoubleSpends)
        {
            setTxnExclusions.insert(mi.first);

            // Anything left in the map needs to have all it's descendants chains also removed.
            // Find all the descendants and add them to the exclusion set.
            const auto pDoubleSpend = mapDagTxns[mi.first];
            std::set<CTransactionRef> descendants;
            descendants.insert(pDoubleSpend);

            while (!descendants.empty())
            {
                auto ptx = *descendants.begin();
                descendants.erase(ptx);
                for (unsigned int j = 0; j < ptx->vout.size(); j++)
                {
                    const auto &outpoint = ptx->OutpointAt(j);
                    if (mapInputs.count(outpoint))
                    {
                        auto pNewDescendant = mapInputs[outpoint];
                        descendants.insert(pNewDescendant);
                        setTxnExclusions.insert(pNewDescendant->GetId());
                    }
                }
            }
        }
    }

    return setTxnExclusions;
}

// Tailstorm Tree
bool CTailstormTree::Insert(CTreeNodeRef newNode)
{
    AssertLockHeld(tailstormForest.cs_forest);

    DbgAssert(newNode->subblock != nullptr, );
    if (!newNode->subblock)
        return false;

    // Add to the tree
    auto res = dag.emplace(newNode->hash, newNode);
    if (res.second)
    {
        // Check if we're trying to insert into the tree of the current active summary block tip.
        // If not then we just return true but without setting the fProcessed flag. This way we keep
        // this new tree node linked into a dag but we can process the subblock later if/when
        // we reorg to its summary block root. (This process is analagous to when
        // we accept summary block headers and blocks but don't connect them yet because
        // they're not on the best chain yet).
        if (pindexSummaryRoot && (chainActive.Tip() != pindexSummaryRoot))
        {
            // Alhough we haven't processed this block yet we later need to know
            // the sequence id.
            newNode->nSequenceId = dag.size();
            return true;
        }

        bool fMissingOrSpent = false;
        std::set<CTreeNodeRef> setConflictingSubblocks;
        CValidationState state;
        CCoinsViewCache upperview(view);
        bool fOK = true;
        {
            const CChainParams &chainparams = Params();
            bool fJustCheck = false;
            bool fParallel = false;
            bool fScriptChecks = true;
            CAmount nFees = 0;
            CBlockUndo blockundo;
            std::vector<std::pair<uint256, CDiskTxPos> > vPos;
            vPos.reserve(newNode->subblock->vtx.size());
            std::map<CGroupTokenID, CAmount> accumulatedMintages;
            std::map<CGroupTokenID, CAuth> accumulatedAuthorities;

            // Try connecting the block and updating the coins cache.  If successful then we can remove
            // the transactions from the mempool.
            // TODO: connect canonical needs to still prepare the upper view with valid coins
            // even if we find a conflict because we later need to flush the view.
            if (!ConnectBlockCanonicalOrdering(newNode->subblock, state, pindexSummaryRoot, upperview, chainparams,
                    fJustCheck, fParallel, fScriptChecks, nFees, blockundo, vPos, accumulatedMintages,
                    accumulatedAuthorities, &mapDagTxns))
            {
                fOK = false;

                int nDos = 0;
                if (state.IsInvalid(nDos))
                {
                    // Check if this subblock is double spending anything in the dag
                    // and if so then fork a new dag and use this subblock as it's
                    // tip.
                    if (state.GetRejectCode() == REJECT_CONFLICT)
                    {
                        fMissingOrSpent = true;
                    }
                }
            }
        }

        if (fMissingOrSpent)
        {
            // The following code verifies whether we actually have a true double spend of if the block has
            // missing inputs. If it has missing inputs then we reject it completely. If it is a double spend
            // then we process it further and add it to the tracking map.
            LOG(DAG, "%s: subbblock %s is potentially a double spend block: %s", __func__, newNode->hash.ToString(),
                state.GetLogString());


            // Create the outpoint map
            std::map<COutPoint, CTransactionRef> mapOutpoints;
            for (CTransactionRef ptx : newNode->subblock->vtx)
            {
                if (ptx->IsCoinBase())
                    continue;

                for (size_t j = 0; j < ptx->vin.size(); j++)
                {
                    mapOutpoints[ptx->vin[j].prevout] = ptx;
                }
            }

            // Cycle through the dag from highest sequence id to lowest looking for a conflicting subblock.
            std::vector<std::pair<uint256, CTreeNodeRef> > vSortedDag(dag.begin(), dag.end());
            std::sort(vSortedDag.begin(), vSortedDag.end(),
                [](const auto &a, const auto &b) { return a.second->nSequenceId < b.second->nSequenceId; });
            for (auto it = vSortedDag.rbegin(); it != vSortedDag.rend(); it++)
            {
                for (CTransactionRef ptx : it->second->subblock->vtx)
                {
                    if (ptx->IsCoinBase())
                        continue;

                    std::map<uint256, CTreeNodeRef> mapTxns;
                    for (size_t j = 0; j < ptx->vin.size(); j++)
                    {
                        if (mapOutpoints.count(ptx->vin[j].prevout))
                        {
                            setConflictingSubblocks.insert(it->second);
                            mapTxns.emplace(ptx->GetId(), it->second);
                            mapTxns.emplace(mapOutpoints[ptx->vin[j].prevout]->GetId(), newNode);
                        }
                    }
                    if (!mapTxns.empty())
                    {
                        vDoubleSpendTxns.push_back(mapTxns);
                    }
                }
            }

            if (!setConflictingSubblocks.empty())
            {
                LOG(DAG, "%s: Found %ld Conflicting subblock(s)", __func__, setConflictingSubblocks.size());

                // If this subblock has its double spent subblock in it's ancestor tree then we "must" reject it.
                auto setAncestors = CalculateAncestors(newNode);
                bool fHasDoubleSpentAncestor = false;
                for (auto &node : setConflictingSubblocks)
                {
                    if (setAncestors.count(node))
                    {
                        fHasDoubleSpentAncestor = true;
                        break;
                    }
                }
                if (fHasDoubleSpentAncestor)
                {
                    dag.erase(newNode->hash);
                    LOG(DAG, "%s: Rejected - subbblock %s has a double spend in its ancestor tree: %s", __func__,
                        newNode->hash.ToString(), state.GetLogString());
                    return false;
                }
                else
                {
                    // If it's a true and acceptable conflicting subblock then we will accept it.
                    fOK = true;
                }
            }
            else
            {
                fOK = false;
                LOG(DAG, "%s: not adding subbblock %s because some inputs are missing: %s", __func__,
                    newNode->hash.ToString(), state.GetLogString());
            }
        }

        if (!fOK)
        {
            dag.erase(newNode->hash);
            LOG(DAG, "%s: subbblock %s failed to validate: %s", __func__, newNode->hash.ToString(),
                state.GetLogString());

            return false;
        }
        else
        {
            // Update the map of all current dag transactions. This must be done before
            // we continue processing, especially is we have a double spend block and
            // we need to re-generate the dag data.
            for (CTransactionRef ptx : newNode->subblock->vtx)
            {
                if (ptx->IsCoinBase())
                    continue;

                mapDagTxns.emplace(ptx->GetId(), ptx);

                for (auto &input : ptx->vin)
                {
                    mapInputs.emplace(input.prevout, ptx);
                }
            }

            // Stop txadmission, and flush the commitQ, before we flush coin state, remove txn conflicts and
            // set the active tree as well as pcoinsDag.
            TxAdmissionPause txlock;

            // After the subblock is validated without error we can flush coin state
            bool result = upperview.Flush();
            assert(result);

            std::list<CTransactionRef> txConflicted;
            // TODO: leave this commented code block as it will be useful in the future.
            // mempool.removeForBlock(pblock->vtx, pblock->height, txConflicted, true);
            // Process orphan pool for transactions in block but do deferr it to be done
            // in another thread.
            // LOCK(orphanpool.cs_blockprocessing);
            // orphanpool.vPostBlockProcessing.push_back(pblock);

            // Remove conflicting txns from the txpool
            {
                WRITELOCK(mempool.cs_txmempool);
                for (const auto &tx : newNode->subblock->vtx)
                {
                    mempool._removeConflicts(*tx, txConflicted);
                }
            }

            // Update the sequence id
            newNode->nSequenceId = dag.size();

            CTailstormGroveRef grove = nullptr;
            if (tailstormForest.GetGrove(*(pindexSummaryRoot->phashBlock), grove))
            {
                // If we had a double spend then regenerate all the dag data, exluding all
                // the low score double spends.
                if (!setConflictingSubblocks.empty())
                {
                    tailstormForest.GenerateDagData(grove);
                }
                else
                {
                    // Set the tree pointer for the grove to the best tree in the grove
                    grove->ActivateBestTree();
                }
            }

            cvCommitQ.notify_all();
        }

        // Set the processed flag
        newNode->fProcessed = true;

        return true;
    }

    return true; // must return true because we already have it and don't want it deleted from the grove
}

// Tailstorm Grove
bool CTailstormGrove::InitializeTree(CTreeNodeRef newNode, CCoinsViewCache *coinsCache)
{
    AssertLockHeld(tailstormForest.cs_forest);

    assert(coinsCache);
    assert(newNode);

    if (!newNode->subblock)
        return false;

    roothash = newNode->subblock->hashPrevBlock;

    // In case we attempted to initialize before and failed
    if (tree->view)
    {
        delete tree->view;
        tree->view = nullptr;
    }

    tree->_pcoinsTip = coinsCache;
    tree->view = new CCoinsViewCache(coinsCache);
    tree->view->SetBestBlock(roothash);
    tree->pindexSummaryRoot = LookupBlockIndex(roothash);
    assert(tree->pindexSummaryRoot);

    nRootHeight = tree->pindexSummaryRoot->height();

    return tree->Insert(newNode);
}

void CTailstormGrove::Clear()
{
    AssertLockHeld(tailstormForest.cs_forest);

    // delete all of the nodes in this grove. mapGroveNodes is
    // a subset of mapAllNodes which we can iterate over to efficiently remove
    // the nodes from mapAllNodes
    for (auto &mi : mapGroveNodes)
    {
        tailstormForest.mapAllNodes.erase(mi.first);
        tailstormForest.mapAllGroves.erase(mi.first);
    }

    mapGroveNodes.clear();
}

bool CTailstormGrove::InsertIntoTree(CTreeNodeRef newNode)
{
    AssertLockHeld(tailstormForest.cs_forest);

    if (!newNode->subblock)
        return false;

    // Check all trees and make sure we don't already have this item. It could be in
    // a double spend tree and if so we don't want to process it again otherwise might
    // end up forking another duplicate double spend tree.
    for (auto &it : setValidTrees)
    {
        if (it->dag.count(newNode->hash))
        {
            tailstormForest.mapNodesUnlinked.erase(newNode->hash);
            LOG(DAG, "%s(): Not inserting new node since treenode already exists", __func__);
            return true; // must return true here
        }
    }

    // Add the very first tree items. These are subblocks with dagHeight 1.  The first time through
    // we initialize the tree.  If there is a second subblock at dagHeight 1 then we just do a simple insert.
    auto setHashes = GetPrevHashes(newNode->subblock->GetBlockHeader());
    if (setHashes.size() == 1 && (*setHashes.begin()) == newNode->subblock->hashPrevBlock)
    {
        auto res = mapGroveNodes.emplace(newNode->hash, newNode);
        if (res.second)
        {
            newNode->dagHeight = 1;
            LOG(DAG, "%s(): Initialize Tree: updated dagHeight to %ld for %s", __func__, newNode->dagHeight,
                newNode->hash.ToString());

            if (tree->dag.empty())
            {
                if (!InitializeTree(newNode, _pcoinsTip))
                {
                    mapGroveNodes.erase(newNode->hash);
                    return false;
                }
                LOG(DAG, "%s(): Initialize Tree: completed init tree for %s", __func__, newNode->hash.ToString());
            }
            else
            {
                if (!tree->Insert(newNode))
                {
                    mapGroveNodes.erase(newNode->hash);
                    tailstormForest.AddSubblockOrphan(newNode);
                    LOG(DAG, "%s(): Initialize Tree: adding orphan to unused nodes", __func__);
                    return false;
                }
                LOG(DAG, "%s(): Initialize Tree: completed insert into tree for %s", __func__,
                    newNode->hash.ToString());
            }

            // Notify the dagviewer
            ConstCBlockRef pblock = newNode->subblock;
            const CBlockHeader header = pblock->GetBlockHeader();
            uint32_t nSequenceId = newNode->nSequenceId;
            uiInterface.NotifyBlockTipDag(false, newNode->dagHeight, nSequenceId, header, true);
        }
    }
    else // Insert all other tree items
    {
        auto res = mapGroveNodes.emplace(newNode->hash, newNode);
        if (res.second)
        {
            // Did we add at least one node to a tree
            bool fAddedOne = false;

            // A subblock could be valid in more than one tree so check each tree
            // in the grove and try to see if the subblock can be added.
            //
            // It could also be valid in one tree but not the other so we have to
            // be careful of that as well.
            for (auto &_tree : setValidTrees)
            {
                // check that we have the treenode of all prevHashes
                std::set<CTreeNodeRef> setPrevNodes;
                {
                    bool fNotFound = false;
                    auto setPrevHashes = GetPrevHashes(newNode->subblock->GetBlockHeader());
                    for (auto prevhash : setPrevHashes)
                    {
                        // Then find it in our tree
                        auto iter_tree = _tree->dag.find(prevhash);
                        if (iter_tree == _tree->dag.end())
                        {
                            fNotFound = true;
                            break;
                        }
                        LOG(DAG, "%s(): Found prevhash in dag %s for %s", __func__, prevhash.ToString(),
                            iter_tree->second->hash.ToString());
                        setPrevNodes.insert(iter_tree->second);
                    }
                    if (fNotFound)
                        continue; // if they're not all present in the dag then don't try to connect this new node.
                }

                // add ancestor information regardless of being added to the tree
                if (!setPrevNodes.empty())
                {
                    uint32_t nBestDagHeight = 0;
                    newNode->AddAncestors(setPrevNodes);
                    for (auto node : setPrevNodes)
                    {
                        node->AddDescendant(newNode);
                        if (nBestDagHeight < node->dagHeight)
                            nBestDagHeight = node->dagHeight;
                    }
                    newNode->dagHeight = nBestDagHeight + 1;
                    LOG(DAG, "%s(): updated dagHeight to %ld dagsize %ld for %s", __func__, newNode->dagHeight,
                        _tree->dag.size(), newNode->hash.ToString());
                }
                else
                {
                    newNode->dagHeight = 1;
                    LOG(DAG, "%s(): updated dagHeight to %ld dagsize %ld  for %s", __func__, newNode->dagHeight,
                        _tree->dag.size(), newNode->hash.ToString());
                }

                // Insert new node into tree
                if (_tree->Insert(newNode))
                {
                    fAddedOne = true;
                    LOG(DAG, "%s(): completed insert into tree dagsize %ld for %s", __func__, _tree->dag.size(),
                        newNode->hash.ToString());
                }
            }

            if (!fAddedOne)
            {
                mapGroveNodes.erase(newNode->hash);
                tailstormForest.AddSubblockOrphan(newNode);
                LOG(DAG, "%s(): adding orphan to unused nodes", __func__);

                return false;
            }


            // Notify the dagviewer
            ConstCBlockRef pblock = newNode->subblock;
            const CBlockHeader header = pblock->GetBlockHeader();
            uint32_t nSequenceId = newNode->nSequenceId;
            uiInterface.NotifyBlockTipDag(false, newNode->dagHeight, nSequenceId, header, true);
        }
    }

    return true;
}

bool CTailstormGrove::Insert(CTreeNodeRef newNode)
{
    AssertLockHeld(tailstormForest.cs_forest);

    return InsertIntoTree(newNode);
}

bool CTailstormGrove::GetBestDag(std::set<CTreeNodeRef> &dag,
    std::vector<std::map<uint256, CTreeNodeRef> > *vDoubleSpendTxns,
    std::map<COutPoint, CTransactionRef> *mapInputs)
{
    AssertLockHeld(tailstormForest.cs_forest);

    if (tree->dag.empty())
    {
        return false;
    }

    for (auto &node : tree->dag)
    {
        // If the sequence id is too high then don't include it
        if (node.second->nSequenceId > Params().GetConsensus().tailstorm_k - 1)
        {
            LOG(DAG, "%s(): sequence id %d is too high for %s - processed: %d", __func__, node.second->nSequenceId,
                node.second->hash.ToString(), node.second->fProcessed);
            continue;
        }

        dag.insert(node.second);
    }

    if (vDoubleSpendTxns != nullptr && !dag.empty())
        *vDoubleSpendTxns = tree->vDoubleSpendTxns;
    if (mapInputs != nullptr && !dag.empty())
        *mapInputs = tree->mapInputs;

    return true;
}

bool CTailstormGrove::GetBestTipHash(uint256 &tiphash)
{
    AssertLockHeld(tailstormForest.cs_forest);

    std::set<CTreeNodeRef> bestDag;
    GetBestDag(bestDag);
    tiphash = FindDagTip(bestDag);
    return true;
}

void CTailstormGrove::ActivateBestTree()
{
    AssertLockHeld(tailstormForest.cs_forest);
    DbgAssert(
        txProcessingCorral.region() == CORRAL_TX_PAUSE, LOGA("Do not have corral pause during activate best tree"));

    // Store the current tree for later comparison
    std::shared_ptr<CTailstormTree> pLastTree = tree;

    // Switch to the longest tree, however if we've already reached tailstorm_k subblocks then
    // we don't want to re-org anymore and instead just stay on the current tree.
    for (std::shared_ptr<CTailstormTree> treeitem : setValidTrees)
    {
        auto nMaxSubblocks = Params().GetConsensus().tailstorm_k - 1;
        auto nTreeItemSize = treeitem->dag.size() > nMaxSubblocks ? nMaxSubblocks : treeitem->dag.size();
        if (nTreeItemSize > tree->dag.size())
        {
            tree = treeitem;
            LOG(DAG, "%s: Active tree tip is %s", __func__,
                tailstormForest.GetDagTipHash(*(tree->pindexSummaryRoot->phashBlock)).ToString());
        }
    }

    // Set pcoinsDag to the our best tree view
    tailstormForest.SetDagCoinsTip();

    // If the tree has changed then we need to resubmit all the transactions
    // in each block and remove their conflicts from the txpool.
    if (tree != pLastTree)
    {
        LOG(DAG, "%s: The active dag tree has changed", __func__);
        std::vector<std::pair<uint256, CTreeNodeRef> > vSortedDag(tree->dag.begin(), tree->dag.end());
        std::sort(vSortedDag.begin(), vSortedDag.end(),
            [](const auto &a, const auto &b) { return a.second->nSequenceId < b.second->nSequenceId; });

        WRITELOCK(mempool.cs_txmempool);
        for (auto it = vSortedDag.begin(); it != vSortedDag.end(); it++)
        {
            ConstCBlockRef pblock = it->second->subblock;
            if (pblock)
            {
                // Resubmit the block first
                std::list<CTransactionRef> txConflicted;
                for (const auto &ptx : pblock->vtx)
                {
                    mempool._removeConflicts(*ptx, txConflicted);
                    if (!ptx->IsCoinBase())
                    {
                        CTxInputData txd;
                        txd.tx = ptx;
                        txd.nodeName = "reorg";
                        txd.msgCookie = 0;
                        EnqueueTxForAdmission(txd);
                    }
                }
            }
        }
    }
}

// Tailstorm Forest
void CTailstormForest::Clear()
{
    LOCK(cs_forest);
    mapAllGroves.clear();
    mapAllNodes.clear();
    mapNodesUnlinked.clear();
    mapSummaryBlocksUnlinked.clear();
}

void CTailstormForest::ClearGrove(const uint256 &hash)
{
    LOCK(cs_forest);
    auto iter = mapAllGroves.find(hash);
    if (iter != mapAllGroves.end())
    {
        if (iter->second != nullptr)
        {
            iter->second->Clear();
            iter->second = nullptr;
        }
        mapAllGroves.erase(iter);
    }

    mapAllNodes.erase(hash);
}

void CTailstormForest::ClearByHeight(const uint32_t nPruneHeight)
{
    AssertLockHeld(tailstormForest.cs_forest);

    auto iter = mapAllNodes.begin();
    while (iter != mapAllNodes.end())
    {
        if (iter->second->subblock && (iter->second->subblock->height <= nPruneHeight))
        {
            const uint256 &hash = iter->first;
            LOG(DAG, "pruning subblock %s at height %ld\n", hash.ToString(), iter->second->subblock->height);

            mapNodesUnlinked.erase(hash);
            mapAllGroves.erase(hash);
            iter = mapAllNodes.erase(iter);
        }
        else
        {
            iter++;
        }
    }

    auto iter2 = mapSummaryBlocksUnlinked.begin();
    while (iter2 != mapSummaryBlocksUnlinked.end())
    {
        if (iter2->second->height <= nPruneHeight)
        {
            LOG(DAG, "pruning summary block %s at height %ld\n", iter2->first.ToString(), iter2->second->height);
            iter2 = mapSummaryBlocksUnlinked.erase(iter2);
        }
        else
        {
            iter2++;
        }
    }

    Check();
}

size_t CTailstormForest::Size()
{
    LOCK(cs_forest);
    return mapAllNodes.size();
}


bool CTailstormForest::Insert(ConstCBlockRef subblock)
{
    AssertLockNotHeld(cs_forest);

    if (!subblock)
        return false;

    LOCK(cs_forest);
    bool fOK = _Insert(subblock);
    if (fOK)
        mapNodesUnlinked.erase(subblock->GetHash());

    Check();
    return fOK;
}

bool CTailstormForest::_Insert(ConstCBlockRef subblock)
{
    AssertLockHeld(cs_forest);

    if (!subblock)
        return false;

    // Never return true from this function but rather use fOK
    // so we can be sure to set the dag active tip after we've
    // had a successful insert of a treenode.
    bool fOK = false;

    // Create new node
    CTreeNodeRef newNode = MakeTreeNodeRef(subblock);

    // emplace the new node into the map
    if (!mapAllNodes.emplace(newNode->hash, newNode).second)
    {
        // There already exists a node for this subblock
        // We don't want to do anything here because this could be an orphan getting connected
        // which has an entry in mapAllNodes but not yet in mapAllGroves.
    }

    // Insert elements into a new grove or and already existing grove.
    auto mi = mapAllGroves.find(subblock->hashPrevBlock);
    if (mi != mapAllGroves.end())
    {
        // Make sure the height of this subblock equals the prev subblock height.
        for (auto &it : mi->second->setValidTrees)
        {
            // find the tree that has a subblock which it connects to.
            if (it->dag.count(subblock->hashPrevBlock))
            {
                if (subblock->height != it->dag[subblock->hashPrevBlock]->subblock->height)
                {
                    LOG(DAG, "%s(): subblock height does not match previous subblock height %s", __func__,
                        newNode->hash.ToString(), subblock->hashPrevBlock.ToString());
                    return false;
                }
            }

            // Check the chainwork when the subblock gets connected to a grove
            auto expectedNbits = GetNextWorkRequired(it->pindexSummaryRoot, &(*subblock), Params().GetConsensus());
            auto expectedChainWork =
                ArithToUint256(it->pindexSummaryRoot->chainWork() + GetWorkForDifficultyBits(expectedNbits));
            if (subblock->chainWork != expectedChainWork)
            {
                LOG(DAG, "%s: invalid chainwork - could not add subblock to grove", __func__);
                return false;
            }
        }


        // Insert subblock into already existing grove
        LOG(DAG, "%s(): trying to add subblock to already existing grove %s", __func__, newNode->hash.ToString());
        if (mi->second->Insert(newNode))
        {
            mapAllGroves.emplace(newNode->hash, mi->second);

            LOG(DAG, "%s(): added subblock %s to existing grove %s with subblock dagHeight %d", __func__,
                newNode->hash.ToString(), subblock->hashPrevBlock.ToString(), newNode->dagHeight);
            fOK = true;
        }
        else
        {
            LOG(DAG, "%s(): FAILED to add subblock %s to existing grove %s", __func__, newNode->hash.ToString(),
                subblock->hashPrevBlock.ToString());
            return false;
        }
    }
    else
    {
        // At this point we need to know if this block connects to a past
        // Summary Block or if it really is an orphan.
        auto pindex = LookupBlockIndex(subblock->hashPrevBlock);
        if (pindex && pindex->IsLinked() && !mapSummaryBlocksUnlinked.count(subblock->hashPrevBlock))
        {
            // Make sure the height of this subblock is 1 more that the previous summary block
            if (subblock->height != pindex->height() + 1)
            {
                LOG(DAG, "%s: invalid subblock height %ld should be %ld - could not add subblock to grove", __func__,
                    subblock->height, pindex->height() + 1);
                return false;
            }

            // Check the chainwork when the subblock gets connected to a grove
            auto expectedNbits = GetNextWorkRequired(pindex, &(*subblock), Params().GetConsensus());
            auto expectedChainWork = ArithToUint256(pindex->chainWork() + GetWorkForDifficultyBits(expectedNbits));
            if (subblock->chainWork != expectedChainWork)
            {
                LOG(DAG, "%s: invalid chainwork - could not add subblock to grove", __func__);
                return false;
            }
            // Add new grove and/or insert subblock
            CTailstormGroveRef grove = nullptr;
            if (GetGrove(subblock->hashPrevBlock, grove))
            {
                LOG(DAG, "%s(): added subblock to already existing grove %s with a prev summary  %s", __func__,
                    newNode->hash.ToString().c_str(), subblock->hashPrevBlock.GetHex());

                auto res = mapAllGroves.emplace(newNode->hash, grove);
                if (res.second)
                {
                    if (grove->Insert(newNode))
                        fOK = true;
                    else
                        return false;
                }
                else
                {
                    fOK = true; // it already exists so return true.
                }
            }
            else
            {
                auto res = mapAllGroves.emplace(newNode->hash, MakeTailstormGroveRef(CTailstormGrove(_pcoinsTip)));
                if (res.second)
                {
                    LOG(DAG, "%s(): added subblock %s to new Grove with prev summary is %s", __func__,
                        newNode->hash.GetHex(), newNode->subblock->hashPrevBlock.GetHex());

                    grove = res.first->second;
                    if (grove->Insert(newNode))
                        fOK = true;
                    else
                        return false;
                }
                else
                {
                    LOG(DAG, "%s: failed to add new grove", __func__);
                    return false;
                }
            }
        }
        else
        {
            // It must be an orphan
            AddSubblockOrphan(newNode);

            LOG(DAG, "%s():added subblock %s to nodes unlinked %s", __func__, newNode->hash.GetHex(),
                subblock->hashPrevBlock.GetHex());
            return false;
        }
    }

    if (fOK)
    {
        // Find the best treenode tip out of all the dags and update
        // the atomic pointer.
        std::set<CTreeNodeRef> dag;
        GetBestDagFor(subblock->hashPrevBlock, dag);
        CTreeNodeRef bestnode = FindDagTipNode(dag);
        if (bestnode)
            SetDagActiveTip(bestnode);
    }
    return fOK;
}

void CTailstormForest::AddSummaryBlockOrphan(ConstCBlockRef pblock)
{
    LOCK(cs_forest);
    CTailstormGroveRef grove = nullptr;
    const uint256 &hash = pblock->GetHash();
    if (!GetGrove(hash, grove))
    {
        LOG(DAG, "Insert summary block orphan : %s", hash.ToString());
        mapSummaryBlocksUnlinked.emplace(hash, pblock);
    }
    else
    {
        LOG(DAG, "Grove already exists. Did not insert summary block orphan : %s", hash.ToString());
    }
}

void CTailstormForest::RemoveSummaryBlockOrphan(ConstCBlockRef pblock)
{
    LOCK(cs_forest);
    const uint256 &hash = pblock->GetHash();
    LOG(DAG, "Remove summary block orphan : %s", hash.ToString());
    mapSummaryBlocksUnlinked.erase(hash);
}

void CTailstormForest::AddSubblockOrphan(CTreeNodeRef newNode)
{
    LOCK(cs_forest);
    mapAllGroves.erase(newNode->hash);
    mapNodesUnlinked.emplace(newNode->hash, newNode);
}

std::set<uint256> CTailstormForest::ProcessOrphans()
{
    AssertLockHeld(cs_forest);

    std::set<uint256> setAllLinked;
    while (true)
    {
        std::set<uint256> setLinked;
        for (auto iter = mapNodesUnlinked.begin(); iter != mapNodesUnlinked.end();)
        {
            assert(iter->second->subblock);

            const uint256 &prevhash = iter->second->subblock->hashPrevBlock;
            auto pindex = LookupBlockIndex(prevhash);

            auto setHashes = GetPrevHashes(iter->second->subblock->GetBlockHeader());
            bool fHaveAllPrevSubblocks = true;
            for (auto &hash : setHashes)
            {
                if (hash == prevhash)
                    continue;

                if (!mapAllGroves.count(hash))
                {
                    fHaveAllPrevSubblocks = false;
                }
            }

            if (((pindex && pindex->IsLinked()) && fHaveAllPrevSubblocks) && !mapSummaryBlocksUnlinked.count(prevhash))
            {
                LOG(DAG, "%s(): process orphans - found orphan %s connecting to prev block %s", __func__,
                    iter->second->hash.ToString(), prevhash.ToString());
                if (_Insert(iter->second->subblock))
                {
                    LOG(DAG, "%s(): Insert of orphan succeeded", __func__);
                    setLinked.insert(iter->second->hash);
                    mapNodesUnlinked.erase(iter);
                    iter = mapNodesUnlinked.begin();
                    continue;
                }
                else
                {
                    LOG(DAG, "%s(): unlinked insert failed for %s size %ld", __func__, iter->second->hash.ToString(),
                        mapNodesUnlinked.size());
                }
            }
            ++iter;
        }

        // Process any summary block orphans that has all subblocks present and valid in the dag.
        // NOTE: we don't add the summary block to setLinked because block processing doesn't
        // finish in this thread so we can't be sure it's linked.  It will instead get announced
        // once the block successfully connects to the blockchain.
        for (auto iter2 = mapSummaryBlocksUnlinked.begin(); iter2 != mapSummaryBlocksUnlinked.end();)
        {
            const ConstCBlockRef pblock = iter2->second;
            {
                // Get all mining hashes from the best dag that exists on top of
                // the prevhash of this Summary Block.  Then Check if all
                // the subblock minining hashes in the minerData of this block
                // are present in the best dag.
                std::set<CTreeNodeRef> dag;
                tailstormForest.GetBestDagFor(pblock->GetBlockHeader().hashPrevBlock, dag);
                std::set<uint256> setMiningHashes;
                for (auto &treenode : dag)
                {
                    if (treenode->subblock)
                    {
                        const auto &miningHeaderCommitment = treenode->subblock->GetMiningHeaderCommitment();
                        const auto &nonce = treenode->subblock->GetBlockHeader().nonce;
                        setMiningHashes.insert(GetMiningHash(miningHeaderCommitment, nonce));
                    }
                }

                // Check to make sure all subblocks were received before connecting the Summary Block
                auto subblockProofs = ParseSummaryBlockMinerData(pblock->minerData);
                bool fHaveSubblocks = true;
                for (const auto &pair : subblockProofs)
                {
                    const auto &miningHeaderCommitment = pair.first;
                    const auto &nonce = pair.second;
                    uint256 mininghash = GetMiningHash(miningHeaderCommitment, nonce);

                    if (!setMiningHashes.count(mininghash))
                    {
                        fHaveSubblocks = false;
                        break;
                    }
                }

                // All subblocks are present that are needed to validate the summary block
                // so now we're able to successfully connect the summary block.
                LOG(DAG, "%s(): Processing Summary block orphan %s", __func__, iter2->first.ToString());
                if (fHaveSubblocks)
                {
                    mapSummaryBlocksUnlinked.erase(iter2);
                    LEAVE_CRITICAL_SECTION(cs_forest);

                    // locking cs_main here prevents any other thread from starting a block validation.
                    {
                        LOCK(cs_main);
                        bool forceProcessing = true;
                        CValidationState state;
                        ProcessNewBlock(state, Params(), nullptr, pblock, forceProcessing, nullptr, false);
                        LOG(DAG, "%s(): Done processing new block and connected an orphaned summary block", __func__);
                    }
                    ENTER_CRITICAL_SECTION(cs_forest);

                    // Because we dropped the lock and took it again the iteration may now
                    // have been invalidated by some other thread so set the iterator to the
                    // beginning again. While theoretically it could be a very small performance
                    // hit, in reality it's unlikely there will even be any other entries in the map
                    // to process anyway.
                    iter2 = mapSummaryBlocksUnlinked.begin();
                    continue;
                }
                else
                {
                    /*
                    LOG(DAG, "%s():  FAILED - do not have all subblocks: %ld", __func__, dag.size());
                    for (auto &treenode : dag)
                    {
                        assert(treenode->subblock);
                        LOG(DAG, "%s(): subblocks in failed dag: %s", __func__,
                            treenode->hash.ToString().c_str());
                    }
                    */
                }
            }

            iter2++;
        }

        // If we connected some orphans then add to the total and
        // do another loop until we don't find anymore.
        if (!setLinked.empty())
        {
            setAllLinked.insert(setLinked.begin(), setLinked.end());
        }
        else
        {
            break;
        }
    }

    Check();
    return setAllLinked;
}

uint256 CTailstormForest::GetDagTipHash(const uint256 &hash)
{
    uint256 tiphash;
    if (GetBestTipHashFor(hash, tiphash))
        return tiphash;
    else
        return hash;
}

bool CTailstormForest::Find(const uint256 &hash, ConstCBlockRef &subblock)
{
    LOCK(cs_forest);
    std::map<uint256, CTreeNodeRef>::iterator iter = mapAllNodes.find(hash);
    if (iter != mapAllNodes.end())
    {
        subblock = iter->second->subblock;
        return true;
    }
    return false;
}

bool CTailstormForest::Contains(const uint256 &hash)
{
    LOCK(cs_forest);
    return (mapAllNodes.count(hash) != 0);
}

std::map<uint256, CTreeNode> CTailstormForest::GetAllNodes()
{
    LOCK(cs_forest);
    std::map<uint256, CTreeNode> allNodes;
    for (auto &mi : mapAllNodes)
    {
        allNodes.emplace(mi.first, *(mi.second));
    }
    return allNodes;
}

bool CTailstormForest::GetBestDagFor(const uint256 &hash,
    std::set<CTreeNodeRef> &dag,
    std::vector<std::map<uint256, CTreeNodeRef> > *vDoubleSpendTxns,
    std::map<COutPoint, CTransactionRef> *mapInputs)
{
    LOCK(cs_forest);
    LOG(DAG, "%s(): Start getbestdagfor", __func__);

    CTailstormGroveRef grove = nullptr;
    if (GetGrove(hash, grove))
    {
        if (!grove->GetBestDag(dag, vDoubleSpendTxns, mapInputs))
        {
            LOG(DAG, "%s(): get best dag returned false", __func__);
            return false;
        }
        LOG(DAG, "%s(): got grove and returning best dag", __func__);
        for (auto item : dag)
            LOG(DAG, "%s():     best dag item: %s nSequenceId: %d fProcessed: %d", __func__, item->hash.ToString(),
                item->nSequenceId, item->fProcessed);
        return true;
    }
    LOG(DAG, "%s(): did not get grove", __func__);

    return false;
}

bool CTailstormForest::GetDagForBlock(ConstCBlockRef &pblock,
    std::set<CTreeNodeRef> &dag,
    std::vector<std::map<uint256, CTreeNodeRef> > *vDoubleSpendTxns,
    std::map<COutPoint, CTransactionRef> *mapInputs)
{
    LOCK(cs_forest);
    DbgAssert(IsSummaryBlock(*pblock), );

    bool fMatch = false;
    CTailstormGroveRef grove = nullptr;
    if (GetGrove(pblock->hashPrevBlock, grove))
    {
        // Check each tree for a full set of treenodes that match the block. If we find
        // a match then break and return a positive result. If we don't match then keep
        // looking in any other trees than may be in the grove.
        //
        // If this function returns "true" then this means that all subblocks have been correctly
        // accepted into the dag and is not also not an orphaned subblock.
        auto subblockProofs = ParseSummaryBlockMinerData(pblock->minerData);
        for (auto &tree : grove->setValidTrees)
        {
            dag.clear();
            std::map<uint256, CTreeNodeRef> mapDagMiningHashes;

            // get all mining hashes in the tree
            for (auto &mi : tree->dag)
            {
                const CTreeNodeRef &node = mi.second;
                if (!node->fProcessed)
                    continue;

                const auto &miningHeaderCommitment = node->subblock->GetMiningHeaderCommitment();
                const auto &nonce = node->subblock->GetBlockHeader().nonce;
                mapDagMiningHashes.emplace(GetMiningHash(miningHeaderCommitment, nonce), node);
            }

            // does each mining hash in the block's minerDag have a corresoponding one in the dag
            for (const auto &pair : subblockProofs)
            {
                const auto &miningHeaderCommitment = pair.first;
                const auto &nonce = pair.second;
                uint256 miningHash = GetMiningHash(miningHeaderCommitment, nonce);

                if (!mapDagMiningHashes.count(miningHash))
                {
                    // Check failed. If there is another tree then break and continue.
                    fMatch = false;
                    break;
                }
                else
                {
                    dag.insert(mapDagMiningHashes[miningHash]);
                    fMatch = true;
                }
            }
            if (fMatch)
            {
                *vDoubleSpendTxns = tree->vDoubleSpendTxns;
                *mapInputs = tree->mapInputs;
                break;
            }
        }

        if (!fMatch)
            dag.clear();
    }

    return fMatch;
}
bool CTailstormForest::GetBestTipHashFor(const uint256 &hash, uint256 &tiphash)
{
    LOCK(cs_forest);
    CTailstormGroveRef grove = nullptr;
    if (GetGrove(hash, grove))
    {
        if (!grove->GetBestTipHash(tiphash))
        {
            return false;
        }
        return true;
    }
    return false;
}

void CTailstormForest::GetDagTxns(const std::set<CTreeNodeRef> &dag, std::map<uint256, CTransactionRef> &mapDagTxns)
{
    for (auto &iter : dag)
    {
        if (!iter->subblock)
            continue;

        for (CTransactionRef ptx : iter->subblock->vtx)
        {
            if (ptx->IsCoinBase())
                continue;

            mapDagTxns.emplace(ptx->GetId(), ptx);
        }
    }
    return;
}

uint32_t CTailstormForest::GetDagHeight(const uint256 &hash)
{
    LOCK(cs_forest);
    auto iter = mapAllNodes.find(hash);
    if (iter == mapAllNodes.end())
    {
        return 0;
    }
    else
    {
        return iter->second->dagHeight;
    }
}

bool CTailstormForest::GetGrove(const uint256 &hash, CTailstormGroveRef &grove)
{
    LOCK(cs_forest);
    LOG(DAG, "%s(): get grove for %s\n", __func__, hash.ToString());
    // Look for the subblock in the grove map
    auto iter = mapAllGroves.find(hash);
    if (iter != mapAllGroves.end())
    {
        grove = iter->second;
        return true;
    }

    // If the subblock is not found then lookup the grove
    // by the roothash.
    for (auto &mi : mapAllGroves)
    {
        assert(!mi.second->roothash.IsNull());
        if (hash == mi.second->roothash)
        {
            grove = mi.second;
            return true;
        }
    }
    LOG(DAG, "%s(): get grove not found for %s\n", __func__, hash.ToString());
    return false;
}

void CTailstormForest::CheckForReorg()
{
    AssertLockNotHeld(cs_forest);

    // Only allow one thread to run re-org at a time.
    TRY_LOCK(cs_reorg, lock);
    if (!lock)
        return;

    CTailstormGroveRef grovetip = nullptr;
    CBlockIndex *chainTip = chainActive.Tip();
    CBlockIndex *pindexMostWork = chainTip;
    arith_uint256 nChainTipWork = chainTip->chainWork();
    arith_uint256 nMaxChainWork = chainTip->chainWork();

    LOG(DAG, "%s(): current chain active height %ld for %s", __func__, chainTip->height(),
        chainTip->phashBlock->ToString());
    {
        LOCK(cs_forest);

        // Find all groves
        std::set<CTailstormGroveRef> setAllGroves;
        for (auto &mi : mapAllGroves)
            setAllGroves.insert(mi.second);

        // Get the chainwork of the current chainactive tip plus all the subblocks in it's dag
        std::set<CTreeNodeRef> tipdag;
        GetBestDagFor(*chainTip->phashBlock, tipdag);
        for (auto node : tipdag)
        {
            nChainTipWork += GetWorkForDifficultyBits(node->subblock->nBits);
        }

        // Cycle through all the trees of each grove and find the chainWork
        for (auto &grove : setAllGroves)
        {
            arith_uint256 nTreeChainWork = grove->tree->pindexSummaryRoot->chainWork();
            std::set<CTreeNodeRef> dag;
            GetBestDagFor(grove->roothash, dag);
            for (auto node : dag)
            {
                nTreeChainWork += GetWorkForDifficultyBits(node->subblock->nBits);
            }
            if (nTreeChainWork > nMaxChainWork && nTreeChainWork > nChainTipWork)
            {
                nMaxChainWork = nTreeChainWork;
                pindexMostWork = grove->tree->pindexSummaryRoot;
                grovetip = grove;

                LOG(DAG, "%s : pindexMostWork %s > chaintip %s\n", __func__, pindexMostWork->phashBlock->ToString(),
                    chainTip->phashBlock->ToString());
            }
        }
    }

    if (!pindexMostWork)
    {
        LOG(DAG, "%s():  could not find pindexMostWork for reorg", __func__);
    }

    if (pindexMostWork && !(pindexMostWork->nStatus & BLOCK_HAVE_DATA))
    {
        LOG(DAG, "%s():  WARNING: block data is not present for Reorg: %s", __func__,
            pindexMostWork->phashBlock->ToString());
        return;
    }

    // Initiate reorg if there is a tree with greater work
    if (nMaxChainWork > nChainTipWork)
    {
        LOG(DAG, "%s(): Attempting to initiate a reorg from %s at height %d to %s at height %d", __func__,
            pindexMostWork->phashBlock->ToString(), pindexMostWork->height(), chainTip->phashBlock->ToString(),
            chainTip->height());

        {
            LOCK(cs_main);
            LOCK(cs_forest);
            TxAdmissionPause txlock;

            if (chainTip != chainActive.Tip())
            {
                LOG(DAG, "%s():  failed to reorg to %s because chain active tip changed", __func__,
                    pindexMostWork->phashBlock->ToString());
                return;
            }

            CValidationState state;
            const CChainParams &chainparams = Params();
            if (!ActivateBestChainStep(state, chainparams, pindexMostWork, nullptr, false))
            {
                LOG(DAG, "%s():  failed to reorg to %s", __func__, pindexMostWork->phashBlock->ToString());
            }
            else
                LOG(DAG, "%s():  completed a reorg to %s", __func__, pindexMostWork->phashBlock->ToString());

            // Rebuild the each tree's coinscache and data structures on the grove we've now set as our best chain tip.
            // We only need to build data for unprocessed subblocks.
            GenerateDagData(grovetip);
        }
    }

    return;
}

void CTailstormForest::GenerateDagData(CTailstormGroveRef grove)
{
    AssertLockHeld(cs_forest);
    DbgAssert(
        txProcessingCorral.region() == CORRAL_TX_PAUSE, LOGA("Do not have corral pause during activate best tree"));

    // Rebuild the each tree's coinscache and data structures on the grove we've now set as our best chain tip.
    // We only need to build data for unprocessed subblocks.
    CValidationState state;
    auto chainparams = Params();
    for (auto &tree : grove->setValidTrees)
    {
        uint32_t nSequenceId = 0;

        // Get the exclusion set for this dag which is use to pass to connect block and allow
        // processing to continue without a missing inputs error begin returned. This exlusion set is needed
        // because mapDagTxns, which is also used to skip processing a transaction twice,
        // does not get created until the block has succesfully finished connecting.
        std::vector<std::map<uint256, CTreeNodeRef> > vDoubleSpendTxns;
        std::map<COutPoint, CTransactionRef> mapInputs;
        std::set<CTreeNodeRef> setDag;
        for (auto mi : tree->dag)
            setDag.insert(mi.second);
        std::set<uint256> setTxnExclusions = GetTxnExclusionSet(setDag, tree->vDoubleSpendTxns, tree->mapInputs);

        // TODO: In the future we could check first if we have a higher score ds before
        // and only clear everything if we need to rebuild entirely. But for now
        // just rebuild everything.
        tree->mapDagTxns.clear();
        tree->mapInputs.clear();
        tree->view->Clear();

        std::vector<std::pair<uint256, CTreeNodeRef> > vSortedDag(tree->dag.begin(), tree->dag.end());
        std::sort(vSortedDag.begin(), vSortedDag.end(),
            [](const auto &a, const auto &b) { return a.second->nSequenceId < b.second->nSequenceId; });
        for (auto it = vSortedDag.begin(); it != vSortedDag.end(); it++)
        {
            nSequenceId++;
            const CTreeNodeRef &treenode = it->second;
            // if (treenode->fProcessed) TODO: for now rebuild everything.
            //     continue;

            bool fJustCheck = false;
            bool fParallel = false;
            bool fScriptChecks = true;
            CAmount nFees = 0;
            CBlockUndo blockundo;
            std::vector<std::pair<uint256, CDiskTxPos> > vPos;
            vPos.reserve(treenode->subblock->vtx.size());
            std::map<CGroupTokenID, CAmount> accumulatedMintages;
            std::map<CGroupTokenID, CAuth> accumulatedAuthorities;

            // Try connecting the subblock and updating the coins cache.
            if (ConnectBlockCanonicalOrdering(treenode->subblock, state, tree->pindexSummaryRoot, *tree->view,
                    chainparams, fJustCheck, fParallel, fScriptChecks, nFees, blockundo, vPos, accumulatedMintages,
                    accumulatedAuthorities, &tree->mapDagTxns, &setTxnExclusions))
            {
                // Rebuild the mapDagTxns as subblocks are connected.
                for (CTransactionRef ptx : treenode->subblock->vtx)
                {
                    if (ptx->IsCoinBase())
                        continue;

                    tree->mapDagTxns.emplace(ptx->GetId(), ptx);

                    for (auto &input : ptx->vin)
                    {
                        tree->mapInputs.emplace(input.prevout, ptx);
                    }
                }

                treenode->fProcessed = true;
                treenode->nSequenceId = nSequenceId;
            }
            else
            {
                AddSubblockOrphan(treenode);
                tree->dag.erase(treenode->hash);
                nSequenceId--;
            }
        }
    }

    grove->ActivateBestTree();
}

void CTailstormForest::SetDagCoinsTip()
{
    AssertLockHeld(tailstormForest.cs_forest);
    DbgAssert(
        txProcessingCorral.region() == CORRAL_TX_PAUSE, LOGA("Do not have corral pause during activate best tree"));

    // Cycle through all the trees of each grove and find the chainWork
    CCoinsViewCache *_pcoinsDag = pcoinsTip;
    arith_uint256 nMaxChainWork = chainActive.Tip()->chainWork();

    // Find all groves
    std::set<CTailstormGroveRef> setAllGroves;
    for (auto &mi : mapAllGroves)
        setAllGroves.insert(mi.second);

    for (auto &grove : setAllGroves)
    {
        arith_uint256 nTreeChainWork = grove->tree->pindexSummaryRoot->chainWork();
        std::set<CTreeNodeRef> dag;
        GetBestDagFor(grove->roothash, dag);
        for (auto node : dag)
        {
            nTreeChainWork += GetWorkForDifficultyBits(node->subblock->nBits);
        }
        if (nTreeChainWork > nMaxChainWork)
        {
            nMaxChainWork = nTreeChainWork;
            _pcoinsDag = grove->tree->view;
        }
    }

    SetDagCoinsTip(_pcoinsDag);
}

void CTailstormForest::SetDagCoinsTip(CCoinsViewCache *coinsCache)
{
    AssertLockHeld(tailstormForest.cs_forest);
    DbgAssert(
        txProcessingCorral.region() == CORRAL_TX_PAUSE, LOGA("Do not have corral pause during activate best tree"));

    pcoinsDag = coinsCache;
}

void CTailstormForest::SetDagActiveTip(CTreeNodeRef treenode)
{
    std::atomic_store(&pDagActiveTip, treenode);
    forceTemplateRecalc = true;
}

uint256 CTailstormForest::GetDagActiveTip()
{
    CTreeNodeRef ref = std::atomic_load(&pDagActiveTip);
    if (ref)
    {
        if (ref->hash.IsNull())
            return chainActive.Tip()->GetBlockHash();
        else
            return ref->hash;
    }
    return chainActive.Tip()->GetBlockHash();
}

void CTailstormForest::Check()
{
    if (nCheckFrequency == 0)
        return;

    if (GetRand(std::numeric_limits<uint32_t>::max()) >= nCheckFrequency)
        return;

    LOCK(cs_forest);
    assert(_pcoinsTip);

    // Check summary blocks unlinked should never have a grove created for it yet.
    for (auto &mi : mapSummaryBlocksUnlinked)
    {
        CTailstormGroveRef grove = nullptr;
        /*  Uncomment when you need extra debug logging
        if (GetGrove(mi.first, grove))
        {
             LOGA(" summary block still in unlinked %s\n", mi.first.ToString().c_str());
        }
        */
        assert(!GetGrove(mi.first, grove));
    }

    // Count up forest nodes and check that all nodes equal grove nodes plus unlinked.
    if (mapAllNodes.size() != mapAllGroves.size() + mapNodesUnlinked.size())
    {
        LOG(DAG, " failed - mapallnodes %ld mapallgroves %ld mapnodesunlinked %ld\n", mapAllNodes.size(),
            mapAllGroves.size(), mapNodesUnlinked.size());

        LOG(DAG, "map all nodes: \n");
        for (auto it : mapAllNodes)
            LOG(DAG, "   %s\n", it.first.ToString().c_str());
        LOG(DAG, "map all groves: \n");
        for (auto it : mapAllGroves)
            LOG(DAG, "   %s\n", it.first.ToString().c_str());
        LOG(DAG, "map nodes unlinked: \n");
        for (auto it : mapNodesUnlinked)
            LOG(DAG, "   %s\n", it.first.ToString().c_str());
    }
    assert(mapAllNodes.size() == mapAllGroves.size() + mapNodesUnlinked.size());

    // Find all unique groves
    std::set<CTailstormGroveRef> setGroves;
    for (auto &mi : mapAllGroves)
    {
        setGroves.insert(mi.second);
    }

    // Count up nodes (within each grove) and check that all forest nodes equal grove nodes plus unlinked.
    std::set<std::shared_ptr<CTailstormTree> > setAllTrees;
    uint32_t nAllGroveNodes = 0;
    for (auto &grove : setGroves)
    {
        nAllGroveNodes += grove->mapGroveNodes.size();
        assert(grove->tree);
        assert(grove->_pcoinsTip);
        assert(!grove->setValidTrees.empty());
        assert(!grove->roothash.IsNull());
        assert(grove->nRootHeight > 0);

        setAllTrees.insert(grove->setValidTrees.begin(), grove->setValidTrees.end());

        // make sure all tree entries also have an entry in mapGroveNodes.
        for (auto &tree : grove->setValidTrees)
        {
            for (auto &mi : tree->dag)
            {
                assert(grove->mapGroveNodes.count(mi.first));
                assert(grove->mapGroveNodes[mi.first] == mi.second);
            }
        }
    }
    assert(mapAllNodes.size() == nAllGroveNodes + mapNodesUnlinked.size());

    // Count up all nodes (within each tree) and check that all forest nodes equals tree nodes plus unlinked.
    std::set<CTreeNodeRef> setAllTreeNodes;
    for (auto &tree : setAllTrees)
    {
        uint64_t nTreeTxnCount = 0;
        for (auto &mi : tree->dag)
        {
            setAllTreeNodes.insert(mi.second);

            // Check tree mapDagTxns is correctly reflecting the tree
            nTreeTxnCount += mi.second->subblock->vtx.size() - 1;

            // Check hash
            assert(mi.first == mi.second->hash);
        }
        assert(nTreeTxnCount >= tree->mapDagTxns.size());

        // Check sequence ids are contiguous and match the total number of nodes
        {
            std::vector<std::pair<uint256, CTreeNodeRef> > vSortedDag(tree->dag.begin(), tree->dag.end());
            std::sort(vSortedDag.begin(), vSortedDag.end(),
                [](const auto &a, const auto &b) { return a.second->nSequenceId < b.second->nSequenceId; });
            for (uint32_t i = 0; i < vSortedDag.size(); i++)
                assert(vSortedDag[i].second->nSequenceId == i + 1);
        }

        // Check tree dag heights, ancestors and descendants
        {
            std::vector<std::pair<uint256, CTreeNodeRef> > vSortedDagHeights(tree->dag.begin(), tree->dag.end());
            std::sort(vSortedDagHeights.begin(), vSortedDagHeights.end(),
                [](const auto &a, const auto &b) { return a.second->dagHeight < b.second->dagHeight; });

            for (uint32_t i = 0; i < vSortedDagHeights.size(); i++)
            {
                CTreeNodeRef node = vSortedDagHeights[i].second;
                auto setPrevHashes = GetPrevHashes(node->subblock->GetBlockHeader());
                assert(!setPrevHashes.empty());

                if (i == 0)
                    assert(node->dagHeight == 1);

                if (node->dagHeight == 1)
                {
                    assert(node->setAncestors.empty());
                    assert(setPrevHashes.size() == 1);
                    assert(setPrevHashes.count(node->subblock->hashPrevBlock));
                }
                else
                {
                    for (auto &ancestor : node->setAncestors)
                    {
                        assert(ancestor->dagHeight <= node->dagHeight - 1);
                        assert(setPrevHashes.count(ancestor->hash));
                    }
                    for (auto &desc : node->setDescendants)
                    {
                        auto setDescHashes = GetPrevHashes(desc->subblock->GetBlockHeader());
                        assert(setDescHashes.count(node->hash));
                    }
                }
            }
        }
    }
    assert(mapAllNodes.size() == setAllTreeNodes.size() + mapNodesUnlinked.size());

    // Check minerData versions
    for (auto &mi : mapNodesUnlinked)
    {
        assert(GetMinerDataVersion(mi.second->subblock->minerData) == DEFAULT_MINER_DATA_SUBBLOCK_VERSION);
    }
    for (auto &mi : mapSummaryBlocksUnlinked)
    {
        assert(GetMinerDataVersion(mi.second->minerData) == DEFAULT_MINER_DATA_SUMMARYBLOCK_VERSION);
    }
}
