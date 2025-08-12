// Copyright (c) 2020-2021 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// tailstorm file includes
#include "dag.h"

// other bitcoin includes
#include "consensus/consensus.h"
#include "txmempool.h"

bool CTailstormTree::CheckForCompatibility(CTreeNodeRef newNode, std::map<COutPoint, uint256> &new_spends)
{
    for (auto &tx : newNode->subblock.vtx)
    {
        if (tx->IsProofBase())
        {
            continue;
        }
        for (auto &input : tx->vin)
        {
            // TODO : change to contains in c++17
            if (_spentOutputs.count(input.prevout) != 0)
            {
                if (_spentOutputs[input.prevout] != tx->GetHash())
                {
                    return false;
                }
            }
            new_spends.emplace(input.prevout, tx->GetHash());
        }
    }
    return true;
}

void CTailstormTree::Insert(CTreeNodeRef newNode, std::map<COutPoint, uint256> &new_spends)
{
    // change to merge in c++17
    _spentOutputs.insert(new_spends.begin(), new_spends.end());
    for (auto &tx : newNode->subblock.vtx)
    {
        bool fCoinbase = tx->IsCoinBase();
        uint256 txid = tx->GetHash();
        for (size_t i = 0; i < tx->vout.size(); ++i)
        {
            _newOutputs.emplace(COutPoint(txid, i), std::make_pair(tx->vout[i], fCoinbase));
        }
    }
    _dag.emplace_back(newNode);
    // UpdateDagScore();
}

void CTailstormGrove::_CreateNewTree(CTreeNodeRef newNode)
{
    AssertWriteLockHeld(cs_grove);
    std::map<COutPoint, uint256> new_spends;
    _tree.CheckForCompatibility(newNode, new_spends);
    _tree.Insert(newNode, new_spends);
    for (auto &tx : newNode->subblock.vtx)
    {
        mempool.UpdateTransactionDagInfo(tx->GetHash(), 0, true);
    }
}

void CTailstormGrove::Clear()
{
    // should always have cs_forest lock because this should only be called from
    // within a clear method at the forest level
    AssertWriteLockHeld(tailstormForest.cs_forest);
    WRITELOCK(cs_grove);
    // delete all of the nodes in this grove. mapAllGroveNodes is
    // a subset of mapAllNodes which we can iterate over to efficiently remove
    // the nodes from mapAllNodes
    for (auto &entry : mapAllGroveNodes)
    {
        tailstormForest.mapAllNodes.erase(entry.first);
    }
    mapAllGroveNodes.clear();
    mapUnusedNodes.clear();
}

void CTailstormGrove::_CheckOrphans(const uint256 &hash)
{
    uint256 ancestorHash;

    for (auto iter = mapUnusedNodes.begin(); iter != mapUnusedNodes.end();)
    {
        if (iter->second->subblock.GetAncestorHash(ancestorHash))
        {
            if (ancestorHash == hash)
            {
                if (_InsertIntoTree(iter->second))
                {
                    iter = mapUnusedNodes.erase(iter);
                    continue;
                }
            }
        }
        ++iter;
    }
}

bool CTailstormGrove::_InsertIntoTree(CTreeNodeRef newNode)
{
    mapAllGroveNodes.emplace(newNode->hash, newNode);
    bool AddToTree = true;
    uint256 ancestorHash = uint256();
    if (_tree._dag.size() == 0)
    {
        // Get the ancestor hash. A zero hash is returned if there is no ancestor
        if (newNode->subblock.GetAncestorHash(ancestorHash))
        {
            LOGA("%s(): ERROR, subblock %s has ancestor hashes but there are no nodes in the tree\n", __func__,
                newNode->hash.GetHex().c_str());
            return false;
        }
        _CreateNewTree(newNode);
        return true;
    }
    // check that we have all ancestor treenodes and that they are in the tree
    CTreeNodeRef ancestor = nullptr;
    if (newNode->subblock.GetAncestorHash(ancestorHash))
    {
        std::map<uint256, CTreeNodeRef>::iterator ancestor_iter = mapAllGroveNodes.find(ancestorHash);
        if (ancestor_iter == mapAllGroveNodes.end())
        {
            // TODO : A subblock is missing, try to re-request it or something
            LOGA("%s(): ERROR, subblock %s references missing ancestor subblock %s\n", __func__,
                newNode->hash.GetHex().c_str(), ancestorHash.GetHex().c_str());
            return false;
        }
        bool found = false;
        for (const auto node : _tree._dag)
        {
            if (node->hash == ancestorHash)
            {
                // use a pointer to the node already inserted in mapAllGroveNodes to avoid obj duplication
                // CTreeNodeRef ancestor = ancestor_iter->second;
                ancestor = ancestor_iter->second;
                found = true;
                break;
            }
        }
        if (found == false)
        {
            LOGA("%s(): WARNING, subblock %s references ancestor subblock %s that is not in tree\n", __func__,
                newNode->hash.GetHex().c_str(), ancestorHash.GetHex().c_str());
            AddToTree = false;
        }
    }
    // add ancestor information regardless of being added to the tree
    if (ancestor != nullptr)
    {
        newNode->AddAncestor(ancestor);
        newNode->height = ancestor->height + 1;
    }
    std::map<COutPoint, uint256> new_spends;
    if (!_tree.CheckForCompatibility(newNode, new_spends))
    {
        LOGA("%s(): subblock %s is incompatible with tree \n", __func__, newNode->hash.GetHex().c_str());
        AddToTree = false;
    }
    if (AddToTree == false)
    {
        mapUnusedNodes.emplace(newNode->hash, newNode);
        return true;
    }
    if (ancestor)
    {
        ancestor->AddDescendant(newNode);
    }
    _tree.Insert(newNode, new_spends);
    // once we have inserted the subblock into a dag, we should update the
    // mempool with information about which dag the txx went into
    for (auto &tx : newNode->subblock.vtx)
    {
        mempool.UpdateTransactionDagInfo(tx->GetHash(), 0, true);
    }
    return true;
}

bool CTailstormGrove::Insert(CTreeNodeRef newNode)
{
    WRITELOCK(cs_grove);
    bool ret = _InsertIntoTree(newNode);
    if (ret)
    {
        _CheckOrphans(newNode->hash);
    }
    return ret;
}

bool CTailstormGrove::GetBestDag(std::set<CTreeNodeRef> &dag)
{
    READLOCK(cs_grove);
    if (_tree._dag.size() < TAILSTORM_K)
    {
        return false;
    }
    size_t nodeCt = 0;
    for (auto &node : _tree._dag)
    {
        dag.emplace(node);
        nodeCt++;
        // TODO: Do something more sophisticated to handle cases where there are more
        // nodes than are necessary to assemble a block
        if (nodeCt == TAILSTORM_K)
            break;
    }
    return true;
}

bool CTailstormGrove::GetBestTipHash(uint256 &hash)
{
    READLOCK(cs_grove);
    unsigned int bestHeight = 0;
    for (auto &node : _tree._dag)
    {
        if (node->IsTip())
        {
            if (node->height > bestHeight)
            {
                hash = node->hash;
                bestHeight = node->height;
            }
            else if (node->height == bestHeight)
            {
                if (node->hash < hash)
                {
                    hash = node->hash;
                }
            }
        }
    }
    return true;
}

bool CTailstormGrove::GetNewOutputs(std::map<COutPoint, std::pair<CTxOut, bool> > &mapNewOutputs)
{
    mapNewOutputs = _tree._newOutputs;
    return true;
}

bool CTailstormGrove::GetSpentOutputs(std::map<COutPoint, uint256> &mapSpentOutputs)
{
    mapSpentOutputs = _tree._spentOutputs;
    return true;
}