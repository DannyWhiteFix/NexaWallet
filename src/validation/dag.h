// Copyright (c) 2020-2025 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_TAILSTORM_DAG_H
#define NEXA_TAILSTORM_DAG_H


#include "chain.h"
#include "coins.h"
#include "primitives/block.h"
#include "sync.h"

#include <deque>
#include <queue>
#include <set>

extern CChain chainActive;
extern CCoinsViewCache *pcoinsTip;

static const uint32_t DEFAULT_UNCLE_SCORE_ADJUSTMENT = 4;

class CTreeNode;
typedef std::shared_ptr<CTreeNode> CTreeNodeRef;
template <typename Node>
static inline CTreeNodeRef MakeTreeNodeRef(Node &&nodeIn)
{
    return std::make_shared<CTreeNode>(std::forward<Node>(nodeIn));
}
class CTailstormGrove;
typedef std::shared_ptr<CTailstormGrove> CTailstormGroveRef;
template <typename Grove>
static inline CTailstormGroveRef MakeTailstormGroveRef(Grove &&groveIn)
{
    return std::make_shared<CTailstormGrove>(std::forward<Grove>(groveIn));
}

// Return a map of all the subblock scores for any nodes in the dag
// NOTE: An int32_t is used because scores can temporarily go negative during the calculation process.
std::map<CTreeNodeRef, uint32_t> GetDagScores(const std::set<CTreeNodeRef> &setBestDag);

// Get the set of invalid double spends which we "DO NOT" want to include in the final summary block.
std::set<uint256> GetTxnExclusionSet(const std::set<CTreeNodeRef> &setBestDag,
    std::vector<std::map<uint256, CTreeNodeRef> > &_vDoubleSpendTxns,
    std::map<COutPoint, CTransactionRef> &mapInputs);

class CTreeNode
{
public:
    uint256 hash; // the subblock hash that is this node
    uint32_t dagHeight = 0;
    uint32_t nSequenceId = 0;
    bool fProcessed = false;
    bool fUncle = false; // is this a subblock (uncle) from the previous summary block
    uint256 roothash; // the summary block hash of the dag that the treenode is being added to.

    ConstCBlockRef subblock = nullptr;

    std::set<CTreeNodeRef> setAncestors; // points to the parents of this subblock
    std::set<CTreeNodeRef> setDescendants; // points to the nodes of the children

    CTreeNode() {}

    CTreeNode(ConstCBlockRef _subblock)
    {
        hash = _subblock->GetHash();
        subblock = _subblock;
    }

    friend bool operator<(const CTreeNode a, const CTreeNode b) { return a.hash < b.hash; }

    void AddAncestors(std::set<CTreeNodeRef> &ancestors) { setAncestors.insert(ancestors.begin(), ancestors.end()); }
    void AddDescendant(CTreeNodeRef _descendent) { setDescendants.emplace(_descendent); }

    // This subblock is just after the last summary block
    bool IsBase() { return (setAncestors.empty() && dagHeight == 1); }

    // This subblock is a tree tip
    bool IsTip() { return setDescendants.empty(); }
};

// All data members are protected by cs_forest
class CTailstormTree
{
    friend class CTailstormGrove;
    friend class CTailstormForest;

protected:
    // pointers point to the nodes for this dag, a pointer to the same node is
    // also available in mapAllNodes at the forest level
    std::map<uint256, CTreeNodeRef> dag;

    // A map of uncles. Uncles are orphans that didn't get included in the last
    // summary block bbut which we could use in the current summary block. Uncles
    // could be subblocks and/or summary blocks.
    std::map<uint256, CTreeNodeRef> mapUncles;

    // map of unique transactions that are already in the dag for this tree. This
    // data also includes all double spend transactions and is updated "after" a block
    // successfully connects to the dag. It is used in connect block to skip the
    // processing of a duplicate transaction which exists in some other subblock.
    std::map<uint256, CTransactionRef> mapDagTxns;

    // a map of all inputs and the transactions they refer to that exist in the dag.
    // Used in determining which transactions are chained. This data also includes
    // all double spend transaction inputs.
    std::map<COutPoint, CTransactionRef> mapInputs;

    // a vector of sets of transactions that double spend each other. In each
    // set the transactions in them double spend one another.
    std::vector<std::map<uint256, CTreeNodeRef> > vDoubleSpendTxns;


    // global coins cache pointer
    CCoinsViewCache *_pcoinsTip = nullptr;

    // coins cache view for the this tree backed by _pcoinsTip
    CCoinsViewCache *view = nullptr;

    // the block index of the summary block that this tree is built on top of.
    CBlockIndex *pindexSummaryRoot = nullptr;

public:
    CTailstormTree() {}
    ~CTailstormTree()
    {
        if (view)
        {
            delete view;
            view = nullptr;
        }
    }

protected:
    bool Insert(CTreeNodeRef new_node);
};

// All datamembers are protected by cs_forest
class CTailstormGrove
{
    friend class CTailstormForest;
    friend class CTailstormTree;

protected:
    // There can be many valid trees in a grove but, "tree" references the current active tree.
    std::shared_ptr<CTailstormTree> tree = nullptr;

    // key is subblock hash for the node in value
    std::map<uint256, CTreeNodeRef> mapGroveNodes;

    // the hash of the summary block that this grove is being built on.
    uint256 roothash;

    // the height of the summary block this grove is being built on.
    uint64_t nRootHeight = 0;

    CCoinsViewCache *_pcoinsTip = nullptr;

protected:
    bool InitializeTree(CTreeNodeRef newNode, CCoinsViewCache *coinsCache);
    bool InsertIntoTree(CTreeNodeRef newNode);

    CTailstormGrove(CCoinsViewCache *coinsCache)
    {
        CTailstormTree temp;
        tree = std::make_shared<CTailstormTree>(temp);

        _pcoinsTip = coinsCache;
        assert(_pcoinsTip);
    }

    void Clear();

    bool Insert(CTreeNodeRef newNode);
    bool GetBestDag(std::set<CTreeNodeRef> &dag,
        std::vector<std::map<uint256, CTreeNodeRef> > *vDoubleSpendTxns = nullptr,
        std::map<COutPoint, CTransactionRef> *mapInputs = nullptr);
    bool GetFullDag(std::set<CTreeNodeRef> &dag);
    bool GetBestTipHash(uint256 &hash);
};

class CTailstormForest
{
    friend class CTailstormGrove;

public:
    // Use for locking all data structure except pDagActiveTip and pcoinsDag.
    CCriticalSection cs_forest;

    // Used for try locking when we check for a re-org
    // to limit execution to one thread.
    CCriticalSection cs_reorg;

protected:
    // key is subblock hash for the node in value
    // mapAllNodes contains all nodes in the entire forest including orphans. The grove contains two
    // maps that are a subsets of this map. They are only used to speed up grove
    // specific node searching and for faster cleanup of nodes being removed
    // from the forest
    std::map<uint256, CTreeNodeRef> mapAllNodes;

    // Used for finding which grove a subblock is in by hash
    std::map<uint256, CTailstormGroveRef> mapAllGroves;

    // Contains all orphan nodes
    std::map<uint256, CTreeNodeRef> mapNodesUnlinked;

    // Contains all orphaned summary blocks
    std::map<uint256, ConstCBlockRef> mapSummaryBlocksUnlinked;

    // The main global coins cache
    CCoinsViewCache *_pcoinsTip = nullptr;

    // This is used for the sake of efficiency to access the current best
    // dag tip for mining purposes. This is used primarily in the getbestdagtiphash()
    // rpc call and is accessed in an atomic fashion so does not need locking when
    // accessed by its class methods.
    CTreeNodeRef pDagActiveTip = nullptr;

public:
    // The coins cache for the active tree. This is used
    // by txadmission and needs to be set each time the active
    // tree is updated.
    //
    // NOTE: pcoinsDag is protected by txAdmissionPause().  You must
    // have taken a Corral, either a TX_PAUSE or TX_PROCESSING before using this
    // pointer.
    CCoinsViewCache *pcoinsDag = nullptr;

protected:
    // The frequency used for sanity checking the dag
    uint32_t nCheckFrequency = 0;

public:
    CTailstormForest() {}
    ~CTailstormForest() { Clear(); }

    //! Clear all forest, grove and tree data structures.
    void Clear();

    //! Clear a grove that has the passed hash in it.
    void ClearGrove(const uint256 &hash);

    //! Trim the forest of any nodes <= nPruneHeight
    void ClearByHeight(const uint32_t nPruneHeight);

    //! The number of nodes in the forest
    size_t Size();

    //! Insert a new subblock into a grove
    bool Insert(ConstCBlockRef subblock);
    bool _Insert(ConstCBlockRef subblock);

    //! Add or remove a summary block to the orphan map
    void AddSummaryBlockOrphan(ConstCBlockRef pblock);
    void RemoveSummaryBlockOrphan(ConstCBlockRef pblock);

    //! Add a subblock orphan to the orphans map.
    void AddSubblockOrphan(CTreeNodeRef newNode);

    //! Process all orphaned subblocks and summary blocks
    std::set<uint256> ProcessOrphans();

    //! Return a hash of the dag tip given a hash of some subblock in the dag.
    uint256 GetDagTipHash(const uint256 &hash);

    //! Find and return a subblock in the forest, if it exists.
    bool Find(const uint256 &hash, ConstCBlockRef &subblock);

    //! Find out whether the forst contains a treenode
    bool Contains(const uint256 &hash);

    //! return a map of all tree nodes.
    std::map<uint256, CTreeNode> GetAllNodes();

    //! Return a set of tree nodes of the best dag and associated data
    bool GetBestDagFor(const uint256 &hash,
        std::set<CTreeNodeRef> &dag,
        std::vector<std::map<uint256, CTreeNodeRef> > *vDoubleSpendTxns = nullptr,
        std::map<COutPoint, CTransactionRef> *mapInputs = nullptr);

    //! Return the entire set of treen nodes and uncle nodes
    bool GetFullDagFor(const uint256 &hash, std::set<CTreeNodeRef> &dag);

    //! Return a set of nodes from a tree that matches what is in a block
    bool GetDagForBlock(ConstCBlockRef &pblock,
        std::set<CTreeNodeRef> &dag,
        std::vector<std::map<uint256, CTreeNodeRef> > *vDoubleSpendTxns,
        std::map<COutPoint, CTransactionRef> *mapInputs);

    //! Return the current hash of the tip of the dag which contains this hash
    bool GetBestTipHashFor(const uint256 &hash, uint256 &tiphash);

    //! Return a map of all the transactions in the given dag
    void GetDagTxns(const std::set<CTreeNodeRef> &dag, std::map<uint256, CTransactionRef> &mapDagTxns);

    //! Return the dag height of a subblock given it's hash.
    uint32_t GetDagHeight(const uint256 &hash);

    //! Return a the grove that a subblock belongs to
    bool GetGrove(const uint256 &hash, CTailstormGroveRef &grove);

    //! Return the number of unlinked subblocks
    uint32_t GetUnlinkedSubblocks();

    //! Return the number of unlinked summary blocks
    uint32_t GetUnlinkedSummaryBlocks();

    //! Detemine if we need to re-org the chainActive tip to one that has a better dag.
    void CheckForReorg();

    //! Generate coincache and mapDagTxn data for a grove and all its valid trees.
    void GenerateDagData(CTailstormGroveRef grove);

    //! Set the main coins cache that we build our tailstorm tree views on top of.
    void SetBackend(CCoinsViewCache *coinsCache)
    {
        LOCK(cs_forest);
        _pcoinsTip = coinsCache;
    }

    //! Set the coins tip for the active dag
    void SetDagCoinsTip();
    void SetDagCoinsTip(CCoinsViewCache *coinsCache);

    //! Atomically set the dag active tip
    void SetDagActiveTip(CTreeNodeRef treenode);

    //! Atomically get the dag active tip
    uint256 GetDagActiveTip();

    //! Get all Uncles for this node, whether they be subblocks or
    //  summary blocks, which can then be added to a trees Uncle map
    std::map<uint256, CTreeNodeRef> GetUncles(CTreeNodeRef node);

    //! Remove a node and any descendants from the forest
    bool Remove(uint256 &hash);

    //! Sanity check the dag for errors.
    void Check();
    void setSanityCheck(double dFrequency = 1.0) { nCheckFrequency = dFrequency * 4294967295.0; }
};

extern CTailstormForest tailstormForest;

// Helper Function: Get the current best dag tip for mining on top of
uint256 GetActiveDagTip(std::set<CTreeNodeRef> &dag);

#endif
