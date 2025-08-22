// Copyright (c) 2016-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/* The request manager creates an isolation layer between the nodes message processor and the network.
It tracks known locations of data objects and issues requests to the node most likely to respond.  It monitors responses
and is capable of re-requesting the object if the node disconnects or does not respond.

This stops this node from losing transactions if the remote node does not respond (previously, additional INVs would be
dropped because the transaction is "in flight"), yet when the request finally timed out or the connection dropped, the
INVs likely would no longer be propagating throughout the network so this node would miss the transaction.

It should also be possible to use the statistics gathered by the request manager to make unsolicited requests for data
likely held by other nodes, to choose the best node for expedited service, and to minimize data flow over poor
links, such as through the "Great Firewall of China".

This is a singleton class, instantiated as a global named "requester".

The P2P message processing software should no longer directly request data from a node.  Instead call:
requester.AskFor(...)

After the object arrives (its ok to call after ANY object arrives), call "requester.Received(...)" to indicate
successful receipt, "requester.Rejected(...)" to indicate a bad object (request manager will try someone else), or
"requester.AlreadyReceived" to indicate the receipt of an object that has already been received.
 */

#ifndef REQUEST_MANAGER_H
#define REQUEST_MANAGER_H

#include "blockrelay/mempool_sync.h"
#include "net.h"
#include "nodestate.h"
#include "stat.h"

#include <atomic>

// How many peers are connected before we start looking for slow peers to disconnect.
static const uint32_t BEGIN_PRUNING_PEERS = 4;

// How many blocks forward to download during IBD
static const uint32_t DEFAULT_BLOCK_DOWNLOAD_WINDOW = 1024;

// How many requests can be active in the request manager at any one time
static const uint64_t MAX_IN_FLIGHT_REQS = 100000;

// How many object sources can we add to the new request.  This will prevent
// too many re-requests from happening and also prevent the unnecessary adding
// of sources when there are many peers connected.  In other words, if we
// can't get a re-request withing a few attempts then it's unlikely we will ever
// get that object and it may just be a DOS attempt at filling up the request manager
// with fake object requests.
static const uint32_t MAX_SOURCES_TO_ADD = 3;

// When should I request a tx from someone else (in microseconds).
static const unsigned int DEFAULT_MIN_TX_REQUEST_RETRY_INTERVAL = 5 * 1000 * 1000;

// When should I request a block from someone else (in microseconds).
static const unsigned int DEFAULT_MIN_BLK_REQUEST_RETRY_INTERVAL = 5 * 1000 * 1000;

// Max requests in a singe getdata message
static const unsigned int MAX_GETDATA_REQUESTS = 1000;

// Which peers have mempool synchronization in-flight?
extern CCriticalSection cs_mempoolsync;
extern std::map<NodeId, CMempoolSyncState> mempoolSyncRequested;

extern std::atomic<uint64_t> lastMempoolSync;

class CNode;

class CNodeRequestData
{
public:
    int requestCount;
    int desirability;
    CNodeRef noderef;
    CNodeRequestData(CNodeRef n);

    CNodeRequestData() : requestCount(0), desirability(0) {}
    void clear(void)
    {
        requestCount = 0;
        noderef.~CNodeRef();
        desirability = 0;
    }
    bool operator<(const CNodeRequestData &rhs) const { return desirability < rhs.desirability; }
};

// Compare a CNodeRequestData object to a node
struct MatchCNodeRequestData
{
    CNodeRef pnode;
    MatchCNodeRequestData(CNodeRef n) : pnode(n){};
    inline bool operator()(const CNodeRequestData &nd) const { return nd.noderef.get() == pnode.get(); }
};

class CUnknownObj
{
public:
    typedef std::list<CNodeRequestData> ObjectSourceList;
    CInv obj;
    bool rateLimited;
    int64_t nDownloadingSince; // last time we started downloading the object
    bool fProcessing; // object was received but is still being processed
    int64_t lastRequestTime; // In stopwatch time microseconds, 0 means no request
    unsigned int outstandingReqs;
    ObjectSourceList availableFrom;
    int64_t nEntryTime;
    CNodeRef prevRequestNode; // The last node we made a request from

    CUnknownObj()
    {
        rateLimited = false;
        nDownloadingSince = 0;
        fProcessing = false;
        outstandingReqs = 0;
        lastRequestTime = 0;
        nEntryTime = 0;
    }

    bool AddSource(CNodeRef &noderef, const CInv &_obj); // returns true if the source did not already exist
};

// The following structs are used for tracking the internal requestmanager nodestate.
struct QueuedBlock
{
    uint256 hash;
    int64_t nTime; // Stopwatch time of "getdata" request in microseconds.
};
struct CRequestManagerNodeState
{
    // An ordered list of blocks currently in flight.  We could use mapBlocksInFlight to get the same
    // data but then we'd have to iterate through the entire map to find what we're looking for.
    std::list<QueuedBlock> vBlocksInFlight;

    // When the first entry in vBlocksInFlight started downloading. Don't care when vBlocksInFlight is empty.
    int64_t nDownloadingFromPeerSince;

    // How many blocks are currently in flight and requested by this node.
    uint64_t nBlocksInFlight;

    CRequestManagerNodeState();
};

class CRequestManager
{
protected:
#ifdef ENABLE_MUTRACE
    friend class CPrintSomePointers;
#endif
#ifdef DEBUG
    friend UniValue getstructuresizes(const UniValue &params, bool fHelp);
#endif
    friend class CState;

    friend class CRequestManagerTest;

    // A cookie can be added to a message which is sent in the message header and which can be used
    // to determine the correct sequence of separate messages that have been received by a node or light client.
    std::atomic<uint32_t> requestCookie{0};

    // Increment the cookie value and then return the new value.
    uint32_t getCookie() { return (++requestCookie << 16); }

    // Loosely track transations per second. This is done so we don't have to repeatedly
    // take the lock in the mempool.
    std::atomic<uint64_t> nApproximateTxnPerSec{0};
    std::atomic<int64_t> nLastCheckForTPS{0};

    // Data structures for making and tracking requests
    CCriticalSection cs_objDownloader;
    typedef std::map<uint256, CUnknownObj> OdMap;
    OdMap mapTxnInfo GUARDED_BY(cs_objDownloader);
    OdMap mapBlkInfo GUARDED_BY(cs_objDownloader);
    std::map<uint256, std::map<NodeId, std::list<QueuedBlock>::iterator> > mapBlocksInFlight GUARDED_BY(
        cs_objDownloader);
    std::map<NodeId, CRequestManagerNodeState> mapRequestManagerNodeState GUARDED_BY(cs_objDownloader);

    // The map of block requests to add.
    CCriticalSection cs_addBlock;
    OdMap mapBlkToAdd GUARDED_BY(cs_addBlock);
    int64_t nBlocksAskedFor GUARDED_BY(cs_addBlock) = 0;

    // The set of block requests to delete
    CCriticalSection cs_deleteBlock;
    std::set<uint256> setBlockDeleter GUARDED_BY(cs_deleteBlock);

    // The map of transaction requests to add.
    CCriticalSection cs_addTxn;
    OdMap mapTxnToAdd GUARDED_BY(cs_addTxn);

    // The set of transaction requests to delete
    CCriticalSection cs_deleteTxn;
    std::set<uint256> setDeleter GUARDED_BY(cs_deleteTxn);

    CStatHistory<int> inFlightTxns; // unused
    CStatHistory<int> receivedTxns; // unused
    CStatHistory<int> rejectedTxns;
    CStatHistory<int> droppedTxns; // unused
    CStatHistory<int> pendingTxns;

    void cleanup(OdMap::iterator &item);
    void cleanup(const CInv &item);

public:
    CRequestManager();

    // Cleanup stops all request manager activity, aborts all current requests, and releases all node references
    // in preparation for shutdown
    void Cleanup();

    // How many outbound nodes are we connected to.
    std::atomic<int32_t> nOutbound;

    /** Size of the "block download window": how far ahead of our current height do we fetch?
     *  Larger windows tolerate larger download speed differences between peer, but increase the potential
     *  degree of disordering of blocks on disk (which make reindexing and in the future perhaps pruning
     *  harder). We'll probably want to make this a per-peer adaptive value at some point. */
    std::atomic<unsigned int> BLOCK_DOWNLOAD_WINDOW{DEFAULT_BLOCK_DOWNLOAD_WINDOW};

    // Request a single block.
    bool RequestBlock(CNode *pfrom, CInv &obj);

    // Get this object from somewhere, asynchronously.
    void AskFor(const CInv &obj, CNode *from);

    // Get these objects from somewhere, asynchronously.
    void AskFor(const std::vector<CInv> &objArray, CNode *from);

    // Get these objects from somewhere, asynchronously during IBD. During IBD we must assume every peer connected
    // can give us the blocks we need and so we tell the request manager about these sources. Otherwise the request
    // manager may not be able to re-request blocks from anyone after a timeout and we also need to be able to not
    // request another group of blocks that are already in flight.
    void AskForDuringIBD(const std::vector<CInv> &objArray, CNode *from);

    // Did we already ask for this block. We need to do this during IBD to make sure we don't ask for another set
    // of the same blocks.
    bool AlreadyAskedForBlock(const uint256 &hash);

    // Update the response time for this transaction request
    void UpdateTxnResponseTime(const CInv &obj, CNode *pfrom);

    // Indicate that we got this object
    void Downloading(const uint256 &hash, CNode *pfrom, unsigned int nSize);

    // Indicate that we are processing this block
    void ProcessingBlock(const uint256 &hash, CNode *pfrom);

    // Indicate that the block failed initial acceptance
    void BlockRejected(const CInv &obj, CNode *pfrom);

    // Indicate that we got this object
    void Received(const CInv &obj, CNode *pfrom);

    // Indicate that we previously got this object
    void AlreadyReceived(CNode *pnode, const CInv &obj);

    // Indicate that getting this object was rejected
    void Rejected(const CInv &obj, CNode *from, unsigned char reason = 0);

    // request a block by its hash
    void RequestCorruptedBlock(const uint256 &blockHash);

    // Resets the last request time to zero when a node disconnects and has blocks in flight.
    void ResetLastBlockRequestTime(const uint256 &hash);

    // Check if this is a new source or a new request. If a new source
    // then have to add this source to the appropriate source list and then
    // remove it from the new request map so we don't end up requesting it twice.
    void CheckIfNewSource(OdMap &mapNewRequests, OdMap &mapOldRequests);

    // Clear out any objects from the block request map that were slated for deletion.
    void RunBlockDeleter(OdMap &mapTemp);

    // Get the map of current requests
    void GetBlockRequests(OdMap &mapTemp);

    // Add new block requests to the transaction request map.
    void AddNewBlockRequests(OdMap &mapTemp);

    // Get the map of current requests
    void GetTxnRequests(OdMap &mapTemp);

    // Clear out any objects from the transaction request maps that are slated for deletion.
    void RunTxnDeleter(OdMap &maybeToSend);

    // Add new transaction requests to the transaction request map.
    void AddNewTxnRequests(OdMap &mapTemp);

    // Send transaction requests for a particular request map
    void SendTxnRequests(OdMap &mapTxns);

    // Send all block and transaction requests
    void SendRequests();

    // Check whether the last unknown block a peer advertised is not yet known.
    void ProcessBlockAvailability(NodeId nodeid);

    // Update tracking information about which blocks a peer is assumed to have.
    void UpdateBlockAvailability(NodeId nodeid, const uint256 &hash);

    // Request the next blocks. Mostly this will get exucuted during IBD but sometimes even
    // when the chain is syncd a block will get request via this method.
    void RequestNextBlocksToDownload(CNode *pto);

    // This gets called from RequestNextBlocksToDownload
    void FindNextBlocksToDownload(CNode *node, size_t count, std::vector<CBlockIndex *> &vBlocks);

    // Request to synchronize mempool with peer pto
    void RequestMempoolSync(CNode *pto);

    // Returns a bool indicating whether we requested this block.
    void MarkBlockAsInFlight(NodeId nodeid, const uint256 &hash);

    // Returns a bool if successful in indicating we received this block.
    bool MarkBlockAsReceived(const uint256 &hash, CNode *pnode);

    // Methods for handling mapBlocksInFlight which is protected.
    void MapBlocksInFlightErase(const uint256 &hash, NodeId nodeid);
    bool MapBlocksInFlightEmpty();
    void MapBlocksInFlightClear();

    void MapNodestateClear()
    {
        LOCK(cs_objDownloader);
        mapRequestManagerNodeState.clear();
    }

    // Methods for handling mapRequestManagerNodeState which is protected.
    void GetBlocksInFlight(std::vector<uint256> &vBlocksInFlight, NodeId nodeid);
    int GetNumBlocksInFlight(NodeId nodeid);

    // Add entry to the requestmanager nodestate map
    void InitializeNodeState(NodeId nodeid)
    {
        LOCK(cs_objDownloader);
        mapRequestManagerNodeState.emplace(nodeid, CRequestManagerNodeState());
    }

    // Remove a request manager node from the nodestate map.
    void RemoveNodeState(NodeId nodeid);

    // Check for block download timeout and disconnect node if necessary.
    void DisconnectOnDownloadTimeout(CNode *pnode, const Consensus::Params &consensusParams, int64_t nNow);
};


extern CRequestManager requester; // Singleton class

#endif
