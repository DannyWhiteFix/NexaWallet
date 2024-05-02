// Copyright (c) 2016-2023 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "requestManager.h"
#include "blockrelay/blockrelay_common.h"
#include "blockrelay/compactblock.h"
#include "blockrelay/graphene.h"
#include "blockrelay/mempool_sync.h"
#include "blockrelay/thinblock.h"
#include "chain.h"
#include "chainparams.h"
#include "consensus/consensus.h"
#include "consensus/params.h"
#include "consensus/validation.h"
#include "dosman.h"
#include "extversionkeys.h"
#include "leakybucket.h"
#include "main.h"
#include "net.h"
#include "nodestate.h"
#include "primitives/block.h"
#include "rpc/server.h"
#include "stat.h"
#include "tinyformat.h"
#include "txmempool.h"
#include "txorphanpool.h"
#include "unlimited.h"
#include "util.h"
#include "utilstrencodings.h"
#include "utiltime.h"
#include "validation/validation.h"
#include "validationinterface.h"
#include "version.h"
#include <boost/accumulators/accumulators.hpp>
#include <boost/accumulators/statistics/mean.hpp>
#include <boost/accumulators/statistics/stats.hpp>
#include <boost/accumulators/statistics/variance.hpp>
#include <boost/lexical_cast.hpp>
#include <inttypes.h>
#include <thread>


using namespace std;

extern CTweak<unsigned int> maxBlocksInTransitPerPeer;
extern CTweak<unsigned int> blockDownloadWindow;
extern CTweak<unsigned int> blockLookAheadInterval;
extern CTweak<unsigned int> blkRetryInterval;
extern CTweak<unsigned int> txRetryInterval;

// Request management
extern CRequestManager requester;

// Any ping < 25 ms is good
unsigned int ACCEPTABLE_PING_USEC = 25 * 1000;

// defined in main.cpp.  should be moved into a utilities file but want to make rebasing easier
extern bool CanDirectFetch(const Consensus::Params &consensusParams);


static bool IsBlockType(const CInv &obj)
{
    return ((obj.type == MSG_BLOCK) || (obj.type == MSG_CMPCT_BLOCK) || (obj.type == MSG_XTHINBLOCK) ||
            (obj.type == MSG_GRAPHENEBLOCK));
}

// Constructor for CRequestManagerNodeState struct
CRequestManagerNodeState::CRequestManagerNodeState()
{
    nDownloadingFromPeerSince = 0;
    nBlocksInFlight = 0;
    nNumRequests = 0;
    nLastRequest = 0;
}

CRequestManager::CRequestManager()
    : inFlightTxns("reqMgr/inFlight", STAT_OP_MAX), receivedTxns("reqMgr/received"), rejectedTxns("reqMgr/rejected"),
      droppedTxns("reqMgr/dropped", STAT_KEEP), pendingTxns("reqMgr/pending", STAT_KEEP)
{
    nOutbound = 0;
}

void CRequestManager::Cleanup()
{
    LOCK(cs_objDownloader);
    MapBlocksInFlightClear();
    OdMap::iterator i = mapTxnInfo.begin();
    while (i != mapTxnInfo.end())
    {
        auto prev = i;
        ++i;
        cleanup(prev); // cleanup erases which is why I need to advance the iterator first
    }

    i = mapBlkInfo.begin();
    while (i != mapBlkInfo.end())
    {
        auto prev = i;
        ++i;
        cleanup(prev); // cleanup erases which is why I need to advance the iterator first
    }
}

void CRequestManager::cleanup(OdMap::iterator &itemIt)
{
    CUnknownObj &item = itemIt->second;
    // Because we'll ignore anything deleted from the map, reduce the # of requests in flight by every request we made
    // for this object
    pendingTxns -= 1;

    if (item.obj.type == MSG_TX)
    {
        LOCK(cs_deleteTxn);
        setDeleter.insert(itemIt->first);
    }
    else
    {
        LOCK(cs_deleteBlock);
        setBlockDeleter.insert(itemIt->first);
    }
}

void CRequestManager::cleanup(const CInv &inv)
{
    pendingTxns -= 1;

    if (inv.type == MSG_TX)
    {
        LOCK(cs_deleteTxn);
        setDeleter.insert(inv.hash);
    }
    else
    {
        LOCK(cs_deleteBlock);
        setBlockDeleter.insert(inv.hash);
    }
}


// Get this object from somewhere, asynchronously.
void CRequestManager::AskFor(const CInv &obj, CNode *from, unsigned int priority)
{
    // LOG(REQ, "ReqMgr: Ask for %s.\n", obj.ToString().c_str());

    CNodeRef noderef(from);
    if (obj.type == MSG_TX)
    {
        // Limit the  number of times we update this value so we don't have to take the lock
        // in the mempool so often. Doing this just a few times a second is ample accuracy.
        int64_t nNow = GetTimeMillis();
        int64_t nLastCheck = nLastCheckForTPS.load();
        if (nNow - nLastCheck > 250)
        {
            if (nLastCheckForTPS.compare_exchange_strong(nLastCheck, nNow))
            {
                nApproximateTxnPerSec.store(mempool.GetInstantaneousTxPerSec());
            }
        }

        // Don't allow the in flight requests to grow unbounded.
        if (mapTxnInfo.size() > std::max(MAX_IN_FLIGHT_REQS, (nApproximateTxnPerSec * 10)))
        {
            LOG(REQ, "Tx request buffer full: Dropping request for %s", obj.hash.ToString());
            return;
        }

        LOCK(cs_addTxn);
        std::pair<OdMap::iterator, bool> result = mapTxnToAdd.emplace(obj.hash, CUnknownObj());
        OdMap::iterator &item = result.first;
        CUnknownObj &data = item->second;
        data.obj = obj;

        // Adjust the priority
        data.priority = std::max(priority, data.priority);

        // Then add another source.  A new souce would be added even
        // if this object already existed in mapTxnToAdd.  This could happen
        // if multiple invs were received before the transaction
        // was actually requested.
        data.AddSource(noderef, obj);

        if (result.second) // inserted new
        {
            pendingTxns += 1;
        }
    }
    else if (IsBlockType(obj))
    {
        // Don't allow the in flight requests to grow unbounded.
        if (mapBlkInfo.size() > DEFAULT_BLOCK_DOWNLOAD_WINDOW * 2)
        {
            LOG(REQ, "Block request buffer full: Dropping request for %s", obj.hash.ToString());
            return;
        }

        LOCK(cs_addBlock);
        std::pair<OdMap::iterator, bool> result = mapBlkToAdd.emplace(obj.hash, CUnknownObj());
        OdMap::iterator &item = result.first;
        CUnknownObj &data = item->second;
        data.obj = obj;

        // Adjust the priority
        data.priority = std::max(priority, data.priority);

        // Then add another source.  A new souce would be added even
        // if this object already existed in mapBlkToAdd.  This could happen
        // if multiple invs were received before the transaction
        // was actually requested.
        if (data.AddSource(noderef, obj))
        {
            // LOG(BLK, "%s available at %s\n", obj.ToString().c_str(), from->addrName.c_str());
        }

        if (result.second) // inserted new
        {
            nBlocksAskedFor++;
            data.nEntryTime = GetStopwatchMicros() + nBlocksAskedFor;
        }
    }
    else
    {
        DbgAssert(!"Request manager does not handle objects of this type", return);
    }
}

// Get these objects from somewhere, asynchronously.
void CRequestManager::AskFor(const std::vector<CInv> &objArray, CNode *from, unsigned int priority)
{
    for (auto &inv : objArray)
    {
        AskFor(inv, from, priority);
    }
}

void CRequestManager::AskForDuringIBD(const std::vector<CInv> &objArray, CNode *from, unsigned int priority)
{
    // This is block and peer that was selected in FindNextBlocksToDownload() so we want to add it as a block
    // source first so that it gets requested first.
    if (from)
        AskFor(objArray, from, priority);

    // We can't hold cs_vNodes in the for loop below because it is out of order with cs_objDownloader which is
    // taken in ProcessBlockAvailability.  We can't take cs_objDownloader earlier because it deadlocks with the
    // CNodeStateAccessor. So make a copy of vNodes here
    std::vector<CNode *> vNodesCopy;

    {
        LOCK(cs_vNodes);
        vNodesCopy = vNodes;
        for (CNode *pnode : vNodesCopy)
        {
            pnode->AddRef();
        }
    }


    // Add the other peers as potential sources in the event the RequestManager needs to make a re-request
    // for this block. Only add NETWORK nodes that have block availability.
    for (CNode *pnode : vNodesCopy)
    {
        // skip the peer we added above and skip non NETWORK nodes
        if ((pnode == from) || (pnode->fClient))
        {
            pnode->Release();
            continue;
        }

        // Make sure pindexBestKnownBlock is up to date.
        ProcessBlockAvailability(pnode->id);

        // check block availability for this peer and only askfor a block if it is available.
        CNodeStateAccessor state(nodestate, pnode->id);
        if (state != nullptr)
        {
            if (state->pindexBestKnownBlock != nullptr &&
                state->pindexBestKnownBlock->chainWork() > chainActive.Tip()->chainWork())
            {
                AskFor(objArray, pnode, priority);
            }
        }
        pnode->Release(); // Release the refs we took
    }
}

bool CRequestManager::AlreadyAskedForBlock(const uint256 &hash)
{
    LOCK(cs_objDownloader);
    OdMap::iterator item = mapBlkInfo.find(hash);
    if (item != mapBlkInfo.end())
        return true;

    return false;
}

void CRequestManager::UpdateTxnResponseTime(const CInv &obj, CNode *pfrom)
{
    int64_t now = GetStopwatchMicros();
    LOCK(cs_objDownloader);
    if (pfrom && obj.type == MSG_TX)
    {
        OdMap::iterator item = mapTxnInfo.find(obj.hash);
        if (item == mapTxnInfo.end())
            return;

        pfrom->txReqLatency << (now - item->second.lastRequestTime);
        receivedTxns += 1;
    }
}

void CRequestManager::ProcessingBlock(const uint256 &hash, CNode *pfrom)
{
    LOCK(cs_objDownloader);
    OdMap::iterator item = mapBlkInfo.find(hash);
    if (item == mapBlkInfo.end())
        return;

    item->second.fProcessing = true;
    LOG(BLK, "ReqMgr: Processing %s (received from %s).\n", item->second.obj.ToString(),
        pfrom ? pfrom->GetLogName() : "unknown");
}
// This block has failed to be accepted so in case this is some sort of attack block
// we need to set the fProcessing flag back to false.
//
// We don't have to remove the source because it would have already been removed if/when we
// requested the block and if this was an unsolicited block or attack block then the source
// would never have been added to the request manager.
void CRequestManager::BlockRejected(const CInv &obj, CNode *pfrom)
{
    LOCK(cs_objDownloader);
    OdMap::iterator item = mapBlkInfo.find(obj.hash);
    if (item == mapBlkInfo.end())
        return;
    item->second.fProcessing = false;
}

void CRequestManager::Downloading(const uint256 &hash, CNode *pfrom, unsigned int nSize)
{
    LOCK(cs_objDownloader);
    OdMap::iterator item = mapBlkInfo.find(hash);
    if (item == mapBlkInfo.end())
        return;

    item->second.nDownloadingSince = GetStopwatchMicros() + (nSize * 5);
    LOG(BLK, "ReqMgr: Downloading %s (received from %s).\n", item->second.obj.ToString(),
        pfrom ? pfrom->GetLogName() : "unknown");
}

// Indicate that we got this object.
void CRequestManager::Received(const CInv &obj, CNode *pfrom)
{
    if (obj.type == MSG_TX)
    {
        LOG(REQ, "ReqMgr: TX received: %s.\n", obj.hash.ToString().c_str());
        cleanup(obj);
    }
    else if (IsBlockType(obj))
    {
        LOG(REQ, "ReqMgr: Block received: %s.\n", obj.hash.ToString().c_str());
        cleanup(obj);
    }
}

// Indicate that we got this object.
void CRequestManager::AlreadyReceived(CNode *pnode, const CInv &obj)
{
    LOCK(cs_objDownloader);
    OdMap::iterator item = mapTxnInfo.find(obj.hash);
    if (item == mapTxnInfo.end())
    {
        item = mapBlkInfo.find(obj.hash);
        if (item == mapBlkInfo.end())
            return; // Not in any map
    }
    LOG(REQ, "ReqMgr: Already received %s.  Removing request.\n", item->second.obj.ToString().c_str());

    // If we have it already make sure to mark it as received here or we'll end up disconnecting this
    // peer later when we think this block download attempt has timed out.
    MarkBlockAsReceived(obj.hash, pnode);

    cleanup(item); // remove the item
}

// Indicate that we got this object, from and bytes are optional (for node performance tracking)
void CRequestManager::Rejected(const CInv &obj, CNode *from, unsigned char reason)
{
    LOCK(cs_objDownloader);
    OdMap::iterator item;
    if (obj.type == MSG_TX)
    {
        item = mapTxnInfo.find(obj.hash);
        if (item == mapTxnInfo.end())
        {
            LOG(REQ, "ReqMgr: Item already removed. Unknown txn rejected %s\n", obj.ToString().c_str());
            return;
        }
        if (item->second.outstandingReqs)
            item->second.outstandingReqs--;

        rejectedTxns += 1;
    }
    else if (IsBlockType(obj))
    {
        item = mapBlkInfo.find(obj.hash);
        if (item == mapBlkInfo.end())
        {
            LOG(REQ, "ReqMgr: Item already removed. Unknown block rejected %s\n", obj.ToString().c_str());
            return;
        }
        if (item->second.outstandingReqs)
            item->second.outstandingReqs--;
    }

    if (reason == REJECT_MALFORMED)
    {
    }
    else if (reason == REJECT_INVALID)
    {
    }
    else if (reason == REJECT_OBSOLETE)
    {
    }
    else if (reason == REJECT_CHECKPOINT)
    {
    }
    else if (reason == REJECT_INSUFFICIENTFEE)
    {
        item->second.rateLimited = true;
    }
    else if (reason == REJECT_DUPLICATE)
    {
        // TODO figure out why this might happen.
    }
    else if (reason == REJECT_NONSTANDARD)
    {
        // Not going to be in any memory pools... does the TX request also look in blocks?
        // TODO remove from request manager (and mark never receivable?)
        // TODO verify that the TX request command also looks in blocks?
    }
    else if (reason == REJECT_DUST)
    {
    }
    else
    {
        LOG(REQ, "ReqMgr: Unknown TX rejection code [0x%x].\n", reason);
        // assert(0); // TODO
    }
}

CNodeRequestData::CNodeRequestData(CNodeRef n)
{
    noderef = n;
    requestCount = 0;
    desirability = 0;

    const int MaxLatency = 10 * 1000 * 1000; // After 10 seconds latency I don't care

    // Calculate how much we like this node:

    // Prefer thin block nodes over low latency ones when the chain is syncd
    if (noderef.get()->ThinBlockCapable() && IsChainNearlySyncd())
    {
        desirability = MaxLatency;
    }
    else
    {
        desirability = MaxLatency / 2;
    }

    // The bigger the transaction latency (in microseconds), the less we want to request from this node
    int latency = noderef.get()->txReqLatency.GetTotalTyped();

    // data has never been requested from this node.  Should we encourage investigation into whether this node is fast,
    // or stick with nodes that we do have data on?
    if (latency == 0)
    {
        latency = 80 * 1000; // assign it a reasonably average latency (80ms) for sorting purposes
    }

    // if latency is very high then make this peer less desirable
    if (latency > MaxLatency)
        latency = MaxLatency;

    // The longer a request takes then the lower it's desirability
    desirability -= latency;

    // If the node had been the cause of a re-request (didn't return a requested object in time)
    // then give it a lower priority.
    uint64_t nReRequests = noderef.get()->nReRequests;
    if (nReRequests > 0)
        desirability = desirability / nReRequests;

    // If the peer has misbehaved recently then make it the least desirable
    if (noderef.get()->nMisbehavior > 0 || desirability < 0)
        desirability = 0;
}

// requires cs_objDownloader
bool CUnknownObj::AddSource(CNodeRef &noderef, const CInv &_obj)
{
    // node is not in the request list
    if (std::find_if(availableFrom.begin(), availableFrom.end(), MatchCNodeRequestData(noderef)) == availableFrom.end())
    {
        LOG(REQ, "AddSource %s is available at %s.\n", _obj.ToString(), noderef.get()->GetLogName());

        bool fAdded = false;
        CNodeRequestData req(noderef);
        for (ObjectSourceList::iterator i = availableFrom.begin(); i != availableFrom.end(); ++i)
        {
            // Place the source in a position desirability in descending order such that the most
            // desirable sources will get requested first.
            if (i->desirability < req.desirability)
            {
                availableFrom.emplace(i, req);
                fAdded = true;
                break;
            }
        }
        if (!fAdded)
        {
            availableFrom.push_back(req);
            if (_obj.type == MSG_TX && availableFrom.size() > MAX_SOURCES_TO_ADD)
                fAdded = false;
            else
                fAdded = true;
        }

        // It's rare to get a re-request so for transactions we limit the number of sources so we
        // don't constantly add them when we have many peers connected.  Sine the items in the list
        // are ordered by most desirable to least desirable then just trim the last item in the list.
        if (_obj.type == MSG_TX)
        {
            if (availableFrom.size() > MAX_SOURCES_TO_ADD)
            {
                // Trim the list so that we have just highest priority items remaining
                availableFrom.pop_back();
                LOG(REQ, "Trimmed a source for txn request %s\n", _obj.ToString());
            }
        }

        if (fAdded)
            return true;
    }
    return false;
}

void CRequestManager::RequestCorruptedBlock(const uint256 &blockHash)
{
    // set it to MSG_BLOCK here but it should get overwritten in RequestBlock
    CInv obj(MSG_BLOCK, blockHash);
    std::vector<CInv> vGetBlocks;
    vGetBlocks.push_back(obj);
    AskForDuringIBD(vGetBlocks, nullptr);
}

static bool IsGrapheneVersionSupported(CNode *pfrom)
{
    try
    {
        NegotiateGrapheneVersion(pfrom);
        return true;
    }
    catch (const std::runtime_error &error)
    {
        return false;
    }
}

bool CRequestManager::RequestBlock(CNode *pfrom, CInv &obj)
{
    const uint256 &hash = obj.hash;
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);

    if (IsChainNearlySyncd() && (!thinrelay.HasBlockRelayTimerExpired(hash) || !thinrelay.IsBlockRelayTimerEnabled()))
    {
        // Ask for Graphene blocks
        // Must download a graphene block from a graphene enabled peer.
        if (IsGrapheneBlockEnabled() && pfrom->GrapheneCapable() && IsGrapheneVersionSupported(pfrom))
        {
            if (thinrelay.AddBlockInFlight(pfrom, hash, NetMsgType::GRAPHENEBLOCK))
            {
                MarkBlockAsInFlight(pfrom->GetId(), hash);

                // Instead of building a bloom filter here as we would for an xthin, we actually
                // just need to fill in CMempoolInfo
                CMemPoolInfo receiverMemPoolInfo = GetGrapheneMempoolInfo();

                if (pfrom->fPeerWantsINV2)
                {
                    CInv2 invType2(MSG_GRAPHENEBLOCK, hash);
                    ss << invType2;
                }
                else
                {
                    CInv inv(MSG_GRAPHENEBLOCK, hash);
                    ss << inv;
                }
                ss << receiverMemPoolInfo;
                graphenedata.UpdateOutBoundMemPoolInfo(
                    ::GetSerializeSize(receiverMemPoolInfo, SER_NETWORK, PROTOCOL_VERSION));

                pfrom->PushMessageWithCookie(NetMsgType::GET_GRAPHENE, getCookie(), ss);
                LOG(GRAPHENE, "Requesting graphene block %s from peer %s\n", hash.ToString(), pfrom->GetLogName());
                return true;
            }
        }


        // Ask for an xthin if Graphene is not possible.
        // Must download an xthinblock from a xthin peer.
        if (IsThinBlocksEnabled() && pfrom->ThinBlockCapable())
        {
            if (thinrelay.AddBlockInFlight(pfrom, hash, NetMsgType::XTHINBLOCK))
            {
                MarkBlockAsInFlight(pfrom->GetId(), hash);

                CBloomFilter filterMemPool;
                std::vector<uint256> vOrphanHashes;
                {
                    READLOCK(orphanpool.cs_orphanpool);
                    for (auto &mi : orphanpool.mapOrphanTransactions)
                        vOrphanHashes.emplace_back(mi.first);
                }
                BuildSeededBloomFilter(filterMemPool, vOrphanHashes, hash, pfrom);
                if (pfrom->fPeerWantsINV2)
                {
                    CInv2 invType2(MSG_XTHINBLOCK, hash);
                    ss << invType2;
                }
                else
                {
                    CInv inv(MSG_XTHINBLOCK, hash);
                    ss << inv;
                }
                ss << filterMemPool;

                pfrom->PushMessageWithCookie(NetMsgType::GET_XTHIN, getCookie(), ss);
                LOG(THIN, "Requesting xthinblock %s from peer %s\n", hash.ToString(), pfrom->GetLogName());
                return true;
            }
        }

        // Ask for a compact block if Graphene or xthin is not possible.
        // Must download an xthinblock from a xthin peer.
        if (IsCompactBlocksEnabled() && pfrom->CompactBlockCapable())
        {
            if (thinrelay.AddBlockInFlight(pfrom, hash, NetMsgType::CMPCTBLOCK))
            {
                MarkBlockAsInFlight(pfrom->GetId(), hash);

                if (pfrom->fPeerWantsINV2)
                {
                    std::vector<CInv2> vGetData;
                    CInv2 invType2(MSG_CMPCT_BLOCK, hash);
                    vGetData.push_back(invType2);
                    pfrom->PushMessageWithCookie(NetMsgType::GETDATA, getCookie(), vGetData);
                    LOG(CMPCT, "Requesting compact block %s from peer %s\n", hash.ToString(), pfrom->GetLogName());
                }
                else
                {
                    std::vector<CInv> vGetData;
                    CInv inv(MSG_CMPCT_BLOCK, hash);
                    vGetData.push_back(inv);
                    pfrom->PushMessageWithCookie(NetMsgType::GETDATA, getCookie(), vGetData);
                    LOG(CMPCT, "Requesting compact block %s from peer %s\n", hash.ToString(), pfrom->GetLogName());
                }
                return true;
            }
        }
    }

    // Request a full block if the BlockRelayTimer has expired.
    if (!IsChainNearlySyncd() || thinrelay.HasBlockRelayTimerExpired(hash) || !thinrelay.IsBlockRelayTimerEnabled())
    {
        if (pfrom->fPeerWantsINV2)
        {
            std::vector<CInv2> vToFetch;
            CInv2 invType2(MSG_BLOCK, hash);
            vToFetch.push_back(invType2);

            MarkBlockAsInFlight(pfrom->GetId(), hash);
            pfrom->PushMessageWithCookie(NetMsgType::GETDATA, getCookie(), vToFetch);
            LOG(THIN | GRAPHENE | CMPCT, "Requesting Regular Block %s from peer %s\n", hash.ToString(),
                pfrom->GetLogName());
        }
        else
        {
            std::vector<CInv> vToFetch;
            CInv inv(MSG_BLOCK, hash);
            vToFetch.push_back(inv);

            MarkBlockAsInFlight(pfrom->GetId(), hash);
            pfrom->PushMessageWithCookie(NetMsgType::GETDATA, getCookie(), vToFetch);
            LOG(THIN | GRAPHENE | CMPCT, "Requesting Regular Block %s from peer %s\n", hash.ToString(),
                pfrom->GetLogName());
        }
        return true;
    }
    return false; // no block was requested
}

void CRequestManager::ResetLastBlockRequestTime(const uint256 &hash)
{
    LOCK(cs_objDownloader);
    OdMap::iterator itemIter = mapBlkInfo.find(hash);
    if (itemIter != mapBlkInfo.end())
    {
        CUnknownObj &item = itemIter->second;
        item.outstandingReqs--;
        item.lastRequestTime = 0;
        item.nDownloadingSince = 0;
    }
}

struct CompareIteratorByNodeRef
{
    bool operator()(const CNodeRef &a, const CNodeRef &b) const { return a.get() < b.get(); }
};

// requires cs_objDownloader
void CRequestManager::RunBlockDeleter(OdMap &maybeToSend)
{
    std::set<uint256> setTemp;
    {
        LOCK(cs_deleteBlock);
        std::swap(setTemp, setBlockDeleter);
    }
    for (const uint256 &hash : setTemp)
    {
        maybeToSend.erase(hash);
        mapBlkInfo.erase(hash);
    }
}


// requires cs_objDownloader
void CRequestManager::GetBlockRequests(OdMap &mapTemp)
{
    LOCK(cs_addBlock);
    std::swap(mapTemp, mapBlkToAdd);
}

// requires cs_objDownloader
void CRequestManager::AddNewBlockRequests(OdMap &mapTemp) { mapBlkInfo.merge(mapTemp); }

// requires cs_objDownloader
void CRequestManager::RunTxnDeleter(OdMap &maybeToSend)
{
    std::set<uint256> setTemp;
    {
        LOCK(cs_deleteTxn);
        std::swap(setTemp, setDeleter);
    }
    for (const uint256 &hash : setTemp)
    {
        maybeToSend.erase(hash);
        mapTxnInfo.erase(hash);
    }
}

// requires cs_objDownloader
void CRequestManager::GetTxnRequests(OdMap &mapTemp)
{
    LOCK(cs_addTxn);
    std::swap(mapTemp, mapTxnToAdd);
}

// requires cs_objDownloader
void CRequestManager::AddNewTxnRequests(OdMap &mapTemp) { mapTxnInfo.merge(mapTemp); }
void CRequestManager::SendRequests()
{
    int64_t now = 0;

    // TODO: if a node goes offline, rerequest txns from someone else and cleanup references right away
    LOCK(cs_objDownloader);

    // Modify retry interval. If we're doing IBD or if Traffic Shaping is ON we want to have a longer interval because
    // those blocks and txns can take much longer to download.
    unsigned int _blkReqRetryInterval = blkRetryInterval.Value();
    unsigned int _txReqRetryInterval = txRetryInterval.Value();
    if (IsTrafficShapingEnabled())
    {
        _blkReqRetryInterval *= 6;
        _txReqRetryInterval *= (12 * 2);
    }
    else if ((!IsChainNearlySyncd() && Params().NetworkIDString() != "regtest"))
    {
        _blkReqRetryInterval *= 2;
        _txReqRetryInterval *= 8;
    }

    // When we are still doing an initial sync we want to batch request the blocks instead of just
    // asking for one at time. We can do this because there will be no XTHIN requests possible during
    // this time.
    bool fBatchBlockRequests = IsInitialBlockDownload();
    std::map<CNodeRef, std::map<int64_t, CInv, std::less<int64_t> >, CompareIteratorByNodeRef> mapBatchBlockRequests;
    std::map<CNodeRef, std::map<int64_t, CInv2, std::less<int64_t> >, CompareIteratorByNodeRef>
        mapBatchBlockRequestsInv2;

    // Get new block requests
    OdMap mapTempBlk;
    GetBlockRequests(mapTempBlk);

    // Remove blocks slated for deletion
    RunBlockDeleter(mapTempBlk);

    // Take any remaining new requests and then check if they have already been
    // requested or not.  If they have already been requested then just add them as a new
    // source in mapBlkInfo and remove them from mapTemp;
    CheckIfNewSource(mapTempBlk, mapBlkInfo);

    // Add new block requests to be processed
    AddNewBlockRequests(mapTempBlk);

    // Get Blocks
    OdMap::iterator sendBlkIter = mapBlkInfo.begin();
    while (sendBlkIter != mapBlkInfo.end())
    {
        if (shutdown_threads.load() == true)
        {
            return;
        }

        now = GetStopwatchMicros();
        OdMap::iterator itemIter = sendBlkIter;
        if (itemIter == mapBlkInfo.end())
            break;

        ++sendBlkIter; // move it forward up here in case we need to erase the item we are working with.
        CUnknownObj &item = itemIter->second;

        // If we've already downloaded the block and it's processing then return here so we don't
        // end up re-requesting it again.
        if (item.fProcessing)
            continue;

        // if never requested then lastRequestTime==0 so this will always be true
        if ((now - item.lastRequestTime > _blkReqRetryInterval && item.nDownloadingSince == 0) ||
            (item.nDownloadingSince != 0 && now - item.nDownloadingSince > blockLookAheadInterval.Value()))
        {
            if (!item.availableFrom.empty())
            {
                CNodeRequestData next;
                // Go thru the availableFrom list, looking for the first node that isn't disconnected
                while (!item.availableFrom.empty() && (next.noderef.get() == nullptr))
                {
                    next = item.availableFrom.front(); // Grab the next location where we can find this object.
                    item.availableFrom.pop_front();
                    if (next.noderef.get() != nullptr)
                    {
                        // Do not request from this node if it was disconnected
                        if (next.noderef.get()->fDisconnect || next.noderef.get()->fDisconnectRequest)
                        {
                            continue;
                        }
                        // Do not request or re-request another block from a peer for which we are currently downloading
                        // a block and are beyond the download limit.
                        else if (next.noderef.get()->fDownloading && item.nDownloadingSince != 0 &&
                                 now - item.nDownloadingSince > blockLookAheadInterval.Value())
                        {
                            continue;
                        }
                    }
                }

                if (next.noderef.get() != nullptr)
                {
                    // If item.lastRequestTime is true then we've requested at least once and we'll try a re-request
                    if (item.lastRequestTime)
                    {
                        LOG(REQ, "Block took longer than %6.2f secs. Request timeout for %s.  Retrying\n",
                            ((double)(now - item.lastRequestTime) / 1000000), item.obj.ToString());

                        if (item.prevRequestNode.get() != nullptr)
                            item.prevRequestNode.get()->nReRequests++;
                    }

                    CInv obj = item.obj;
                    item.outstandingReqs++;
                    int64_t then = item.lastRequestTime;
                    item.prevRequestNode = next.noderef;

                    int64_t nDownloadingSincePrev = item.nDownloadingSince;
                    {
                        std::map<NodeId, CRequestManagerNodeState>::iterator it =
                            mapRequestManagerNodeState.find(next.noderef.get()->GetId());
                        if (it == mapRequestManagerNodeState.end())
                        {
                            if (next.noderef.get()->fPeerWantsINV2)
                                mapBatchBlockRequestsInv2.erase(next.noderef);
                            else
                                mapBatchBlockRequests.erase(next.noderef);
                            continue;
                        }
                        CRequestManagerNodeState *state = &it->second;

                        LOCK(next.noderef.get()->cs_nAvgBlkResponseTime);
                        item.lastRequestTime =
                            now + (next.noderef.get()->nAvgBlkResponseTime * 1000000 * 5 * state->nBlocksInFlight);
                    }
                    item.nDownloadingSince = 0;
                    bool fReqBlkResult = false;

                    if (fBatchBlockRequests)
                    {
                        if (next.noderef.get()->fPeerWantsINV2)
                            mapBatchBlockRequestsInv2[next.noderef].emplace(item.nEntryTime, CInv2(obj.type, obj.hash));
                        else
                            mapBatchBlockRequests[next.noderef].emplace(item.nEntryTime, obj);
                    }
                    else
                    {
                        fReqBlkResult = RequestBlock(next.noderef.get(), obj);

                        if (!fReqBlkResult)
                        {
                            // having released cs_objDownloader, item and itemiter may be invalid.
                            // So in the rare case that we could not request the block we need to
                            // find the item again (if it exists) and set the tracking back to what it was
                            itemIter = mapBlkInfo.find(obj.hash);
                            if (itemIter != mapBlkInfo.end())
                            {
                                item = itemIter->second;
                                item.outstandingReqs--;
                                item.lastRequestTime = then;
                                item.nDownloadingSince = nDownloadingSincePrev;
                            }

                            // We never asked for the block, typically because the graphene block timer hasn't timed out
                            // yet but we only have sources for an xthinblock. When this happens we add the node back to
                            // the end of the list so that we don't lose the source, when/if the graphene timer has
                            // a time out and we are then ready to ask for an xthinblock.
                            item.availableFrom.push_back(next);
                        }
                    }
                }
                else
                {
                    // We requested from all available sources so remove the source. This should not
                    // happen and would indicate some other problem.
                    LOG(REQ, "Block %s has no sources. Removing\n", item.obj.ToString());
                    cleanup(itemIter);
                }
            }
            else
            {
                // There can be no block sources because a node dropped out.  In this case, nothing can be done so
                // remove the item.
                LOG(REQ, "Block %s has no available sources. Removing\n", item.obj.ToString());
                cleanup(itemIter);
            }
        }
    }
    // send batched requests if any.
    if (fBatchBlockRequests && (!mapBatchBlockRequests.empty() || !mapBatchBlockRequestsInv2.empty()))
    {
        {
            for (auto iter : mapBatchBlockRequests)
            {
                if (shutdown_threads.load() == true)
                {
                    return;
                }

                // iterate through the second map and create the inv message
                std::vector<CInv> vInv;
                for (auto mi : iter.second)
                {
                    const uint256 &hash = mi.second.hash;
                    MarkBlockAsInFlight(iter.first.get()->GetId(), hash);
                    vInv.push_back(mi.second);
                }
                iter.first.get()->PushMessageWithCookie(NetMsgType::GETDATA, getCookie(), vInv);
                LOG(REQ, "Sent batched request with %d blocks to node %s\n", vInv.size(),
                    iter.first.get()->GetLogName());
            }
            for (auto iter : mapBatchBlockRequestsInv2)
            {
                if (shutdown_threads.load() == true)
                {
                    return;
                }

                // iterate through the second map and create the inv message
                std::vector<CInv2> vInv;
                for (auto mi : iter.second)
                {
                    const uint256 &hash = mi.second.hash;
                    MarkBlockAsInFlight(iter.first.get()->GetId(), hash);
                    vInv.push_back(mi.second);
                }
                iter.first.get()->PushMessage(NetMsgType::GETDATA, vInv);
                LOG(REQ, "Sent batched request with %d blocks to node %s\n", vInv.size(),
                    iter.first.get()->GetLogName());
            }
        }

        mapBatchBlockRequests.clear();
        mapBatchBlockRequestsInv2.clear();
    }


    // Get new Transaction requests
    OdMap mapTemp;
    GetTxnRequests(mapTemp);

    // Remove Transactions slated for deletion including
    // any we are going attempting to request. These txns
    // that we would be attmeping to request again would really
    // have been new txn sources but because of our multithreading
    // they would end up becoming new and unwanted requests so we
    // run the deleter first on both the new request map as well
    // as the mapTxnInfo.
    RunTxnDeleter(mapTemp);

    // Take any remaining new requests and then check if they have already been
    // requested or not.  If they have already been requested then just add them as a new
    // source in mapTxnInfo and remove them from mapTemp;
    CheckIfNewSource(mapTemp, mapTxnInfo);

    // Now send the new requests.
    SendTxnRequests(mapTemp);

    // Add the new requests to the re-request map
    AddNewTxnRequests(mapTemp);

    // Make Transaction re-requests if necessary.
    // Check only every second to avoid parsing through this large map too many times.
    static std::atomic<int64_t> nLastSend{GetTimeMillis()};
    if (GetTimeMillis() - nLastSend > 1000)
    {
        nLastSend.store(GetTimeMillis());
        SendTxnRequests(mapTxnInfo);
    }
}

// requires cs_objDownloader
void CRequestManager::CheckIfNewSource(OdMap &mapNewRequests, OdMap &mapOldRequests)
{
    OdMap::iterator iterNew = mapNewRequests.begin();
    while (iterNew != mapNewRequests.end())
    {
        // If the request already has been made and exists in the re-request map
        // then add a source to the re-request map and delete the request from
        // the map of new requests.
        auto iterOld = mapOldRequests.find(iterNew->first);
        if (iterOld != mapOldRequests.end())
        {
            // Add a new source to the re-request map
            for (CNodeRequestData &item : iterNew->second.availableFrom)
            {
                iterOld->second.AddSource(item.noderef, iterNew->second.obj);
            }
            // Remove the the new request
            iterNew = mapNewRequests.erase(iterNew);
        }
        else
        {
            iterNew++;
        }
    }
}

void CRequestManager::SendTxnRequests(OdMap &mapTxns)
{
    int64_t now = 0;

    // Batch any transaction requests when possible. The process of batching and requesting batched transactions
    // is simlilar to batched block requests, however, we don't make the distinction of whether we're in the process
    // of syncing the chain, as we do with block requests.
    std::map<CNodeRef, std::vector<CInv>, CompareIteratorByNodeRef> mapBatchTxnRequests;
    std::map<CNodeRef, std::vector<CInv2>, CompareIteratorByNodeRef> mapBatchTxnRequestsInv2;

    // Modify retry interval. If we're doing IBD or if Traffic Shaping is ON we want to have a longer interval because
    // those blocks and txns can take much longer to download.
    unsigned int _txReqRetryInterval = txRetryInterval.Value();
    if (IsTrafficShapingEnabled())
    {
        _txReqRetryInterval *= (12 * 2);
    }
    else if ((!IsChainNearlySyncd() && Params().NetworkIDString() != "regtest"))
    {
        _txReqRetryInterval *= 8;
    }

    OdMap::iterator sendIter = mapTxns.begin();
    while (sendIter != mapTxns.end())
    {
        if (shutdown_threads.load() == true)
        {
            return;
        }

        now = GetStopwatchMicros();
        OdMap::iterator itemIter = sendIter;
        if (itemIter == mapTxns.end())
            break;

        ++sendIter; // move it forward up here in case we need to erase the item we are working with.
        CUnknownObj &item = itemIter->second;

        // If we've already received the item and it's in processing then skip it here so we don't
        // end up re-requesting it again.
        if (item.fProcessing)
            continue;

        // if never requested then lastRequestTime==0 so this will always be true
        if (now - item.lastRequestTime > _txReqRetryInterval)
        {
            if (!item.rateLimited)
            {
                // If item.lastRequestTime is true then we've requested at least once, so this is a rerequest -> a txn
                // request was dropped.
                if (item.lastRequestTime)
                {
                    LOG(REQ, "Request timeout for %s.  Retrying\n", item.obj.ToString().c_str());
                }

                if (item.availableFrom.empty())
                {
                    // There can be no block sources because a node dropped out.  In this case, nothing can be done so
                    // remove the item.
                    LOG(REQ, "Tx has no sources for %s.  Removing\n", item.obj.ToString().c_str());
                    cleanup(itemIter);
                }
                else // Ok, we have at least one source so request this item.
                {
                    CNodeRequestData next;
                    // Go thru the availableFrom list, looking for the first node that isn't disconnected
                    while (!item.availableFrom.empty() && (next.noderef.get() == nullptr))
                    {
                        next = item.availableFrom.front(); // Grab the next location where we can find this object.
                        item.availableFrom.pop_front();
                        if (next.noderef.get() != nullptr)
                        {
                            // Node was disconnected so we can't request from it
                            if (next.noderef.get()->fDisconnect || next.noderef.get()->fDisconnectRequest)
                            {
                                continue;
                            }
                        }
                    }

                    if (next.noderef.get() != nullptr)
                    {
                        // This commented code skips requesting TX if the node is not synced. The request
                        // manager should not make this decision but rather the caller should not give us the TX.
                        if (1)
                        {
                            // If item.lastRequestTime is true then we've requested at least once, so this is a
                            // rerequest -> a txn request was dropped.
                            if (item.lastRequestTime)
                            {
                                LOG(REQ, "Request timeout for %s.  Retrying\n", item.obj.ToString().c_str());
                                // Not reducing inFlight; it's still outstanding and will be cleaned up when
                                // item is removed from map.
                                // Note we can never be sure its really dropped verses just delayed for a long
                                // time so this is not authoritative.
                                droppedTxns += 1;

                                // if we've requested before then increment the re-request counter for the
                                // previous peer we requested from.
                                if (item.prevRequestNode.get() != nullptr)
                                    item.prevRequestNode.get()->nReRequests++;
                            }

                            item.outstandingReqs++;
                            item.lastRequestTime = now;
                            item.prevRequestNode = next.noderef;

                            if (next.noderef.get()->fPeerWantsINV2)
                            {
                                mapBatchTxnRequestsInv2[next.noderef].emplace_back(CInv2(item.obj.type, item.obj.hash));

                                // If we have 1000 requests for this peer then send them right away.
                                if (mapBatchTxnRequestsInv2[next.noderef].size() >= 1000)
                                {
                                    next.noderef.get()->PushMessageWithCookie(NetMsgType::GETDATA,
                                        (++requestCookie << 16), mapBatchTxnRequestsInv2[next.noderef]);
                                    LOG(REQ, "Sent batched request with %d transactions to node %s\n",
                                        mapBatchTxnRequestsInv2[next.noderef].size(), next.noderef.get()->GetLogName());

                                    mapBatchTxnRequestsInv2.erase(next.noderef);
                                }
                            }
                            else
                            {
                                mapBatchTxnRequests[next.noderef].emplace_back(item.obj);

                                // If we have 1000 requests for this peer then send them right away.
                                if (mapBatchTxnRequests[next.noderef].size() >= 1000)
                                {
                                    next.noderef.get()->PushMessageWithCookie(
                                        NetMsgType::GETDATA, getCookie(), mapBatchTxnRequests[next.noderef]);
                                    LOG(REQ, "Sent batched request with %d transactions to node %s\n",
                                        mapBatchTxnRequests[next.noderef].size(), next.noderef.get()->GetLogName());

                                    mapBatchTxnRequests.erase(next.noderef);
                                }
                            }
                        }
                    }
                    else
                    {
                        // We requested from all available sources so remove the source. This should not
                        // happen and would indicate some other problem.
                        LOG(REQ, "Tx has no sources for %s.  Removing\n", item.obj.ToString().c_str());
                        cleanup(itemIter);
                    }
                }
            }
        }
    }
    // send batched requests if any.
    if (!mapBatchTxnRequests.empty())
    {
        for (auto iter : mapBatchTxnRequests)
        {
            if (shutdown_threads.load() == true)
            {
                return;
            }

            iter.first.get()->PushMessageWithCookie(NetMsgType::GETDATA, getCookie(), iter.second);
            LOG(REQ, "Sent batched request with %d transactions to node %s\n", iter.second.size(),
                iter.first.get()->GetLogName());
        }

        mapBatchTxnRequests.clear();
    }
    if (!mapBatchTxnRequestsInv2.empty())
    {
        for (auto iter : mapBatchTxnRequestsInv2)
        {
            if (shutdown_threads.load() == true)
            {
                return;
            }

            iter.first.get()->PushMessageWithCookie(NetMsgType::GETDATA, (++requestCookie << 16), iter.second);
            LOG(REQ, "Sent batched request with %d transactions to node %s\n", iter.second.size(),
                iter.first.get()->GetLogName());
        }

        mapBatchTxnRequestsInv2.clear();
    }
}

bool CRequestManager::CheckForRequestDOS(CNode *pfrom, const CChainParams &chainparams)
{
    // Check for Misbehaving and DOS
    // If they make more than MAX_THINTYPE_OBJECT_REQUESTS requests in 10 minutes then assign misbehavior points.
    //
    // Other networks have variable mining rates, so only apply these rules to mainnet only.
    if (chainparams.NetworkIDString() == "main")
    {
        LOCK(cs_objDownloader);

        std::map<NodeId, CRequestManagerNodeState>::iterator it = mapRequestManagerNodeState.find(pfrom->GetId());
        DbgAssert(it != mapRequestManagerNodeState.end(), return false);
        CRequestManagerNodeState *state = &it->second;

        // First decay the previous value
        uint64_t nNow = GetTime();
        state->nNumRequests = std::pow(1.0 - 1.0 / 600.0, (double)(nNow - state->nLastRequest));

        // Now add one request and update the time
        state->nNumRequests++;
        state->nLastRequest = nNow;

        if (state->nNumRequests >= MAX_THINTYPE_OBJECT_REQUESTS)
        {
            pfrom->fDisconnect = true;
            return error("Disconnecting  %s. Making too many (%f) thin object requests.", pfrom->GetLogName(),
                state->nNumRequests);
        }
    }
    return true;
}

// Check whether the last unknown block a peer advertised is not yet known.
void CRequestManager::ProcessBlockAvailability(NodeId nodeid)
{
    CNodeStateAccessor state(nodestate, nodeid);
    DbgAssert(state != nullptr, return);

    if (!state->hashLastUnknownBlock.IsNull())
    {
        auto *pindex = LookupBlockIndex(state->hashLastUnknownBlock);
        if (pindex && pindex->chainWork() > 0)
        {
            if (state->pindexBestKnownBlock == nullptr ||
                pindex->chainWork() >= state->pindexBestKnownBlock->chainWork())
            {
                state->pindexBestKnownBlock = pindex;
            }
            state->hashLastUnknownBlock.SetNull();
        }
    }
}

// Update tracking information about which blocks a peer is assumed to have.
void CRequestManager::UpdateBlockAvailability(NodeId nodeid, const uint256 &hash)
{
    auto *pindex = LookupBlockIndex(hash);

    CNodeStateAccessor state(nodestate, nodeid);
    DbgAssert(state != nullptr, return);

    ProcessBlockAvailability(nodeid);

    if (pindex && pindex->chainWork() > 0)
    {
        // An actually better block was announced.
        if (state->pindexBestKnownBlock == nullptr || pindex->chainWork() >= state->pindexBestKnownBlock->chainWork())
        {
            state->pindexBestKnownBlock = pindex;
        }
    }
    else
    {
        // An unknown block was announced; just assume that the latest one is the best one.
        state->hashLastUnknownBlock = hash;
    }
}

void CRequestManager::RequestNextBlocksToDownload(CNode *pto)
{
    uint64_t nBlocksInFlight = 0;
    {
        LOCK(cs_objDownloader);
        nBlocksInFlight = mapRequestManagerNodeState[pto->GetId()].nBlocksInFlight;
    }

    if (!pto->fDisconnectRequest && !pto->fDisconnect && !pto->fClient && nBlocksInFlight < pto->nMaxBlocksInTransit)
    {
        std::vector<CBlockIndex *> vToDownload;

        FindNextBlocksToDownload(pto, pto->nMaxBlocksInTransit.load() - nBlocksInFlight, vToDownload);
        // LOG(REQ, "IBD AskFor %d blocks from peer=%s\n", vToDownload.size(), pto->GetLogName());
        std::vector<CInv> vGetBlocks;
        for (CBlockIndex *pindex : vToDownload)
        {
            CInv inv(MSG_BLOCK, pindex->GetBlockHash());
            if (!AlreadyHaveBlock(inv))
            {
                vGetBlocks.emplace_back(inv);
                // LOG(REQ, "AskFor block %s (%d) peer=%s\n", pindex->GetBlockHash().ToString(),
                //     pindex->height(), pto->GetLogName());
            }
        }
        if (!vGetBlocks.empty())
        {
            std::vector<CInv> vToFetchNew;
            {
                LOCK(cs_objDownloader);
                for (CInv &inv : vGetBlocks)
                {
                    // If this block is already in flight then don't ask for it again during the IBD process.
                    //
                    // If it's an additional source for a new peer then it would have been added already in
                    // FindNextBlocksToDownload().
                    std::map<uint256, std::map<NodeId, std::list<QueuedBlock>::iterator> >::iterator itInFlight =
                        mapBlocksInFlight.find(inv.hash);
                    if (itInFlight != mapBlocksInFlight.end())
                    {
                        continue;
                    }

                    vToFetchNew.push_back(inv);
                }
            }
            vGetBlocks.swap(vToFetchNew);
            if (!IsInitialBlockDownload())
            {
                AskFor(vGetBlocks, pto);
            }
            else
            {
                AskForDuringIBD(vGetBlocks, pto);
            }
        }
    }
}

// Update pindexLastCommonBlock and add not-in-flight missing successors to vBlocks, until it has
// at most count entries.
void CRequestManager::FindNextBlocksToDownload(CNode *node, size_t count, std::vector<CBlockIndex *> &vBlocks)
{
    if (count == 0)
    {
        return;
    }
    DbgAssert(count <= 128, count = 128);

    NodeId nodeid = node->GetId();
    vBlocks.reserve(vBlocks.size() + count);

    // Make sure pindexBestKnownBlock is up to date, we'll need it.
    ProcessBlockAvailability(nodeid);

    CNodeStateAccessor state(nodestate, nodeid);
    DbgAssert(state != nullptr, return);

    if (state->pindexBestKnownBlock == nullptr ||
        state->pindexBestKnownBlock->chainWork() < chainActive.Tip()->chainWork())
    {
        // This peer has nothing interesting.
        return;
    }

    CBlockIndex *tmp = state->pindexLastCommonBlock;
    if (tmp == nullptr)
    {
        // Bootstrap quickly by guessing a parent of our best tip is the forking point.
        // Guessing wrong in either direction is not a problem.
        tmp = chainActive[std::min(state->pindexBestKnownBlock->height(), chainActive.Height())];
        // Extremely unlikely but chainActive can change between when we get the Height and when we index it.
        // Also, a reorg could happen so there is no active block at either height when we try to access it.
        // In this case just punt and start with the tip.
        if (tmp == nullptr)
        {
            tmp = chainActive.Tip();
        }
    }

    // If the peer reorganized, our previous pindexLastCommonBlock may not be an ancestor
    // of its current tip anymore. Go back enough to fix that.
    state->pindexLastCommonBlock = const_cast<CBlockIndex *>(LastCommonAncestor(tmp, state->pindexBestKnownBlock));
    if (state->pindexLastCommonBlock == state->pindexBestKnownBlock)
        return;

    std::vector<CBlockIndex *> vToFetch;
    CBlockIndex *pindexWalk = state->pindexLastCommonBlock;
    // Never fetch further than the current chain tip + the block download window.  We need to ensure
    // the if running in pruning mode we don't download too many blocks ahead and as a result use to
    // much disk space to store unconnected blocks.
    int nWindowEnd = chainActive.Height() + BLOCK_DOWNLOAD_WINDOW.load();

    int nMaxHeight = std::min<int>(state->pindexBestKnownBlock->height(), nWindowEnd + 1);
    while (pindexWalk->height() < nMaxHeight)
    {
        // Read up to 128 (or more, if more blocks than that are needed) successors of pindexWalk (towards
        // pindexBestKnownBlock) into vToFetch. We fetch 128, because CBlockIndex::GetAncestor may be as expensive
        // as iterating over ~100 CBlockIndex* entries anyway.
        int nToFetch = std::min((size_t)(nMaxHeight - pindexWalk->height()), count - vBlocks.size());
        if (nToFetch == 0)
        {
            break;
        }
        vToFetch.resize(nToFetch);
        pindexWalk = state->pindexBestKnownBlock->GetAncestor(pindexWalk->height() + nToFetch);
        vToFetch[nToFetch - 1] = pindexWalk;
        for (unsigned int i = nToFetch - 1; i > 0; i--)
        {
            vToFetch[i - 1] = vToFetch[i]->pprev;
        }

        // Iterate over those blocks in vToFetch (in forward direction), adding the ones that
        // are not yet downloaded and not in flight to vBlocks. In the mean time, update
        // pindexLastCommonBlock as long as all ancestors are already downloaded, or if it's
        // already part of our chain (and therefore don't need it even if pruned).
        for (CBlockIndex *pindex : vToFetch)
        {
            uint256 blockHash = pindex->GetBlockHash();
            if (AlreadyAskedForBlock(blockHash))
            {
                // Only add a new source if there is a block in flight from a different peer. This prevents
                // us from re-adding a source for the same peer and possibly downloading two duplicate blocks.
                // This edge condition can typically happen when we were only connected to only one peer and we
                // exceed the download timeout causing us to re-request the same block from the same peer.
                LOCK(cs_objDownloader);
                std::map<uint256, std::map<NodeId, std::list<QueuedBlock>::iterator> >::iterator itInFlight =
                    mapBlocksInFlight.find(blockHash);
                if (itInFlight != mapBlocksInFlight.end() && !itInFlight->second.count(nodeid))
                {
                    AskFor(CInv(MSG_BLOCK, blockHash), node); // Add another source
                    continue;
                }
            }

            if (!pindex->IsValid(BLOCK_VALID_TREE))
            {
                // We consider the chain that this peer is on invalid.
                return;
            }
            if (pindex->nStatus & BLOCK_HAVE_DATA || chainActive.Contains(pindex))
            {
                if (pindex->IsLinked())
                    state->pindexLastCommonBlock = pindex;
            }
            else
            {
                // Return if we've reached the end of the download window.
                if (pindex->height() > nWindowEnd)
                {
                    return;
                }

                // Return if we've reached the end of the number of blocks we can download for this peer.
                vBlocks.push_back(pindex);
                if (vBlocks.size() == count)
                {
                    return;
                }
            }
        }
    }
}

void CRequestManager::RequestMempoolSync(CNode *pto)
{
    LOCK(cs_mempoolsync);
    NodeId nodeId = pto->GetId();

    if ((mempoolSyncRequested.count(nodeId) == 0 ||
            ((GetStopwatchMicros() - mempoolSyncRequested[nodeId].lastUpdated) > MEMPOOLSYNC_FREQ_US)) &&
        pto->canSyncMempoolWithPeers)
    {
        // Similar to Graphene, receiver must send CMempoolInfo
        CMempoolSyncInfo receiverMemPoolInfo = GetMempoolSyncInfo();
        mempoolSyncRequested[nodeId] = CMempoolSyncState(
            GetStopwatchMicros(), receiverMemPoolInfo.shorttxidk0, receiverMemPoolInfo.shorttxidk1, false);
        if (NegotiateMempoolSyncVersion(pto) > 0)
            pto->PushMessageWithCookie(NetMsgType::GET_MEMPOOLSYNC, getCookie(), receiverMemPoolInfo);
        else
        {
            CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
            ss << receiverMemPoolInfo;
            pto->PushMessageWithCookie(NetMsgType::GET_MEMPOOLSYNC, getCookie(), ss);
        }
        LOG(MPOOLSYNC, "Requesting mempool synchronization from peer %s\n", pto->GetLogName());

        lastMempoolSync.store(GetStopwatchMicros());
    }
}

// indicate whether we requested this block.
void CRequestManager::MarkBlockAsInFlight(NodeId nodeid, const uint256 &hash)
{
    // If started then clear the timers used for preferential downloading
    thinrelay.ClearBlockRelayTimer(hash);

    // Add to inflight, if it hasn't already been marked inflight for this node id.
    LOCK(cs_objDownloader);
    std::map<uint256, std::map<NodeId, std::list<QueuedBlock>::iterator> >::iterator itInFlight =
        mapBlocksInFlight.find(hash);
    if (itInFlight == mapBlocksInFlight.end() || !itInFlight->second.count(nodeid))
    {
        // Get a request manager nodestate pointer.
        std::map<NodeId, CRequestManagerNodeState>::iterator it = mapRequestManagerNodeState.find(nodeid);
        DbgAssert(it != mapRequestManagerNodeState.end(), return);
        CRequestManagerNodeState *state = &it->second;

        // Add queued block to nodestate and add iterator for queued block to mapBlocksInFlight
        int64_t nNow = GetStopwatchMicros();
        QueuedBlock newentry = {hash, nNow};
        std::list<QueuedBlock>::iterator it2 = state->vBlocksInFlight.emplace(state->vBlocksInFlight.end(), newentry);
        mapBlocksInFlight[hash][nodeid] = it2;

        // Increment blocks in flight for this node and if applicable the time we started downloading.
        state->nBlocksInFlight++;
        if (state->nBlocksInFlight == 1)
        {
            // We're starting a block download (batch) from this peer.
            state->nDownloadingFromPeerSince = GetStopwatchMicros();
        }
    }
}

// Returns a bool if successful in indicating we received this block.
bool CRequestManager::MarkBlockAsReceived(const uint256 &hash, CNode *pnode)
{
    if (!pnode)
        return false;

    LOCK(cs_objDownloader);
    NodeId nodeid = pnode->GetId();

    // Check if we have any block in flight, for this hash, that we asked for.
    std::map<uint256, std::map<NodeId, std::list<QueuedBlock>::iterator> >::iterator itHash =
        mapBlocksInFlight.find(hash);
    if (itHash == mapBlocksInFlight.end())
        return false;

    // Lookup this block for this nodeid and if we have one in flight then mark it as received.
    std::map<NodeId, std::list<QueuedBlock>::iterator>::iterator itInFlight = itHash->second.find(nodeid);
    if (itInFlight != itHash->second.end())
    {
        // Get a request manager nodestate pointer.
        std::map<NodeId, CRequestManagerNodeState>::iterator it = mapRequestManagerNodeState.find(nodeid);
        DbgAssert(it != mapRequestManagerNodeState.end(), return false);
        CRequestManagerNodeState *state = &it->second;

        int64_t getdataTime = itInFlight->second->nTime;
        int64_t now = GetStopwatchMicros();
        double nResponseTime = (double)(now - getdataTime) / 1000000.0;

        // calculate avg block response time over a range of blocks to be used for IBD tuning.
        uint8_t blockRange = 50;
        {
            double nAvgBlkResponseTime = 0.0;
            {
                LOCK(pnode->cs_nAvgBlkResponseTime);
                if (pnode->nAvgBlkResponseTime > 0)
                    pnode->nAvgBlkResponseTime -= (pnode->nAvgBlkResponseTime / blockRange);

                pnode->nAvgBlkResponseTime += nResponseTime / blockRange;
                if (pnode->nAvgBlkResponseTime < 0)
                {
                    pnode->nAvgBlkResponseTime = nResponseTime / blockRange;
                }
                nAvgBlkResponseTime = pnode->nAvgBlkResponseTime;
            }

            // Protect nOverallAverageResponseTime and nIterations with cs_overallaverage.
            static CCriticalSection cs_overallaverage;
            static double nOverallAverageResponseTime = 00.0;
            static uint32_t nIterations = 0;

            // Get the average value for overall average response time (s) of all nodes.
            {
                LOCK(cs_overallaverage);
                uint32_t nOverallRange = blockRange * nMaxOutConnections;
                if (nIterations <= nOverallRange)
                    nIterations++;

                if (nOverallRange > 0)
                {
                    if (nIterations > nOverallRange)
                    {
                        nOverallAverageResponseTime -= (nOverallAverageResponseTime / nOverallRange);
                    }
                    nOverallAverageResponseTime += nResponseTime / nOverallRange;
                    if (nOverallAverageResponseTime < 0)
                    {
                        nOverallAverageResponseTime = nResponseTime / nOverallRange;
                    }
                }
                else
                {
                    LOG(IBD, "Calculation of average response time failed and will be inaccurate due to division by "
                             "zero.\n");
                }

                // Request for a disconnect if over the response time limit.  We don't do an fDisconnect = true here
                // because we want to drain the queue for any blocks that are still returning.  This prevents us from
                // having to re-request all those blocks again.
                //
                // We only check wether to issue a disconnect during initial sync and we only disconnect up to two
                // peers at a time if and only if all our outbound slots have been used to prevent any sudden loss of
                // all peers. We do this for two peers and not one in the event that one of the peers is hung and their
                // block queue does not drain; in that event we would end up waiting for 10 minutes before finally
                // disconnecting.
                //
                // We disconnect a peer only if their average response time is more than 5 times the overall average.
                static int nStartDisconnections GUARDED_BY(cs_overallaverage) = BEGIN_PRUNING_PEERS;
                if (!pnode->fDisconnectRequest &&
                    (nOutbound >= nMaxOutConnections - 1 || nOutbound >= nStartDisconnections) &&
                    IsInitialBlockDownload() && nIterations > nOverallRange &&
                    pnode->nAvgBlkResponseTime > nOverallAverageResponseTime * 5)
                {
                    LOG(IBD, "disconnecting %s because too slow , overall avg %d peer avg %d\n", pnode->GetLogName(),
                        nOverallAverageResponseTime, nAvgBlkResponseTime);
                    pnode->InitiateGracefulDisconnect();
                    // We must not return here but continue in order
                    // to update the vBlocksInFlight stats.

                    // Increment so we start disconnecting at a higher number of peers each time. This
                    // helps to improve the very beginning of IBD such that we don't have to wait for all outbound
                    // connections to be established before we start pruning the slow peers and yet we don't end
                    // up suddenly overpruning.
                    nStartDisconnections = nOutbound;
                    if (nStartDisconnections < nMaxOutConnections)
                        nStartDisconnections++;
                }
            }

            if (nAvgBlkResponseTime < 0.2)
            {
                pnode->nMaxBlocksInTransit.store(64);
            }
            else if (nAvgBlkResponseTime < 0.5)
            {
                pnode->nMaxBlocksInTransit.store(56);
            }
            else if (nAvgBlkResponseTime < 0.9)
            {
                pnode->nMaxBlocksInTransit.store(48);
            }
            else if (nAvgBlkResponseTime < 1.4)
            {
                pnode->nMaxBlocksInTransit.store(32);
            }
            else if (nAvgBlkResponseTime < 2.0)
            {
                pnode->nMaxBlocksInTransit.store(24);
            }
            else if (nAvgBlkResponseTime < 2.7)
            {
                pnode->nMaxBlocksInTransit.store(16);
            }
            else if (nAvgBlkResponseTime < 3.5)
            {
                pnode->nMaxBlocksInTransit.store(8);
            }
            else if (nAvgBlkResponseTime < 4.3)
            {
                pnode->nMaxBlocksInTransit.store(4);
            }
            else if (nAvgBlkResponseTime < 5.3)
            {
                pnode->nMaxBlocksInTransit.store(2);
            }
            else
                pnode->nMaxBlocksInTransit.store(1);


            LOG(THIN | BLK, "Average block response time is %.2f seconds for %s\n", nAvgBlkResponseTime,
                pnode->GetLogName());
        }

        // if there are no blocks in flight then ask for a few more blocks
        if (state->nBlocksInFlight <= 0)
            pnode->nMaxBlocksInTransit.fetch_add(4);

        if (maxBlocksInTransitPerPeer.Value() != 0)
        {
            pnode->nMaxBlocksInTransit.store(maxBlocksInTransitPerPeer.Value());
        }
        if (blockDownloadWindow.Value() != 0)
        {
            BLOCK_DOWNLOAD_WINDOW.store(blockDownloadWindow.Value());
        }
        LOG(THIN | BLK, "BLOCK_DOWNLOAD_WINDOW is %d nMaxBlocksInTransit is %lu\n", BLOCK_DOWNLOAD_WINDOW.load(),
            pnode->nMaxBlocksInTransit.load());

        // Update the appropriate response time based on the type of block received.
        if (IsChainNearlySyncd())
        {
            // Update Thinblock stats
            if (thinrelay.IsBlockInFlight(pnode, NetMsgType::XTHINBLOCK, hash))
            {
                thindata.UpdateResponseTime(nResponseTime);
            }
            // Update Graphene stats
            if (thinrelay.IsBlockInFlight(pnode, NetMsgType::GRAPHENEBLOCK, hash))
            {
                graphenedata.UpdateResponseTime(nResponseTime);
            }
            // Update CompactBlock stats
            if (thinrelay.IsBlockInFlight(pnode, NetMsgType::CMPCTBLOCK, hash))
            {
                compactdata.UpdateResponseTime(nResponseTime);
            }
        }

        if (state->vBlocksInFlight.begin() == itInFlight->second)
        {
            // First block on the queue was received, update the start download time for the next one
            state->nDownloadingFromPeerSince =
                std::max(state->nDownloadingFromPeerSince, (int64_t)GetStopwatchMicros());
        }
        // In order to prevent a dangling iterator we must erase from vBlocksInFlight after mapBlockInFlight
        // however that will invalidate the iterator held by mapBlocksInFlight. Use a temporary to work around this.
        std::list<QueuedBlock>::iterator tmp = itInFlight->second;
        state->nBlocksInFlight--;
        MapBlocksInFlightErase(hash, nodeid);
        state->vBlocksInFlight.erase(tmp);

        return true;
    }
    return false;
}

void CRequestManager::MapBlocksInFlightErase(const uint256 &hash, NodeId nodeid)
{
    // If there are more than one block in flight for the same block hash then we only remove
    // the entry for this particular node, otherwise entirely remove the hash from mapBlocksInFlight.
    LOCK(cs_objDownloader);
    std::map<uint256, std::map<NodeId, std::list<QueuedBlock>::iterator> >::iterator itHash =
        mapBlocksInFlight.find(hash);
    if (itHash != mapBlocksInFlight.end())
    {
        itHash->second.erase(nodeid);

        // Special case which would be triggered during a sudden disconnect of all peers.
        if (itHash->second.empty())
            mapBlocksInFlight.erase(hash);
    }
}

bool CRequestManager::MapBlocksInFlightEmpty()
{
    LOCK(cs_objDownloader);
    return mapBlocksInFlight.empty();
}

void CRequestManager::MapBlocksInFlightClear()
{
    LOCK(cs_objDownloader);
    mapBlocksInFlight.clear();
}

void CRequestManager::GetBlocksInFlight(std::vector<uint256> &vBlocksInFlight, NodeId nodeid)
{
    LOCK(cs_objDownloader);
    for (auto &iter : mapRequestManagerNodeState[nodeid].vBlocksInFlight)
    {
        vBlocksInFlight.emplace_back(iter.hash);
    }
}

int CRequestManager::GetNumBlocksInFlight(NodeId nodeid)
{
    LOCK(cs_objDownloader);
    return mapRequestManagerNodeState[nodeid].nBlocksInFlight;
}

void CRequestManager::RemoveNodeState(NodeId nodeid)
{
    LOCK(cs_objDownloader);
    std::vector<uint256> vBlocksInFlight;
    GetBlocksInFlight(vBlocksInFlight, nodeid);
    for (const uint256 &hash : vBlocksInFlight)
    {
        // Erase mapblocksinflight entries for this node.
        MapBlocksInFlightErase(hash, nodeid);

        // Reset all requests times to zero so that we can immediately re-request these blocks
        ResetLastBlockRequestTime(hash);
    }
    mapRequestManagerNodeState.erase(nodeid);
}

void CRequestManager::DisconnectOnDownloadTimeout(CNode *pnode, const Consensus::Params &consensusParams, int64_t nNow)
{
    // In case there is a block that has been in flight from this peer for 2 + 0.5 * N times the block interval
    // (with N the number of peers from which we're downloading validated blocks), disconnect due to timeout.
    // We compensate for other peers to prevent killing off peers due to our own downstream link
    // being saturated. We only count validated in-flight blocks so peers can't advertise non-existing block hashes
    // to unreasonably increase our timeout.
    LOCK(cs_objDownloader);
    NodeId nodeid = pnode->GetId();
    if (!pnode->fDisconnect && mapRequestManagerNodeState[nodeid].vBlocksInFlight.size() > 0)
    {
        if (nNow >
            mapRequestManagerNodeState[nodeid].nDownloadingFromPeerSince +
                consensusParams.nPowTargetSpacing * (BLOCK_DOWNLOAD_TIMEOUT_BASE + BLOCK_DOWNLOAD_TIMEOUT_PER_PEER))
        {
            LOGA("Timeout downloading block %s from peer %s, disconnecting\n",
                mapRequestManagerNodeState[nodeid].vBlocksInFlight.front().hash.ToString(), pnode->GetLogName());
            pnode->fDisconnect = true;
        }
    }
}
