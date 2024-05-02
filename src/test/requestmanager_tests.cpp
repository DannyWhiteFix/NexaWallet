// Copyright (c) 2016-2022 The Bitcoin Unlimited Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "blockrelay/blockrelay_common.h"
#include "blockrelay/graphene.h"
#include "blockrelay/thinblock.h"
#include "bloom.h"
#include "chainparams.h"
#include "dosman.h"
#include "main.h"
#include "net.h"
#include "primitives/block.h"
#include "protocol.h"
#include "random.h"
#include "requestManager.h"
#include "serialize.h"
#include "streams.h"
#include "txmempool.h"
#include "uint256.h"
#include "unlimited.h"
#include "util.h"
#include "utilstrencodings.h"
#include "validation/validation.h"
#include "version.h"

#include "test/test_nexa.h"

#include <algorithm>
#include <atomic>
#include <boost/test/unit_test.hpp>
#include <sstream>
#include <string>

extern CTweak<uint64_t> grapheneMaxVersionSupported;

class CRequestManagerTest
{
private:
    CRequestManager *_rman;

public:
    CRequestManagerTest(CRequestManager *r) { _rman = r; }
    std::map<uint256, CUnknownObj> GetMapTxnToAdd() { return _rman->mapTxnToAdd; }
    std::map<uint256, CUnknownObj> GetMapBlkToAdd() { return _rman->mapBlkToAdd; }
    std::map<uint256, CUnknownObj> GetMapTxnInfo() { return _rman->mapTxnInfo; }
    std::map<uint256, CUnknownObj> GetMapBlkInfo() { return _rman->mapBlkInfo; }
    std::set<uint256> GetSetDeleter() { return _rman->setDeleter; }
    std::set<uint256> GetSetBlockDeleter() { return _rman->setBlockDeleter; }
};

// Cleanup all maps
static void CleanupAll(std::vector<CNode *> &vPeers)
{
    for (auto pnode : vPeers)
    {
        thinrelay.ClearAllBlocksToReconstruct(pnode->GetId());
        thinrelay.ClearAllBlocksInFlight(pnode->GetId());
        thinrelay.RemovePeers(pnode);

        {
            LOCK(pnode->cs_vSend);
            pnode->vSendMsg.clear();
            pnode->vLowPrioritySendMsg.clear();
        }
    }
    requester.MapBlocksInFlightClear();
}

// Return the netmessage string for a block/xthin/graphene request
static std::string NetMessage(CLockSwapQ<CSerializeData> &_vSendMsg)
{
    if (_vSendMsg.size() == 0)
        return "none";

    CInv inv_result;
    CSerializeData data;
    if (!_vSendMsg.pop_front(data))
    {
        return "none";
    }
    std::string ssData(data.begin(), data.end());
    std::string ss(ssData.begin() + 4, ssData.begin() + 16);

    // Remove whitespace
    ss.erase(std::remove(ss.begin(), ss.end(), '\000'), ss.end());

    // if it's a getdata then we need to find out what type
    if (ss == "getdata")
    {
        CDataStream ssInv(SER_NETWORK, PROTOCOL_VERSION);
        ssInv.insert(ssInv.begin(), ssData.begin() + 25, ssData.begin() + 61);

        CInv inv;
        ssInv >> inv;

        if (inv.type == MSG_BLOCK)
            return "getdata";

        else if (inv.type == MSG_CMPCT_BLOCK)
            return "cmpctblock";
        else
            return "nothing";
    }
    return ss;
}

static void ClearThinBlocksInFlight(CNode &node, CInv &inv) { thinrelay.ClearBlockInFlight(node.GetId(), inv.hash); }
BOOST_FIXTURE_TEST_SUITE(requestmanager_tests, TestingSetup)

BOOST_AUTO_TEST_CASE(blockrequest_tests)
{
    // Test the requesting of blocks/graphenblocks/thinblocks with varying node configurations.
    // This tests all the code paths within RequestBlock() in the request manager.

    // create dummy test addrs
    CAddress addr_xthin(ipaddress(0xa0b0c001, 10000));
    CAddress addr_graphene(ipaddress(0xa0b0c002, 10001));
    CAddress addr_cmpct(ipaddress(0xa0b0c003, 10002));
    CAddress addr_none(ipaddress(0xa0b0c004, 10003));

    // create nodes
    CNode dummyNodeXthin(INVALID_SOCKET, addr_xthin, "", true);
    CNode dummyNodeGraphene(INVALID_SOCKET, addr_graphene, "", true);
    CNode dummyNodeCmpct(INVALID_SOCKET, addr_cmpct, "", true);
    CNode dummyNodeNone(INVALID_SOCKET, addr_none, "", true);
    dummyNodeXthin.nVersion = MIN_PEER_PROTO_VERSION;
    SetConnected(dummyNodeXthin);
    dummyNodeXthin.nServices |= NODE_XTHIN;
    dummyNodeXthin.nServices &= ~NODE_GRAPHENE;
    dummyNodeXthin.fSupportsCompactBlocks = false;
    dummyNodeXthin.id = 1;
    dummyNodeGraphene.nVersion = MIN_PEER_PROTO_VERSION;
    SetConnected(dummyNodeGraphene);
    dummyNodeGraphene.nServices |= NODE_GRAPHENE;
    dummyNodeGraphene.nServices &= ~NODE_XTHIN;
    dummyNodeGraphene.fSupportsCompactBlocks = false;
    dummyNodeGraphene.id = 2;
    // This dummy node does not exchange a simulated extversion so jam in graphene supported version.
    dummyNodeGraphene.negotiatedGrapheneVersion = grapheneMaxVersionSupported.Value();
    dummyNodeCmpct.nVersion = MIN_PEER_PROTO_VERSION;
    SetConnected(dummyNodeCmpct);
    dummyNodeCmpct.nServices &= ~NODE_GRAPHENE;
    dummyNodeCmpct.nServices &= ~NODE_XTHIN;
    dummyNodeCmpct.fSupportsCompactBlocks = true;
    dummyNodeCmpct.id = 3;
    dummyNodeNone.nVersion = MIN_PEER_PROTO_VERSION;
    SetConnected(dummyNodeNone);
    dummyNodeNone.nServices &= ~NODE_GRAPHENE;
    dummyNodeNone.nServices &= ~NODE_XTHIN;
    dummyNodeNone.fSupportsCompactBlocks = false;
    dummyNodeNone.id = 4;

    // Add to vNodes
    vNodes.push_back(&dummyNodeXthin);
    vNodes.push_back(&dummyNodeGraphene);
    vNodes.push_back(&dummyNodeCmpct);
    vNodes.push_back(&dummyNodeNone);

    // Initialize Nodes
    GetNodeSignals().InitializeNode(&dummyNodeXthin);
    GetNodeSignals().InitializeNode(&dummyNodeGraphene);
    GetNodeSignals().InitializeNode(&dummyNodeCmpct);
    GetNodeSignals().InitializeNode(&dummyNodeNone);

    // Create basic Inv for requesting blocks. This simulates an entry in the request manager for a block
    // download.
    uint256 hash = InsecureRand256();
    uint256 randhash = InsecureRand256();
    CInv inv(MSG_BLOCK, hash);
    CInv inv_cmpct(MSG_CMPCT_BLOCK, hash);

    uint64_t nTime = GetTime();
    dosMan.ClearBanned();

    /** Block in flight tests */
    // Try to add the same block twice which will fail the second attempt.
    // We should only be allowed one unique thintype block in flight
    thinrelay.AddBlockInFlight(&dummyNodeGraphene, hash, NetMsgType::GRAPHENEBLOCK);
    BOOST_CHECK(!thinrelay.AreTooManyBlocksInFlight());
    BOOST_CHECK(!thinrelay.AddBlockInFlight(&dummyNodeGraphene, hash, NetMsgType::GRAPHENEBLOCK));

    // Add 4 more blocks in flight
    thinrelay.AddBlockInFlight(&dummyNodeGraphene, GetRandHash(), NetMsgType::GRAPHENEBLOCK);
    thinrelay.AddBlockInFlight(&dummyNodeGraphene, GetRandHash(), NetMsgType::GRAPHENEBLOCK);
    thinrelay.AddBlockInFlight(&dummyNodeGraphene, GetRandHash(), NetMsgType::GRAPHENEBLOCK);
    thinrelay.AddBlockInFlight(&dummyNodeGraphene, GetRandHash(), NetMsgType::GRAPHENEBLOCK);
    BOOST_CHECK(!thinrelay.AreTooManyBlocksInFlight());

    // Add one more which is the max blocks in flight. A call to TooManyBlocksInFlight() will now
    // return false.
    BOOST_CHECK(thinrelay.AddBlockInFlight(&dummyNodeGraphene, GetRandHash(), NetMsgType::GRAPHENEBLOCK));
    BOOST_CHECK(thinrelay.AreTooManyBlocksInFlight());

    // Try to add one beyond the maximum which should fail
    BOOST_CHECK(!thinrelay.AddBlockInFlight(&dummyNodeGraphene, GetRandHash(), NetMsgType::GRAPHENEBLOCK));
    CleanupAll(vNodes);


    // Test the General Case: Chain synced, graphene ON, Thinblocks ON, Cmpct ON
    // This should return a Graphene block.
    IsChainNearlySyncdSet(true);
    SetBoolArg("-use-grapheneblocks", true);
    SetBoolArg("-use-thinblocks", true);
    SetBoolArg("-use-compactblocks", true);
    thinrelay.AddPeers(&dummyNodeGraphene);
    thinrelay.AddPeers(&dummyNodeXthin);
    thinrelay.AddCompactBlockPeer(&dummyNodeCmpct);
    thinrelay.AddPeers(&dummyNodeNone);

    BOOST_CHECK(requester.RequestBlock(&dummyNodeXthin, inv) == true);
    BOOST_CHECK(NetMessage(dummyNodeXthin.vSendMsg) == "get_xthin");
    thinrelay.ClearBlockRelayTimer(inv.hash);
    CleanupAll(vNodes);

    BOOST_CHECK(requester.RequestBlock(&dummyNodeGraphene, inv) == true);
    BOOST_CHECK(NetMessage(dummyNodeGraphene.vSendMsg) == "get_grblk");
    thinrelay.ClearBlockRelayTimer(inv.hash);
    CleanupAll(vNodes);

    BOOST_CHECK(requester.RequestBlock(&dummyNodeCmpct, inv_cmpct) == true);
    // TODO: compact block requests are done through getdata and so can not be requested with priority.
    BOOST_CHECK(NetMessage(dummyNodeCmpct.vLowPrioritySendMsg) == "cmpctblock");
    thinrelay.ClearBlockRelayTimer(inv_cmpct.hash);
    CleanupAll(vNodes);

    BOOST_CHECK(requester.RequestBlock(&dummyNodeNone, inv) == true);
    // TODO: full block requests are done through getdata and so can not be requested with priority.
    BOOST_CHECK(NetMessage(dummyNodeNone.vLowPrioritySendMsg) == "getdata");
    thinrelay.ClearBlockRelayTimer(inv.hash);
    CleanupAll(vNodes);

    // Test the General Case: Chain synced, graphene ON, Thinblocks ON, Cmpct ON
    // This should return a Graphene block.
    IsChainNearlySyncdSet(true);
    SetBoolArg("-use-grapheneblocks", true);
    SetBoolArg("-use-thinblocks", true);
    SetBoolArg("-use-compactblocks", true);
    thinrelay.AddPeers(&dummyNodeGraphene);
    thinrelay.AddPeers(&dummyNodeXthin);
    thinrelay.AddCompactBlockPeer(&dummyNodeCmpct);
    thinrelay.AddPeers(&dummyNodeNone);

    BOOST_CHECK(requester.RequestBlock(&dummyNodeXthin, inv) == true);
    BOOST_CHECK(NetMessage(dummyNodeXthin.vSendMsg) == "get_xthin");
    thinrelay.ClearBlockRelayTimer(inv.hash);
    CleanupAll(vNodes);

    BOOST_CHECK(requester.RequestBlock(&dummyNodeGraphene, inv) == true);
    BOOST_CHECK(NetMessage(dummyNodeGraphene.vSendMsg) == "get_grblk");
    thinrelay.ClearBlockRelayTimer(inv.hash);
    CleanupAll(vNodes);

    BOOST_CHECK(requester.RequestBlock(&dummyNodeCmpct, inv_cmpct) == true);
    BOOST_CHECK(NetMessage(dummyNodeCmpct.vLowPrioritySendMsg) == "cmpctblock");
    thinrelay.ClearBlockRelayTimer(inv_cmpct.hash);
    CleanupAll(vNodes);

    BOOST_CHECK(requester.RequestBlock(&dummyNodeNone, inv) == true);
    BOOST_CHECK(NetMessage(dummyNodeNone.vLowPrioritySendMsg) == "getdata");
    thinrelay.ClearBlockRelayTimer(inv.hash);
    CleanupAll(vNodes);

    // Thin timer disabled: Chain synced, graphene ON, Thinblocks OFF, Cmpct ON
    // Although the timer would have been on because one relay type was off, here we explicity turn off
    // the timer. We should still be able to request a Graphene, or Cmpct or regular block
    IsChainNearlySyncdSet(true);
    SetBoolArg("-use-grapheneblocks", true);
    SetBoolArg("-use-thinblocks", false);
    SetBoolArg("-use-compactblocks", true);
    SetArg("-preferential-timer", "0");
    thinrelay.AddPeers(&dummyNodeGraphene);
    thinrelay.AddPeers(&dummyNodeXthin);
    thinrelay.AddCompactBlockPeer(&dummyNodeCmpct);
    thinrelay.AddPeers(&dummyNodeNone);

    // This test would generally cause a request for a "get_xthin", however xthins is not on and
    // the timer is off which results in a full block request.
    BOOST_CHECK(requester.RequestBlock(&dummyNodeXthin, inv) == true);
    BOOST_CHECK(NetMessage(dummyNodeXthin.vLowPrioritySendMsg) == "getdata");
    thinrelay.ClearBlockRelayTimer(inv.hash);
    CleanupAll(vNodes);

    BOOST_CHECK(requester.RequestBlock(&dummyNodeGraphene, inv) == true);
    BOOST_CHECK(NetMessage(dummyNodeGraphene.vSendMsg) == "get_grblk");
    thinrelay.ClearBlockRelayTimer(inv.hash);
    CleanupAll(vNodes);

    BOOST_CHECK(requester.RequestBlock(&dummyNodeCmpct, inv_cmpct) == true);
    BOOST_CHECK(NetMessage(dummyNodeCmpct.vLowPrioritySendMsg) == "cmpctblock");
    thinrelay.ClearBlockRelayTimer(inv_cmpct.hash);
    CleanupAll(vNodes);

    inv.type = MSG_BLOCK;
    BOOST_CHECK(requester.RequestBlock(&dummyNodeNone, inv) == true);
    BOOST_CHECK(NetMessage(dummyNodeNone.vLowPrioritySendMsg) == "getdata");
    thinrelay.ClearBlockRelayTimer(inv.hash);
    CleanupAll(vNodes);
    SetArg("-preferential-timer", "10000"); // reset from 0

    // Chain NOT synced with any nodes, graphene ON, Thinblocks ON, Cmpct ON
    IsChainNearlySyncdSet(false);
    SetBoolArg("-use-grapheneblocks", true);
    SetBoolArg("-use-thinblocks", true);
    SetBoolArg("-use-compactblocks", true);
    thinrelay.AddPeers(&dummyNodeGraphene);
    thinrelay.AddPeers(&dummyNodeXthin);
    thinrelay.AddCompactBlockPeer(&dummyNodeCmpct);
    thinrelay.AddPeers(&dummyNodeNone);

    BOOST_CHECK(requester.RequestBlock(&dummyNodeXthin, inv) == true);
    BOOST_CHECK(NetMessage(dummyNodeXthin.vLowPrioritySendMsg) == "getdata");

    BOOST_CHECK(requester.RequestBlock(&dummyNodeGraphene, inv) == true);
    BOOST_CHECK(NetMessage(dummyNodeGraphene.vLowPrioritySendMsg) == "getdata");

    BOOST_CHECK(requester.RequestBlock(&dummyNodeNone, inv) == true);
    BOOST_CHECK(NetMessage(dummyNodeNone.vLowPrioritySendMsg) == "getdata");

    thinrelay.ClearBlockRelayTimer(inv.hash);
    CleanupAll(vNodes);

    // Chains IS sync'd: No graphene nodes, No Thinblock nodes, No Cmpct nodes, Thinblocks OFF, Graphene OFF, CMPCT OFF
    IsChainNearlySyncdSet(true);
    SetBoolArg("-use-grapheneblocks", false);
    SetBoolArg("-use-thinblocks", false);
    SetBoolArg("-use-compactblocks", false);
    thinrelay.AddPeers(&dummyNodeNone);

    BOOST_CHECK(requester.RequestBlock(&dummyNodeNone, inv) == true);
    BOOST_CHECK(NetMessage(dummyNodeNone.vLowPrioritySendMsg) == "getdata");

    thinrelay.ClearBlockRelayTimer(inv.hash);
    ClearThinBlocksInFlight(dummyNodeNone, inv);
    requester.MapBlocksInFlightClear();
    thinrelay.RemovePeers(&dummyNodeNone);
    CleanupAll(vNodes);

    // Chains IS sync'd: HAVE graphene nodes, NO Thinblock nodes, No Cmpt nodes, Graphene OFF, Thinblocks OFF,
    // Compactblocks OFF
    IsChainNearlySyncdSet(true);
    SetBoolArg("use-grapheneblocks", false);
    SetBoolArg("-use-thinblocks", false);
    SetBoolArg("-use-compactblocks", false);
    thinrelay.AddPeers(&dummyNodeGraphene);
    thinrelay.AddPeers(&dummyNodeNone);

    BOOST_CHECK(requester.RequestBlock(&dummyNodeNone, inv) == true);
    BOOST_CHECK(NetMessage(dummyNodeNone.vLowPrioritySendMsg) == "getdata");

    thinrelay.ClearBlockRelayTimer(inv.hash);
    CleanupAll(vNodes);

    // Chains IS sync'd,  NO graphene nodes, NO Thinblock nodes, No Cmpt nodes, Graphene OFF, Thinblocks ON, Cmpctblocks
    // OFF
    IsChainNearlySyncdSet(true);
    SetBoolArg("-use-grapheneblocks", false);
    SetBoolArg("-use-thinblocks", true);
    SetBoolArg("-use-compactblocks", false);
    thinrelay.AddPeers(&dummyNodeNone);

    BOOST_CHECK(requester.RequestBlock(&dummyNodeNone, inv) == true);
    BOOST_CHECK(NetMessage(dummyNodeNone.vLowPrioritySendMsg) == "getdata");

    thinrelay.ClearBlockRelayTimer(inv.hash);
    CleanupAll(vNodes);

    // Chains IS sync'd,  NO graphene nodes, NO Thinblock nodes, No Cmpt nodes, Graphene OFF, Thinblocks OFF,
    // Cmpctblocks ON
    IsChainNearlySyncdSet(true);
    SetBoolArg("-use-grapheneblocks", false);
    SetBoolArg("-use-thinblocks", false);
    SetBoolArg("-use-compactblocks", true);
    thinrelay.AddPeers(&dummyNodeNone);

    BOOST_CHECK(requester.RequestBlock(&dummyNodeNone, inv) == true);
    BOOST_CHECK(NetMessage(dummyNodeNone.vLowPrioritySendMsg) == "getdata");

    thinrelay.ClearBlockRelayTimer(inv.hash);
    CleanupAll(vNodes);

    // Chains IS sync'd, HAVE graphene nodes, NO Thinblock nodes, No Cmpct nodes, Graphene OFF, Thinblocks ON,
    // Cmpctblocks OFF
    IsChainNearlySyncdSet(true);
    SetBoolArg("-use-grapheneblocks", false);
    SetBoolArg("-use-thinblocks", true);
    SetBoolArg("-use-compactblocks", false);
    thinrelay.AddPeers(&dummyNodeGraphene);
    thinrelay.AddPeers(&dummyNodeNone);

    BOOST_CHECK(requester.RequestBlock(&dummyNodeNone, inv) == true);
    BOOST_CHECK(NetMessage(dummyNodeNone.vLowPrioritySendMsg) == "getdata");

    thinrelay.ClearBlockRelayTimer(inv.hash);
    CleanupAll(vNodes);

    // Chains IS sync'd, HAVE graphene nodes, NO Thinblock nodes, No Cmpct nodes, Graphene OFF, Thinblocks ON,
    // Cmpctblocks ON
    IsChainNearlySyncdSet(true);
    SetBoolArg("-use-grapheneblocks", false);
    SetBoolArg("-use-thinblocks", true);
    SetBoolArg("-use-compactblocks", true);
    thinrelay.AddPeers(&dummyNodeGraphene);
    thinrelay.AddPeers(&dummyNodeNone);

    BOOST_CHECK(requester.RequestBlock(&dummyNodeNone, inv) == true);
    BOOST_CHECK(NetMessage(dummyNodeNone.vLowPrioritySendMsg) == "getdata");

    thinrelay.ClearBlockRelayTimer(inv.hash);
    CleanupAll(vNodes);

    // Chains IS sync'd, HAVE graphene nodes, NO Thinblock nodes, No Cmpct nodes, Graphene OFF, Thinblocks OFF,
    // Cmpctblocks ON
    IsChainNearlySyncdSet(true);
    SetBoolArg("-use-grapheneblocks", false);
    SetBoolArg("-use-thinblocks", false);
    SetBoolArg("-use-compactblocks", true);
    thinrelay.AddPeers(&dummyNodeGraphene);
    thinrelay.AddPeers(&dummyNodeNone);

    BOOST_CHECK(requester.RequestBlock(&dummyNodeNone, inv) == true);
    BOOST_CHECK(NetMessage(dummyNodeNone.vLowPrioritySendMsg) == "getdata");

    thinrelay.ClearBlockRelayTimer(inv.hash);
    CleanupAll(vNodes);

    // Chains IS sync'd,  NO graphene nodes, HAVE Thinblock nodes, No Cmpct Nodes, Thinblocks OFF, Graphene ON, Cmpct
    // blocks OFF
    IsChainNearlySyncdSet(true);
    SetBoolArg("-use-grapheneblocks", true);
    SetBoolArg("-use-thinblocks", false);
    SetBoolArg("-use-compactblocks", false);
    thinrelay.AddPeers(&dummyNodeXthin);
    thinrelay.AddPeers(&dummyNodeNone);

    BOOST_CHECK(requester.RequestBlock(&dummyNodeNone, inv) == true);
    BOOST_CHECK(NetMessage(dummyNodeNone.vLowPrioritySendMsg) == "getdata");

    thinrelay.ClearBlockRelayTimer(inv.hash);
    CleanupAll(vNodes);

    // Chains IS sync'd,  NO graphene nodes, HAVE Thinblock nodes, No Cmpct Nodes, Thinblocks OFF, Graphene ON, Cmpct
    // blocks ON
    IsChainNearlySyncdSet(true);
    SetBoolArg("-use-grapheneblocks", true);
    SetBoolArg("-use-thinblocks", false);
    SetBoolArg("-use-compactblocks", true);
    thinrelay.AddPeers(&dummyNodeXthin);
    thinrelay.AddPeers(&dummyNodeNone);

    BOOST_CHECK(requester.RequestBlock(&dummyNodeNone, inv) == true);
    BOOST_CHECK(NetMessage(dummyNodeNone.vLowPrioritySendMsg) == "getdata");

    thinrelay.ClearBlockRelayTimer(inv.hash);
    CleanupAll(vNodes);

    // Chains IS sync'd, NO graphene nodes, HAVE Thinblock nodes, No Cmpct Nodes, Thinblocks OFF, Graphene OFF, Cmpct
    // blocks ON
    IsChainNearlySyncdSet(true);
    SetBoolArg("-use-grapheneblocks", false);
    SetBoolArg("-use-thinblocks", false);
    SetBoolArg("-use-compactblocks", true);
    thinrelay.AddPeers(&dummyNodeXthin);
    thinrelay.AddPeers(&dummyNodeNone);

    BOOST_CHECK(requester.RequestBlock(&dummyNodeNone, inv) == true);
    BOOST_CHECK(NetMessage(dummyNodeNone.vLowPrioritySendMsg) == "getdata");

    thinrelay.ClearBlockRelayTimer(inv.hash);
    CleanupAll(vNodes);

    // Chains IS sync'd, NO graphene nodes, HAVE Thinblock nodes, No Cmpct Nodes, Thinblocks OFF, Graphene OFF, Cmpct
    // blocks OFF
    IsChainNearlySyncdSet(true);
    SetBoolArg("-use-grapheneblocks", false);
    SetBoolArg("-use-thinblocks", false);
    SetBoolArg("-use-compactblocks", false);
    thinrelay.AddPeers(&dummyNodeXthin);
    thinrelay.AddPeers(&dummyNodeNone);

    BOOST_CHECK(requester.RequestBlock(&dummyNodeNone, inv) == true);
    BOOST_CHECK(NetMessage(dummyNodeNone.vLowPrioritySendMsg) == "getdata");

    thinrelay.ClearBlockRelayTimer(inv.hash);
    CleanupAll(vNodes);


    // Chains IS sync'd,  NO graphene nodes, NO Thinblock nodes, No Cmpctblock nodes, Thinblocks OFF, Graphene ON, Cmpt
    // blocks OFF
    IsChainNearlySyncdSet(true);
    SetBoolArg("-use-grapheneblocks", true);
    SetBoolArg("-use-thinblocks", false);
    SetBoolArg("-use-compactblocks", false);
    thinrelay.AddPeers(&dummyNodeNone);

    BOOST_CHECK(requester.RequestBlock(&dummyNodeNone, inv) == true);
    BOOST_CHECK(NetMessage(dummyNodeNone.vLowPrioritySendMsg) == "getdata");

    thinrelay.ClearBlockRelayTimer(inv.hash);
    CleanupAll(vNodes);

    // Chains IS sync'd,  NO graphene nodes, NO Thinblock nodes, No Cmpctblock nodes, Thinblocks OFF, Graphene ON, Cmpt
    // blocks ON
    IsChainNearlySyncdSet(true);
    SetBoolArg("-use-grapheneblocks", true);
    SetBoolArg("-use-thinblocks", false);
    SetBoolArg("-use-compactblocks", true);
    thinrelay.AddPeers(&dummyNodeNone);

    BOOST_CHECK(requester.RequestBlock(&dummyNodeNone, inv) == true);
    BOOST_CHECK(NetMessage(dummyNodeNone.vLowPrioritySendMsg) == "getdata");

    thinrelay.ClearBlockRelayTimer(inv.hash);
    CleanupAll(vNodes);

    // Chains IS sync'd,  NO graphene nodes, NO Thinblock nodes, No Cmpctblock nodes, Thinblocks ON, Graphene ON, Cmpt
    // blocks ON
    IsChainNearlySyncdSet(true);
    SetBoolArg("-use-grapheneblocks", true);
    SetBoolArg("-use-thinblocks", true);
    SetBoolArg("-use-compactblocks", true);
    thinrelay.AddPeers(&dummyNodeNone);

    BOOST_CHECK(requester.RequestBlock(&dummyNodeNone, inv) == true);
    BOOST_CHECK(NetMessage(dummyNodeNone.vLowPrioritySendMsg) == "getdata");

    thinrelay.ClearBlockRelayTimer(inv.hash);
    CleanupAll(vNodes);

    // Chains IS sync'd,  NO graphene nodes, NO Thinblock nodes, No Cmpctblock nodes, Thinblocks ON, Graphene ON, Cmpt
    // blocks OFF
    IsChainNearlySyncdSet(true);
    SetBoolArg("-use-grapheneblocks", true);
    SetBoolArg("-use-thinblocks", true);
    SetBoolArg("-use-compactblocks", false);
    thinrelay.AddPeers(&dummyNodeNone);

    BOOST_CHECK(requester.RequestBlock(&dummyNodeNone, inv) == true);
    BOOST_CHECK(NetMessage(dummyNodeNone.vLowPrioritySendMsg) == "getdata");

    thinrelay.ClearBlockRelayTimer(inv.hash);
    CleanupAll(vNodes);

    // Chains IS sync'd, HAVE graphene nodes, NO Thinblock nodes, No Cmpct nodes, Thinblocks ON, Graphene ON, Cmpct
    // blocks ON
    IsChainNearlySyncdSet(true);
    SetBoolArg("-use-grapheneblocks", true);
    SetBoolArg("-use-thinblocks", true);
    SetBoolArg("-use-compactblocks", true);
    thinrelay.AddPeers(&dummyNodeGraphene);
    thinrelay.AddPeers(&dummyNodeNone);

    BOOST_CHECK(requester.RequestBlock(&dummyNodeGraphene, inv) == true);
    BOOST_CHECK(NetMessage(dummyNodeGraphene.vSendMsg) == "get_grblk");

    thinrelay.ClearBlockRelayTimer(inv.hash);
    CleanupAll(vNodes);

    // Chains IS sync'd, HAVE graphene nodes, NO Thinblock nodes, No Cmpct nodes, Thinblocks OFF, Graphene ON, Cmpct
    // blocks ON
    IsChainNearlySyncdSet(true);
    SetBoolArg("-use-grapheneblocks", true);
    SetBoolArg("-use-thinblocks", false);
    SetBoolArg("-use-compactblocks", true);
    thinrelay.AddPeers(&dummyNodeGraphene);
    thinrelay.AddPeers(&dummyNodeNone);

    BOOST_CHECK(requester.RequestBlock(&dummyNodeGraphene, inv) == true);
    BOOST_CHECK(NetMessage(dummyNodeGraphene.vSendMsg) == "get_grblk");

    thinrelay.ClearBlockRelayTimer(inv.hash);
    CleanupAll(vNodes);

    // Chains IS sync'd, HAVE graphene nodes, NO Thinblock nodes, No Cmpct nodes, Thinblocks OFF, Graphene ON, Cmpct
    // blocks OFF
    IsChainNearlySyncdSet(true);
    SetBoolArg("-use-grapheneblocks", true);
    SetBoolArg("-use-thinblocks", false);
    SetBoolArg("-use-compactblocks", false);
    thinrelay.AddPeers(&dummyNodeGraphene);
    thinrelay.AddPeers(&dummyNodeNone);

    BOOST_CHECK(requester.RequestBlock(&dummyNodeGraphene, inv) == true);
    BOOST_CHECK(NetMessage(dummyNodeGraphene.vSendMsg) == "get_grblk");

    thinrelay.ClearBlockRelayTimer(inv.hash);
    CleanupAll(vNodes);

    // Chains IS sync'd,  HAVE graphene nodes, HAVE Thinblock nodes, Thinblocks ON, Graphene ON
    IsChainNearlySyncdSet(true);
    SetBoolArg("-use-grapheneblocks", true);
    SetBoolArg("-use-thinblocks", true);
    thinrelay.AddPeers(&dummyNodeGraphene);
    thinrelay.AddPeers(&dummyNodeXthin);
    thinrelay.AddPeers(&dummyNodeNone);

    BOOST_CHECK(requester.RequestBlock(&dummyNodeGraphene, inv) == true);
    BOOST_CHECK(NetMessage(dummyNodeGraphene.vSendMsg) == "get_grblk");

    CleanupAll(vNodes);

    // Chains IS sync'd,  NO graphene nodes, HAVE Thinblock nodes, No Cmpct Nodes, Thinblocks ON, Graphene OFF, Cmpct
    // OFF
    IsChainNearlySyncdSet(true);
    SetBoolArg("-use-grapheneblocks", false);
    SetBoolArg("-use-thinblocks", true);
    SetBoolArg("-use-compactblocks", false);
    thinrelay.AddPeers(&dummyNodeXthin);
    thinrelay.AddPeers(&dummyNodeNone);

    BOOST_CHECK(requester.RequestBlock(&dummyNodeXthin, inv) == true);
    BOOST_CHECK(NetMessage(dummyNodeXthin.vSendMsg) == "get_xthin");

    thinrelay.ClearBlockRelayTimer(inv.hash);
    CleanupAll(vNodes);

    // Chains IS sync'd,  NO graphene nodes, HAVE Thinblock nodes, No Cmpct Nodes, Thinblocks ON, Graphene ON, Cmpct ON
    IsChainNearlySyncdSet(true);
    SetBoolArg("-use-grapheneblocks", true);
    SetBoolArg("-use-thinblocks", true);
    SetBoolArg("-use-compactblocks", true);
    thinrelay.AddPeers(&dummyNodeXthin);
    thinrelay.AddPeers(&dummyNodeNone);

    BOOST_CHECK(requester.RequestBlock(&dummyNodeXthin, inv) == true);
    BOOST_CHECK(NetMessage(dummyNodeXthin.vSendMsg) == "get_xthin");

    thinrelay.ClearBlockRelayTimer(inv.hash);
    CleanupAll(vNodes);

    // Chains IS sync'd,  NO graphene nodes, No Thinblock nodes, Have Cmpct Nodes, Thinblocks OFF, Graphene OFF, Cmpct
    // ON
    IsChainNearlySyncdSet(true);
    SetBoolArg("-use-grapheneblocks", false);
    SetBoolArg("-use-thinblocks", false);
    SetBoolArg("-use-compactblocks", true);
    thinrelay.AddCompactBlockPeer(&dummyNodeCmpct);
    thinrelay.AddPeers(&dummyNodeNone);

    BOOST_CHECK(requester.RequestBlock(&dummyNodeCmpct, inv_cmpct) == true);
    BOOST_CHECK(NetMessage(dummyNodeCmpct.vLowPrioritySendMsg) == "cmpctblock");

    thinrelay.ClearBlockRelayTimer(inv.hash);
    CleanupAll(vNodes);

    // Chains IS sync'd,  NO graphene nodes, No Thinblock nodes, Have Cmpct Nodes, Thinblocks ON, Graphene ON, Cmpct ON
    IsChainNearlySyncdSet(true);
    SetBoolArg("-use-grapheneblocks", true);
    SetBoolArg("-use-thinblocks", true);
    SetBoolArg("-use-compactblocks", true);
    thinrelay.AddCompactBlockPeer(&dummyNodeCmpct);
    thinrelay.AddPeers(&dummyNodeNone);

    BOOST_CHECK(requester.RequestBlock(&dummyNodeCmpct, inv_cmpct) == true);
    BOOST_CHECK(NetMessage(dummyNodeCmpct.vLowPrioritySendMsg) == "cmpctblock");

    thinrelay.ClearBlockRelayTimer(inv.hash);
    CleanupAll(vNodes);


    /******************************
     * Check full blocks are downloaded when no block announcements come from a graphene, thinblock or cmpct peer.
     * The timers in this case will be disabled so we will immediately download a full block.
     */

    // Chains IS sync'd,  HAVE graphene nodes, HAVE Thinblock nodes, Have Cmpct node, Thinblocks ON, Graphene ON, Cmpct
    // ON
    IsChainNearlySyncdSet(true);
    SetBoolArg("-use-grapheneblocks", true);
    SetBoolArg("-use-thinblocks", true);
    SetBoolArg("-use-compactblocks", true);
    thinrelay.AddPeers(&dummyNodeGraphene);
    thinrelay.AddPeers(&dummyNodeXthin);
    thinrelay.AddCompactBlockPeer(&dummyNodeCmpct);
    thinrelay.AddPeers(&dummyNodeNone);

    BOOST_CHECK(requester.RequestBlock(&dummyNodeNone, inv) == true);
    BOOST_CHECK(NetMessage(dummyNodeNone.vLowPrioritySendMsg) == "getdata");

    thinrelay.ClearBlockRelayTimer(inv.hash);
    CleanupAll(vNodes);


    /******************************
     * Check full blocks are downloaded when graphene is off but thin type timer is exceeded
     */

    // Chains IS sync'd,  HAVE graphene nodes, HAVE Thinblock nodes, Have Cmpct nodes, Graphene OFF, Thinblocks ON,
    // Cmpct ON
    IsChainNearlySyncdSet(true);
    SetBoolArg("-use-grapheneblocks", false);
    SetBoolArg("-use-thinblocks", true);
    SetBoolArg("-use-compactblocks", true);
    thinrelay.AddPeers(&dummyNodeGraphene);
    thinrelay.AddPeers(&dummyNodeXthin);
    thinrelay.AddCompactBlockPeer(&dummyNodeCmpct);
    thinrelay.AddPeers(&dummyNodeNone);

    // Set mocktime
    nTime = GetTime();
    SetMockTime(nTime);

    // The first request should fail but the xthin timer should be triggered
    BOOST_CHECK(requester.RequestBlock(&dummyNodeNone, inv) == false);

    // Now move the clock ahead so that the timer is exceeded and we should now
    // download a full block
    SetMockTime(nTime + 20);
    BOOST_CHECK(requester.RequestBlock(&dummyNodeNone, inv) == true);
    BOOST_CHECK(NetMessage(dummyNodeNone.vLowPrioritySendMsg) == "getdata");

    thinrelay.ClearBlockRelayTimer(inv.hash);
    CleanupAll(vNodes);


    /******************************
     * Check a full block is downloaded when Graphene timer is exceeded but then we get an announcement
     * from a graphene peer (thinblocks is OFF), and then request from that graphene peer before we
     * request from any others.
     */

    // Chains IS sync'd,  HAVE graphene nodes, HAVE Thinblock nodes, Thinblocks OFF, Graphene ON
    IsChainNearlySyncdSet(true);
    SetBoolArg("-use-grapheneblocks", true);
    SetBoolArg("-use-thinblocks", false);
    thinrelay.AddPeers(&dummyNodeGraphene);
    thinrelay.AddPeers(&dummyNodeXthin);
    thinrelay.AddPeers(&dummyNodeNone);

    // Set mocktime
    nTime = GetTime();
    SetMockTime(nTime);

    // The first request should fail but the timers should be triggered for graphene
    BOOST_CHECK(requester.RequestBlock(&dummyNodeNone, inv) == false);

    // Now move the clock ahead so that the timer is exceeded and we should now
    // download a full block
    SetMockTime(nTime + 20);
    randhash = InsecureRand256();
    thinrelay.AddBlockInFlight(&dummyNodeGraphene, randhash, NetMsgType::GRAPHENEBLOCK);
    BOOST_CHECK(requester.RequestBlock(&dummyNodeGraphene, inv) == true);
    BOOST_CHECK(NetMessage(dummyNodeGraphene.vLowPrioritySendMsg) == "getdata");

    CleanupAll(vNodes);

    /******************************
     * Check another graphene block is downloaded when Graphene timer is exceeded and then we get an announcement
     * from a graphene peer (thinblocks is ON), and then request from that graphene peer before we
     * request from any others.
     * However this time we already have a grapheneblock in flight but we end up downloading another graphene block
     * because we haven't exceeded the limit on number of thintype blocks in flight.
     * Then proceed to request more thintype blocks until the limit is exceeded.
     */

    // Chains IS sync'd,  HAVE graphene nodes, HAVE Thinblock nodes, Thinblocks ON, Graphene ON, Cmpct OFF
    IsChainNearlySyncdSet(true);
    SetBoolArg("-use-grapheneblocks", true);
    SetBoolArg("-use-thinblocks", true);
    SetBoolArg("-use-compactblocks", false);
    thinrelay.AddPeers(&dummyNodeGraphene);
    thinrelay.AddPeers(&dummyNodeXthin);
    thinrelay.AddPeers(&dummyNodeNone);

    // Set mocktime
    nTime = GetTime();
    SetMockTime(nTime);

    // The first request should suceed as should successive requests up until the limit of thintype requests in flight
    inv.hash = InsecureRand256();
    BOOST_CHECK(requester.RequestBlock(&dummyNodeGraphene, inv) == true);
    BOOST_CHECK(dummyNodeGraphene.GetSendMsgSize() == 1);

    inv.hash = InsecureRand256();
    BOOST_CHECK(requester.RequestBlock(&dummyNodeGraphene, inv) == true);
    BOOST_CHECK(dummyNodeGraphene.GetSendMsgSize() == 2);

    inv.hash = InsecureRand256();
    BOOST_CHECK(requester.RequestBlock(&dummyNodeGraphene, inv) == true);
    BOOST_CHECK(dummyNodeGraphene.GetSendMsgSize() == 3);

    inv.hash = InsecureRand256();
    BOOST_CHECK(requester.RequestBlock(&dummyNodeGraphene, inv) == true);
    BOOST_CHECK(dummyNodeGraphene.GetSendMsgSize() == 4);

    inv.hash = InsecureRand256();
    BOOST_CHECK(requester.RequestBlock(&dummyNodeGraphene, inv) == true);
    BOOST_CHECK(dummyNodeGraphene.GetSendMsgSize() == 5);

    // Now move the clock ahead so that the timers are exceeded and we should now
    // download an xthin
    SetMockTime(nTime + 20);
    {
        LOCK(dummyNodeXthin.cs_vSend);
        dummyNodeXthin.vSendMsg.clear();
    }
    inv.hash = InsecureRand256();
    BOOST_CHECK(requester.RequestBlock(&dummyNodeXthin, inv) == true);
    BOOST_CHECK(dummyNodeXthin.GetSendMsgSize() == 1);

    // Try to send a 7th block. It should fail to send as it's above the limit of thintype blocks in flight.
    inv.hash = InsecureRand256();
    BOOST_CHECK(requester.RequestBlock(&dummyNodeGraphene, inv) == false);
    BOOST_CHECK(dummyNodeGraphene.GetSendMsgSize() == 5);

    thinrelay.ClearBlockRelayTimer(inv.hash);
    CleanupAll(vNodes);

    /******************************
     * Check a Xthin is is downloaded when thinblock timer is exceeded but then we get an announcement
     * from a thinblock peer, and then request from that thinblock peer before we request from any others.
     */

    // Chains IS sync'd,  HAVE graphene nodes, HAVE Thinblock nodes, Thinblocks ON, Graphene OFF
    IsChainNearlySyncdSet(true);
    SetBoolArg("-use-grapheneblocks", false);
    SetBoolArg("-use-thinblocks", true);
    thinrelay.AddPeers(&dummyNodeGraphene);
    thinrelay.AddPeers(&dummyNodeXthin);
    thinrelay.AddPeers(&dummyNodeNone);

    // Set mocktime
    nTime = GetTime();
    SetMockTime(nTime);

    // The first request should fail but the timers should be triggered for xthin
    BOOST_CHECK(requester.RequestBlock(&dummyNodeNone, inv) == false);

    // Now move the clock ahead so that the timer is exceeded and we should now
    // download a full block
    SetMockTime(nTime + 20);
    BOOST_CHECK(requester.RequestBlock(&dummyNodeXthin, inv) == true);
    BOOST_CHECK(NetMessage(dummyNodeXthin.vLowPrioritySendMsg) == "getdata");

    thinrelay.ClearBlockRelayTimer(inv.hash);
    CleanupAll(vNodes);

    /******************************
     * Check a Xthin is is downloaded when thinblock timer is exceeded but then we get an announcement
     * from a thinblock peer, and then request from that thinblock peer before we request from any others.
     * However this time we already have an xthin in flight for this peer so we end up downloading a full block.
     */

    // Chains IS sync'd,  HAVE graphene nodes, HAVE Thinblock nodes, Thinblocks ON, Graphene OFF
    IsChainNearlySyncdSet(true);
    SetBoolArg("-use-grapheneblocks", false);
    SetBoolArg("-use-thinblocks", true);
    thinrelay.AddPeers(&dummyNodeGraphene);
    thinrelay.AddPeers(&dummyNodeXthin);
    thinrelay.AddPeers(&dummyNodeNone);

    // Set mocktime
    nTime = GetTime();
    SetMockTime(nTime);

    // The first request should fail but the timers should be triggered for xthin
    BOOST_CHECK(requester.RequestBlock(&dummyNodeNone, inv) == false);

    // Now move the clock ahead so that the timer is exceeded and we should now
    // download a full block
    SetMockTime(nTime + 20);
    randhash = InsecureRand256();
    thinrelay.AddBlockInFlight(&dummyNodeXthin, randhash, NetMsgType::XTHINBLOCK);
    BOOST_CHECK(requester.RequestBlock(&dummyNodeXthin, inv) == true);
    BOOST_CHECK(NetMessage(dummyNodeXthin.vLowPrioritySendMsg) == "getdata");


    thinrelay.ClearBlockRelayTimer(inv.hash);
    CleanupAll(vNodes);

    /******************************
     * Check a full block is is downloaded when thinblock timer is exceeded but then we get an announcement
     * from a cmpctblock peer, and then request from that cmpctnblock peer before we request from any others.
     * However this time we already have an cmpctblk in flight for this peer so we end up downloading a full block.
     */

    // Chains IS sync'd,  HAVE graphene nodes, HAVE Thinblock nodes, Have Cmpct nodes, Thinblocks OFF, Graphene OFF,
    // Cmpct ON
    IsChainNearlySyncdSet(true);
    SetBoolArg("-use-grapheneblocks", false);
    SetBoolArg("-use-thinblocks", true);
    SetBoolArg("-use-compactblocks", true);
    thinrelay.AddPeers(&dummyNodeGraphene);
    thinrelay.AddPeers(&dummyNodeXthin);
    thinrelay.AddCompactBlockPeer(&dummyNodeCmpct);
    thinrelay.AddPeers(&dummyNodeNone);

    // Set mocktime
    nTime = GetTime();
    SetMockTime(nTime);

    // The first request should fail but the timers should be triggered for cmpctblock
    BOOST_CHECK(requester.RequestBlock(&dummyNodeNone, inv) == false);

    // Now move the clock ahead so that the timer is exceeded and we should now
    // download a full block
    SetMockTime(nTime + 20);
    randhash = InsecureRand256();
    thinrelay.AddBlockInFlight(&dummyNodeCmpct, randhash, NetMsgType::CMPCTBLOCK);
    BOOST_CHECK(requester.RequestBlock(&dummyNodeCmpct, inv) == true);
    BOOST_CHECK(NetMessage(dummyNodeCmpct.vLowPrioritySendMsg) == "getdata");


    thinrelay.ClearBlockRelayTimer(inv.hash);
    CleanupAll(vNodes);


    // Final cleanup: Unset mocktime
    SetMockTime(0);
    requester.MapBlocksInFlightClear();

    // remove from vNodes
    vNodes.erase(remove(vNodes.begin(), vNodes.end(), &dummyNodeGraphene), vNodes.end());
    vNodes.erase(remove(vNodes.begin(), vNodes.end(), &dummyNodeNone), vNodes.end());
    vNodes.erase(remove(vNodes.begin(), vNodes.end(), &dummyNodeCmpct), vNodes.end());
    vNodes.erase(remove(vNodes.begin(), vNodes.end(), &dummyNodeXthin), vNodes.end());
}

BOOST_AUTO_TEST_CASE(askfor_tests)
{
    CAddress addr1(ipaddress(0xa0b0c001, 10000));
    CAddress addr2(ipaddress(0xa0b0c002, 10001));
    CAddress addr3(ipaddress(0xa0b0c003, 10002));
    CAddress addr4(ipaddress(0xa0b0c004, 10003));
    CAddress addr5(ipaddress(0xa0b0c005, 10004));
    CAddress addr6(ipaddress(0xa0b0c006, 10005));
    CAddress addr7(ipaddress(0xa0b0c007, 10006));
    CAddress addr8(ipaddress(0xa0b0c008, 10007));

    // create nodes
    CNode *dummyNode1 = new CNode(INVALID_SOCKET, addr1, "", true);
    CNode *dummyNode2 = new CNode(INVALID_SOCKET, addr2, "", true);
    CNode *dummyNode3 = new CNode(INVALID_SOCKET, addr3, "", true);
    CNode *dummyNode4 = new CNode(INVALID_SOCKET, addr4, "", true);
    CNode *dummyNode5 = new CNode(INVALID_SOCKET, addr5, "", true);
    CNode *dummyNode6 = new CNode(INVALID_SOCKET, addr6, "", true);
    CNode *dummyNode7 = new CNode(INVALID_SOCKET, addr7, "", true);
    CNode *dummyNode8 = new CNode(INVALID_SOCKET, addr8, "", true);

    CRequestManager rman;
    CRequestManagerTest rman_access(&rman);
    std::map<uint256, CUnknownObj> mapTxnToAdd;
    std::map<uint256, CUnknownObj> mapTxnInfo;
    std::map<uint256, CUnknownObj> mapBlkToAdd;
    std::map<uint256, CUnknownObj> mapBlkInfo;
    std::map<uint256, CUnknownObj> mapTmp;
    std::set<uint256> setDeleter;
    std::set<uint256> setBlockDeleter;

    /*** tests for transactions ***/
    uint256 hash_txn = GetRandHash();
    CInv inv_txn(MSG_TX, hash_txn);

    // make a new transaction request2. There should be one item in mapTxnToAdd and 3 sources
    rman.AskFor(inv_txn, dummyNode1);
    mapTxnToAdd = rman_access.GetMapTxnToAdd();
    setDeleter = rman_access.GetSetDeleter();
    mapTxnInfo = rman_access.GetMapTxnInfo();
    BOOST_CHECK_EQUAL(mapTxnToAdd[inv_txn.hash].availableFrom.size(), 1);
    BOOST_CHECK_EQUAL(mapTxnToAdd.size(), 1);
    BOOST_CHECK_EQUAL(setDeleter.count(inv_txn.hash), 0);
    BOOST_CHECK_EQUAL(mapTxnInfo.size(), 0);

    rman.AskFor(inv_txn, dummyNode2);
    mapTxnToAdd = rman_access.GetMapTxnToAdd();
    setDeleter = rman_access.GetSetDeleter();
    mapTxnInfo = rman_access.GetMapTxnInfo();
    BOOST_CHECK_EQUAL(mapTxnToAdd[inv_txn.hash].availableFrom.size(), 2);
    BOOST_CHECK_EQUAL(mapTxnToAdd.size(), 1);
    BOOST_CHECK_EQUAL(setDeleter.count(inv_txn.hash), 0);
    BOOST_CHECK_EQUAL(mapTxnInfo.size(), 0);

    rman.AskFor(inv_txn, dummyNode3);
    mapTxnToAdd = rman_access.GetMapTxnToAdd();
    setDeleter = rman_access.GetSetDeleter();
    mapTxnInfo = rman_access.GetMapTxnInfo();
    BOOST_CHECK_EQUAL(mapTxnToAdd[inv_txn.hash].availableFrom.size(), 3);
    BOOST_CHECK_EQUAL(mapTxnToAdd.size(), 1);
    BOOST_CHECK_EQUAL(setDeleter.count(inv_txn.hash), 0);
    BOOST_CHECK_EQUAL(mapTxnInfo.size(), 0);

    rman.AskFor(inv_txn, dummyNode4);
    mapTxnToAdd = rman_access.GetMapTxnToAdd();
    mapTxnInfo = rman_access.GetMapTxnInfo();
    setDeleter = rman_access.GetSetDeleter();
    BOOST_CHECK_EQUAL(mapTxnToAdd[inv_txn.hash].availableFrom.size(), 3); // not added because only 3 maximum allowed
    BOOST_CHECK_EQUAL(mapTxnToAdd.size(), 1);
    BOOST_CHECK_EQUAL(setDeleter.count(inv_txn.hash), 0);
    BOOST_CHECK_EQUAL(mapTxnInfo.size(), 0);

    // add the new requests. mapTxnToAdd elements should be moved to mapTxnInfo.
    mapTmp.clear();
    rman.GetTxnRequests(mapTmp);
    rman.AddNewTxnRequests(mapTmp);
    mapTxnInfo = rman_access.GetMapTxnInfo();
    mapTxnToAdd = rman_access.GetMapTxnToAdd();
    BOOST_CHECK_EQUAL(mapTxnToAdd.size(), 0);
    BOOST_CHECK_EQUAL(mapTxnInfo.size(), 1);


    // Mark a txn as received. The deleter should then have one item added to it.
    rman.Received(inv_txn, dummyNode1);
    setDeleter = rman_access.GetSetDeleter();
    BOOST_CHECK_EQUAL(setDeleter.count(inv_txn.hash), 1);
    BOOST_CHECK_EQUAL(setDeleter.size(), 1);

    // map still retains it's entry until the deleter gets called.
    BOOST_CHECK_EQUAL(mapTxnInfo[inv_txn.hash].availableFrom.size(), 3);
    BOOST_CHECK_EQUAL(mapTxnToAdd.size(), 0);

    // Add another new request so that both mapTxnInfo and mapTxnToAdd have entries
    uint256 hash_txn2 = GetRandHash();
    CInv inv_txn2(MSG_TX, hash_txn2);
    rman.AskFor(inv_txn2, dummyNode3);
    mapTxnInfo = rman_access.GetMapTxnInfo();
    mapTxnToAdd = rman_access.GetMapTxnToAdd();
    BOOST_CHECK_EQUAL(mapTxnToAdd.size(), 1);
    BOOST_CHECK_EQUAL(mapTxnInfo.size(), 1);

    // Receive the new txn before it gets added to mapTxnInfo
    mapTmp.clear();
    rman.GetTxnRequests(mapTmp);
    rman.Received(inv_txn2, dummyNode1);
    setDeleter = rman_access.GetSetDeleter();
    mapTxnToAdd = rman_access.GetMapTxnToAdd();
    BOOST_CHECK_EQUAL(setDeleter.count(inv_txn2.hash), 1);
    BOOST_CHECK_EQUAL(setDeleter.size(), 2);

    // now run the deleter and all maps should be empty
    rman.RunTxnDeleter(mapTmp);
    setDeleter = rman_access.GetSetDeleter();
    mapTxnInfo = rman_access.GetMapTxnInfo();
    mapTxnToAdd = rman_access.GetMapTxnToAdd();
    BOOST_CHECK_EQUAL(setDeleter.size(), 0);
    BOOST_CHECK_EQUAL(mapTxnInfo.size(), 0);
    BOOST_CHECK_EQUAL(mapTxnToAdd.size(), 0);


    // Make a new request and push it to mapTxnInfo
    uint256 hash_txn3 = GetRandHash();
    CInv inv_txn3(MSG_TX, hash_txn3);
    rman.AskFor(inv_txn3, dummyNode1);
    mapTmp.clear();
    rman.GetTxnRequests(mapTmp);
    rman.CheckIfNewSource(mapTmp, mapTxnInfo);
    rman.AddNewTxnRequests(mapTmp);
    mapTxnInfo = rman_access.GetMapTxnInfo();
    mapTxnToAdd = rman_access.GetMapTxnToAdd();
    BOOST_CHECK_EQUAL(mapTxnToAdd.size(), 0);
    BOOST_CHECK_EQUAL(mapTxnInfo.size(), 1);
    BOOST_CHECK_EQUAL(mapTxnInfo[inv_txn3.hash].availableFrom.size(), 1);

    rman.AskFor(inv_txn3, dummyNode2);
    mapTmp.clear();
    rman.GetTxnRequests(mapTmp);
    mapTxnInfo = rman_access.GetMapTxnInfo();
    rman.CheckIfNewSource(mapTmp, mapTxnInfo);
    rman.AddNewTxnRequests(mapTmp);
    mapTxnToAdd = rman_access.GetMapTxnToAdd();
    BOOST_CHECK_EQUAL(mapTxnToAdd.size(), 0);
    BOOST_CHECK_EQUAL(mapTxnInfo.size(), 1);
    BOOST_CHECK_EQUAL(mapTxnInfo[inv_txn3.hash].availableFrom.size(), 2);

    rman.AskFor(inv_txn3, dummyNode3);
    mapTmp.clear();
    rman.GetTxnRequests(mapTmp);
    rman.CheckIfNewSource(mapTmp, mapTxnInfo);
    rman.AddNewTxnRequests(mapTmp);
    mapTxnToAdd = rman_access.GetMapTxnToAdd();
    BOOST_CHECK_EQUAL(mapTxnToAdd.size(), 0);
    BOOST_CHECK_EQUAL(mapTxnInfo.size(), 1);
    BOOST_CHECK_EQUAL(mapTxnInfo[inv_txn3.hash].availableFrom.size(), 3);

    rman.AskFor(inv_txn3, dummyNode4);
    mapTmp.clear();
    rman.GetTxnRequests(mapTmp);
    rman.CheckIfNewSource(mapTmp, mapTxnInfo);
    rman.AddNewTxnRequests(mapTmp);
    mapTxnToAdd = rman_access.GetMapTxnToAdd();
    BOOST_CHECK_EQUAL(mapTxnToAdd.size(), 0);
    BOOST_CHECK_EQUAL(mapTxnInfo.size(), 1);
    BOOST_CHECK_EQUAL(mapTxnInfo[inv_txn3.hash].availableFrom.size(), 3); // no source added

    /*** tests for blocks ***/
    uint256 hash_block = GetRandHash();
    CInv inv_block(MSG_BLOCK, hash_block);

    // make a new transaction request. There should be one item in mapTxnToAdd.
    rman.AskFor(inv_block, dummyNode1);
    mapBlkToAdd = rman_access.GetMapBlkToAdd();
    setBlockDeleter = rman_access.GetSetBlockDeleter();
    BOOST_CHECK_EQUAL(mapBlkToAdd[inv_block.hash].availableFrom.size(), 1);
    BOOST_CHECK_EQUAL(mapBlkToAdd.size(), 1);
    BOOST_CHECK_EQUAL(setBlockDeleter.count(inv_block.hash), 0);

    // deleter should have one item added to it
    rman.Received(inv_block, dummyNode1);
    setBlockDeleter = rman_access.GetSetBlockDeleter();
    BOOST_CHECK_EQUAL(setBlockDeleter.count(inv_block.hash), 1);
    BOOST_CHECK_EQUAL(setBlockDeleter.size(), 1);

    // map still retains it's entry until the deleter gets called.
    BOOST_CHECK_EQUAL(mapBlkToAdd[inv_block.hash].availableFrom.size(), 1);
    BOOST_CHECK_EQUAL(mapBlkToAdd.size(), 1);
    BOOST_CHECK_EQUAL(mapBlkInfo.size(), 0);

    // add the new requests. mapBlkToAdd elements should be moved to mapBlkInfo.
    mapTmp.clear();
    rman.GetBlockRequests(mapTmp);
    rman.AddNewBlockRequests(mapTmp);
    mapBlkInfo = rman_access.GetMapBlkInfo();
    mapBlkToAdd = rman_access.GetMapBlkToAdd();
    BOOST_CHECK_EQUAL(mapBlkToAdd.size(), 0);
    BOOST_CHECK_EQUAL(mapBlkInfo.size(), 1);

    // now run the deleter and all maps should be empty
    rman.RunBlockDeleter(mapBlkToAdd);
    setBlockDeleter = rman_access.GetSetBlockDeleter();
    mapBlkInfo = rman_access.GetMapBlkInfo();
    mapBlkToAdd = rman_access.GetMapBlkToAdd();
    BOOST_CHECK_EQUAL(setBlockDeleter.size(), 0);
    BOOST_CHECK_EQUAL(mapBlkInfo.size(), 0);

    /** Test multiple requests for same block from different peers */
    rman.AskFor(inv_block, dummyNode1);
    mapBlkToAdd = rman_access.GetMapBlkToAdd();
    setBlockDeleter = rman_access.GetSetBlockDeleter();
    BOOST_CHECK_EQUAL(mapBlkToAdd[inv_block.hash].availableFrom.size(), 1);
    BOOST_CHECK_EQUAL(mapBlkToAdd.size(), 1);
    BOOST_CHECK_EQUAL(setBlockDeleter.count(inv_block.hash), 0);
    BOOST_CHECK_EQUAL(mapBlkInfo.size(), 0);

    // blocks are handled differently than transactions. A new source should have been added.
    rman.ProcessingBlock(inv_block.hash, dummyNode1);
    rman.AskFor(inv_block, dummyNode2);
    mapBlkToAdd = rman_access.GetMapBlkToAdd();
    setBlockDeleter = rman_access.GetSetBlockDeleter();
    BOOST_CHECK_EQUAL(mapBlkToAdd.size(), 1);
    BOOST_CHECK_EQUAL(setBlockDeleter.count(inv_block.hash), 0);
    BOOST_CHECK_EQUAL(mapBlkToAdd[inv_block.hash].availableFrom.size(), 2); // there should be another source
    BOOST_CHECK_EQUAL(mapBlkInfo.size(), 0);

    // Add multiple new sources.  For blocks it should be possible, for transactions there is a limit of 3
    rman.AskFor(inv_block, dummyNode3);
    mapBlkToAdd = rman_access.GetMapBlkToAdd();
    setBlockDeleter = rman_access.GetSetBlockDeleter();
    BOOST_CHECK_EQUAL(mapBlkToAdd.size(), 1);
    BOOST_CHECK_EQUAL(setBlockDeleter.count(inv_block.hash), 0);
    BOOST_CHECK_EQUAL(mapBlkToAdd[inv_block.hash].availableFrom.size(), 3); // there should be another source
    BOOST_CHECK_EQUAL(mapBlkInfo.size(), 0);

    rman.AskFor(inv_block, dummyNode4);
    mapBlkToAdd = rman_access.GetMapBlkToAdd();
    setBlockDeleter = rman_access.GetSetBlockDeleter();
    BOOST_CHECK_EQUAL(mapBlkToAdd.size(), 1);
    BOOST_CHECK_EQUAL(setBlockDeleter.count(inv_block.hash), 0);
    BOOST_CHECK_EQUAL(mapBlkToAdd[inv_block.hash].availableFrom.size(), 4); // there should be another source
    BOOST_CHECK_EQUAL(mapBlkInfo.size(), 0);

    rman.AskFor(inv_block, dummyNode5);
    mapBlkToAdd = rman_access.GetMapBlkToAdd();
    setBlockDeleter = rman_access.GetSetBlockDeleter();
    BOOST_CHECK_EQUAL(mapBlkToAdd.size(), 1);
    BOOST_CHECK_EQUAL(setBlockDeleter.count(inv_block.hash), 0);
    BOOST_CHECK_EQUAL(mapBlkToAdd[inv_block.hash].availableFrom.size(), 5); // there should be another source
    BOOST_CHECK_EQUAL(mapBlkInfo.size(), 0);

    // Try to add the same source again.  Nothing should be added.
    rman.AskFor(inv_block, dummyNode5);
    mapBlkToAdd = rman_access.GetMapBlkToAdd();
    setBlockDeleter = rman_access.GetSetBlockDeleter();
    BOOST_CHECK_EQUAL(mapBlkToAdd.size(), 1);
    BOOST_CHECK_EQUAL(setBlockDeleter.count(inv_block.hash), 0);
    BOOST_CHECK_EQUAL(mapBlkToAdd[inv_block.hash].availableFrom.size(), 5); // no new source
    BOOST_CHECK_EQUAL(mapBlkInfo.size(), 0);

    // Add the new requests to mapBlkInfo, the re-request map, and then try to add more sources. With blocks
    // it should be possible to continue to add more sources.
    mapTmp.clear();
    rman.GetBlockRequests(mapTmp);
    rman.AddNewBlockRequests(mapTmp);
    mapBlkInfo = rman_access.GetMapBlkInfo();
    mapBlkToAdd = rman_access.GetMapBlkToAdd();
    BOOST_CHECK_EQUAL(mapBlkToAdd.size(), 0);
    BOOST_CHECK_EQUAL(mapBlkInfo.size(), 1);

    // add more sources. This time however the sources should increase
    // but there will be no new requests in mapBlkToAdd and mapBlkInfo should remain
    // unchanged with 1 re-request item still remaining.
    rman.AskFor(inv_block, dummyNode6);
    mapBlkToAdd = rman_access.GetMapBlkToAdd();
    mapBlkInfo = rman_access.GetMapBlkInfo();
    rman.CheckIfNewSource(mapBlkToAdd, mapBlkInfo);
    setBlockDeleter = rman_access.GetSetBlockDeleter();
    BOOST_CHECK_EQUAL(mapBlkToAdd.size(), 0);
    BOOST_CHECK_EQUAL(mapBlkInfo.size(), 1);
    BOOST_CHECK_EQUAL(setBlockDeleter.count(inv_block.hash), 0);
    BOOST_CHECK_EQUAL(mapBlkInfo[inv_block.hash].availableFrom.size(), 6); // there should be another source

    rman.AskFor(inv_block, dummyNode7);
    mapBlkToAdd = rman_access.GetMapBlkToAdd();
    mapBlkInfo = rman_access.GetMapBlkInfo();
    rman.CheckIfNewSource(mapBlkToAdd, mapBlkInfo);
    setBlockDeleter = rman_access.GetSetBlockDeleter();
    BOOST_CHECK_EQUAL(mapBlkToAdd.size(), 0);
    BOOST_CHECK_EQUAL(mapBlkInfo.size(), 1);
    BOOST_CHECK_EQUAL(setBlockDeleter.count(inv_block.hash), 0);
    BOOST_CHECK_EQUAL(mapBlkInfo[inv_block.hash].availableFrom.size(), 7); // there should be another source

    rman.AskFor(inv_block, dummyNode8);
    mapBlkToAdd = rman_access.GetMapBlkToAdd();
    mapBlkInfo = rman_access.GetMapBlkInfo();
    rman.CheckIfNewSource(mapBlkToAdd, mapBlkInfo);
    setBlockDeleter = rman_access.GetSetBlockDeleter();
    BOOST_CHECK_EQUAL(mapBlkToAdd.size(), 0);
    BOOST_CHECK_EQUAL(mapBlkInfo.size(), 1);
    BOOST_CHECK_EQUAL(setBlockDeleter.count(inv_block.hash), 0);
    BOOST_CHECK_EQUAL(mapBlkInfo[inv_block.hash].availableFrom.size(), 8); // there should be another source
}

BOOST_AUTO_TEST_SUITE_END()
