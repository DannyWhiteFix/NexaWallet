#!/usr/bin/env python3
# Copyright (c) 2015-2023 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
import test_framework.loginit

import io
import time
import sys
if sys.version_info[0] < 3:
    raise "Use Python 3"
import logging

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from test_framework.bunode import BasicBUCashNode, BUProtocolHandler
from test_framework.mininode import NetworkThread
from test_framework.nodemessages import *
from test_framework.bumessages import *

CAPD_MSG_TYPE = 72

CAPD_QUERY_MAX_MSGS = 200
CAPD_QUERY_MAX_INVS = 2000

CAPD_XVERSION_STR = '000000020000000e'

TIMEOUT = 30;

def hashToHex(x):
    return x[::-1].hex()

class CapdProtoHandler(BUProtocolHandler):
    def __init__(self):
        BUProtocolHandler.__init__(self, extversion=True)
        self.lastCapdGetMsg = None
        self.numCapdGetMsg = 0
        self.lastCapdInvHashes = None
        self.numInvMsgs = 0
        self.callbacks = {}
        self.msgs = {}  # messages to auto-reply with based on a request message
        self.capdinfo = None

        self.todo = []

    def setAsyncMsgProcessing(self):
        self.todo = None

    def on_version(self, conn, message):
        BUProtocolHandler.on_version(self,conn, message)
        conn.send_message(msg_extversion({int(CAPD_XVERSION_STR,16): 1}))

    def on_extversion(self, conn, message):
        # otherwise node doesn't have capd turned on so this test can't be run
        assert message.xver[int(CAPD_XVERSION_STR,16)] == bytes([1])
        BUProtocolHandler.on_extversion(self,conn, message)
        # handled by superclass: conn.send_message(msg_verack())
        logging.info(message)

    def on_capdinfo(self, conn, message):
        self.capdinfo = message

    def on_capdinv(self, conn, message):
        self.lastCapdInvHashes = message.hashes
        self.numInvMsgs += 1
        # logging.info("CAPD INV:")
        # for m in message.hashes:
        #    logging.info("  " + m.hex())

    def on_capdmsg(self, conn, message):  # we don't expect p2p propagation of capd messages to the python node
        assert False, "P2P capd message propagated to the python node"

    def on_capdgetmsg(self, conn, message):
        self.lastCapdGetMsg = message
        self.numCapdGetMsg += 1

        # If test should automatically reply to this incoming message, then fill self.msgs with possible replies
        replymsgs = []
        for h in message.hashes:
            if h in self.msgs:
                replymsgs.append(self.msgs[h])
        if len(replymsgs)>0:
            self.send_message(msg_capdmsg(replymsgs))

    def doJobs(self):
        todo = self.todo
        self.todo = []
        for t in todo:
            t()

    def capdqreplyHandler(self, conn, message):
        if message.cookie in self.callbacks:
            (cb, notification) = self.callbacks[message.cookie]
            result = cb(conn, message)
            if not notification:
                del self.callbacks[message.cookie]

    def on_capdqreply(self, conn, message):
        # logging.info("received capdqreply")
        # logging.info(message)

        # defer processing into another thread if chosen.
        if self.todo != None:
            self.todo.append(lambda c=conn, m=message: self.capdqreplyHandler(c, m))
        else:
            self.capdqreplyHandler(conn, message)

    def sendHandleQuery(self, query, handler):
        assert not query.cookie in self.callbacks  # Oops you gave a bad cookie
        self.callbacks[query.cookie] = (handler, (query.typ & CAPD_QUERY_TYPE_NOTIFICATION) > 0)
        self.send_message(query)

    def removeNotification(self, cookie):
        assert type(cookie) is int
        self.send_message(msg_capdremove(cookie))


def check(x):
    assert x

class MyTest (BitcoinTestFramework):

    def setup_chain(self,bitcoinConfDict=None, wallets=None):
        logging.info("Initializing test directory "+self.options.tmpdir)
        bitcoinConfDict.update({ "cache.maxCapdPool": 100000})
        initialize_chain(self.options.tmpdir, bitcoinConfDict, wallets)

    def setup_network(self, split=False):
        self.nodes = start_nodes(2, self.options.tmpdir)
        # Now interconnect the nodes
        connect_nodes_full(self.nodes)
        self.is_network_split=False
        self.sync_blocks()
        self.pynode = pynode = BasicBUCashNode()
        self.conn = pynode.connect(0, '127.0.0.1', p2p_port(0), self.nodes[0], protohandler = CapdProtoHandler(), send_initial_version = True, extversion_service = True)
        self.nt = NetworkThread()
        self.nt.start()

    def pyMsgSerTest(self):
        msg = msg_capdquery(1234, 1, 2, 3, b"abc")
        data = msg.serialize()
        s = io.BytesIO(data)
        msg1 = msg_capdquery(0,0,0,0,None).deserialize(s)
        logging.info(msg)
        logging.info(msg1)
        assert msg == msg1

        testmsgs = [ CapdMsg(bytes([0,1,2,3,4,5])), CapdMsg(bytes([0,1]))]
        for m in testmsgs:
            m.solve(4)
        msg = msg_capdqreply(12345, CAPD_QUERY_TYPE_MSG, testmsgs)
        data = msg.serialize()
        s = io.BytesIO(data)
        msg1 = msg_capdqreply(0,None).deserialize(s)
        logging.info(msg)
        logging.info(msg1)
        assert msg == msg1
        return True

    def run_test (self):
        logging.info("CAPD message pool test")

        self.pyMsgSerTest()
        # generate 1 block to kick nodes out of IBD mode
        self.nodes[0].generate(1)
        self.sync_blocks()

        if True:
            result = self.nodes[0].capd()
            # Check the empty msg pool
            assert_equal(result['size'], 0)
            assert_equal(result['count'], 0)
            assert_equal(result['relayPriority'], 2)
            assert_equal(result['minPriority'], 1)

        hdlr = self.pynode.cnxns[0]
        self.conn.handle_write()

        # Wait for the whole version/extversion protocol to finish
        # Otherwise, peer info data may not be complete
        hdlr.wait_for_verack()

        result = self.nodes[0].getpeerinfo()
        for n in result:
            # Note that this tests both the C code exchanging CAPD xversion and this python node
            # All BU nodes and this node should show up as supporting CAPD (but not rostrum)
            if "Nexa" in n["subver"]:
                capdVer = int(n["extversion_map"][CAPD_XVERSION_STR])
                assert_equal(capdVer, 1)

        if True:
            capdStats = self.nodes[0].capd()
            assert_equal(capdStats["count"], 0)

        # Send an INV and expect a getmsg back asking for the message
        hdlr.lastCapdGetMsg = None
        msg = msg_getaddr()
        hdlr.send_message(msg)

        msg = msg_capdinv([hash256(b'0')])
        hdlr.send_message(msg)
        waitFor(30, lambda: hdlr.lastCapdGetMsg)
        getmsg = hdlr.lastCapdGetMsg
        assert_equal(len(getmsg.hashes), 1)
        assert_equal(getmsg.hashes[0],hash256(b'0'))
        # I sent a bogus hash, nothing to do except ignore the message request

        m = CapdMsg(b"this is a test..")
        m.solve(4)
        logging.info("hash: " + m.calcHash().hex() )
        firstMsgHash = m.calcHash()
        msgHashes = [m.calcHash()]

        hdlr.send_message(msg_capdmsg([m]))
        # Wait for the node to INV me with my own message
        waitFor(30, lambda: hdlr.lastCapdInvHashes)

        # This checks the communications protocol and that both sides calculated the same hash for the same message, which
        # tests both the message serialization integrity, the hash algorithm, and endianness when converting hash bytes to numbers
        # because if the conversion is wrong, the incorrect hash-as-integer will be very likely to be > the target so won't be inserted or relayed
        assert_equal(hdlr.lastCapdInvHashes[0], m.calcHash())

        # Test propagation protocol since node 0 and node 1 should run the INV, GETCAPDMSG, CAPDMSG protocol when I gave node 0 a new message
        assert_equal(self.nodes[1].capd()["count"], 1)

        # Let's do queries to see if the message is matched, and other queries do not match
        # 2 bytes
        worked = [0]
        def qReply(c,msg, msgHashes=True, expectedCookie=None, expectedTotal=None, expectedMsg=None):
            logging.info("Received query reply: %s" % str(msg))
            check(len(msg.msgs) >= 1 and len(msg.msgs) <= 3)
            assert type(msg) == test_framework.bumessages.msg_capdqreply, "incorrect message type, expecting capdqreply"
            if expectedCookie != None: assert msg.cookie == expectedCookie, "incorrect capdqreply msg cookie"
            if expectedTotal != None: assert msg.totalMsgs == expectedTotal, "incorrect capdqreply total %d expecting %d" % ( msg.totalMsgs, expectedTotal)
            # check that every message is deserializable
            if msgHashes:
                for m in msg.msgs:
                    assert len(m) == 32, "message hash is incorrect length %s" % len(m)
            else:
                for m in msg.msgs:
                    assert type(m) == CapdMsg, "incorrect data object, expecting a capd message"
            if expectedMsg != None:
                if type(expectedMsg) == CapdMsg:
                    # because object comparison compares references, compare serialized representations 
                    assert expectedMsg.serialize() in [x.serialize() for x in msg.msgs]
                else:
                    assert expectedMsg in msg.msgs, "capdqreply message not found"
            worked[0] += 1
        # try a query asking for the message hash
        hdlr.sendHandleQuery(msg_capdquery(1234,CAPD_QUERY_TYPE_MSG_HASH,0,10,b"th"), lambda c,msg: qReply(c,msg, True, 1234,1, firstMsgHash))
        waitFor(TIMEOUT, lambda: len(hdlr.todo)>0)
        hdlr.doJobs()

        hdlr.send_message(msg_capdgetinfo())
        waitFor(TIMEOUT, lambda: hdlr.capdinfo != None)
        # we know these values because only 1 message inserted
        assert hdlr.capdinfo.localPriority == 1.0
        assert hdlr.capdinfo.relayPriority == 2.0
        assert hdlr.capdinfo.highestPriority > 2.5  # might change since the priority of messages falls as time goes by so use >

        # try a query asking for the message
        hdlr.sendHandleQuery(msg_capdquery(1234,CAPD_QUERY_TYPE_MSG,0,10,b"th"), lambda c,msg: qReply(c,msg, False, 1234,1, m))
        waitFor(TIMEOUT, lambda: len(hdlr.todo)>0)
        hdlr.doJobs()

        # Verify propagation
        assert len(self.nodes[0].capd("list")) == 1
        assert len(self.nodes[1].capd("list")) == 1


        # install a notification
        workedNotify = [0]
        def tnotify(c,msg):
            check(len(msg.msgs) == 1)
            workedNotify[0] += 1
        hdlr.sendHandleQuery(msg_capdquery(2234,CAPD_QUERY_TYPE_MSG_HASH | CAPD_QUERY_TYPE_NOTIFICATION,0,10,b"th"), tnotify)
        waitFor(TIMEOUT, lambda: len(hdlr.todo)>0)   # We should get an immediate notify for anything currently in the msgpool
        hdlr.doJobs()
        waitFor(TIMEOUT, lambda: workedNotify[0] == 1)

        # See if it notifies us asynchronously: just sending a message should hand us a notification, no query required
        m1 = CapdMsg(b"this is another test..")
        m1.solve(4)
        msgHashes.append(m1.calcHash())
        hdlr.send_message(msg_capdmsg([m1]))
        waitFor(TIMEOUT, lambda: len(hdlr.todo)>0)
        hdlr.doJobs()
        waitFor(TIMEOUT, lambda: workedNotify[0] == 2)  # We should get another notify

        # we shouldn't get an async notify because wrong pattern
        m1 = CapdMsg(b"his is another test..")
        m1.solve(4)
        msgHashes.append(m1.calcHash())
        hdlr.send_message(msg_capdmsg([m1]))

        time.sleep(2)
        assert workedNotify[0] == 2

        # Remove the notification we set up
        hdlr.removeNotification(2234)

        # we shouldn't get an async notify because we removed it
        m1 = CapdMsg(b"this is another another test..")
        m1.solve(4)
        msgHashes.append(m1.calcHash())
        hdlr.send_message(msg_capdmsg([m1]))

        time.sleep(2)
        assert workedNotify[0] == 2

        hdlr.setAsyncMsgProcessing()
        worked = [0]  # Reset count for next test sequence

        # this handler expects a bad match
        def expectNone(c,msg):
            assert len(msg.msgs) == 0
            # logging.info("Received None reply")
            worked[0] += 1
        hdlr.sendHandleQuery(msg_capdquery(1235,CAPD_QUERY_TYPE_MSG_HASH,0,10,b"ab"), expectNone)
        waitFor(TIMEOUT, lambda: worked[0] == 1)

        # 4 bytes
        hdlr.sendHandleQuery(msg_capdquery(1236,CAPD_QUERY_TYPE_MSG_HASH,0,10,b"this"), qReply)
        waitFor(TIMEOUT, lambda: worked[0] == 2)
        # should be a bad match
        hdlr.sendHandleQuery(msg_capdquery(1237,CAPD_QUERY_TYPE_MSG_HASH,0,10,b"abcd"), expectNone)
        waitFor(TIMEOUT, lambda: worked[0] == 3)

        # 8 bytes
        hdlr.sendHandleQuery(msg_capdquery(1238,CAPD_QUERY_TYPE_MSG_HASH,0,10,b"this is "), qReply)
        waitFor(TIMEOUT, lambda: worked[0] == 4)
        # should be a bad match
        hdlr.sendHandleQuery(msg_capdquery(1239,CAPD_QUERY_TYPE_MSG_HASH,0,10,b"abcdefgh"), expectNone)
        waitFor(TIMEOUT, lambda: worked[0] == 5)

        # 16 bytes
        hdlr.sendHandleQuery(msg_capdquery(1240,CAPD_QUERY_TYPE_MSG_HASH,0,10,b"this is a test.."), qReply)
        waitFor(TIMEOUT, lambda: worked[0] == 6)
        # should be a bad match
        hdlr.sendHandleQuery(msg_capdquery(1241,CAPD_QUERY_TYPE_MSG_HASH,0,10,b"abcdefghhijklmno"), expectNone)
        waitFor(TIMEOUT, lambda: worked[0] == 7)


        l0 = self.nodes[0].capd("list")
        l1 = self.nodes[1].capd("list")
        assert_equal(l0, l1)

        logging.info("Create 33 messages")
        # Let's create a lot of messages
        hdlr.msgs = {}
        EXP_MSGS = 33
        beginCount = self.nodes[0].capd()["count"]
        for i in range(0,EXP_MSGS):
            m = CapdMsg(b"m" + (b"%02d" % i) + b" a message")
            m.solve(10)
            hdlr.msgs[m.getHash()] = m

        hdlr.send_message(msg_capdinv([ x.getHash() for x in hdlr.msgs.values()]))

        # Wait for all the messages to be loaded into the node
        # Nothing will be aged out because lots of room in the buffer
        waitFor(TIMEOUT, lambda: self.nodes[0].capd()["count"] >= beginCount + EXP_MSGS)

        # Lets see if a query returns a subset of them
        worked = [0]
        replies = []
        def t3(c,msg,w = worked):
            assert len(msg.msgs) == 10, "Expecting 10 messages, got %d, full msg %s" % (len(msg.msgs), str(msg))
            replies.append(set([x.data for x in msg.msgs]))
            w[0] += 1
        hdlr.sendHandleQuery(msg_capdquery(9876,CAPD_QUERY_TYPE_MSG,0,20,b"m0"), t3)
        waitFor(TIMEOUT, lambda: worked[0] == 1)
        hdlr.sendHandleQuery(msg_capdquery(9877,CAPD_QUERY_TYPE_MSG,0,20,b"m1"), t3)
        waitFor(TIMEOUT, lambda: worked[0] == 2)
        hdlr.sendHandleQuery(msg_capdquery(9878,CAPD_QUERY_TYPE_MSG,0,20,b"m2"), t3)
        waitFor(TIMEOUT, lambda: worked[0] == 3)

        assert len(replies) == 3
        # each set should be disjoint because I had different search queries
        assert len(replies[0].intersection(replies[1])) == 0
        assert len(replies[0].intersection(replies[2])) == 0
        assert len(replies[1].intersection(replies[2])) == 0

        try:
            waitFor(TIMEOUT, lambda: sorted(self.nodes[0].capd("list")) == sorted(self.nodes[1].capd("list")))
        except TimeoutException:
            print ("not equal")

        if 0:
            for x in self.nodes:
                print()
                print(x.capd())
                print(x.capd("list"))

        l0 = self.nodes[0].capd("list")
        l1 = self.nodes[1].capd("list")
        assert_equal(sorted(l0),sorted(l1))
        if sorted(l0) != sorted(l1):
            logging.info("incomplete propagation")
            s0 = set(l0)
            s1 = set(l1)
            sleft = s0 - s1
            logging.info("unpropagated: %s" % str(len(sleft)))
            logging.info (sleft)

        c0 = sorted([ hashToHex(x) for x in hdlr.msgs.keys()] + [hashToHex(x) for x in msgHashes])
        assert_equal(c0, sorted(l0))

        self.nodes[0].capd("clear")
        self.nodes[1].capd("clear")
        assert self.nodes[0].capd("info")["count"] == 0
        assert self.nodes[0].capd("info")["size"] == 0
        assert self.nodes[1].capd("info")["count"] == 0

        n0 = []
        n1 = []
        ISSUED=10
        for cnt in range(0,ISSUED):
            m = self.nodes[0].capd("send", "a" + str(cnt))
            m1 = self.nodes[1].capd("send", "b" + str(cnt))
            n0.append(m)
            n1.append(m1)
            logging.info(str(m) + " " + str(m1))

        # check that propagation occurred between the 2 nodes
        waitFor(TIMEOUT, lambda: len(self.nodes[0].capd("list")) == 2*ISSUED)
        waitFor(TIMEOUT, lambda: len(self.nodes[1].capd("list")) == 2*ISSUED)
        l0 = self.nodes[0].capd("list")
        l1 = self.nodes[1].capd("list")
        for n in n0:
            assert n in l0
            assert n in l1
        for n in n1:
            assert n in l1
            assert n in l0

        # reduce the capd message size and validate that it gets pared down
        self.nodes[1].set("cache.maxCapdPool=10000")
        st0 = self.nodes[1].capd()
        assert st0["size"] < 10000
        logging.info(st0)

        logging.info("Create 3500 messages, overflow pool")
        # Generate acceptable messages, given a full msg pool
        hdlr.msgs={}
        msgs = []
        while i < 3500:
            i+=1
            st0 = self.nodes[0].capd()
            pri0 = st0["maxPriority"]
            # logging.info(st0)
            st1 = self.nodes[1].capd()
            pri1 = st0["maxPriority"]
            pri = max(pri0, pri1)
            if i&127 == 0: logging.info("%d: priority: %f, %f -> %f" % (i, pri0, pri1, pri))
            m = CapdMsg(i.to_bytes(2,"big") + (b" 2nd msg count %d" % i))
            m.solve(pri + decimal.Decimal(0.01))
            hdlr.msgs[m.getHash()] = m
            hdlr.send_message(msg_capdinv([ m.getHash()]))
            msgs.append(m)

        # Wait for the message to be pulled into the server
        lastMsg = None
        count = 0
        while count < 10:
            count += 1
            try:
                lastMsg = self.nodes[1].capd("get", hashToHex(msgs[-1].getHash()))
                break
            except: # propagation time
                time.sleep(0.10)

        assert(lastMsg != None)

        # let's do a small query to see the query work with many messages.  We know the last one won't have overflowed
        worked = [0]
        def t4(c,msg,w = worked):
            assert len(msg.msgs) == 1, "Expecting 1 messages, got %d, full msg %s" % (len(msg.msgs), str(msg))
            w[0] += 1
        hdlr.sendHandleQuery(msg_capdquery(8765,CAPD_QUERY_TYPE_MSG,0,20,i.to_bytes(2,"big")), t4)
        waitFor(TIMEOUT, lambda: worked[0] == 1)

        epoch_time = int(time.time())
        epoch_time += 300
        s0 = self.nodes[0].capd()
        m0 = self.nodes[0].capd("get", hashToHex(msgs[-1].getHash()))
        try:
            mF0 = self.nodes[0].capd("get", hashToHex(msgs[0].getHash()))
            assert False, "first message should have aged out"
        except JSONRPCException as e:
            assert True

        self.nodes[0].setmocktime(epoch_time)
        s1 = self.nodes[0].capd()
        m1 = self.nodes[0].capd("get", hashToHex(msgs[-1].getHash()))
        epoch_time += 300
        self.nodes[0].setmocktime(epoch_time)
        s2 = self.nodes[0].capd()
        m2 = self.nodes[0].capd("get", hashToHex(msgs[-1].getHash()))

        # check that the priority continues to fall.
        assert s0["maxPriority"]/s1["maxPriority"] > 1.25, "time priority reduction issue"
        # after half the time, the priority of every message will have halved
        # This is the last message created so priority is falling quickly
        assert m0['priority']/m1['priority'] > 1.99, "time priority reduction issue 2"

        assert_equal(s2["maxPriority"], CAPD_MIN_RELAY_PRIORITY)
        assert_equal(s2["relayPriority"], CAPD_MIN_RELAY_PRIORITY)
        assert_equal(s2["minPriority"], CAPD_MIN_LOCAL_PRIORITY)

        # After 10 minutes the message is fully aged
        assert(m2["priority"] <= 0)

        logging.info("CAPD test finished")
        # time.sleep(1)
        # pdb.set_trace()



if __name__ == '__main__':
    logging.getLogger().setLevel(logging.ERROR)
    MyTest ().main ()

# Create a convenient function for an interactive python debugging session
def Test():
    t = MyTest()
    t.drop_to_pdb=True
    bitcoinConf = {
        "debug": ["capd", "net", "blk", "thin", "mempool", "req", "bench", "evict"],
    }
    logging.getLogger().setLevel(logging.INFO)
    flags = standardFlags()
    flags.append("--tmpdir=/ramdisk/test/t")
    t.main(flags, bitcoinConf, None)
