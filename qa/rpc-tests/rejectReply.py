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
from test_framework.bunode import *
from test_framework.mininode import *
from test_framework.nodemessages import *
import test_framework.nodemessages
from test_framework.bumessages import *

test_framework.nodemessages.MY_SUBVERSION = b"/python-cookie-tester:0.0.1/"

CAPD_MSG_TYPE = 72

CAPD_QUERY_MAX_MSGS = 200
CAPD_QUERY_MAX_INVS = 2000

IGNORE_CHECKSUM_STR = '0000000200000002'

TIMEOUT = 30

class CookieTestNode():
    def __init__(self):
        self.cnxns = {}
        self.nblocks = 0
        self.nthin = 0
        self.nxthin = 0

    def connect(self, id, ip, port, rpc=None, protohandler=None, send_initial_version = True, extversion_service = True):
        if not protohandler:
            protohandler = BUProtocolHandler()
        conn = NodeConn(ip, port, rpc, protohandler, services=NODE_NETWORK | NODE_EXTVERSION, send_initial_version = send_initial_version, extversion_service = extversion_service)
        protohandler.add_connection(conn)
        protohandler.add_parent(self)
        self.cnxns[id] = protohandler
        return conn

class MsgCookieProtoHandler(BUProtocolHandler):
    def __init__(self):
        BUProtocolHandler.__init__(self, extversion=True)
        self.lastCapdGetMsg = None
        self.numCapdGetMsg = 0
        self.lastCapdInvHashes = None
        self.numInvMsgs = 0
        self.callbacks = {}
        self.msgs = {}  # messages to auto-reply with based on a request message
        self.capdinfo = None
        self.expectedCookie = 0
        self.todo = []
        self.numBlocks = 0
        self.numFilteredBlocks = 0
        self.numTxes = 0
        self.numInvs = 0
        self.numNotFound = 0
        self.numRejects = 0
        self.expectedBlockInv = None
        self.invs = []
        self.printReject = False

    def setAsyncMsgProcessing(self):
        self.todo = None

    def on_version(self, conn, message):
        BUProtocolHandler.on_version(self,conn, message)
        # Tell the node that we are doing cookies not checksums
        conn.send_message(msg_extversion({int(IGNORE_CHECKSUM_STR,16): 1}))

    def on_block(self, conn, message):
        # print("block cookie %x" % self.cookie)
        assert (self.cookie == self.expectedCookie) or (self.cookie ==  self.expectedCookie | 0xFFFF), "Incorrect message cookie on block receipt expected %x got %x" % (self.expectedCookie, self.cookie)
        self.expectedCookie += 1
        self.numBlocks += 1

    def on_merkleblock(self, conn, message):
        # print("merkle block cookie %x" % self.cookie)
        assert (self.cookie == self.expectedCookie) or (self.cookie ==  self.expectedCookie | 0xFFFF), "Incorrect message cookie on block receipt expected %x got %x" % (self.expectedCookie, self.cookie)
        self.expectedCookie += 1
        self.numFilteredBlocks += 1

    def on_tx(self, conn, message):
        # print("tx cookie %x" % self.cookie)
        assert (self.cookie == self.expectedCookie) or (self.cookie ==  self.expectedCookie | 0xFFFF), "Incorrect message cookie on block receipt expected %x got %x" % (self.expectedCookie, self.cookie)
        self.expectedCookie += 1
        self.numTxes += 1

    def on_inv(self, conn, message):
        BUProtocolHandler.on_inv(self, conn, message)
        for inv in message.inv:
            self.invs.append(inv)
        self.numInvs += 1

    def on_notfound(self, conn, message):
        # print("Got not found")
        assert (self.cookie == self.expectedCookie) or (self.cookie ==  self.expectedCookie | 0xFFFF), "Incorrect message cookie on block receipt expected %x got %x" % (self.expectedCookie, self.cookie)
        self.expectedCookie += 1
        self.numNotFound += 1

    def on_reject(self, conn, message):
        # if client sent GETDATA with multiple items, you can get rejects that are not terminating.
        if self.printReject or (self.cookie != self.expectedCookie | 0xFFFF) and (self.cookie != self.expectedCookie):
            print("reject: %d expected %d --  %s" % (self.cookie, self.expectedCookie | 0xFFFF, str(message)))
        self.numRejects += 1


def hex2Num(x):
    return int(x, 16)

class MsgRejectTest (BitcoinTestFramework):

    # mine count blocks and return the new tip
    def mine_blocks(self, count):
        self.nodes[0].generate(count)
        return hex2Num(self.nodes[0].getbestblockhash())

    def setup_chain(self,bitcoinConfDict=None, wallets=None):
        logging.info("Initializing test directory "+self.options.tmpdir)
        bitcoinConfDict.update({ "maxsendbuffer":2})
        initialize_chain(self.options.tmpdir, bitcoinConfDict, wallets)

    def setup_network(self, split=False):
        self.nodes = start_nodes(2, self.options.tmpdir)
        # Now interconnect the nodes
        connect_nodes_full(self.nodes)
        self.is_network_split=False
        self.sync_blocks()
        self.pynode = pynode = CookieTestNode()
        self.conn = pynode.connect(0, '127.0.0.1', p2p_port(0), self.nodes[0], protohandler = MsgCookieProtoHandler(), send_initial_version = True, extversion_service = True)
        self.nt = NetworkThread()
        self.nt.start()

    def run_test (self):
        TIMEOUT = 30
        logging.info("Message Reply Reject Test")

        # generate 1 block to kick nodes out of IBD mode
        tip = self.mine_blocks(1)
        self.sync_blocks()

        hdlr = self.pynode.cnxns[0]
        self.conn.handle_write() # start a thread up handling received messages
        # Wait for the whole version/extversion protocol to finish
        # Otherwise, peer info data may not be complete
        hdlr.wait_for_verack()

        # Ask for the latest block hash
        hdlr.expectedCookie = 3 << 16
        hdlr.expectedBlockInv = tip
        tmp = hdlr.numInvs + 1
        hdlr.get_data_blocks_with_cookie([0], hdlr.expectedCookie)
        waitFor(TIMEOUT, lambda: hdlr.numInvs == tmp)
        hdlr.expectedBlockInv = None

        # The test strategy here is to set up variables in the comm handler (MsgCookieProtoHandler) that define
        # what responses we expect, and then to issue a request.

        # The response(es) will be handled by callbacks to the comm handler in a separate thread.
        # These handlers check various expected values, and increment state variables.

        # Back in this thread, we "waitFor" the proper state to ensure that replies were processed.

        # If we give unknown objects in the inv, we should get NOT_FOUND back
        hdlr.expectedCookie = 1 << 16
        ivNotFound = CInv(CInv.MSG_BLOCK, 1234)  # Bad inv
        miv = msg_getdata(ivNotFound)
        hdlr.send_message_with_cookie(miv, hdlr.expectedCookie)
        waitFor(TIMEOUT, lambda: hdlr.numNotFound == 1)
        hdlr.expectedCookie = 1 << 16
        iv = CInv(CInv.MSG_FILTERED_BLOCK, 1234)  # Bad inv
        miv = msg_getdata(iv)
        hdlr.send_message_with_cookie(miv, hdlr.expectedCookie)
        waitFor(TIMEOUT, lambda: hdlr.numNotFound == 2)
        hdlr.expectedCookie = 1 << 16
        iv = CInv(CInv.MSG_CMPCT_BLOCK, 1234)  # Bad inv
        miv = msg_getdata(iv)
        hdlr.send_message_with_cookie(miv, hdlr.expectedCookie)
        waitFor(TIMEOUT, lambda: hdlr.numNotFound == 3)


        # build a fork
        self.nodes[0].generate(1)
        orphanTipHash = self.nodes[0].getbestblockhash()
        orphanTip =  hex2Num(orphanTipHash)
        self.nodes[0].generate(1)
        orphanTipHash2 = self.nodes[0].getbestblockhash()
        orphanTip2 =  hex2Num(orphanTipHash2)

        self.nodes[0].invalidateblock(orphanTipHash)
        newTip = self.mine_blocks(3)

        # Should not have had rejects yet
        assert hdlr.numRejects == 0, "We got some rejects but should not have"

        # Lets make sure something works
        hdlr.numBlocks = 0
        miv = msg_getdata(CInv(CInv.MSG_BLOCK, newTip))
        hdlr.send_message_with_cookie(miv, hdlr.expectedCookie)
        waitFor(TIMEOUT, lambda: hdlr.numBlocks == 1)

        # This filter matches all transactions, because what we want to test is that
        # the cookie increments properly, not that bloom filtering really works.
        filt = CBloomFilter(bytes.fromhex("ffff"), 1, 1, 0)
        hdlr.install_bloom_filter(filt)

        # If we give an off-main-chain object, we should get REJECT back
        hdlr.numRejects = 0
        hdlr.expectedCookie = 1 << 16
        iv = CInv(CInv.MSG_BLOCK, orphanTip)  # off-main-chain inv
        miv = msg_getdata(iv)
        hdlr.send_message_with_cookie(miv, hdlr.expectedCookie)
        waitFor(TIMEOUT, lambda: hdlr.numRejects == 1)

        iv = CInv(CInv.MSG_FILTERED_BLOCK, orphanTip)  # off-main-chain inv
        miv = msg_getdata(iv)
        hdlr.send_message_with_cookie(miv, hdlr.expectedCookie)
        waitFor(TIMEOUT, lambda: hdlr.numRejects == 2)

        iv = CInv(CInv.MSG_CMPCT_BLOCK, orphanTip)  # off-main-chain inv
        miv = msg_getdata(iv)
        hdlr.send_message_with_cookie(miv, hdlr.expectedCookie)
        waitFor(TIMEOUT, lambda: hdlr.numRejects == 3)

        # Verify that 2 off-tip invs gives 2 rejects
        ivOffMain = CInv(CInv.MSG_FILTERED_BLOCK, orphanTip)  # off-main-chain inv
        iv2 = CInv(CInv.MSG_FILTERED_BLOCK, orphanTip2)  # off-main-chain inv
        miv = msg_getdata([ivOffMain,iv2])
        hdlr.send_message_with_cookie(miv, hdlr.expectedCookie)
        waitFor(TIMEOUT, lambda: hdlr.numRejects == 5)

        # Verify that 1 off-tip invs and 1 unknown inv gives 1 reject 1 notfound
        miv = msg_getdata([ivOffMain,ivNotFound])
        hdlr.send_message_with_cookie(miv, hdlr.expectedCookie)
        waitFor(TIMEOUT, lambda: hdlr.numRejects == 6)
        waitFor(TIMEOUT, lambda: hdlr.numNotFound == 4)

        #print("orphan tips 0x%x 0x%x" % (orphanTip, orphanTip2))
        #print("New tip %d 0x%x: " % (newTip, newTip) )

        # Ask for so many blocks that we run out of send space, to ensure that the full node properly defers the reqs
        # to another send attempt
        bbc = self.nodes[0].getblockcount()
        lotsInvs = []
        for n in range(bbc-100,bbc):
            b = self.nodes[0].getblock(n)
            cinv = CInv(CInv.MSG_BLOCK, hex2Num(b['hash']))
            lotsInvs.append(cinv)

        hdlr.numRejects = 0
        hdlr.numFilteredBlocks = 0
        hdlr.numNotFound = 0
        hdlr.numBlocks = 0
        hdlr.printReject = True
        biv = msg_getdata(lotsInvs)
        hdlr.send_message_with_cookie(biv, hdlr.expectedCookie)

        # All blocks should be handled because the full node defers processing whenever
        # the send buffer size is exceeded (except for at least 1 message)
        waitFor(TIMEOUT, lambda:
                [print("Rejects %d  Blocks: %d" % (hdlr.numRejects, hdlr.numBlocks)), hdlr.numBlocks == 100][1])



if __name__ == '__main__':
    logging.getLogger().setLevel(logging.ERROR)
    MsgRejectTest().main ()

# Create a convenient function for an interactive python debugging session
def Test():
    t = MsgRejectTest()
    t.drop_to_pdb=True
    bitcoinConf = {
        "debug": ["capd", "net", "blk", "thin", "mempool", "req", "bench", "evict"],
    }
    logging.getLogger().setLevel(logging.INFO)
    flags = standardFlags()
    flags.append("--tmpdir=/ramdisk/test/t")
    t.main(flags, bitcoinConf, None)
