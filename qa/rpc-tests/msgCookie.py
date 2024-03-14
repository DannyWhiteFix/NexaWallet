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

def hashToHex(x):
    return x[::-1].hex()

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
            # print("Got INV %d" % inv.type)
            if inv.type == CInv.MSG_BLOCK:
                if self.expectedBlockInv != None:
                    assert inv.hash == self.expectedBlockInv
        self.numInvs += 1

    def on_notfound(self, conn, message):
        # print("Got not found")
        assert (self.cookie == self.expectedCookie) or (self.cookie ==  self.expectedCookie | 0xFFFF), "Incorrect message cookie on block receipt expected %x got %x" % (self.expectedCookie, self.cookie)
        self.expectedCookie += 1
        self.numNotFound += 1

    def on_reject(self, conn, message):
        assert (self.cookie == self.expectedCookie | 0xFFFF), "Incorrect message cookie on block receipt expected %x got %x" % (self.expectedCookie, self.cookie)
        self.numRejects += 1
        


def hex2Num(x):
    return int(x, 16)

class MsgCookieTest (BitcoinTestFramework):

    # mine count blocks and return the new tip
    def mine_blocks(self, count):
        self.nodes[0].generate(count)
        return int(self.nodes[0].getbestblockhash(), 16)

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
        self.pynode = pynode = CookieTestNode()
        self.conn = pynode.connect(0, '127.0.0.1', p2p_port(0), self.nodes[0], protohandler = MsgCookieProtoHandler(), send_initial_version = True, extversion_service = True)
        self.nt = NetworkThread()
        self.nt.start()

    def run_test (self):
        TIMEOUT = 30
        logging.info("Message Cookie test")

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

        # print("try a bad transaction")
        hdlr.expectedCookie = 1 << 16
        tx = CTransaction()
        mtx = msg_tx(tx)
        hdlr.send_message_with_cookie(mtx, hdlr.expectedCookie)
        waitFor(TIMEOUT, lambda: hdlr.numRejects == 1)

        # print("Ask for blocks")
        hdlr.expectedCookie = 2 << 16
        hdlr.get_data_blocks_with_cookie([tip], hdlr.expectedCookie)
        waitFor(TIMEOUT, lambda: hdlr.numBlocks == 1)

        tip2 = self.mine_blocks(1)
        hdlr.expectedCookie = 4 << 16
        hdlr.get_data_blocks_with_cookie([tip, tip2], hdlr.expectedCookie)
        waitFor(TIMEOUT, lambda: hdlr.numBlocks == 3)

        tip3 = self.mine_blocks(1)
        hdlr.expectedCookie = 5 << 16
        hdlr.get_data_blocks_with_cookie([tip, tip2, tip3], hdlr.expectedCookie)
        waitFor(TIMEOUT, lambda: hdlr.numBlocks == 6)

        # print("Ask for transactions")
        node = self.nodes[0]
        addr = node.getnewaddress()
        txIdems = [node.sendtoaddress(addr, 1000),node.sendtoaddress(addr, 2000),node.sendtoaddress(addr, 3000)]
        # print(txIdems)
        txIds = [ node.gettransaction(x)["txid"] for x in txIdems ]
        txes = [hex2Num(x) for x in txIds]

        hdlr.expectedCookie = 6 << 16
        hdlr.get_data_txes_with_cookie([txes[0]], hdlr.expectedCookie)
        waitFor(TIMEOUT, lambda: hdlr.numTxes == 1)

        hdlr.expectedCookie = 7 << 16
        hdlr.get_data_txes_with_cookie([txes[0], txes[1]], hdlr.expectedCookie)
        waitFor(TIMEOUT, lambda: hdlr.numTxes == 3)

        hdlr.expectedCookie = 8 << 16
        hdlr.get_data_txes_with_cookie(txes, hdlr.expectedCookie)
        waitFor(TIMEOUT, lambda: hdlr.numTxes == 6)

        # print("Trying nonexistent transactions")
        hdlr.expectedCookie = 9 << 16
        hdlr.get_data_txes_with_cookie([0,1,2], hdlr.expectedCookie)
        waitFor(TIMEOUT, lambda: hdlr.numNotFound == 1)

        # print("Trying nonexistent blocks")
        hdlr.expectedCookie = 10 << 16
        hdlr.get_data_blocks_with_cookie([1], hdlr.expectedCookie)
        waitFor(TIMEOUT, lambda: hdlr.numNotFound == 2)

        # print("Ask for a merkle block")

        # we previously created 3 transactions so this new block will have 4 total
        blockWithTx = self.mine_blocks(1)

        # This filter matches all transactions, because what we want to test is that
        # the cookie increments properly, not that bloom filtering really works.
        filt = CBloomFilter(bytes.fromhex("ffff"), 1, 1, 0)
        hdlr.install_bloom_filter(filt)

        # Reset our transaction count to 0 for ease of testing
        hdlr.numTxes = 0
        hdlr.expectedCookie = 11 << 16
        # Ask for a filtered blocks
        hdlr.get_data_filtered_blocks_with_cookie([blockWithTx], hdlr.expectedCookie)
        # We expect 1 filtered block and 4 transactions because all match
        waitFor(TIMEOUT, lambda: hdlr.numFilteredBlocks == 1)
        waitFor(TIMEOUT, lambda: hdlr.numTxes == 4)  # 1 coinbase tx & 3 txes I created



if __name__ == '__main__':
    logging.getLogger().setLevel(logging.ERROR)
    MsgCookieTest().main ()

# Create a convenient function for an interactive python debugging session
def Test():
    t = MsgCookieTest()
    t.drop_to_pdb=True
    bitcoinConf = {
        "debug": ["capd", "net", "blk", "thin", "mempool", "req", "bench", "evict"],
    }
    logging.getLogger().setLevel(logging.INFO)
    flags = standardFlags()
    flags.append("--tmpdir=/ramdisk/test/t")
    t.main(flags, bitcoinConf, None)
