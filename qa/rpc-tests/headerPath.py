#!/usr/bin/env python3
# Copyright (c) 2015-2023 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
import test_framework.loginit

from itertools import cycle
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

test_framework.nodemessages.MY_SUBVERSION = b"/python-headerpath-tester:0.0.1/"
IGNORE_CHECKSUM_STR = '0000000200000002'
TIMEOUT = 30

def hashToHex(x):
    return x[::-1].hex()

class TestNode():
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
        self.numHeaderPaths = 0
        self.headerPath = None
        self.numNotFound = 0
        self.numRejects = 0
        self.expectedBlockInv = None

    def setAsyncMsgProcessing(self):
        self.todo = None

    def on_version(self, conn, message):
        BUProtocolHandler.on_version(self,conn, message)
        # Tell the node that we are doing cookies not checksums
        conn.send_message(msg_extversion({int(IGNORE_CHECKSUM_STR,16): 1}))

    def on_hdrpath(self, conn, message):
        self.numHeaderPaths += 1
        self.headerPath = message

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

class HeaderPathTest (BitcoinTestFramework):

    def setup_chain(self,bitcoinConfDict=None, wallets=None):
        logging.info("Initializing test directory "+self.options.tmpdir)
        initialize_chain(self.options.tmpdir, bitcoinConfDict, wallets)

    def setup_network(self, split=False):
        self.nodes = start_nodes(2, self.options.tmpdir)
        # Now interconnect the nodes
        connect_nodes_full(self.nodes)
        self.is_network_split=False
        self.sync_blocks()
        self.pynode = pynode = TestNode()
        self.conn = pynode.connect(0, '127.0.0.1', p2p_port(0), self.nodes[0], protohandler = MsgCookieProtoHandler(), send_initial_version = True, extversion_service = True)
        self.nt = NetworkThread()
        self.nt.start()

    def checkHeaderPath(self, hp, startHeight, endHeight, verbose = False):
        assert hp[0].height == startHeight, "checkHeaderPath unexpected start height %d, expected %d" % (hp[0].height, startHeight)
        assert hp[-1].height == endHeight, "checkHeaderPath unexpected end height %d, expected %d" % (hp[-1].height, endHeight)
        cyc = cycle(hp)
        nexthdr = next(cyc)
        while True:
            hdr, nexthdr = nexthdr, next(cyc)
            if verbose: print(hdr)
            if hdr.height == endHeight:
                break
            nexthash = nexthdr.gethash()
            assert nexthash == hdr.hashAncestor or nexthash == hdr.hashPrevBlock, "header chain broken at height %d" % nexthdr.height

    def run_test (self):
        TIMEOUT = 30
        logging.info("Message Header Path Test")
        logging.info(" mining blocks")
        self.nodes[0].generate(100)
        # hand run larger span test
        #self.sync_blocks()
        #self.nodes[0].generate(1500)
        #self.sync_blocks()
        #self.nodes[0].generate(1500)
        #self.sync_blocks()
        #self.nodes[0].generate(1500)
        #self.sync_blocks()
        #self.nodes[0].generate(1500)
        logging.info(" mining blocks complete")
        self.sync_blocks()

        hdlr = self.pynode.cnxns[0]
        self.conn.handle_write() # start a thread up handling received messages
        # Wait for the whole version/extversion protocol to finish
        # Otherwise, peer info data may not be complete
        hdlr.wait_for_verack()

        # Ask for the complete path from the tip to the genesis block
        hdlr.expectedCookie = 3 << 16
        tmp = hdlr.numHeaderPaths + 1
        hdlr.get_header_path(0xFFFFFFFF, 0, hdlr.expectedCookie)
        waitFor(TIMEOUT, lambda: hdlr.numHeaderPaths == tmp)
        headerPath = hdlr.headerPath.headers
        self.checkHeaderPath(headerPath, headerPath[0].height, 0)
        logging.info("complete headers %d -> %d in %d steps" % (headerPath[0].height, headerPath[-1].height, len(hdlr.headerPath.headers)))
        hdlr.headerPath.headers = []

        logging.info(" try a path using hashes")
        # grab them from the prior path query
        ahash = headerPath[1%len(headerPath)].hashPrevBlock
        ah    = headerPath[1%len(headerPath)].height-1
        bhash = headerPath[3%len(headerPath)].hashPrevBlock
        bh    = headerPath[3%len(headerPath)].height-1
        tmp = hdlr.numHeaderPaths + 1
        hdlr.get_header_path(ahash, bhash, hdlr.expectedCookie)
        waitFor(TIMEOUT, lambda: hdlr.numHeaderPaths == tmp)
        self.checkHeaderPath(hdlr.headerPath.headers, ah, bh)

        # Degenerate case, ask for a single header at some height
        hdlr.expectedCookie = 3 << 16
        tmp = hdlr.numHeaderPaths + 1
        hdlr.get_header_path(100, 100, hdlr.expectedCookie)
        waitFor(TIMEOUT, lambda: hdlr.numHeaderPaths == tmp)
        headerPath = hdlr.headerPath.headers
        self.checkHeaderPath(headerPath, 100, 100)
        assert len(hdlr.headerPath.headers)==1

        logging.info(" negative tests")
        hdlr.get_header_path(10, 100, hdlr.expectedCookie)  # backwards
        hdlr.get_header_path(9, 10, hdlr.expectedCookie)    # backwards
        hdlr.get_header_path(bhash, ahash, hdlr.expectedCookie)    # backwards
        hdlr.get_header_path(ahash+1, bhash, hdlr.expectedCookie)  # bad hash
        hdlr.get_header_path(1000000, 50, hdlr.expectedCookie)  # beyond tip
        waitFor(TIMEOUT, lambda: hdlr.numRejects == 5)

        logging.info(" random test")
        tipHeight = self.nodes[0].getblockcount()

        for i in range(0,10):
            a = random.randrange(tipHeight+1)
            b = random.randrange(tipHeight+1)
            if b > a:
                tmp2 = a
                a = b
                b = tmp2

            tmp = hdlr.numHeaderPaths + 1
            hdlr.get_header_path(a, b, hdlr.expectedCookie)
            # print("headers path %d -> %d" % (a,b))
            waitFor(TIMEOUT, lambda: hdlr.numHeaderPaths == tmp)
            logging.info("headers path %d -> %d in %d steps" % (a,b,len(hdlr.headerPath.headers)))
            self.checkHeaderPath(hdlr.headerPath.headers, a, b)



if __name__ == '__main__':
    logging.getLogger().setLevel(logging.ERROR)
    HeaderPathTest().main ()

# Create a convenient function for an interactive python debugging session
def Test():
    t = HeaderPathTest()
    t.drop_to_pdb=True
    bitcoinConf = {
        "debug": ["capd", "net", "blk", "thin", "mempool", "req", "bench", "evict"],
    }
    logging.getLogger().setLevel(logging.INFO)
    flags = standardFlags()
    flags.append("--tmpdir=/ramdisk/test/t")
    t.main(flags, bitcoinConf, None)
