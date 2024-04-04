#!/usr/bin/env python3
# Copyright (c) 2015-2018 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# This is a template to make creating new QA tests easy.
# You can also use this template to quickly start and connect a few regtest nodes.

from itertools import cycle, tee
import io
from pathlib import Path
import time
import sys
if sys.version_info[0] < 3:
    raise "Use Python 3"
import logging
logging.basicConfig(format='%(asctime)s.%(levelname)s: %(message)s', level=logging.INFO,stream=sys.stdout)

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *

from test_framework.util import *
from test_framework.bunode import *
from test_framework.mininode import *
from test_framework.nodemessages import *
import test_framework.nodemessages
from test_framework.bumessages import *


RPC_USERNAME = None
RPC_PASSWORD = None

TIMEOUT = 30

#testnet
RPC_PORT = 18332
# mainnet
RPC_PORT = 7227

def readNexaConfFile(filepath=None):
    if filepath is None:
        filepath = Path.home() / ".nexa" / "nexa.conf"
    with open(filepath) as f:
        ret = {}
        for line in f:
            print("line:")
            print(line)
            l = line.strip()
            if len(l) > 0 and l[0] != '#':
                kv = l.split("=")
                print(kv)
                ret[kv[0]] = kv[1]
                print(ret)
        return ret

def rpc_url(user=None, password=None, i=None, rpchost=None):
    if user is None:
        cfgfile = readNexaConfFile()
        print(cfgfile)
        user = cfgfile["rpcuser"]
        password = cfgfile["rpcpassword"]
        if i is None:
            i = cfgfile.get("rpcport", RPC_PORT)
    if i is None:
        i = RPC_PORT
    return "http://%s:%s@%s:%d" % (user, password, rpchost or '127.0.0.1', i)


# https://docs.python.org/3.8/library/itertools.html#itertools-recipes
def pairwise(iterable):
    "s -> (s0, s1), (s1, s2), (s2, s3), ..."
    a, b = tee(iterable)
    next(b, None)
    return zip(a, b)

class TestNode():
    def __init__(self):
        self.cnxns = {}
        self.nblocks = 0
        self.nthin = 0
        self.nxthin = 0

    def connect(self, id, ip, port, rpc=None, protohandler=None, send_initial_version = True, extversion_service = True):
        if not protohandler:
            protohandler = BUProtocolHandler()
        conn = NodeConn(ip, port, rpc, protohandler, net="nexa", services=NODE_NETWORK | NODE_EXTVERSION, send_initial_version = send_initial_version, extversion_service = extversion_service)
        protohandler.add_connection(conn)
        protohandler.add_parent(self)
        self.cnxns[id] = protohandler
        return conn

class ProtoHandler(BUProtocolHandler):
    def __init__(self):
        BUProtocolHandler.__init__(self, extversion=True)
        self.numNotFound = 0
        self.numRejects = 0
        self.numInvs = 0

    def setAsyncMsgProcessing(self):
        pass

    def on_version(self, conn, message):
        BUProtocolHandler.on_version(self,conn, message)

    def on_hdrpath(self, conn, message):
        self.numHeaderPaths += 1
        self.headerPath = message

    def on_inv(self, conn, inv):
        print("Got Inv")
        self.numInvs += 1

    def on_notfound(self, conn, message):
        print("Got not found")
        self.numNotFound += 1

    def on_reject(self, conn, message):
        self.numRejects += 1



class MyTest (BitcoinTestFramework):

    def setup_chain(self,bitcoinConfDict=None, wallets=None):
        pass

    def setup_network(self, split=False):
        self.nodes = []
        url = rpc_url(RPC_USERNAME, RPC_PASSWORD)
        print(url)
        self.node = get_rpc_proxy(url, 0, timeout=120)
        self.nodes.append(self.node)
        self.is_network_split=False

        self.pynode = pynode = TestNode()
        self.conn = pynode.connect(0, '127.0.0.1', 7228, self.nodes[0], protohandler = ProtoHandler(), send_initial_version = True, extversion_service = True)
        self.nt = NetworkThread()
        self.nt.start()


    def checkHeaderPath(self, hp, startHeight, endHeight, verbose = False):
        if startHeight != 0xFFFFFFFF:
            assert hp[0].height == startHeight, "checkHeaderPath unexpected start height %d, expected %d" % (hp[0].height, startHeight)
        if endHeight != 0xFFFFFFFF:
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
        mininode = self.pynode.cnxns[0]
        self.conn.handle_write() # start a thread up handling received messages
        # Wait for the whole version/extversion protocol to finish
        # Otherwise, peer info data may not be complete
        mininode.wait_for_verack()
        # ok mininode is connected

        startTime = time.time()
        sleepInterval = 10
        count = 0
        while 1:
            curTime = time.time()
            blocks = self.node.getblockcount()
            txpool = self.node.gettxpoolinfo()
            elapsed = curTime - startTime
            print("Time: %3.6f blocks: %d txpool: %s mininodeInvs: %d" % (elapsed, blocks, str(txpool), mininode.numInvs))
            count+=1
            sleepAmt = startTime+(count*sleepInterval) - curTime # This corrects for the time needed to run the above
            time.sleep(sleepAmt)



if __name__ == '__main__':
    flags = ["--nocleanup","--noshutdown"]
    MyTest ().main (flags)

# Create a convenient function for an interactive python debugging session
def Test():
    t = MyTest()
    bitcoinConf = {}
    flags = ["--nocleanup","--noshutdown"]
    t.main(flags, bitcoinConf, None)
