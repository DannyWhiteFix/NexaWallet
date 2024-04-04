#!/usr/bin/env python3
# Copyright (c) 2015-2018 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# This is a template to make creating new QA tests easy.
# You can also use this template to quickly start and connect a few regtest nodes.

from itertools import cycle, tee
import io
import time
import sys
if sys.version_info[0] < 3:
    raise "Use Python 3"
import logging
from pathlib import Path
logging.basicConfig(format='%(asctime)s.%(levelname)s: %(message)s', level=logging.INFO,stream=sys.stdout)

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *

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

    def run_test (self):
        startTime = time.time()
        sleepInterval = 10
        count = 0
        while 1:
            curTime = time.time()
            blocks = self.node.getblockcount()
            txpool = self.node.gettxpoolinfo()
            elapsed = curTime - startTime
            print("Time: %3.6f blocks: %d txpool: %s" % (elapsed, blocks, str(txpool)))
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
