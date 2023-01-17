#!/usr/bin/env python3
# Copyright (c) 2015-2022 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
import test_framework.loginit
# This is a template to make creating new QA tests easy.
# You can also use this template to quickly start and connect a few regtest nodes.

import time
import sys
if sys.version_info[0] < 3:
    raise "Use Python 3"
import logging
import copy

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from test_framework.nodemessages import *

class MyTest (BitcoinTestFramework):

    def setup_chain(self,bitcoinConfDict=None, wallets=None):
        print("Initializing test directory "+self.options.tmpdir)
        # pick this one to start from the cached 4 node 100 blocks mined configuration
        initialize_chain(self.options.tmpdir, bitcoinConfDict, wallets)
        # pick this one to start at 0 mined blocks
        # initialize_chain_clean(self.options.tmpdir, 1, bitcoinConfDict, wallets)
        # Number of nodes to initialize ----------> ^

    def setup_network(self, split=False):
        self.nodes = start_nodes(1, self.options.tmpdir)
        # Nodes to start --------^
        # Note for this template I readied 4 nodes but only started 2

        # Now interconnect the nodes
        connect_nodes_full(self.nodes)
        # Let the framework know if the network is fully connected.
        # If not, the framework assumes this partition: (0,1) and (2,3)
        # For more complex partitions, you can't use the self.sync* member functions
        self.is_network_split=False
        self.sync_blocks()

    def writeFile(self, name, data):
        f = open(name,"wt")
        f.write(data)
        
    def run_test (self):

        bal = self.nodes[0].getbalance()

        tx = CTransaction()
        self.writeFile("blanktx.hex", tx.toHex())

        addrs = [self.nodes[0].getnewaddress() for x in range(0,10)]

        txidem = self.nodes[0].sendmany("",{addrs[0]: 11, addrs[1]:11})
        txhex = self.nodes[0].getrawtransaction(txidem)
        self.writeFile("tx3x3.hex", txhex)
        txorig = CTransaction(txhex)
        tx = copy.deepcopy(txorig)
        del tx.vin[1]
        self.writeFile("tx3x3-delin1-out.hex", tx.toHex())

        tx = copy.deepcopy(txorig)
        del tx.vout[1]
        self.writeFile("tx3x3-delout1-out.hex", tx.toHex())

        tx = copy.deepcopy(txorig)
        tx.nLockTime = 317000
        self.writeFile("tx3x3-locktime317000-out.hex", tx.toHex())



if __name__ == '__main__':
    MyTest ().main ()

# Create a convenient function for an interactive python debugging session
def Test():
    t = MyTest()
    t.drop_to_pdb = True
    # install ctrl-c handler
    #import signal, pdb
    #signal.signal(signal.SIGINT, lambda sig, stk: pdb.Pdb().set_trace(stk))
    bitcoinConf = {
        "debug": ["net", "blk", "thin", "mempool", "req", "bench", "evict"],
        "blockprioritysize": 2000000  # we don't want any transactions rejected due to insufficient fees...
    }
    logging.getLogger().setLevel(logging.INFO)
    flags = standardFlags()
    t.main(flags, bitcoinConf, None)
