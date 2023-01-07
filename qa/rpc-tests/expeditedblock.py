#!/usr/bin/env python3
# Copyright (c) 2015-2023 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
import test_framework.loginit
# This functionally tests expedited block forwarding.  Its does not make sense to do a perf test
# of this within a QA environment because the nodes share resources...

import time
import sys
if sys.version_info[0] < 3:
    raise "Use Python 3"
import logging

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *

class MyTest (BitcoinTestFramework):

    def setup_chain(self,bitcoinConfDict=None, wallets=None):
        print("Initializing test directory "+self.options.tmpdir)
        # pick this one to start from the cached 4 node 100 blocks mined configuration
        # initialize_chain(self.options.tmpdir, bitcoinConfDict, wallets)
        # pick this one to start at 0 mined blocks
        num_nodes = 4
        for i in range(num_nodes):
            if i < num_nodes:
                bitcoinConfDict["expeditedblock"] = "localhost:" + str(p2p_port(i+1))
            else:
                del bitcoinConfDict["expeditedblock"]
            datadir=initialize_datadir(self.options.tmpdir, i, bitcoinConfDict, wallets)

    def setup_network(self, split=False):
        self.nodes = start_nodes(4, self.options.tmpdir)
        connect_nodes_full(self.nodes)
        self.is_network_split=False

    def run_test (self):
        logging.info("Expedited Block tests")

        # generate enough blocks so that nodes[0] has a balance
        self.sync_blocks()
        self.nodes[0].generate(101)
        waitFor(30, lambda: self.nodes[3].getblockcount() == 101)

        # Restart with a different expedited configuration
        stop_nodes(self.nodes)
        wait_bitcoinds()

        logging.info("Expedited strange config test")
        # node 0 sends to both 1 and 2.  1 & 2 both send to 3, and 3 sends back to 0.
        # A loop should be benign because we don't forward an already-seen block
        self.nodes = start_nodes(4, self.options.tmpdir, [ ["-expeditedblock=localhost:" + str(p2p_port(1)), "-expeditedblock=localhost:" + str(p2p_port(2)), ],
                                                           ["-expeditedblock=localhost:" + str(p2p_port(3))], ["-expeditedblock=localhost:" + str(p2p_port(3))],
                                                           ["-expeditedblock=localhost:" + str(p2p_port(0))]])
        connect_nodes_bi(self.nodes,0,1)
        connect_nodes_bi(self.nodes,1,2)
        connect_nodes_bi(self.nodes,0,2)
        connect_nodes_bi(self.nodes,2,3)
        self.sync_blocks()
        self.nodes[0].generate(10)
        waitFor(30, lambda: self.nodes[3].getblockcount() == 111)
        self.nodes[1].generate(10)
        waitFor(30, lambda: self.nodes[0].getblockcount() == 121)


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
    }
    logging.getLogger().setLevel(logging.INFO)
    flags = standardFlags()
    t.main(flags, bitcoinConf, None)
