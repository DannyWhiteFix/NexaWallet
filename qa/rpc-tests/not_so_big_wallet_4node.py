#!/usr/bin/env python3
# Copyright (c) 2015-2022 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
import test_framework.loginit
# This is a template to make creating new QA tests easy.
# You can also use this template to quickly start and connect a few regtest nodes.

import timeit
import time
import sys
if sys.version_info[0] < 3:
    raise "Use Python 3"
import logging

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *

class BigWallet (BitcoinTestFramework):

    def setup_chain(self,bitcoinConfDict=None, wallets=None):
        print("Initializing test directory " + self.options.tmpdir)
        # pick this one to start from the cached 4 node 100 blocks mined configuration
        initialize_chain(self.options.tmpdir, bitcoinConfDict, wallets)
        # pick this one to start at 0 mined blocks
        #initialize_chain_clean(self.options.tmpdir, 4, bitcoinConfDict, wallets)

    def setup_network(self, split=False):
        self.nodes = start_nodes(4, self.options.tmpdir)

        # Now interconnect the nodes
        connect_nodes_full(self.nodes)
        # Let the framework know if the network is fully connected.
        # If not, the framework assumes this partition: (0,1) and (2,3)
        # For more complex partitions, you can't use the self.sync* member functions
        self.is_network_split=False
        self.sync_blocks()

    def run_test (self):

        logging.info("Create a large wallet via sending lots of small amounts")
        logging.info("Every 500 txs a consolidate (1000,256) for node0 is executed, mine a block every 100 txs")

        # generate enough blocks so that nodes[0] has a balance
        self.sync_blocks()
        self.nodes[1].generate(1)
        self.nodes[2].generate(1)
        self.nodes[3].generate(1)
        self.nodes[0].generate(1)
        self.sync_blocks()

        waitFor(5, lambda: self.nodes[2].getbalance() > 0)
        waitFor(5, lambda: self.nodes[3].getbalance() > 0)

        dest=self.nodes[0].getnewaddress()
        cons_dest=self.nodes[0].getnewaddress()
        # perform 10K txs 2000 from each node.
        # At the current oerformance rate the test took around 850sec
        # if you go higher, eg 40K txs you can go over the 1hr mark,
        # one such test excuted in 4030 sec last time I run it
        for i in range(0, 10000, 4):
            self.nodes[0].sendtoaddress(dest, 7)
            self.nodes[1].sendtoaddress(dest, 7)
            self.nodes[2].sendtoaddress(dest, 7)
            self.nodes[3].sendtoaddress(dest, 7)
            if ((i % 100) == 0):
                self.nodes[0].generate(1)
                self.sync_blocks()
            if ((i % 500) == 0):
                self.nodes[0].consolidate(1000,256)

        # mine one last blocks
        self.nodes[0].generate(1)
        self.sync_blocks()

        # count utxos number and balance before doing a  big final consolidation
        logging.info("Balance: " + str(self.nodes[0].getbalance()) + " - Utxos cardinality: " + str(len(self.nodes[0].listunspent(0))));
        # measure the performance of `getbalance` and `listunspent`
        logging.info("Finished sending transaction, now it's time to track getbalance/listunspent performance")
        getbalance_ex_time = timeit.timeit(lambda: self.nodes[0].getbalance(), number=10) / 10
        logging.info("Average getbalance time over 10 run: " + str(getbalance_ex_time))
        listunspent_ex_time = timeit.timeit(lambda: self.nodes[0].listunspent(0), number=10) /10
        logging.info("Average listunspent execution time over 10 run: " + str(listunspent_ex_time))

        # perform a big consolidation,
        logging.info("Perform a consolidation over 20K utxos")
        self.nodes[0].consolidate(20000, 1)
        # perform a warm up get balance so that we can updat the map of all ready to spend output
        self.nodes[0].getbalance()

        # measure the performance of `getbalance` and `listunspent`after the warm up `getbalance`
        logging.info("Measuring execution time of getbalance/listunspent after consolidating")
        getbalance_ex_time = timeit.timeit(lambda: self.nodes[0].getbalance(), number=10) / 10
        logging.info("Average getbalance time over 10 run: " + str(getbalance_ex_time))
        listunspent_ex_time = timeit.timeit(lambda: self.nodes[0].listunspent(0), number=10) /10
        logging.info("Average listunspent execution time over 10 run: " + str(listunspent_ex_time))

        # example of stopping and restarting the nodes
        stop_nodes(self.nodes)
        wait_bitcoinds()


if __name__ == '__main__':
    BigWallet().main()

# Create a convenient function for an interactive python debugging session
def Test():
    t = BigWallet()
    t.drop_to_pdb = True
    # install ctrl-c handler
    #import signal, pdb
    #signal.signal(signal.SIGINT, lambda sig, stk: pdb.Pdb().set_trace(stk))
    bitcoinConf = {
        "debug": ["bench"],
    }
    logging.getLogger().setLevel(logging.INFO)
    flags = standardFlags()
    t.main(flags, bitcoinConf, None)
