#!/usr/bin/env python3
# Copyright (c) 2014-2015 The Bitcoin Core developers
# Copyright (c) 2015-2023 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
import test_framework.loginit
#
# Test merkleblock fetch/validation
#

import logging
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *

class TxIndexTest(BitcoinTestFramework):

    def setup_chain(self):
        print("Initializing test directory "+self.options.tmpdir)
        initialize_chain_clean(self.options.tmpdir, 4)

    def setup_network(self):
        self.nodes = []
        self.nodes.append(start_node(0, self.options.tmpdir, ["-debug"]))
        self.nodes.append(start_node(1, self.options.tmpdir, ["-debug", "-txindex=1"]))
        connect_nodes(self.nodes[0], 1)

        self.is_network_split = False
        self.sync_all()

    def get_rawtransaction(self, node, txn):
        try:
            node.getrawtransaction(txn)
            return True
        except JSONRPCException as e:
            return False

    def run_test(self):
        logging.info("Mining blocks...")
        self.nodes[0].generate(101)
        self.sync_all()

        # Check that node0 has no txindex available.
        logging.info("Checking non txindex on node0...")
        waitFor(30, lambda: self.nodes[0].getinfo()["txindex"] == "not ready")
        for i in range(1, self.nodes[0].getblockcount()):
            blockhash = self.nodes[0].getblockhash(i)
            txns = self.nodes[0].getblock(blockhash)['txid']
            for tx in txns:
               waitFor(30, lambda: self.get_rawtransaction(self.nodes[0], tx) == False)

        # Check node1 can find all blockchain txns in the txindex
        logging.info("Checking txindex on node1...")
        waitFor(30, lambda: self.nodes[1].getblockcount() == 101)
        waitFor(30, lambda: self.nodes[1].getinfo()["txindex"] == "synced")
        for i in range(self.nodes[1].getblockcount()):
            blockhash = self.nodes[1].getblockhash(i)
            txns = self.nodes[1].getblock(blockhash)['txid']
            for tx in txns:
               waitFor(30, lambda: self.get_rawtransaction(self.nodes[1], tx) == True)
            txns = self.nodes[1].getblock(blockhash)['txidem']
            for tx in txns:
               waitFor(30, lambda: self.get_rawtransaction(self.nodes[1], tx) == True)

        # Check we can not find an invalid tx
        logging.info("Checking invalid tx...")
        try:
            self.nodes[0].getrawtransaction(self.nodes[0].getbestblockhash())
        except JSONRPCException as e:
            assert("No such txpool transaction. Use -txindex" in e.error['message'])
        try:
            self.nodes[1].getrawtransaction(self.nodes[0].getbestblockhash())
        except JSONRPCException as e:
            assert("No such txpool or blockchain transaction. Use gettransaction" in e.error['message'])

        # add to the txpool, should be able to find it now on either peer
        logging.info("Checking tx added to txpool...")
        address = self.nodes[0].getnewaddress("test")
        txid = self.nodes[0].sendtoaddress(address, 10, "", "", True)
        self.sync_all()
        waitFor(30, lambda: self.get_rawtransaction(self.nodes[1], tx) == True)

        logging.info("Checking mined tx...")
        self.nodes[0].generate(1)
        self.sync_all()
        waitFor(30, lambda: self.get_rawtransaction(self.nodes[0], tx) == True)
        waitFor(30, lambda: self.get_rawtransaction(self.nodes[1], tx) == True)

        # Mine a few more blocks and see that they are reflected in the txindex correctly
        logging.info("Mining blocks...")
        self.nodes[0].generate(5)
        self.sync_all()

        logging.info("Checking txindex on node1...")
        waitFor(30, lambda: self.nodes[1].getblockcount() == 107)
        waitFor(30, lambda: self.nodes[1].getinfo()["txindex"] == "synced")
        for i in range(self.nodes[1].getblockcount()):
            blockhash = self.nodes[1].getblockhash(i)
            txns = self.nodes[1].getblock(blockhash)['txid']
            for tx in txns:
                waitFor(30, lambda: self.get_rawtransaction(self.nodes[1], tx) == True)
            txns = self.nodes[1].getblock(blockhash)['txidem']
            for tx in txns:
                waitFor(30, lambda: self.get_rawtransaction(self.nodes[1], tx) == True)

        #### Restart with txindex turned off, mine some blocks and then restart with txindex on.
        #    The txindex should automatically catch up and the new entries should be acessible.
        logging.info("Restarting...")
        stop_nodes(self.nodes)
        wait_bitcoinds()

        self.nodes = []
        self.nodes.append(start_node(0, self.options.tmpdir, ["-debug"]))
        self.nodes.append(start_node(1, self.options.tmpdir, ["-debug"]))
        connect_nodes(self.nodes[0], 1)
        self.is_network_split = False
        self.sync_all()

        logging.info("Mining more blocks...")
        self.nodes[0].generate(10)
        self.sync_all()

        logging.info("Restarting...")
        stop_nodes(self.nodes)
        wait_bitcoinds()

        self.nodes = []
        self.nodes.append(start_node(0, self.options.tmpdir, ["-debug"]))
        self.nodes.append(start_node(1, self.options.tmpdir, ["-debug", "-txindex=1"]))
        connect_nodes(self.nodes[0], 1)
        self.is_network_split = False
        self.sync_all()

        # Check that node0 has no txindex available.
        logging.info("Checking non txindex on node0...")
        waitFor(30, lambda: self.nodes[0].getinfo()["txindex"] == "not ready")
        for i in range(self.nodes[0].getblockcount()):
            blockhash = self.nodes[0].getblockhash(i)
            txns = self.nodes[0].getblock(blockhash)['txid']
            for tx in txns:
                waitFor(30, lambda: self.get_rawtransaction(self.nodes[0], tx) == False)

        # Check node1 can find all blockchain txns in the txindex
        logging.info("Checking txindex on node1...")
        waitFor(30, lambda: self.nodes[1].getblockcount() == 117)
        waitFor(30, lambda: self.nodes[1].getinfo()["txindex"] == "synced")
        for i in range(self.nodes[1].getblockcount()):
            blockhash = self.nodes[1].getblockhash(i)
            txns = self.nodes[1].getblock(blockhash)['txid']
            for tx in txns:
                waitFor(30, lambda: self.get_rawtransaction(self.nodes[1], tx) == True)
            txns = self.nodes[1].getblock(blockhash)['txidem']
            for tx in txns:
                waitFor(30, lambda: self.get_rawtransaction(self.nodes[1], tx) == True)

        # Do a reindex and validate the txindex is working on both nodes
        logging.info("Restarting...")
        stop_nodes(self.nodes)
        wait_bitcoinds()

        self.nodes = []
        self.nodes.append(start_node(0, self.options.tmpdir, ["-debug", "-txindex=1", "-reindex=1"]))
        self.nodes.append(start_node(1, self.options.tmpdir, ["-debug", "-txindex=1", "-reindex=1"]))
        connect_nodes(self.nodes[0], 1)
        self.is_network_split = False
        self.sync_all()

        # Check node0 can find all blockchain txns in the txindex
        logging.info("Checking txindex on node0...")
        waitFor(30, lambda: self.nodes[1].getblockcount() == 117)
        waitFor(30, lambda: self.nodes[0].getinfo()["txindex"] == "synced")
        for i in range(self.nodes[0].getblockcount()):
            blockhash = self.nodes[0].getblockhash(i)
            txns = self.nodes[0].getblock(blockhash)['txid']
            for tx in txns:
                waitFor(30, lambda: self.get_rawtransaction(self.nodes[0], tx) == True)

        # Check node1 can find all blockchain txns in the txindex
        logging.info("Checking txindex on node1...")
        waitFor(30, lambda: self.nodes[1].getinfo()["txindex"] == "synced")
        for i in range(self.nodes[1].getblockcount()):
            blockhash = self.nodes[1].getblockhash(i)
            txns = self.nodes[1].getblock(blockhash)['txid']
            for tx in txns:
                waitFor(30, lambda: self.get_rawtransaction(self.nodes[1], tx) == True)


if __name__ == '__main__':
    TxIndexTest().main()

# Create a convenient function for an interactive python debugging session
def Test():
    t = TxIndexTest()
    t.drop_to_pdb = True
    # install ctrl-c handler
    #import signal, pdb
    #signal.signal(signal.SIGINT, lambda sig, stk: pdb.Pdb().set_trace(stk))
    bitcoinConf = {
        "debug": ["net", "blk", "thin", "mempool", "req", "bench", "evict"],
        "blockprioritysize": 2000000  # we don't want any transactions rejected due to insufficient fees...
    }
    flags = standardFlags()
    t.main(flags, bitcoinConf, None)
