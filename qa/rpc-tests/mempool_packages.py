#!/usr/bin/env python3
# Copyright (c) 2014-2015 The Bitcoin Core developers
# Copyright (c) 2015-2022 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
import test_framework.loginit
# Test descendant package tracking code

from test_framework.test_framework import BitcoinTestFramework
from test_framework.blocktools import *
from test_framework.util import *
from test_framework.mininode import COIN


MAX_ANCESTORS = 25
MAX_DESCENDANTS = 25

class MempoolPackagesTest(BitcoinTestFramework):

    def setup_network(self):
        self.nodes = []
        self.nodes.append(start_node(0, self.options.tmpdir, ["-cache.maxOrphanPool=10000", "-debug=mempool", "-test.nextMaxBlockSize=10000000"]))
        self.nodes.append(start_node(1, self.options.tmpdir, ["-cache.maxOrphanPool=10000", "-debug=mempool", "-test.nextMaxBlockSize=10000000"]))
        connect_nodes(self.nodes[0], 1)
        self.is_network_split = False

    def run_test(self):
        ''' Mine some blocks and have them mature. '''
        self.nodes[1].generate(201)
        self.sync_blocks()
        disconnect_all(self.nodes[0])

        #create coins that we can use for creating multi input transactions
        CHAIN_DEPTH = 55
        TX_TO_EVICT = 45
        DELAY_TIME = 240
        self.relayfee = 1000
        startHeight = self.nodes[1].getblockcount()
        logging.info("Starting at %d blocks" % startHeight)
        startHeight = self.nodes[1].getblockcount()
        logging.info("Initial sync to %d blocks" % startHeight)

        # Create a valid chain of transactions on node1 that we can store and resurrect.
        # On node0 we skip adding the first transaction so that all that follow will be orphaned.
        tx_amount = 1000000
        txidem = self.nodes[1].sendtoaddress(self.nodes[1].getnewaddress(), tx_amount);
        txToEvict = txidem
        for i in range(1, CHAIN_DEPTH + 1):
          try:
              outpoint = COutPoint().fromIdemAndIdx(txidem, 0).rpcHex()
              inputs = []
              inputs.append({ "outpoint" : outpoint, "amount" : tx_amount}) # references the prior tx created

              txin_amount = tx_amount
              outputs = {}
              tx_amount = tx_amount - self.relayfee
              outputs[self.nodes[1].getnewaddress()] = Decimal(tx_amount)
              rawtx = self.nodes[1].createrawtransaction(inputs, outputs)
              signed_tx = self.nodes[1].signrawtransaction(rawtx)["hex"]
              txidem = self.nodes[1].sendrawtransaction(signed_tx, False, "standard", True)
              self.nodes[0].sendrawtransaction(signed_tx, False, "standard", True) #orphaned
              logging.info("tx depth %d" % i) # Keep travis from timing out
              print(str(txidem))

              if i == CHAIN_DEPTH + 1 - TX_TO_EVICT:
                  txToEvict = txidem

          except JSONRPCException as e: # an exception you don't catch is a testing error
              print(str(e))
              raise

        # check that we have a full valid chain on node1 and a series of orhpans on node0
        waitFor(30, lambda: self.nodes[0].gettxpoolinfo()["size"] == 0)
        waitFor(30, lambda: self.nodes[0].getorphanpoolinfo()["size"] == CHAIN_DEPTH)
        waitFor(30, lambda: self.nodes[1].gettxpoolinfo()["size"] == CHAIN_DEPTH + 1)
        waitFor(30, lambda: self.nodes[1].getorphanpoolinfo()["size"] == 0)

        # evict the last 45 transactions from node1
        self.nodes[1].evicttransaction(txToEvict)
        waitFor(30, lambda: self.nodes[1].gettxpoolinfo()["size"] == CHAIN_DEPTH + 1 - TX_TO_EVICT)
        waitFor(30, lambda: self.nodes[1].getorphanpoolinfo()["size"] == 0)

        # mine a block on node 1. This will clear it's mempool and when node0 receives the block
        # it should pull in the last 5 orphans of the chain to it's mempool.
        self.nodes[1].generate(1)
        waitFor(30, lambda: self.nodes[1].gettxpoolinfo()["size"] == 0)
        waitFor(30, lambda: self.nodes[1].getorphanpoolinfo()["size"] == 0)

        connect_nodes(self.nodes[0], 1)
        self.is_network_split = False
        self.sync_blocks()

        waitFor(30, lambda: self.nodes[1].gettxpoolinfo()["size"] == TX_TO_EVICT)
        waitFor(30, lambda: self.nodes[1].getorphanpoolinfo()["size"] == 0)
        waitFor(30, lambda: self.nodes[1].getblockheader(self.nodes[1].getblockcount())["txcount"] == CHAIN_DEPTH + 1 - TX_TO_EVICT + 1)
        waitFor(30, lambda: self.nodes[0].gettxpoolinfo()["size"] == TX_TO_EVICT)
        waitFor(30, lambda: self.nodes[0].getorphanpoolinfo()["size"] == 0)


if __name__ == '__main__':
    MempoolPackagesTest().main()
