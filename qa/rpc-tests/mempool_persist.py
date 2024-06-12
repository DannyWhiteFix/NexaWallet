#!/usr/bin/env python3
# Copyright (c) 2014-2017 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test txpool persistence.

By default, nexad will dump txpool on shutdown and
then reload it on startup. This can be overridden with
the -cache.persistTxPool=0 command line option.

Test is as follows:

  - start node0, node1 and node2. node1 has -cache.persistTxPool=0
  - create 5 transactions on node2 to its own address. Note that these
    are not sent to node0 or node1 addresses because we don't want
    them to be saved in the wallet.
  - check that node0 and node1 have 5 transactions in their txpools
  - shutdown all nodes.
  - startup node0. Verify that it still has 5 transactions
    in its txpool. Shutdown node0. This tests that by default the
    txpool is persistent.
  - startup node1. Verify that its txpool is empty. Shutdown node1.
    This tests that with -cache.persistTxPool=0, the txpool is not
    dumped to disk when the node is shut down.
  - Restart node0 with -cache.persistTxPool=0. Verify that its txpool is
    empty. Shutdown node0. This tests that with -cache.persistTxPool=0,
    the txpool is not loaded from disk on start up.
  - Restart node0 with -cache.persistTxPool. Verify that it has 5
    transactions in its txpool. This tests that -cache.persistTxPool=0
    does not overwrite a previously valid txpool stored on disk.
  - Remove node0 txpool.dat and verify savetxpool RPC recreates it
    and verify that node1 can load it and has 5 transaction in its
    txpool.
  - Verify that savetxpool throws when the RPC is called if
    node1 can't write to disk.

"""
import os
import time
import logging
import test_framework.loginit

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from test_framework.nodemessages import *

waitTime = 60

class MempoolPersistTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 4

    def run_test(self):
        chain_height = self.nodes[0].getblockcount()
        assert_equal(chain_height, 200)

        ########## Check the memory pool persistence ###########

        logging.info("Mine a single block to get out of IBD")
        self.nodes[0].generate(1)
        self.sync_all()

        logging.info("Send 5 transactions from node2 (to its own address)")
        for i in range(5):
            self.nodes[2].sendtoaddress(self.nodes[2].getnewaddress(), Decimal("10"))
        self.sync_all()

        logging.info("Verify that node0 and node1 have 5 transactions in their txpools")
        assert_equal(len(self.nodes[0].getrawtxpool()), 5)
        assert_equal(len(self.nodes[1].getrawtxpool()), 5)

        logging.info("Stop-start node0 and node1. Verify that node0 has the transactions in its txpool and node1 does not.")
        stop_nodes(self.nodes)
        wait_bitcoinds()
        node_args = [[ ], ['-cache.persistTxPool=0']]
        self.nodes = start_nodes(2, self.options.tmpdir, node_args)
        waitFor(waitTime, lambda: len(self.nodes[0].getrawtxpool()) == 5)
        assert_equal(len(self.nodes[1].getrawtxpool()), 0)

        logging.info("Stop-start node0 with -cache.persistTxPool=0. Verify that it doesn't load its txpool.dat file.")
        stop_nodes(self.nodes)
        wait_bitcoinds()
        node_args = [['-cache.persistTxPool=0']]
        self.nodes = start_nodes(1, self.options.tmpdir, node_args)
        # Give bitcoind a second to reload the txpool
        time.sleep(1)
        assert_equal(len(self.nodes[0].getrawtxpool()), 0)

        logging.info("Stop-start node0. Verify that it has the transactions in its txpool.")
        stop_nodes(self.nodes)
        wait_bitcoinds()
        self.nodes = start_nodes(1, self.options.tmpdir)
        waitFor(waitTime, lambda: len(self.nodes[0].getrawtxpool()) == 5)

        txpooldat0 = os.path.join(self.options.tmpdir, 'node0', 'regtest', 'txpool.dat')
        txpooldat1 = os.path.join(self.options.tmpdir, 'node1', 'regtest', 'txpool.dat')
        logging.info("Remove the txpool.dat file. Verify that savetxpool to disk via RPC re-creates it")
        os.remove(txpooldat0)
        self.nodes[0].savetxpool()
        assert os.path.isfile(txpooldat0)

        logging.info("Stop nodes, make node1 use txpool.dat from node0. Verify it has 5 transactions")
        os.rename(txpooldat0, txpooldat1)
        stop_nodes(self.nodes)
        wait_bitcoinds()
        self.nodes = start_nodes(2, self.options.tmpdir)
        waitFor(waitTime, lambda: len(self.nodes[0].getrawtxpool()) == 5)
        waitFor(waitTime, lambda: len(self.nodes[1].getrawtxpool()) == 5)


        logging.info("Prevent nexad from writing txpool.dat to disk. Verify that `savetxpool` fails")
        # try to dump txpool content on a directory rather than a file
        # which is an implementation detail that could change and break this test
        txpooldotnew1 = txpooldat1 + '.new'
        os.mkdir(txpooldotnew1)
        assert_raises_rpc_error(-1, "Unable to dump txpool to disk", self.nodes[1].savetxpool)
        os.rmdir(txpooldotnew1)

        ########## Check the orphan pool persistence ###########

        stop_nodes(self.nodes)
        wait_bitcoinds()
        node_args = [["-debug=net", "-debug=mempool"]]
        self.nodes = start_nodes(1, self.options.tmpdir, node_args)
        self.nodes = start_nodes(2, self.options.tmpdir)
        connect_nodes_full(self.nodes)
        self.sync_blocks()

        #create coins that we can use for creating multi input transactions
        CHAIN_DEPTH = 55
        DELAY_TIME = 240
        self.relayfee = self.nodes[1].getnetworkinfo()['relayfee']
        utxo_count = CHAIN_DEPTH * 3 + 1
        startHeight = self.nodes[1].getblockcount()
        logging.info("Starting at %d blocks" % startHeight)
        utxos = create_confirmed_utxos(self.relayfee, self.nodes[1], utxo_count)
        startHeight = self.nodes[1].getblockcount()
        logging.info("Initial sync to %d blocks" % startHeight)

        # create a chain of orphans that we can store and resurrect.
        tx_amount = 50000000
        outpoint = bytes(range(0,32)).hex()  # Begin by referencing a nonexistent tx/outpoint
        for i in range(1, CHAIN_DEPTH + 1):
          try:
              inputs = []
              inputs.append(utxos.pop())
              inputs.append({ "outpoint" : outpoint, "amount" : tx_amount}) # references the prior tx created

              outputs = {}
              tx_amount = inputs[0]["amount"] + tx_amount - self.relayfee
              outputs[self.nodes[1].getnewaddress()] = tx_amount
              rawtx = self.nodes[1].createrawtransaction(inputs, outputs)
              signed_tx = self.nodes[1].signrawtransaction(rawtx)["hex"]
              txidem = self.nodes[1].sendrawtransaction(signed_tx, False, "standard", True)
              outpoint = COutPoint().fromIdemAndIdx(txidem, 0).rpcHex()
              logging.info("tx depth %d" % i) # Keep travis from timing out
          except JSONRPCException as e: # an exception you don't catch is a testing error
              print(str(e))
              raise

        waitFor(DELAY_TIME, lambda: self.nodes[0].getorphanpoolinfo()["size"] == 0, lambda: print (getNodeInfo(self.nodes[0])))
        waitFor(DELAY_TIME, lambda: self.nodes[1].getorphanpoolinfo()["size"] == 55, lambda: print (getNodeInfo(self.nodes[1])))
        waitFor(DELAY_TIME, lambda: self.nodes[1].gettxpoolinfo()["size"] == 0, lambda: print (getNodeInfo(self.nodes[1])))
        waitFor(DELAY_TIME, lambda: self.nodes[1].gettxpoolinfo()["size"] == 0, lambda: print (getNodeInfo(self.nodes[1])))

        #stop and start nodes and verify that the orphanpool was resurrected
        stop_nodes(self.nodes)
        wait_bitcoinds()
        self.nodes = start_nodes(2, self.options.tmpdir)
        waitFor(DELAY_TIME, lambda: self.nodes[0].getorphanpoolinfo()["size"] == 0, lambda: print (getNodeInfo(self.nodes[0])))
        waitFor(DELAY_TIME, lambda: self.nodes[1].getorphanpoolinfo()["size"] == 55, lambda: print (getNodeInfo(self.nodes[1])))
        waitFor(DELAY_TIME, lambda: self.nodes[1].gettxpoolinfo()["size"] == 0, lambda: print (getNodeInfo(self.nodes[1])))
        waitFor(DELAY_TIME, lambda: self.nodes[1].gettxpoolinfo()["size"] == 0, lambda: print (getNodeInfo(self.nodes[1])))

        orphanpooldat0 = os.path.join(self.options.tmpdir, 'node0', 'regtest', 'orphanpool.dat')
        orphanpooldat1 = os.path.join(self.options.tmpdir, 'node1', 'regtest', 'orphanpool.dat')
        logging.info("Remove the orphanpool.dat file. Verify that saveorphanpool to disk via RPC re-creates it")
        os.remove(orphanpooldat0)
        self.nodes[0].saveorphanpool()
        assert os.path.isfile(orphanpooldat0)

        logging.info("Stop nodes, make node1 use orphanpool.dat from node0. Verify it has 5 transactions")
        os.rename(orphanpooldat0, orphanpooldat1)
        stop_nodes(self.nodes)
        wait_bitcoinds()
        self.nodes = start_nodes(2, self.options.tmpdir)
        waitFor(waitTime, lambda: len(self.nodes[0].getraworphanpool()) == 0)
        waitFor(waitTime, lambda: len(self.nodes[1].getraworphanpool()) == 55)
        waitFor(DELAY_TIME, lambda: self.nodes[1].gettxpoolinfo()["size"] == 0, lambda: print (getNodeInfo(self.nodes[1])))
        waitFor(DELAY_TIME, lambda: self.nodes[1].gettxpoolinfo()["size"] == 0, lambda: print (getNodeInfo(self.nodes[1])))

        logging.info("Prevent nexad from writing orphanpool.dat to disk. Verify that `saveorphanpool` fails")
        # try to dump orphanpool content on a directory rather than a file
        # which is an implementation detail that could change and break this test
        orphanpooldotnew1 = orphanpooldat1 + '.new'
        os.mkdir(orphanpooldotnew1)
        assert_raises_rpc_error(-1, "Unable to dump orphanpool to disk", self.nodes[1].saveorphanpool)
        os.rmdir(orphanpooldotnew1)

        #stop and start with cache.persistTxPool off and verify that the orphan pool was not resurrected
        stop_nodes(self.nodes)
        wait_bitcoinds()
        node_args = [['-cache.persistTxPool=0'], ['-cache.persistTxPool=0']]
        self.nodes = start_nodes(2, self.options.tmpdir, node_args)
        waitFor(DELAY_TIME, lambda: self.nodes[0].getorphanpoolinfo()["size"] == 0)
        waitFor(DELAY_TIME, lambda: self.nodes[1].getorphanpoolinfo()["size"] == 0)

        ########## Check the CAPD message pool persistence ###########

        connect_nodes_full(self.nodes)
        self.sync_blocks()

        logging.info("Send 5 transactions from node2 (to its own address)")
        for i in range(5):
            self.nodes[1].capd("send", "this is the message")

        logging.info("Verify that node0 and node1 have 5 transactions in their msgpools")
        waitFor(waitTime, lambda: self.nodes[0].capd("info")["count"] == 5)
        waitFor(waitTime, lambda: self.nodes[1].capd("info")["count"] == 5)

        logging.info("Stop-start node0 and node1. Verify that node0 has the messages in its msgpool and node1 does not.")
        stop_nodes(self.nodes)
        wait_bitcoinds()
        node_args = [[ ], ['-cache.maxCapdPool=0']]
        self.nodes = start_nodes(2, self.options.tmpdir, node_args)
        waitFor(waitTime, lambda: self.nodes[0].capd("info")["count"] == 5)
        waitFor(waitTime, lambda: self.nodes[1].capd("info")["count"] == 0)

        logging.info("Stop-start node0 with -cache.maxCapdPool=0. Verify that it doesn't load its msgpool.dat file.")
        stop_nodes(self.nodes)
        wait_bitcoinds()
        node_args = [['-cache.maxCapdPool=0']]
        self.nodes = start_nodes(1, self.options.tmpdir, node_args)
        # Give bitcoind a second to reload the msgpool
        time.sleep(1)
        waitFor(waitTime, lambda: self.nodes[0].capd("info")["count"] == 0)

        logging.info("Stop-start node0. Verify that it has the transactions in its msgpool.")
        stop_nodes(self.nodes)
        wait_bitcoinds()
        self.nodes = start_nodes(1, self.options.tmpdir)
        waitFor(waitTime, lambda: self.nodes[0].capd("info")["count"] == 5)

        msgpooldat0 = os.path.join(self.options.tmpdir, 'node0', 'regtest', 'msgpool.dat')
        msgpooldat1 = os.path.join(self.options.tmpdir, 'node1', 'regtest', 'msgpool.dat')
        logging.info("Remove the msgpool.dat file. Verify that savetxpool to disk via RPC re-creates it")
        os.remove(msgpooldat0)
        self.nodes[0].savemsgpool()
        assert os.path.isfile(msgpooldat0)

        logging.info("Stop nodes, make node1 use msgpool.dat from node0. Verify it has 5 messages")
        os.rename(msgpooldat0, msgpooldat1)
        stop_nodes(self.nodes)
        wait_bitcoinds()
        self.nodes = start_nodes(2, self.options.tmpdir)
        waitFor(waitTime, lambda: self.nodes[1].capd("info")["count"] == 5)

        logging.info("Prevent nexad from writing msgpool.dat to disk. Verify that `savemsgpool` fails")
        # try to dump txpool content on a directory rather than a file
        # which is an implementation detail that could change and break this test
        msgpooldotnew1 = msgpooldat1 + '.new'
        os.mkdir(msgpooldotnew1)
        assert_raises_rpc_error(-1, "Unable to dump msgpool to disk", self.nodes[1].savemsgpool)
        os.rmdir(msgpooldotnew1)



if __name__ == '__main__':
    MempoolPersistTest().main()

def Test():
    t = MempoolPersistTest()
    t.drop_to_pdb = True
    bitcoinConf = {
        "debug": ["blk", "mempool", "net", "req", "-event"],
        "logtimemicros": 1
    }

    flags = standardFlags()
    t.main(flags, bitcoinConf, None)
