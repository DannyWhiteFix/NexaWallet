#!/usr/bin/env python3
# Copyright (c) 2014-2015 The Bitcoin Core developers
# Copyright (c) 2015-2022 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
import test_framework.loginit
import time
import pprint
import sys
if sys.version_info[0] < 3:
    raise "Use Python 3"
import logging
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
import binascii
from test_framework.script import *
from test_framework.nodemessages import *

class WalletWatchonlyTest (BitcoinTestFramework):

    def add_options(self, parser):
        parser.add_option("--addrType", dest="addrType", default="p2pkt", action="store",
                          help="Choose p2pkt or p2pkh address types to use with the wallet")

    def setup_chain(self,bitcoinConfDict=None, wallets=None):
        logging.info("Initializing test directory "+self.options.tmpdir)
        initialize_chain_clean(self.options.tmpdir, 4, bitcoinConfDict, wallets)

    def setup_network(self, split=False):
        self.node_args = [['-usehd=0', '-wallet.maxTxFee=10000'], ['-usehd=0', '-wallet.maxTxFee=10000'], ['-usehd=0', '-wallet.maxTxFee=10000']]
        self.nodes = start_nodes(3, self.options.tmpdir, self.node_args)
        connect_nodes_full(self.nodes)
        self.is_network_split=False
        self.sync_blocks()

    def run_test (self):
        addrType = self.options.addrType

        # Check that there's no UTXO on none of the nodes
        assert_equal(len(self.nodes[0].listunspent()), 0)
        assert_equal(len(self.nodes[1].listunspent()), 0)
        assert_equal(len(self.nodes[2].listunspent()), 0)

        logging.info("Mining blocks...")

        self.nodes[0].generate(1)

        walletinfo = self.nodes[0].getwalletinfo()
        assert_equal(walletinfo['immature_balance'], COINBASE_REWARD)
        assert_equal(walletinfo['balance'], 0)
        assert_equal(walletinfo['txcount'], 1)
        assert_equal(walletinfo['unspentcount'], 1)

        self.sync_blocks()
        watch_mining_address = self.nodes[1].getnewaddress()
        watch_recv_address = self.nodes[1].getnewaddress()
        # import the watch addresses into node 2
        self.nodes[2].importaddress(str(watch_mining_address), "", False, False)
        self.nodes[2].importaddress(str(watch_recv_address), "", False, False)
        # mine on node 1
        self.nodes[1].generatetoaddress(101, str(watch_mining_address), 100000000)
        self.sync_blocks()

        assert_equal(self.nodes[0].getbalance(), COINBASE_REWARD)
        assert_equal(self.nodes[1].getbalance(), COINBASE_REWARD)
        assert_equal(self.nodes[2].getbalance(), 0)
        assert_equal(self.nodes[0].getbalance("*"), COINBASE_REWARD)
        assert_equal(self.nodes[1].getbalance("*"), COINBASE_REWARD)
        assert_equal(self.nodes[2].getbalance("*"), 0)

        # Check that only first and second nodes have spendable UTXOs
        unspent_0 = self.nodes[0].listunspent()
        assert_equal(len(unspent_0), 1)
        assert_equal(unspent_0[0]['spendable'], True)

        unspent_1 = self.nodes[1].listunspent()
        assert_equal(len(unspent_1), 1)
        assert_equal(unspent_1[0]['spendable'], True)

        # the third node has 1 unspenable utxo
        unspent_2 = self.nodes[2].listunspent()
        assert_equal(len(unspent_2), 1)
        assert_equal(unspent_2[0]['spendable'], False)

        # check watch only balances on node 2
        waitFor(60, lambda: self.nodes[2].getwalletinfo()['watchonly_balance'] == COINBASE_REWARD)
        waitFor(60, lambda: self.nodes[2].getwalletinfo()['immature_watchonly_balance'] == COINBASE_REWARD * 100)
        waitFor(60, lambda: self.nodes[2].getwalletinfo()['unconfirmed_watchonly_balance'] == 0)
        waitFor(60, lambda: self.nodes[2].getwalletinfo()['unspentcount'] == 101)

        # send some coins to watchonly address, see that we see it in the watcher
        watch_sent = 50000
        self.nodes[0].sendtoaddress(watch_recv_address, watch_sent, "", "", False)
        sync_mempools(self.nodes)
        walletinfo = self.nodes[2].getwalletinfo()
        assert_equal(walletinfo['watchonly_balance'], COINBASE_REWARD)
        assert_equal(walletinfo['immature_watchonly_balance'], COINBASE_REWARD * 100)
        assert_equal(walletinfo['unconfirmed_watchonly_balance'], watch_sent)
        assert_equal(walletinfo['unspentcount'], 102)

        # Send small coins from node1 to node2. This should work but in the past
        # would trigger an error becasue watchonly coins were being used as available coins
        self.nodes[1].sendtoaddress(self.nodes[2].getnewaddress(), 100, "", "", True)
        self.nodes[1].sendtoaddress(self.nodes[2].getnewaddress(), 100, "", "", True)
        self.nodes[1].sendtoaddress(self.nodes[2].getnewaddress(), 100, "", "", True)
        self.nodes[1].sendtoaddress(self.nodes[2].getnewaddress(), 200, "", "", True)
        self.nodes[1].sendtoaddress(self.nodes[2].getnewaddress(), 300, "", "", True)
        self.nodes[1].generate(1)
        self.sync_blocks()

        self.nodes[2].sendtoaddress(self.nodes[0].getnewaddress(), 100, "", "", False)
        self.nodes[2].sendtoaddress(self.nodes[0].getnewaddress(), 100, "", "", False)
        self.nodes[2].sendtoaddress(self.nodes[0].getnewaddress(), 100, "", "", False)
        self.nodes[2].sendtoaddress(self.nodes[0].getnewaddress(), 50, "", "", False)
        self.nodes[2].sendtoaddress(self.nodes[0].getnewaddress(), 100, "", "", False)
        self.nodes[2].sendtoaddress(self.nodes[0].getnewaddress(), 70, "", "", False)
 

if __name__ == '__main__':
    WalletWatchonlyTest ().main ()

def Test():
    t = WalletWatchonlyTest()
    t.drop_to_pdb = True
    bitcoinConf = {
        "debug": ["dbase", "selectcoins", "rpc","net", "blk", "thin", "mempool", "req", "bench", "evict"]
    }

    flags = standardFlags()
    t.main(flags, bitcoinConf, None)
