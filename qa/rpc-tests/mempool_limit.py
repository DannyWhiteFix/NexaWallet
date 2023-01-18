#!/usr/bin/env python3
# Copyright (c) 2014-2015 The Bitcoin Core developers
# Copyright (c) 2015-2022 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
import test_framework.loginit
# Test mempool limiting together/eviction with the wallet

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from test_framework.blocktools import *

class MempoolLimitTest(BitcoinTestFramework):

    def __init__(self):
        self.txouts = gen_return_txouts()

    def setup_network(self):
        self.nodes = []
        self.nodes.append(start_node(0, self.options.tmpdir,
        ["-cache.maxTxPool=5",
         "-spendzeroconfchange=0",
         "-relay.minRelayTxFee=2000"]))
        self.is_network_split = False
        self.sync_all()
        self.relayfee = self.nodes[0].getnetworkinfo()['relayfee']

    def setup_chain(self):
        print("Initializing test directory "+self.options.tmpdir)
        initialize_chain_clean(self.options.tmpdir, 1, self.confDict)

    def run_test(self):
        node = self.nodes[0]
        txids = []
        utxos = create_confirmed_utxos(self.relayfee, node, 33*12)

        # create a lot of txns up to but not exceeding the maxtxpool
        relayfee = node.getnetworkinfo()['relayfee']
        base_fee = decimal.Decimal(relayfee/10)
        for i in range (2):
            txids.append([])
            txids[i] = create_lots_of_big_transactions(node, self.txouts, utxos[33*i:33*i+33], 33, decimal.Decimal(i)/COIN+base_fee)
            print(str(node.gettxpoolinfo()))

        num_txns_in_txpool = node.gettxpoolinfo()["size"]

        # create another txn that will exceed the maxtxpool which should evict some random transaction.
        all_txns = node.getrawtxpool()

        tries = 0
        i = 2
        while tries < 10:
            new_txn = create_lots_of_big_transactions(node, self.txouts, utxos[33*i:33*i+33], 1, (i+1)*decimal.Decimal(base_fee/10) + Decimal(0.1*tries))[0] # Adding tries to the fee changes the transaction (we are reusing the prev UTXOs)
            assert(node.gettxpoolinfo()["usage"] < node.gettxpoolinfo()["maxtxpool"])

            # make sure the txpool count did not change much (an eviction could put a smaller tx in, which could then allow another in)
            waitFor(10, lambda: abs(num_txns_in_txpool - node.gettxpoolinfo()["size"]) < 2)

            # make sure new tx is in the txpool, but since the txpool has a random eviction policy,
            # this tx could be the one that was evicted.  So retry 10 times to make failures it VERY unlikely
            # we have a spurious failure due to ejecting the tx we just added.
            if new_txn[0] in node.getrawtxpool():
                break
            tries+=1
            i+=1

        if tries >= 10:
            assert False, "Newly created tx is repeatedly NOT being put into the mempool"


if __name__ == '__main__':
    MempoolLimitTest().main()

def Test():
    t = MempoolLimitTest()
    t.drop_to_pdb = True
    import signal, pdb
    signal.signal(signal.SIGINT, lambda sig, frame: pdb.Pdb().set_trace(frame))
    bitcoinConf = {
        "debug": ["blk", "mempool", "net", "req"],
        "logtimemicros": 1
    }

    flags = standardFlags()
    t.main(flags, bitcoinConf, None)
