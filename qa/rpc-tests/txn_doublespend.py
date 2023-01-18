#!/usr/bin/env python3
# Copyright (c) 2014-2015 The Bitcoin Core developers
# Copyright (c) 2015-2022 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
import test_framework.loginit
#
# Test proper accounting with a double-spend conflict
#

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *

class TxnDoubleSpendTest(BitcoinTestFramework):

    def add_options(self, parser):
        parser.add_option("--mineblock", dest="mine_block", default=False, action="store_true",
                          help="Test double-spend of 1-confirmed transaction")

    def setup_network(self):
        # Start with split network:
        return super(TxnDoubleSpendTest, self).setup_network(True)

    def run_test(self):
        # All nodes should start with 25 mined blocks:
        starting_balance = COINBASE_REWARD*25
        for i in range(4):
            assert_equal(self.nodes[i].getbalance(), starting_balance)
            assert_equal(self.nodes[i].getbalance("*"), starting_balance)
            self.nodes[i].getnewaddress("p2pkh", "")  # bug workaround, coins generated assigned to first getnewaddress!

        startHeight = self.nodes[2].getblockcount()

        # Coins are sent to node1_address
        node1_address = self.nodes[1].getnewaddress("p2pkh", "from0")

        # First: use raw transaction API to send 1240 BTC to node1_address,
        # but don't broadcast:

        unspent = self.nodes[0].listunspent()

        doublespend_fee = Decimal('-20000')
        doublespend_amt = unspent[0]["amount"] + unspent[1]["amount"] - Decimal("10000000.0")
        rawtx_input_0 = {}
        rawtx_input_0["outpoint"] = unspent[0]["outpoint"]
        rawtx_input_0["amount"] = unspent[0]["amount"]
        rawtx_input_1 = {}
        rawtx_input_1["outpoint"] = unspent[1]["outpoint"]
        rawtx_input_1["amount"] = unspent[1]["amount"]
        inputs = [rawtx_input_0, rawtx_input_1]
        change_address = self.nodes[0].getnewaddress("p2pkh")
        outputs = {}
        outputs[node1_address] = doublespend_amt
        outputs[change_address] = Decimal("10000000.0") + doublespend_fee
        rawtx2 = self.nodes[0].createrawtransaction(inputs, outputs)
        doublespend2 = self.nodes[0].signrawtransaction(rawtx2)
        assert_equal(doublespend2["complete"], True)

        # Change how we allocate the coins slightly
        outputs[node1_address] =  outputs[node1_address] - Decimal("10000000.0")
        outputs[change_address] = outputs[change_address] + Decimal("10000000.0")
        # And build a doublespend
        rawtx1 = self.nodes[0].createrawtransaction(inputs, outputs)
        doublespend1 = self.nodes[0].signrawtransaction(rawtx1)
        assert_equal(doublespend1["complete"], True)

        # doublespends will have different idems because they change utxo state
        # (as opposed to malleated tx, which have same idem, but different id)
        assert doublespend1["txidem"] != doublespend2["txidem"], "transactions are not different"

        # Now give doublespend1 to one side of the network
        doublespend1_txidem = self.nodes[0].sendrawtransaction(doublespend1["hex"])
        try: # Check that it did not propagate because the network is split
            ret = self.nodes[2].gettransaction(doublespend1_txidem)
            assert(False)
        except JSONRPCException:
            pass

        # Now give doublespend2 to miner:
        doublespend2_txidem = self.nodes[2].sendrawtransaction(doublespend2["hex"])
        # ... mine a block...
        self.nodes[2].generate(1)

        # Reconnect the split network, and sync chain:
        connect_nodes(self.nodes[1], 2)
        self.nodes[2].generate(1)  # Mine another block to make sure we sync
        sync_blocks(self.nodes)
        assert_equal(self.nodes[0].gettransaction(doublespend2_txidem)["confirmations"], 2)

        # Re-fetch transaction info:
        tx1byid = self.nodes[0].gettransaction(doublespend1["txid"])
        tx1 = self.nodes[0].gettransaction(doublespend1_txidem)

        # transaction should be conflicted
        assert tx1byid["confirmations"] == -2
        assert tx1["confirmations"] == -2

        # Node0's total balance should be what the winning doublespend tx (#2) paid.  That is,
        # the starting balance, plus coinbase for two more matured blocks,
        # minus the doublespend send, plus fees (which are negative):
        expected = starting_balance + 2*COINBASE_REWARD - doublespend_amt + doublespend_fee
        assert_equal(self.nodes[0].getbalance(), expected)
        assert_equal(self.nodes[0].getbalance("*"), expected)

        # Node1's "from0" account balance should be just the doublespend:
        assert_equal(self.nodes[1].getbalance("from0"), doublespend_amt)

if __name__ == '__main__':
    TxnDoubleSpendTest().main()

def Test():
    t = TxnDoubleSpendTest()
    t.drop_to_pdb = True
    bitcoinConf = {
        "debug": ["blk", "mempool", "net", "req"],
        "logtimemicros": 1
    }

    flags = standardFlags()
    t.main(flags, bitcoinConf, None)
