#!/usr/bin/env python3
# Copyright (c) 2014-2015 The Bitcoin Core developers
# Copyright (c) 2015-2022 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
import test_framework.loginit
#
# Test proper accounting with an equivalent malleability clone
#

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from test_framework.nodemessages import *
from test_framework.script import *
import pdb
import traceback

class TxnCloneTest(BitcoinTestFramework):

    def add_options(self, parser):
        parser.add_option("--mineblock", dest="mine_block", default=False, action="store_true",
                          help="Test double-spend of 1-confirmed transaction")

    def setup_network(self):
        # Start with split network:
        return super(TxnCloneTest, self).setup_network(True)

    def run_test(self):
        # All nodes should start with 25 mined blocks:
        starting_balance = COINBASE_REWARD*25
        for i in range(4):
            assert_equal(self.nodes[i].getbalance(), starting_balance)
            self.nodes[i].getnewaddress("p2pkt","")  # bug workaround, coins generated assigned to first getnewaddress!

        self.nodes[0].set("wallet.payTxFee=100")
        FooAmt = COINBASE_REWARD*25 - 31000000

        node0_address_foo = self.nodes[0].getnewaddress("p2pkt","foo")
        fund_foo_txid = self.nodes[0].sendfrom("", node0_address_foo, FooAmt)
        fund_foo_tx = self.nodes[0].gettransaction(fund_foo_txid)

        # Coins are sent to node1_address
        node1_address = self.nodes[1].getnewaddress("p2pkt","from0")

        # Send tx1, and another transaction tx2 that won't be cloned
        txidem1 = self.nodes[0].sendfrom("foo", node1_address, 40, 0)

        # Construct a clone of tx1, to be malleated

        tx1hex = self.nodes[0].getrawtransaction(txidem1)
        tx1json = self.nodes[0].gettransaction(txidem1)
        tx1id = tx1json["txid"]
        # Use a different signature hash type to sign.  This creates an equivalent but malleated clone.
        tx = CTransaction(tx1hex)
        for v in tx.vin:  # Wipe out the sigs
            v.scriptSig = CScript()
        tx1_clone = self.nodes[0].signrawtransaction(tx.toHex(), None, None, "THIS_IN|ALL_OUT")
        # Its malleated so the hex representations are different
        assert(tx1_clone["hex"] != tx1hex)
        # but Idem is the same
        assert(txidem1 == tx1_clone["txidem"])
        assert(txidem1 == tx1json["txidem"])
        # and Id is different
        tx1_clone_id = tx1_clone["txid"]
        assert(tx1_clone_id != tx1json["txid"])

        # Have node0 mine a block, if requested:
        if (self.options.mine_block):
            self.nodes[0].generate(1)
            sync_blocks(self.nodes[0:2])

        tx1 = tx1json

        # Node0's balance should be starting balance, plus 50BTC for another
        # matured block, minus tx1 and tx2 amounts, and minus transaction fees:
        expected = starting_balance + fund_foo_tx["fee"]
        if self.options.mine_block: expected += COINBASE_REWARD
        expected += tx1["amount"] + tx1["fee"]
        assert_equal(self.nodes[0].getbalance(), expected)

        # foo and bar accounts should be debited:
        assert_equal(self.nodes[0].getbalance("foo", 0), FooAmt + tx1["amount"] + tx1["fee"])

        if self.options.mine_block:
            assert_equal(tx1["confirmations"], 1)
            # Node1's "from0" balance should be both transaction amounts:
            assert_equal(self.nodes[1].getbalance("from0"), -(tx1["amount"] + tx2["amount"]))
        else:
            assert_equal(tx1["confirmations"], 0)

        # Send clone and its parent to miner
        self.nodes[2].sendrawtransaction(fund_foo_tx["hex"])
        txid1_clone = self.nodes[2].sendrawtransaction(tx1_clone["hex"])
        # ... mine a block...
        self.nodes[2].generate(1)

        # Reconnect the split network, and sync chain:
        connect_nodes(self.nodes[1], 2)
        self.nodes[2].generate(1)  # Mine another block to make sure we sync
        sync_blocks(self.nodes)

        # Re-fetch transaction info:
        tx1 = self.nodes[0].gettransaction(tx1id)
        tx1_idem = self.nodes[0].gettransaction(txidem1)
        tx1_clone = self.nodes[0].gettransaction(tx1_clone_id)

        # Verify expected confirmations
        assert_equal(tx1["confirmations"], -2)
        assert_equal(tx1_clone["confirmations"], 2)
        assert_equal(tx1_idem["confirmations"], 2)

        # Check node0's total balance; should be same as before the clone, + 100 BTC for 2 matured,
        # less possible orphaned matured subsidy
        expected += 2*COINBASE_REWARD
        if (self.options.mine_block):
            expected -= COINBASE_REWARD
        assert_equal(self.nodes[0].getbalance(), expected)
        assert_equal(self.nodes[0].getbalance("*", 0), expected)

        # Check node0's individual account balances.
        # "foo" should have been debited by the equivalent clone of tx1
        logging.info("foo balance: " + str(self.nodes[0].getbalance("foo")) + " foo amt " + str(FooAmt) + " tx1amt " + str( tx1["amount"]) + " foo fee " + str(tx1["fee"]))
        assert_equal(self.nodes[0].getbalance("foo"), FooAmt + tx1["amount"] + tx1["fee"])
        assert_equal(self.nodes[0].getbalance("", 0), starting_balance
                                                                - FooAmt
                                                                + fund_foo_tx["fee"]
                                                                + 2*COINBASE_REWARD)

        # Node1's "from0" account balance
        assert_equal(self.nodes[1].getbalance("from0", 0), -(tx1["amount"]))

if __name__ == '__main__':
    TxnCloneTest().main()

def Test():
    t = TxnCloneTest()
    t.drop_to_pdb = True
    bitcoinConf = {
        "debug": ["graphene", "blk", "mempool", "net", "req"],
        "logtimemicros": 1
    }

    flags = standardFlags()
    t.main(flags, bitcoinConf, None)
