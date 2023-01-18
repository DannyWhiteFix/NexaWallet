#!/usr/bin/env python3
# Copyright (c) 2014-2015 The Bitcoin Core developers
# Copyright (c) 2015-2022 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
import test_framework.loginit
#
# Test spending coinbase transactions.
# The coinbase transaction in block N can appear in block
# N+100... so is valid in the txpool when the best block
# height is N+99.
# This test makes sure coinbase spends that will be mature
# in the next block are accepted into the memory pool,
# but less mature coinbase spends are NOT.
#

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from test_framework.blocktools import *

# Create one-input, one-output, no-fee transaction:
class MempoolSpendCoinbaseTest(BitcoinTestFramework):

    def setup_network(self):
        # Just need one node for this test
        args = ["-debug=mempool"]
        self.nodes = []
        self.nodes.append(start_node(0, self.options.tmpdir, args))
        self.is_network_split = False

    def run_test(self):
        node0_address = self.nodes[0].getnewaddress()
        waitFor(30, lambda : self.nodes[0].getblockcount() == 200, "Restoration of cached blockchain failed")

        # Coinbase at height chain_height-100+1 ok in txpool, should
        # get mined. Coinbase at height chain_height-100+2 is
        # is too immature to spend.
        b = [ self.nodes[0].getblockhash(n) for n in range(101, 103) ]
        coinbase_txidems = [ self.nodes[0].getblock(h)['txidem'][0] for h in b ]
        spends_raw = [ spend_coinbase_tx(self.nodes[0], txidem, node0_address, COINBASE_REWARD) for txidem in coinbase_txidems ]

        spend_101_id = self.nodes[0].sendrawtransaction(spends_raw[0])

        # coinbase at height 102 should be too immature to spend
        assert_raises(JSONRPCException, self.nodes[0].sendrawtransaction, spends_raw[1])

        # txpool should have just spend_101:
        assert_equal(self.nodes[0].getrawtxpool(), [ spend_101_id ])

        # mine a block, spend_101 should get confirmed
        self.nodes[0].generate(1)
        assert_equal(set(self.nodes[0].getrawtxpool()), set())

        # ... and now height 102 can be spent:
        spend_102_id = self.nodes[0].sendrawtransaction(spends_raw[1])
        assert_equal(self.nodes[0].getrawtxpool(), [ spend_102_id ])

if __name__ == '__main__':
    MempoolSpendCoinbaseTest().main()

# Create a convenient function for an interactive python debugging session
def Test():
    t = MempoolSpendCoinbaseTest()
    t.drop_to_pdb = True
    # install ctrl-c handler
    import signal, pdb
    signal.signal(signal.SIGINT, lambda sig, stk: pdb.Pdb().set_trace(stk))
    bitcoinConf = {
        "debug": ["net", "blk", "thin", "mempool", "req", "bench", "evict"],
        "blockprioritysize": 2000000  # we don't want any transactions rejected due to insufficient fees...
    }
    flags = standardFlags()
    t.main(flags, bitcoinConf, None)
