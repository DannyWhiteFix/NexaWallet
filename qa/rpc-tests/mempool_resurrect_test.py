#!/usr/bin/env python3
# Copyright (c) 2014-2015 The Bitcoin Core developers
# Copyright (c) 2015-2022 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test resurrection of mined transactions when the blockchain is re-organized.
Several transactions are created and mined and a child for each transaction is created and mined.
These blocks are rewound, and we verify that all the created transactions are returned to the mempool.
Next a new block is mined, and we verify that all transactions are in that new block
"""
import test_framework.loginit


from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from test_framework.blocktools import *

# Create one-input, one-output, no-fee transaction:
class MempoolCoinbaseTest(BitcoinTestFramework):

    def setup_network(self):
        # Just need one node for this test
        args = ["-debug=mempool"]
        self.nodes = []
        self.nodes.append(start_node(0, self.options.tmpdir, args))
        self.is_network_split = False

    def run_test(self):
        node0_address = self.nodes[0].getnewaddress()
        # Spend block 1/2/3's coinbase transactions
        # Mine a block.
        # Create three more transactions, spending the spends
        # Mine another block.
        # ... make sure all the transactions are confirmed
        # Invalidate both blocks
        # ... make sure all the transactions are put back in the txpool
        # Mine a new block
        # ... make sure all the transactions are confirmed again.

        b = [ self.nodes[0].getblockhash(n) for n in range(1, 4) ]
        coinbase_txids = [ self.nodes[0].getblock(h)['txidem'][0] for h in b ]
        spends1_raw = [ spend_coinbase_tx(self.nodes[0], txid, node0_address, COINBASE_REWARD) for txid in coinbase_txids ]
        spends1_id = [ self.nodes[0].sendrawtransaction(tx) for tx in spends1_raw ]

        blocks = []
        blocks.extend(self.nodes[0].generate(1))

        # Now create children of each spends1
        spends2_raw = [ spend_coinbase_tx(self.nodes[0], txid, node0_address, COINBASE_REWARD-Decimal("0.01")) for txid in spends1_id ]
        spends2_id = [ self.nodes[0].sendrawtransaction(tx) for tx in spends2_raw ]

        mpi = self.nodes[0].gettxpoolinfo()
        assert mpi['size'] == 3, "Transactions rejected from txpool"

        blocks.extend(self.nodes[0].generate(1))

        # txpool should be empty, all txns confirmed
        mpi = self.nodes[0].gettxpoolinfo()
        assert mpi['size'] == 0, "Transactions were not committed to a block"
        assert_equal(set(self.nodes[0].getrawtxpool()), set())
        for txid in spends1_id+spends2_id:
            tx = self.nodes[0].gettransaction(txid)
            assert(tx["confirmations"] > 0)

        # Should be 1 chain
        ct = self.nodes[0].getchaintips()
        assert len(ct) == 1

        # Use invalidateblock to re-org back; all transactions should
        # end up unconfirmed and back in the txpool
        for node in self.nodes:
            node.logline("Invalidating block %s" % blocks[0])
            node.invalidateblock(blocks[0])

        time.sleep(3) # wait for tx processing threads to put them back into the txpool

        # Should be a fork
        ct = self.nodes[0].getchaintips()
        assert len(ct) == 2

        # txpool should be empty, all txns confirmed (check 2 different ways)
        mpi = self.nodes[0].gettxpoolinfo()
        assert mpi['size'] == 6, "Transactions rejected from txpool"
        assert_equal(set(self.nodes[0].getrawtxpool()), set(spends1_id+spends2_id))

        for txid in spends1_id+spends2_id:
            tx = self.nodes[0].gettransaction(txid)
            assert(tx["confirmations"] == 0)

        # Generate another block, they should all get mined
        self.nodes[0].generate(1)
        # txpool should be empty, all txns confirmed
        assert_equal(set(self.nodes[0].getrawtxpool()), set())
        for txid in spends1_id+spends2_id:
            tx = self.nodes[0].gettransaction(txid)
            assert(tx["confirmations"] > 0)


if __name__ == '__main__':
    MempoolCoinbaseTest().main()

def Test():
    t = MempoolCoinbaseTest()
    t.drop_to_pdb = True
    bitcoinConf = {
        "debug": ["net", "blk", "thin", "mempool", "req", "bench", "evict"],
    }

    flags = standardFlags()
    t.main(flags, bitcoinConf, None)
