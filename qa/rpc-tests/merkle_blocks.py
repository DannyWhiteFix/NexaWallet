#!/usr/bin/env python3
# Copyright (c) 2014-2015 The Bitcoin Core developers
# Copyright (c) 2015-2021 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
import test_framework.loginit
#
# Test merkleblock fetch/validation
#

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *

class MerkleBlockTest(BitcoinTestFramework):

    def setup_chain(self):
        print("Initializing test directory "+self.options.tmpdir)
        initialize_chain_clean(self.options.tmpdir, 4)

    def setup_network(self):
        self.nodes = []
        # Nodes 0/1 are "wallet" nodes
        self.nodes.append(start_node(0, self.options.tmpdir, ["-debug"]))
        self.nodes.append(start_node(1, self.options.tmpdir, ["-debug"]))
        # Nodes 2/3 are used for testing
        self.nodes.append(start_node(2, self.options.tmpdir, ["-debug"]))
        self.nodes.append(start_node(3, self.options.tmpdir, ["-debug", "-txindex"]))
        connect_nodes(self.nodes[0], 1)
        connect_nodes(self.nodes[0], 2)
        connect_nodes(self.nodes[0], 3)

        self.is_network_split = False
        self.sync_all()

    def run_test(self):
        print("Mining blocks...")
        self.nodes[0].generate(105)
        self.sync_all()

        chain_height = self.nodes[1].getblockcount()
        assert_equal(chain_height, 105)
        assert_equal(self.nodes[1].getbalance(), 0)
        assert_equal(self.nodes[2].getbalance(), 0)

        sync_wallet(30, self.nodes[0])
        node0utxos = self.nodes[0].listunspent(1)
        tx1 = self.nodes[0].createrawtransaction([node0utxos.pop()], {self.nodes[1].getnewaddress(): COINBASE_REWARD})
        tx1 = self.nodes[0].signrawtransaction(tx1)
        txidem1 = self.nodes[0].sendrawtransaction(tx1["hex"])
        txid1 = tx1["txid"]
        tx2 = self.nodes[0].createrawtransaction([node0utxos.pop()], {self.nodes[1].getnewaddress(): COINBASE_REWARD})
        tx2 = self.nodes[0].signrawtransaction(tx2)
        txid2 = tx2["txid"]
        txidem2 = self.nodes[0].sendrawtransaction(tx2["hex"])
        assert_raises(JSONRPCException, self.nodes[0].gettxoutproof, [txid1])

        self.nodes[0].generate(1)
        blockhash = self.nodes[0].getblockhash(chain_height + 1)
        self.sync_all()

        txlist = []
        blocktxn = self.nodes[0].getblock(blockhash, True)["txid"]
        txlist.append(blocktxn[1])
        txlist.append(blocktxn[2])
        # I have to use idems here because I am relying on the outpoints to find the block (since I didn't supply a block)
        # If I had txindex enabled, I could provide txids
        proof = self.nodes[2].gettxoutproof([txidem1])
        assert_equal(self.nodes[2].verifytxoutproof(proof), [txid1])
        proof = self.nodes[2].gettxoutproof([txidem1, txidem2])
        assert_equal(self.nodes[2].verifytxoutproof(proof), txlist)
        # If I supplied the block, I can give txids
        proof = self.nodes[2].gettxoutproof([txid1, txid2], blockhash)
        assert_equal(self.nodes[2].verifytxoutproof(proof), txlist)

        txin_spent = self.nodes[1].listunspent(1).pop()
        tx3 = self.nodes[1].createrawtransaction([txin_spent], {self.nodes[0].getnewaddress(): COINBASE_REWARD})
        self.nodes[0].sendrawtransaction(self.nodes[1].signrawtransaction(tx3)["hex"])
        self.nodes[0].generate(1)
        self.sync_all()

        txidem_spent = txin_spent["txidem"]
        txidem_unspent = txidem1 if txin_spent["txid"] != txid1 else txidem2
        txid_spent = txin_spent["txid"]
        txid_unspent = txid1 if txin_spent["txid"] != txid1 else txid2

        # We can't find the block from a fully-spent tx
        assert_raises(JSONRPCException, self.nodes[2].gettxoutproof, [txidem_spent])
        assert_raises(JSONRPCException, self.nodes[2].gettxoutproof, [txid_spent])
        # ...but we can if we specify the block
        assert_equal(self.nodes[2].verifytxoutproof(self.nodes[2].gettxoutproof([txidem_spent], blockhash)), [txid_spent])
        assert_equal(self.nodes[2].verifytxoutproof(self.nodes[2].gettxoutproof([txid_spent], blockhash)), [txid_spent])
        # ...or if the first tx is not fully-spent
        proof = self.nodes[2].gettxoutproof([txidem_unspent])
        assert_equal(self.nodes[2].verifytxoutproof(proof), [txid_unspent])
        try:
            assert_equal(self.nodes[2].verifytxoutproof(self.nodes[2].gettxoutproof([txidem1, txidem2])), txlist)
        except JSONRPCException:
            assert_equal(self.nodes[2].verifytxoutproof(self.nodes[2].gettxoutproof([txidem2, txidem1])), txlist)
        # ...or if we have a -txindex
        assert_equal(self.nodes[2].verifytxoutproof(self.nodes[3].gettxoutproof([txid_spent])), [txid_spent])

        # ensure we get the same data for fetching multiple proofs at a time that we get for each one individually
        proofsresult = self.nodes[2].gettxoutproofs([txid1, txid2], blockhash)
        assert_equal(proofsresult[txid1], self.nodes[2].gettxoutproof([txid1], blockhash))
        assert_equal(proofsresult[txid2], self.nodes[2].gettxoutproof([txid2], blockhash))

if __name__ == '__main__':
    MerkleBlockTest().main()

# Create a convenient function for an interactive python debugging session
def Test():
    t = MerkleBlockTest()
    t.drop_to_pdb = True
    # install ctrl-c handler
    #import signal, pdb
    #signal.signal(signal.SIGINT, lambda sig, stk: pdb.Pdb().set_trace(stk))
    bitcoinConf = {
        "debug": ["net", "blk", "thin", "mempool", "req", "bench", "evict"],
        "blockprioritysize": 2000000  # we don't want any transactions rejected due to insufficient fees...
    }
    SetupPythonLogConfig("INFO")
    flags = standardFlags()
    t.main(flags, bitcoinConf, None)
