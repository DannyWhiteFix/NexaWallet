#!/usr/bin/env python3
# Copyright (c) 2014-2015 The Bitcoin Core developers
# Copyright (c) 2015-2022 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
import test_framework.loginit

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from test_framework.nodemessages import *
import urllib.parse

class AbandonConflictTest(BitcoinTestFramework):

    def setup_network(self):
        self.nodes = []
        self.nodes.append(start_node(0, self.options.tmpdir, ["-debug=net,mempool","-logtimemicros","-relay.minRelayTxFee=1000"]))
        self.nodes.append(start_node(1, self.options.tmpdir, ["-debug=net,mempool","-logtimemicros"]))
        connect_nodes(self.nodes[0], 1)

    def run_test(self):
        self.nodes[1].generate(100)
        sync_blocks(self.nodes)
        balance = self.nodes[0].getbalance()
        txA = self.nodes[0].sendtoaddress(self.nodes[0].getnewaddress(), Decimal("1000000"))
        txB = self.nodes[0].sendtoaddress(self.nodes[0].getnewaddress(), Decimal("1000000"))
        txC = self.nodes[0].sendtoaddress(self.nodes[0].getnewaddress(), Decimal("1000000"))
        sync_mempools(self.nodes)
        self.nodes[1].generate(1)

        sync_blocks(self.nodes)
        newbalance = self.nodes[0].getbalance()
        print("balance " + str(newbalance) + " balance " + str(balance))
        assert(balance - newbalance < Decimal("10")) #no more than fees lost
        balance = newbalance

        url = urllib.parse.urlparse(self.nodes[1].url)
        self.nodes[0].disconnectnode(url.hostname+":"+str(p2p_port(1)))

        # Identify the 1 MNEX outputs
        nA = next(i for i, vout in enumerate(self.nodes[0].getrawtransaction(txA, 1000000)["vout"]) if vout["value"] == Decimal("1000000"))
        nB = next(i for i, vout in enumerate(self.nodes[0].getrawtransaction(txB, 1000000)["vout"]) if vout["value"] == Decimal("1000000"))
        nC = next(i for i, vout in enumerate(self.nodes[0].getrawtransaction(txC, 1000000)["vout"]) if vout["value"] == Decimal("1000000"))

        inputs =[]
        # spend 1MNEX outputs from txA and txB
        inputs.append({"outpoint":COutPoint().fromIdemAndIdx(txA, nA).rpcHex(), "amount": Decimal("1000000")})
        inputs.append({"outpoint":COutPoint().fromIdemAndIdx(txB, nB).rpcHex(), "amount": Decimal("1000000")})
        outputs = {}

        outputs[self.nodes[0].getnewaddress()] = Decimal("1499998")
        outputs[self.nodes[1].getnewaddress()] = Decimal("500000")
        signed = self.nodes[0].signrawtransaction(self.nodes[0].createrawtransaction(inputs, outputs))
        txAB1 = self.nodes[0].sendrawtransaction(signed["hex"])

        # Identify the 1499998 output
        nAB = next(i for i, vout in enumerate(self.nodes[0].getrawtransaction(txAB1, 1)["vout"]) if vout["value"] == Decimal("1499998"))

        # Create a child tx spending AB1 and C
        inputs = []
        inputs.append({"outpoint":COutPoint().fromIdemAndIdx(txAB1, nAB).rpcHex(), "amount": Decimal("1499998")})
        inputs.append({"outpoint":COutPoint().fromIdemAndIdx(txC, nC).rpcHex(), "amount": Decimal("1000000")})
        outputs = {}
        outputs[self.nodes[0].getnewaddress()] = Decimal("2499960")
        signed2 = self.nodes[0].signrawtransaction(self.nodes[0].createrawtransaction(inputs, outputs))
        txABC2 = self.nodes[0].sendrawtransaction(signed2["hex"])

        # In txpool txs from self should increase balance from change
        newbalance = self.nodes[0].getbalance()
        assert(newbalance == balance - Decimal("3000000") + Decimal("2499960"))
        balance = newbalance

        # Restart the node with a higher min relay fee so the parent tx is no longer in txpool
        # TODO: redo with eviction
        # Note: had to make sure tx was a considered a free transaction to prevent it from getting into the txpool.
        stop_node(self.nodes[0],0)
        self.nodes[0]=start_node(0, self.options.tmpdir, ["-debug=net,mempool","-logtimemicros","-relay.priority=1", "-relay.minRelayTxFee=10000", "-relay.limitFreeRelay=0"])

       # Verify txs no longer in txpool
        assert(len(self.nodes[0].getrawtxpool()) == 0)

        # Not in txpool txs from self should only reduce balance
        # inputs are still spent, but change not received
        newbalance = self.nodes[0].getbalance()
        assert(newbalance == balance - Decimal("2499960"))
        # Unconfirmed received funds that are not in txpool, also shouldn't show
        # up in unconfirmed balance
        unconfbalance = self.nodes[0].getunconfirmedbalance() + self.nodes[0].getbalance()
        assert(unconfbalance == newbalance)
        # Also shouldn't show up in listunspent
        assert(not txABC2 in [utxo["txid"] for utxo in self.nodes[0].listunspent(0)])
        balance = newbalance

        # Abandon original transaction and verify inputs are available again
        # including that the child tx was also abandoned
        self.nodes[0].abandontransaction(txAB1)
        newbalance = self.nodes[0].getbalance()
        assert(newbalance == balance + Decimal("3000000"))
        balance = newbalance

        # Verify that even with a zero min relay fee, the tx is not reaccepted from wallet on startup once abandoned
        stop_node(self.nodes[0],0)
        self.nodes[0]=start_node(0, self.options.tmpdir, ["-debug=net,mempool","-logtimemicros","-relay.minRelayTxFee=0", "-cache.persistTxPool=0"])
        assert(len(self.nodes[0].getrawtxpool()) == 0)
        assert(self.nodes[0].getbalance() == balance)

        # But if its received again then it is unabandoned
        # And since now in txpool, the change is available
        # But its child tx remains abandoned
        self.nodes[0].enqueuerawtransaction(signed["hex"],"flush")
        newbalance = self.nodes[0].getbalance()
        assert(newbalance == balance - Decimal("2000000") + Decimal("1499998"))
        balance = newbalance

        # Send child tx again so its unabandoned
        self.nodes[0].enqueuerawtransaction(signed2["hex"],"flush")
        newbalance = self.nodes[0].getbalance()
        assert(newbalance == balance - Decimal("1000000") - Decimal("1499998") + Decimal("2499960"))
        balance = newbalance

        # Remove using high relay fee again
        stop_node(self.nodes[0],0)
        self.nodes[0]=start_node(0, self.options.tmpdir, ["-debug=net,mempool","-logtimemicros","-relay.priority=1","-relay.minRelayTxFee=10000", "-relay.limitFreeRelay=0"])
        assert(len(self.nodes[0].getrawtxpool()) == 0)
        newbalance = self.nodes[0].getbalance()
        assert(newbalance == balance - Decimal("2499960"))
        balance = newbalance

        # Create a double spend of AB1 by spending again from only A's 10 output
        # Mine double spend from node 1
        inputs =[]
        inputs.append({"outpoint":COutPoint().fromIdemAndIdx(txA, nA).rpcHex(), "amount": Decimal("1000000")})
        outputs = {}
        outputs[self.nodes[1].getnewaddress()] = Decimal("999990")

        tx = self.nodes[0].createrawtransaction(inputs, outputs)
        signed = self.nodes[0].signrawtransaction(tx)
        self.nodes[1].enqueuerawtransaction(signed["hex"],"flush")
        blkhash = self.nodes[1].generate(1)[0]
        blk = self.nodes[1].getblock(blkhash)
        assert signed["txid"] in blk["txid"]

        connect_nodes(self.nodes[0], 1)
        sync_blocks(self.nodes)

        assert self.nodes[0].getbestblockhash() == blkhash
        # Verify that B and C's 1 BTC outputs are available for spending again because AB1 is now conflicted
        newbalance = self.nodes[0].getbalance()
        assert(newbalance == balance + Decimal("2000000"))
        balance = newbalance

        # There is currently a minor bug around this and so this test doesn't work.  See Issue #7315
        # Invalidate the block with the double spend and B's 1 BCH output should no longer be available
        # Don't think C's should either
        self.nodes[0].invalidateblock(self.nodes[0].getbestblockhash())
        newbalance = self.nodes[0].getbalance()
        #assert(newbalance == balance - Decimal("1.0"))
        print("If balance has not declined after invalidateblock then out of txpool wallet tx which is no longer")
        print("conflicted has not resumed causing its inputs to be seen as spent.  See Issue #7315")
        print(str(balance) + " -> " + str(newbalance) + " ?")

if __name__ == '__main__':
    AbandonConflictTest().main()

def Test():
    t = AbandonConflictTest()
    t.drop_to_pdb = True
    bitcoinConf = {
        "debug": ["rpc","net", "blk", "thin", "mempool", "req", "bench", "evict"]
    }
    flags = standardFlags()
    t.main(flags, bitcoinConf, None)
