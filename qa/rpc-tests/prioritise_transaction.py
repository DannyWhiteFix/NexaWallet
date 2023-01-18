#!/usr/bin/env python3
# Copyright (c) 2015 The Bitcoin Core developers
# Copyright (c) 2015-2022 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
import test_framework.loginit
#
# Test PrioritiseTransaction code
#

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from test_framework.blocktools import *
from test_framework.mininode import COIN

MAX_BLOCK_SIZE = 3000000

class PrioritiseTransactionTest(BitcoinTestFramework):

    def __init__(self):
        self.txouts = gen_return_txouts()

    def setup_chain(self):
        logging.info("Initializing test directory "+self.options.tmpdir)
        initialize_chain_clean(self.options.tmpdir, 1)

    def setup_network(self):
        self.nodes = []
        self.is_network_split = False

        self.nodes.append(start_node(0, self.options.tmpdir, ["-mining.blockSize=" + str(MAX_BLOCK_SIZE), "-test.nextMaxBlockSize=" + str(MAX_BLOCK_SIZE), "-relay.minRelayTxFee=1000", "-printpriority=1", "-relay.limitFreeRelay=0", "-debug=mempool"]))
        self.relayfee = self.nodes[0].getnetworkinfo()['relayfee']

    def run_test(self):
        utxo_count = 90
        utxos = create_confirmed_utxos(self.relayfee, self.nodes[0], utxo_count)
        base_fee = decimal.Decimal(self.relayfee)
        txids = []

        # Create 3 batches of transactions at 3 different fee rate levels
        range_size = utxo_count // 3
        for i in range(3):
            txids.append([])
            start_range = i * range_size
            end_range = start_range + range_size
            txids[i] = create_lots_of_big_transactions(self.nodes[0], self.txouts, utxos[start_range:end_range], end_range - start_range, (i+1)*base_fee)[1]

        # Make sure that the size of each group of transactions exceeds
        # MAX_BLOCK_SIZE -- otherwise the test needs to be revised to create
        # more transactions.
        txpool = self.nodes[0].getrawtxpool(True, "id")
        assert(txids[0][0] in txpool)
        assert(txids[0][1] in txpool)
        sizes = [0, 0, 0]
        for i in range(3):
            for j in txids[i]:
                assert(j in txpool)
                sizes[i] += txpool[j]['size']
        assert(self.nodes[0].gettxpoolinfo()["bytes"] > MAX_BLOCK_SIZE) # Fail => raise utxo_count

        # add a fee delta to something in the cheapest bucket and make sure it gets mined
        # also check that a different entry in the cheapest bucket is NOT mined (lower
        # the priority to ensure its not mined due to priority)
        result = self.nodes[0].prioritisetransaction(txids[0][0], 0, int(3*base_fee*COIN))
        assert result
        result = self.nodes[0].prioritisetransaction(txids[0][1], -1e15, 0)
        assert result
        self.nodes[0].generate(1)
        txpool = self.nodes[0].getrawtxpool(False,"id")
        logging.info("Assert that prioritised transaction was mined")
        assert(txids[0][0] not in txpool)
        assert(txids[0][1] in txpool)

        high_fee_tx = None
        for x in txids[2]:
            if x not in txpool:
                high_fee_tx = x

        # Something high-fee should have been mined!
        assert(high_fee_tx != None)

        # Add a prioritisation before a tx is in the txpool (de-prioritising a
        # high-fee transaction so that it's now low fee).
        # This must be done as a txid, not txidem
        logging.info("Add a prioritisation before invalidating a block")
        ret = self.nodes[0].prioritisetransaction(high_fee_tx, -1e15, -int(100*base_fee*COIN))
        assert ret == False  # False means couldn't find it, but added an entry anyway

        # Add everything back to txpool
        self.nodes[0].invalidateblock(self.nodes[0].getbestblockhash())

        # Check to make sure our high fee rate tx is back in the txpool
        waitFor(60, lambda: high_fee_tx in self.nodes[0].getrawtxpool(False, "id"))

        # Now verify the modified-high feerate transaction isn't mined before
        # the other high fee transactions. Keep mining until our txpool has
        # decreased by all the high fee size that we calculated above.
        while (self.nodes[0].gettxpoolinfo()['bytes'] > sizes[0] + sizes[1]):
            poolDetails = self.nodes[0].getrawtxpool(True, "id")
            txDetails = poolDetails[high_fee_tx]
            assert txDetails["currentpriority"] < 0
            print("tx ", txDetails)
            blk = self.nodes[0].generate(1)[0]
            print("generated ", blk)
            blkjson = self.nodes[0].getblock(blk)
            assert not high_fee_tx in blkjson['txid']

        # High fee transaction should not have been mined, but other high fee rate
        # transactions should have been.
        txpool = self.nodes[0].getrawtxpool(False,"id")
        logging.info("Assert that de-prioritised transaction is still in txpool")
        assert(high_fee_tx in txpool)
        for x in txids[2]:
            if (x != high_fee_tx):
                assert(x not in txpool)

        # Create a free, low priority transaction.  Should be rejected.
        utxo_list = self.nodes[0].listunspent()
        assert(len(utxo_list) > 0)
        utxo = None
        for idx, u in enumerate(utxo_list):
            if u["amount"] > self.relayfee * 100:  # get a reasonably big utxo
                utxo = u
                del utxo_list[idx]
                break

        inputs = []
        outputs = {}
        inputs.append({"outpoint" : utxo["outpoint"], "amount" : utxo["amount"]})
        outamt = utxo["amount"] - self.relayfee
        outputs[self.nodes[0].getnewaddress()] = outamt
        raw_tx = self.nodes[0].createrawtransaction(inputs, outputs)
        tx_hex = self.nodes[0].signrawtransaction(raw_tx)["hex"]
        txid = self.nodes[0].sendrawtransaction(tx_hex)

        # A tx that spends an in-txpool tx has 0 priority, so we can use it to
        # test the effect of using prioritise transaction for txpool acceptance
        inputs = []
        inputs.append({"outpoint": COutPoint().fromIdemAndIdx(txid,0).rpcHex(), "amount":outamt})
        outputs = {}
        outputs[self.nodes[0].getnewaddress()] = utxo["amount"] - self.relayfee
        raw_tx2 = self.nodes[0].createrawtransaction(inputs, outputs)
        tx2_signed = self.nodes[0].signrawtransaction(raw_tx2)
        tx2_hex = tx2_signed["hex"]
        tx2_idem = tx2_signed["txidem"] # self.nodes[0].decoderawtransaction(tx2_hex)["txidem"]
        try:
            self.nodes[0].sendrawtransaction(tx2_hex)
        except JSONRPCException as exp:
            assert_equal(exp.error['code'], -26) # insufficient fee
            assert(tx2_idem not in self.nodes[0].getrawtxpool())
        else:
            assert(False)

        # This is a less than 1000-byte transaction, so just set the fee
        # to be the minimum for a 1000 byte transaction and check that it is
        # accepted.
        self.nodes[0].prioritisetransaction(tx2_idem, 0, int(self.relayfee*100*COIN))

        logging.info("Assert that prioritised free transaction is accepted to txpool")
        self.nodes[0].sendrawtransaction(tx2_hex)
        waitFor(60, lambda: tx2_idem in self.nodes[0].getrawtxpool())

        # Try via ID
        utxo = None
        for idx, u in enumerate(utxo_list):
            if u["amount"] > self.relayfee * 100:  # get a reasonably big utxo
                utxo = u
                del utxo_list[idx]
                break

        inputs = []
        outputs = {}
        inputs.append({"outpoint" : utxo["outpoint"], "amount" : utxo["amount"]})
        outamt = utxo["amount"] - self.relayfee
        outputs[self.nodes[0].getnewaddress()] = outamt
        raw_tx = self.nodes[0].createrawtransaction(inputs, outputs)
        tx_hex = self.nodes[0].signrawtransaction(raw_tx)["hex"]
        txid = self.nodes[0].sendrawtransaction(tx_hex)

        # A tx that spends an in-txpool tx has 0 priority, so we can use it to
        # test the effect of using prioritise transaction for txpool acceptance
        inputs = []
        inputs.append({"outpoint": COutPoint().fromIdemAndIdx(txid,0).rpcHex(), "amount":outamt})
        outputs = {}
        outputs[self.nodes[0].getnewaddress()] = utxo["amount"] - self.relayfee
        raw_tx2 = self.nodes[0].createrawtransaction(inputs, outputs)
        tx2_signed = self.nodes[0].signrawtransaction(raw_tx2)
        tx2_hex = tx2_signed["hex"]
        tx2_id = tx2_signed["txid"] # self.nodes[0].decoderawtransaction(tx2_hex)["txidem"]
        try:
            self.nodes[0].sendrawtransaction(tx2_hex)
        except JSONRPCException as exp:
            assert_equal(exp.error['code'], -26) # insufficient fee
            assert(tx2_id not in self.nodes[0].getrawtxpool(False,"id"))
        else:
            assert(False)

        # This is a less than 1000-byte transaction, so just set the fee
        # to be the minimum for a 1000 byte transaction and check that it is
        # accepted.
        self.nodes[0].prioritisetransaction(tx2_id, 0, int(self.relayfee*100*COIN))

        logging.info("Assert that prioritised free transaction is accepted to txpool")
        self.nodes[0].sendrawtransaction(tx2_hex)
        waitFor(60, lambda: tx2_id in self.nodes[0].getrawtxpool(False, "id"))


if __name__ == '__main__':
    PrioritiseTransactionTest().main()

def Test():
    t = PrioritiseTransactionTest()
    t.drop_to_pdb = True
    import signal, pdb
    signal.signal(signal.SIGINT, lambda sig, stk: pdb.Pdb().set_trace(stk))
    bitcoinConf = {
        "debug": ["blk", "mempool", "net", "req"],
        "logtimemicros": 1
    }

    flags = standardFlags()
    t.main(flags, bitcoinConf, None)
