#!/usr/bin/env python3
# Copyright (c) 2015-2023 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import test_framework.loginit
import logging
#logging.getLogger().setLevel(logging.INFO)

#
# Test HardFork1 block size increase activation
#
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from test_framework.blocktools import *
from test_framework.nodemessages import *
from test_framework.script import *

# Accurately count satoshis
# 8 digits to get to 21million, and each bitcoin is 100 million satoshis
import decimal
decimal.getcontext().prec = 16

class UpgradeActivationTest(BitcoinTestFramework):

    def setup_chain(self):
        print("Initializing test directory "+self.options.tmpdir)
        initialize_chain_clean(self.options.tmpdir, 2, self.confDict)

    def setup_network(self):
        self.nodes = []
        self.is_network_split = False
        self.nodes.append(start_node(0, self.options.tmpdir, []))
        self.nodes.append(start_node(1, self.options.tmpdir, []))
        interconnect_nodes(self.nodes)

    def testWideStack(self, shouldItWork):
        """ Test wide stack operations """
        # Make a tx that uses too much stack
        tx = CTransaction()
        scr = CScript([bytes([1,2]), OP_DUP, OP_CAT,  # 4
                       OP_DUP, OP_CAT, OP_DUP, OP_CAT, OP_DUP, OP_CAT, OP_DUP, OP_CAT, OP_DUP, OP_CAT, # 128
                       OP_DUP, OP_CAT, OP_DUP, OP_CAT, OP_DUP, OP_CAT, OP_DROP, OP_TRUE
        ])
        tx.vout.append(CTxOut(10000, scr))
        h = tx.toHex()
        frtReturn = self.nodes[0].fundrawtransaction(h)
        sgnReturn = self.nodes[0].signrawtransaction(frtReturn["hex"])
        print(sgnReturn)
        fundedTx = CTransaction().fromHex(sgnReturn["hex"])
        print(fundedTx)
        self.nodes[0].sendrawtransaction(sgnReturn["hex"])

        txs = CTransaction()
        # spend it
        for idx in range(0, len(fundedTx.vout)):
            if fundedTx.vout[idx].nValue == 10000:  # its my output
                txs.vin.append(fundedTx.SpendOutput(idx))  # I don't have to sign it because its anyone can spend
                break

        txs.vout.append(CTxOut(9000, scr))
        print(txs)

        try:
            spendTxSend = self.nodes[0].sendrawtransaction(txs.toHex())
            print(spendTxSend)
            assert shouldItWork, "Large stack width worked"
        except JSONRPCException as e:
            assert not shouldItWork, "Large stack width did not work: %s" % e

    def preupgradeTests(self):
        """Add any tests here that should run prior to the upgrade"""
        self.testWideStack(False)
        pass

    def atUpgradeTests(self):
        """Add any tests here that should run when the current block is not upgraded but the next one will be"""
        pass

    def postupgradeTests(self):
        """Add any tests here that should run after the upgrade"""
        self.testWideStack(True)
        pass


    def run_test(self):

        # Mine some blocks to get utxos etc

        # Generate enough blocks that we can spend some coinbase.
        nBlocks = 101
        self.nodes[0].generate(nBlocks-1)
        self.sync_all()
        self.nodes[0].generate(1)
        assert_equal(self.nodes[0].getblockcount(), 101)

        # mine a few blocks 1 second apart so we can get a more meaningful "mediantime"
        bestblock = self.nodes[0].getbestblockhash()
        lastblocktime = self.nodes[0].getblockheader(bestblock)['time']
        mocktime = lastblocktime
        for i in range(10):
            mocktime = mocktime + 120
            self.nodes[0].setmocktime(mocktime)
            self.nodes[0].generate(1)
        assert_equal(self.nodes[0].getblockcount(), 111)

        self.preupgradeTests()

        # set the hardfork activation to just a few blocks ahead
        bestblock = self.nodes[0].getbestblockhash()
        lastblocktime = self.nodes[0].getblockheader(bestblock)['time']
        activationtime = lastblocktime + 240
        self.nodes[0].set("consensus.fork1Time=" + str(activationtime))

        blockchaininfo = self.nodes[0].getblockchaininfo()
        assert_equal(blockchaininfo['forktime'], activationtime)
        assert_equal(blockchaininfo['forkactive'], False)
        assert_equal(blockchaininfo['forkenforcednextblock'], False)
        assert_greater_than(activationtime, blockchaininfo['mediantime'])

        # Mine just up to the hard fork activation (activationtime will still be greater than mediantime).
        for i in range(6):
            mocktime = mocktime + 120
            self.nodes[0].setmocktime(mocktime)
            self.nodes[0].generate(1)
            blockchaininfo = self.nodes[0].getblockchaininfo()
            assert_equal(blockchaininfo['forkactive'], False)
            assert_equal(blockchaininfo['forkenforcednextblock'], False)
            assert_greater_than(activationtime, blockchaininfo['mediantime']) # activationtime > mediantime

        # Fork should be active after the next block mined (median time will be greater than or equal to blocktime)
        # NOTE: although the fork will be active on the next block, the nextmaxblocksize will not increase
        #       yet.  This is because we can not have an increase in the nextmaxblocksize until we mine our
        #       first block under the new rules.
        self.atUpgradeTests()
        mocktime = mocktime + 120
        self.nodes[0].setmocktime(mocktime)
        self.nodes[0].generate(1)
        blockchaininfo = self.nodes[0].getblockchaininfo()
        assert_equal(blockchaininfo['forkactive'], True)
        assert_equal(blockchaininfo['forkenforcednextblock'], True)
        assert_equal(activationtime, blockchaininfo['mediantime']) # when median time is >= activationtime

        # First block mined under new rules:  At this point the nextmaxblocksize can be calculated
        # and will allow for a larger block after the first fork block is mined.
        mocktime = mocktime + 120
        self.nodes[0].setmocktime(mocktime)
        self.nodes[0].generate(1)
        blockchaininfo = self.nodes[0].getblockchaininfo()
        assert_equal(blockchaininfo['forkactive'], True)
        assert_equal(blockchaininfo['forkenforcednextblock'], False)
        assert_greater_than(blockchaininfo['mediantime'], activationtime)

        self.postupgradeTests()

        # Mine a few more blocks. Nothing should change regarding activation.
        for i in range(10):
            mocktime = mocktime + 120
            self.nodes[0].setmocktime(mocktime)
            self.nodes[0].generate(1)
            blockchaininfo = self.nodes[0].getblockchaininfo()
            assert_equal(blockchaininfo['forkactive'], True)
            assert_equal(blockchaininfo['forkenforcednextblock'], False)
            assert_greater_than(blockchaininfo['mediantime'], activationtime)

if __name__ == '__main__':
    UpgradeActivationTest().main()

def Test():
    t = UpgradeActivationTest()
    t.drop_to_pdb = True
    bitcoinConf = {
        "debug": ["validation", "rpc", "net", "blk", "thin", "mempool", "req", "bench", "evict"],
    }
    flags = standardFlags()
    flags[0] = '--tmpdir=/ramdisk/test/t'
    t.main(flags, bitcoinConf, None)
