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

    def setup_chain(self,bitcoinConfDict=None, wallets=None):
        print("Initializing test directory "+self.options.tmpdir)
        # initialize_chain_clean(self.options.tmpdir, 2, self.confDict)
        initialize_chain(self.options.tmpdir, bitcoinConfDict, wallets)

    def setup_network(self):
        self.nodes = []
        self.is_network_split = False
        self.nodes.append(start_node(0, self.options.tmpdir, []))
        self.nodes.append(start_node(1, self.options.tmpdir, []))
        interconnect_nodes(self.nodes)

    def testStackLimit(self, dups, shouldItWork):
        """ Test max stack size """
        tx = CTransaction()

        scrList = [bytes([1,2]), OP_DUP, OP_CAT,  # 4
                       OP_DUP, OP_CAT, OP_DUP, OP_CAT, OP_DUP, OP_CAT, OP_DUP, OP_CAT, OP_DUP, OP_CAT, # 128
                       OP_DUP, OP_CAT, OP_DUP, OP_CAT, OP_DUP # 2 items of 512 bytes each
        ]
        scrList += [OP_2DUP] * (dups-1)
        scrList += [OP_2DROP] * dups

        out = TxOut(nValue=10000)
        scr = CScript(scrList)
        out.setLockingToTemplate(scr,None)
        tx.vout.append(out)

        h = tx.toHex()
        # print("Transaction: " + h)

        frtReturn = self.nodes[0].fundrawtransaction(h)
        sgnReturn = self.nodes[0].signrawtransaction(frtReturn["hex"])
        fundedTx = CTransaction().fromHex(sgnReturn["hex"])
        # print("Funded signed transaction: " + str(fundedTx)[0:200])
        self.nodes[0].sendrawtransaction(sgnReturn["hex"])

        txs = CTransaction()
        # spend it
        for idx in range(0, len(fundedTx.vout)):
            if fundedTx.vout[idx].nValue == 10000:  # its my output
                inp = fundedTx.SpendOutput(idx)
                inp.setUnlockingToTemplate(scr, None, None)
                txs.vin.append(inp)  # I don't have to sign it because its anyone can spend
                break
        txs.vout.append(TxOut(TxOut.TYPE_SATOSCRIPT, 9000, CScript()))
        # print(txs)
        # print("http://debug.nexa.org/tx/%s?idx=0&utxo=%s" % (txs.toHex(), out.toHex()))

        validatedResult = self.nodes[0].validaterawtransaction(txs.toHex())
        if not shouldItWork:
            assert "mandatory-script-verify-flag-failed" in validatedResult["inputs_flags"]['inputs'][0]['errors'][0]
            return

        try:
            spendTxSend = self.nodes[0].sendrawtransaction(txs.toHex())
            # print("Spending TX: %s" % spendTxSend)
            assert shouldItWork, "Large stack worked"
        except JSONRPCException as e:
            assert not shouldItWork, "Large stack did not work: %s" % e


    def testWideStack(self, shouldItWork, template=True):
        """ Test wide stack operations """
        # Make a tx that uses too much stack
        tx = CTransaction()
        scr = CScript([bytes([1,2]), OP_DUP, OP_CAT,  # 4
                       OP_DUP, OP_CAT, OP_DUP, OP_CAT, OP_DUP, OP_CAT, OP_DUP, OP_CAT, OP_DUP, OP_CAT, # 128
                       OP_DUP, OP_CAT, OP_DUP, OP_CAT, OP_DUP, OP_CAT,
                       OP_DROP, OP_TRUE if not template else OP_NOP
        ])
        if template:
            out = TxOut(nValue=10000)
            out.setLockingToTemplate(scr,None)
            tx.vout.append(out)
        else:
            tx.vout.append(CTxOut(10000, scr))
        h = tx.toHex()
        frtReturn = self.nodes[0].fundrawtransaction(h)
        sgnReturn = self.nodes[0].signrawtransaction(frtReturn["hex"])
        assert len(sgnReturn.get("errors",[])) ==0, print("Error funding transaction: %s" % sgnReturn)
        # print(sgnReturn)
        fundedTx = CTransaction().fromHex(sgnReturn["hex"])
        # print(fundedTx)
        vrt = self.nodes[0].validaterawtransaction(sgnReturn["hex"])
        # print(vrt)
        self.nodes[0].sendrawtransaction(sgnReturn["hex"])

        txs = CTransaction()
        # spend it
        for idx in range(0, len(fundedTx.vout)):
            if fundedTx.vout[idx].nValue == 10000:  # its my output
                if template:
                    inp = fundedTx.SpendOutput(idx)
                    inp.setUnlockingToTemplate(scr, None, None)
                    txs.vin.append(inp)  # I don't have to sign it because its anyone can spend
                else:
                    txs.vin.append(fundedTx.SpendOutput(idx))  # I don't have to sign it because its anyone can spend
                break

        txs.vout.append(CTxOut(9000, scr))
        # print(txs)
        # print(txs.toHex())

        # vrt = self.nodes[0].validaterawtransaction(txs.toHex())
        # print(vrt)

        try:
            spendTxSend = self.nodes[0].sendrawtransaction(txs.toHex())
            # print(spendTxSend)
            assert shouldItWork, "Large stack width worked"
        except JSONRPCException as e:
            if shouldItWork:
                print(txs)
                print(txs.toHex())
            assert not shouldItWork, "Large stack width did not work: %s" % e

    def preupgradeTests(self):
        """Add any tests here that should run prior to the upgrade"""
        self.testWideStack(False)
        # testStackLimit N checks a stack of size N*1024 made up of 2 512 byte stack items
        self.testStackLimit(500, True)
        self.testStackLimit(1024, False)
        pass

    def atUpgradeTests(self):
        """Add any tests here that should run when the current block is not upgraded but the next one will be"""
        pass

    def postupgradeTests(self):
        """Add any tests here that should run after the upgrade"""
        self.testWideStack(True)

        # testStackLimit N checks a stack of size N*1024 made up of 2 512 byte stack items
        self.testStackLimit(1024, True)  # So this is the max
        self.testStackLimit(1, True)
        self.testStackLimit(11, True)
        self.testStackLimit(111, True)
        self.testStackLimit(1111, False) # Nothing above 1MB (1024*1024) will work
        self.testStackLimit(1025, False)
        pass

    def run_test(self):
        # Mine some blocks to get utxos etc

        # mine a few blocks 1 second apart so we can get a meaningful "mediantime"
        # that does not contain the gap between the cached blockchain and this run
        bestblock = self.nodes[0].getbestblockhash()
        lastblocktime = self.nodes[0].getblockheader(bestblock)['time']
        mocktime = lastblocktime
        for i in range(10):
            mocktime = mocktime + 120
            self.nodes[0].setmocktime(mocktime)
            self.nodes[0].generate(1)
        assert_equal(self.nodes[0].getblockcount(), 210)

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
