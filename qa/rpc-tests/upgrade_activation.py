#!/usr/bin/env python3
# Copyright (c) 2015-2023 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import test_framework.loginit
import logging
import pprint
from copy import copy as scopy
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

def fundSignSendParse(node, tx, verbose = False):
    h = tx.toHex()
    if verbose:
        print("Input TX: " + h)
        print("Decoded: " + pprint.pformat(node.decoderawtransaction(h)))
    frtReturn = node.fundrawtransaction(h)
    sgnReturn = node.signrawtransaction(frtReturn["hex"])
    if True: # if verbose:
        print("Funded TX: " + str(sgnReturn))
        print("Decoded: " + pprint.pformat(node.decoderawtransaction(sgnReturn["hex"])))
    fundedTx = CTransaction().fromHex(sgnReturn["hex"])
    v = node.validaterawtransaction(sgnReturn["hex"])
    if verbose:
        print(pprint.pformat(v))
    node.sendrawtransaction(sgnReturn["hex"])
    return fundedTx

def spendOutputOfAmount(amt, tx, templateScript, constraintArgs=None, satisfierArgs=None):
    for idx in range(0, len(tx.vout)):
            if tx.vout[idx].nValue == amt:  # its my output
                inp = tx.SpendOutput(idx)
                inp.setUnlockingToTemplate(templateScript, constraintArgs, satisfierArgs)
                return inp
    return None

class UpgradeActivationTest(BitcoinTestFramework):

    def setup_chain(self,bitcoinConfDict=None, wallets=None):
        print("Initializing test directory "+self.options.tmpdir)
        initialize_chain_clean(self.options.tmpdir, 2, self.confDict)
        # initialize_chain(self.options.tmpdir, bitcoinConfDict, wallets)

    def setup_network(self):
        self.nodes = []
        self.is_network_split = False
        self.nodes.append(start_node(0, self.options.tmpdir, []))
        self.nodes.append(start_node(1, self.options.tmpdir, []))
        interconnect_nodes(self.nodes)

    def testSomeScript(self, scriptList, shouldItWork):
        tx = CTransaction()
        out = TxOut(nValue=10000)
        scr = CScript(scriptList)
        out.setLockingToTemplate(scr,None)
        tx.vout.append(out)

        h = tx.toHex()

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


    def testNegOpRoll(self, shouldItWork):
        self.testSomeScript([ bytes([0x55]), OP_DUP, OP_DUP, OP_DEPTH, OP_NEGATE, OP_ROLL, OP_2DROP, OP_DROP], shouldItWork)
    def testNegOpPick(self, shouldItWork):
        self.testSomeScript([ bytes([0x55]), OP_DUP, OP_DUP, OP_DEPTH, OP_NEGATE, OP_PICK, OP_2DROP, OP_2DROP], shouldItWork)
        
    def testReadOnlyInput(self, shouldItWork):
        n = self.nodes[0]
        tx = CTransaction()
        out = TxOut(nValue=10000)
        scr = CScript([OP_FROMALTSTACK,OP_FROMALTSTACK, OP_DROP, OP_DROP])  # pop the two public args and always work
        out.setLockingToTemplate(scr,None, [1,2])
        tx.vout.append(out)

        out2 = TxOut(nValue=5000)
        out2.setLockingToTemplate(scr,None, [3,4])
        tx.vout.append(out2)

        out3 = TxOut(nValue=4000)
        scr3 = CScript([OP_DROP])  # You have to spend this with 1 push
        out3.setLockingToTemplate(scr3,None, None)
        tx.vout.append(out3)

        # Make a TX with an output that we will input readonly
        preTx = fundSignSendParse(n, tx)

        inp = spendOutputOfAmount(10000, preTx, scr)

        roInp = spendOutputOfAmount(10000, preTx, scr)
        assert roInp != None
        roInp.t = CTxIn.READONLY
        roInp.amount = 0
        roInp.scriptSig = bytes()

        # Set up another read only output, that we can use to test sig/nosig because a correct sig is a single push
        roInp3 = spendOutputOfAmount(4000, preTx, scr3, None, [1])
        assert roInp3 != None
        roInp3.t = CTxIn.READONLY
        roInp3.amount = 0

        # Read-only the prev tx -- should not work because not confirmed
        tx = CTransaction()
        tx.vin.append(roInp)
        tx.vout.append(out2)  # This output is worth half of the readonly input
        try:
            roTx = fundSignSendParse(n, tx)
            assert False, "should have failed because read-only needs to be confirmed before use"
        except JSONRPCException as e:
            pass # Worked

        blkhash = n.generate(1)[0] # commit preTx so we can access its outputs in the UTXO
        waitFor(30, lambda: n.getwalletinfo()["syncblock"] == blkhash)

        # Make a TX with a readonly input (should work if post fork), no signature
        tx = CTransaction()
        tx.vin.append(scopy(roInp))
        tx.vout.append(out2)
        try:
            roTx = fundSignSendParse(n, tx)
            assert shouldItWork, "Signing this tx should have failed (pre upgrade)"
            print("COMMITTING: ")
            print(pprint.pformat(n.decoderawtransaction(roTx.toHex())))
        except JSONRPCException as e:
            if shouldItWork:
                raise e
            assert not shouldItWork, "Signing this tx should have succeeded (post upgrade)"

        # nothing more to do pre-upgrade -- tx was rejected
        if not shouldItWork: return

        # Use the same read only input again
        tx = CTransaction()
        tx.vin.append(scopy(roInp))
        tx.vout.append(out2)
        try:
            roTx2 = fundSignSendParse(n, tx)
            assert shouldItWork, "Signing this tx should have failed (pre upgrade)"
            print(roTx2)
            print("COMMITTING: ")
            print(pprint.pformat(n.decoderawtransaction(roTx2.toHex())))
        except JSONRPCException as e:
            if shouldItWork:
                raise e
            assert not shouldItWork, "Signing this tx should have succeeded (post upgrade)"

        assert roTx != roTx2

        # RO input with a nonzero bad sig
        tx = CTransaction()
        tx.vin.append(scopy(roInp3))
        tx.vin[0].scriptSig = CScript([1,2,3,4])  # too many pushes
        tx.vout.append(out2)
        try:
            fundSignSendParse(n, tx)
            assert false
        except JSONRPCException as e:
            pass

        # RO input with a nonzero good sig
        tx = CTransaction()
        tx.vin.append(scopy(roInp3))
        tx.vout.append(out2)
        try:
            fundSignSendParse(n, tx, True)
        except JSONRPCException as e:
            if shouldItWork:
                raise e
            assert not shouldItWork, "Signing this tx should have succeeded (post upgrade)"

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
        self.testNegOpRoll(False)
        self.testNegOpPick(False)
        self.testReadOnlyInput(False)
        self.testWideStack(False)
        # testStackLimit N checks a stack of size N*1024 made up of 2 512 byte stack items
        self.testStackLimit(500, True)
        self.testStackLimit(1024, False)

    def atUpgradeTests(self):
        """Add any tests here that should run when the current block is not upgraded but the next one will be"""
        pass

    def postupgradeTests(self):
        """Add any tests here that should run after the upgrade"""
        self.testNegOpRoll(True)
        self.testNegOpPick(True)
        self.testReadOnlyInput(True)
        self.testWideStack(True)

        # testStackLimit N checks a stack of size N*1024 made up of 2 512 byte stack items
        self.testStackLimit(1024, True)  # So this is the max
        self.testStackLimit(1, True)
        self.testStackLimit(11, True)
        self.testStackLimit(111, True)
        self.testStackLimit(1111, False) # Nothing above 1MB (1024*1024) will work
        self.testStackLimit(1025, False)


    def run_test(self):
        # Mine some blocks to get utxos etc
        self.nodes[1].generate(120)

        # Inject a very controlled amount of utxos into the working wallet
        addr = self.nodes[0].getnewaddress()
        for i in range(0,20):
            self.nodes[1].sendtoaddress(addr, 1000000)

        miningNode = self.nodes[1]
        # mine a few blocks 1 second apart so we can get a meaningful "mediantime"
        # that does not contain the gap between the cached blockchain and this run
        startcount = miningNode.getblockcount()
        bestblock = miningNode.getbestblockhash()
        lastblocktime = miningNode.getblockheader(bestblock)['time']
        mocktime = lastblocktime
        for i in range(10):
            mocktime = mocktime + 120
            miningNode.setmocktime(mocktime)
            miningNode.generate(1)
        assert_equal(miningNode.getblockcount(), startcount+10)
        sync_blocks(self.nodes)
        self.preupgradeTests()

        # set the hardfork activation to just a few blocks ahead
        bestblock = miningNode.getbestblockhash()
        lastblocktime = miningNode.getblockheader(bestblock)['time']
        activationtime = lastblocktime + 240
        for n in self.nodes:
            n.set("consensus.fork1Time=" + str(activationtime))

        blockchaininfo = miningNode.getblockchaininfo()
        assert_equal(blockchaininfo['forktime'], activationtime)
        assert_equal(blockchaininfo['forkactive'], False)
        assert_equal(blockchaininfo['forkenforcednextblock'], False)
        assert_greater_than(activationtime, blockchaininfo['mediantime'])

        # Mine just up to the hard fork activation (activationtime will still be greater than mediantime).
        for i in range(100):
            mocktime = mocktime + 120
            for n in self.nodes: n.setmocktime(mocktime)
            miningNode.generate(1)
            blockchaininfo = miningNode.getblockchaininfo()
            if blockchaininfo['forkenforcednextblock'] == True: break
            # ^ another possibility: if blockchaininfo['mediantime'] >= activationtime: break
            assert_equal(blockchaininfo['forkactive'], False)
            assert_equal(blockchaininfo['forkenforcednextblock'], False)
            assert_greater_than(activationtime, blockchaininfo['mediantime']) # activationtime > mediantime

        # Fork should be active after the next block mined (median time will be greater than or equal to blocktime)
        # NOTE: although the fork will be active on the next block, the nextmaxblocksize will not increase
        #       yet.  This is because we can not have an increase in the nextmaxblocksize until we mine our
        #       first block under the new rules.
        self.atUpgradeTests()
        mocktime = mocktime + 120
        for n in self.nodes: n.setmocktime(mocktime)
        miningNode.generate(1)
        blockchaininfo = miningNode.getblockchaininfo()
        assert_equal(blockchaininfo['forkactive'], True)

        # First block mined under new rules:  At this point the nextmaxblocksize can be calculated
        # and will allow for a larger block after the first fork block is mined.
        mocktime = mocktime + 120
        for n in self.nodes: n.setmocktime(mocktime)
        firstForkBlk = miningNode.generate(1)[0]
        # Wait for all nodes to move to the fork block and activate the fork
        for n in self.nodes:
            waitFor(30, lambda: n.getbestblockhash() == firstForkBlk)

            blockchaininfo = miningNode.getblockchaininfo()
            assert_equal(blockchaininfo['forkactive'], True)
            assert_equal(blockchaininfo['forkenforcednextblock'], False)
            assert_greater_than(blockchaininfo['mediantime'], activationtime)

        self.postupgradeTests()

        # Mine a few more blocks. Nothing should change regarding activation.
        for i in range(10):
            mocktime = mocktime + 120
            miningNode.setmocktime(mocktime)
            miningNode.generate(1)
            blockchaininfo = miningNode.getblockchaininfo()
            assert_equal(blockchaininfo['forkactive'], True)
            assert_equal(blockchaininfo['forkenforcednextblock'], False)
            assert_greater_than(blockchaininfo['mediantime'], activationtime)

if __name__ == '__main__':
    UpgradeActivationTest().main()
    exit(0)

def Test():
    t = UpgradeActivationTest()
    t.drop_to_pdb = True
    bitcoinConf = {
        "debug": ["validation", "rpc", "net", "blk", "thin", "mempool", "req", "bench", "evict"],
    }
    flags = standardFlags()
    flags[0] = '--tmpdir=/ramdisk/test/t'
    t.main(flags, bitcoinConf, None)
