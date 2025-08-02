#!/usr/bin/env python3
# Copyright (c) 2015-2023 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import test_framework.loginit
import logging
import pprint
from copy import copy as scopy

import test_framework.libnexa as libnexa
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from test_framework.blocktools import *
from test_framework.nodemessages import *
from test_framework.script import *
# Accurately count satoshis
# 8 digits to get to 21million, and each bitcoin is 100 million satoshis
import decimal
decimal.getcontext().prec = 16

GROUP_MINT_AUTH = (0xD << 60)

ITERS=1

def fundSignSendParse(node, tx, verbose = False):
    h = tx.toHex()
    if verbose:
        print("Input TX: " + h)
        print("Decoded: " + pprint.pformat(node.decoderawtransaction(h)))
    frtReturn = node.fundrawtransaction(h)
    sgnReturn = node.signrawtransaction(frtReturn["hex"])
    if verbose:
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


def UnpackGroupAmount(b):
    unp = "<B"
    if len(b)==2: unp = "<H"
    elif len(b)==4: unp = "<I"
    elif len(b)==8: unp = "<Q"
    else: raise Exception("Bad group amount size")
    return struct.unpack(unp, b)[0]


def spendOutputOfGroupAmount(amt, tx, templateScript, constraintArgs=None, satisfierArgs=None):
    for idx in range(0, len(tx.vout)):
        scr = CScript(tx.vout[idx].scriptPubKey)
        scrLst = [ x for x in scr]
        if scrLst[0] != OP_0 and UnpackGroupAmount(scrLst[1]) == amt:
            inp = tx.SpendOutput(idx)
            inp.setUnlockingToTemplate(templateScript, constraintArgs, satisfierArgs)
            return inp
    return None

def findOutputOfGroupAmount(amt, tx):
    for idx in range(0, len(tx.vout)):
        scr = CScript(tx.vout[idx].scriptPubKey)
        scrLst = [ x for x in scr]
        if len(scrLst) > 1:
            if len(scrLst[0]) > 0:
                a = UnpackGroupAmount(scrLst[1])
                if a == amt:
                    return idx
    return None


def spendOutput(idx, tx, templateScript, constraintArgs=None, satisfierArgs=None):
    inp = tx.SpendOutput(idx)
    inp.setUnlockingToTemplate(templateScript, constraintArgs, satisfierArgs)
    return inp



class RoTest(BitcoinTestFramework):
    NUM_NODES = 2
    def setup_chain(self,bitcoinConfDict=None, wallets=None):
        libnexa.loadLibNexaOrExit(self.options.srcdir)
        print("Initializing test directory "+self.options.tmpdir)
        initialize_chain_clean(self.options.tmpdir, self.NUM_NODES, self.confDict)
        # initialize_chain(self.options.tmpdir, bitcoinConfDict, wallets)

    def setup_network(self):
        self.nodes = []
        self.is_network_split = False
        for i in range(0, self.NUM_NODES):
            self.nodes.append(start_node(i, self.options.tmpdir, []))
        interconnect_nodes(self.nodes)

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


        if True:
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
        waitFor(60, lambda: n.getwalletinfo()["syncblock"] == blkhash)

        # Make a TX with a readonly input (should work if post fork), no signature
        tx = CTransaction()
        tx.vin.append(scopy(roInp))
        tx.vout.append(out2)
        try:
            roTx = fundSignSendParse(n, tx)
            assert shouldItWork, "Signing this tx should have failed (pre upgrade)"
            # print("COMMITTING: ")
            # print(pprint.pformat(n.decoderawtransaction(roTx.toHex())))
        except JSONRPCException as e:
            if shouldItWork:
                raise e
            assert not shouldItWork, "Signing this tx should have succeeded (post upgrade)"

        # Make a TX with a readonly input, bad amount (should never work)
        tx = CTransaction()
        tx.vin.append(scopy(roInp))
        tx.vin[0].amount = 10000
        tx.vout.append(out2)  # This output is worth half of the readonly input
        try:
            roTx = fundSignSendParse(n, tx)
            assert False, "nonzero amount should never work"
        except JSONRPCException as e:
            pass # correctly failed

        # Make a TX with a readonly input, bad amount (some other amount) (should never work)
        tx.vin[0].amount = 5000
        try:
            roTx = fundSignSendParse(n, tx)
            assert False, "nonzero amount should never work"
        except JSONRPCException as e:
            pass # correctly failed

        # Make a TX with a readonly input, bad signature
        tx = CTransaction()
        tx.vin.append(scopy(roInp))
        tx.vin[0].scriptSig = CScript([0]) # will end up with too much on the stack
        tx.vout.append(out2)  # This output is worth half of the readonly input
        try:
            roTx = fundSignSendParse(n, tx)
            assert False, "bad sig should never work"
        except JSONRPCException as e:
            pass # correctly failed

        # Make a TX with a readonly input (should work if post fork), no signature
        tx = CTransaction()
        tx.vin.append(scopy(roInp))
        tx.vout.append(out2)
        try:
            roTx = fundSignSendParse(n, tx)
            assert shouldItWork, "Signing this tx should have failed (pre upgrade)"
            # print("COMMITTING: ")
            # print(pprint.pformat(n.decoderawtransaction(roTx.toHex())))
        except JSONRPCException as e:
            if shouldItWork:
                raise e
            assert not shouldItWork, "Signing this tx should have succeeded (post upgrade)"

        # Use the same read only input again
        tx = CTransaction()
        tx.vin.append(scopy(roInp))
        tx.vout.append(out2)
        try:
            roTx2 = fundSignSendParse(n, tx)
            assert shouldItWork, "Signing this tx should have failed (pre upgrade)"
            # print(roTx2)
            # print("COMMITTING: ")
            # print(pprint.pformat(n.decoderawtransaction(roTx2.toHex())))
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
            fundSignSendParse(n, tx, False)
        except JSONRPCException as e:
            if shouldItWork:
                raise e
            assert not shouldItWork, "Signing this tx should have succeeded (post upgrade)"


        txpool = n.getrawtxpool()
        assert roTx.GetRpcHexIdem() in txpool
        assert roTx2.GetRpcHexIdem() in txpool

        waitFor(60, lambda: n.gettxpoolinfo()["size"] >= 2)
        blkhash = n.generate(1)[0]
        waitFor(60, lambda: n.getwalletinfo()["syncblock"] == blkhash)
        txpoolstats = n.gettxpoolinfo()
        if txpoolstats["size"] != 0:
            rawtx = n.getrawtxpool()
            for t in rawtx:
                # print(t)
                txinfo = n.gettransaction(t)
                decoded = n.decoderawtransaction(txinfo["hex"])
                # print(decoded)
                blkhash = n.generate(1)[0]  # Should consume the rest of the tx
                waitFor(60, lambda: n.gettxpoolinfo()["size"] == 0)
        self.sync_blocks()
 
        for i in range(0, self.NUM_NODES):
            waitFor(60, lambda: self.nodes[i].gettxpoolinfo()["size"] == 0)

        # Use the same read only input again, after we committed some RO uses, but we haven't spent it yet
        tx = CTransaction()
        tx.vin.append(scopy(roInp))
        tx.vout.append(out2)
        try:
            roTx3 = fundSignSendParse(n, tx, False)
            assert shouldItWork, "Signing this tx should have failed (pre upgrade)"
        except JSONRPCException as e:
            if shouldItWork:
                raise e
            assert not shouldItWork, "Signing this tx should have succeeded (post upgrade)"

        # Spend the input I've been using as read-only.
        # Any transaction chains decending from read only input are not allowed as instant transactions so check
        # that balances are not effected until the next block is mined.
        for i in range(0, self.NUM_NODES):
            waitFor(60, lambda: self.nodes[i].gettxpoolinfo()["size"] == 1)

        DELAY=3
        StartBalances = []
        for i in range(0, self.NUM_NODES):
            self.nodes[i].set("wallet.instant=true");
            self.nodes[i].set("wallet.instantDelay=3");
            StartBalances.append(self.nodes[i].getbalance())

        tx = CTransaction()
        tx.vin.append(spendOutputOfAmount(10000, preTx, scr))
        assert tx.vin[0] != None
        tx.vout.append(out2)  # This output is worth half of the readonly input
        v = n.validaterawtransaction(tx.toHex())
        # print(v)
        n.sendrawtransaction(tx.toHex())
        mempoolTx = tx
        wait = DELAY + 1 # wait a little extra beyond the instant timeout before checking balances
        time.sleep(wait)
        for i in range(0, self.NUM_NODES):
            waitFor(60, lambda: self.nodes[i].gettxpoolinfo()["size"] == 2)

        # balances should not have changed. Only when the next block is mined should we see a difference.
        for i in range(0, self.NUM_NODES):
            assert_equal(StartBalances[i], self.nodes[i].getbalance())

        # Use the same read only input again -- it should work because its spend is in the txpool, not committed
        tx = CTransaction()
        tx.vin.append(spendOutputOfAmount(10000, preTx, scr))
        assert tx.vin[0] != None
        tx.vin[0].t = CTxIn.READONLY
        tx.vin[0].amount = 0
        tx.vin[0].scriptSig = bytes()
        tx.vout.append(out2)  # This output is worth half of the readonly input
        try:
            roTx2 = fundSignSendParse(n, tx)
            assert shouldItWork, "Signing this tx should have failed (pre upgrade)"
            # print(roTx2)
        except JSONRPCException as e:
            if shouldItWork:
                raise e
            assert not shouldItWork, "Signing this tx should have succeeded (post upgrade)"

        # Now try to create a read-only tx from an output in the mempool (should never work)
        tx = CTransaction()
        tx.vin.append(spendOutputOfAmount(out2.nValue, mempoolTx, scr))
        assert tx.vin[0] != None
        tx.vin[0].t = CTxIn.READONLY
        tx.vin[0].amount = 0
        tx.vin[0].scriptSig = bytes()
        tx.vout.append(out3)
        try:
            roTx2 = fundSignSendParse(n, tx)
            assert False
        except JSONRPCException as e:
            assert True

        # Now mine a block and the wallet balances should update for RO transactions
        blkhash = self.nodes[1].generate(1)
        self.sync_blocks()
        for i in range(0, self.NUM_NODES):
            waitFor(60, lambda: self.nodes[i].getwalletinfo()["syncblock"] in blkhash)
            assert_not_equal(StartBalances[i], self.nodes[i].getbalance())

    def testGroupReadOnlyInput(self):
        # set up
        n = self.nodes[0]
        scr = CScript([OP_DROP])
        addr = libnexa.templateToAddress(libnexa.REGTEST, scr)
        newgrpReply = n.token("new")
        gid = newgrpReply["groupIdentifier"]
        newgrpTxIdem = newgrpReply["transaction"]
        sync_wallet_with_unconf_txidem(60, n, newgrpReply["transaction"])

        while True:
          try:
              mintTxIdem = n.token("mint", gid, addr, 1000)
              break
          except JSONRPCException as e:
              print("mint failed")
              time.sleep(1)

        txhex = n.gettransaction(mintTxIdem)
        mintTx = CTransaction(txhex)
        outIdx = findOutputOfGroupAmount(1000, mintTx)
        inp = spendOutput(outIdx, mintTx, scr)

        sync_wallet_with_unconf_txidem(60, n, mintTxIdem)
        # Create a mint child authority
        while True:
          try:
              authTxIdem = n.token("authority", "create", gid, addr, "mint")
              break
          except JSONRPCException as e:
              print("authority failed")
              time.sleep(1)

        authtxhex = n.gettransaction(authTxIdem)
        authTx = CTransaction(authtxhex)

        # print(n.gettxpoolinfo())
        poolTxes = n.getrawtxpool()
        for txidem in poolTxes:
            try:
                txhex = n.getrawtransaction(txidem)
                decoded = n.decoderawtransaction(txhex)
            except JSONRPCException as e:
                if "No such txpool" in str(e):
                    # print("\n***  " + txidem + " LEFT THE POOL  ***")
                    continue
                else: raise
            try:
                v = n.validaterawtransaction(txhex)
            except JSONRPCException as e:
                v = str(e)
                # print("\n***  " + txidem + "  ***")
                # print(pprint.pformat(decoded))
                # print(txhex)
            # print(v)
            self.genBlock(n) # Cannot use as readonly until confirmed

        # try importing a read-only group utxo and spending tokens
        tx = CTransaction()
        tx.vin.append(scopy(inp))
        tx.vin[0].t = CTxIn.READONLY
        tx.vin[0].amount = 0
        tx.vin[0].scriptSig = bytes()

        # just try to spend it anywhere (back to same place) with a RO input (FAIL)
        tx.vout.append(scopy(mintTx.vout[outIdx]))
        h = tx.toHex()
        frtReturn = n.fundrawtransaction(h)
        sgnReturn = n.signrawtransaction(frtReturn["hex"])
        v = n.validaterawtransaction(sgnReturn["hex"])
        assert "grp-invalid-mint" in str(v) or 'inputs-are-missing' in str(v)
        try:
            n.sendrawtransaction(sgnReturn["hex"])
            assert False
        except JSONRPCException as e:
            assert "group-token-imbalance" in str(e)


        # try to use the mint auth without signing (FAIL)
        idx = findOutputOfGroupAmount(0xd000000000000000, authTx)
        assert idx
        tx = CTransaction()
        inp = spendOutput(idx, authTx, scr, None, CScript([1]))
        tx.vin.append(scopy(inp))
        tx.vin[0].t = CTxIn.READONLY
        tx.vin[0].amount = 0
        goodSig = tx.vin[0].scriptSig
        tx.vin[0].scriptSig = bytes()
        # Just try to mint the same amount again for ease
        tx.vout.append(scopy(mintTx.vout[outIdx]))
        frtReturn = n.fundrawtransaction(tx.toHex())  # For fee
        sgnReturn = n.signrawtransaction(frtReturn["hex"])
        v = n.validaterawtransaction(sgnReturn["hex"])
        assert "grp-invalid-mint" in str(v) or 'inputs-are-missing' in str(v)
        try:
            n.sendrawtransaction(sgnReturn["hex"])
            assert False
        except JSONRPCException as e:
            assert "group-token-imbalance" in str(e)

        # Ok now sign the mint input (WORK)
        tx.vin[0].scriptSig = goodSig
        frtReturn = n.fundrawtransaction(tx.toHex())  # For fee
        sgnReturn = n.signrawtransaction(frtReturn["hex"])
        v = n.validaterawtransaction(sgnReturn["hex"])
        assert not ("grp-invalid-mint" in str(v))
        n.sendrawtransaction(sgnReturn["hex"])

        # Again sign the mint input to prove multi-mint using RO auths  (WORK)
        tx.vin[0].scriptSig = goodSig
        frtReturn = n.fundrawtransaction(tx.toHex())  # For fee
        sgnReturn = n.signrawtransaction(frtReturn["hex"])
        v = n.validaterawtransaction(sgnReturn["hex"])
        assert not ("grp-invalid-mint" in str(v))
        n.sendrawtransaction(sgnReturn["hex"])

        txp = n.gettxpoolinfo()
        # print(txp)
        assert txp["size"] == 2 # Make sure all the tx that should have succeeded got to the txpool
        self.genBlock(n)  # Make sure these tx can get in a block (WORK)
        txp = n.gettxpoolinfo()
        assert txp["size"] == 0

        # Make sure mintage counts these tokens
        mnt =  n.token("mintage", gid)
        assert mnt["mintage_satoshis"] == 3000

    def genBlock(self, node):
        blkhash = node.generate(1)[0]
        blkhdr = node.getblock(blkhash)
        # print("Generated: %d:%s with %d tx nonCB: %s" % (blkhdr["height"], blkhash, blkhdr["txcount"], blkhdr["txidem"][1:]))
        return blkhash

    def run_test(self):
        miningNode = self.nodes[1]
        # Mine some blocks to get utxos etc
        miningNode.generate(110)
        sync_blocks(self.nodes)

        # Inject a very controlled amount of utxos into the working wallet
        addr = self.nodes[0].getnewaddress()
        addr1 = self.nodes[1].getnewaddress()
        for i in range(0,10):
            miningNode.sendtoaddress(addr, 1000000)
        waitFor(60, lambda: miningNode.gettxpoolinfo()["size"] == 10)
        # print(miningNode.gettxpoolinfo())
        miningNode.generate(1)

        for i in range(0,ITERS):
            sync_blocks(self.nodes)
            # print("\n\n*** Iteration: %d at %s" % (i, [x.getblockcount() for x in self.nodes]))
            self.testReadOnlyInput(True)
            # print("Test Completed, Syncing")
            sync_blocks(self.nodes)
            # print("Synced")
            blk1 = miningNode.generate(1)[0]
            # print("generated: " + blk1)
            sync_blocks(self.nodes)
            self.testGroupReadOnlyInput()
            bal0 = self.nodes[0].getwalletinfo()["balance"]
            bal1 = self.nodes[1].getwalletinfo()["balance"]
            a = addr if (bal0 < bal1) else addr1
            n = self.nodes[0] if (bal0 < bal1) else self.nodes[1]
            for i in range(0,10):
                n.sendtoaddress(a, 1000000)
            blk2 = miningNode.generate(1)[0]
            # print("generated: " + blk2)


if __name__ == '__main__':
    RoTest().main()

def Test():
    t = RoTest()
    t.drop_to_pdb = True
    bitcoinConf = {
        "par": 1,
        "txindex":1,
        "debug": ["all","-libevent"]
        # "debug": ["validation", "rpc", "net", "blk", "thin", "mempool", "req", "bench", "evict"],
    }
    flags = standardFlags()
    flags[0] = '--tmpdir=/ramdisk/test/t'
    t.main(flags, bitcoinConf, None)
