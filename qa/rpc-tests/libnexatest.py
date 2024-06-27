#!/usr/bin/env python3
# Copyright (c) 2015-2022 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
import test_framework.loginit
import time
import sys
import copy
if sys.version_info[0] < 3:
    raise "Use Python 3"
import logging
import enum

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
import test_framework.libnexa as libnexa
from test_framework.nodemessages import *
from test_framework.script import *

class MyTest (BitcoinTestFramework):

    def setup_chain(self, bitcoinConfDict=None, wallets=None):
        libnexa.loadLibNexaOrExit(self.options.srcdir)
        print("Initializing test directory " + self.options.tmpdir)
        initialize_chain(self.options.tmpdir, bitcoinConfDict, wallets)

    def setup_network(self, split=False):
        self.nodes = start_nodes(2, self.options.tmpdir)
        connect_nodes_bi(self.nodes, 0, 1)
        self.is_network_split = False
        self.sync_all()

    def runScriptMachineTests(self):
        # Check basic script
        sm = libnexa.ScriptMachine()
        worked = sm.eval(CScript([OP_1, OP_0, OP_5, OP_6, OP_TOALTSTACK, OP_TOALTSTACK]))
        assert(worked)
        # Check stack
        stk = sm.stack()
        assert_equal(stk[1][0], libnexa.StackItemType.BYTES)
        assert_equal(int.from_bytes(stk[1][1], byteorder='little'), 1)
        assert_equal(len(stk[0][1]), 0)

        altstk = sm.altstack()
        assert_equal(stk[0][0], libnexa.StackItemType.BYTES)
        assert_equal(int.from_bytes(altstk[0][1], byteorder='little'), 5)
        assert_equal(stk[1][0], libnexa.StackItemType.BYTES)
        assert_equal(int.from_bytes(altstk[1][1], byteorder='little'), 6)

        worked = sm.eval(CScript([OP_FROMALTSTACK, OP_FROMALTSTACK]))
        assert(worked)
        stk = sm.stack()
        assert_equal(stk[0][0], libnexa.StackItemType.BYTES)
        assert_equal(int.from_bytes(stk[0][1], byteorder='little'), 6)
        # Check reset
        sm.reset()
        stk = sm.stack()
        assert(len(stk) == 0)
        altstk = sm.altstack()
        assert(len(altstk) == 0)

        # Check stepping
        worked = sm.eval(CScript([OP_1, OP_1]))
        assert(worked)
        worked = sm.begin(CScript([OP_IF, OP_IF, OP_2, OP_ELSE, OP_3, OP_ENDIF, OP_ENDIF]))
        count = 0
        try:
            while 1:
                count += 1
                sm.step()
                assert(sm.pos() == count)  # only matches count because every opcode in the script is 1 byte (no pushdata)
        except libnexa.Error as e:
            assert(str(e) == 'stepped beyond end of script')
        stk = sm.stack()
        assert_equal(int.from_bytes(stk[0][1], byteorder='little'), 2)

        sm.reset()
        # Check clone
        worked = sm.eval(CScript([OP_1, OP_1]))
        assert(worked)
        sm2 = sm.clone()
        worked = sm.eval(CScript([OP_IF, OP_IF, OP_2, OP_ELSE, OP_3, OP_ENDIF, OP_ENDIF]))
        stk = sm.stack()
        assert_equal(int.from_bytes(stk[0][1], byteorder='little'), 2)
        sm.cleanup()
        worked = sm2.eval(CScript([OP_IF, OP_IF, OP_3, OP_ELSE, OP_2, OP_ENDIF, OP_ENDIF]))
        assert(worked)
        stk = sm2.stack()
        assert_equal(int.from_bytes(stk[0][1], byteorder='little'), 3)
        sm2.cleanup()

        # Check stack assignment
        sm = libnexa.ScriptMachine()
        worked = sm.eval(CScript([OP_1, OP_1]))
        assert(worked)
        sm.setStackItem(1, libnexa.StackItemType.BYTES, b"")
        worked = sm.eval(CScript([OP_IF, OP_IF, OP_2, OP_ELSE, OP_3, OP_ENDIF, OP_ENDIF]))
        assert(worked)
        stk = sm.stack()
        # since I overwrote a true with a false, the else condition should have been taken
        assert_equal(int.from_bytes(stk[0][1], byteorder='little'), 3)

        # Check stack push
        sm.reset()
        sm.setStackItem(-1, libnexa.StackItemType.BYTES, b"")
        sm.setStackItem(-1, libnexa.StackItemType.BYTES, bytes([1]))
        worked = sm.eval(CScript([OP_IF, OP_IF, OP_2, OP_ELSE, OP_3, OP_ENDIF, OP_ENDIF]))
        assert(worked)
        stk = sm.stack()
        assert_equal(int.from_bytes(stk[0][1], byteorder='little'), 3)
        assert(sm.error()[0] == 0)

        # Check script error
        sm.reset()
        sm.setStackItem(-1, libnexa.StackItemType.BYTES, bytes([1]))
        worked = sm.eval(CScript([OP_IF, OP_IF, OP_2, OP_ELSE, OP_3, OP_ENDIF, OP_ENDIF]))
        assert(not worked)
        err = sm.error()
        assert_equal(err[0], libnexa.ScriptError.SCRIPT_ERR_UNBALANCED_CONDITIONAL)
        assert_equal(err[1], 2)

    def run_test(self):
        self.runScriptMachineTests()
        faulted = False
        try:
            libnexa.spendscript(OP_1)
        except AssertionError:
            faulted = True
            pass
        assert faulted, "only data in spend scripts"
        try:
            libnexa.signTxInput(b"", 0, 5, b"", b"", b"abc")  # bad sighashtype
        except libnexa.Error:
            faulted = True
            pass
        assert faulted, "bad sighashtype accepted"

        # Sanity check id and idem for an empty transaction
        tx = CTransaction()
        ret = libnexa.txid(tx)
        assert ret.hex() == 'c8e6c337c4fce20c6fc5861225591e1104c559c038fcf6f7429837f664209c7e'
        ret = libnexa.txidem(tx)
        assert ret.hex() == 'df297c043efd84657387d675de57f8c8d69ac2290644aff12ac5ad66555a0980'

        try:
            ret = libnexa.txid(bytes([0,1,2,3]))  # bad tx decode
            assert False
        except AssertionError:
            pass


        # grab inputs from 2 different full nodes and sign a single tx that spends them both
        wallets = [self.nodes[0].listunspent(), self.nodes[1].listunspent()]
        inputs = [x[0] for x in wallets]
        privb58 = [self.nodes[0].dumpprivkey(inputs[0]["address"]), self.nodes[1].dumpprivkey(inputs[1]["address"])]

        privkeys = [decodeBase58(x)[1:-5] for x in privb58]
        pubkeys = [libnexa.pubkey(x) for x in privkeys]

        tx = CTransaction()
        for i in inputs:
            tx.vin.append(CTxIn(COutPoint(i["outpoint"]), i["amount"], b"", 0xffffffff))

        destPrivKey = libnexa.randombytes(32)
        destPubKey = libnexa.pubkey(destPrivKey)
        destHash = libnexa.addrbin(destPubKey)

        output = CScript([OP_DUP, OP_HASH160, destHash, OP_EQUALVERIFY, OP_CHECKSIG])

        amt = int(sum([x["amount"] for x in inputs]) * libnexa.NEX)
        tx.vout.append(CTxOut(amt, output))

        p2pkt = CScript([OP_FROMALTSTACK, OP_CHECKSIGVERIFY])
        n = 0
        for i, priv in zip(inputs, privkeys):
            sig = libnexa.signTxInput(tx, n, i["amount"], p2pkt, priv)
            # tx.vin[n].scriptSig = libnexa.spendscript(sig)  # P2PK
            pubkey = libnexa.pubkey(priv)
            args = bytes(CScript([pubkey]))
            tx.vin[n].scriptSig = CScript([ args, sig])
            n += 1

        txhex = hexlify(tx.serialize()).decode("utf-8")
        txidem = self.nodes[0].enqueuerawtransaction(txhex)
        assert txidem == hexlify(libnexa.txidem(txhex)[::-1]).decode("utf-8")

        # Now spend the created output to an anyone can spend address
        tx2 = CTransaction()
        tx2.vin.append(CTxIn(COutPoint().fromIdemAndIdx(txidem, 0), amt, b"", 0xffffffff))
        tx2.vout.append(CTxOut(amt, CScript([OP_1])))
        sig2 = libnexa.signTxInput(tx2, 0, amt, output, destPrivKey)
        tx2.vin[0].scriptSig = libnexa.spendscript(sig2, destPubKey)

        # Local script interpreter:
        # Check that the spend works in a transaction-aware script machine
        txbad = copy.deepcopy(tx2)
        badsig = list(sig2)
        badsig[10] = 1  # mess up the sig
        badsig[11] = 2
        txbad.vin[0].scriptSig = libnexa.spendscript(bytes(badsig), destPubKey)

        # try a bad script (sig check should fail)
        sm = libnexa.ScriptMachine(tx=tx2, prevouts=[tx.vout[0]], inputIdx=0)
        ret = sm.eval(txbad.vin[0].scriptSig)
        assert(ret)
        ret = sm.eval(tx.vout[0].scriptPubKey)
        assert(not ret)
        assert(sm.error()[0] == libnexa.ScriptError.SCRIPT_ERR_SIG_NULLFAIL)

        # try a good spend script
        sm.reset()
        ret = sm.eval(tx2.vin[0].scriptSig)
        assert(ret)
        ret = sm.eval(tx.vout[0].scriptPubKey)
        assert(ret)

        # commit the created transaction
        tx2id = self.nodes[0].enqueuerawtransaction(hexlify(tx2.serialize()).decode("utf-8"))

        # Check that all tx were created, and commit them
        waitFor(20, lambda: self.nodes[0].gettxpoolinfo()["size"] == 2)
        blk = self.nodes[0].generate(1)
        self.sync_blocks()
        assert self.nodes[0].gettxpoolinfo()["size"] == 0
        assert self.nodes[1].gettxpoolinfo()["size"] == 0


if __name__ == '__main__':
    MyTest().main()

# Create a convenient function for an interactive python debugging session


def Test():
    t = MyTest()
    t.drop_to_pdb = True
    # install ctrl-c handler
    #import signal, pdb
    #signal.signal(signal.SIGINT, lambda sig, stk: pdb.Pdb().set_trace(stk))
    bitcoinConf = {
        "debug": ["rpc", "net", "blk", "thin", "mempool", "req", "bench", "evict"],
    }
    logging.getLogger().setLevel(logging.INFO)
    flags = standardFlags() # ["--nocleanup", "--noshutdown"]
    binpath = findBitcoind()
    flags.append("--srcdir=%s" % binpath)
    t.main(flags, bitcoinConf, None)
