#!/usr/bin/env python3
# Copyright (c) 2015-2022 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
import test_framework.loginit
import time
import sys
import copy
import io
if sys.version_info[0] < 3:
    raise "Use Python 3"
import logging

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
import test_framework.libnexa as libnexa
from test_framework.nodemessages import *
from test_framework.script import *


class ScriptDebugError(Exception):
    pass


def prettyStk(t):
    ret = ""
    if t[0] == libnexa.StackItemType.BYTES:
        return "d_"+hexlify(t[1]).decode()
    if t[0] == libnexa.StackItemType.BIGNUM:
        return "n_"+hexlify(t[1]).decode()
    else:
        return "u_"+hexlify(t[1]).decode()

def stepEval(sm, script):
        worked = sm.begin(script)
        count = 0
        pos = 0
        try:
            while 1:
                stk = sm.stack()
                print("step %d" % count)
                rest = CScript(script[pos:])
                textrest = []
                for (opcode, data, sop_idx) in rest.raw_iter():
                    if not data:
                        try:
                            textrest.append(OPCODE_NAMES[opcode])
                        except KeyError as e:
                            textrest.append("OP_x%X" % opcode)
                    else:
                        textrest.append("DATA(%s)" % hexlify(data))
                print("  stack: ", [ prettyStk(x) for x in stk])
                print("  script: ", textrest)
                count += 1
                pos = sm.step()

        except libnexa.Error as e:
            if str(e) == 'stepped beyond end of script':
                return (libnexa.ScriptError.SCRIPT_ERR_OK, pos)
            else:
                (err, pos) = sm.error()
                print("Error: %d (%s): %s" % (err, err.name, str(e)))
                return (err, pos)
        return (libnexa.ScriptError.SCRIPT_ERR_OK, pos)


def MakeCTransaction(data):
    if type(data) is str:
        data = unhexlify(data)
    if type(data) is bytes:
        txStream = io.BytesIO(data)
        tx = CTransaction()
        tx.deserialize(txStream)
        return tx
    if type(data) is CTransaction:
        return data
    raise ScriptDebugError("unknown transaction format: %s" % str(data))


class DebugSession:

    def __init__(self, prevTx, spendTx, flags=None, prevoutIdx=None):
        """You only have to specify the prevoutIdx if the spendTx spends > 1 outputs from prevTx"""
        self.prevTx = MakeCTransaction(prevTx)
        self.spendTx = MakeCTransaction(spendTx)
        self.inputIdx = None
        if prevoutIdx==None:
            # find the related input/output.
            self.inputIdx = 0
            pdb.set_trace()
            for inp in self.spendTx.vin:
                for outIdx in range(0,len(self.prevTx.vout)):
                    outpt = self.prevTx.OutpointAt(outIdx)
                    if outpt.hash == inp.prevout.hash:
                        prevoutIdx = inp.prevout.n
                        break
                if prevoutIdx != None:
                    break
                self.inputIdx += 1

        self.prevoutIdx = prevoutIdx
        if self.prevoutIdx is None or self.spendTx.vin[self.prevoutIdx].prevout.hash != self.prevTx.getHash():
            raise ScriptDebugError("The spend transaction does not spend any outputs from the passed previous transaction")

        self.constraintScript = self.prevTx.vout[self.prevoutIdx].scriptPubKey
        self.inputAmount = self.prevTx.vout[self.prevoutIdx].nValue
        self.flags = flags
        if self.flags is None: self.flags = libnexa.ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS

        self.spendScript = self.spendTx.vin[self.inputIdx].scriptSig
        self.redeemScript = None

        self.sm = libnexa.ScriptMachine(flags=self.flags, tx=self.spendTx, inputIdx=self.inputIdx, inputAmount=self.inputAmount)


    def evalSpendScript(self):
        self.evals(self.spendScript)

        # The constraintScript may not be P2SH, but if it is, then the top of the stack must be the redeemScript
        stk = self.sm.stack()
        if len(stk):
            self.redeemScript = stk[0]

    def evalConstraintScript(self):
        return self.evalWithReturn(self.constraintScript)

    def evalWithReturn(self, script):
        result = self.evals(script)
        if result[0] != libnexa.ScriptError.SCRIPT_ERR_OK:
            return result # script failed to execute fully

        # if script fully executed, evaluate the "return code"
        stk = self.sm.stack()
        if len(stk): # outside of your script, the VM pops 1 thing off the stack and uses that to decide whether the script is successful
            stkTop = stk[0]
            self.sm.eval(CScript([OP_DROP]))
            if self.flags & libnexa.ScriptFlags.SCRIPT_VERIFY_CLEANSTACK:
                if len(stk) > 1:
                    print("Script finished with result %s but unclean stack: %s" % (prettyStk(stkTop), [ prettyStk(x) for x in stk]))
                    return (libnexa.ScriptError.SCRIPT_ERR_CLEANSTACK, result[1])
            if stkTop[0] == libnexa.StackItemType.BYTES and ord(stkTop[1]) == 1:
                return (libnexa.ScriptError.SCRIPT_ERR_OK, result[1])
            else:
                return (libnexa.ScriptError.SCRIPT_EVAL_FALSE, result[1])
        return None

    def evalRedeemScript(self):
        return self.evalWithReturn(self.redeemScript[1])

    def evals(self, script):
        worked = self.sm.begin(script)
        count = 0
        pos = 0
        try:
            while 1:
                stk = self.sm.stack()
                print("step %d" % count)
                rest = CScript(script[pos:])
                textrest = []
                for (opcode, data, sop_idx) in rest.raw_iter():
                    if not data:
                        try:
                            textrest.append(OPCODE_NAMES[opcode])
                        except KeyError as e:
                            textrest.append("OPx%x" % opcode)
                    else:
                        textrest.append("DATA(%s)" % hexlify(data))
                print("  stack: ", [ prettyStk(x) for x in stk])
                print("  script: ", textrest)
                count += 1
                pos = self.sm.step()

        except libnexa.Error as e:
            if str(e) == 'stepped beyond end of script':
                return (libnexa.ScriptError.SCRIPT_ERR_OK, pos)
            else:
                (err, pos) = self.sm.error()
                print("Error: %d (%s): %s" % (err, err.name, str(e)))
                return (err, pos)
        return (libnexa.ScriptError.SCRIPT_ERR_OK, pos)

class ScriptDebugTest (BitcoinTestFramework):

    def setup_chain(self, bitcoinConfDict=None, wallets=None):
        pass

    def setup_network(self, split=False):
        pass

    def runScriptMachineTests(self):

        txbin = unhexlify("0100000003ee6cfb264416c5eb6ae631915520f18529aadec50342ac8d30b01c719529f46200000000920047304402203de0797e489002423332d44e7568ff19f66bebcebaa39c35fe654432c567cc43022064d97a58a99259348e6f348ba98bb1744c1d7e9700faa9a155115a5a25444b8341004752210371f9bb1024de3b2da052ec3c238b1917d3f3eca7c7f75798d096b7ed05dc371221028d7ef7f437223338528f7f0c042c95e1d717c0613b97078601ed3019865288eb52aeffffffffd3db8d2204c5ed5f6741a953016505d16b775fc69d9f353f135b857b1d9b0381010000009300483045022100da712b8ed1ca2a7b78f777c8872bbe314c9bbdad2e44fd87f60c8569ffdac3a70220013878512919d6b27a71cd7ed3be5b035b21da778c8afa2ca337c527b07b43b741004752210371f9bb1024de3b2da052ec3c238b1917d3f3eca7c7f75798d096b7ed05dc371221028d7ef7f437223338528f7f0c042c95e1d717c0613b97078601ed3019865288eb52aeffffffffb244ad0b4ff3ffd25661c85ace8e9af79307d89d19992a604434f984ea820eac000000009200473044022025738b81d3e92d613a33ee20bd608ceb8c949bc8cc48957036b7757c96931acf022010003ed448664b4abc23fb8106d2d00030c7d286cf6982703e8e3b72a82efe3c41004752210371f9bb1024de3b2da052ec3c238b1917d3f3eca7c7f75798d096b7ed05dc371221028d7ef7f437223338528f7f0c042c95e1d717c0613b97078601ed3019865288eb52aeffffffff0380969800000000001976a914fa9c06f766135ba96654def7f4e315a0ec4adc2d88ac4ac40000000000001976a914c1b3a40e8ab22b08586e47c1ceb287def9ad23d188ac70b55c050000000017a9141c10a9aa9c416d313f6379ee0829a7df6a6f8a598700000000")
        txStream = io.BytesIO(txbin)
        tx = CTransaction()
        tx.deserialize(txStream)

        flags = libnexa.ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS

        print("eval scriptSig")
        sm = libnexa.ScriptMachine(flags=flags, tx=tx, inputIdx=0)
        worked = evals(sm,CScript(unhexlify("00473044022001a983ec77ff66bcf2d4ad6d4d96a1f6431ee1102c884dc3d01f564092fad92102204d3af3b419ffb2e27249bdfb2290f77bb40b66afc874c2b561f10d5674f61f4201004752210371f9bb1024de3b2da052ec3c238b1917d3f3eca7c7f75798d096b7ed05dc371221028d7ef7f437223338528f7f0c042c95e1d717c0613b97078601ed3019865288eb52ae")))
        if not worked:
            print(sm.error())

        # eval scriptPubKey
        print("eval scriptPubKey")
        worked = evals(sm,CScript(unhexlify("a9141c10a9aa9c416d313f6379ee0829a7df6a6f8a5987")))
        if not worked:
            print(sm.error())
        sm.eval(CScript([OP_DROP]))
        # eval redeemScript
        print("eval redeemScript")
        worked = evals(sm,CScript(unhexlify("52210371f9bb1024de3b2da052ec3c238b1917d3f3eca7c7f75798d096b7ed05dc371221028d7ef7f437223338528f7f0c042c95e1d717c0613b97078601ed3019865288eb52ae")))

        if not worked:
            print(sm.error())
        pdb.set_trace()

    def runAscript(self):
        pdb.set_trace()
        flags=libnexa.ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS | libnexa.ScriptFlags.SCRIPT_ENABLE_CHECKDATASIG
        sm = libnexa.ScriptMachine(flags=flags, tx=None, inputIdx=0)
        # s = CScript([ unhexlify("000000000000000000000000000000000000000000000000000001"), OP_SETBMD, unhexlify("f334a8c048898e4de6b8ca6359533d7fb7c12df3619e22238400"), OP_BIN2BIGNUM, OP_DUP, OP_ADD])
        s = CScript([ unhexlify("000000000000000000000000000000000000000000000000000001"), OP_SETBMD, unhexlify("f334a8c048898e4de6b8ca6359533d7fb7c12df3619e22238400"), OP_DUP, OP_BIN2BIGNUM, OP_SWAP, OP_BIN2BIGNUM, OP_ADD])
        # s = CScript([ unhexlify("000000000000000000000000000000000000000000000000000001"), OP_SETBMD, unhexlify("f334a8c048898e4de6b8ca6359533d7fb7c12df3619e22238400"), OP_BIN2BIGNUM, unhexlify("f334a8c048898e4de6b8ca6359533d7fb7c12df3619e22238400"), OP_BIN2BIGNUM, OP_ADD, 26, OP_NUM2BIN])
        stepEval(sm, s)

    def runDSVtest(self):

        # this DATASIGVERIFY transaction has a non-minimal number encoding so will fail with the default flags but succeed without MINIMALDATA
        prevTx = ""
        spendTx = unhexlify("")

        dbg = DebugSession(prevTx, spendTx, flags=libnexa.ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS | libnexa.ScriptFlags.SCRIPT_ENABLE_CHECKDATASIG )
        print("Evaluating spend script")
        dbg.evalSpendScript()
        print("Evaluating constraint script")
        result = dbg.evalConstraintScript()
        assert(result[0] == libnexa.ScriptError.SCRIPT_ERR_NUMBER_BAD_ENCODING)

        dbg = DebugSession(prevTx, spendTx, flags= (libnexa.ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS | libnexa.ScriptFlags.SCRIPT_ENABLE_CHECKDATASIG) & ~libnexa.ScriptFlags.SCRIPT_VERIFY_MINIMALDATA)
        print("Evaluating spend script")
        dbg.evalSpendScript()
        print("Evaluating constraint script")
        result = dbg.evalConstraintScript()
        assert(result[0] == libnexa.ScriptError.SCRIPT_ERR_OK)

    def multisigTest(self):
        
        prevTx = ""
        spendTx =""

        dbg = DebugSession(prevTx, spendTx, flags=libnexa.ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS | libnexa.ScriptFlags.SCRIPT_ENABLE_CHECKDATASIG )
        print("Evaluating spend script")
        dbg.evalSpendScript()
        print("Evaluating constraint script")
        result = dbg.evalConstraintScript()
        print(result)
        print("Evaluating redeem script")
        pdb.set_trace()
        redeemResult = dbg.evalRedeemScript()
        print(redeemResult)


    def run_test(self):
        # TODO all the examples need updating for Nexa.  However, the active effort in making a debugger has moved to Kotlin so
        # wait until this is needed again.
        pass
        #self.runScriptMachineTests()
        # self.multisigTest()
        # self.runAscript()
        # self.runDSVtest()



if __name__ == '__main__':
    env = os.getenv("NEXAD", None)
    if env is None:
        env = os.path.dirname(os.path.abspath(__file__))
        env = env + os.sep + ".." + os.sep + ".." + os.sep + "src" + os.sep + "nexad"
        env = os.path.abspath(env)
    path = os.path.dirname(env)
    try:
        libnexa.init(path + os.sep + ".libs" + os.sep + "libnexa.so")
        MyTest().main()
    except OSError as e:
        print("Issue loading shared library.  This is expected during cross compilation since the native python will not load the .so: %s" % str(e))

# Create a convenient function for an interactive python debugging session


def Test():
    t = ScriptDebugTest()
    bitcoinConf = {
        "debug": ["net", "blk", "thin", "mempool", "req", "bench", "evict"],
    }
    t.drop_to_pdb = True
    
    flags = [] # ["--nocleanup", "--noshutdown"]
    if os.path.isdir("/ramdisk/test"):
        flags.append("--tmppfx=/ramdisk/test")
    binpath = findBitcoind()
    flags.append("--srcdir=%s" % binpath)
    libnexa.init(binpath + os.sep + ".libs" + os.sep + "libnexa.so")
    t.main(flags, bitcoinConf, None)
