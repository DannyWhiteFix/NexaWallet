#!/usr/bin/env python3
# Copyright (c) 2015-2022 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# parts taken from weirdtx.py

import test_framework.loginit

import time
import sys
if sys.version_info[0] < 3:
    raise "Use Python 3"
import logging

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from test_framework.blocktools import *
from test_framework.script import *
from test_framework.key import *
from binascii import unhexlify, hexlify

def Hash256Puzzle(s):
    if type(s) is str:
        s = s.encode()
    ret = CScript([OP_HASH256, hash256(s), OP_EQUAL])
    return ret


def MatchString(s):
    if type(s) is str:
        s = s.encode()
    ret = CScript([s, OP_EQUAL])
    return ret


def p2pkh_list(addr):
    return [OP_DUP, OP_HASH160, bitcoinAddress2bin(addr), OP_EQUALVERIFY, OP_CHECKSIG]


def SignWithAorB(twoAddrs):
    ret = CScript([OP_IF] + p2pkh_list(twoAddrs[0]) + [OP_ELSE] + p2pkh_list(twoAddrs[1]) + [OP_ENDIF])
    return ret


class SigHashMatchTest(BitcoinTestFramework):
    def setup_chain(self, bitcoinConfDict, wallets=None):
        print("Initializing test directory " + self.options.tmpdir)
        initialize_chain_clean(self.options.tmpdir, 2, bitcoinConfDict, wallets)

    def setup_network(self, split=False):
        self.nodes = start_nodes(2, self.options.tmpdir)
        connect_nodes_bi(self.nodes, 0, 1)
        self.is_network_split = False
        self.sync_all()

    def run_test(self):
        # generate enough blocks so that nodes[0] has a balance
        self.sync_blocks()
        self.nodes[0].generate(150)
        self.sync_blocks()

        unspents = self.nodes[0].listunspent()
        unspents.sort(key=lambda x: x["amount"], reverse=False)
        utxo = unspents.pop()
        amt = utxo["amount"]
        addr = utxo["address"]
        outp = { "any" : amt - 1000}  # give some fee
        hextx = createrawtransaction([utxo], outp)
        txn = CTransaction().deserialize(hextx)

        # create signature manually using txn.SignatureHash() calculation
        # plus the new signdata RPC call, append the sighashbyte and make sure
        # it is accepted by the node.

        privkey = self.nodes[0].dumpprivkey(addr)
        key = CECKey()
        key.set_secretbytes(decodeBase58(privkey)[1:-5])
        key.set_compressed(True)
        pub = key.get_pubkey()

        for hashcode in [ SIGHASH_ALL, bytes(), bytes([SIGHASH_THIS_IN | SIGHASH_ALL_OUT]), bytes([SIGHASH_FIRSTN_IN | SIGHASH_FIRSTN_OUT, 1,1]), bytes([SIGHASH_FIRSTN_IN | SIGHASH_FIRSTN_OUT, 0,1])]:
            scriptcode = CScript([OP_FROMALTSTACK, OP_CHECKSIGVERIFY])
            sighash = txn.SignatureHashNexa(0, bytes(scriptcode), hashcode, debug=False)
            txn_mansig = unhexlify(self.nodes[0].signdata(addr, "hash", hexlify(sighash).decode("ascii")))
            hcBytes = hashcode if type(hashcode) == bytes else bytes([hashcode])
            fullsig = txn_mansig + hcBytes 
            templateArgs = CScript([pub])
            txn.vin[0].scriptSig = CScript([templateArgs, fullsig])
            analysis = self.nodes[0].validaterawtransaction(txn.toHex())
            assert analysis["isValid"] == True, "Python sighashing problem"

        # finally try issuing the tx
        scriptcode = CScript([OP_FROMALTSTACK, OP_CHECKSIGVERIFY])
        hashcode = SIGHASH_ALL
        sighash = txn.SignatureHashNexa(0, bytes(scriptcode), hashcode, debug=False)
        txn_mansig = unhexlify(self.nodes[0].signdata(addr, "hash", hexlify(sighash).decode("ascii")))
        fullsig = txn_mansig+bytes([hashcode])
        templateArgs = CScript([pub])
        txn.vin[0].scriptSig = CScript([templateArgs, fullsig])
        txid = self.nodes[0].sendrawtransaction(txn.toHex())
        assert len(txid) == 64
        assert self.nodes[0].gettxpoolinfo()['size'] == 1  # our tx got committed to the pool

if __name__ == '__main__':
    SigHashMatchTest().main(bitcoinConfDict = {"usecashaddr" : 0})

# Create a convenient function for an interactive python debugging session


def Test():
    t = SigHashMatchTest()
    t.drop_to_pdb = True
    bitcoinConf = {
        "debug": ["net", "blk", "thin", "mempool", "req", "bench", "evict"],
        "usecashaddr" : 0
    }
    flags = standardFlags()
    t.main(flags, bitcoinConf, None)
