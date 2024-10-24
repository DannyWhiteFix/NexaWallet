#!/usr/bin/env python3
# Copyright (c) 2024 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import test_framework.loginit
import logging


import test_framework.libnexa as libnexa
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from test_framework.blocktools import *
from test_framework.nodemessages import *
from test_framework.script import *


class ScriptRegistersTest(BitcoinTestFramework):
    NUM_NODES = 4
    def setup_chain(self,bitcoinConfDict=None, wallets=None):
        libnexa.loadLibNexaOrExit(self.options.srcdir)
        logging.info("Initializing test directory "+self.options.tmpdir)
        initialize_chain_clean(self.options.tmpdir, self.NUM_NODES, self.confDict)

    def setup_network(self):
        self.nodes = []
        self.is_network_split = False
        for i in range(0, self.NUM_NODES):
            self.nodes.append(start_node(i, self.options.tmpdir, []))
        interconnect_nodes(self.nodes)

    def run_test(self):
        dest_addr = self.nodes[1].getnewaddress()
        dest_addr = self.nodes[1].getaddressforms(dest_addr)["legacy"]
        miningNode = self.nodes[2]
        # check failure before activation
        miningNode.generate(110)
        self.sync_all()
        bestblock = miningNode.getbestblockhash()
        lastblocktime = miningNode.getblockheader(bestblock)['time']
        activationtime = lastblocktime + 200000000
        for n in self.nodes:
            n.set("consensus.fork1Time=" + str(activationtime))

        blockchaininfo = miningNode.getblockchaininfo()
        assert_equal(blockchaininfo['forktime'], activationtime)
        assert_equal(blockchaininfo['forkactive'], False)
        assert_equal(blockchaininfo['forkenforcednextblock'], False)
        assert_greater_than(activationtime, blockchaininfo['mediantime'])


        utxos = self.nodes[2].listunspent()
        assert(len(utxos) > 0)
        utxo = utxos[0]
        tx = CTransaction()
        # Create an output with the new opcodes
        tx_value = int(int(satoshi_round(utxo["amount"]) * COIN) * 0.95)
        tx.vin = [CTxIn(COutPoint().fromIdemAndIdx(utxo['txidem'],utxo['vout']).rpcHex(), utxo["amount"])]
        tx.vout = []
        redeemScript = CScript([bitcoinAddress2bin(dest_addr), OP_DUP, OP_1, OP_STORE, OP_HASH160, OP_1, OP_LOAD, OP_EQUALVERIFY, OP_CHECKSIG])
        tx.vout.append(CTxOut(tx_value, redeemScript))
        tx_signed_hex = self.nodes[2].signrawtransaction(tx.toHex())["hex"]
        res = self.nodes[2].sendrawtransaction(tx_signed_hex)

        # Now spend them (should fail)
        tx = CTransaction()
        # Create an input that spends the new opcodes
        tx.vin = [CTxIn(COutPoint().fromIdemAndIdx(res,0).rpcHex(), tx_value)]
        tx.vout = []
        s = CScript([OP_TRUE])
        tx.vout.append(CTxOut(tx_value - 300, CScript([bitcoinAddress2bin(dest_addr), OP_DROP, OP_TRUE])))
        tx_signed_hex = self.nodes[2].signrawtransaction(tx.toHex())["hex"]
        try:
            res2 = self.nodes[2].sendrawtransaction(tx_signed_hex)
            print(res2)
            assert(False)  # Should not work because we haven't activated!
        except JSONRPCException as e:
            # expected to get here
            assert "Opcode missing or not understood" in str(e)

        miningNode.generate(1)
        # Activate the hard fork
        bestblock = miningNode.getbestblockhash()
        lastblocktime = miningNode.getblockheader(bestblock)['time']
        activationtime = lastblocktime - 2000
        for n in self.nodes:
            n.set("consensus.fork1Time=" + str(activationtime))

        # get some utxos
        for n in self.nodes:
            n.generate(int(60/len(self.nodes)))
            sync_blocks(self.nodes)

        miningNode.generate(120)
        sync_blocks(self.nodes)

        blockchaininfo = miningNode.getblockchaininfo()
        assert_equal(blockchaininfo['forkactive'], True)

        # do something that works and uses registers
        begin_node0_balance = self.nodes[0].getbalance()
        begin_node1_balance = self.nodes[1].getbalance()
        utxos = self.nodes[0].listunspent()
        assert(len(utxos) > 0)
        utxo = utxos[0]
        tx = CTransaction()
        # spend half the utxo
        tx_value = int(int(satoshi_round(utxo["amount"]) * COIN) * 0.95)
        tx.vin = [CTxIn(COutPoint().fromIdemAndIdx(utxo['txidem'],utxo['vout']).rpcHex(), utxo["amount"])]
        tx.vout = []
        redeemScript = CScript([OP_1, OP_STORE, 10, OP_1, OP_LOAD, OP_SUB])
        tx.vout.append(CTxOut(tx_value-2000, redeemScript))
        redeemScriptBad = CScript([bitcoinAddress2bin(dest_addr), OP_DUP, OP_1, OP_STORE, OP_HASH160, 36, OP_LOAD, OP_EQUALVERIFY, OP_CHECKSIG])
        tx.vout.append(CTxOut(2000, redeemScriptBad))
        tx_signed_hex = self.nodes[0].signrawtransaction(tx.toHex())["hex"]
        txidem = self.nodes[0].sendrawtransaction(tx_signed_hex)
        self.sync_all()
        assert(txidem in self.nodes[0].getrawtxpool())
        assert(txidem in self.nodes[1].getrawtxpool())
        assert(txidem in self.nodes[2].getrawtxpool())
        self.nodes[2].generate(1)
        self.sync_all()
        end_node0_balance = self.nodes[0].getbalance()
        end_node1_balance = self.nodes[1].getbalance()
        # check that the tx was processed, the balance of node 0 should be less than the
        # start - the tx value because some fee was paid. checking the exact amount is not
        # necessary, only that the value sent is gone indicating the tx was valid
        # node 1 balance should have grown by value
        assert(end_node0_balance*COIN < begin_node0_balance*COIN - tx_value)
        # Although we sent this money to a node1 address, the wallet isn't smart enough to identify this custom transaction as going to this node
        # assert(end_node1_balance*COIN == begin_node1_balance*COIN)

        tx = CTransaction()
        # Create an input that spends the new opcodes
        tx.vin = [CTxIn(COutPoint().fromIdemAndIdx(txidem,0).rpcHex(), tx_value, CScript([10]))]
        tx.vout = []
        s = CScript([bitcoinAddress2bin(dest_addr), OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG])
        tx.vout.append(CTxOut(tx_value - 2300, CScript([bitcoinAddress2bin(dest_addr), OP_DROP, OP_TRUE])))
        tx_signed_hex = self.nodes[2].signrawtransaction(tx.toHex())["hex"]

        try:
            res3 = self.nodes[2].sendrawtransaction(tx_signed_hex)
            assert False, "This should have failed because if the script register restored the proper value the SUB result is 0 not 1"
        except JSONRPCException as e:
            pass

        # Now spend the register-using input into a standard node 1 address
        tx = CTransaction()
        # Create an input that spends the new opcodes
        tx.vin = [CTxIn(COutPoint().fromIdemAndIdx(txidem,0).rpcHex(), tx_value-2000, CScript([11]))]
        tx.vout = []
        s = CScript([bitcoinAddress2bin(dest_addr), OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG])
        tx.vout.append(CTxOut(tx_value - 2300, CScript([bitcoinAddress2bin(dest_addr), OP_DROP, OP_TRUE])))
        tx_signed_hex = self.nodes[2].signrawtransaction(tx.toHex())["hex"]
        res3 = self.nodes[2].sendrawtransaction(tx_signed_hex)
        print(res3)
        assert(True)  # Should work

        # make another tx that fails to send
        tx = CTransaction()
        tx.vin = [CTxIn(COutPoint().fromIdemAndIdx(txidem,1).rpcHex(), 2000)]
        tx.vout = [ CTxOut(1700, CScript([ b'5' * 30, OP_DROP, OP_TRUE])) ]  # need to bulk out the tx
        try:
            self.nodes[0].sendrawtransaction(tx.toHex())
            assert(False)
        except JSONRPCException as e:
            # print(str(e))
            assert "Invalid script register number" in str(e)



if __name__ == '__main__':
    ScriptRegistersTest().main()
    exit(0)

def Test():
    t = ScriptRegistersTest()
    t.drop_to_pdb = True
    bitcoinConf = {
        "par": 1,
        "txindex":1,
        "debug": ["all","-libevent"]
    }
    flags = standardFlags()
    t.main(flags, bitcoinConf, None)
