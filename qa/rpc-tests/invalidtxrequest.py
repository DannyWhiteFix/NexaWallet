#!/usr/bin/env python3
# Copyright (c) 2015-2022 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
""" Test invalid transaction as passed through the p2p and RPC layers
"""
import test_framework.loginit

import time
import sys
if sys.version_info[0] < 3:
    raise "Use Python 3"
import logging

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from test_framework.bunode import *
from test_framework.script import *

class MyTest (BitcoinTestFramework):

    def setup_chain(self,bitcoinConfDict=None, wallets=None):
        print("Initializing test directory "+self.options.tmpdir)
        # pick this one to start from the cached 4 node 100 blocks mined configuration
        initialize_chain(self.options.tmpdir, bitcoinConfDict, wallets)

    def setup_network(self, split=False):
        self.nodes = start_nodes(2, self.options.tmpdir)
        # Nodes to start --------^
        # Note for this template I readied 4 nodes but only started 2

        # Now interconnect the nodes
        connect_nodes_full(self.nodes)
        # Let the framework know if the network is fully connected.
        # If not, the framework assumes this partition: (0,1) and (2,3)
        # For more complex partitions, you can't use the self.sync* member functions
        self.is_network_split=False
        self.sync_blocks()

    def invGetdata(self, tx):
        self.pynodeCnxn.send_inv(tx)
        waitFor(10, lambda: len(self.pynodeCnxn.last_getdata) > 0)
        msg = self.pynodeCnxn.last_getdata.pop()
        assert msg.inv[0].hash == tx.GetIdAsInt()
        self.pynodeCnxn.send_message(msg_tx(tx))

    def tryAtx(self, tx, p2pErr, rpcErr):
        node = self.node
        rnode = self.rnode  # node can relay to node 1
        self.invGetdata(tx)
        txrpcIdem = util.uint256ToRpcHex(tx.GetIdem())
        waitFor(10, lambda: len(self.pynodeCnxn.last_reject) > 0)
        rej = self.pynodeCnxn.last_reject.pop()
        assert p2pErr in rej.reason
        assert txrpcIdem not in node.getrawtxpool()
        assert txrpcIdem not in rnode.getrawtxpool()  # Verify that the bad tx did not relay
        # Check RPC interface
        expectException(lambda: rnode.sendrawtransaction(tx.toHex()), JSONRPCException, rpcErr)
        ret = rnode.validaterawtransaction(tx.toHex())
        assert rpcErr in str(ret)  # We don't know exactly where validaterawtransaction will put the error, but it must be in there

    def trySpendingAtx(self, tx, p2pErr, rpcErr):
        node = self.node
        rnode = self.rnode  # node can relay to node 1

        testTx = fundSignSendSpend(node, tx, relay=False)

        self.invGetdata(testTx)
        txrpcIdem = util.uint256ToRpcHex(testTx.GetIdem())
        waitFor(10, lambda: len(self.pynodeCnxn.last_reject) > 0)
        rej = self.pynodeCnxn.last_reject.pop()
        assert p2pErr in rej.reason
        assert txrpcIdem not in node.getrawtxpool()
        assert txrpcIdem not in rnode.getrawtxpool()  # Verify that the bad tx did not relay
        # Check RPC interface
        expectException(lambda: rnode.sendrawtransaction(testTx.toHex()), JSONRPCException, rpcErr)
        ret = rnode.validaterawtransaction(testTx.toHex())
        assert rpcErr in str(ret)  # We don't know exactly where validaterawtransaction will put the error, but it must be in there

    def run_test (self):
        self.nodes[0].generate(1)  # Kick out of IBD so txes relay (since using cached blocks, it looks like no blocks arrived for a long time)

        # 300 sats
        fee = decimal.Decimal(300)/COIN

        # Both BUcash and BU should connect to a normal BU node
        pynode = BasicBUCashNode()
        pynode.connect(0,'127.0.0.1', p2p_port(0), self.nodes[0])
        NetworkThread().start()  # Start up network handling in another thread
        pynode.cnxns[0].wait_for_verack()

        # Pick some roles that are used in various member functions
        self.node = self.nodes[0]
        self.rnode = self.nodes[1]  # node can relay to node 1
        self.pynodeCnxn = pynode.cnxns[0]

        # Make a bunch of satoscript utxos because this test uses them
        addr = self.node.getnewaddress("p2pkh")
        self.node.sendtoaddress(addr, 10000)
        self.node.sendtoaddress(addr, 10000)
        self.node.sendtoaddress(addr, 10000)
        self.node.sendtoaddress(addr, 10000)
        self.node.generate(1)

        # grab a list of coins to work with
        utxos = self.node.listunspent()
        utxos = list(filter(lambda x: x["scriptType"] != "template", utxos)) # Find inputs that are not a template

        # Try a valid tx
        utxo = utxos.pop()
        tx1 = CTransaction()
        tx1.vin.append(CTxIn(utxo))
        tx1.vout.append(TxOut(0,utxo["amount"]-fee, CScript([OP_1])))
        # result = node.fundrawtransaction(tx1.toHex())
        result = self.node.signrawtransaction(tx1.toHex())
        # print(result)
        tx1 = CTransaction(result)
        self.invGetdata(tx1)
        tx1rpcIdem = util.uint256ToRpcHex(tx1.GetIdem())
        waitFor(10, lambda: tx1rpcIdem in self.node.getrawtxpool() )


        # Bad TX: A single OP_NOTIF
        # b'\x64' is OP_NOTIF
        # 0x61 is OP_NOP (throw a bunch of nops in so that tx > 100 bytes
        # Transaction will be rejected with code 16 (REJECT_INVALID)
        utxo = utxos.pop()
        tx2 = CTransaction()
        tx2.vin.append(CTxIn(utxo))
        #tx2.vin[0].scriptSig = b'\x61'*48 + b'\x64'
        # tx2.vout.append(TxOut(0,utxo["amount"]-fee, CScript([OP_1])))
        tx2.vout.append(TxOut(0,utxo["amount"]-fee, CScript([OP_NOP]*48 + [OP_NOTIF])))
        self.trySpendingAtx(tx2, b'mandatory-script-verify-flag-failed', 'mandatory-script-verify-flag-failed (Invalid OP_IF construction)')

        # Try undersize transaction
        tx2.vin[0].scriptSig = b''
        tx2.vout[0].scriptPubKey = b'\x64'
        tx2.rehash()
        assert len(tx2.toHex()) == 128, "transaction changed size so this test needs to be reworked"
        self.tryAtx(tx2, b'txn-undersize', 'txn-undersize')

        # TODO: test further transactions...

if __name__ == '__main__':
    MyTest ().main ()

# Create a convenient function for an interactive python debugging session
def Test():
    t = MyTest()
    t.drop_to_pdb = True
    # install ctrl-c handler
    #import signal, pdb
    #signal.signal(signal.SIGINT, lambda sig, stk: pdb.Pdb().set_trace(stk))
    bitcoinConf = {
        "debug": ["net", "blk", "thin", "mempool", "req", "bench", "evict"],
    }
    flags = standardFlags()
    # logging.getLogger().setLevel(logging.DEBUG)
    t.main(flags, bitcoinConf, None)
