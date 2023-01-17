#!/usr/bin/env python3
# Copyright (c) 2015 The Bitcoin Core developers
# Copyright (c) 2015-2022 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

#
# Test ZMQ interface
#

import time
import test_framework.loginit
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
import zmq
import struct

import http.client
import urllib.parse

def ZmqReceive(socket, timeout=30):
    start = time.time()
    while True:
        try:
            return socket.recv_multipart()
        except zmq.ZMQError as e:
            if e.errno != zmq.EAGAIN or time.time() - start >= timeout:
                raise
            time.sleep(0.05)


class ZMQTest (BitcoinTestFramework):

    port = 28340 # ZMQ ports of these test must be unique so multiple tests can be run simultaneously

    def setup_nodes(self):
        self.zmqContext = zmq.Context()
        self.zmqBlock = self.zmqContext.socket(zmq.SUB)
        self.zmqBlock.setsockopt(zmq.SUBSCRIBE, b"hashblock")
        self.zmqBlock.setsockopt(zmq.RCVTIMEO, 30)
        self.zmqBlock.setsockopt(zmq.LINGER, 5)
        self.zmqBlock.connect("tcp://127.0.0.1:%i" % self.port)

        self.zmqSubSocket = self.zmqContext.socket(zmq.SUB)
        self.zmqSubSocket.setsockopt(zmq.SUBSCRIBE, b"txid")
        self.zmqSubSocket.setsockopt(zmq.SUBSCRIBE, b"txidem")
        self.zmqSubSocket.setsockopt(zmq.SUBSCRIBE, b"dsid")
        self.zmqSubSocket.setsockopt(zmq.SUBSCRIBE, b"dsidem")
        self.zmqBlock.setsockopt(zmq.RCVTIMEO, 30)
        self.zmqSubSocket.setsockopt(zmq.LINGER, 5)
        self.zmqSubSocket.connect("tcp://127.0.0.1:%i" % self.port)
        return start_nodes(4, self.options.tmpdir, extra_args=[
            ['-zmqpubhashtx=tcp://127.0.0.1:'+str(self.port), '-zmqpubhashblock=tcp://127.0.0.1:'+str(self.port), '-zmqpubhashds=tcp://127.0.0.1:'+str(self.port), '-debug=respend', '-debug=dsproof', '-debug=mempool', '-debug=net', '-debug=zmq'],
            ['-debug=respend', '-debug=dsproof', '-debug=mempool', '-debug=net', '-debug=zmq'],
            ['-debug=respend', '-debug=dsproof', '-debug=mempool', '-debug=net', '-debug=zmq'],
            []
            ])

    def run_test(self):
        try:
            self.sync_all()

            genhashes = self.nodes[0].generate(1)
            self.sync_all()

            print("listen...")
            # Look for the coinbase announcements (id and idem)
            for i in range(0,2):
                msg = ZmqReceive(self.zmqSubSocket)
                topic = msg[0]
                body = msg[1]
                assert(topic == b"txid" or topic == b"txidem")

            # Look for the block announcement
            msg = ZmqReceive(self.zmqBlock)
            topic = msg[0]
            body = bytes_to_hex_str(msg[1])
            assert_equal(topic,b"hashblock")
            assert_equal(genhashes[0], body) #blockhash from generate must be equal to the hash received over zmq


            n = 10
            genhashes = self.nodes[1].generate(n)
            self.sync_all()

            zmqHashes = []
            for x in range(0,n):
                msg = ZmqReceive(self.zmqBlock)
                topic = msg[0]
                body = msg[1]
                assert(topic == b"hashblock")
                zmqHashes.append(bytes_to_hex_str(body))
            
            # get the coinbase tx announcements
            for x in range(0,n*2):
                msg = ZmqReceive(self.zmqSubSocket)
                topic = msg[0]
                assert(topic == b"txid" or topic == b"txidem")

            for x in range(0,n):
                assert_equal(genhashes[x], zmqHashes[x]) # blockhash from generate must be equal to the hash received over zmq

            #test tx from a second node
            hashRPC = self.nodes[1].sendtoaddress(self.nodes[0].getnewaddress("p2pkh"), 100000.0)
            self.sync_all()

            # now we should receive a zmq msg because the tx was broadcast
            for x in range(0,2):
                msg = ZmqReceive(self.zmqSubSocket)
                topic = msg[0]
                body = msg[1]
                if topic == b"txidem":
                    hashZMQ = bytes_to_hex_str(body)
                    assert_equal(hashRPC, hashZMQ) #tx hash from generate must be equal to the hash received over zmq

            # Send all coins to a single new address so that we can be sure that we
            # try double spending a p2pkh output in the subsequent step.
            wallet = self.nodes[0].listunspent()
            inputs = []
            num_coins = 0
            for t in wallet:
                inputs.append({ "outpoint" : t["outpoint"], "amount" : t["amount"]})
                num_coins += 1
            outputs = { self.nodes[0].getnewaddress("p2pkh") : num_coins * COINBASE_REWARD-Decimal("9900") }
            rawtx   = self.nodes[0].createrawtransaction(inputs, outputs)
            rawtx   = self.nodes[0].signrawtransaction(rawtx)
            idRPC = rawtx["txid"]
            try:
                hashRPC   = self.nodes[0].sendrawtransaction(rawtx['hex'])
            except JSONRPCException as e:
                print(e.error['message'])
                assert(False)
            self.sync_all()

            for i in range(0,2):
                #check we received zmq notification
                msg = ZmqReceive(self.zmqSubSocket)
                topic = msg[0]
                body = msg[1]
                if topic == b"txidem":
                    hashZMQ = bytes_to_hex_str(body)
                    assert_equal(hashRPC, hashZMQ) #tx hash from generate must be equal to the hash received over zmq
                elif topic == b"txid":
                    hashZMQ = bytes_to_hex_str(body)
                    assert_equal(idRPC, hashZMQ) #tx hash from generate must be equal to the hash received over zmq
                else:
                    print("unexpected topic: ", topic)


            hashRPC = self.nodes[1].generate(1)
            self.sync_all()

            #check we received zmq notification
            for i in range(8):
                msg = ZmqReceive(self.zmqSubSocket)

            msg = ZmqReceive(self.zmqBlock)
            topic = msg[0]
            body = msg[1]

            hashZMQ = ""
            if topic == b"hashblock":
                hashZMQ = bytes_to_hex_str(body)
            assert_equal(hashRPC[0], hashZMQ) #blockhash from generate must be equal to the hash received over zmq

            # Send 2 transactions that double spend each another
            wallet = self.nodes[0].listunspent()
            walletp2pkh = list(filter(lambda x : x["scriptType"] == 'satoscript' and len(x["scriptPubKey"]) != 70, wallet))  # Find an input that is not P2PK
            t = walletp2pkh.pop()
            inputs = []
            inputs.append({ "outpoint" : t["outpoint"], "amount" : t["amount"]})
            outputs = { self.nodes[1].getnewaddress("p2pkh") : t["amount"] }

            rawtx   = self.nodes[0].createrawtransaction(inputs, outputs)
            rawtx   = self.nodes[0].signrawtransaction(rawtx)
            idDoubleSpendTx = rawtx["txid"]
            try:
                hashTxToDoubleSpend   = self.nodes[1].sendrawtransaction(rawtx['hex'])
            except JSONRPCException as e:
                print(e.error['message'])
                assert(False)
            self.sync_all()

            #check we received zmq notification
            for i in range(0,2):
                msg = ZmqReceive(self.zmqSubSocket)
                topic = msg[0]
                body = msg[1]
                hashZMQ = ""
                if topic == b"txidem":
                    hashZMQ = bytes_to_hex_str(body)
                    assert_equal(hashTxToDoubleSpend, hashZMQ) #tx hash from generate must be equal to the hash received over zmq

            outputs = { self.nodes[1].getnewaddress("p2pkh") : t["amount"] }
            rawtx   = self.nodes[0].createrawtransaction(inputs, outputs)
            rawtx   = self.nodes[0].signrawtransaction(rawtx)
            idtx = rawtx["txid"]
            try:
                idemtx   = self.nodes[0].sendrawtransaction(rawtx['hex'])
            except JSONRPCException as e:
                assert("txn-mempool-conflict" in e.error['message'])
            else:
                assert(False)
            self.sync_all()

            # now we should receive a zmq ds msg because the tx was broadcast
            for i in range(0,2):
                msg = ZmqReceive(self.zmqSubSocket)
                topic = msg[0]
                body = msg[1]
                hashZMQ = ""
                if topic == b"dsidem":
                    hashZMQ = bytes_to_hex_str(body)
                    assert_equal(hashTxToDoubleSpend, hashZMQ) #double spent tx hash from generate must be equal to the hash received over zmq
                if topic == b"dsid":
                    hashZMQ = bytes_to_hex_str(body)
                    assert_equal(idDoubleSpendTx, hashZMQ) #double spent tx hash from generate must be equal to the hash received over zmq

        finally:
            self.zmqSubSocket.close()
            self.zmqSubSocket = None
            self.zmqContext.destroy()
            self.zmqContext = None


if __name__ == '__main__':
    ZMQTest ().main ()

def Test():
    flags = standardFlags()
    # install ctrl-c handler
    import signal, pdb
    signal.signal(signal.SIGINT, lambda sig, stk: pdb.Pdb().set_trace(stk))

    t = ZMQTest()
    t.drop_to_pdb = True
    t.main(flags)
