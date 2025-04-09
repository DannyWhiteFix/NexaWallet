#!/usr/bin/env python3
# Copyright (c) 2014-2015 The Bitcoin Core developers
# Copyright (c) 2015-2022 The Bitcoin Unlimited developers
#
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
import test_framework.loginit
import pdb
import sys
if sys.version_info[0] < 3:
    raise "Use Python 3"
import logging

# Test validateblocktemplate RPC call
from test_framework.key import CECKey
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from test_framework.script import *
from test_framework.mininode import *
from test_framework.blocktools import *

# Create a transaction with an anyone-can-spend output, that spends the
# nth output of prevtx.  pass a single integer value to make one output,
# or a list to create multiple outputs


def create_broken_transaction(prevtx, n, sig, value, out=anyoneCanSpend()):
    if not type(value) is list:
        value = [value]
    tx = CTransaction()
    amt = 1000 if len(prevtx.vout) <= n else prevtx.vout[n].nValue  # make up a fake amt if n is bad
    tx.vin.append(CTxIn(COutPoint().fromIdemAndIdx(prevtx.GetIdem(), n), amt, sig, 0xffffffff))
    for v in value:
        tx.vout.append(TxOut(TxOut.TYPE_TEMPLATE, v, out))
    tx.calcId()
    return tx

class ValidateblocktemplateTest(BitcoinTestFramework):

    def setup_network(self):
        self.nodes = []
        self.nodes.append(start_node(0, self.options.tmpdir, ["-test.nextMaxBlockSize=1000000"]))
        self.nodes.append(start_node(1, self.options.tmpdir, ["-test.nextMaxBlockSize=1000000"]))

        self.is_network_split = False
        connect_nodes(self.nodes[0], 1)

    def run_test(self):
        # Generate enough blocks to trigger certain block votes and activate BIP65 (version 4 blocks)
        if 1:
            amt = 1352 - self.nodes[0].getblockcount()
            for i in range(int(amt/100)):
               self.nodes[0].generate(100)
               self.sync_all()

        self.nodes[0].generate(1352 - self.nodes[0].getblockcount())
        self.sync_all()

        logging.info("not on chain tip")
        badtip = int(self.nodes[0].getblockhash(self.nodes[0].getblockcount() - 1), 16)
        height = self.nodes[0].getblockcount()
        nextheight = height + 1
        tip = int(self.nodes[0].getblockhash(height), 16)
        tipHdr = self.nodes[0].getblock(height)
        work = int(tipHdr["chainwork"],16) + 2
        coinbase = create_coinbase(nextheight)
        cur_time = int(time.time())
        ancHeight = ancestorHeight(nextheight)
        ancHash = rpcHexToUint256(self.nodes[0].getblockheader(ancHeight)["hash"])
        self.nodes[0].setmocktime(cur_time)
        self.nodes[1].setmocktime(cur_time)

        block = create_block(badtip, nextheight, work, coinbase, ancHash, cur_time + 600)
        block.rehash()

        hexblk = ToHex(block)
        expectException(lambda: self.nodes[0].validateblocktemplate(hexblk),
                        JSONRPCException, "invalid block: does not build on chain tip")

        logging.info("time too far in the past")
        block = create_block(tip, nextheight, work, coinbase, ancHash, cur_time - 100)
        block.rehash()
        hexblk = ToHex(block)
        expectException(lambda: self.nodes[0].validateblocktemplate(hexblk), JSONRPCException, "invalid block: time-too-old")

        logging.info("time too far in the future")
        block = create_block(tip, nextheight, work, coinbase, ancHash, cur_time + 10000000)
        block.rehash()
        hexblk = ToHex(block)
        expectException(lambda: self.nodes[0].validateblocktemplate(
            hexblk), JSONRPCException, "invalid block: time-too-new")

        logging.info("bad height 1")
        block = create_block(tip, height+2, work, coinbase, ancHash, cur_time + 600)
        block.rehash()
        hexblk = ToHex(block)
        expectException(lambda: self.nodes[0].validateblocktemplate(
            hexblk), JSONRPCException, "invalid block: bad-height")
        logging.info("bad height 2")
        block = create_block(tip, height, work, coinbase, ancHash, cur_time + 600)
        block.rehash()
        hexblk = ToHex(block)
        expectException(lambda: self.nodes[0].validateblocktemplate(
            hexblk), JSONRPCException, "invalid block: bad-height")

        logging.info("bad work")
        block = create_block(tip, nextheight, work+1, coinbase, ancHash, cur_time + 600)
        block.rehash()
        hexblk = ToHex(block)
        expectException(lambda: self.nodes[0].validateblocktemplate(
            hexblk), JSONRPCException, "invalid block: bad-chainwork")
        logging.info("bad work")
        block = create_block(tip, nextheight, work-1, coinbase, ancHash, cur_time + 600)
        block.rehash()
        hexblk = ToHex(block)
        expectException(lambda: self.nodes[0].validateblocktemplate(
            hexblk), JSONRPCException, "invalid block: bad-chainwork")

        logging.info("bad coinbase height")
        tip = int(self.nodes[0].getblockhash(height), 16)
        block = create_block(tip, nextheight, work, create_coinbase(height), ancHash, cur_time + 600)
        block.rehash()
        hexblk = ToHex(block)
        expectException(lambda: self.nodes[0].validateblocktemplate(
            hexblk), JSONRPCException, "invalid block: bad-cb-height")

        logging.info("bad merkle root")
        block = create_block(tip, nextheight, work, coinbase, ancHash, cur_time + 600)
        block.hashMerkleRoot = 0x12345678
        block.rehash()
        hexblk = ToHex(block)
        expectException(lambda: self.nodes[0].validateblocktemplate(hexblk),
                        JSONRPCException, "invalid block:")

        logging.info("no tx")
        block = create_block(tip, nextheight, work, None, ancHash, cur_time + 600)
        block.rehash()
        hexblk = ToHex(block)
        expectException(lambda: self.nodes[0].validateblocktemplate(hexblk),
                        JSONRPCException, "invalid block: bad-blk-length")

        block = create_block(tip, nextheight, work, None, ancHash+1, cur_time + 600)
        block.rehash()
        hexblk = ToHex(block)
        expectException(lambda: self.nodes[0].validateblocktemplate(hexblk),
                        JSONRPCException, "invalid block: bad-ancestor-hash")

        logging.info("good block")
        block = create_block(tip, nextheight, work, coinbase, ancHash, cur_time + 600)
        block.rehash()
        hexblk = ToHex(block)

        # ------
        self.nodes[0].validateblocktemplate(hexblk)
        block.solve()
        hexblk = ToHex(block)
        self.nodes[0].submitblock(hexblk)
        self.sync_all()

        prev_block = block
        # out_value is less than 50BTC because regtest halvings happen every 150 blocks, and is in Satoshis
        out_value = block.vtx[0].vout[0].nValue
        tx1 = create_transaction(prev_block.vtx[0], 0, spendAnyoneCanSpend(), [int(out_value / 2), int(out_value / 2)])
        height = self.nodes[0].getblockcount()
        nextheight = height + 1
        tip = int(self.nodes[0].getblockhash(height), 16)
        tipHdr = self.nodes[0].getblock(height)
        work = int(tipHdr["chainwork"],16) + 2
        ancHash = rpcHexToUint256(self.nodes[0].getblockheader(ancestorHeight(nextheight))["hash"])
        coinbase = create_coinbase(nextheight)
        next_time = cur_time + 1200

        logging.info("no coinbase")
        block = create_block(tip, nextheight, work, None, ancHash, next_time, [tx1])
        block.rehash()
        hexblk = ToHex(block)
        expectException(lambda: self.nodes[0].validateblocktemplate(hexblk),
                        JSONRPCException, "invalid block: bad-cb-missing")

        logging.info("double coinbase")

        coinbase_key = CECKey()
        coinbase_key.set_secretbytes(b"horsebattery")
        coinbase_pubkey = coinbase_key.get_pubkey()

        coinbase2 = create_coinbase(nextheight, coinbase_pubkey)
        block = create_block(tip, nextheight, work, coinbase, ancHash, next_time, [coinbase2, tx1])
        block.rehash()
        hexblk = ToHex(block)
        expectException(lambda: self.nodes[0].validateblocktemplate(hexblk),
                        JSONRPCException, "invalid block: bad-cb-multiple")

        logging.info("premature coinbase spend")
        block = create_block(tip, nextheight, work, coinbase, ancHash, next_time, [tx1])
        block.rehash()
        hexblk = ToHex(block)
        expectException(lambda: self.nodes[0].validateblocktemplate(hexblk),
                        JSONRPCException, "invalid block: bad-txns-premature-spend-of-coinbase")

        self.nodes[0].generate(100)
        self.sync_all()
        height = self.nodes[0].getblockcount()
        nextheight = height + 1
        tip = int(self.nodes[0].getblockhash(height), 16)
        tipHdr = self.nodes[0].getblock(height)
        work = int(tipHdr["chainwork"],16) + 2
        ancHash = rpcHexToUint256(self.nodes[0].getblockheader(ancestorHeight(nextheight))["hash"])

        coinbase = create_coinbase(nextheight)
        next_time = cur_time + 1200

        op1 = OP_1.toBin()

        logging.info("inputs below outputs")
        tx6 = create_transaction(prev_block.vtx[0], 0, op1, [out_value + int(COINBASE_REWARD*COIN)])
        block = create_block(tip, nextheight, work, coinbase, ancHash, next_time, [tx6])
        block.rehash()
        hexblk = ToHex(block)
        expectException(lambda: self.nodes[0].validateblocktemplate(hexblk),
                        JSONRPCException, "invalid block: bad-txns-in-belowout")

        tx5 = create_transaction(prev_block.vtx[0], 0, op1, [int(21000000000001 * COIN)])
        logging.info("money range")
        block = create_block(tip, nextheight, work, coinbase, ancHash, next_time, [tx5])
        block.rehash()
        hexblk = ToHex(block)
        expectException(lambda: self.nodes[0].validateblocktemplate(hexblk),
                        JSONRPCException, "invalid block: bad-txns-vout-toolarge")

        logging.info("bad tx offset")
        tx_bad = create_broken_transaction(prev_block.vtx[0], 1, anyoneCanSpend(), [int(out_value / 4)])
        block = create_block(tip, nextheight, work, coinbase, ancHash, next_time, [tx_bad])
        block.rehash()
        hexblk = ToHex(block)
        expectException(lambda: self.nodes[0].validateblocktemplate(hexblk),
                        JSONRPCException, "invalid block: bad-txns-inputs-missingorspent")

        logging.info("bad tx offset largest number")
        tx_bad = create_broken_transaction(prev_block.vtx[0], 0xffffffff, anyoneCanSpend(), [int(out_value / 4)])
        block = create_block(tip, nextheight, work, coinbase, ancHash, next_time, [tx_bad])
        block.rehash()
        hexblk = ToHex(block)
        expectException(lambda: self.nodes[0].validateblocktemplate(hexblk),
                        JSONRPCException, "invalid block: bad-txns-inputs-missingorspent")


        logging.info("double tx")
        tx2 = create_transaction(prev_block.vtx[0], 0, anyoneCanSpend(), [int(out_value / 4)])
        block = create_block(tip, nextheight, work, coinbase, ancHash, next_time, [tx2, tx2])
        block.rehash()
        hexblk = ToHex(block)
        expectException(lambda: self.nodes[0].validateblocktemplate(hexblk),
                        JSONRPCException, "repeated-txn")

        tx3 = create_transaction(prev_block.vtx[0], 0, anyoneCanSpend(), [int(out_value / 9), int(out_value / 10)])
        tx4 = create_transaction(prev_block.vtx[0], 0, anyoneCanSpend(), [int(out_value / 8), int(out_value / 7)])
        logging.info("double spend")
        block = create_block(tip, nextheight, work, coinbase, ancHash, next_time, [tx3, tx4])
        block.rehash()
        hexblk = ToHex(block)
        expectException(lambda: self.nodes[0].validateblocktemplate(hexblk),
                        JSONRPCException, "invalid block: bad-txns-inputs-missingorspent")

        txes = [tx3, tx4]
        # sort is lexical ordering which is backwards for little-endian bitcoin so just use GetRpcHexId for simplicity
        txes.sort(key=lambda x: x.GetRpcHexId(), reverse=True)
        logging.info("bad tx ordering")
        block = create_block(tip, nextheight, work, coinbase, ancHash, next_time, txes, ctor=False)
        block.rehash()
        hexblk = ToHex(block)
        expectException(lambda: self.nodes[0].validateblocktemplate(hexblk),
                        JSONRPCException, "invalid block: bad-txn-order")

        tx_good = create_transaction(prev_block.vtx[0], 0, spendAnyoneCanSpend(), [int(out_value / 50)] * 50)
        logging.info("good tx")
        block = create_block(tip, nextheight, work, coinbase, ancHash, next_time, [tx_good])
        block.rehash()
        block.solve()
        hexblk = ToHex(block)
        self.nodes[0].validateblocktemplate(hexblk)
        self.nodes[0].submitblock(hexblk)

        self.sync_all()

        height = self.nodes[0].getblockcount()
        nextheight = height + 1
        tip = int(self.nodes[0].getblockhash(height), 16)
        tipHdr = self.nodes[0].getblock(height)
        work = int(tipHdr["chainwork"],16) + 2
        ancHash = rpcHexToUint256(self.nodes[0].getblockheader(ancestorHeight(nextheight))["hash"])
        coinbase = create_coinbase(nextheight)
        next_time = next_time + 600

        coinbase_key = CECKey()
        coinbase_key.set_secretbytes(b"horsebattery")
        coinbase_pubkey = coinbase_key.get_pubkey()
        coinbase3 = create_coinbase(nextheight, coinbase_pubkey)

        txl = []
        for i in range(0, 50):
            ov = block.vtx[1].vout[i].nValue
            txl.append(create_transaction(block.vtx[1], i, spendAnyoneCanSpend(), [int(ov / 50)] * 50))
        block = create_block(tip, nextheight, work, coinbase, ancHash, next_time, txl)
        block.rehash()
        block.solve()
        hexblk = ToHex(block)
        for n in self.nodes:
            n.validateblocktemplate(hexblk)

        self.nodes[0].setminingmaxblock(1000 * 1000)
        self.nodes[0].set("test.nextMaxBlockSize=10000000")

        for it in range(0, 100):
            # if (it&1023)==0: print(it)
            h2 = hexblk
            pos = random.randint(0, len(hexblk))
            val = random.randint(0, 15)
            h3 = h2[:pos] + ('%x' % val) + h2[pos + 1:]
            try:
                self.nodes[0].validateblocktemplate(h3)
            except JSONRPCException as e:
                if not (e.error["code"] == -1 or e.error["code"] == -22):
                    print(str(e))
                # its ok we expect garbage

        self.nodes[1].submitblock(hexblk)
        self.sync_all()

        height = self.nodes[0].getblockcount()
        nextheight = height + 1
        tip = int(self.nodes[0].getblockhash(height), 16)
        tipHdr = self.nodes[0].getblock(height)
        work = int(tipHdr["chainwork"],16) + 2
        coinbase = create_coinbase(nextheight)
        ancHash = rpcHexToUint256(self.nodes[0].getblockheader(ancestorHeight(nextheight))["hash"])
        next_time = next_time + 600
        prev_block = block
        txl = []
        for tx in prev_block.vtx[0:1]:
            for outp in range(0, len(tx.vout)):
                ov = tx.vout[outp].nValue
                if ov > 0:  # not data
                    txl.append(create_transaction(tx, outp, CScript([OP_CHECKSIG] * 100), [int(ov / 2)] * 2))
        block = create_block(tip, nextheight, work, coinbase, ancHash, next_time, txl)
        block.solve()
        hexblk = ToHex(block)
        for n in self.nodes:
            expectException(lambda: n.validateblocktemplate(hexblk), JSONRPCException,
                            "-1: invalid block: bad-txns-premature-spend-of-coinbase")

def Test():
    t = ValidateblocktemplateTest()
    t.drop_to_pdb = True
    bitcoinConf = {
        "debug": ["net", "blk", "thin", "mempool", "req", "bench", "evict","-event"],
        "blockprioritysize": 2000000  # we don't want any transactions rejected due to insufficient fees...
    }

    flags = []
    # you may want these additional flags:
    # flags.append("--nocleanup")
    # flags.append("--noshutdown")

    # Execution is much faster if a ramdisk is used, so use it if one exists in a typical location
    if os.path.isdir("/ramdisk/test"):
        flags.append("--tmppfx=/ramdisk/test")

    # Out-of-source builds are awkward to start because they need an additional flag
    # automatically add this flag during testing for common out-of-source locations
    here = os.path.dirname(os.path.abspath(__file__))
    if not os.path.exists(os.path.abspath(here + "/../../src/nexad")):
        dbg = os.path.abspath(here + "/../../debug/src/nexad")
        rel = os.path.abspath(here + "/../../release/src/nexad")
        if os.path.exists(dbg):
            print("Running from the debug directory (%s)" % dbg)
            flags.append("--srcdir=%s" % os.path.dirname(dbg))
        elif os.path.exists(rel):
            print("Running from the release directory (%s)" % rel)
            flags.append("--srcdir=%s" % os.path.dirname(rel))

    t.main(flags, bitcoinConf, None)

if __name__ == '__main__':
    bitcoinConf = {
        "debug": ["net", "blk", "thin", "mempool", "req", "bench", "evict"]
    }
    args = sys.argv
    if "--no-ipv6-rpc-listen":
        args.append("--no-ipv6-rpc-listen")
    ValidateblocktemplateTest().main(args,bitcoinConf)

def Test():
    t = ValidateblocktemplateTest()
    t.drop_to_pdb = True
    bitcoinConf = {
        "debug": ["rpc", "net", "blk", "thin", "mempool", "req", "bench", "evict"],
    }
    flags = standardFlags()
    t.main(flags, bitcoinConf, None)
