#!/usr/bin/env python3
# Copyright (c) 2015-2022 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.


# Test Schnorr signatures.
# This test first compares the signatures created in Python with those created by the bitcoind library.
from test_framework.script import *
from test_framework.util import *
from test_framework.nodemessages import *
from test_framework.blocktools import *
from test_framework.test_framework import BitcoinTestFramework
import test_framework.libnexa as libnexa
import test_framework.schnorr as schnorr
import logging
import test_framework.loginit
import array
import platform

import time
import sys
if sys.version_info[0] < 3:
    raise "Use Python 3"

# This is test is not about actually veryfing node behavior
# across fork but just to test how nodes behave once schnorr
# is activated. Hence just set activation time in the past so
# that node 0 and 1 would be able to use schnorr sig and drop
# transaction that come from pre-activation nodes

class PlaceHolder():
    def __init__(self, d=None):
        self.data = d

class SchnorrSigTest (BitcoinTestFramework):

    def setup_chain(self, bitcoinConfDict=None, wallets=None):
        # initialize_chain(self.options.tmpdir, bitcoinConfDict, wallets)
        # I cannot used cached because I am using mocktime
        initialize_chain_clean(self.options.tmpdir, 4, bitcoinConfDict, wallets)

    def setup_network(self, split=False):
        self.nodes = start_nodes(3, self.options.tmpdir)

        # Now interconnect the nodes
        connect_nodes_full(self.nodes)
        # Let the framework know if the network is fully connected.
        # If not, the framework assumes this partition: (0,1) and (2,3)
        # For more complex partitions, you can't use the self.sync* member functions
        self.is_network_split = False
        self.sync_blocks()

    def pubkeySearch(self):
        print("pid: ", os.getpid())
        privkey = libnexa.randombytes(32)
        pubkey = schnorr.getpubkey(privkey, compressed=True)
        lens = array.array("Q",[0 for i in range (0,101)])
        data = 1
        while 1:
            databytes = struct.pack(">Q", data)
            sig = libnexa.signData(databytes, privkey)
            l = len(sig)
            if l == 64:
                print("data: ", data, " ", hexlify(databytes))
                print("sig: ", hexlify(sig))
                print("privkey:", hexlify(privkey))
            lens[l] += 1
            data += 1
            if ((data&16383)==0):
                print(data)
                print(lens[60:])

    def basicSchnorrSigning(self):
        # First try a canned sig (taken from schnorr.py)
        privkey = bytes.fromhex("12b004fff7f4b69ef8650e767f18f11ede158148b425660723b9f9a66e61f747")

        pubkey = schnorr.getpubkey(privkey, compressed=True)
        assert pubkey == bytes.fromhex("030b4c866585dd868a9d62348a9cd008d6a312937048fff31670e7e920cfc7a744")

        msg = b"Very deterministic message"
        msghash = hash256(msg)
        assert msghash == bytes.fromhex("5255683da567900bfd3e786ed8836a4e7763c221bf1ac20ece2a5171b9199e8a")

        sig = schnorr.sign(privkey, msghash)
        assert sig == bytes.fromhex("2c56731ac2f7a7e7f11518fc7722a166b02438924ca9d8b4d111347b81d0717571846de67ad3d913a8fdf9d8f3f73161a4c48ae81cb183b214765feb86e255ce")
        sig2 = libnexa.SignHashSchnorr(privkey, msghash)
        assert sig2 == sig

        logging.info("random Schnorr signature comparison")
        # Next try random signatures
        for i in range(1, 1000):
            privkey = libnexa.randombytes(32)
            pubkey = schnorr.getpubkey(privkey, compressed=True)
            pubkey2 = libnexa.pubkey(privkey)
            assert pubkey == pubkey2

            msg = libnexa.randombytes(random.randint(0, 10000))
            hsh = libnexa.hash256(msg)

            sigpy = schnorr.sign(privkey, hsh)
            siglibnexa = libnexa.SignHashSchnorr(privkey, hsh)
            assert sigpy == siglibnexa

    def negativeTests(self):
        n = self.nodes[0]
        wallet = n.listunspent()
        inp = wallet[0]
        privb58 = n.dumpprivkey(inp["address"])
        privkey = decodeBase58(privb58)[1:-5]
        pubkey = libnexa.pubkey(privkey)

        destPrivKey = libnexa.randombytes(32)
        destPubKey = libnexa.pubkey(destPrivKey)
        destHash = libnexa.addrbin(destPubKey)
        constraint = CScript([OP_DUP, OP_HASH160, destHash, OP_EQUALVERIFY, OP_CHECKSIG])

        for amt in [inp['amount']-decimal.Decimal(0.00001), inp['amount']+decimal.Decimal(0.0000001)]:
            tx = CTransaction()
            # Amount too small
            amt = inp['amount']-decimal.Decimal(0.00001)
            tx.vin.append(CTxIn(COutPoint(inp["outpoint"]), amt, b"", 0xffffffff))
            tx.vout.append(CTxOut(amt, constraint))
            sighashtype = SIGHASH_ALL
            idx = 0
            for i, priv in zip([inp], [privkey]):
                sig = libnexa.signTxInputSchnorr(tx, idx, i["amount"], i["scriptPubKey"], priv, sighashtype)
                tx.vin[idx].scriptSig = libnexa.spendscript(sig)  # P2PK
                idx += 1
            result = n.validaterawtransaction(tx.toHex())
            assert result['inputs_flags']['isValid'] == False, "amount is incorrect"
            assert "input-amount-mismatch" in result['inputs_flags']['inputs'][0]['errors'][0]
            expectException(lambda: n.sendrawtransaction(tx.toHex()), JSONRPCException,'input-amount-mismatch')

        # Build a bad block with tx with bad amounts
        height = self.nodes[0].getblockcount()
        nextheight = height + 1
        tip = int(self.nodes[0].getblockhash(height), 16)
        tipHdr = self.nodes[0].getblock(height)
        work = int(tipHdr["chainwork"],16) + 2
        coinbase = create_coinbase(nextheight)
        blkTime = max(tipHdr["time"],int(time.time()))

        block = create_block(tip, nextheight, work, coinbase, getAncHash(nextheight, self.nodes[0]), blkTime+1, [tx])
        block.rehash()
        hexblk = ToHex(block)
        expectException(lambda: n.validateblocktemplate(hexblk), JSONRPCException,'bad-txns-input-amount-mismatch')

    def testSignChildFirst(self):
        """This test creates a parent and child tranaction.  It then signs the child and posts it to the node, without signing the parent.
           The child will end up in the orphan pool of the node.  It then signs the parent and posts it, verifying that both transactions
           enter the mempool.
        """
        n = self.nodes[0]
        # get a traditional P2PKH
        addr = n.getnewaddress("p2pkh")
        n.sendtoaddress(addr, 1000000)
        n.generate(1)
        wallet = n.listunspent()
        wallet = filter(lambda x: x['scriptType'] != 'template', wallet)
        inp = list(wallet)[0]
        privb58 = n.dumpprivkey(inp["address"])
        privkey = decodeBase58(privb58)[1:-5]
        pubkey = libnexa.pubkey(privkey)

        destPrivKey = libnexa.randombytes(32)
        destPubKey = libnexa.pubkey(destPrivKey)
        destHash = libnexa.addrbin(destPubKey)
        constraint = CScript([OP_DUP, OP_HASH160, destHash, OP_EQUALVERIFY, OP_CHECKSIG])

        fee = decimal.Decimal("2")
        # construct parent tx
        txp = CTransaction()
        amt = inp['amount']
        txp.vin.append(CTxIn(COutPoint(inp["outpoint"]), amt, b"", 0xffffffff))
        txp.vout.append(CTxOut(amt-fee, constraint))

        # construct child tx
        txc = CTransaction()
        txc.vin.append(txp.SpendOutput(0))
        txc.vout.append(CTxOut(decimal.Decimal(txc.vin[0].amount)/COIN-fee, constraint))

        # sign child tx
        sighashtype = SIGHASH_ALL
        sig = libnexa.signTxInputSchnorr(txc, 0, txc.vin[0].amount, constraint, destPrivKey, sighashtype)
        txc.vin[0].scriptSig = CScript([sig, destPubKey])  # P2PKH
        result = n.validaterawtransaction(txc.toHex())
        assert("inputs-are-missing" in result["errors"])
        n.enqueuerawtransaction(txc.toHex())
        waitFor(10,lambda: n.getorphanpoolinfo()['size'] == 1)

        # sign and post parent tx
        sig = libnexa.signTxInputSchnorr(txp, 0, txp.vin[0].amount, inp["scriptPubKey"], privkey, sighashtype)
        txp.vin[0].scriptSig = CScript([sig, pubkey])  # P2PKH
        # txp.vin[0].scriptSig = CScript([sig])  # P2PK
        n.sendrawtransaction(txp.toHex())
        # The child orphan should have been added to the mempool
        waitFor(10, lambda: n.getorphanpoolinfo()['size'] == 0)
        waitFor(10, lambda: n.gettxpoolinfo()['size'] == 2)
        mp = n.getrawtxpool()
        assert txp.GetRpcHexIdem() in mp
        assert txc.GetRpcHexIdem() in mp
        n.generate(1) # Clean up txs



    def run_test(self):
        self.basicSchnorrSigning()

        self.nodes[0].generate(15)
        self.sync_blocks()
        self.nodes[1].generate(15)
        self.sync_blocks()
        self.nodes[2].generate(15)
        self.sync_blocks()
        self.nodes[0].generate(100)
        self.sync_blocks()

        self.negativeTests()

        self.testSignChildFirst()

        logging.info("Schnorr signature transaction generation and commitment")

        # Make some P2PKH outputs because this test uses them for legacy reasons
        for n in self.nodes:
            for i in range(0,10):
                addr = n.getnewaddress("p2pkh")
                n.sendtoaddress(addr, 1000000)
            n.generate(1)
            self.sync_blocks()


        resultWallet = []
        alltx = []

        wallets = [list(filter(lambda x: x['scriptType'] != 'template',self.nodes[0].listunspent())),
                   list(filter(lambda x: x['scriptType'] != 'template',self.nodes[1].listunspent()))]
        for txcount in range(0, 2):
            inputs = [x[0] for x in wallets]
            for x in wallets:  # Remove this utxo so we don't use it in the next time around
                del x[0]
            privb58 = [self.nodes[0].dumpprivkey(inputs[0]["address"]), self.nodes[1].dumpprivkey(inputs[1]["address"])]

            privkeys = [decodeBase58(x)[1:-5] for x in privb58]
            pubkeys = [libnexa.pubkey(x) for x in privkeys]

            for doubleSpend in range(0, 2):  # Double spend this many times
                tx = CTransaction()
                for i in inputs:
                    tx.vin.append(CTxIn(COutPoint(i["outpoint"]), i['amount'], b"", 0xffffffff-doubleSpend))  # subtracting doubleSpend changes the tx slightly

                destPrivKey = libnexa.randombytes(32)
                destPubKey = libnexa.pubkey(destPrivKey)
                destHash = libnexa.addrbin(destPubKey)

                output = CScript([OP_DUP, OP_HASH160, destHash, OP_EQUALVERIFY, OP_CHECKSIG])

                amt = int(sum([x["amount"] for x in inputs]) * libnexa.NEX)
                tx.vout.append(CTxOut(amt, output))

                sighashtype = SIGHASH_ALL
                n = 0
                for i, priv, pub in zip(inputs, privkeys, pubkeys):
                    sig = libnexa.signTxInputSchnorr(tx, n, i["amount"], i["scriptPubKey"], priv, sighashtype)
                    tx.vin[n].scriptSig = libnexa.spendscript(sig, pub)  # P2PKH
                    n += 1

                txhex = hexlify(tx.serialize()).decode("utf-8")
                txid = self.nodes[0].enqueuerawtransaction(txhex)

        # because enqueuerawtransaction and propagation is asynchronous we need to wait for it
        waitFor(30, lambda: self.nodes[1].gettxpoolinfo()['size'] == txcount+1)
        mp = [i.gettxpoolinfo() for i in self.nodes]
        assert txcount+1 == mp[0]['size'] == mp[1]['size']

        nonSchnorrBlkHash = self.nodes[0].getbestblockhash()
        self.nodes[0].generate(1)

        assert self.nodes[0].gettxpoolinfo()['size'] == 0
        waitFor(30, lambda: self.nodes[0].getbestblockhash() == self.nodes[1].getbestblockhash())

        # Since we doublespent the above txs, we can't be sure which succeeded (we'd have to check the blocks)
        # Instead just grab new ones from a node's wallet
        wallets = list(filter(lambda x: x['scriptType'] != 'template', self.nodes[0].listunspent()))
        resultWallet = []
        for i in wallets:
            privb58 = self.nodes[0].dumpprivkey(i["address"])
            privKey = decodeBase58(privb58)[1:-5]
            pubKey = libnexa.pubkey(privKey)
            resultWallet.append([privKey, pubKey, i["satoshi"], PlaceHolder(i['txidem']), i["vout"], i['amount'], CScript(i["scriptPubKey"])])

        FEEINSAT = 5000
        # now spend all the new utxos again
        for spendLoop in range(0, 2):
            incomingWallet = resultWallet
            resultWallet = []

            logging.info("spend iteration %d, num transactions %d" % (spendLoop, len(incomingWallet)))
            for w in incomingWallet:
                txidHolder = PlaceHolder()
                tx = CTransaction()
                tx.vin.append(CTxIn(COutPoint().fromIdemAndIdx(w[3].data, w[4]), w[5], b"", 0xffffffff))

                NOUTS = 10 - spendLoop*2
                if NOUTS < 0:
                    NOUTS = 1
                amtPerOut = int((w[2]-FEEINSAT)/NOUTS)
                for outIdx in range(0, NOUTS):
                    destPrivKey = libnexa.randombytes(32)
                    destPubKey = libnexa.pubkey(destPrivKey)
                    destHash = libnexa.addrbin(destPubKey)
                    output = CScript([OP_DUP, OP_HASH160, destHash, OP_EQUALVERIFY, OP_CHECKSIG])
                    tx.vout.append(CTxOut(amtPerOut, output))
                    resultWallet.append([destPrivKey, destPubKey, amtPerOut, txidHolder, outIdx, amtPerOut, output])

                n = 0
                sig = libnexa.signTxInputSchnorr(tx, n, w[2], w[6], w[0])
                # In this test we only have P2PK or P2PKH type constraint scripts so the length can be used to distinguish them
                if len(w[6]) == 35:
                    tx.vin[n].scriptSig = libnexa.spendscript(sig)  # P2PK
                else:
                    tx.vin[n].scriptSig = libnexa.spendscript(sig, w[1])  # P2PKH

                txhex = hexlify(tx.serialize()).decode("utf-8")
                txid = self.nodes[1].enqueuerawtransaction(txhex)
                alltx.append(txhex)
                txidHolder.data = txid

            # because enqueuerawtransaction and propagation is asynchronous we need to wait for it
            waitFor(30, lambda: self.nodes[0].gettxpoolinfo()['size'] == len(incomingWallet))
            while self.nodes[0].gettxpoolinfo()['size'] != 0:
                self.nodes[0].generate(1)
            waitFor(30, lambda: self.nodes[0].getbestblockhash() == self.nodes[1].getbestblockhash())

if __name__ == '__main__':
    binpath = findBitcoind()
    try:
        libnexa.init(binpath + os.sep + ".libs" + os.sep + "libbitcoincash.so")
        SchnorrSigTest().main()
    except OSError as e:
        p = platform.platform()
        if "Linux" in p and "x86-64" in p: raise  # libnexa should be properly created on this platform
        print("Issue loading libnexa shared library.  This is expected during cross compilation since the native python will not load the .so so no error will be reported: %s" % str(e))


# Create a convenient function for an interactive python debugging session
def Test():
    t = SchnorrSigTest()
    t.drop_to_pdb = True
    bitcoinConf = {
        "debug": ["net", "blk", "thin", "req", "bench", "evict"],
    }

    flags = []  # ["--nocleanup", "--noshutdown"]
    if os.path.isdir("/ramdisk/test/t"):
        flags.append("--tmpdir=/ramdisk/test/t")
    binpath = findBitcoind()
    flags.append("--srcdir=%s" % binpath)
    libnexa.init(binpath + os.sep + ".libs" + os.sep + "libnexa.so")

    t.main(flags, bitcoinConf, None)
