#!/usr/bin/env python3
# Copyright (c) 2015-2023 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# This test verifies blockchain consensus (no permanent forks) and no crashes under extreme read-only use conditions
# that is meant to simulate but accelerate real scenarios.

# It creates highly connected transactions, with up to 10 read-only and consumed inputs, and up to 10 outputs.
# These transactions are issued on all nodes and mining occurs on all nodes without waiting for transaction
# sync.  This means that nodes need to deal with common transaction txpool scenarios that do not occur in more controlled
# tests such as:
# Transactions that appear in blocks when the transaction is in any location in the acceptance pipeline, from queues to the txpool.
# Natural forks
# Orphaned blocks and transactions

# This test does not check for correct read-only semantics, it checks for consistent semantics and crash-free operation.
# Correct semantics are tested in the unit tests and in readonlyinputs.py.


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

MAX_RO_INPUTS=10
MAX_INPUTS=10

ITERS=200
verbose = False

def fundSignSendParse(node, tx, verbose = False):
    h = tx.toHex()
    if verbose:
        logging.info("Input TX: " + h)
        logging.info("Decoded: " + pprint.pformat(node.decoderawtransaction(h)))
    frtReturn = node.fundrawtransaction(h)
    sgnReturn = node.signrawtransaction(frtReturn["hex"])
    if verbose:
        logging.info("Funded TX: " + str(sgnReturn))
        logging.info("Decoded: " + pprint.pformat(node.decoderawtransaction(sgnReturn["hex"])))
    fundedTx = CTransaction().fromHex(sgnReturn["hex"])
    v = node.validaterawtransaction(sgnReturn["hex"])
    if verbose:
        logging.info(pprint.pformat(v))
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
    NUM_NODES = 4
    def setup_chain(self,bitcoinConfDict=None, wallets=None):
        libnexa.loadLibNexaOrExit(self.options.srcdir)
        logging.info("Initializing test directory "+self.options.tmpdir)
        initialize_chain_clean(self.options.tmpdir, self.NUM_NODES, self.confDict)
        # initialize_chain(self.options.tmpdir, bitcoinConfDict, wallets)

    def setup_network(self):
        self.nodes = []
        self.is_network_split = False
        for i in range(0, self.NUM_NODES):
            self.nodes.append(start_node(i, self.options.tmpdir, []))
        interconnect_nodes(self.nodes)


    def testReadOnlyRandom(self):
        NEWBLOCK = 0.20
        SEND = 0.75
        SEND_WITH_RO = 0.30
        CHECK_SYNC = 0.02
        STATS = 0.70
        addrs = []
        allAddrs = []
        global verbose
        # Prep a bunch of addresses
        for i in self.nodes:
            nodeAddrs = []
            for j in range(0,10):
                nodeAddrs.append(i.getnewaddress())
            addrs.append(nodeAddrs)
            allAddrs += nodeAddrs

        for stepnum in range(0, ITERS):
            if random.uniform(0,1) < STATS:
                balances = [n.getbalance() for n in self.nodes]
                for n in self.nodes:
                    n.getinfo()
                logging.info([str(x) for x in balances])
                if verbose:
                    logging.info("Step %d: Stats" % stepnum)
                    logging.info("  TX POOL")
                    for n in self.nodes:
                        logging.info(pprint.pformat(n.gettxpoolinfo()))
                    logging.info("  NODE")
                    for n in self.nodes:
                        logging.info(pprint.pformat(balances))
                        logging.info(pprint.pformat(n.getinfo()))

            if random.uniform(0,1) < CHECK_SYNC:  # Make sure no permanent forks have happened
                logging.info("Step %d: Sync blocks" % stepnum)
                sync_blocks(self.nodes)
            if random.uniform(0,1) < NEWBLOCK:
                nodeIdx = random.randrange(0,len(self.nodes))
                node = self.nodes[nodeIdx]
                try:
                    blk = node.generate(1)[0]
                    logging.info("Step %d: Generated block %s on node %d" % (stepnum, blk, nodeIdx))
                except JSONRPCException as e:
                    logging.error(e)
                    logging.error("Step %d: Failed attempt to generate block from node %d" % (stepnum, nodeIdx))
                    txpool = node.gettxpoolinfo()
                    logging.error(txpool)
                    rawtxpool = node.getrawtxpool()
                    logging.error(rawtxpool)
                    # pdb.set_trace()
                    raise e
            if random.uniform(0,1) < SEND:
                node = random.choice(self.nodes)
                avail = int(node.getbalance()*100)
                if avail > 10000:
                    amt = random.randint(10000, min(10000000, avail) )
                    addr = random.choice(allAddrs)
                    try:
                        txidem = node.sendtoaddress(addr, amt/100)
                        logging.info("Step %d: Sending %d to %s txidem: %s" % (stepnum, amt/100, addr, txidem))
                    except JSONRPCException as e:  # probably benign: out of coins
                        logging.info("  sendtoaddress failed with error %s" % str(e))

            if random.uniform(0,1) < SEND_WITH_RO:
                logging.info("Step %d: RO send" % stepnum)
                while True:  # Not really just want to break
                    ronode = random.choice(self.nodes)
                    rochoices = ronode.listunspent()
                    if len(rochoices) == 0:
                        logging.info("  RO send aborted, node has no unspents")
                        break
                    tx = CTransaction()
                    # Fill with read only
                    for i in range(0,random.randint(0,MAX_RO_INPUTS)):
                        if len(rochoices) == 0:
                            break
                        inputIdx = random.randrange(0, len(rochoices))
                        anInput = rochoices[inputIdx]
                        roTxIn = CTxIn().fromRpcUtxo(anInput)
                        roTxIn.t = CTxIn.READONLY
                        roTxIn.amount = 0
                        tx.vin.append(roTxIn)
                        del rochoices[inputIdx]

                    # Now grab some consumed inputs
                    nodeIdx = random.randrange(0,len(self.nodes))
                    node = self.nodes[nodeIdx]
                    if node == ronode:  # because we cant reuse an input
                        nodeUnspent = rochoices
                    else:
                        nodeUnspent = node.listunspent()
                    if len(nodeUnspent) == 0:
                        logging.info("  RO send aborted, node needs outpoints to spend")
                        break
                    totalSpent = 0
                    spentOutpoint = None  # Remember one spent outpoint
                    for i in range(0,MAX_INPUTS): # random.randint(0,10)):
                        if len(nodeUnspent) == 0:
                            break
                        uIdx = random.randrange(0,len(nodeUnspent))
                        txIn = CTxIn().fromRpcUtxo(nodeUnspent[uIdx])
                        totalSpent += nodeUnspent[uIdx]["satoshi"]
                        if spentOutpoint is None: spentOutpoint = nodeUnspent[uIdx]["outpoint"]
                        del nodeUnspent[uIdx]
                        tx.vin.append(txIn)
                    if totalSpent < 2000:  # Not enough to bother
                        break

                    random.shuffle(tx.vin)

                    # Make a couple of outputs
                    for i in range(0,random.randint(0,3)):
                        if totalSpent <= 1000: break
                        out = CTxOut()
                        addr = random.choice(addrs[nodeIdx])
                        out.t = TxOut.TYPE_TEMPLATE
                        out.nValue = random.randint(1,totalSpent-900)
                        out.scriptPubKey = libnexa.addressToBin(addr)
                        tx.vout.append(out)
                        totalSpent -= out.nValue

                    if totalSpent > 2000:  # Spend the rest not counting change
                        out = CTxOut()
                        addr = random.choice(addrs[nodeIdx])
                        out.t = TxOut.TYPE_TEMPLATE
                        out.nValue = totalSpent-1000
                        out.scriptPubKey = libnexa.addressToBin(addr)
                        tx.vout.append(out)

                    sgnReturn = node.signrawtransaction(tx.toHex())
                    dcd = node.decoderawtransaction(sgnReturn["hex"])
                    vld = node.validaterawtransaction(sgnReturn["hex"])
                    if verbose:
                        logging.info("  Sending using %d:\n%s" % (nodeIdx, pprint.pformat(dcd)))
                    totalUnspent = len(node.listunspent())
                    txidem = None
                    try:
                        txidem = node.sendrawtransaction(sgnReturn["hex"])
                        # waitFor(30, lambda: totalUnspent != len(node.listunspent()))  # wait for some to be used
                        waitFor(30, lambda: not spentOutpoint in [x['outpoint'] for x in node.listunspent()])  # wait for some to be used
                    except JSONRPCException as e:
                        # if verbose:
                        logging.info("Exception sending: %s TX validation:\n%s" % (str(e), pprint.pformat(vld)))

                    # this isn't right, I'd need to see if unspent tx disappear not appear!
                    #logging.info("Sync %s" % txidem)
                    # sync_wallet_with_unconf_txidem(30000, node, txidem)

                    # I could relay it to a random node, but that node would not process its own tx right away
                    # meaning that later I could reuse the inputs so I'd have to be tolerant of that
                    # txid = random.choice(self.nodes).sendrawtransaction(sgnReturn["hex"])

                    logging.info("  Sent txidem: %s" % txidem)
                    break




    def genBlock(self, node):
        blkhash = node.generate(1)[0]
        blkhdr = node.getblock(blkhash)
        logging.info("Generated: %d:%s with %d tx nonCB: %s" % (blkhdr["height"], blkhash, blkhdr["txcount"], blkhdr["txidem"][1:]))
        return blkhash

    def run_test(self):
        miningNode = self.nodes[1]
        # Mine some blocks to get utxos etc
        miningNode.generate(1)
        # Activate the hard fork
        bestblock = miningNode.getbestblockhash()
        lastblocktime = miningNode.getblockheader(bestblock)['time']
        activationtime = lastblocktime - 2000
        for n in self.nodes:
            n.set("consensus.fork1Time=" + str(activationtime))

        for n in self.nodes:
            n.generate(int(60/len(self.nodes)))
            sync_blocks(self.nodes)
        for n in self.nodes:
            n.generate(int(120/len(self.nodes)))
            sync_blocks(self.nodes)

        self.testReadOnlyRandom()



if __name__ == '__main__':
    RoTest().main()
    exit(0)

def Test():
    for i in range(0,100): OneTest()
    
    
def OneTest():
    global ITERS
    ITERS=500
    t = RoTest()
    t.drop_to_pdb = True
    bitcoinConf = {
        "par": 1,
        "txindex":1,
        "debug": ["all","-libevent"]
        # "debug": ["validation", "rpc", "net", "blk", "thin", "mempool", "req", "bench", "evict"],
    }
    flags = standardFlags()
    flags[0] = '--tmpdir=/ramdisk/test/t1'
    t.main(flags, bitcoinConf, None)
