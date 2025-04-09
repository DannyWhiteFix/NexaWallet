#!/usr/bin/env python3
# Copyright (c) 2019 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
This tests the MINIMALDATA consensus rule.
- test rejection in mempool, with error changing before/after activation.
- test acceptance in blocks before activation, and rejection after.
- check non-banning for peers who send invalid txns that would have been valid
on the other side of the upgrade.
"""
import pdb

from test_framework.mininode import (
        NodeConn, NetworkThread, P2PDataStore
)
from test_framework.blocktools import (
    create_block,
    create_coinbase,
    create_transaction,
    make_conform_to_ctor,
    pad_tx,
    getAncHash,
    ancestorHeight
)
from test_framework.nodemessages import (
    CBlock,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
    FromHex,
    ToHex,
    anySpender
)

from test_framework.script import (
    CScript,
    OP_ADD,
    OP_TRUE,
    OP_EQUALVERIFY,
    OP_1,
    OP_2,
    spendAnyoneCanSpend
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_raises_rpc_error, p2p_port, waitFor, standardFlags
import logging

# this is the errror you get when minimal push errors are detected during mempool admission
MINIMALPUSH_ERROR = 'mandatory-script-verify-flag-failed (Data push larger than necessary)'

# Blocks with invalid scripts give this error:
BADSIGNATURE_ERROR = 'bad-blk-signatures'


def rpc_error(*, reject_code, reject_reason):
    # RPC indicates rejected items in a slightly different way than p2p.
    return '{:s} (code {:d})'.format(reject_reason.decode(), reject_code)


class P2PNode(P2PDataStore):
    pass

class MinimaldataTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.set_test_params()
        self.block_hashes = {}

    def set_test_params(self):
        self.num_nodes = 1
        self.block_heights = {}
        self.extra_args = [["-debug=mempool"]]

    def bootstrap_p2p(self):
        """Add a P2P connection to the node.

        Helper to connect and wait for version handshake."""
        self.p2p = P2PNode()
        self.connection = NodeConn('127.0.0.1', p2p_port(0), self.nodes[0], self.p2p)
        self.p2p.add_connection(self.connection)
        NetworkThread().start()
        self.p2p.wait_for_verack()
        assert(self.p2p.connection.state == "connected")

    def getbestblock(self, node):
        """Get the best block. Register its height so we can use build_block."""
        block_height = node.getblockcount()
        blockhash = node.getblockhash(block_height)
        block = FromHex(CBlock(), node.getblock(blockhash, 0))
        self.block_heights[block.gethash()] = block_height
        return block

    def build_block(self, parent, transactions=(), nTime=None):
        """Make a new block with an OP_1 coinbase output.

        Requires parent to have its height registered."""
        parent.rehash()
        block_height = self.block_heights[parent.gethash()] + 1
        block_time = (parent.nTime + 1) if nTime is None else nTime

        ancHeight = ancestorHeight(block_height)
        ancHash = self.block_hashes.get(ancHeight, None)
        if ancHash is None: ancHash = getAncHash(block_height, self.nodes[0])
        block = create_block(
            parent.gethash(), block_height, parent.chainWork + 2,create_coinbase(block_height), ancHash, block_time)
        block.vtx.extend(transactions)
        make_conform_to_ctor(block)
        block.update_fields()
        block.solve()
        self.block_heights[block.gethash()] = block_height
        self.block_hashes[block_height] = block.gethash()
        return block

    def check_for_ban_on_rejected_tx(self, tx, reject_reason=None):
        """Check we trigger a ban when sending a txn that the node rejects."""
        self.p2p.send_txs_and_test(
            [tx], self.nodes[0], success=False, expect_ban=True, reject_reason=reject_reason)

    def check_for_ban_on_rejected_block(self, block, reject_reason=None):
        """Check we trigger a ban when sending a block that the node rejects.
        (Can't actually get banned, since bitcoind won't ban local peers.)"""
        self.p2p.send_blocks_and_test(
            [block], self.nodes[0], success=False, expect_ban=True, reject_reason=reject_reason, timeout=15)

    def run_test(self):
        node = self.nodes[0]
        node.generate(1)

        self.bootstrap_p2p()

        tip = self.getbestblock(node)

        logging.info("Create some blocks with coinbase for spending.")
        blocks = []
        for _ in range(10):
            tip = self.build_block(tip)
            blocks.append(tip)
        self.p2p.send_blocks_and_test(blocks, node, success=True)
        spendable_outputs = [block.vtx[0] for block in blocks]

        logging.info("Mature the blocks and get out of IBD.")
        node.generate(100)

        tip = self.getbestblock(node)

        logging.info("Setting up spends to test and mining the fundings.")
        fundings = []

        def create_fund_and_spend_tx():
            spendfrom = spendable_outputs.pop()

            script = CScript([OP_ADD, OP_2, OP_EQUALVERIFY])

            value = spendfrom.vout[0].nValue

            # Fund transaction
            txfund = create_transaction(spendfrom, 0, spendAnyoneCanSpend(), value, script)
            # pad_tx(txfund)
            txfund.rehash()
            fundings.append(txfund)

            # Spend transaction
            txspend = CTransaction()
            txspend.vout.append(anySpender(value-1000))

            txspend.vin.append(txfund.SpendTemplate(0, script, None, CScript(b'\x01\x01\x51')  ))  # PUSH1(0x01) OP_1  (PUSH1 is not minimaldata)
            pad_tx(txspend)
            txspend.rehash()

            return txspend

        # no minimal tx are invalid
        nonminimaltx = create_fund_and_spend_tx()

        tip = self.build_block(tip, fundings)
        self.p2p.send_blocks_and_test([tip], node)

        logging.info("Trying to mine a minimaldata violation")
        self.check_for_ban_on_rejected_block(
            self.build_block(tip, [nonminimaltx]), BADSIGNATURE_ERROR)
        logging.info("If we try to submit it by mempool or RPC we are banned")
        assert_raises_rpc_error(-26, MINIMALPUSH_ERROR, node.sendrawtransaction, ToHex(nonminimaltx))
        self.check_for_ban_on_rejected_tx(nonminimaltx, MINIMALPUSH_ERROR)

        logging.info("Mine a normal block")
        tip = self.build_block(tip)
        self.p2p.send_blocks_and_test([tip], node)

if __name__ == '__main__':
    MinimaldataTest().main()

# Create a convenient function for an interactive python debugging session
def Test():
    t = MinimaldataTest()
    t.drop_to_pdb = True
    logging.getLogger().setLevel(logging.INFO)
    bitcoinConf = {
        "debug": ["blk", "mempool", "net", "req"],
    }
    flags = standardFlags()
    t.main(flags, bitcoinConf, None)
