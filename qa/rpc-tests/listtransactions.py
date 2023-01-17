#!/usr/bin/env python3
# Copyright (c) 2014-2015 The Bitcoin Core developers
# Copyright (c) 2015-2022 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
import test_framework.loginit
# Exercise the listtransactions API
import pdb
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from test_framework.mininode import CTransaction, COIN
from io import BytesIO


def txFromHex(hexstring):
    return CTransaction().deserialize(hexstring)


class ListTransactionsTest(BitcoinTestFramework):

    def setup_nodes(self):
        enable_mocktime()
        return start_nodes(4, self.options.tmpdir)

    def run_test(self):
        self.test_listtransactionsfrom()
        self.test_listtransactions()

    def test_listtransactionsfrom(self):
        # Simple send, 0 to 1:
        self.sync_all()
        tmp = self.nodes[2].listtransactionsfrom("*", 10000, 0)
        curpos = len(tmp)
        txid = self.nodes[2].sendtoaddress(self.nodes[3].getnewaddress(), 100000)
        self.sync_all()
        self.nodes[0].generate(1)
        self.sync_blocks()

        # Basic positive test
        tmp = self.nodes[2].listtransactionsfrom("*", 1, curpos)
        assert len(tmp) == 1
        assert tmp[0]["txidem"] == txid

        tmp = self.nodes[2].listtransactionsfrom("*", 10, curpos)
        assert len(tmp) == 1

        # Negative tests
        # test beyond end of tx list
        tmp = self.nodes[2].listtransactionsfrom("*", 100, curpos + 100)
        assert(len(tmp) == 0)

        # test bad input values
        try:
            tmp = self.nodes[2].listtransactionsfrom("*", -1, curpos)
            assert 0
        except JSONRPCException:
            pass
        try:
            tmp = self.nodes[2].listtransactionsfrom("*", 100, -1)
            assert 0
        except JSONRPCException:
            pass

        # test multiple rows
        curpos += 1

        txidsA = [self.nodes[2].sendtoaddress(self.nodes[3].getnewaddress(), 200000), self.nodes[2].sendtoaddress(
            self.nodes[3].getnewaddress(), 300000), self.nodes[2].sendtoaddress(self.nodes[3].getnewaddress(), 400000)]
        self.sync_all()
        self.nodes[0].generate(1)
        self.sync_blocks()

        tmp = self.nodes[2].listtransactionsfrom("*", 100, curpos)
        assert len(tmp) == 3
        assert tmp[0]["txidem"] == txidsA[0]
        assert tmp[1]["txidem"] == txidsA[1]
        assert tmp[2]["txidem"] == txidsA[2]

        txidsB = [self.nodes[2].sendtoaddress(self.nodes[3].getnewaddress(), 500000), self.nodes[2].sendtoaddress(
            self.nodes[3].getnewaddress(), 600000), self.nodes[2].sendtoaddress(self.nodes[3].getnewaddress(), 700000)]

        tmp = self.nodes[2].listtransactionsfrom("*", 100, curpos)
        assert len(tmp) == 6
        assert tmp[0]["txidem"] == txidsA[0]
        assert tmp[1]["txidem"] == txidsA[1]
        assert tmp[2]["txidem"] == txidsA[2]
        assert tmp[3]["txidem"] == txidsB[0]
        assert tmp[4]["txidem"] == txidsB[1]
        assert tmp[5]["txidem"] == txidsB[2]

        # test when I advance to the end, I get nothing
        curpos += len(tmp)
        tmp = self.nodes[2].listtransactionsfrom("*", 100, curpos)
        assert tmp == []

    def test_listtransactions(self):
        # Simple send, 0 to 1:
        txid = self.nodes[0].sendtoaddress(self.nodes[1].getnewaddress(), 100000)
        self.sync_all()
        assert_array_result(self.nodes[0].listtransactions(),
                            {"txidem": txid},
                            {"category": "send", "account": "", "amount": Decimal("-100000"), "confirmations": 0})
        assert_array_result(self.nodes[1].listtransactions(),
                            {"txidem": txid},
                            {"category": "receive", "account": "", "amount": Decimal("100000"), "confirmations": 0})
        # mine a block, confirmations should change:
        self.nodes[0].generate(1)
        self.sync_blocks()
        assert_array_result(self.nodes[0].listtransactions(),
                            {"txidem": txid},
                            {"category": "send", "account": "", "amount": Decimal("-100000"), "confirmations": 1})
        assert_array_result(self.nodes[1].listtransactions(),
                            {"txidem": txid},
                            {"category": "receive", "account": "", "amount": Decimal("100000"), "confirmations": 1})

        # send-to-self:
        txid = self.nodes[0].sendtoaddress(self.nodes[0].getnewaddress(), 200000)
        assert_array_result(self.nodes[0].listtransactions(),
                            {"txidem": txid, "category": "send"},
                            {"amount": Decimal("-200000")})
        assert_array_result(self.nodes[0].listtransactions(),
                            {"txidem": txid, "category": "receive"},
                            {"amount": Decimal("200000")})

        # sendmany from node1: twice to self, twice to node2:
        send_to = {self.nodes[0].getnewaddress(): 110000.11,
                   self.nodes[1].getnewaddress(): 220000.22,
                   self.nodes[0].getaccountaddress("from1"): 330000.33,
                   self.nodes[1].getaccountaddress("toself"): 440000.44}
        txid = self.nodes[1].sendmany("", send_to)
        self.sync_all()
        assert_array_result(self.nodes[1].listtransactions(),
                            {"category": "send", "amount": Decimal("-110000.11")},
                            {"txidem": txid})
        assert_array_result(self.nodes[0].listtransactions(),
                            {"category": "receive", "amount": Decimal("110000.11")},
                            {"txidem": txid})
        assert_array_result(self.nodes[1].listtransactions(),
                            {"category": "send", "amount": Decimal("-220000.22")},
                            {"txidem": txid})
        assert_array_result(self.nodes[1].listtransactions(),
                            {"category": "receive", "amount": Decimal("220000.22")},
                            {"txidem": txid})
        assert_array_result(self.nodes[1].listtransactions(),
                            {"category": "send", "amount": Decimal("-330000.33")},
                            {"txidem": txid})
        assert_array_result(self.nodes[0].listtransactions(),
                            {"category": "receive", "amount": Decimal("330000.33")},
                            {"txidem": txid, "account": "from1"})
        assert_array_result(self.nodes[1].listtransactions(),
                            {"category": "send", "amount": Decimal("-440000.44")},
                            {"txidem": txid, "account": ""})
        assert_array_result(self.nodes[1].listtransactions(),
                            {"category": "receive", "amount": Decimal("440000.44")},
                            {"txidem": txid, "account": "toself"})

        multisig = self.nodes[1].createmultisig(1, [self.nodes[1].getnewaddress("p2pkh")])
        self.nodes[0].importaddress(multisig["redeemScript"], "watchonly", False, True)
        txid = self.nodes[1].sendtoaddress(multisig["address"], 100000)
        self.nodes[1].generate(1)
        self.sync_blocks()
        assert(len(self.nodes[0].listtransactions("watchonly", 100, 0, False)) == 0)
        assert_array_result(self.nodes[0].listtransactions("watchonly", 100, 0, True),
                            {"category": "receive", "amount": Decimal("100000")},
                            {"txidem": txid, "account": "watchonly"})


if __name__ == '__main__':
    ListTransactionsTest().main(None, {
        "debug": ["all"],
    })


def Test():
    t = ListTransactionsTest()
    t.drop_to_pdb = True
    bitcoinConf = {
        "debug": ["all","-libevent"],
    }
    flags = standardFlags()
    # flags.append("--tmpdir=/tmp/test")
    t.main(flags, bitcoinConf, None)
