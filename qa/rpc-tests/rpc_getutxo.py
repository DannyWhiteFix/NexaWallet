#!/usr/bin/env python3
# Copyright (c) 2025 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test for the getutxo RPC methods."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *

class RPCGetUtxoTest(BitcoinTestFramework):

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def run_test(self):
        self._test_getutxo()

    def _test_getutxo(self):
        self.nodes[0].generate(101)
        self.sync_all()

        # Test a non-existent utxo
        outpoint = "f6501b509257617a37606ceb340e120a01f5516ee8534d1246e693835bb7f939"
        assert_equal(self.nodes[0].getutxo(outpoint)[0]["outpoint"], "f6501b509257617a37606ceb340e120a01f5516ee8534d1246e693835bb7f939");
        assert_equal(self.nodes[0].getutxo(outpoint)[0]["exists"], False);

        # Test a utxo that is a coinbase
        waitFor(60, lambda: len(self.nodes[0].listunspent()) == 1)
        list = self.nodes[0].listunspent();
        saved_outpoint_1 = list[0]['outpoint'];
        getutxo = self.nodes[0].getutxo(saved_outpoint_1)
        assert_equal(getutxo[0]["outpoint"], saved_outpoint_1);
        assert_equal(getutxo[0]["height"], 1);
        assert_equal(getutxo[0]["intxpool"], False);
        assert_equal(getutxo[0]["spent"], False);
        assert_equal(getutxo[0]["exists"], True);

        #### Test a utxo that is in the mempool only
        subtractfeefromamount = False
        self.nodes[0].sendtoaddress(self.nodes[0].getnewaddress(), 1000000, "", "", subtractfeefromamount)
        waitFor(60, lambda: len(self.nodes[0].listunspent(0,1)) == 2)
        list = self.nodes[0].listunspent(0,1);

        # the confirmed coinbase should have been spent
        getutxo = self.nodes[0].getutxo(saved_outpoint_1)
        assert_equal(getutxo[0]["outpoint"], saved_outpoint_1);
        assert_equal(getutxo[0]["height"], 0);
        assert_equal(getutxo[0]["intxpool"], False);
        assert_equal(getutxo[0]["spent"], True); #spent
        assert_equal(getutxo[0]["exists"], True);

        # Two utxos should now be in memory. One for the send and one for the change address
        saved_outpoint_2 = list[0]['outpoint'];
        saved_outpoint_3 = list[1]['outpoint'];

        getutxo = self.nodes[0].getutxo(saved_outpoint_2)
        assert_equal(getutxo[0]["outpoint"], saved_outpoint_2);
        assert_equal(getutxo[0]["height"], 0);
        assert_equal(getutxo[0]["intxpool"], True); #intxpool
        assert_equal(getutxo[0]["spent"], False);
        assert_equal(getutxo[0]["exists"], True);

        getutxo = self.nodes[0].getutxo(saved_outpoint_3)
        assert_equal(getutxo[0]["outpoint"], saved_outpoint_3);
        assert_equal(getutxo[0]["height"], 0);
        assert_equal(getutxo[0]["intxpool"], True); # intxpool
        assert_equal(getutxo[0]["spent"], False);
        assert_equal(getutxo[0]["exists"], True);


        # Test a utxo that was spent which was "intxpool"
        self.nodes[0].sendtoaddress(self.nodes[0].getnewaddress(), 9000000, "", "", subtractfeefromamount)
        waitFor(60, lambda: len(self.nodes[0].listunspent(0,1)) == 2)
        list = self.nodes[0].listunspent(0,1);

        # check that the old utxos were spent
        getutxo = self.nodes[0].getutxo(saved_outpoint_2)
        assert_equal(getutxo[0]["outpoint"], saved_outpoint_2);
        assert_equal(getutxo[0]["height"], 0);
        assert_equal(getutxo[0]["intxpool"], True); # intxpool
        assert_equal(getutxo[0]["spent"], True); # now should be spent
        assert_equal(getutxo[0]["exists"], True);

        getutxo = self.nodes[0].getutxo(saved_outpoint_3)
        assert_equal(getutxo[0]["outpoint"], saved_outpoint_3);
        assert_equal(getutxo[0]["height"], 0);
        assert_equal(getutxo[0]["intxpool"], True); # in txpool
        assert_equal(getutxo[0]["spent"], True); # now should be spent
        assert_equal(getutxo[0]["exists"], True);

        #check new utxos created. One for the send and one for the change address
        saved_outpoint_4 = list[0]['outpoint'];
        saved_outpoint_5 = list[1]['outpoint'];

        getutxo = self.nodes[0].getutxo(saved_outpoint_4)
        assert_equal(getutxo[0]["outpoint"], saved_outpoint_4);
        assert_equal(getutxo[0]["height"], 0);
        assert_equal(getutxo[0]["intxpool"], True);
        assert_equal(getutxo[0]["spent"], False);
        assert_equal(getutxo[0]["exists"], True);

        getutxo = self.nodes[0].getutxo(saved_outpoint_5)
        assert_equal(getutxo[0]["outpoint"], saved_outpoint_5);
        assert_equal(getutxo[0]["height"], 0);
        assert_equal(getutxo[0]["intxpool"], True);
        assert_equal(getutxo[0]["spent"], False);
        assert_equal(getutxo[0]["exists"], True);

        # Test a utxo that is in poinsTip RAM only
        self.nodes[0].generate(1)
        self.sync_all()
        waitFor(60, lambda: self.nodes[0].gettxpoolinfo()['size'] == 0)

        # Check old utxos: They were all spent so they should no longer exist after the block was mined.
        getutxo = self.nodes[0].getutxo(saved_outpoint_1)
        assert_equal(getutxo[0]["outpoint"], saved_outpoint_1);
        assert_equal(getutxo[0]["height"], 0);
        assert_equal(getutxo[0]["intxpool"], False);
        assert_equal(getutxo[0]["spent"], False);
        assert_equal(getutxo[0]["exists"], False);

        getutxo = self.nodes[0].getutxo(saved_outpoint_2)
        assert_equal(getutxo[0]["outpoint"], saved_outpoint_2);
        assert_equal(getutxo[0]["height"], 0);
        assert_equal(getutxo[0]["intxpool"], False);
        assert_equal(getutxo[0]["spent"], False);
        assert_equal(getutxo[0]["exists"], False);

        getutxo = self.nodes[0].getutxo(saved_outpoint_3)
        assert_equal(getutxo[0]["outpoint"], saved_outpoint_3);
        assert_equal(getutxo[0]["height"], 0);
        assert_equal(getutxo[0]["intxpool"], False);
        assert_equal(getutxo[0]["spent"], False);
        assert_equal(getutxo[0]["exists"], False);

        #check new utxos created. One for the send and one for the change address
        getutxo = self.nodes[0].getutxo(saved_outpoint_4)
        assert_equal(getutxo[0]["outpoint"], saved_outpoint_4);
        assert_equal(getutxo[0]["height"], 102);
        assert_equal(getutxo[0]["intxpool"], False);
        assert_equal(getutxo[0]["spent"], False);
        assert_equal(getutxo[0]["exists"], True);

        getutxo = self.nodes[0].getutxo(saved_outpoint_5)
        assert_equal(getutxo[0]["outpoint"], saved_outpoint_5);
        assert_equal(getutxo[0]["height"], 102);
        assert_equal(getutxo[0]["intxpool"], False);
        assert_equal(getutxo[0]["spent"], False);
        assert_equal(getutxo[0]["exists"], True);

        # Restart the node so that no utxos are found in RAM,
        # and then see if we can lookup a UTXO directly from the disk storage.
        stop_nodes(self.nodes)
        wait_bitcoinds()
        self.node_args = [['-debug=rpc']]
        self.nodes = start_nodes(1, self.options.tmpdir, self.node_args)

        getutxo = self.nodes[0].getutxo(saved_outpoint_4)
        assert_equal(getutxo[0]["outpoint"], saved_outpoint_4);
        assert_equal(getutxo[0]["height"], 102);
        assert_equal(getutxo[0]["intxpool"], False);
        assert_equal(getutxo[0]["spent"], False);
        assert_equal(getutxo[0]["exists"], True);

        getutxo = self.nodes[0].getutxo(saved_outpoint_5)
        assert_equal(getutxo[0]["outpoint"], saved_outpoint_5);
        assert_equal(getutxo[0]["height"], 102);
        assert_equal(getutxo[0]["intxpool"], False);
        assert_equal(getutxo[0]["spent"], False);
        assert_equal(getutxo[0]["exists"], True);

        # Lookup multiple utxos
        getutxo = self.nodes[0].getutxo(saved_outpoint_4, saved_outpoint_5)
        assert_equal(getutxo[0]["outpoint"], saved_outpoint_4);
        assert_equal(getutxo[0]["height"], 102);
        assert_equal(getutxo[0]["intxpool"], False);
        assert_equal(getutxo[0]["spent"], False);
        assert_equal(getutxo[0]["exists"], True);

        assert_equal(getutxo[1]["outpoint"], saved_outpoint_5);
        assert_equal(getutxo[1]["height"], 102);
        assert_equal(getutxo[1]["intxpool"], False);
        assert_equal(getutxo[1]["spent"], False);
        assert_equal(getutxo[1]["exists"], True);


if __name__ == '__main__':
    RPCGetUtxoTest().main()

def Test():
    flags = standardFlags()
    t = RPCGetUtxoTest()
    t.drop_to_pdb = True
    t.main(flags)
