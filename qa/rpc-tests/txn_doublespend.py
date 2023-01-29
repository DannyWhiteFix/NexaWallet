#!/usr/bin/env python3
# Copyright (c) 2014-2015 The Bitcoin Core developers
# Copyright (c) 2015-2022 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
import test_framework.loginit
#
# Test proper accounting with a double-spend conflict
#

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *

class TxnDoubleSpendTest(BitcoinTestFramework):

    def setup_network(self):
        # Start with split network:
        return super(TxnDoubleSpendTest, self).setup_network(True)

    def run_test(self):
        # All nodes should start with 25 mined blocks:
        starting_balance = COINBASE_REWARD*25
        for i in range(4):
            assert_equal(self.nodes[i].getbalance(), starting_balance)
            assert_equal(self.nodes[i].getbalance("*"), starting_balance)
            self.nodes[i].getnewaddress("p2pkh", "")  # bug workaround, coins generated assigned to first getnewaddress!

        balance = self.nodes[1].getwalletinfo()["balance"]
        unconfirmed_balance = self.nodes[1].getwalletinfo()["unconfirmed_balance"]
        immature_balance = self.nodes[1].getwalletinfo()["immature_balance"]

        startHeight = self.nodes[2].getblockcount()

        # Coins are sent to node1_address
        node1_address = self.nodes[1].getnewaddress("p2pkh", "from0")

        # First: use raw transaction API to send NEXA to node1_address,
        # but don't broadcast:

        unspent = self.nodes[0].listunspent()

        doublespend_fee = Decimal('-20000')
        doublespend_amt = unspent[0]["amount"] + unspent[1]["amount"] - Decimal("10000000.0")
        rawtx_input_0 = {}
        rawtx_input_0["outpoint"] = unspent[0]["outpoint"]
        rawtx_input_0["amount"] = unspent[0]["amount"]
        rawtx_input_1 = {}
        rawtx_input_1["outpoint"] = unspent[1]["outpoint"]
        rawtx_input_1["amount"] = unspent[1]["amount"]
        inputs = [rawtx_input_0, rawtx_input_1]
        change_address = self.nodes[0].getnewaddress("p2pkt")
        outputs = {}
        outputs[change_address] = Decimal("10000000.0") + doublespend_fee
        outputs[node1_address] = doublespend_amt
        rawtx2 = self.nodes[0].createrawtransaction(inputs, outputs)
        doublespend2 = self.nodes[0].signrawtransaction(rawtx2)
        assert_equal(doublespend2["complete"], True)

        # Change how we allocate the coins slightly
        outputs[node1_address] =  outputs[node1_address] - Decimal("5000000.0")
        outputs[change_address] = outputs[change_address] + Decimal("5000000.0")
        # And build a doublespend
        rawtx1 = self.nodes[0].createrawtransaction(inputs, outputs)
        doublespend1 = self.nodes[0].signrawtransaction(rawtx1)
        assert_equal(doublespend1["complete"], True)

        # doublespends will have different idems because they change utxo state
        # (as opposed to malleated tx, which have same idem, but different id)
        assert doublespend1["txidem"] != doublespend2["txidem"], "transactions are not different"

        # Now give doublespend1 to one side of the network
        doublespend1_txidem = self.nodes[0].sendrawtransaction(doublespend1["hex"])

        # Now give doublespend2 to miner:
        doublespend2_txidem = self.nodes[2].sendrawtransaction(doublespend2["hex"])


        ################################################################################################
        # Before mining the block on node2, check the instant transactions functionality by using node1
        # to send transactions and doublespends to before they get confirmed.
        # 1) Send a transaction to node 1 and check that the balance is first unavailable but then
        #    after 5 seconds becomes available.
        # 2) Then send a double spend of that transaction, again to node 1.  The available balance will
        #    now become unavailable.

        # turn on instant transactions for node1
        instantTxnDelay = 3
        self.nodes[1].set("wallet.instant=1");
        self.nodes[1].set("wallet.instantDelay=3");

        # Node1 is the destination wallet so send the first spend to node1 and check that the balance is unavailable
        node1_txidem = self.nodes[1].sendrawtransaction(doublespend1["hex"])
        try: # Check that it got into the mempool
            ret = self.nodes[1].gettransaction(doublespend1_txidem)
        except JSONRPCException:
            assert(False)
        
        # Check balances. The txn just received should intially show in the unconfirmed balance
        balance = self.nodes[1].getwalletinfo()["balance"]
        unconfirmed_balance = self.nodes[1].getwalletinfo()["unconfirmed_balance"]
        immature_balance = self.nodes[1].getwalletinfo()["immature_balance"]
        assert_equal(balance, 250000000)
        assert_equal(unconfirmed_balance, 5000000) # coins are unavailable
        assert_equal(immature_balance, 245000000)       
      
        # Wait for the instant transaction time delay period, and then check balances again on node1.
        # The unavailable coins should now be available.
        time.sleep(instantTxnDelay)
        balance = self.nodes[1].getwalletinfo()["balance"]
        unconfirmed_balance = self.nodes[1].getwalletinfo()["unconfirmed_balance"]
        immature_balance = self.nodes[1].getwalletinfo()["immature_balance"]
        assert_equal(balance, 255000000) # coins are now available to be spent
        assert_equal(unconfirmed_balance, 0)
        assert_equal(immature_balance, 245000000)       

        # Send the double spend to node1.
        # We should get an exception caused by a txpool conflict
        try: # Check that it got into the mempool
            ret = self.nodes[1].sendrawtransaction(doublespend2["hex"])
        except JSONRPCException as e:
            assert_equal(e.error["code"], -26)
            assert_equal(e.error["message"], "258: txn-txpool-conflict")
        
        # Check that the first transaction sent which is currently in the txpool was marked "doublespent".
        # This is caused by the txpool conflict from the second transaction (the doublepend).
        assert_equal(self.nodes[1].gettxpoolentry(node1_txidem)["doublespent"], True)

        # Check that the balance on node1.
        # A dsproof should have been received causing the coins to be changed from available to unavailable.
        balance = self.nodes[1].getwalletinfo()["balance"]
        unconfirmed_balance = self.nodes[1].getwalletinfo()["unconfirmed_balance"]
        immature_balance = self.nodes[1].getwalletinfo()["immature_balance"]
        assert_equal(balance, 250000000)
        assert_equal(unconfirmed_balance, 5000000) # coins now show as unconfirmed
        assert_equal(immature_balance, 245000000)       

        # END instant transaction check
        #####################################################################################################

        # Reconnect the split network, and resend wallet transactions:
        interconnect_nodes(self.nodes)
        self.is_network_split=False

        self.nodes[2].generate(1)
        sync_blocks(self.nodes)
        assert_equal(self.nodes[0].gettransaction(doublespend2_txidem)["confirmations"], 1)

        # Re-fetch transaction info:
        tx1byid = self.nodes[0].gettransaction(doublespend1["txid"])
        tx1 = self.nodes[0].gettransaction(doublespend1_txidem)

        # transaction should be conflicted
        assert tx1byid["confirmations"] == -1
        assert tx1["confirmations"] == -1

        # Node0's total balance should be what the winning doublespend tx (#2) paid.  That is,
        # the starting balance, plus coinbase for one matured block,
        # minus the doublespend send, plus fees (which are negative):
        expected = starting_balance + 1*COINBASE_REWARD - doublespend_amt + doublespend_fee
        assert_equal(self.nodes[0].getbalance(), expected)
        assert_equal(self.nodes[0].getbalance("*"), expected)

        # Node1's "from0" account balance should be just the doublespend:
        assert_equal(self.nodes[1].getbalance("from0"), doublespend_amt)


if __name__ == '__main__':
    TxnDoubleSpendTest().main()

def Test():
    t = TxnDoubleSpendTest()
    t.drop_to_pdb = True
    bitcoinConf = {
        "debug": ["blk", "mempool", "net", "req"],
        "logtimemicros": 1
    }

    flags = standardFlags()
    t.main(flags, bitcoinConf, None)
