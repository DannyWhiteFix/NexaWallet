#!/usr/bin/env python3
# Copyright (c) 2014-2015 The Bitcoin Core developers
# Copyright (c) 2015-2022 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
import test_framework.loginit
import logging
#logging.getLogger().setLevel(logging.INFO)

#
# Test the adaptive block size functionality
#
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from test_framework.blocktools import *

# Accurately count satoshis
# 8 digits to get to 21million, and each bitcoin is 100 million satoshis
import decimal
decimal.getcontext().prec = 16

class AdaptiveBlockSizeTest(BitcoinTestFramework):

    def setup_chain(self):
        print("Initializing test directory "+self.options.tmpdir)
        initialize_chain_clean(self.options.tmpdir, 2, self.confDict)

    def setup_network(self):
        self.nodes = []
        self.is_network_split = False
        self.nodes.append(start_node(0, self.options.tmpdir, ["-debug=net", "-relay.dataCarrierSize=30000"]))
        self.nodes.append(start_node(1, self.options.tmpdir, ["-debug=net", "-relay.dataCarrierSize=30000"]))
        interconnect_nodes(self.nodes)

        self.relayfee = self.nodes[0].getnetworkinfo()['relayfee']

    def create_tx_with_many_inputs(self, node, utxos, fee, num):
        addr = node.getnewaddress()
        txids = []
        send_value = decimal.Decimal(0)
        send_sats = 0

        inputs = []
        for i in range(num):
            t = utxos.pop()
            inputs.append({ "outpoint" : t["outpoint"], "amount" : t["amount"]})
            send_value += t['amount']
            send_sats += t['satoshi']
        send_value = send_value - fee

        outputs = {}
        outputs[addr] = send_value
        rawtx = node.createrawtransaction(inputs, outputs)

        signedtxn = node.signrawtransaction(rawtx)
        assert_equal(signedtxn["complete"], True)
        node.sendrawtransaction(signedtxn["hex"])
        return signedtxn["hex"]

    def generateTx(self, node, txBytes, addrs, data=None):
        wallet = node.listunspent()
        wallet.sort(key=lambda x: x["amount"], reverse=False)

        size = 0
        count = 0
        while size < txBytes:
            count += 1
            utxo = wallet.pop()
            outp = {}
            # Make the tx bigger by adding addtl outputs so it validates faster
            payamt = satoshi_round(utxo["amount"] / 8)
            for x in range(0, 8):
                # its test code, I don't care if rounding error is folded into the fee
                outp[addrs[(count + x) % len(addrs)]] = payamt
            if data:
                outp["data"] = data
            txn = createrawtransaction([utxo], outp, createWastefulOutput)
            # The python createrawtransaction is meant to have the same API as the node's RPC so you can also do:
            signedtxn = node.signrawtransaction(txn)
            size += len(binascii.unhexlify(signedtxn["hex"]))
            node.sendrawtransaction(signedtxn["hex"], True)
        return (count, size)

    def MineBlock(self, node, TEST_BLOCK_SIZE, NUM_ADDRS, DATA_SIZE):
        addrs = [node.getnewaddress() for _ in range(NUM_ADDRS)]

        legacyAddrs = [node.getaddressforms(x)["legacy"] for x in addrs]
        self.generateTx(node, TEST_BLOCK_SIZE, legacyAddrs, "01" * DATA_SIZE)

        node.generate(1)

        return True

    def run_test(self):

        # Generate enough blocks that we can spend some coinbase.
        nBlocks = 148
        self.nodes[0].generate(nBlocks-1)
        self.sync_all()
        self.nodes[0].generate(1)
        assert_equal(self.nodes[0].getblockcount(), 148)

        # Test whether we can still process a block that less than the default of 100K before we hit the first short window
        logging.info("Test the default block size")
        utxos = create_confirmed_utxos(self.relayfee, self.nodes[0], 1200)
        assert_equal(self.nodes[0].getblockcount(), 149)
        assert_equal(self.nodes[0].getblockstats(self.nodes[0].getbestblockhash())["nextmaxblocksize"], 100000)

        self.MineBlock(self.nodes[0], 10000, 1, 11000)
        assert_greater_than(11800, self.nodes[0].getblockstats(self.nodes[0].getbestblockhash())["blocksize"])
        assert_greater_than(self.nodes[0].getblockstats(self.nodes[0].getbestblockhash())["blocksize"], 11700)
        assert_equal(self.nodes[0].getblockstats(self.nodes[0].getbestblockhash())["nextmaxblocksize"], 100000)
        assert_equal(self.nodes[0].getblockcount(), 150)

        # Test whether we can mining from a full txpool creates a block of less than the max adaptive size
        # next block size hasn't yet changed because the median has not changed beyond the default value.
        logging.info("Test max adaptive block size not exceeded")
        self.MineBlock(self.nodes[0], 100000, 10, 11000)
        assert_greater_than(96900, self.nodes[0].getblockstats(self.nodes[0].getbestblockhash())["blocksize"])
        assert_greater_than(self.nodes[0].getblockstats(self.nodes[0].getbestblockhash())["blocksize"], 96200)
        assert_equal(self.nodes[0].getblockstats(self.nodes[0].getbestblockhash())["nextmaxblocksize"], 100000)
        assert_equal(self.nodes[0].getblockcount(), 151)


        # We now have two larger blocks in our window.  Add more blocks that are greater than 10KB in size so we can
        # get the median (and the next max blocksize) on the short window to rise.
        # Test whether the next max block size will increase after the next 51 blocks are mined
        logging.info("Test first block size increase")
        for i in range(72):
            assert_equal(self.nodes[0].getblockcount(), 151 + i)
            self.MineBlock(self.nodes[0], 10000, 1, 11000)
            assert_equal(self.nodes[0].getblockstats(self.nodes[0].getbestblockhash())["nextmaxblocksize"], 100000)

        # We should have 223 blocks now with 75 of the last blocks which are larger than the previous group of blocks.
        # Mine one more which should increase cause our median to rise.
        assert_equal(self.nodes[0].getblockcount(), 223)
        self.MineBlock(self.nodes[0], 10000, 1, 11000)
        assert_greater_than(self.nodes[0].getblockstats(self.nodes[0].getbestblockhash())["nextmaxblocksize"], 116400)
        assert_greater_than(117500, self.nodes[0].getblockstats(self.nodes[0].getbestblockhash())["nextmaxblocksize"])

        # Mine another large block, as many as can fit in the nextmax block size.
        nextblocksize = self.nodes[0].getblockstats(self.nodes[0].getbestblockhash())["nextmaxblocksize"];
        self.MineBlock(self.nodes[0], 100000, 10, 11000)
        assert_greater_than(self.nodes[0].getblockstats(self.nodes[0].getbestblockhash())["blocksize"], 110000)
        assert_greater_than(110700, self.nodes[0].getblockstats(self.nodes[0].getbestblockhash())["blocksize"])
        assert_greater_than(nextblocksize, self.nodes[0].getblockstats(self.nodes[0].getbestblockhash())["blocksize"])
        assert_greater_than(self.nodes[0].getblockstats(self.nodes[0].getbestblockhash())["nextmaxblocksize"], 116400)
        assert_greater_than(117500, self.nodes[0].getblockstats(self.nodes[0].getbestblockhash())["nextmaxblocksize"])
        assert_equal(self.nodes[0].getblockcount(), 225)

        # Mine larger blocks until we get another median increase
        logging.info("Test second block size increase")
        for i in range(72):
            assert_greater_than(self.nodes[0].getblockstats(self.nodes[0].getbestblockhash())["nextmaxblocksize"], 116400)
            assert_greater_than(117500, self.nodes[0].getblockstats(self.nodes[0].getbestblockhash())["nextmaxblocksize"])
            assert_equal(self.nodes[0].getblockcount(), 225 + i)
            self.MineBlock(self.nodes[0], 10000, 1, 11500)

        nextblocksize = self.nodes[0].getblockstats(self.nodes[0].getbestblockhash())["nextmaxblocksize"];
        # mine a large block to get the increase
        self.MineBlock(self.nodes[0], 120000, 10, 11000)
        nextblocksize = self.nodes[0].getblockstats(self.nodes[0].getbestblockhash())["nextmaxblocksize"];
        assert_greater_than(self.nodes[0].getblockstats(self.nodes[0].getbestblockhash())["blocksize"], 110200)
        assert_greater_than(110700, self.nodes[0].getblockstats(self.nodes[0].getbestblockhash())["blocksize"])
        assert_greater_than(nextblocksize, self.nodes[0].getblockstats(self.nodes[0].getbestblockhash())["blocksize"])
        assert_greater_than(self.nodes[0].getblockstats(self.nodes[0].getbestblockhash())["nextmaxblocksize"], 121300)
        assert_greater_than(122600, self.nodes[0].getblockstats(self.nodes[0].getbestblockhash())["nextmaxblocksize"])
        assert_equal(self.nodes[0].getblockcount(), 298)

        # Mine another large block, as many as can fit in the next max block size
        self.MineBlock(self.nodes[0], 120000, 10, 11000)
        nextblocksize = self.nodes[0].getblockstats(self.nodes[0].getbestblockhash())["nextmaxblocksize"];
        assert_greater_than(self.nodes[0].getblockstats(self.nodes[0].getbestblockhash())["blocksize"], 110200)
        assert_greater_than(110700, self.nodes[0].getblockstats(self.nodes[0].getbestblockhash())["blocksize"])
        assert_greater_than(nextblocksize, self.nodes[0].getblockstats(self.nodes[0].getbestblockhash())["blocksize"])
        assert_greater_than(self.nodes[0].getblockstats(self.nodes[0].getbestblockhash())["nextmaxblocksize"], 121300)
        assert_greater_than(122600, self.nodes[0].getblockstats(self.nodes[0].getbestblockhash())["nextmaxblocksize"])
        assert_equal(self.nodes[0].getblockcount(), 299)

        # test setting and unsetting the tweak for a very large block. The memory pool is not vey full so we'll
        # end up mining just a small block but we will also clear the memory pool of transactions.
        self.nodes[0].set("test.nextMaxBlockSize=10000000")
        self.nodes[0].generate(1)
        self.nodes[0].set("test.nextMaxBlockSize=0")

        # Mine more blocks until get a median decrease
        logging.info("Test first block size decrease")
        for i in range(76):
            assert_greater_than(self.nodes[0].getblockstats(self.nodes[0].getbestblockhash())["nextmaxblocksize"], 121300)
            assert_greater_than(122600, self.nodes[0].getblockstats(self.nodes[0].getbestblockhash())["nextmaxblocksize"])
            self.MineBlock(self.nodes[0], 10000, 1, 11000)
        assert_greater_than(self.nodes[0].getblockstats(self.nodes[0].getbestblockhash())["nextmaxblocksize"], 116300)
        assert_greater_than(117500, self.nodes[0].getblockstats(self.nodes[0].getbestblockhash())["nextmaxblocksize"])

        # Mine more small blocks until get another median decrease
        logging.info("Test second block size decrease")
        for i in range(151):
            assert_greater_than(self.nodes[0].getblockstats(self.nodes[0].getbestblockhash())["nextmaxblocksize"], 116300)
            assert_greater_than(117500, self.nodes[0].getblockstats(self.nodes[0].getbestblockhash())["nextmaxblocksize"])
            self.nodes[0].generate(1)
        assert_equal(self.nodes[0].getblockstats(self.nodes[0].getbestblockhash())["nextmaxblocksize"], 100000)

        # Increase the next max block size on node1 and mine a larger block than would be allowed on node0.
        # This should cause node0 to reject the block and then disconnect from node1.
        assert_equal(self.nodes[0].getinfo()["connections"], 2)
        utxos = create_confirmed_utxos(self.relayfee, self.nodes[1], 300)
        blockcount_start = 639  # Depends on the exact functioning of create_confirmed_utxos so may change
        waitFor(30, lambda: self.nodes[0].getblockcount() == blockcount_start)
        waitFor(30, lambda: self.nodes[1].getblockcount() == blockcount_start)

        # set the next max size on node1 to double what is on node0 and mine the large block which should be greater
        # than the next max on node0
        logging.info("Test the rejection of a block that is too large")
        nextmax = self.nodes[0].getblockstats(self.nodes[0].getbestblockhash())["nextmaxblocksize"] * 2
        self.nodes[1].set("test.nextMaxBlockSize=" + str(nextmax))
        self.MineBlock(self.nodes[1], nextmax, 1, 11000)
        node0_nextmax = self.nodes[0].getblockstats(self.nodes[0].getbestblockhash())["nextmaxblocksize"]
        node1_blocksize = self.nodes[1].getblockstats(self.nodes[1].getbestblockhash())["blocksize"]
        assert_greater_than(node1_blocksize, node0_nextmax)

        # node0 will not sync with node1. If we were not running locally then
        # a disconnect from node1 would happen due to the oversized block it received from node1
        assert_equal(self.nodes[0].getblockcount(), blockcount_start)
        assert_equal(self.nodes[1].getblockcount(), blockcount_start + 1)

        # mine another block on node1. node0 still should not sync
        self.nodes[1].generate(1)
        assert_equal(self.nodes[0].getblockcount(), blockcount_start)
        assert_equal(self.nodes[1].getblockcount(), blockcount_start+2)

        # check the chain tips. The header from node1 should have been rejected on node0 because
        # the block size was too large and therefore it should not show up as a chaintip on node0.
        tips0 = self.nodes[0].getchaintips()
        tips1 = self.nodes[1].getchaintips()
        assert_equal (len (tips0), 1)
        assert_equal (tips0[0]['branchlen'], 0)
        assert_equal (tips0[0]['height'], blockcount_start)
        assert_equal (tips0[0]['status'], 'active')
        assert_equal (len (tips1), 1)
        assert_equal (tips1[0]['branchlen'], 0)
        assert_equal (tips1[0]['height'], blockcount_start + 2)
        assert_equal (tips1[0]['status'], 'active')

        # mine several blocks on node0 so that node1 re-orgs and follows the chain on node0
        self.nodes[0].generate(3)
        waitFor(30, lambda: self.nodes[0].getblockcount() == blockcount_start + 3)
        waitFor(30, lambda: self.nodes[1].getblockcount() == blockcount_start + 3)
        assert_equal(self.nodes[0].getbestblockhash(), self.nodes[1].getbestblockhash())

        # check the chain tips. We should have one tip on node0 and two on node1.
        tips0 = self.nodes[0].getchaintips()
        tips1 = self.nodes[1].getchaintips()
        assert_equal (len (tips0), 1)
        assert_equal (tips0[0]['branchlen'], 0)
        assert_equal (tips0[0]['height'], blockcount_start + 3)
        assert_equal (tips0[0]['status'], 'active')
        assert_equal (len (tips1), 2)
        assert_equal (tips1[0]['branchlen'], 0)
        assert_equal (tips1[0]['height'], blockcount_start + 3)
        assert_equal (tips1[0]['status'], 'active')
        assert_equal (tips1[1]['branchlen'], 2)
        assert_equal (tips1[1]['height'], blockcount_start + 2)
        assert_equal (tips1[1]['status'], 'valid-fork')


        # Create blocks that test the sigop mining limit.  The first block will add transactions to the block
        # that reach the sigop limit. The second block will contain transactions that will not hit the sig op
        # limit perfectly but will rather have to choose transactions that add up to slightly less than the sig
        # op limit.
        logging.info("Test sigop limits")

        coinbase_sigop_padding = 100 # This is reserved in mining blocks for the coinbase txn
        BLOCK_SIGCHECKS_RATIO = 141 # how many block bytes per sigop

        self.sync_all()
        blockcount_start = self.nodes[0].getblockcount();

        MAX_INPUTS = 256

        # create a set of txns with sigops such that when they are mined will not fill the block perfectly and will
        # result in a sigops total that are less than the maximum allowed. This proves that the miner is not able to
        # mine a block which is over the sigop limit.
        # Result:  both block size and sigops should be less than the max allowed.
        utxos_sigops = create_confirmed_utxos(self.relayfee, self.nodes[0], 1200)
        useUtxos = 710
        while useUtxos > 0:
            self.create_tx_with_many_inputs(self.nodes[0], utxos_sigops, self.relayfee, min(useUtxos, MAX_INPUTS))
            useUtxos -= min(useUtxos, MAX_INPUTS)

        nextmaxblocksize = self.nodes[0].getblockstats(self.nodes[0].getbestblockhash())["nextmaxblocksize"]
        max_block_sigops = int(nextmaxblocksize / BLOCK_SIGCHECKS_RATIO)
        self.nodes[0].generate(1)
        self.sync_all()
        assert_greater_than(max_block_sigops - coinbase_sigop_padding, self.nodes[0].getblockstats(self.nodes[0].getbestblockhash())["ins"])
        assert_greater_than(nextblocksize, self.nodes[0].getblockstats(self.nodes[0].getbestblockhash())["blocksize"])

        # Clear out the txpool by mining several blocks
        self.nodes[0].generate(5)
        assert_equal(0, self.nodes[0].gettxpoolinfo()['size'])
        self.sync_all()

        # Test that we can not bypass the mining code by submitting a block to a node which is beyond the sigop limit.
        # 1) Disconnect the two nodes
        # 2) Raise the nextmaxblocksize on one node0 which will not exceed the nextmaxblocksize on node1 but will exceed
        #    the sigop limit on node1.
        # 3) create transactions and mine a block on node0
        # 3) reconnect the peers which will propagate the block from node0 to node1.
        # Result:  node1 will reject the block.
        #
        # NOTE: it's not all that easy to create a block with > max sigops. In the following we have to manually
        #       adjust the nextmax block size in order to get condition just right to make such a block.

        if 0:  # TODO: the changed transaction size seems to have messed up these sizes.  Is there a way we can make it more robust?
            disconnect_all(self.nodes[0])
            disconnect_all(self.nodes[1])

            self.nodes[0].set("test.nextMaxBlockSize=160000")
            self.nodes[1].set("test.nextMaxBlockSize=140000")

            utxos_sigops3 = create_confirmed_utxos(self.relayfee, self.nodes[0], 1200)
            self.create_tx_with_many_inputs(self.nodes[0], utxos_sigops3, self.relayfee, 500)
            self.create_tx_with_many_inputs(self.nodes[0], utxos_sigops3, self.relayfee, 493)
            blkhash = self.nodes[0].generate(1)
            assert_greater_than(self.nodes[0].getblockstats(self.nodes[0].getbestblockhash())["ins"], max_block_sigops - coinbase_sigop_padding)
            node0_nextmax = self.nodes[0].getblockstats(self.nodes[0].getbestblockhash())["nextmaxblocksize"]
            assert_greater_than(node0_nextmax, self.nodes[0].getblockstats(self.nodes[0].getbestblockhash())["blocksize"])
            node1_nextmax = self.nodes[0].getblockstats(self.nodes[1].getbestblockhash())["nextmaxblocksize"]
            assert_greater_than(node1_nextmax, self.nodes[0].getblockstats(self.nodes[0].getbestblockhash())["blocksize"])

            n1ct = self.nodes[1].getchaintips()
            interconnect_nodes(self.nodes)
            waitFor(10, lambda: self.nodes[1].getchaintips()[0]['status'] == 'invalid')

            # chaintips will show that the last block in the chain was invalidated since it has too many sigops.
            tips = self.nodes[1].getchaintips()
            assert_equal (tips[0]['branchlen'], 1)
            assert_equal (tips[0]['status'], 'invalid')
            assert_equal (tips[0]['height'], 643)
            assert_equal (tips[1]['branchlen'], 0)
            assert_equal (tips[1]['status'], 'active')
            assert_equal (tips[1]['height'], 642)
 

        print("Success")

if __name__ == '__main__':
    AdaptiveBlockSizeTest().main()

def Test():
    t = AdaptiveBlockSizeTest()
    t.drop_to_pdb = True
    bitcoinConf = {
        "debug": ["validation", "rpc", "net", "blk", "thin", "mempool", "req", "bench", "evict"],
    }
    flags = standardFlags()
    flags[0] = '--tmpdir=/ramdisk/test/t1'
    t.main(flags, bitcoinConf, None)
