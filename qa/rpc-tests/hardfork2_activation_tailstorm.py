#!/usr/bin/env python3
# Copyright (c) 2015-2025 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import test_framework.loginit
import logging
#logging.getLogger().setLevel(logging.INFO)

#
# Test HardFork2 tailstorm activation
#
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from test_framework.blocktools import *

# Accurately count satoshis
import decimal
decimal.getcontext().prec = 16

waitTime = 60

class TailstormActivationTest(BitcoinTestFramework):

    def setup_chain(self):
        print("Initializing test directory "+self.options.tmpdir)
        initialize_chain_clean(self.options.tmpdir, 2, self.confDict)

    def setup_network(self):
        self.nodes = []
        self.is_network_split = False
        self.nodes.append(start_node(0, self.options.tmpdir, ["-debug=req", "-debug=net", "-debug=dag", "-relay.dataCarrierSize=30000"]))
        self.nodes.append(start_node(1, self.options.tmpdir, ["-debug=req", "-debug=net", "-debug=dag", "-relay.dataCarrierSize=30000"]))
        interconnect_nodes(self.nodes)

    def setmocktime(self, time):
        for node in self.nodes:
            node.setmocktime(time)

    def setforktime(self, time):
        for node in self.nodes:
            node.set("consensus.fork2Time=" + str(time))

    def run_test(self):

        # Mine some blocks to get utxos etc

        # Generate enough blocks that we can spend some coinbase.
        nBlocks = 101
        self.nodes[0].generate(nBlocks-1)
        self.sync_all()
        self.nodes[0].generate(1)
        assert_equal(self.nodes[0].getblockcount(), 101)

        # mine a few blocks 1 second apart so we can get a more meaningful "mediantime"
        bestblock = self.nodes[0].getbestblockhash()
        lastblocktime = self.nodes[0].getblockheader(bestblock)['time']
        mocktime = lastblocktime
        for i in range(10):
            mocktime = mocktime + 120
            self.setmocktime(mocktime)
            self.nodes[0].generate(1)
        assert_equal(self.nodes[0].getblockcount(), 111)

        # set the harfork activation to just a few blocks ahead
        bestblock = self.nodes[0].getbestblockhash()
        lastblocktime = self.nodes[0].getblockheader(bestblock)['time']
        activationtime = lastblocktime + 240
        self.setforktime(activationtime)

        blockchaininfo = self.nodes[0].getblockchaininfo()
        assert_equal(blockchaininfo['forktime'], activationtime)
        assert_equal(blockchaininfo['forkactive'], False)
        assert_equal(blockchaininfo['forkenforcednextblock'], False)
        assert_greater_than(activationtime, blockchaininfo['mediantime'])

        # Mine just up to the hard fork activation (activationtime will still be greater than mediantime).
        for i in range(6):
            mocktime = mocktime + 120
            self.setmocktime(mocktime)
            
            # get the mining commitment and make sure it changes after a block is mined
            commitment_before = self.nodes[0].getminingcandidate()
            self.nodes[0].generate(1)
            assert_not_equal(commitment_before['headerCommitment'], self.nodes[0].getminingcandidate()['headerCommitment']);

            blockchaininfo = self.nodes[0].getblockchaininfo()
            assert_equal(blockchaininfo['forkactive'], False)
            assert_equal(blockchaininfo['forkenforcednextblock'], False)
            assert_greater_than(activationtime, blockchaininfo['mediantime']) # activationtime > mediantime
            try:
                tailstorminfo = self.nodes[0].gettailstorminfo()
                assert False; # tailstorm is not enabled yet
            except JSONRPCException as e:
                pass

        # check mininginfo is not yet enabled for subblocks
        self.sync_all()
        info = self.nodes[0].getmininginfo();
        assert_equal(info["currentmaxblocksize"], 100000);
        assert_equal(info["currentmaxsubblocksize"], "N/A");
        info = self.nodes[1].getmininginfo();
        assert_equal(info["currentmaxblocksize"], 100000);
        assert_equal(info["currentmaxsubblocksize"], "N/A");

        ###### Check potential chain splitting issue at the moment the fork goes "pending".
        #  We can't differentiate between subblocks and legacy blocks so at "pending" time
        #  we need to set an internal flag which know what the pending height is. Then if a block
        #  has a higher height we know it's a subblock, if equal to or lower then it's a legacy block.
        logging.info("Test block pending chain split issue")

        # Disconnect peers and mine a block on each peer.
        disconnect_all(self.nodes[0])
        waitFor(waitTime, lambda: len(self.nodes[0].getpeerinfo()) == 0)

        # Fork should be pending after the next block mined (median time will be greater than or equal to blocktime)
        mocktime = mocktime + 120
        self.setmocktime(mocktime)

        legacy_block_hash0 = self.nodes[0].generate(1)
        blockchaininfo = self.nodes[0].getblockchaininfo()
        assert_equal(blockchaininfo['forkactive'], False)
        assert_equal(blockchaininfo['forkenforcednextblock'], True)
        assert_equal(activationtime, blockchaininfo['mediantime']) # when median time is >= activationtime

        legacy_block_hash1 = self.nodes[1].generate(1)
        blockchaininfo = self.nodes[0].getblockchaininfo()
        assert_equal(blockchaininfo['forkactive'], False)
        assert_equal(blockchaininfo['forkenforcednextblock'], True)
        assert_equal(activationtime, blockchaininfo['mediantime']) # when median time is >= activationtime

        # when fork is pending on next block, check mininginfo was enabled for subblocks and also the
        # max blocksize was increased to 100Kb * tailstorm_k = 400Kb
        info = self.nodes[0].getmininginfo();
        assert_equal(info["currentmaxblocksize"], 400000);
        assert_equal(info["currentmaxsubblocksize"], 100000);
        info = self.nodes[1].getmininginfo();
        assert_equal(info["currentmaxblocksize"], 400000);
        assert_equal(info["currentmaxsubblocksize"], 100000);

        # also check node 1 for pending status
        blockchaininfo1 = self.nodes[1].getblockchaininfo()
        assert_equal(blockchaininfo1['forkactive'], False)
        assert_equal(blockchaininfo1['forkenforcednextblock'], True)
        assert_equal(activationtime, blockchaininfo1['mediantime']) # when median time is >= activationtime

        ### Now we start generating subblocks. One on each node.
        logging.info("Start Generating first subblocks when fork is pending")
        subblock_hash = self.nodes[0].generate(1)
        tailstorminfo = self.nodes[0].gettailstorminfo()
        assert_equal(tailstorminfo['chaintip'], blockchaininfo['bestblockhash'])
        assert_equal(tailstorminfo['dagtip'], subblock_hash[0])
        assert_equal(tailstorminfo['total'], 1)
        assert_equal(tailstorminfo['bestdag'], 1)
        assert_equal(tailstorminfo['uncles'], 0)

        subblock_hash1 = self.nodes[1].generate(1)
        tailstorminfo = self.nodes[1].gettailstorminfo()
        assert_equal(tailstorminfo['chaintip'], blockchaininfo1['bestblockhash'])
        assert_equal(tailstorminfo['dagtip'], subblock_hash1[0])
        assert_equal(tailstorminfo['total'], 1)
        assert_equal(tailstorminfo['bestdag'], 1)
        assert_equal(tailstorminfo['uncles'], 0)

        # Interconnect peers and check that both competing blocks and subblocks were propagated
        # and that all dag and chain info is correct.
        interconnect_nodes(self.nodes)
        self.sync_all()
        assert_equal(self.nodes[0].getbestblockhash(), legacy_block_hash0[0])
        assert_equal(self.nodes[1].getbestblockhash(), legacy_block_hash1[0])
        waitFor(waitTime, lambda: self.nodes[0].getblock(legacy_block_hash1[0]))
        waitFor(waitTime, lambda: self.nodes[1].getblock(legacy_block_hash0[0]))

        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['chaintip'] == blockchaininfo['bestblockhash'])
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['dagtip'] == subblock_hash[0])
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['total'] == 2)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['bestdag'] == 1)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['uncles'] == 0)

        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['chaintip'] == blockchaininfo1['bestblockhash'])
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['dagtip'] == subblock_hash1[0])
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['total'] == 2)
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['bestdag'] == 1)
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['uncles'] == 0)

        # Continue generating subblocks (both peers should now be on same fork with same best dag)
        # Also, get the mining commitment and make sure it changes after a subblock is mined
        commitment_before0 = self.nodes[0].getminingcandidate()
        commitment_before1 = self.nodes[1].getminingcandidate()
        subblock_hash = self.nodes[0].generate(1)

        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['chaintip'] == blockchaininfo['bestblockhash'])
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['dagtip'] == subblock_hash[0])
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['total'] == 3)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['bestdag'] == 2)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['uncles'] == 0)

        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['chaintip'] == blockchaininfo['bestblockhash'])
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['dagtip'] == subblock_hash[0])
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['total'] == 3)
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['bestdag'] == 2)
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['uncles'] == 0)

        assert_not_equal(commitment_before0['headerCommitment'], self.nodes[0].getminingcandidate()['headerCommitment']);
        assert_not_equal(commitment_before1['headerCommitment'], self.nodes[1].getminingcandidate()['headerCommitment']);

        # Generate last subblock
        subblock_hash = self.nodes[0].generate(1)
        tailstorminfo = self.nodes[0].gettailstorminfo()
        assert_equal(tailstorminfo['chaintip'], blockchaininfo['bestblockhash'])
        assert_equal(tailstorminfo['dagtip'], subblock_hash[0])
        assert_equal(tailstorminfo['total'], 4)
        assert_equal(tailstorminfo['bestdag'], 3)
        assert_equal(tailstorminfo['uncles'], 0)

        # Check that block rewards being given out correctly to the right miners
        waitFor(waitTime, lambda: self.nodes[0].getwalletinfo()['balance'] == 180000000)
        waitFor(waitTime, lambda: self.nodes[0].getwalletinfo()['immature_balance'] == 1000000000)
        waitFor(waitTime, lambda: self.nodes[1].getwalletinfo()['balance'] == 0)
        waitFor(waitTime, lambda: self.nodes[1].getwalletinfo()['immature_balance'] == 0) # re-org resolves balance to zero.

        # Now we mine the Summary block which locks in the activation
        logging.info("Generate first summary block")
        self.nodes[0].generate(1)
        blockchaininfo = self.nodes[0].getblockchaininfo()
        assert_equal(blockchaininfo['forkactive'], True)
        assert_equal(blockchaininfo['forkenforcednextblock'], False)
        tailstorminfo = self.nodes[0].gettailstorminfo()
        assert_equal(tailstorminfo['chaintip'], blockchaininfo['bestblockhash'])
        assert_equal(tailstorminfo['dagtip'], blockchaininfo['bestblockhash'])
        assert_equal(tailstorminfo['total'], 4)
        assert_equal(tailstorminfo['bestdag'], 0)
        assert_equal(tailstorminfo['uncles'], 0)

        info = self.nodes[0].getmininginfo()
        assert_equal(info["currentmaxblocksize"], 400000)
        assert_equal(info["currentmaxsubblocksize"], 100000)

        # Check that block rewards being given out correctly to the right miners
        waitFor(waitTime, lambda: self.nodes[0].getwalletinfo()['balance'] == 190000000)
        waitFor(waitTime, lambda: self.nodes[0].getwalletinfo()['immature_balance'] == 1000000000)
        waitFor(waitTime, lambda: self.nodes[1].getwalletinfo()['balance'] == 0)
        waitFor(waitTime, lambda: self.nodes[1].getwalletinfo()['immature_balance'] == 0)

        # First subblock mined under new rules:
        logging.info("Start Generating first subblocks after new rules")
        self.sync_all()
        mocktime = mocktime + 30
        self.setmocktime(mocktime)
        subblock_hash = self.nodes[0].generate(1)
        assert_equal(blockchaininfo['forkactive'], True)
        assert_equal(blockchaininfo['forkenforcednextblock'], False)
        assert_greater_than(blockchaininfo['mediantime'], activationtime)
        tailstorminfo = self.nodes[0].gettailstorminfo()
        assert_equal(tailstorminfo['chaintip'], blockchaininfo['bestblockhash'])
        assert_equal(tailstorminfo['dagtip'], subblock_hash[0])
        assert_equal(tailstorminfo['total'], 5)
        assert_equal(tailstorminfo['bestdag'], 1)
        assert_equal(tailstorminfo['uncles'], 0)

        ##### Make sure we don't mine previously mined transactions.
        # Create a transaction that gets added to the txpool in both nodes
        # One subblock is already in the dag.
        # Now mine the remaining subblocks and the summary block. The second
        # subblock should have the transaction in it. The third should not,
        # however, the summary block should have it.
        addr1 = self.nodes[1].getnewaddress()
        txidem = self.nodes[0].sendtoaddress(addr1, 10000)
        waitFor(waitTime, lambda: self.nodes[1].gettxpoolinfo()['size'] == 1)

        # mine the second subblock. The tx should be in it.
        mocktime = mocktime + 30
        self.setmocktime(mocktime)
        subblock_hash = self.nodes[0].generate(1)
        blockdata = self.nodes[0].getsubblock(subblock_hash[0])
        assert(txidem in blockdata['txidem'])

        # mine the third subblock. The tx should NOT be in it.
        mocktime = mocktime + 30
        self.setmocktime(mocktime)
        subblock_hash = self.nodes[0].generate(1)
        blockdata = self.nodes[0].getsubblock(subblock_hash[0])
        assert(txidem not in blockdata['txidem'])

        # mine the Summary block. The tx should be in it.
        mocktime = mocktime + 30
        self.setmocktime(mocktime)
        summaryblock_hash = self.nodes[0].generate(1)
        blockdata = self.nodes[0].getblock(summaryblock_hash[0])
        assert(txidem in blockdata['txidem'])

        # Check that block rewards being given out correctly to the right miners
        self.sync_all()
        waitFor(waitTime, lambda: self.nodes[0].getbalance() == Decimal('199989997.81'))
        waitFor(waitTime, lambda: self.nodes[1].getbalance() == Decimal('10000.00'))
        wallet0 = self.nodes[0].getwalletinfo()
        wallet1 = self.nodes[1].getwalletinfo()
        assert_equal(wallet0['balance'], Decimal('199989997.81'))
        assert_equal(wallet0['unconfirmed_balance'], 0)
        assert_equal(wallet0['immature_balance'], Decimal('1000000002.19'))
        assert_equal(wallet1['balance'], Decimal('10000.00'))
        assert_equal(wallet1['unconfirmed_balance'], Decimal('0.00'))
        assert_equal(wallet1['immature_balance'], 0)

        ##### Make sure we don't mine previously mined transactions when fast block template is enabled.
        # Make sure that fast block template also filters out duplicate transactions
        # that were already mined.
        logging.info("Test fast block template")
        self.nodes[0].set('mining.fastBlockTemplate=1')

        addr1 = self.nodes[1].getnewaddress()
        txidem1 = self.nodes[0].sendtoaddress(addr1, 10000)
        txidem2 = self.nodes[0].sendtoaddress(addr1, 10000)
        txidem3 = self.nodes[0].sendtoaddress(addr1, 10000)
        waitFor(waitTime, lambda: self.nodes[1].gettxpoolinfo()['size'] == 3)

        # mine the first subblock. The tx should be in it.
        mocktime = mocktime + 30
        self.setmocktime(mocktime)
        subblock_hash = self.nodes[0].generate(1)
        blockdata = self.nodes[0].getsubblock(subblock_hash[0])
        assert(txidem1 in blockdata['txidem'])
        assert(txidem2 in blockdata['txidem'])
        assert(txidem3 in blockdata['txidem'])

        # mine the second subblock. The tx should NOT be in it.
        mocktime = mocktime + 30
        self.setmocktime(mocktime)
        subblock_hash = self.nodes[0].generate(1)
        blockdata = self.nodes[0].getsubblock(subblock_hash[0])
        assert(txidem1 not in blockdata['txidem'])
        assert(txidem2 not in blockdata['txidem'])
        assert(txidem3 not in blockdata['txidem'])

        # mine the third subblock but from the other peer. The tx should NOT be in it.
        mocktime = mocktime + 30
        self.setmocktime(mocktime)
        subblock_hash = self.nodes[0].generate(1)
        blockdata = self.nodes[0].getsubblock(subblock_hash[0])
        assert(txidem1 not in blockdata['txidem'])
        assert(txidem2 not in blockdata['txidem'])
        assert(txidem3 not in blockdata['txidem'])

        # mine the Summary block. The tx should be in it.
        mocktime = mocktime + 30
        self.setmocktime(mocktime)
        summaryblock_hash = self.nodes[0].generate(1)
        blockdata = self.nodes[0].getblock(summaryblock_hash[0])
        assert(txidem1 in blockdata['txidem'])
        assert(txidem2 in blockdata['txidem'])
        assert(txidem3 in blockdata['txidem'])

        ######## Make sure we don't mine previously mined transactions when using a block priority size.
        # Make sure that fast block template also filters out duplicate transactions
        # that were already mined.
        logging.info("Test block priority size")
        self.sync_all()
        self.nodes[0].set('mining.fastBlockTemplate=0')
        self.nodes[0].set('mining.prioritySize=10000')

        addr1 = self.nodes[1].getnewaddress()
        txidem1 = self.nodes[0].sendtoaddress(addr1, 10000)
        txidem2 = self.nodes[0].sendtoaddress(addr1, 10000)
        txidem3 = self.nodes[0].sendtoaddress(addr1, 10000)
        waitFor(waitTime, lambda: self.nodes[1].gettxpoolinfo()['size'] == 3)

        # mine the first subblock. The tx should be in it.
        mocktime = mocktime + 30
        self.setmocktime(mocktime)
        subblock_hash = self.nodes[0].generate(1)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['bestdag'] == 1)
        blockdata = self.nodes[0].getsubblock(subblock_hash[0])
        assert(txidem1 in blockdata['txidem'])
        assert(txidem2 in blockdata['txidem'])
        assert(txidem3 in blockdata['txidem'])

        # mine the second subblock. The tx should NOT be in it.
        mocktime = mocktime + 30
        self.setmocktime(mocktime)
        subblock_hash = self.nodes[0].generate(1)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['bestdag'] == 2)
        blockdata = self.nodes[0].getsubblock(subblock_hash[0])
        assert(txidem1 not in blockdata['txidem'])
        assert(txidem2 not in blockdata['txidem'])
        assert(txidem3 not in blockdata['txidem'])

        # mine the third subblock but from the other peer. The tx should NOT be in it.
        mocktime = mocktime + 30
        self.setmocktime(mocktime)
        subblock_hash = self.nodes[0].generate(1)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['bestdag'] == 3)
        blockdata = self.nodes[0].getsubblock(subblock_hash[0])
        assert(txidem1 not in blockdata['txidem'])
        assert(txidem2 not in blockdata['txidem'])
        assert(txidem3 not in blockdata['txidem'])

        # mine the Summary block. The tx should be in it.
        mocktime = mocktime + 30
        self.setmocktime(mocktime)
        summaryblock_hash = self.nodes[0].generate(1)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['bestdag'] == 0)
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['bestdag'] == 0)
        blockdata = self.nodes[0].getblock(summaryblock_hash[0])
        assert(txidem1 in blockdata['txidem'])
        assert(txidem2 in blockdata['txidem'])
        assert(txidem3 in blockdata['txidem'])

        ######## Startup test where subblocks are shared between nodes
        logging.info("Test sharing of subblocks on startup")
        self.sync_blocks()
        self.nodes[0].set('mining.fastBlockTemplate=0')
        self.nodes[0].set('mining.prioritySize=0')

        # Disconnect peers.
        disconnect_all(self.nodes[0])
        waitFor(waitTime, lambda: len(self.nodes[0].getpeerinfo()) == 0)

        # Mine a few subblocks on node 0 and then reconnect
        subblock1 = self.nodes[0].generate(1)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['bestdag'] == 1)
        subblock2 = self.nodes[0].generate(1)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['bestdag'] == 2)
        subblock3 = self.nodes[0].generate(1)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['bestdag'] == 3)

        # Subblocks should now show up on node1 after reconnect.
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['bestdag'] == 0)
        interconnect_nodes(self.nodes)
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['bestdag'] == 3)
        blockdata1 = self.nodes[1].getsubblock(subblock1[0])
        blockdata2 = self.nodes[1].getsubblock(subblock2[0])
        blockdata3 = self.nodes[1].getsubblock(subblock3[0])
        assert(blockdata1['hash'] == subblock1[0])
        assert(blockdata2['hash'] == subblock2[0])
        assert(blockdata3['hash'] == subblock3[0])

        # Now mine the summary block
        summary_block = self.nodes[0].generate(1)
        self.sync_blocks()


        ######## Test with the same transaction in different subblocks
        # This would happen if for instance two miners mined subblocks from their
        # txpools at roughly the same time. This is a key feature of tailstorm that
        # all subblocks are allowed even when they have duplicate transactions.
        # NOTE: this test also tests when we have two subblocks at height 1 or what you could call
        #       two separate tree roots pointing to the same summary block.
        logging.info("Test duplicate transactions in subblocks and two subblocks at height 1")

        # setup both txpools with the same transactions then
        addr1 = self.nodes[1].getnewaddress()
        txidem1 = self.nodes[0].sendtoaddress(addr1, 10000)
        txidem2 = self.nodes[0].sendtoaddress(addr1, 10000)
        txidem3 = self.nodes[0].sendtoaddress(addr1, 10000)
        waitFor(waitTime, lambda: self.nodes[1].gettxpoolinfo()['size'] == 3)

        # Disconnect peers.
        disconnect_all(self.nodes[0])
        waitFor(waitTime, lambda: len(self.nodes[0].getpeerinfo()) == 0)

        subblock_hash_node0 = self.nodes[0].generate(1)
        subblock_hash_node1 = self.nodes[1].generate(1)

        # reconnect peers and both nodes will share subblocks with each other
        interconnect_nodes(self.nodes)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['bestdag'] == 2)
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['bestdag'] == 2)

        blockdata1 = self.nodes[0].getsubblock(subblock_hash_node0[0])
        blockdata2 = self.nodes[0].getsubblock(subblock_hash_node1[0])
        assert(blockdata1['hash'] == subblock_hash_node0[0])
        assert(blockdata2['hash'] == subblock_hash_node1[0])
        assert(txidem1 in blockdata1['txidem'])
        assert(txidem2 in blockdata1['txidem'])
        assert(txidem3 in blockdata1['txidem'])
        assert(txidem1 in blockdata2['txidem'])
        assert(txidem2 in blockdata2['txidem'])
        assert(txidem3 in blockdata2['txidem'])

        blockdata1 = self.nodes[1].getsubblock(subblock_hash_node0[0])
        blockdata2 = self.nodes[1].getsubblock(subblock_hash_node1[0])
        assert(blockdata1['hash'] == subblock_hash_node0[0])
        assert(blockdata2['hash'] == subblock_hash_node1[0])
        assert(txidem1 in blockdata1['txidem'])
        assert(txidem2 in blockdata1['txidem'])
        assert(txidem3 in blockdata1['txidem'])
        assert(txidem1 in blockdata2['txidem'])
        assert(txidem2 in blockdata2['txidem'])
        assert(txidem3 in blockdata2['txidem'])

        # Mine the third subblock which will have no txns in it.
        subblock_hash = self.nodes[1].generate(1)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['bestdag'] == 3)
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['bestdag'] == 3)
        blockdata = self.nodes[1].getsubblock(subblock_hash[0])
        assert(txidem1 not in blockdata['txidem'])
        assert(txidem2 not in blockdata['txidem'])
        assert(txidem3 not in blockdata['txidem'])

        # Mine the summary block
        wallet0_before = self.nodes[0].getwalletinfo()
        wallet1_before = self.nodes[1].getwalletinfo()
        block_hash = self.nodes[1].generate(1)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['bestdag'] == 0)
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['bestdag'] == 0)
        blockdata = self.nodes[1].getblock(block_hash[0])
        assert(txidem1 in blockdata['txidem'])
        assert(txidem2 in blockdata['txidem'])
        assert(txidem3 in blockdata['txidem'])

        # check wallet balances
        self.sync_all()
        wallet0_after = self.nodes[0].getwalletinfo()
        wallet1_after = self.nodes[1].getwalletinfo()
        wallet0_balance_delta = wallet0_after['balance'] - wallet0_before['balance']
        wallet0_unconfirmed_balance_delta = wallet0_after['unconfirmed_balance'] - wallet0_before['unconfirmed_balance']
        wallet0_immature_balance_delta = wallet0_after['immature_balance'] - wallet0_before['immature_balance']
        wallet1_balance_delta = wallet1_after['balance'] - wallet1_before['balance']
        wallet1_unconfirmed_balance_delta = wallet1_after['unconfirmed_balance'] - wallet1_before['unconfirmed_balance']
        wallet1_immature_balance_delta = wallet1_after['immature_balance'] - wallet1_before['immature_balance']

        assert_equal(wallet0_balance_delta, Decimal('10000000.00'))
        assert_equal(wallet0_unconfirmed_balance_delta, 0)
        assert_equal(wallet0_immature_balance_delta, Decimal('-7999998.69'))
        assert_equal(wallet1_balance_delta, Decimal('30000.00'))
        assert_equal(wallet1_unconfirmed_balance_delta, Decimal('-30000.00'))
        assert_equal(wallet1_immature_balance_delta, Decimal('8000005.26'))

        ###### Do a few more tests to check correct block reward distribution

        # Test with 2 blocks mined on each peer
        self.nodes[0].generate(1)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['bestdag'] == 1)
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['bestdag'] == 1)
        self.nodes[0].generate(1)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['bestdag'] == 2)
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['bestdag'] == 2)
        self.nodes[1].generate(1)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['bestdag'] == 3)
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['bestdag'] == 3)

        # now mine the summary block
        wallet0_before = self.nodes[0].getwalletinfo()
        wallet1_before = self.nodes[1].getwalletinfo()
        self.nodes[1].generate(1)
        self.sync_all()
        wallet0_after = self.nodes[0].getwalletinfo()
        wallet1_after = self.nodes[1].getwalletinfo()
        wallet0_balance_delta = wallet0_after['balance'] - wallet0_before['balance']
        wallet0_unconfirmed_balance_delta = wallet0_after['unconfirmed_balance'] - wallet0_before['unconfirmed_balance']
        wallet0_immature_balance_delta = wallet0_after['immature_balance'] - wallet0_before['immature_balance']
        wallet1_balance_delta = wallet1_after['balance'] - wallet1_before['balance']
        wallet1_unconfirmed_balance_delta = wallet1_after['unconfirmed_balance'] - wallet1_before['unconfirmed_balance']
        wallet1_immature_balance_delta = wallet1_after['immature_balance'] - wallet1_before['immature_balance']

        assert_equal(wallet0_balance_delta, Decimal('10000000.00'))
        assert_equal(wallet0_unconfirmed_balance_delta, 0)
        assert_equal(wallet0_immature_balance_delta, Decimal('-5000000.00'))
        assert_equal(wallet1_balance_delta, Decimal('0.00'))
        assert_equal(wallet1_unconfirmed_balance_delta, Decimal('0.00'))
        assert_equal(wallet1_immature_balance_delta, Decimal('5000000.00'))

        # Test with 3 blocks mined on one peer and only 1 on the other
        self.nodes[0].generate(1)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['bestdag'] == 1)
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['bestdag'] == 1)
        self.nodes[0].generate(1)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['bestdag'] == 2)
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['bestdag'] == 2)
        self.nodes[0].generate(1)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['bestdag'] == 3)
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['bestdag'] == 3)

        # now mine the summary block
        wallet0_before = self.nodes[0].getwalletinfo()
        wallet1_before = self.nodes[1].getwalletinfo()
        self.nodes[1].generate(1)
        self.sync_all()
        wallet0_after = self.nodes[0].getwalletinfo()
        wallet1_after = self.nodes[1].getwalletinfo()
        wallet0_balance_delta = wallet0_after['balance'] - wallet0_before['balance']
        wallet0_unconfirmed_balance_delta = wallet0_after['unconfirmed_balance'] - wallet0_before['unconfirmed_balance']
        wallet0_immature_balance_delta = wallet0_after['immature_balance'] - wallet0_before['immature_balance']
        wallet1_balance_delta = wallet1_after['balance'] - wallet1_before['balance']
        wallet1_unconfirmed_balance_delta = wallet1_after['unconfirmed_balance'] - wallet1_before['unconfirmed_balance']
        wallet1_immature_balance_delta = wallet1_after['immature_balance'] - wallet1_before['immature_balance']

        assert_equal(wallet0_balance_delta, Decimal('10000000.00'))
        assert_equal(wallet0_unconfirmed_balance_delta, 0)
        assert_equal(wallet0_immature_balance_delta, Decimal('-2500000.00'))
        assert_equal(wallet1_balance_delta, Decimal('0.00'))
        assert_equal(wallet1_unconfirmed_balance_delta, Decimal('0.00'))
        assert_equal(wallet1_immature_balance_delta, Decimal('2500000.00'))

        # Test re-orgs between dags being built on top of different summary blocks. So in this case
        # there's a summary block race which then we have to decide which dag is our best
        # dag to continue mining on. And if a better dag shows up then we have to follow that
        # and re-org to the other summary block and continue mining on top of that other summary
        # blocks' dag.
        logging.info("Test reorgs between between a summary block race and their two different dags")

        # Mine the next 3 subblocks and share them between peers before disconnecting.
        subblock_hash_node0 = self.nodes[0].generate(3)

        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['bestdag'] == 3)
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['bestdag'] == 3)

        # Disconnect peers.
        disconnect_all(self.nodes[0])
        waitFor(waitTime, lambda: len(self.nodes[0].getpeerinfo()) == 0)

        # Generate a new summary block and then start
        # a new tree by mining a subblock on each peer.
        node0_count = self.nodes[0].getblockcount()
        node1_count = self.nodes[1].getblockcount()
        summary_block_node0 = self.nodes[0].generate(1)
        summary_block_node1 = self.nodes[1].generate(1)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['bestdag'] == 0)
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['bestdag'] == 0)
        waitFor(waitTime, lambda: self.nodes[0].getblockcount() == node0_count + 1)
        waitFor(waitTime, lambda: self.nodes[1].getblockcount() == node1_count + 1)

        # the summary block chain tips on each node should not be equal
        waitFor(waitTime, lambda: self.nodes[0].getbestblockhash() == summary_block_node0[0])
        waitFor(waitTime, lambda: self.nodes[1].getbestblockhash() == summary_block_node1[0])
        node0_chaintip = self.nodes[0].getbestblockhash()
        node1_chaintip = self.nodes[1].getbestblockhash()
        assert_not_equal(node0_chaintip, node1_chaintip)

        # now extend the subblock chain on each peer by one
        subblock_hash_node0 = self.nodes[0].generate(1)
        subblock_hash_node1 = self.nodes[1].generate(1)
        assert_not_equal(subblock_hash_node0[0], subblock_hash_node1[0])
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['bestdag'] == 1)
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['bestdag'] == 1)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['dagtip'] == subblock_hash_node0[0])
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['dagtip'] == subblock_hash_node1[0])

        # reconnect peers and both nodes will share subblocks with each other
        # but each peer should stay on it's own previous chain tip.
        interconnect_nodes(self.nodes)
        waitFor(waitTime, lambda: len(self.nodes[0].getpeerinfo()) != 0)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['bestdag'] == 1)
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['bestdag'] == 1)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['dagtip'] == subblock_hash_node0[0])
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['dagtip'] == subblock_hash_node1[0])

        # now mine 1 additional subblock on one of the nodes and this should
        # cause the other node to re-org as evidenced by both having the same
        # chaintip and bestdag hash
        commitment_before0 = self.nodes[0].getminingcandidate()
        commitment_before1 = self.nodes[1].getminingcandidate()
        subblock_hash_node1 = self.nodes[1].generate(1)
        waitFor(waitTime, lambda: self.nodes[1].getbestblockhash() == node1_chaintip)
        waitFor(waitTime, lambda: self.nodes[0].getbestblockhash() == node1_chaintip)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['chaintip'] == node1_chaintip)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['dagtip'] == subblock_hash_node1[0])
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['bestdag'] == 2)
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['chaintip'] == node1_chaintip)
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['dagtip'] == subblock_hash_node1[0])
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['bestdag'] == 2)

        # After mining a new subblock and re-orging the miningcandidate should have updated on both peers
        assert_not_equal(commitment_before0['headerCommitment'], self.nodes[0].getminingcandidate()['headerCommitment']);
        assert_not_equal(commitment_before1['headerCommitment'], self.nodes[1].getminingcandidate()['headerCommitment']);

        # mine a subblock
        subblock_hash_node1 = self.nodes[1].generate(1)
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['chaintip'], node1_chaintip)
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['bestdag'] == 3)
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['dagtip'] == subblock_hash_node1[0])
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['chaintip'] == node1_chaintip)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['bestdag'] == 3)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['dagtip'] == subblock_hash_node1[0])

        # mine the summary block
        summary_hash = self.nodes[1].generate(1)
        waitFor(waitTime, lambda: summary_hash[0] == self.nodes[1].getbestblockhash())
        waitFor(waitTime, lambda: summary_hash[0] == self.nodes[0].getbestblockhash())
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['bestdag'] == 0)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['bestdag'] == 0)

        ###### Test where all the subblocks and the summary block should be mined by one miner
        logging.info("Test where all subblocks and summary block are mined by one miner")
        summary_hash = self.nodes[1].generate(4)
        waitFor(waitTime, lambda: summary_hash[3] == self.nodes[1].getbestblockhash())
        waitFor(waitTime, lambda: summary_hash[3] == self.nodes[0].getbestblockhash())
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['bestdag'] == 0)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['bestdag'] == 0)

        self.nodes[1].generate(2)
        summary_hash = self.nodes[1].generate(2)
        waitFor(waitTime, lambda: summary_hash[1] == self.nodes[1].getbestblockhash())
        waitFor(waitTime, lambda: summary_hash[1] == self.nodes[0].getbestblockhash())
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['bestdag'] == 0)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['bestdag'] == 0)

        self.nodes[1].generate(1)
        summary_hash = self.nodes[1].generate(3)
        waitFor(waitTime, lambda: summary_hash[2] == self.nodes[1].getbestblockhash())
        waitFor(waitTime, lambda: summary_hash[2] == self.nodes[0].getbestblockhash())
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['bestdag'] == 0)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['bestdag'] == 0)

        ###### Test where one node falls behind by more than the subblock check depth
        #      and then catches up again after the check depth has been exceeded.
        logging.info("Test where one node falls behind and then catches up later")
        disconnect_all(self.nodes[0])
        waitFor(waitTime, lambda: len(self.nodes[0].getpeerinfo()) == 0)

        # make one peer pull ahead before reconnecting
        mocktime = mocktime + 30
        self.setmocktime(mocktime)
        subblock_hash_node1 = self.nodes[1].generate(1)
        subblock_hash_node1 = self.nodes[1].generate(1)
        subblock_hash_node1 = self.nodes[1].generate(1)
        summary_block_node1 = self.nodes[1].generate(1)

        mocktime = mocktime + 30
        self.setmocktime(mocktime)
        subblock_hash_node1 = self.nodes[1].generate(1)
        subblock_hash_node1 = self.nodes[1].generate(1)
        subblock_hash_node1 = self.nodes[1].generate(1)
        summary_block_node1 = self.nodes[1].generate(1)

        # connect peers and the nodes should sync
        interconnect_nodes(self.nodes)
        waitFor(waitTime, lambda: len(self.nodes[0].getpeerinfo()) != 0)
        waitFor(waitTime, lambda: len(self.nodes[1].getpeerinfo()) != 0)
        waitFor(waitTime, lambda: self.nodes[1].getbestblockhash() == summary_block_node1[0])
        waitFor(waitTime, lambda: self.nodes[0].getbestblockhash() == summary_block_node1[0])
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['bestdag'] == 0)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['bestdag'] == 0)
        waitFor(waitTime, lambda: self.nodes[0].getblockcount() == self.nodes[1].getblockcount())


        ###### Test double spent subblocks.
        logging.info("Double spend subblocks")

        # disconnect peers
        disconnect_all(self.nodes[0])

        # create a two different transactions that spend the same output and send
        # to both peers.
        node1_address = self.nodes[1].getnewaddress("p2pkt", "from0")
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
        change_address = self.nodes[0].getnewaddress("p2pkh")
        outputs = {}
        outputs[change_address] = Decimal("10000000.0") + doublespend_fee
        rawtx2 = self.nodes[0].createrawtransaction(inputs, outputs)
        doublespend2 = self.nodes[0].signrawtransaction(rawtx2)
        doublespend2_outputs_node1 = outputs[change_address]
        assert_equal(doublespend2["complete"], True)

        # Change how we allocate the coins slightly
        outputs[change_address] = outputs[change_address] - Decimal("5000000.0")
        # And build a doublespend
        rawtx1 = self.nodes[0].createrawtransaction(inputs, outputs)
        doublespend1 = self.nodes[0].signrawtransaction(rawtx1)
        assert_equal(doublespend1["complete"], True)

        # doublespends will have different idems because they change utxo state
        # (as opposed to malleated tx, which have same idem, but different id)
        assert doublespend1["txidem"] != doublespend2["txidem"], "transactions are not different"

        # Now give doublespend1 to one side of the network
        doublespend1_txidem = self.nodes[0].sendrawtransaction(doublespend1["hex"], True)
        waitFor(waitTime, lambda: self.nodes[0].gettxpoolinfo()['size'] == 1)

        # create a small chain of txns using the output of the first doublespend
        txidem_ds1_chain = doublespend1_txidem
        tx_amount_ds1_chain = outputs[change_address]
        relayfee = 1000
        txidem_array_node0 = []
        for i in range(1, 3):
          try:
              outpoint = COutPoint().fromIdemAndIdx(txidem_ds1_chain, 0).rpcHex()
              inputs = []
              inputs.append({ "outpoint" : outpoint, "amount" : tx_amount_ds1_chain}) # references the prior tx created

              txin_amount = tx_amount_ds1_chain
              outputs = {}
              tx_amount_ds1_chain = tx_amount_ds1_chain - relayfee
              outputs[self.nodes[0].getnewaddress()] = Decimal(tx_amount_ds1_chain)
              rawtx = self.nodes[0].createrawtransaction(inputs, outputs)
              signed_tx = self.nodes[0].signrawtransaction(rawtx)["hex"]
              txidem_ds1_chain = self.nodes[0].sendrawtransaction(signed_tx, False, "standard", True)
              txidem_array_node0.append(txidem_ds1_chain)
              logging.info("node0: created chained tx depth %d" % i)

          except JSONRPCException as e: # an exception you don't catch is a testing error
              print(str(e))
              raise

        waitFor(waitTime, lambda: self.nodes[0].gettxpoolinfo()['size'] == 3)

        # Now give doublespend2 to other peer
        doublespend2_txidem = self.nodes[1].sendrawtransaction(doublespend2["hex"], True)
        waitFor(waitTime, lambda: self.nodes[1].gettxpoolinfo()['size'] == 1)

        # mine a subblock on both peers. These subblocks will double spend each other.
        subblock_hash_node0 = self.nodes[0].generate(1);
        subblock_hash_node1 = self.nodes[1].generate(1);
        node0_ds_hash = subblock_hash_node0[0];
        node1_ds_hash = subblock_hash_node1[0];
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['bestdag'] == 1)
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['bestdag'] == 1)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['total'] == 10)
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['total'] == 16)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['dagtip'] == subblock_hash_node0[0])
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['dagtip'] == subblock_hash_node1[0])

        # connect peers. The nodes should share their subblocks but each peer
        # should be having a different best dag tip because the sequence ids differ.
        interconnect_nodes(self.nodes)

        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['bestdag'] == 2)
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['bestdag'] == 2)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['total'] == 11)
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['total'] == 17)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['dagtip'] == subblock_hash_node0[0])
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['dagtip'] == subblock_hash_node1[0])

        # check conflicts were removed.  We can't leave conflicts in the txpool othewise
        # if we attemped to mine a new subblock those conflicts would most likely get added
        # to the new subblock and cause it to fail validation.
        waitFor(waitTime, lambda: self.nodes[0].gettxpoolinfo()['size'] == 0)
        waitFor(waitTime, lambda: self.nodes[1].gettxpoolinfo()['size'] == 0)

        # Try to re-enter the conflicting txs into the txpool. It should not be
        # possible.
        try:
            self.nodes[0].sendrawtransaction(doublespend1["hex"])
        except JSONRPCException as e:
            assert("Missing inputs" in e.error['message'])
        else:
            assert(False)

        try:
            self.nodes[1].sendrawtransaction(doublespend2["hex"])
        except JSONRPCException as e:
            assert("Missing inputs" in e.error['message'])
        else:
            assert(False)

        waitFor(waitTime, lambda: self.nodes[0].gettxpoolinfo()['size'] == 0)
        waitFor(waitTime, lambda: self.nodes[1].gettxpoolinfo()['size'] == 0)

        # now mine the next subblock on one node causing the other to re-org their dag tree
        # and so both peers should end up on the same dagtip.
        subblock_hash_node0 = self.nodes[0].generate(1);
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['total'] == 12)
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['total'] == 18)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['bestdag'] == 3)
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['bestdag'] == 3)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['dagtip'] == subblock_hash_node0[0])
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['dagtip'] == subblock_hash_node0[0])

        # Mine the summary block on node 1: both peers should end up on the same node1 chaintip.
        # NOTE: This test also tests that as the previous subblocks were received on node 1
        #       the conflicted txns on node1 also got removed either from its miners
        #       view (or directly from the txpool). If they hadn't been then the summary block
        #       which got mined on node 1 could never have been validated because the conflicting
        #       txns would have been added to the summary block.
        summary_hash = self.nodes[1].generate(1);
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['chaintip'] == summary_hash[0])
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['chaintip'] == summary_hash[0])
        self.sync_all()

        # Check that the right double spend transaction was chosen for the summary block
        summary_block = self.nodes[0].getblock(summary_hash[0])
        if node1_ds_hash > node0_ds_hash:
            assert(doublespend2_txidem in summary_block['txidem'])

            # check ds on node0 and any associated chained txns are "NOT" in the summary block
            assert(doublespend1_txidem not in summary_block['txidem'])
            for idem in txidem_array_node0:
                assert(idem not in summary_block['txidem'])
        else:
            assert(doublespend1_txidem in summary_block['txidem'])

            # check ds on node0 and any associated chained txns are not "IN" the summary block
            for idem in txidem_array_node0:
                assert(idem in summary_block['txidem'])

            assert(doublespend2_txidem not in summary_block['txidem'])

        ##### The dag should now continue to grow in size beyond the height neeeded to check summary
        #     block validity. So check that after a while the dag size doesn't change as we mined more
        #     blocks.
        logging.info("Check the trimming of the dag")
        currentCount = self.nodes[1].getblockcount();
        self.nodes[0].generate(4)
        waitFor(waitTime, lambda: currentCount + 1 == self.nodes[1].getblockcount())
        self.sync_all()

        currentCount = self.nodes[0].getblockcount();
        self.nodes[1].generate(4)
        waitFor(waitTime, lambda: currentCount + 1 == self.nodes[0].getblockcount())
        self.sync_all()

        currentCount = self.nodes[1].getblockcount();
        self.nodes[0].generate(4)
        waitFor(waitTime, lambda: currentCount + 1 == self.nodes[1].getblockcount())
        self.sync_all()

        currentCount = self.nodes[0].getblockcount();
        self.nodes[1].generate(4)
        waitFor(waitTime, lambda: currentCount + 1 == self.nodes[0].getblockcount())
        self.sync_all()

        currentCount = self.nodes[0].getblockcount();
        self.nodes[1].generate(4)
        waitFor(waitTime, lambda: currentCount + 1 == self.nodes[0].getblockcount())
        self.sync_all()

        currentCount = self.nodes[0].getblockcount();
        self.nodes[1].generate(4)
        waitFor(waitTime, lambda: currentCount + 1 == self.nodes[0].getblockcount())
        self.sync_all()

        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['total'] == 18)
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['total'] == 18)


        # Test mining longer chains of subblocks and blocks. When many blocks are
        # mined at one time the blocks can arrive and be processed out of order
        # by the receiving node.
        logging.info("Check out of order block handling")
        for i in range(3):
            currentCount = self.nodes[1].getblockcount();
            self.nodes[1].generate(16)
            waitFor(waitTime, lambda: currentCount + 4 == self.nodes[1].getblockcount())
            self.sync_all()

        # Create enough large transactions that would more than fill a summary block
        # and then mine them.
        # This test proves we won't create a summary block that is oversized.
        logging.info("Check blocksize limits")
        info = self.nodes[0].getmininginfo();
        maxSummaryBlockSize = info["currentmaxblocksize"]
        maxSubblockSize = info["currentmaxsubblocksize"]

        NUM_ADDRS = 10
        TX_POOL_BYTES = 420000
        TX_DATA_SIZE = 20000
        addrs = [self.nodes[0].getnewaddress() for _ in range(NUM_ADDRS)]
        generateTx(self.nodes[0], TX_POOL_BYTES, addrs, "01" * TX_DATA_SIZE)

        # generate the subblocks and make sure their sizes are below accepted limits
        subblockhash = self.nodes[0].generate(1)
        subblockSize = self.nodes[0].getsubblock(subblockhash[0])["size"]
        assert_greater_than(subblockSize, 90000)
        assert_greater_than(maxSubblockSize, subblockSize)

        subblockhash = self.nodes[0].generate(1)
        subblockSize = self.nodes[0].getsubblock(subblockhash[0])["size"]
        assert_greater_than(subblockSize, 90000)
        assert_greater_than(maxSubblockSize, subblockSize)
        subblockhash = self.nodes[0].generate(1)
        subblockSize = self.nodes[0].getsubblock(subblockhash[0])["size"]
        assert_greater_than(subblockSize, 90000)
        assert_greater_than(maxSubblockSize, subblockSize)

        # mine the summary block and make sure it's not over the limit.
        summaryhash = self.nodes[0].generate(1)
        summaryBlockSize = self.nodes[0].getblock(summaryhash[0])["size"]
        assert_greater_than(summaryBlockSize, 300000)
        assert_greater_than(maxSummaryBlockSize, summaryBlockSize)


        ####  Test Emergent Consensus snap to chain.
        #     Mine a few subblocks and then delete one from one of the nodes.
        #     Then continue to mine on the peer that was not deleted from until
        #     you mine beyond the "check depth" limit. What should happen is the
        #     node you "did" delete from will fall behind until the check depth
        #     is exceeded at which point it will "snap" back to the chain tip of the other.
        logging.info("Emergent Consensus: snap to chaintip")
        self.sync_all()
        subblock_hash1 = self.nodes[1].generate(1)
        subblock_hash2 = self.nodes[1].generate(1)
        subblock_hash3 = self.nodes[1].generate(1)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['bestdag'] == 3)
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['bestdag'] == 3)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['dagtip'] == subblock_hash3[0])
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['dagtip'] == subblock_hash3[0])

        node0_chaintip = self.nodes[0].getbestblockhash()
        node1_chaintip = self.nodes[1].getbestblockhash()
        assert_equal(node0_chaintip, node1_chaintip)

        # delete the last subblock on node0: chaintips will be equal but dags will not
        self.nodes[0].getsubblock(subblock_hash2[0], "remove")
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['bestdag'] == 1)
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['bestdag'] == 3)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['dagtip'] == subblock_hash1[0])
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['dagtip'] == subblock_hash3[0])

        node0_chaintip = self.nodes[0].getbestblockhash()
        node1_chaintip = self.nodes[1].getbestblockhash()
        assert_equal(node0_chaintip, node1_chaintip)

        # Advance the chain on node1: node0 should fall behind
        summary_hash = self.nodes[1].generate(1)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['bestdag'] == 1)
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['bestdag'] == 0)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['dagtip'] == subblock_hash1[0])
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['dagtip'] == summary_hash[0])
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['chaintip'] == node0_chaintip)
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['chaintip'] == summary_hash[0])

        node0_chaintip = self.nodes[0].getbestblockhash()
        node1_chaintip = self.nodes[1].getbestblockhash()
        assert_not_equal(node0_chaintip, node1_chaintip)

        # Advance 4 more summary blocks which makes the check depth limit of 4+1 or 5: node0 should still not have advanced.
        self.nodes[1].generate(4)
        self.nodes[1].generate(4)
        self.nodes[1].generate(3)
        summary_hash = self.nodes[1].generate(1)
        self.nodes[1].generate(2)

        sublock_hash1 = self.nodes[1].generate(1)
        summary_hash = self.nodes[1].generate(1)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['bestdag'] == 1)
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['bestdag'] == 0)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['dagtip'] == subblock_hash1[0])
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['dagtip'] == summary_hash[0])
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['chaintip'] == node0_chaintip)
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['chaintip'] == summary_hash[0])

        node0_chaintip = self.nodes[0].getbestblockhash()
        node1_chaintip = self.nodes[1].getbestblockhash()
        assert_not_equal(node0_chaintip, node1_chaintip)

        # mine one more summary block: node0 should catch up now and have the same chaintip
        self.nodes[1].generate(3)
        summary_hash = self.nodes[1].generate(1)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['bestdag'] == 0)
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['bestdag'] == 0)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['dagtip'] == summary_hash[0])
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['dagtip'] == summary_hash[0])
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['chaintip'] == summary_hash[0])
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['chaintip'] == summary_hash[0])

        node0_chaintip = self.nodes[0].getbestblockhash()
        node1_chaintip = self.nodes[1].getbestblockhash()
        assert_equal(node0_chaintip, node1_chaintip)


if __name__ == '__main__':
    TailstormActivationTest().main()

def Test():
    t = TailstormActivationTest()
    t.drop_to_pdb = True
    bitcoinConf = {
        "debug": ["validation", "rpc", "net", "blk", "thin", "mempool", "req", "bench", "evict"],
    }
    flags = standardFlags()
    flags[0] = '--tmpdir=/ramdisk/test/t1'
    t.main(flags, bitcoinConf, None)
