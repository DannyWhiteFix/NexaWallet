#!/usr/bin/env python3
# Copyright (c) 2014-2015 The Bitcoin Core developers
# Copyright (c) 2015-2022 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
import test_framework.loginit
#
# Test re-org scenarios with a mempool that contains transactions
# that spend (directly or indirectly) coinbase transactions.
#
import logging
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from test_framework.blocktools import *

import code, traceback, signal

def debug(sig, frame):
    """Interrupt running process, and provide a python prompt for
    interactive debugging."""
    d={'_frame':frame}         # Allow access to frame object.
    d.update(frame.f_globals)  # Unless shadowed by global
    d.update(frame.f_locals)

    #i = code.InteractiveConsole(d)
    message  = "Signal received : entering python shell.\nTraceback:\n"
    message += ''.join(traceback.format_stack(frame))
    logging.info(message)
    logging.info("FRAME: ")
    logging.info(str(d))

    #i.interact(message)

def initSigDebugging():
    signal.signal(signal.SIGUSR1, debug)  # Register handler


# Create one-input, one-output, no-fee transaction:
class RawTransactionsTest(BitcoinTestFramework):

    def setup_chain(self):
        print("Initializing test directory "+self.options.tmpdir)
        initialize_chain_clean(self.options.tmpdir, 3)

    def setup_network(self, split=False):
        self.nodes = start_nodes(3, self.options.tmpdir)

        #connect to a local machine for debugging
        #url = "http://bitcoinrpc:DP6DvqZtqXarpeNWyN3LZTFchCCyCUuHwNF7E8pX99x1@%s:%d" % ('127.0.0.1', 18332)
        #proxy = AuthServiceProxy(url)
        #proxy.url = url # store URL on proxy for info
        #self.nodes.append(proxy)
        connect_nodes_full(self.nodes)

        self.is_network_split=False
        self.sync_blocks()

    def run_test(self):
        initSigDebugging()
        #prepare some coins for multiple *rawtransaction commands
        self.nodes[2].generate(1)
        self.sync_blocks()
        self.nodes[0].generate(101)
        self.sync_blocks()

        # check that coinbase transaction has to have the fee field set to 0
        block = self.nodes[0].getblock(101)
        cbTxIdem = block['txidem'][0]
        rawCbTx = self.nodes[0].getrawtransaction(cbTxIdem, True)
        assert_equal(rawCbTx['fee'],0)


        self.nodes[0].sendtoaddress(self.nodes[2].getnewaddress(),1500000)
        self.nodes[0].sendtoaddress(self.nodes[2].getnewaddress(),1000000)
        txidem = self.nodes[0].sendtoaddress(self.nodes[2].getnewaddress(),5000000)
        txjson = self.nodes[0].gettransaction(txidem)
        txdecode = self.nodes[0].decoderawtransaction(txjson['hex'])
        # verify some basic stuff about the transaction
        assert txdecode['spends'] - txdecode['sends'] == txdecode['fee']
        assert txdecode['txidem'] == txidem
        assert txjson['txidem'] == txidem
        assert txdecode['txid'] == txjson['txid']
        assert len(txdecode['vin']) == 1  # since this test just started up, we have knowledge of the coins so this is what the alg will pick
        assert len(txdecode['vout']) == 2  # since this test just started up, we have knowledge of the coins so this is what the alg will pick
        # one of the outputs needs to be our send, but it could be any
        assert Decimal('5000000') in [ x['value'] for x in txdecode['vout']]
        self.nodes[0].generate(5)
        self.sync_blocks()

        #########################################
        # sendrawtransaction with missing input #
        #########################################
        inputs  = [ {'outpoint' : "1d1d4e24ed99057e84c3f80fd8fbec79ed9e1acee37da269356ecea000000000", 'amount' : 1000000}] # won't exist
        outputs = { self.nodes[0].getnewaddress() : 3998000, self.nodes[0].getnewaddress() : 1000000 }
        rawtx   = self.nodes[2].createrawtransaction(inputs, outputs)
        rawtx   = self.nodes[2].signrawtransaction(rawtx)

        try:
            rawtx   = self.nodes[2].sendrawtransaction(rawtx['hex'])
        except JSONRPCException as e:
            assert("Missing inputs" in e.error['message'])
        else:
            assert(False)

        #####################################
        # getrawtransaction with block hash #
        #####################################

        # make a tx by sending then generate 2 blocks; block1 has the tx in it
        tx = self.nodes[2].sendtoaddress(self.nodes[1].getnewaddress(), 1000000)
        block1, block2 = self.nodes[2].generate(2)
        self.sync_all()
        # We should be able to get the raw transaction by providing the correct block
        gottx = self.nodes[0].getrawtransaction(tx, True, block1)
        assert_equal(gottx['txidem'], tx)
        assert_equal(gottx['in_active_chain'], True)
        assert_equal(gottx['in_txpool'], False)
        assert_equal(gottx['in_orphanpool'], False)
        assert_equal(gottx['blockhash'], block1)
        # We should not have the 'in_active_chain' flag when we don't provide a block
        gottx = self.nodes[0].getrawtransaction(tx, True)
        assert_equal(gottx['txidem'], tx)
        assert 'in_active_chain' not in gottx
        assert_equal(gottx['in_txpool'], False)
        assert_equal(gottx['in_orphanpool'], False)
        assert_equal(gottx['blockhash'], block1)
        # We should not get the tx if we provide an unrelated block
        assert_raises_rpc_error(-5, "No such transaction found", self.nodes[0].getrawtransaction, tx, True, block2)
        # An invalid block hash should raise the correct errors
        assert_raises_rpc_error(-8, "parameter 3 must be hexadecimal", self.nodes[0].getrawtransaction, tx, True, True)
        assert_raises_rpc_error(-8, "parameter 3 must be hexadecimal", self.nodes[0].getrawtransaction, tx, True, "foobar")
        assert_raises_rpc_error(-8, "parameter 3 must be of length 64", self.nodes[0].getrawtransaction, tx, True, "abcd1234")
        assert_raises_rpc_error(-5, "Block hash not found", self.nodes[0].getrawtransaction, tx, True, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

        #########################
        # RAW TX MULTISIG TESTS #
        #########################
        # 2of2 test
        addr1 = self.nodes[2].getnewaddress()
        addr2 = self.nodes[2].getnewaddress()

        addr1Obj = self.nodes[2].validateaddress(addr1)
        addr2Obj = self.nodes[2].validateaddress(addr2)

        mSigObj = self.nodes[2].addmultisigaddress(2, [addr1Obj['pubkey'], addr2Obj['pubkey']])
        mSigObjValid = self.nodes[2].validateaddress(mSigObj)

        #use balance deltas instead of absolute values
        bal = self.nodes[2].getbalance()

        # send 1.2 BTC to msig adr
        txId = self.nodes[0].sendtoaddress(mSigObj, 1200000)
        waitFor(60, lambda: self.nodes[0].gettxpoolinfo()['size'] == 1) 
        self.nodes[0].generate(1)
        self.sync_blocks()
        waitFor(60, lambda: self.nodes[2].getbalance() == bal+Decimal('1200000.00')) #node2 has both keys of the 2of2 ms addr., tx should affect the balance

        # 2of16 test from different nodes
        addr01 = self.nodes[0].getnewaddress()
        addr02 = self.nodes[0].getnewaddress()
        addr1 = self.nodes[1].getnewaddress()
        addr2 = self.nodes[2].getnewaddress()
        addr3 = self.nodes[2].getnewaddress()
        addr4 = self.nodes[2].getnewaddress()
        addr5 = self.nodes[2].getnewaddress()
        addr6 = self.nodes[2].getnewaddress()
        addr7 = self.nodes[2].getnewaddress()
        addr8 = self.nodes[2].getnewaddress()
        addr9 = self.nodes[2].getnewaddress()
        addr10 = self.nodes[2].getnewaddress()
        addr11 = self.nodes[2].getnewaddress()
        addr12 = self.nodes[2].getnewaddress()
        addr13 = self.nodes[2].getnewaddress()
        addr14 = self.nodes[2].getnewaddress()
        addr15 = self.nodes[2].getnewaddress()
        addr16 = self.nodes[2].getnewaddress()
        addr17 = self.nodes[2].getnewaddress()
        addr18 = self.nodes[2].getnewaddress()
        addr19 = self.nodes[2].getnewaddress()
        addr20 = self.nodes[2].getnewaddress()
        addr21 = self.nodes[2].getnewaddress()

        addr01Obj = self.nodes[0].validateaddress(addr01)
        addr02Obj = self.nodes[0].validateaddress(addr02)
        addr1Obj = self.nodes[1].validateaddress(addr1)
        addr2Obj = self.nodes[2].validateaddress(addr2)
        addr3Obj = self.nodes[2].validateaddress(addr3)
        addr4Obj = self.nodes[2].validateaddress(addr4)
        addr5Obj = self.nodes[2].validateaddress(addr5)
        addr6Obj = self.nodes[2].validateaddress(addr6)
        addr7Obj = self.nodes[2].validateaddress(addr7)
        addr8Obj = self.nodes[2].validateaddress(addr8)
        addr9Obj = self.nodes[2].validateaddress(addr9)
        addr10Obj = self.nodes[2].validateaddress(addr10)
        addr11Obj = self.nodes[2].validateaddress(addr11)
        addr12Obj = self.nodes[2].validateaddress(addr12)
        addr13Obj = self.nodes[2].validateaddress(addr13)
        addr14Obj = self.nodes[2].validateaddress(addr14)
        addr15Obj = self.nodes[2].validateaddress(addr15)
        addr16Obj = self.nodes[2].validateaddress(addr16)
        addr17Obj = self.nodes[2].validateaddress(addr17)
        addr18Obj = self.nodes[2].validateaddress(addr18)
        addr19Obj = self.nodes[2].validateaddress(addr19)
        addr20Obj = self.nodes[2].validateaddress(addr20)
        addr21Obj = self.nodes[2].validateaddress(addr21)

        # mine a few blocks 1 second apart so we can get a more meaningful "mediantime"
        logging.info("starting fork tests")
        bestblock = self.nodes[2].getbestblockhash()
        lastblocktime = self.nodes[2].getblockheader(bestblock)['time']
        mocktime = lastblocktime
        for i in range(10):
            mocktime = mocktime + 120
            self.nodes[0].setmocktime(mocktime)
            self.nodes[1].setmocktime(mocktime)
            self.nodes[2].setmocktime(mocktime)
            self.nodes[2].generate(1)
        assert_equal(self.nodes[2].getblockcount(), 120)
        self.sync_blocks()

        # set the harfork activation to just a few blocks ahead
        bestblock = self.nodes[2].getbestblockhash()
        lastblocktime = self.nodes[2].getblockheader(bestblock)['time']
        activationtime = lastblocktime + 240
        self.nodes[0].set("consensus.fork1Time=" + str(activationtime))
        self.nodes[1].set("consensus.fork1Time=" + str(activationtime))
        self.nodes[2].set("consensus.fork1Time=" + str(activationtime))

        blockchaininfo = self.nodes[2].getblockchaininfo()
        assert_equal(blockchaininfo['forktime'], activationtime)
        assert_equal(blockchaininfo['forkactive'], False)
        assert_equal(blockchaininfo['forkenforcednextblock'], False)
        assert_greater_than(activationtime, blockchaininfo['mediantime'])

        # Mine just up to the hard fork activation minus 1 (activationtime will still be greater than mediantime).
        for i in range(5):
            mocktime = mocktime + 120
            self.nodes[0].setmocktime(mocktime)
            self.nodes[1].setmocktime(mocktime)
            self.nodes[2].setmocktime(mocktime)
            self.nodes[2].generate(1)
            blockchaininfo = self.nodes[2].getblockchaininfo()
            assert_equal(blockchaininfo['forkactive'], False)
            assert_equal(blockchaininfo['forkenforcednextblock'], False)
            assert_greater_than(activationtime, blockchaininfo['mediantime']) # activationtime > mediantime
        self.sync_blocks()

        # Should not be able to create a multisig with more than 15 pubkeys because the script size limit will be exceeded.
        # This is actually not correct, we should be able to create 16 but for the stack limitations.  Once the hard fork
        # is activated, we should be able to create 16.
        try:
            mSigObj = self.nodes[2].addmultisigaddress(2, [addr1Obj['pubkey'], addr2Obj['pubkey'], addr3Obj['pubkey'], addr4Obj['pubkey'], addr5Obj['pubkey'], addr6Obj['pubkey'], addr7Obj['pubkey'], addr8Obj['pubkey'], addr9Obj['pubkey'], addr10Obj['pubkey'],addr11Obj['pubkey'],addr12Obj['pubkey'],addr13Obj['pubkey'],addr14Obj['pubkey'], addr15Obj['pubkey']])
        except JSONRPCException as e:
            assert(e.error["message"] == "redeemScript exceeds size limit: 547")

        # Try to create with one more than the maximum of 8. This should fail as there is a bug in the current
        # implementation which the hardfork will fix.
        mSigObj = self.nodes[2].addmultisigaddress(1, [addr1Obj['pubkey'], addr2Obj['pubkey'], addr3Obj['pubkey'], addr4Obj['pubkey'], addr5Obj['pubkey'], addr6Obj['pubkey'], addr7Obj['pubkey'], addr8Obj['pubkey'], addr9Obj['pubkey']])
        mSigObjValid = self.nodes[1].validateaddress(mSigObj)

        txId = self.nodes[2].sendtoaddress(mSigObj, 2200000)
        decTx = self.nodes[2].gettransaction(txId)
        rawTx = self.nodes[2].decoderawtransaction(decTx['hex'])
        sPK = rawTx['vout'][0]['scriptPubKey']['hex']

        txDetails = self.nodes[2].gettransaction(txId, True)
        decrawTx = self.nodes[2].decoderawtransaction(txDetails['hex'])
        vout = False
        for outpoint in decrawTx['vout']:
            if outpoint['value'] == Decimal('2200000.00'):
                vout = outpoint
                break

        inputs = [{ "outpoint" : vout["outpoint"], "scriptPubKey" : vout['scriptPubKey']['hex'], "amount":str(vout['value']) }]
        outputs = { self.nodes[2].getnewaddress() : 2190000 }
        rawTx = self.nodes[2].createrawtransaction(inputs, outputs)
        rawTxSigned = self.nodes[2].signrawtransaction(rawTx, inputs)
        assert_equal(rawTxSigned['complete'], False)

        # Create one with the maximum number of pubkeys (currently only 8 will work - this is a bug in the current codebase
        # which the hardfork1 changes will also fix.
        bal = self.nodes[2].getbalance()
        mSigObj = self.nodes[2].addmultisigaddress(2, [addr1Obj['pubkey'], addr2Obj['pubkey'], addr3Obj['pubkey'], addr4Obj['pubkey'], addr5Obj['pubkey'], addr6Obj['pubkey'], addr7Obj['pubkey'], addr8Obj['pubkey']])
        mSigObjValid = self.nodes[2].validateaddress(mSigObj)

        txId = self.nodes[0].sendtoaddress(mSigObj, 2200000)
        decTx = self.nodes[0].gettransaction(txId)
        rawTx = self.nodes[0].decoderawtransaction(decTx['hex'])
        sPK = rawTx['vout'][0]['scriptPubKey']['hex']

        # Mine right up to the activation time
        mocktime = mocktime + 120
        self.nodes[0].setmocktime(mocktime)
        self.nodes[1].setmocktime(mocktime)
        self.nodes[2].setmocktime(mocktime)
        self.nodes[0].generate(1)
        self.sync_all()

        # fork still not active
        blockchaininfo = self.nodes[2].getblockchaininfo()
        assert_equal(blockchaininfo['forkactive'], False)
        assert_equal(blockchaininfo['forkenforcednextblock'], False)

        #THIS IS A INCOMPLETE FEATURE
        #NODE2 HAS TWO OF THREE KEY AND THE FUNDS SHOULD BE SPENDABLE AND COUNT AT BALANCE CALCULATION
        assert_equal(self.nodes[2].getbalance(), bal) #for now, assume the funds of a 2of3 multisig tx are not marked as spendable

        txDetails = self.nodes[0].gettransaction(txId, True)
        decrawTx = self.nodes[0].decoderawtransaction(txDetails['hex'])
        vout = False
        for outpoint in decrawTx['vout']:
            if outpoint['value'] == Decimal('2200000.00'):
                vout = outpoint
                break

        bal = self.nodes[0].getbalance()
        inputs = [{ "outpoint" : vout["outpoint"], "scriptPubKey" : vout['scriptPubKey']['hex'], "amount":str(vout['value']) }]
        outputs = { self.nodes[0].getnewaddress() : 2190000 }
        rawTx = self.nodes[2].createrawtransaction(inputs, outputs)
        rawTxPartialSigned = self.nodes[1].signrawtransaction(rawTx, inputs)
        assert_equal(rawTxPartialSigned['complete'], False) #node1 only has one key, can't comp. sign the tx
        rawTxSigned = self.nodes[2].signrawtransaction(rawTx, inputs)
        assert_equal(rawTxSigned['complete'], True) #node2 can sign the tx compl., own two of 16 keys
        self.nodes[2].enqueuerawtransaction(rawTxSigned['hex'],"flush")
        rawTx = self.nodes[0].decoderawtransaction(rawTxSigned['hex'])
        self.sync_all()

        # Fork should be active after the next block mined (median time will be greater than or equal to blocktime)
        logging.info("activate fork")
        mocktime = mocktime + 120
        self.nodes[0].setmocktime(mocktime)
        self.nodes[1].setmocktime(mocktime)
        self.nodes[2].setmocktime(mocktime)
        self.nodes[2].generate(1)
        self.sync_blocks()
        blockchaininfo = self.nodes[2].getblockchaininfo()
        assert_equal(blockchaininfo['forkactive'], True)
        assert_equal(blockchaininfo['forkenforcednextblock'], True)

        # Check balance - NOTE: after the fork on mainnet and we remove the forking upgrade test we still
        # need to keep this line as it is part of the above test that we will be keeping.
        assert_equal(self.nodes[0].getbalance(), bal+COINBASE_REWARD+Decimal('2190000.00')) #block reward + tx


        # after the hardfork is activated try to create one with 17 pubkeys
        logging.info("post fork testing")
        try:
            mSigObj = self.nodes[2].addmultisigaddress(2, [addr1Obj['pubkey'], addr2Obj['pubkey'], addr3Obj['pubkey'], addr4Obj['pubkey'], addr5Obj['pubkey'], addr6Obj['pubkey'], addr7Obj['pubkey'], addr8Obj['pubkey'], addr9Obj['pubkey'], addr10Obj['pubkey'],addr11Obj['pubkey'],addr12Obj['pubkey'],addr13Obj['pubkey'],addr14Obj['pubkey'], addr15Obj['pubkey'],addr16Obj['pubkey'], addr17Obj['pubkey']])
        except JSONRPCException as e:
            assert(e.error["message"] == "Number of addresses involved in the multisignature address creation > 16")


        # Create one with the maximum of 16 pubkeys
        bal = self.nodes[2].getbalance()
        mSigObj = self.nodes[2].addmultisigaddress(2, [addr1Obj['pubkey'], addr2Obj['pubkey'], addr3Obj['pubkey'], addr4Obj['pubkey'], addr5Obj['pubkey'], addr6Obj['pubkey'], addr7Obj['pubkey'], addr8Obj['pubkey'], addr9Obj['pubkey'], addr10Obj['pubkey'],addr11Obj['pubkey'],addr12Obj['pubkey'],addr13Obj['pubkey'],addr14Obj['pubkey'], addr15Obj['pubkey'], addr16Obj['pubkey']])

        txId = self.nodes[0].sendtoaddress(mSigObj, 2200000)
        decTx = self.nodes[0].gettransaction(txId)
        rawTx = self.nodes[0].decoderawtransaction(decTx['hex'])
        sPK = rawTx['vout'][0]['scriptPubKey']['hex']
        self.nodes[0].generate(1)
        self.sync_blocks()
        blockchaininfo = self.nodes[2].getblockchaininfo()
        assert_equal(blockchaininfo['forkactive'], True)
        assert_equal(blockchaininfo['forkenforcednextblock'], False)

        #THIS IS A INCOMPLETE FEATURE
        #NODE2 HAS TWO OF THREE KEY AND THE FUNDS SHOULD BE SPENDABLE AND COUNT AT BALANCE CALCULATION
        assert_equal(self.nodes[2].getbalance(), bal) #for now, assume the funds of a 2of3 multisig tx are not marked as spendable

        txDetails = self.nodes[0].gettransaction(txId, True)
        decrawTx = self.nodes[0].decoderawtransaction(txDetails['hex'])
        vout = False
        for outpoint in decrawTx['vout']:
            if outpoint['value'] == Decimal('2200000.00'):
                vout = outpoint
                break

        bal = self.nodes[0].getbalance()
        inputs = [{ "outpoint" : vout["outpoint"], "scriptPubKey" : vout['scriptPubKey']['hex'], "amount":str(vout['value']) }]
        outputs = { self.nodes[0].getnewaddress() : 2190000 }
        rawTx = self.nodes[2].createrawtransaction(inputs, outputs)
        rawTxPartialSigned = self.nodes[1].signrawtransaction(rawTx, inputs)
        assert_equal(rawTxPartialSigned['complete'], False) #node1 only has one key, can't comp. sign the tx
        rawTxSigned = self.nodes[2].signrawtransaction(rawTx, inputs)
        assert_equal(rawTxSigned['complete'], True) #node2 can sign the tx compl., own two of 16 keys
        self.nodes[2].enqueuerawtransaction(rawTxSigned['hex'],"flush")
        rawTx = self.nodes[0].decoderawtransaction(rawTxSigned['hex'])
        self.sync_all()
        self.nodes[0].generate(1)
        self.sync_blocks()
        assert_equal(self.nodes[0].getbalance(), bal+COINBASE_REWARD+Decimal('2190000.00')) #block reward + tx

        ### More testing of different multisigs
        logging.info("additional multisig tests")
        # 1 of 16, only last key signed.
        mSigObj = self.nodes[2].addmultisigaddress(1, [addr1Obj['pubkey'], addr2Obj['pubkey'], addr3Obj['pubkey'], addr4Obj['pubkey'], addr5Obj['pubkey'], addr6Obj['pubkey'], addr7Obj['pubkey'], addr8Obj['pubkey'], addr9Obj['pubkey'], addr10Obj['pubkey'],addr11Obj['pubkey'],addr12Obj['pubkey'],addr13Obj['pubkey'],addr14Obj['pubkey'], addr15Obj['pubkey'], addr01Obj['pubkey']])
        mSigObj = self.nodes[1].addmultisigaddress(1, [addr1Obj['pubkey'], addr2Obj['pubkey'], addr3Obj['pubkey'], addr4Obj['pubkey'], addr5Obj['pubkey'], addr6Obj['pubkey'], addr7Obj['pubkey'], addr8Obj['pubkey'], addr9Obj['pubkey'], addr10Obj['pubkey'],addr11Obj['pubkey'],addr12Obj['pubkey'],addr13Obj['pubkey'],addr14Obj['pubkey'], addr15Obj['pubkey'], addr01Obj['pubkey']])
        mSigObj = self.nodes[0].addmultisigaddress(1, [addr1Obj['pubkey'], addr2Obj['pubkey'], addr3Obj['pubkey'], addr4Obj['pubkey'], addr5Obj['pubkey'], addr6Obj['pubkey'], addr7Obj['pubkey'], addr8Obj['pubkey'], addr9Obj['pubkey'], addr10Obj['pubkey'],addr11Obj['pubkey'],addr12Obj['pubkey'],addr13Obj['pubkey'],addr14Obj['pubkey'], addr15Obj['pubkey'], addr01Obj['pubkey']])

        txId = self.nodes[0].sendtoaddress(mSigObj, 2200000)
        self.nodes[0].generate(1)
        self.sync_blocks()

        txDetails = self.nodes[0].gettransaction(txId, True)
        decrawTx2 = self.nodes[0].decoderawtransaction(txDetails['hex'])
        vout = False
        for outpoint in decrawTx2['vout']:
            if outpoint['value'] == Decimal('2200000.00'):
                vout = outpoint
                break

        inputs = [{ "outpoint" : vout["outpoint"], "scriptPubKey" : vout['scriptPubKey']['hex'], "amount":str(vout['value']) }]
        outputs = { self.nodes[0].getnewaddress() : 2190000 }
        rawTx2 = self.nodes[0].createrawtransaction(inputs, outputs)
        rawTxPartialSigned2 = self.nodes[0].signrawtransaction(rawTx2, inputs)
        assert_equal(rawTxPartialSigned2['complete'], True)

        # 1 of 16, only first key signed.
        mSigObj = self.nodes[2].addmultisigaddress(1, [addr01Obj['pubkey'], addr2Obj['pubkey'], addr3Obj['pubkey'], addr4Obj['pubkey'], addr5Obj['pubkey'], addr6Obj['pubkey'], addr7Obj['pubkey'], addr8Obj['pubkey'], addr9Obj['pubkey'], addr10Obj['pubkey'],addr11Obj['pubkey'],addr12Obj['pubkey'],addr13Obj['pubkey'],addr14Obj['pubkey'], addr15Obj['pubkey'], addr16Obj['pubkey']])
        mSigObj = self.nodes[1].addmultisigaddress(1, [addr01Obj['pubkey'], addr2Obj['pubkey'], addr3Obj['pubkey'], addr4Obj['pubkey'], addr5Obj['pubkey'], addr6Obj['pubkey'], addr7Obj['pubkey'], addr8Obj['pubkey'], addr9Obj['pubkey'], addr10Obj['pubkey'],addr11Obj['pubkey'],addr12Obj['pubkey'],addr13Obj['pubkey'],addr14Obj['pubkey'], addr15Obj['pubkey'], addr16Obj['pubkey']])
        mSigObj = self.nodes[0].addmultisigaddress(1, [addr01Obj['pubkey'], addr2Obj['pubkey'], addr3Obj['pubkey'], addr4Obj['pubkey'], addr5Obj['pubkey'], addr6Obj['pubkey'], addr7Obj['pubkey'], addr8Obj['pubkey'], addr9Obj['pubkey'], addr10Obj['pubkey'],addr11Obj['pubkey'],addr12Obj['pubkey'],addr13Obj['pubkey'],addr14Obj['pubkey'], addr15Obj['pubkey'], addr16Obj['pubkey']])

        txId = self.nodes[0].sendtoaddress(mSigObj, 2200000)
        self.nodes[0].generate(1)
        self.sync_blocks()

        txDetails = self.nodes[0].gettransaction(txId, True)
        decrawTx2 = self.nodes[0].decoderawtransaction(txDetails['hex'])
        vout = False
        for outpoint in decrawTx2['vout']:
            if outpoint['value'] == Decimal('2200000.00'):
                vout = outpoint
                break

        inputs = [{ "outpoint" : vout["outpoint"], "scriptPubKey" : vout['scriptPubKey']['hex'], "amount":str(vout['value']) }]
        outputs = { self.nodes[0].getnewaddress() : 2190000 }
        rawTx2 = self.nodes[0].createrawtransaction(inputs, outputs)
        rawTxPartialSigned2 = self.nodes[0].signrawtransaction(rawTx2, inputs)
        assert_equal(rawTxPartialSigned2['complete'], True)

        # 1 of 16, only middle key signed.
        mSigObj = self.nodes[2].addmultisigaddress(1, [addr1Obj['pubkey'], addr2Obj['pubkey'], addr3Obj['pubkey'], addr4Obj['pubkey'], addr5Obj['pubkey'], addr6Obj['pubkey'], addr7Obj['pubkey'], addr01Obj['pubkey'], addr9Obj['pubkey'], addr10Obj['pubkey'],addr11Obj['pubkey'],addr12Obj['pubkey'],addr13Obj['pubkey'],addr14Obj['pubkey'], addr15Obj['pubkey'], addr16Obj['pubkey']])
        mSigObj = self.nodes[1].addmultisigaddress(1, [addr1Obj['pubkey'], addr2Obj['pubkey'], addr3Obj['pubkey'], addr4Obj['pubkey'], addr5Obj['pubkey'], addr6Obj['pubkey'], addr7Obj['pubkey'], addr01Obj['pubkey'], addr9Obj['pubkey'], addr10Obj['pubkey'],addr11Obj['pubkey'],addr12Obj['pubkey'],addr13Obj['pubkey'],addr14Obj['pubkey'], addr15Obj['pubkey'], addr16Obj['pubkey']])
        mSigObj = self.nodes[0].addmultisigaddress(1, [addr1Obj['pubkey'], addr2Obj['pubkey'], addr3Obj['pubkey'], addr4Obj['pubkey'], addr5Obj['pubkey'], addr6Obj['pubkey'], addr7Obj['pubkey'], addr01Obj['pubkey'], addr9Obj['pubkey'], addr10Obj['pubkey'],addr11Obj['pubkey'],addr12Obj['pubkey'],addr13Obj['pubkey'],addr14Obj['pubkey'], addr15Obj['pubkey'], addr16Obj['pubkey']])

        txId = self.nodes[0].sendtoaddress(mSigObj, 2200000)
        self.nodes[0].generate(1)
        self.sync_blocks()

        txDetails = self.nodes[0].gettransaction(txId, True)
        decrawTx2 = self.nodes[0].decoderawtransaction(txDetails['hex'])
        vout = False
        for outpoint in decrawTx2['vout']:
            if outpoint['value'] == Decimal('2200000.00'):
                vout = outpoint
                break

        inputs = [{ "outpoint" : vout["outpoint"], "scriptPubKey" : vout['scriptPubKey']['hex'], "amount":str(vout['value']) }]
        outputs = { self.nodes[0].getnewaddress() : 2190000 }
        rawTx2 = self.nodes[0].createrawtransaction(inputs, outputs)
        rawTxPartialSigned2 = self.nodes[0].signrawtransaction(rawTx2, inputs)
        assert_equal(rawTxPartialSigned2['complete'], True)

        # 2 of 16, only first and last key signed.
        mSigObj = self.nodes[2].addmultisigaddress(2, [addr01Obj['pubkey'], addr2Obj['pubkey'], addr3Obj['pubkey'], addr4Obj['pubkey'], addr5Obj['pubkey'], addr6Obj['pubkey'], addr7Obj['pubkey'], addr8Obj['pubkey'], addr9Obj['pubkey'], addr10Obj['pubkey'],addr11Obj['pubkey'],addr12Obj['pubkey'],addr13Obj['pubkey'],addr14Obj['pubkey'], addr15Obj['pubkey'], addr02Obj['pubkey']])
        mSigObj = self.nodes[1].addmultisigaddress(2, [addr01Obj['pubkey'], addr2Obj['pubkey'], addr3Obj['pubkey'], addr4Obj['pubkey'], addr5Obj['pubkey'], addr6Obj['pubkey'], addr7Obj['pubkey'], addr8Obj['pubkey'], addr9Obj['pubkey'], addr10Obj['pubkey'],addr11Obj['pubkey'],addr12Obj['pubkey'],addr13Obj['pubkey'],addr14Obj['pubkey'], addr15Obj['pubkey'], addr02Obj['pubkey']])
        mSigObj = self.nodes[0].addmultisigaddress(2, [addr01Obj['pubkey'], addr2Obj['pubkey'], addr3Obj['pubkey'], addr4Obj['pubkey'], addr5Obj['pubkey'], addr6Obj['pubkey'], addr7Obj['pubkey'], addr8Obj['pubkey'], addr9Obj['pubkey'], addr10Obj['pubkey'],addr11Obj['pubkey'],addr12Obj['pubkey'],addr13Obj['pubkey'],addr14Obj['pubkey'], addr15Obj['pubkey'], addr02Obj['pubkey']])

        txId = self.nodes[0].sendtoaddress(mSigObj, 2200000)
        self.nodes[0].generate(1)
        self.sync_blocks()

        txDetails = self.nodes[0].gettransaction(txId, True)
        decrawTx2 = self.nodes[0].decoderawtransaction(txDetails['hex'])
        vout = False
        for outpoint in decrawTx2['vout']:
            if outpoint['value'] == Decimal('2200000.00'):
                vout = outpoint
                break

        inputs = [{ "outpoint" : vout["outpoint"], "scriptPubKey" : vout['scriptPubKey']['hex'], "amount":str(vout['value']) }]
        outputs = { self.nodes[0].getnewaddress() : 2190000 }
        rawTx2 = self.nodes[0].createrawtransaction(inputs, outputs)
        rawTxPartialSigned2 = self.nodes[0].signrawtransaction(rawTx2, inputs)
        assert_equal(rawTxPartialSigned2['complete'], True)

        # test for 3 of 5 multisig
        mSigObj = self.nodes[2].addmultisigaddress(3, [addr01Obj['pubkey'], addr02Obj['pubkey'], addr1Obj['pubkey'], addr4Obj['pubkey'], addr5Obj['pubkey']])
        mSigObj = self.nodes[1].addmultisigaddress(3, [addr01Obj['pubkey'], addr02Obj['pubkey'], addr1Obj['pubkey'], addr4Obj['pubkey'], addr5Obj['pubkey']])
        mSigObj = self.nodes[0].addmultisigaddress(3, [addr01Obj['pubkey'], addr02Obj['pubkey'], addr1Obj['pubkey'], addr4Obj['pubkey'], addr5Obj['pubkey']])

        txId = self.nodes[0].sendtoaddress(mSigObj, 2200000)
        self.nodes[0].generate(1)
        self.sync_blocks()

        txDetails = self.nodes[0].gettransaction(txId, True)
        decrawTx2 = self.nodes[0].decoderawtransaction(txDetails['hex'])
        vout = False
        for outpoint in decrawTx2['vout']:
            if outpoint['value'] == Decimal('2200000.00'):
                vout = outpoint
                break

        inputs = [{ "outpoint" : vout["outpoint"], "scriptPubKey" : vout['scriptPubKey']['hex'], "amount":str(vout['value']) }]
        outputs = { self.nodes[0].getnewaddress() : 2190000 }
        rawTx2 = self.nodes[0].createrawtransaction(inputs, outputs)

        # partially sign the transaction. Using node 0 there are 2 keys that will be signing.
        rawTxPartialSigned2 = self.nodes[0].signrawtransaction(rawTx2, inputs)
        assert_equal(rawTxPartialSigned2['complete'], False)

        # now sign the partially signed transaction using node 1 which has the final 3rd key needed.
        rawTxSigned = self.nodes[1].signrawtransaction(rawTxPartialSigned2['hex'], inputs)
        assert_equal(rawTxSigned['complete'], True)
        self.nodes[2].enqueuerawtransaction(rawTxSigned['hex'],"flush")
        rawTx = self.nodes[0].decoderawtransaction(rawTxSigned['hex'])

        # test for 5 of 5 multisig
        mSigObj = self.nodes[2].addmultisigaddress(5, [addr01Obj['pubkey'], addr02Obj['pubkey'], addr1Obj['pubkey'], addr4Obj['pubkey'], addr5Obj['pubkey']])
        mSigObj = self.nodes[1].addmultisigaddress(5, [addr01Obj['pubkey'], addr02Obj['pubkey'], addr1Obj['pubkey'], addr4Obj['pubkey'], addr5Obj['pubkey']])
        mSigObj = self.nodes[0].addmultisigaddress(5, [addr01Obj['pubkey'], addr02Obj['pubkey'], addr1Obj['pubkey'], addr4Obj['pubkey'], addr5Obj['pubkey']])

        txId = self.nodes[0].sendtoaddress(mSigObj, 2200000)
        self.nodes[0].generate(1)
        self.sync_blocks()

        txDetails = self.nodes[0].gettransaction(txId, True)
        decrawTx2 = self.nodes[0].decoderawtransaction(txDetails['hex'])
        vout = False
        for outpoint in decrawTx2['vout']:
            if outpoint['value'] == Decimal('2200000.00'):
                vout = outpoint
                break

        inputs = [{ "outpoint" : vout["outpoint"], "scriptPubKey" : vout['scriptPubKey']['hex'], "amount":str(vout['value']) }]
        outputs = { self.nodes[0].getnewaddress() : 2190000 }
        rawTx2 = self.nodes[0].createrawtransaction(inputs, outputs)

        # partially sign the transaction. Using node 0 there are 2 keys that will be signing.
        rawTxPartialSigned2 = self.nodes[0].signrawtransaction(rawTx2, inputs)
        assert_equal(rawTxPartialSigned2['complete'], False)

        # now sign the partially signed transaction using node 1
        rawTxPartialSigned3 = self.nodes[1].signrawtransaction(rawTxPartialSigned2['hex'], inputs)
        assert_equal(rawTxPartialSigned3['complete'], False)

        # now sign the partially signed transaction using node 3 which has all the final keys needed
        rawTxSigned = self.nodes[2].signrawtransaction(rawTxPartialSigned3['hex'], inputs)
        assert_equal(rawTxSigned['complete'], True)

        self.nodes[2].enqueuerawtransaction(rawTxSigned['hex'],"flush")
        rawTx = self.nodes[0].decoderawtransaction(rawTxSigned['hex'])

        self.sync_all()
        self.nodes[0].generate(1)
        self.sync_blocks()

        #########################################
        # standard/nonstandard sendrawtransaction
        #########################################

        logging.info("standard and nonstandard sendrawtransaction")
        wallet = self.nodes[0].listunspent()
        wallet.sort(key=lambda x: x["amount"], reverse=False)
        utxo = wallet.pop()
        amt = utxo["amount"]
        addr = self.nodes[0].getaddressforms(self.nodes[0].getnewaddress("p2pkh"))["legacy"]
        outp = {addr: amt-decimal.Decimal(100)}  # give some fee
        txn = createrawtransaction([utxo], outp, createWastefulOutput)  # create a nonstandard tx
        signedtxn = self.nodes[0].signrawtransaction(txn)
        txpool = self.nodes[0].gettxpoolinfo()
        try:
            self.nodes[0].sendrawtransaction(signedtxn["hex"], False, "STANDARD")
            assert 0 # should have failed because I'm insisting on a standard tx
        except JSONRPCException as e:
            assert(e.error["code"] == -26)

        try:
            self.nodes[0].sendrawtransaction(signedtxn["hex"], False, "standard")
            assert 0 # should have failed, check case insensitivity
        except JSONRPCException as e:
            assert(e.error["code"] == -26)

        ret = self.nodes[0].sendrawtransaction(signedtxn["hex"], False, "NONstandard")
        assert(len(ret) == 64)  # should succeed and return a txid

        # In regtest mode, nonstandard transactions are allowed by default
        ret2 = self.nodes[0].sendrawtransaction(signedtxn["hex"], False, "default")
        assert ret == ret2  # I'm sending the same tx so it should work with the same result

        txpool2 = self.nodes[0].gettxpoolinfo()
        assert txpool["size"] + 1 == txpool2["size"]  # one tx should have been added to the txpool

        self.nodes[0].generate(1)  # clean it up
        txpool3 = self.nodes[0].gettxpoolinfo()
        assert txpool3["size"] == 0  # Check that the nonstandard tx in the txpool got mined

        # Now try it as if we were on mainnet (rejecting nonstandard transactions)
        stop_nodes(self.nodes)
        wait_bitcoinds()
        # restart the node with a flag that forces the behavior to be more like mainnet -- don't accept nonstandard tx
        self.nodes = start_nodes(3, self.options.tmpdir, [ ["--acceptnonstdtxn=0"], [], [], []])
        connect_nodes_full(self.nodes)

        wallet = self.nodes[0].listunspent()
        wallet.sort(key=lambda x: x["amount"], reverse=False)
        utxo = wallet.pop()
        amt = utxo["amount"]
        addr = self.nodes[0].getaddressforms(self.nodes[0].getnewaddress())["legacy"]
        outp = {addr: amt-decimal.Decimal(100)}  # give some fee
        txn = createrawtransaction([utxo], outp, createWastefulOutput)  # create a nonstandard tx
        signedtxn = self.nodes[0].signrawtransaction(txn)
        txpool = self.nodes[0].gettxpoolinfo()
        try:
            self.nodes[0].sendrawtransaction(signedtxn["hex"])
            assert 0 # should have failed because I'm insisting on a standard tx
        except JSONRPCException as e:
            assert e.error["code"] == -26
        try:
            self.nodes[0].sendrawtransaction(signedtxn["hex"], False, "STANDARD")
            assert 0 # should have failed because I'm insisting on a standard tx
        except JSONRPCException as e:
            assert e.error["code"] == -26
        try:
            self.nodes[0].sendrawtransaction(signedtxn["hex"], False, "default")
            assert 0 # should have failed because I'm insisting on a standard tx via the --acceptnonstdtxn flag
        except JSONRPCException as e:
            assert e.error["code"] == -26

        try:
            self.nodes[0].sendrawtransaction(signedtxn["hex"], False, "somebadvalue")
            assert 0 # should have failed because I'm insisting on a standard tx via the --acceptnonstdtxn flag
        except JSONRPCException as e:
            assert e.error["code"] == -8
            assert e.error["message"] == 'Invalid transaction class'
        txpool4 = self.nodes[0].gettxpoolinfo()
        assert txpool["size"] == txpool4["size"]  # all of these failures should have added nothing to txpool

        ret = self.nodes[0].sendrawtransaction(signedtxn["hex"], False, "nonstandard")
        assert(len(ret) == 64)  # should succeed and return a txid
        txpool2 = self.nodes[0].gettxpoolinfo()
        assert txpool["size"] + 1 == txpool2["size"]  # one tx should have been added to the txpool

        self.nodes[0].generate(1)  # clean it up
        txpool3 = self.nodes[0].gettxpoolinfo()
        assert txpool3["size"] == 0  # Check that the nonstandard tx in the txpool got mined

        # finally, let's make sure that a standard tx works with the standard flag set
        utxo = wallet.pop()
        amt = utxo["amount"]
        addr = self.nodes[0].getaddressforms(self.nodes[0].getnewaddress("p2pkh"))["legacy"]
        outp = {addr: amt-decimal.Decimal(100)}  # give some fee
        txn = createrawtransaction([utxo], outp, p2pkh)  # create a standard tx
        signedtxn = self.nodes[0].signrawtransaction(txn)
        txid = self.nodes[0].sendrawtransaction(signedtxn["hex"], False, "STANDARD")
        assert(len(txid) == 64)

        # getrawtransaction tests
        # 1. valid parameters - only supply txid
        txHash = rawTx["txidem"]
        assert_equal(self.nodes[0].getrawtransaction(txHash), rawTxSigned['hex'])

        # 2. valid parameters - supply txid and 0 for non-verbose
        assert_equal(self.nodes[0].getrawtransaction(txHash, 0), rawTxSigned['hex'])

        # 3. valid parameters - supply txid and False for non-verbose
        assert_equal(self.nodes[0].getrawtransaction(txHash, False), rawTxSigned['hex'])

        # 4. valid parameters - supply txid and 1 for verbose.
        # We only check the "hex" field of the output so we don't need to update this test every time the output format changes.
        txn = self.nodes[0].getrawtransaction(txid, 1)
        assert_equal(txn["hex"], signedtxn['hex'])
        assert_equal(txn['in_txpool'], True)
        assert_equal(txn['in_orphanpool'], False)

        # 4a. valid parameters - supply a txid that is in the orphanpool
        unknown_txid = "c5c6ef8d06b90564e6c5451d7650b8dfc44349bee73ad85519bec3d24a680f23"
        address1 = self.nodes[0].getaddressforms(self.nodes[0].getnewaddress("p2pkh"))["legacy"]
        address2 = self.nodes[0].getaddressforms(self.nodes[0].getnewaddress("p2pkh"))["legacy"]
        outputs = {address1 : 49000000, address2 : 1000000}
        inputs = []
        inputs.append({ "outpoint" : unknown_txid, "amount" : 51})
        raw_orphan = createrawtransaction(inputs, outputs) # creating an orphan tx
        signedtxn_orphan = self.nodes[0].signrawtransaction(raw_orphan)
        orphan_txid = signedtxn_orphan["txid"]
        orphan_txidem = self.nodes[0].sendrawtransaction(signedtxn_orphan["hex"], True, "standard", True)

        # Have to access via txid to get from the orphan list
        txn_orphan = self.nodes[0].getrawtransaction(orphan_txid, 1)
        assert_equal(txn_orphan["hex"], signedtxn_orphan['hex'])
        assert_equal(txn_orphan['in_txpool'], False)
        assert_equal(txn_orphan['in_orphanpool'], True)

        # 5. valid parameters - supply txid and True for non-verbose
        assert_equal(self.nodes[0].getrawtransaction(txHash, True)["hex"], rawTxSigned['hex'])

        # 6. invalid parameters - supply txid and string "Flase"
        assert_raises_rpc_error(-32700,"Error parsing JSON:Flase", self.nodes[0].getrawtransaction, txHash, "Flase")

        # 7. invalid parameters - supply txid and empty array
        assert_raises_rpc_error(-1,"not a boolean", self.nodes[0].getrawtransaction, txHash, [])

        # 8. invalid parameters - supply txid and empty dict
        assert_raises_rpc_error(-1,"not a boolean", self.nodes[0].getrawtransaction, txHash, {})

        inputs  = [ {'outpoint' : "1d1d4e24ed99057e84c3f80fd8fbec79ed9e1acee37da269356ecea000000000", 'amount' : 1, 'sequence' : 1000}]
        outputs = { self.nodes[0].getnewaddress() : 1 }
        rawtx   = self.nodes[0].createrawtransaction(inputs, outputs)
        decrawtx= self.nodes[0].decoderawtransaction(rawtx)
        assert_equal(decrawtx['vin'][0]['sequence'], 1000)


        inputs  = [ {'outpoint' : "1d1d4e24ed99057e84c3f80fd8fbec79ed9e1acee37da269356ecea000000000", 'sequence' : -1}]
        outputs = { self.nodes[0].getnewaddress() : 1 }
        assert_raises(JSONRPCException, self.nodes[0].createrawtransaction, inputs, outputs)

        inputs  = [ {'outpoint' : "1d1d4e24ed99057e84c3f80fd8fbec79ed9e1acee37da269356ecea000000000", 'amount' : "1.1", 'sequence' : -1}]
        outputs = { self.nodes[0].getnewaddress() : 1 }
        assert_raises(JSONRPCException, self.nodes[0].createrawtransaction, inputs, outputs)

        inputs  = [ {'outpoint' : "1d1d4e24ed99057e84c3f80fd8fbec79ed9e1acee37da269356ecea000000000", 'amount' : 1, 'sequence' : 4294967296}]
        outputs = { self.nodes[0].getnewaddress() : 1 }
        assert_raises(JSONRPCException, self.nodes[0].createrawtransaction, inputs, outputs)

        inputs  = [ {'outpoint' : "1d1d4e24ed99057e84c3f80fd8fbec79ed9e1acee37da269356ecea000000000", 'amount' : "1", 'sequence' : 'notanumber'}]
        outputs = { self.nodes[0].getnewaddress() : 1 }
        assert_raises(JSONRPCException, self.nodes[0].createrawtransaction, inputs, outputs)

        inputs  = [ {'outpoint' : "1d1d4e24ed99057e84c3f80fd8fbec79ed9e1acee37da269356ecea000000000", 'amount' : 1, 'sequence' : 4294967294}]
        outputs = { self.nodes[0].getnewaddress() : 1 }
        rawtx   = self.nodes[0].createrawtransaction(inputs, outputs)
        decrawtx= self.nodes[0].decoderawtransaction(rawtx)
        assert_equal(decrawtx['vin'][0]['sequence'], 4294967294)


if __name__ == '__main__':
    RawTransactionsTest().main()

def Test():
    t = RawTransactionsTest()
    t.drop_to_pdb = True
    bitcoinConf = {
        "debug": ["rpc","net", "blk", "thin", "mempool", "req", "bench", "evict"],
    }

    flags = standardFlags()
    t.main(flags, bitcoinConf, None)
