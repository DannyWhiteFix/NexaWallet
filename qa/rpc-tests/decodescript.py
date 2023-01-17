#!/usr/bin/env python3
# Copyright (c) 2015 The Bitcoin Core developers
# Copyright (c) 2015-2022 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
import test_framework.loginit
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from test_framework.script import *
from test_framework.blocktools import *
from test_framework.mininode import *
from io import BytesIO

class DecodeScriptTest(BitcoinTestFramework):
    """Tests decoding scripts via RPC command "decodescript"."""

    def setup_chain(self,bitcoinConfDict=None, wallets=None):
        print('Initializing test directory ' + self.options.tmpdir)
        initialize_chain(self.options.tmpdir, bitcoinConfDict)

    def setup_network(self, split=False):
        self.nodes = start_nodes(1, self.options.tmpdir)
        self.is_network_split = False

    def decodescript_script_sig(self):
        signature = '304502207fa7a6d1e0ee81132a269ad84e68d695483745cde8b541e3bf630749894e342a022100c1f7ab20e13e22fb95281a870f3dcf38d782e53023ee313d741ad0cfbc0c509001'
        push_signature = '48' + signature
        public_key = '03b0da749730dc9b4b1f4a14d6902877a92541f5368778853d9c4a0cb7802dcfb2'
        push_public_key = '21' + public_key

        # below are test cases for all of the standard transaction types

        # 1) P2PK scriptSig
        # the scriptSig of a public key scriptPubKey simply pushes a signature onto the stack
        rpc_result = self.nodes[0].decodescript(push_signature)
        assert_equal(signature, rpc_result['asm'])

        # 2) P2PKH scriptSig
        rpc_result = self.nodes[0].decodescript(push_signature + push_public_key)
        assert_equal(signature + ' ' + public_key, rpc_result['asm'])

        # 3) multisig scriptSig
        # this also tests the leading portion of a P2SH multisig scriptSig
        # OP_0 <A sig> <B sig>
        rpc_result = self.nodes[0].decodescript('00' + push_signature + push_signature)
        assert_equal('0 ' + signature + ' ' + signature, rpc_result['asm'])

        # 4) P2SH scriptSig
        # an empty P2SH redeemScript is valid and makes for a very simple test case.
        # thus, such a spending scriptSig would just need to pass the outer redeemScript
        # hash test and leave true on the top of the stack.
        rpc_result = self.nodes[0].decodescript('5100')
        assert_equal('1 0', rpc_result['asm'])

        # 5) null data scriptSig - no such thing because null data scripts can not be spent.
        # thus, no test case for that standard transaction type is here.

    def decodescript_script_pub_key(self):
        public_key = '03b0da749730dc9b4b1f4a14d6902877a92541f5368778853d9c4a0cb7802dcfb2'
        push_public_key = '21' + public_key
        public_key_hash = '11695b6cd891484c2d49ec5aa738ec2b2f897777'
        push_public_key_hash = '14' + public_key_hash

        # below are test cases for all of the standard transaction types

        # 1) P2PK scriptPubKey
        # <pubkey> OP_CHECKSIG
        rpc_result = self.nodes[0].decodescript(push_public_key + 'ac')
        assert_equal(public_key + ' OP_CHECKSIG', rpc_result['asm'])

        # 2) P2PKH scriptPubKey
        # OP_DUP OP_HASH160 <PubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
        rpc_result = self.nodes[0].decodescript('76a9' + push_public_key_hash + '88ac')
        assert_equal('OP_DUP OP_HASH160 ' + public_key_hash + ' OP_EQUALVERIFY OP_CHECKSIG', rpc_result['asm'])

        # 3) multisig scriptPubKey
        # <m> <A pubkey> <B pubkey> <C pubkey> <n> OP_CHECKMULTISIG
        # just imagine that the pub keys used below are different.
        # for our purposes here it does not matter that they are the same even though it is unrealistic.
        rpc_result = self.nodes[0].decodescript('52' + push_public_key + push_public_key + push_public_key + '53ae')
        assert_equal('2 ' + public_key + ' ' + public_key + ' ' + public_key +  ' 3 OP_CHECKMULTISIG', rpc_result['asm'])

        # 4) P2SH scriptPubKey
        # OP_HASH160 <Hash160(redeemScript)> OP_EQUAL.
        # push_public_key_hash here should actually be the hash of a redeem script.
        # but this works the same for purposes of this test.
        rpc_result = self.nodes[0].decodescript('a9' + push_public_key_hash + '87')
        assert_equal('OP_HASH160 ' + public_key_hash + ' OP_EQUAL', rpc_result['asm'])

        # 5) null data scriptPubKey
        # use a signature look-alike here to make sure that we do not decode random data as a signature.
        # this matters if/when signature sighash decoding comes along.
        # would want to make sure that no such decoding takes place in this case.
        signature_imposter = '48304502207fa7a6d1e0ee81132a269ad84e68d695483745cde8b541e3bf630749894e342a022100c1f7ab20e13e22fb95281a870f3dcf38d782e53023ee313d741ad0cfbc0c509001'
        # OP_RETURN <data>
        rpc_result = self.nodes[0].decodescript('6a' + signature_imposter)
        assert_equal('OP_RETURN ' + signature_imposter[2:], rpc_result['asm'])

        # 6) a CLTV redeem script. redeem scripts are in-effect scriptPubKey scripts, so adding a test here.
        # OP_NOP2 is also known as OP_CHECKLOCKTIMEVERIFY.
        # just imagine that the pub keys used below are different.
        # for our purposes here it does not matter that they are the same even though it is unrealistic.
        #
        # OP_IF
        #   <receiver-pubkey> OP_CHECKSIGVERIFY
        # OP_ELSE
        #   <lock-until> OP_CHECKLOCKTIMEVERIFY OP_DROP
        # OP_ENDIF
        # <sender-pubkey> OP_CHECKSIG
        #
        # lock until block 500,000
        rpc_result = self.nodes[0].decodescript('63' + push_public_key + 'ad670320a107b17568' + push_public_key + 'ac')
        assert_equal('OP_IF ' + public_key + ' OP_CHECKSIGVERIFY OP_ELSE 500000 OP_CHECKLOCKTIMEVERIFY OP_DROP OP_ENDIF ' + public_key + ' OP_CHECKSIG', rpc_result['asm'])

    def decoderawtransaction_asm_sighashtype(self):
        """Tests decoding scripts via RPC command "decoderawtransaction".

        This test is in with the "decodescript" tests because they are testing the same "asm" script decodes.
        """
        # tx = CTransaction()
        #tx.vin = [ CTxIn(COutPoint(bytes(range(0,32))), 1000, CScript([OP_NOP]))]
        #tx.vout = [ TxOut(0, 1000, p2pkh(addr))]
        #txhex = tx.toHex()
        #rpc_result = self.nodes[0].decoderawtransaction(txhex)

        # TODO: add constant transactions
        node = self.nodes[0]

        addr = node.getnewaddress()
        txidem = node.sendtoaddress(addr, 1000000)
        txhex = node.getrawtransaction(txidem)
        decode = node.decoderawtransaction(txhex)
        # standard sighashtype for our signing
        assert "[ALL]" in decode["vin"][0]["scriptSig"]["asm"]
        hexScriptSig = decode["vin"][0]["scriptSig"]["hex"]

        # now we'll put in other sighashtypes.  Even though the sig will be bad, decoderawtransaction does not care
        txSave = CTransaction(txhex)
        origSatisfier = txSave.vin[0].scriptSig
        modSatisfier = bytearray(txSave.vin[0].scriptSig)
        modSatisfier[35] = 65 # make the serialized sig vector one longer

        txSave.vin[0].scriptSig = bytes(modSatisfier) + bytes([0x20])  # Lop off the sighash type (last byte) and add another
        decode = node.decoderawtransaction(txSave.toHex())
        assert "[THIS_IN|ALL_OUT]" in decode["vin"][0]["scriptSig"]["asm"]

        signature_sighash_decoded = decode["vin"][0]["scriptSig"]["asm"].split()[1]
        modSatisfier[35] = 67 # make the serialized sig vector longer
        txSave.vin[0].scriptSig = bytes(modSatisfier) + bytes([0x11, 0x20, 0x10])  # Lop off the sighash type (last byte) and add another
        decode = node.decoderawtransaction(txSave.toHex())
        assert "[FIRST_32_IN|FIRST_16_OUT]" in decode["vin"][0]["scriptSig"]["asm"]
        signature_2_sighash_decoded = decode["vin"][0]["scriptSig"]["asm"].split()[1]

        # 2) multisig scriptSig
        sig = CScript(origSatisfier).nth(1)
        assert len(sig) == 64 # its ALL/ALL
        s1 = sig + bytes([0x20])
        s2 = sig + bytes([0x11, 0x20,  0x10])
        txSave.vin[0].scriptSig = CScript([ 0, s1, s2])
        rpc_result = self.nodes[0].decoderawtransaction(bytes_to_hex_str(txSave.serialize()))
        # '0 8bb45fa8b774a4c39151f87ff9c871e2511c83fdbce1c7f40f3cd824fab420356de3b710cd49863b7838d557d243d410502c8c7e9247823ef9ec3495a10ad4ab[THIS_IN | ALL_OUT] 8bb45fa8b774a4c39151f87ff9c871e2511c83fdbce1c7f40f3cd824fab420356de3b710cd49863b7838d557d243d410502c8c7e9247823ef9ec3495a10ad4ab[FIRST_0_IN | 0_0_OUT]'
        assert_equal('0 ' + signature_sighash_decoded + ' ' + signature_2_sighash_decoded, rpc_result['vin'][0]['scriptSig']['asm'])

        # 3) test a scriptSig that contains more than push operations.
        # in fact, it contains an OP_RETURN with data specially crafted to cause improper decode if the code does not catch it.
        txSave.vin[0].scriptSig = hex_str_to_bytes('6a143011020701010101010101020601010101010101')
        rpc_result = self.nodes[0].decoderawtransaction(bytes_to_hex_str(txSave.serialize()))
        assert_equal('OP_RETURN 3011020701010101010101020601010101010101', rpc_result['vin'][0]['scriptSig']['asm'])

    def run_test(self):
        self.decodescript_script_sig()
        self.decodescript_script_pub_key()
        self.decoderawtransaction_asm_sighashtype()

if __name__ == '__main__':
    DecodeScriptTest().main()

# Create a convenient function for an interactive python debugging session
def Test():
    t = DecodeScriptTest()
    t.drop_to_pdb = True
    # install ctrl-c handler
    #import signal, pdb
    #signal.signal(signal.SIGINT, lambda sig, stk: pdb.Pdb().set_trace(stk))
    bitcoinConf = {
        "debug": ["net", "blk", "thin", "mempool", "req", "bench", "evict"],
    }
    flags = standardFlags()
    t.main(flags, bitcoinConf, None)
