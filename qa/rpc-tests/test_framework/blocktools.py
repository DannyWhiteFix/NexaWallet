#!/usr/bin/env python3
# blocktools.py - utilities for manipulating blocks and transactions
# Copyright (c) 2015-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
import pdb
import binascii
import random
import copy

from .script import CScript
from .scriptop import OP_TRUE, OP_CHECKSIG, OP_DROP, OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG, OP_RETURN, OP_NOP
from .util import BTC, COINBASE_REWARD, uint256ToRpcHex, rpcHexToUint256
from .mininode import *

import test_framework.cashaddr as cashaddr

# Minimum size a transaction can have.
MIN_TX_SIZE = 100

# Maximum bytes in a TxOut pubkey script
MAX_TXOUT_PUBKEY_SCRIPT = 10000

def getAncHash(height, node):
    return rpcHexToUint256(node.getblockheader(ancestorHeight(height))["hash"])

def ancestorHeight(height):
    assert height != 0  # ancestor height of GB is undefined (hash is all 0s)
    if height & 1 == 0:
        return height & (height - 1)
    else:
        return max(0, height - 5040)

# Create a block (with regtest difficulty)
def create_block(hashprev, height, chainwork, coinbase, hashAncestor, nTime=None, txns=None, ctor=True):
    block = CBlock()
    if nTime is None:
        import time
        block.nTime = int(time.time()+600)
    else:
        if type(nTime) is not int:
            raise ValueError("nTime should be int, got {}".format(type(nTime)))
        block.nTime = nTime
    if type(hashprev) is str:
        hashprev = uint256_from_bigendian(hashprev)
    block.chainWork = chainwork
    block.height = height
    block.hashPrevBlock = hashprev
    block.hashAncestor = hashAncestor
    block.nBits = 0x207fffff # Will break after a difficulty adjustment... which never happens in regtest
    if coinbase:
        block.vtx.append(coinbase)
    if txns:
        if ctor:
            txns.sort(key=lambda x: uint256ToRpcHex(x.GetId()))
        block.vtx += txns
    block.txCount = len(block.vtx)
    block.nonce = b""
    block.utxoCommitment = b""
    block.minerData = b""
    block.nonce = bytearray(3)
    block.update_fields()
    return block

# Create large OP_RETURN txouts that can be appended to a transaction
# to make it large (helper for constructing large transactions).
def gen_return_txouts():
    # Some pre-processing to create a bunch of OP_RETURN txouts to insert into transactions we create
    # So we have big transactions (and therefore can't fit very many into each block)
    # create one script_pubkey
    script_pubkey = "6a4d0200" #OP_RETURN OP_PUSH2 512 bytes
    for i in range(1024):
        script_pubkey = script_pubkey + "01"
    constraint = bytes.fromhex(script_pubkey) #CScript(script_pubkey)
    # concatenate 63 txouts of above script_pubkey which we'll insert before the txout for change
    txouts = []
    for k in range(63):
        tmp = TxOut(0,0,constraint)
        txouts.append(tmp)
    return txouts

# Create a spend of each passed-in utxo, splicing in "txouts" to each raw
# transaction to make it large.  See gen_return_txouts() above.
def create_lots_of_big_transactions(node, txouts, utxos, num, feePerKb):
    addr = node.getnewaddress("p2pkh")
    txidems = []
    txids = []
    fee = 0
    for i in range(num):
        t = utxos.pop()
        tx = CTransaction()
        tx.vin = [ CTxIn(COutPoint(t["outpoint"]), t["amount"])]
        tx.vout = copy.copy(txouts)
        send_value = t['amount'] - fee
        tx.vout.append(TxOut(0,send_value, p2pkh(addr)))
        newtx = tx.serialize().hex()
        if fee==0:
            fee = decimal.Decimal(1)/COIN+(66 + int(len(newtx)/2))*feePerKb/1024  # 66 is approx size of satisfier script for 1 sig
            send_value = t['amount'] - fee
            tx.vout[-1].nValue = send_value
            newtx = tx.serialize().hex()

        signresult = node.signrawtransaction(newtx, None, None, "ALL")
        txids.append(signresult["txid"])
        txidem = node.sendrawtransaction(signresult["hex"], True)
        txidems.append(txidem)
    return (txidems, txids)

def make_conform_to_ctor(block):
    for tx in block.vtx:
        tx.rehash()
    block.vtx = [block.vtx[0]] + \
        sorted(block.vtx[1:], key=lambda tx: uint256ToRpcHex(tx.GetId()))

def serialize_script_num(value):
    r = bytearray(0)
    if value == 0:
        return r
    neg = value < 0
    absvalue = -value if neg else value
    while (absvalue):
        r.append(int(absvalue & 0xff))
        absvalue >>= 8
    if r[-1] & 0x80:
        r.append(0x80 if neg else 0)
    elif neg:
        r[-1] |= 0x80
    return r

# Create a coinbase transaction, assuming no miner fees.
# If pubkey is passed in, the coinbase output will be a P2PK output;
# otherwise an anyone-can-spend output.
def create_coinbase(height, pubkey = None, scriptPubKey = None):
    assert not (pubkey and scriptPubKey), "cannot both have pubkey and custom scriptPubKey"
    coinbase = CTransaction()
    coinbaseoutput = CTxOut()
    coinbaseoutput.nValue = int(COINBASE_REWARD) * COIN
    halvings = int(height/150) # regtest
    coinbaseoutput.nValue >>= halvings
    if (pubkey != None):
        coinbaseoutput.scriptPubKey = CScript([pubkey, OP_CHECKSIG])
    else:
        if scriptPubKey is None:
            scriptPubKey = CScript([OP_NOP])
        coinbaseoutput.scriptPubKey = CScript(scriptPubKey)

    uniquifier = TxOut(0, 0, CScript([OP_RETURN, height]))
    coinbase.vout = [ coinbaseoutput, uniquifier ]

    # Make sure the coinbase is at least 64 bytes
    coinbase_size = len(coinbase.serialize())
    if coinbase_size < 65:
        coinbase.vout[1].scriptPubKey += b'x' * (65 - coinbase_size)

    coinbase.calcId()
    return coinbase

# Create a transaction with an anyone-can-spend output, that spends the
# nth output of prevtx.  pass a single integer value to make one output,
# or a list to create multiple outputs
PADDED_ANY_SPEND =  b'\x61'*50 # add a bunch of OP_NOPs to make sure this tx is long enough
def create_transaction(prevtx, n, sig, value, out=PADDED_ANY_SPEND):
    prevtx.calcIdem()
    if not type(value) is list:
        value = [value]
    tx = CTransaction()
    assert(n < len(prevtx.vout))
    outpt = COutPoint().fromIdemAndIdx(prevtx.GetIdem(), n)
    tx.vin.append(CTxIn(outpt, prevtx.vout[n].nValue, sig, 0xffffffff))
    for v in value:
        tx.vout.append(CTxOut(v, out))
    tx.rehash()
    return tx


def bitcoinAddress2bin(btcAddress):
    """convert a bitcoin address to binary data capable of being put in a CScript"""
    # chop the version and checksum out of the bytes of the address
    return decodeBase58(btcAddress)[1:-4]

def address2bin(btcAddress):
    """convert a bitcoin address to binary data capable of being put in a CScript"""
    try:
        addr = cashaddr.decode(btcAddress)
        return addr[2]
    except:
        pass
    # Try bitcoin address: chop the version and checksum out of the bytes of the address
    return decodeBase58(btcAddress)[1:-4]


B58_DIGITS = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def decodeBase58(s):
    """Decode a base58-encoding string, returning bytes"""
    if not s:
        return b''

    # Convert the string to an integer
    n = 0
    for c in s:
        n *= 58
        if c not in B58_DIGITS:
            raise InvalidBase58Error('Character %r is not a valid base58 character' % c)
        digit = B58_DIGITS.index(c)
        n += digit

    # Convert the integer to bytes
    h = '%x' % n
    if len(h) % 2:
        h = '0' + h
    res = binascii.unhexlify(h.encode('utf8'))

    # Add padding back.
    pad = 0
    for c in s[:-1]:
        if c == B58_DIGITS[0]:
            pad += 1
        else:
            break
    return b'\x00' * pad + res

def createWastefulOutput(btcAddress):
    """ Warning: Creates outputs that can't be spent by bitcoind"""
    data = b"""this is junk data. this is junk data. this is junk data. this is junk data. this is junk data.
this is junk data. this is junk data. this is junk data. this is junk data. this is junk data.
this is junk data. this is junk data. this is junk data. this is junk data. this is junk data."""
    ret = CScript([data, OP_DROP, OP_DUP, OP_HASH160, address2bin(btcAddress), OP_EQUALVERIFY, OP_CHECKSIG])
    return ret


def p2pkh(btcAddress):
    """ create a pay-to-public-key-hash script"""
    ret = CScript([OP_DUP, OP_HASH160, address2bin(btcAddress), OP_EQUALVERIFY, OP_CHECKSIG])
    return ret

def p2t(btcAddress):
    """ create a pay-to-template script"""
    pdb.set_trace()
    tmp = address2bin(btcAddress)
    ret = CScript(tmp)
    return ret

def spend_coinbase_tx(node, coinbase, to_address, amount, in_amount=None):
    if in_amount is None:
        in_amount = COINBASE_REWARD
    inputs = [{ "outpoint" : COutPoint().fromIdemAndIdx(coinbase,0).rpcHex(), "amount" : in_amount}]
    outputs = { to_address : amount }
    rawtx = node.createrawtransaction(inputs, outputs)
    signresult = node.signrawtransaction(rawtx)
    util.assert_equal(signresult["complete"], True)
    return signresult["hex"]


def createrawtransaction(inputs, outputs, outScriptGenerator=p2pkh):
    """
    Create a transaction with the exact input and output syntax as the bitcoin-cli "createrawtransaction" command.
    If you use the default outScriptGenerator, this function will return a hex string that exactly matches the
    output of bitcoin-cli createrawtransaction.

    But this function is extended beyond bitcoin-cli in the following ways:
    inputs can have a "sig" field which is a binary hex string of the signature script
    outputs can be a list of tuples rather than a dictionary.  In that format, they can pass complex objects to
    the outputScriptGenerator (use a tuple or an object), be a list (that is passed to CScript()), or a callable
    """
    if not type(inputs) is list:
        inputs = [inputs]

    tx = CTransaction()
    for i in inputs:
        sigScript = i.get("sig", b"")
        tx.vin.append(CTxIn(COutPoint(i["outpoint"]), int(i["amount"]*COIN), sigScript, 0xffffffff))
    pairs = []
    if type(outputs) is dict:
        for addr, amount in outputs.items():
            pairs.append((addr,amount))
    else:
        pairs = outputs

    for addr, amount in pairs:
        if callable(addr):
            tx.vout.append(CTxOut(int(amount * COIN), addr()))
        elif type(addr) is list:
            tx.vout.append(CTxOut(int(amount * COIN), CScript(addr)))
        elif addr == "data":
            tx.vout.append(CTxOut(0, CScript([OP_RETURN, unhexlify(amount)])))
        else:
            tx.vout.append(CTxOut(int(amount * COIN), outScriptGenerator(addr)))
    tx.rehash()
    return hexlify(tx.serialize()).decode("utf-8")


def pad_tx(tx, pad_to_size=MIN_TX_SIZE):
    """
    Pad a transaction with op_return junk data until it is at least pad_to_size, or
    leave it alone if it's already bigger than that.
    """
    curr_size = len(tx.serialize())
    if curr_size >= pad_to_size:
        # Bail early txn is already big enough
        return

    # This code attempts to pad a transaction with opreturn vouts such that
    # it will be exactly pad_to_size.  In order to do this we have to create
    # vouts of size x (maximum OP_RETURN size - vout overhead), plus the final
    # one subsumes any runoff which would be less than vout overhead.
    #
    # There are two cases where this is not possible:
    # 1. The transaction size is between pad_to_size and pad_to_size - extrabytes
    # 2. The transaction is already greater than pad_to_size
    #
    # Visually:
    # | .. x  .. | .. x .. | .. x .. | .. x + desired_size % x |
    #    VOUT_1     VOUT_2    VOUT_3    VOUT_4
    # txout.value + txout.pk_script bytes + op_return
    extra_bytes = 8 + 1 + 1
    required_padding = pad_to_size - curr_size
    while required_padding > 0:
        # We need at least extra_bytes left over each time, or we can't
        # subsume the final (and possibly undersized) iteration of the loop
        padding_len = min(required_padding,
                          MAX_TXOUT_PUBKEY_SCRIPT - extra_bytes)
        assert padding_len >= 0, "Can't pad less than 0 bytes, trying {}".format(
            padding_len)
        # We will end up with less than 1 UTXO of bytes after this, add
        # them to this txn
        next_iteration_padding = required_padding - padding_len - extra_bytes
        if next_iteration_padding > 0 and next_iteration_padding < extra_bytes:
            padding_len += next_iteration_padding

        # If we're at exactly, or below, extra_bytes we don't want a 1 extra byte padding
        if padding_len <= extra_bytes:
            tx.vout.append(CTxOut(0, CScript([OP_RETURN])))
        else:
            # Subtract the overhead for the TxOut
            padding_len -= extra_bytes
            padding = random.randrange(
                1 << 8 * padding_len - 2, 1 << 8 * padding_len - 1)
            tx.vout.append(
                CTxOut(0, CScript([OP_RETURN, padding])))

        curr_size = len(tx.serialize())
        required_padding = pad_to_size - curr_size
    assert curr_size >= pad_to_size, "{} !>= {}".format(curr_size, pad_to_size)
    tx.rehash()

def pad_raw_tx(rawtx_hex, min_size=MIN_TX_SIZE):
    """
    Pad a raw transaction with OP_RETURN data until it reaches at least min_size
    """
    tx = CTransaction()
    FromHex(tx, rawtx_hex)
    pad_tx(tx, min_size)
    return ToHex(tx)

def create_tx_with_script(prevtx, n, script_sig=b"",
                          amount=1, script_pub_key=CScript()):
    """Return one-input, one-output transaction object
       spending the prevtx's n-th output with the given amount.

       Can optionally pass scriptPubKey and scriptSig, default is anyone-can-spend output.
    """
    tx = CTransaction()
    assert(n < len(prevtx.vout))
    tx.vin.append(CTxIn(prevtx.OutpointAt(n), prevtx.vout[n].nValue, script_sig, 0xffffffff))
    tx.vout.append(CTxOut(amount, script_pub_key))
    pad_tx(tx)
    tx.rehash()
    return tx

