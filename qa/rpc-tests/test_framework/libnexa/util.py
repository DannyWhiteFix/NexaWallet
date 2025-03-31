# Copyright (c) 2018-2022 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
from ctypes import *
from test_framework.nodemessages import *
from test_framework.constants import *
from test_framework.ripemd160 import *
from test_framework.util import findBitcoind
from binascii import hexlify, unhexlify
from enum import IntEnum, IntFlag
import pdb
import hashlib
import decimal
import platform
import os

from .libnexa_api_wrapper import ChainSelector, PayAddressType, Error
from . import libnexa_api_wrapper as libnexa_api

# How many sats make a nex
NEX = 100

def strToChainSelector(s):
    if s == "nexa": return ChainSelector.AddrBlockchainNexa
    if s == "nexatest": return ChainSelector.AddrBlockchainTestnet
    if s == "nexareg": return ChainSelector.AddrBlockchainRegtest
    if s == "bch": return ChainSelector.AddrBlockchainBCH
    if s == "bchtest": return ChainSelector.AddrBlockchainBchTestnet
    if s == "bchreg": return ChainSelector.AddrBlockchainBchRegtest
    raise Error("Unknown blockchain")

def bin2hex(data):
    """convert the passed binary data to hex"""
    assert type(data) is bytes, "bintohex requires parameter of type bytes"
    result = libnexa_api.Bin2Hex(data)
    if result:
        return result.value.decode("utf-8")
    raise Error("libnexa bin2hex error")

def signData(data, key):
    if type(data) == str:
        data = unhexlify(data)
    elif type(data) != bytes:
        data = data.serialize()
    return libnexa_api.SignData(data)

def templateToAddress(chainSelector, templateScript, constraintArgs=None, publicArgs=None, group=None, groupQty=None):
    if publicArgs is None: publicArgs = []
    hashTemplate = hash160(templateScript)
    hashArgs = hash160(constraintArgs) if (constraintArgs != None) else OP_0
    grpPfx = [ OP_0 ] if (group == None) else [ group, groupQty]
    lockingScript = CScript(grpPfx + [hashTemplate, hashArgs] + publicArgs)
    return lockingScriptToTemplateAddress(chainSelector, lockingScript)

def lockingScriptToTemplateAddress(chainSelector, data):
    return lockingScriptToAddress(chainSelector, PayAddressType.PayAddressTypeTEMPLATE, data)

def lockingScriptToAddress(chainSelector, addrType, data):
    if type(data) == str:
        data = unhexlify(data)
    elif type(data) != bytes:
        data = data.serialize()
    if addrType == PayAddressType.PayAddressTypeTEMPLATE:
        data = ser_bytes(data)
    res = libnexa_api.encodeCashAddr(chainSelector, addrType, data)
    if not res:
        return None
    return res.decode()

def addressToBin(addrStr):
    """Convert an address to its binary representation (the locking script for script template addresses)"""
    blockchainStr = addrStr.split(":")[0]
    addr = addrStr.split(":")[1]
    chain = strToChainSelector(blockchainStr)
    typ, result = libnexa_api.decodeCashAddr(chain.value, addr)
    if not result:
        print(libnexa_api.get_libnexa_error())
    # first byte is the type, 2nd byte is the script length (for small scripts anyway -- compact int encoded)
    scriptlen = result[0]
    return result[1:1+scriptlen]

def signTxInputECDSA(tx, inputIdx, inputAmount, prevoutScript, key, sigHashType=BTCBCH_SIGHASH_FORKID | BTCBCH_SIGHASH_ALL):
    """Signs one input of a transaction.  Signature is returned.  You must use this signature to construct the spend script
    Parameters:
    tx: Transaction in object, hex or binary format
    inputIdx: index of input being signed
    inputAmount: how many Satoshi's does this input add to the transaction?
    prevoutScript: the script that this input is spending.
    key: sign using this private key in binary format
    sigHashType: flags describing what should be signed (SIGHASH_FORKID | SIGHASH_ALL (default), SIGHASH_NONE, SIGHASH_SINGLE, SIGHASH_ANYONECANPAY)
    """
    assert (sigHashType & BTCBCH_SIGHASH_FORKID) > 0, "Did you forget to indicate the bitcoin cash hashing algorithm?"
    if type(tx) == str:
        tx = unhexlify(tx)
    elif type(tx) != bytes:
        tx = tx.serialize()
    if type(prevoutScript) == str:
        prevoutScript = unhexlify(prevoutScript)
    if type(inputAmount) is decimal.Decimal:
        inputAmount = int(inputAmount * NEX)

    sig = libnexa_api.SignTxECDSA(tx, inputIdx, inputAmount, prevoutScript, sigHashType, key)
    if not siglen:
        raise Error("libnexa signtx error")
    return sig

def signTxInput(tx, inputIdx, inputAmount, prevoutScript, key, sigHashType=SIGHASH_ALL):
    """Default signing is now Schnorr"""
    return signTxInputSchnorr(tx, inputIdx, inputAmount, prevoutScript, key, sigHashType)

def signTxInputSchnorr(tx, inputIdx, inputAmount, prevoutScript, key, sigHashType=SIGHASH_ALL):
    """Signs one input of a transaction.  Schnorr signature is returned.  You must use this signature to construct the spend script
    Parameters:
    tx: Transaction in object, hex or binary format
    inputIdx: index of input being signed
    inputAmount: how many Satoshi's does this input add to the transaction?
    prevoutScript: the script that this input is spending.
    key: sign using this private key in binary format
    sigHashType: bytes describing which parts of the transaction are signed.  If a single byte sighashtype is used, an integer can be passed
    """
    if type(tx) == str:
        tx = unhexlify(tx)
    elif type(tx) != bytes:
        tx = tx.serialize()
    if type(prevoutScript) == str:
        prevoutScript = unhexlify(prevoutScript)
    if type(inputAmount) is decimal.Decimal:
        inputAmount = int(inputAmount * NEX)

    sig = libnexa_api.SignTxSchnorr(tx, inputIdx, inputAmount, prevoutScript, sigHashType, key)
    if not sig:
        raise Error("libnexa signtx error")
    return sig

def SignHashSchnorr(key, hsh):
    """Signs a 32 byte message (presumably the hash of something).  A Schnorr signature is returned.  You must use this signature to construct the spend script
    Parameters:
    hsh: 32 bytes of data, hex, binary, or object (contains serialize member) format
    key: sign using this private key in binary format
    sigHashType: flags describing what should be signed (SIGHASH_FORKID | SIGHASH_ALL (default), SIGHASH_NONE, SIGHASH_SINGLE, SIGHASH_ANYONECANPAY)
    """
    if type(hsh) == str:
        hsh = unhexlify(hsh)
    elif type(hsh) != bytes:
        hsh = hsh.serialize()

    assert len(hsh) == 32
    sig = libnexa_api.signHashSchnorr(hsh, key)
    if not sig:
        raise Error("libnexa signtx error")
    return sig


def randombytes(length):
    """Get cryptographically acceptable pseudorandom bytes from the OS"""
    ret_bytes = bytearray()
    i = length
    while i > 0:
        x = i
        if x > 32:
            x = 32
        result = libnexa_api.RandomBytes(x)
        if len(result) != x:
            raise Error("libnexa randombytes error")
        ret_bytes.extend(result)
        i = i - x
    return bytes(ret_bytes)


def pubkey(key):
    """Given a private key, return its public key"""
    pubkey = libnexa_api.GetPubKey(key)
    return pubkey


def addrbin(pubkey):
    """Given a public key, in binary format, return its binary form address (just the bytes, no type or checksum)"""
    return libnexa_api.hash160(pubkey)

def GetTxid(txbin):
    """Return a transaction id, given a transaction in hex, object or binary form.
       The returned binary txid is not reversed.  Do: hexlify(libnexa_api.txid(txhex)[::-1]).decode("utf-8") to convert to
       bitcoind's hex format.
    """
    if type(txbin) == str:
        txbin = unhexlify(txbin)
    elif type(txbin) != bytes:
        txbin = txbin.serialize()
    ret = libnexa_api.txid(txbin)
    if ret is not None:
        return ret
    assert ret, "transaction decode error"

    # Bitcoin/BitcoinCash
    # return sha256(sha256(txbin))

def GetTxidem(txbin):
    """Return a transaction id, given a transaction in hex, object or binary form.
       The returned binary txid is not reversed.  Do: hexlify(libnexa_api.txid(txhex)[::-1]).decode("utf-8") to convert to
       bitcoind's hex format.
    """
    if type(txbin) == str:
        txbin = unhexlify(txbin)
    elif type(txbin) != bytes:
        txbin = txbin.serialize()
    ret = libnexa_api.txidem(txbin)
    if ret is not None:
        return ret
    assert ret, "transaction decode error"


def spendscript(*data):
    """Take binary data as parameters and return a spend script containing that data"""
    ret = []
    for d in data:
        if type(d) is str:
            d = unhexlify(d)
        assert type(d) is bytes, "There can only be data in spend scripts (no opcodes allowed)"
        l = len(d)
        if l == 0:  # push empty value onto the stack
            ret.append(bytes([0]))
        elif l <= 0x4b:
            ret.append(bytes([l]))  # 1-75 bytes push # of bytes as the opcode
            ret.append(d)
        elif l < 256:
            ret.append(bytes([76]))  # PUSHDATA1
            ret.append(bytes([l]))
            ret.append(d)
        elif l < 65536:
            ret.append(bytes([77]))  # PUSHDATA2
            ret.append(bytes([l & 255, l >> 8]))  # little endian
            ret.append(d)
        else:  # bigger values won't fit on the stack anyway
            assert 0, "cannot push %d bytes" % l
    return b"".join(ret)
