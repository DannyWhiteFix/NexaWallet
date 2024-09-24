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

MAX_STACK_ITEM_LENGTH = 520

# How many sats make a nex
NEX = 100

libnexa = None

def loadLibNexaOrExit(srcdir=None):
    try:
        path = findBitcoind(srcdir)
        init(path + os.sep + ".libs" + os.sep + "libnexa.so")
    except OSError as e:
        p = platform.platform()
        print("Platform  : " + p)
        if "Linux" in p and "x86_64" in p: raise  # libnexa should be created on this platform
        print("Issue loading shared library.  This is expected during cross compilation since the native python will not load the .so: %s" % str(e))
        exit(0)


# match this with value in stackitem.h
class StackItemType(IntEnum):
    BYTES = 0
    BIGNUM = 1

# match this with values in libnexa_common.h
class PayAddressType(IntEnum):
    PayAddressTypeP2PKH = 0
    PayAddressTypeP2SH = 1
    PayAddressTypeGROUP = 11
    PayAddressTypeTEMPLATE = 19
    PayAddressTypeNONE = 255

class ChainSelector(IntEnum):
    AddrBlockchainNexa = 1
    AddrBlockchainTestnet = 2
    AddrBlockchainRegtest = 3
    AddrBlockchainBCH = 4
    AddrBlockchainBchTestnet = 5
    AddrBlockchainBchRegtest = 6

REGTEST = ChainSelector.AddrBlockchainRegtest
    
class Error(BaseException):
    pass

def strToChainSelector(s):
    if s == "nexa": return ChainSelector.AddrBlockchainNexa
    if s == "nexatest": return ChainSelector.AddrBlockchainTestnet
    if s == "nexareg": return ChainSelector.AddrBlockchainRegtest
    if s == "bch": return ChainSelector.AddrBlockchainBCH
    if s == "bchtest": return ChainSelector.AddrBlockchainBchTestnet
    if s == "bchreg": return ChainSelector.AddrBlockchainBchRegtest
    raise Error("Unknown blockchain")

def init(libbitcoincashfile=None):
    global libnexa
    if libbitcoincashfile is None:
        libbitcoincashfile = "libnexa.so"
        try:
            libnexa = CDLL(libbitcoincashfile)
            print("Loaded %s" % libbitcoincashfile)
        except OSError:
            import os
            dir_path = os.path.dirname(os.path.realpath(__file__))
            libnexa = CDLL(dir_path + os.sep + libbitcoincashfile)
            print("Loaded %s" % (dir_path + os.sep + libbitcoincashfile))
    else:
        libnexa = CDLL(libbitcoincashfile)
        print("Loaded %s" % libbitcoincashfile)
    if libnexa is None:
        raise Error("Cannot find %s shared library", libbitcoincashfile)
    libnexa.CreateNoContextScriptMachine.restype = c_void_p
    libnexa.CreateScriptMachine.restype = c_void_p
    libnexa.CreateScriptMachine.argtypes = [ c_int, c_int, c_char_p, c_int, c_char_p, c_int ]
    libnexa.SmEval.argtypes = [ c_void_p, c_char_p, c_int]
    libnexa.SmBeginStep.argtypes = [ c_void_p, c_char_p, c_int]
    libnexa.SmClone.argtypes = [ c_void_p ]
    libnexa.SmClone.restype = c_void_p
    libnexa.SmRelease.argtypes = [ c_void_p ]
    libnexa.SmReset.argtypes = [ c_void_p ]
    libnexa.SmStep.argtypes = [ c_void_p ]
    libnexa.SmPos.argtypes = [ c_void_p ]
    libnexa.SmGetError.argtypes = [ c_void_p ]
    libnexa.SmEndStep.argtypes = [ c_void_p ]
    libnexa.SmGetStackItem.argtypes = [ c_void_p, c_int, c_int, c_char_p, c_char_p ]
    libnexa.SmSetStackItem.argtypes = [ c_void_p, c_int, c_int, c_int, c_char_p, c_int ]

# Serialization/deserialization tools
def sha256(s):
    """Return the sha256 hash of the passed binary data

    >>> hexlify(sha256("e hat eye pie plus one is O".encode()))
    b'c5b94099f454a3807377724eb99a33fbe9cb5813006cadc03e862a89d410eaf0'
    """
    return hashlib.new('sha256', s).digest()


def hash256(s):
    """Return the double SHA256 hash (what bitcoin typically uses) of the passed binary data

    >>> hexlify(hash256("There was a terrible ghastly silence".encode()))
    b'730ac30b1e7f4061346277ab639d7a68c6686aeba4cc63280968b903024a0a40'
    """
    return sha256(sha256(s))


def hash160(msg):
    """RIPEMD160(SHA256(msg)) -> bytes"""
    return ripemd160(hashlib.sha256(msg).digest())


def bin2hex(data):
    """convert the passed binary data to hex"""
    assert type(data) is bytes, "libnexa.bintohex requires parameter of type bytes"
    l = len(data)
    result = create_string_buffer(2 * l + 1)
    if libnexa.Bin2Hex(data, l, result, 2 * l + 1):
        return result.value.decode("utf-8")
    raise Error("libnexa bin2hex error")

def signData(data, key):
    if type(data) == str:
        data = unhexlify(data)
    elif type(data) != bytes:
        data = data.serialize()
    result = create_string_buffer(100)
    siglen = libnexa.SignData(data,len(data),key, result, 100)
    return result.raw[0:siglen]

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
    result = create_string_buffer(10000)
    ok = libnexa.encodeCashAddr(chainSelector, addrType, data,len(data), result, 10000)
    if ok==0: return None
    return result.raw[0:ok].decode()

def addressToBin(addrStr):
    """Convert an address to its binary representation (the locking script for script template addresses)"""
    blockchainStr = addrStr.split(":")[0]
    addr = addrStr.split(":")[1].encode("utf-8")
    chain = strToChainSelector(blockchainStr)
    result = create_string_buffer(len(addrStr))  # Binary representation is going to be smaller than the text rep
    typ = create_string_buffer(1)
    # resultlen = libnexa.decodeCashAddrContent(chain.value, addr, result, len(addrStr), typ)
    resultlen = libnexa.decodeCashAddr(chain.value, addr, result, len(addrStr), typ)
    if resultlen==0:
        print(libnexa.get_libnexa_error())
    # first byte is the type, 2nd byte is the script length (for small scripts anyway -- compact int encoded)
    scriptlen = result.raw[1]
    data = result.raw[2:2+scriptlen]
    return data

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

    result = create_string_buffer(100)
    siglen = libnexa.SignTxECDSA(tx, len(tx), inputIdx, c_longlong(inputAmount), prevoutScript,
                            len(prevoutScript), sigHashType, key, result, 100)
    if siglen == 0:
        raise Error("libnexa signtx error")
    return result.raw[0:siglen]

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
    if type(sigHashType) == int:  # As a convenience allow 1 byte sighashtypes to be passed as an integer
        sigHashType = bytes([sigHashType])
    if type(tx) == str:
        tx = unhexlify(tx)
    elif type(tx) != bytes:
        tx = tx.serialize()
    if type(prevoutScript) == str:
        prevoutScript = unhexlify(prevoutScript)
    if type(inputAmount) is decimal.Decimal:
        inputAmount = int(inputAmount * NEX)

    result = create_string_buffer(100)
    siglen = libnexa.SignTxSchnorr(tx, len(tx), inputIdx, c_longlong(inputAmount), prevoutScript,
        len(prevoutScript), sigHashType, len(sigHashType), key, result, 100)
    if siglen == 0:
        raise Error("libnexa signtx error")
    return result.raw[0:siglen]

def signHashSchnorr(key, hsh):
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

    result = create_string_buffer(100)
    assert len(hsh) == 32
    siglen = libnexa.SignHashSchnorr(hsh, key, result, 100)
    if siglen == 0:
        raise Error("libnexa signtx error")
    return result.raw[0:siglen]


def randombytes(length):
    """Get cryptographically acceptable pseudorandom bytes from the OS"""
    result = create_string_buffer(length)
    worked = libnexa.RandomBytes(result, length)
    if worked != length:
        raise Error("libnexa randombytes error")
    return result.raw


def pubkey(key):
    """Given a private key, return its public key"""
    result = create_string_buffer(65)
    l = libnexa.GetPubKey(key, result, 65)
    return result.raw[0:l]


def addrbin(pubkey):
    """Given a public key, in binary format, return its binary form address (just the bytes, no type or checksum)"""
    result = create_string_buffer(20)
    libnexa.hash160(pubkey, len(pubkey), result)
    return bytes(result)

def txid(txbin):
    """Return a transaction id, given a transaction in hex, object or binary form.
       The returned binary txid is not reversed.  Do: hexlify(libnexa.txid(txhex)[::-1]).decode("utf-8") to convert to
       bitcoind's hex format.
    """
    if type(txbin) == str:
        txbin = unhexlify(txbin)
    elif type(txbin) != bytes:
        txbin = txbin.serialize()
    result = create_string_buffer(32)
    ret = libnexa.txid(txbin, len(txbin), result)
    if ret:
        return bytes(result)
    assert ret, "transaction decode error"

    # Bitcoin/BitcoinCash
    # return sha256(sha256(txbin))

def txidem(txbin):
    """Return a transaction id, given a transaction in hex, object or binary form.
       The returned binary txid is not reversed.  Do: hexlify(libnexa.txid(txhex)[::-1]).decode("utf-8") to convert to
       bitcoind's hex format.
    """
    if type(txbin) == str:
        txbin = unhexlify(txbin)
    elif type(txbin) != bytes:
        txbin = txbin.serialize()
    result = create_string_buffer(32)
    ret = libnexa.txidem(txbin, len(txbin), result)
    if ret:
        return bytes(result)
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

class ScriptError(IntEnum):
    SCRIPT_ERR_OK = 0
    SCRIPT_ERR_UNKNOWN_ERROR = 1
    SCRIPT_ERR_EVAL_FALSE = 2
    SCRIPT_ERR_OP_RETURN = 3

    # Max sizes
    SCRIPT_ERR_SCRIPT_SIZE = 4
    SCRIPT_ERR_PUSH_SIZE = 5
    SCRIPT_ERR_OP_COUNT = 6
    SCRIPT_ERR_STACK_SIZE = 7
    SCRIPT_ERR_SIG_COUNT = 8
    SCRIPT_ERR_PUBKEY_COUNT = 9

    # Operands checks
    SCRIPT_ERR_INVALID_OPERAND_SIZE = 10
    SCRIPT_ERR_INVALID_NUMBER_RANGE = 11
    SCRIPT_ERR_IMPOSSIBLE_ENCODING = 12
    SCRIPT_ERR_INVALID_SPLIT_RANGE = 13
    SCRIPT_ERR_INVALID_BIT_COUNT = 14

    # Failed verify operations
    SCRIPT_ERR_VERIFY = 15
    SCRIPT_ERR_EQUALVERIFY = 16
    SCRIPT_ERR_CHECKMULTISIGVERIFY = 17
    SCRIPT_ERR_CHECKSIGVERIFY = 18
    SCRIPT_ERR_CHECKDATASIGVERIFY = 19
    SCRIPT_ERR_NUMEQUALVERIFY = 20

    # Logical/Format/Canonical errors
    SCRIPT_ERR_BAD_OPCODE = 21
    SCRIPT_ERR_DISABLED_OPCODE = 22
    SCRIPT_ERR_INVALID_STACK_OPERATION = 23
    SCRIPT_ERR_INVALID_ALTSTACK_OPERATION = 24
    SCRIPT_ERR_UNBALANCED_CONDITIONAL = 25

    #  Divisor errors
    SCRIPT_ERR_DIV_BY_ZERO = 26
    SCRIPT_ERR_MOD_BY_ZERO = 27

    # Bitfield errors
    SCRIPT_ERR_INVALID_BITFIELD_SIZE = 28
    SCRIPT_ERR_INVALID_BIT_RANGE = 29

    # CHECKLOCKTIMEVERIFY and CHECKSEQUENCEVERIFY
    SCRIPT_ERR_NEGATIVE_LOCKTIME = 30
    SCRIPT_ERR_UNSATISFIED_LOCKTIME = 31

    # BIP62 (Malleability)
    SCRIPT_ERR_SIG_HASHTYPE = 32
    SCRIPT_ERR_SIG_DER = 33
    SCRIPT_ERR_MINIMALDATA = 34
    SCRIPT_ERR_SIG_PUSHONLY = 35
    SCRIPT_ERR_SIG_HIGH_S = 36
    SCRIPT_ERR_PUBKEYTYPE = 37
    SCRIPT_ERR_CLEANSTACK = 38
    SCRIPT_ERR_SIG_NULLFAIL = 39
    SCRIPT_ERR_MULTISIG_NULLFAIL = 40

    # Schnorr
    SCRIPT_ERR_SIG_BADLENGTH = 41
    SCRIPT_ERR_SIG_NONSCHNORR = 42
    SCRIPT_ERR_MUST_USE_FORKID = 43
    SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS = 44
    SCRIPT_ERR_NONCOMPRESSED_PUBKEY = 45
    SCRIPT_ERR_NUMBER_OVERFLOW = 46
    SCRIPT_ERR_NUMBER_BAD_ENCODING = 47
    SCRIPT_ERR_SIGCHECKS_LIMIT_EXCEEDED = 48

    SCRIPT_ERR_INVALID_NUMBER_RANGE_64_BIT = 49

    SCRIPT_ERR_DATA_REQUIRED = 50
    SCRIPT_ERR_INVALID_TX_INPUT_INDEX = 51
    SCRIPT_ERR_INVALID_TX_OUTPUT_INDEX = 52

    # Nextchain
    SCRIPT_ERR_TEMPLATE = 100
    SCRIPT_ERR_EXEC_DEPTH_EXCEEDED = 101
    SCRIPT_ERR_EXEC_COUNT_EXCEEDED = 102
    SCRIPT_ERR_BAD_OPERATION_ON_TYPE = 103
    SCRIPT_ERR_STACK_LIMIT_EXCEEDED = 104
    SCRIPT_ERR_INVALID_STATE_SPECIFIER = 105
    SCRIPT_ERR_INITIAL_STATE = 106

    SCRIPT_ERR_ERROR_COUNT = 107

class ScriptFlags(IntFlag):
    SCRIPT_VERIFY_P2SH = 1
    SCRIPT_VERIFY_STRICTENC = 1 << 1
    SCRIPT_VERIFY_DERSIG = 1 << 2
    SCRIPT_VERIFY_LOW_S = 1 << 3
    SCRIPT_VERIFY_SIGPUSHONLY = (1 << 5)
    SCRIPT_VERIFY_MINIMALDATA = (1 << 6)
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS = (1 << 7)
    SCRIPT_VERIFY_CLEANSTACK = (1 << 8)
    SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY = (1 << 9)
    SCRIPT_VERIFY_CHECKSEQUENCEVERIFY = (1 << 10)
    SCRIPT_VERIFY_NULLFAIL = (1 << 14)
    SCRIPT_ENABLE_SIGHASH_FORKID = (1 << 16)
    SCRIPT_ENABLE_CHECKDATASIG = (1 << 18)
    SCRIPT_ALLOW_64_BIT_INTEGERS = (1 << 24)
    SCRIPT_ALLOW_NATIVE_INTROSPECTION = (1 << 25)

    MANDATORY_SCRIPT_VERIFY_FLAGS = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_STRICTENC | SCRIPT_ENABLE_SIGHASH_FORKID | SCRIPT_VERIFY_LOW_S | SCRIPT_VERIFY_NULLFAIL;
    STANDARD_SCRIPT_VERIFY_FLAGS = MANDATORY_SCRIPT_VERIFY_FLAGS | SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_MINIMALDATA | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS | SCRIPT_VERIFY_CLEANSTACK | SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY | SCRIPT_VERIFY_CHECKSEQUENCEVERIFY | SCRIPT_ENABLE_CHECKDATASIG;


class ScriptMachine:
    STACK = 0
    ALTSTACK = 1

    def __init__(self, flags=-1, nocreate=False, tx=None, prevouts=None, inputIdx=None):
        self.flags = flags
        if self.flags == -1:
            self.flags = ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS
        result = create_string_buffer(100)
        if nocreate:
            self.smId = None
        else:
            if tx is None:
                self.smId = libnexa.CreateNoContextScriptMachine(self.flags)
            else:
                # If string (assumes hex) or object convert to binary serialization
                if type(tx) == str:
                    txbin = unhexlify(txbin)
                elif type(tx) != bytes:
                    txbin = tx.serialize()
                else:
                    txbin = tx
                if type(prevouts) == str:
                    prevoutsBin = unhexlify(prevouts)
                elif type(tx) != bytes:
                    prevoutsBin = ser_vector(prevouts)
                else:
                    prevoutsbin = prevouts

                self.smId = libnexa.CreateScriptMachine(self.flags, inputIdx, txbin, len(txbin), prevoutsBin, len(prevoutsBin))
        self.curPos = 0
        self.script = None

    def __del__(self):
        if hasattr(self, 'smId'):
            if self.smId: self.cleanup()

    def clone(self):
        sm = ScriptMachine(self.flags, nocreate=True)
        sm.smId = libnexa.SmClone(self.smId)
        sm.curPos = self.curPos
        sm.script = self.script
        return sm

    def cleanup(self):
        """Call to explicitly free the resources used by this script machine"""
        if self.smId:
            libnexa.SmRelease(self.smId)
            self.smId = 0
        else:
            raise Error("accessed inactive script machine")

    def reset(self):
        if self.smId==0: raise Error("accessed inactive script machine")
        libnexa.SmReset(self.smId)
        self.curPos = 0

    def eval(self, script):
        if self.smId==0: raise Error("accessed inactive script machine")
        if type(script) == str:
            script = unhexlify(script)
        ret = libnexa.SmEval(self.smId, script, len(script))
        return ret

    def begin(self, script):
        """Start stepping through the provided script"""
        if self.smId==0: raise Error("accessed inactive script machine")
        if type(script) == str:
            script = unhexlify(script)
        ret = libnexa.SmBeginStep(self.smId, script, len(script))
        self.curPos = 0
        self.script = script
        return ret

    def step(self):
        """Step forward 1 instruction"""
        if self.smId==0: raise Error("accessed inactive script machine")
        if self.curPos >= len(self.script):
            raise Error("stepped beyond end of script")
        ret = libnexa.SmStep(self.smId)
        if ret == 0:
            raise Error("execution error")
        self.curPos = libnexa.SmPos(self.smId)
        return self.curPos

    def error(self):
        if self.smId==0: raise Error("accessed inactive script machine")
        return (ScriptError(libnexa.SmGetError(self.smId)), libnexa.SmPos(self.smId))

    def pos(self):
        return self.curPos

    def end(self):
        """Call when script is complete to do final script checks"""
        if self.smId==0: raise Error("accessed inactive script machine")
        ret = libnexa.SmEndStep(self.smId)
        return ret

    def altstack(self):
        return self.stack(self.ALTSTACK)

    def stack(self, which = None):
        """Returns the machine's stack (main stack by default) as a list of byte arrays, index 0 is the stack top"""
        if self.smId==0: raise Error("accessed inactive script machine")
        if which is None: which = self.STACK
        stk = []
        idx  = 0
        item = create_string_buffer(MAX_STACK_ITEM_LENGTH)
        itemType = create_string_buffer(1)
        while 1:
            result = libnexa.SmGetStackItem(self.smId, which, idx, itemType, item)
            if result == -1: break
            if itemType[0] == b'\x00':
                itemTyp = StackItemType.BYTES
            elif itemType[0] == b'\x01':
                itemTyp = StackItemType.BIGNUM
            else:
                raise Error("Bad stack item type")
            stk.append((itemTyp, item[0:result]))
            idx+=1
        return stk

    def setAltStackItem(self, idx, itemType, value):
        """Set an item on the stack to a value, index 0 is the top.  index -1 means push"""
        self.setStackItem(idx, itemType, value, self.ALTSTACK)

    def setStackItem(self, idx, itemType, value, which = None):
        """Set an item on the stack to a value, index 0 is the top.  index -1 means push"""
        if self.smId==0: raise Error("accessed inactive script machine")
        if which is None: which = self.STACK
        libnexa.SmSetStackItem(self.smId, which, idx, int(itemType), value, len(value))


def Test():
    assert bin2hex(b"123") == "313233"
    assert len(randombytes(10)) == 10
    assert randombytes(16) != randombytes(16)
