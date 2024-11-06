import sys
import socket
import struct
import random
import hashlib
import decimal
import pdb
import io
from binascii import hexlify, unhexlify
import time
from codecs import encode
from threading import RLock
from io import BytesIO
import copy
from test_framework.schnorr import sign
from test_framework.siphash import siphash256
import test_framework.util as util
from test_framework.constants import *
from test_framework.scriptop import *
from test_framework.script import CScript

MY_VERSION = 80003 # past bip-152 for compactblocks

# Serialization Types
SER_DEFAULT = 0
SER_ID = 0
SER_IDEM = 1

INVALID_OPCODE = b'\xff'

from .constants import SIGHASH_ALL, SIGHASH_ANYONECANPAY, SIGHASH_NONE

MY_SUBVERSION = b"/python-mininode-tester:0.0.3/"

COIN = 100  # 1 coin in satoshis

# One lock for synchronizing all data access between the networking thread (see
# NetworkThread below) and the thread running the test logic.  For simplicity,
# NodeConn acquires this lock whenever delivering a message to a NodeConnCB,
# and whenever adding anything to the send buffer (in send_message()).  This
# lock should be acquired in the thread running the test logic to synchronize
# access to any data shared with the NodeConnCB or NodeConn.
mininode_lock = RLock()

# Helper function

# These functions were moved to util, but keep them in this namespace for backwards compatibility
sha256 = util.sha256
hash256 = util.hash256
hash160 = util.hash160
ser_uint256 = util.ser_uint256
deser_uint256 = util.deser_uint256

def wait_until(predicate, attempts=float('inf'), timeout=float('inf')):
    attempt = 0
    elapsed = 0

    while attempt < attempts and elapsed < timeout:
        with mininode_lock:
            if predicate():
                return True
        attempt += 1
        elapsed += 0.25
        time.sleep(0.25)

    return False

def bitcoinAddress2bin(btcAddress):
    """convert a bitcoin address to binary data capable of being put in a CScript"""
    # chop the version and checksum out of the bytes of the address
    return decodeBase58(btcAddress)[1:-4]

B58_DIGITS = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

class InvalidBase58Error(Exception):
    """Raised on generic invalid base58 data, such as bad characters.
    Checksum failures raise Base58ChecksumError specifically.
    """
    pass

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
    res = unhexlify(h.encode('utf8'))

    # Add padding back.
    pad = 0
    for c in s[:-1]:
        if c == B58_DIGITS[0]:
            pad += 1
        else:
            break
    return b'\x00' * pad + res


def encodeBase58(b):
    """Encode bytes to a base58-encoded string"""

    # Convert big-endian bytes to integer
    n = int('0x0' + hexlify(b).decode('utf8'), 16)

    # Divide that integer into bas58
    res = []
    while n > 0:
        n, r = divmod(n, 58)
        res.append(B58_DIGITS[r])
    res = ''.join(res[::-1])

    # Encode leading zeros as base58 zeros
    czero = b'\x00'
    if sys.version > '3':
        # In Python3 indexing a bytes returns numbers, not characters.
        czero = 0
    pad = 0
    for c in b:
        if c == czero:
            pad += 1
        else:
            break
    return B58_DIGITS[0] * pad + res

def encodeBitcoinAddress(prefix, data):
    data2 = prefix + data
    cksm = hash256(data2)[:4]
    data3 = data2 + cksm
    b58 = encodeBase58(data3)
    return b58


class CompactSize(int):
    def serialize(self, stype=SER_DEFAULT):
        assert(self>=0)
        if self<253:
            return struct.pack("<B", self)
        elif self<2**16:
            return struct.pack("<B", 253) + struct.pack("<H", self)
        elif self<2**32:
            return struct.pack("<B", 254) + struct.pack("<I", self)
        elif self<2**64:
            return struct.pack("<B", 255) + struct.pack("<Q", self)

    def deserialize(self, f):
        self = struct.unpack("<B", f.read(1))[0]
        if self == 253:
            self = struct.unpack("<H", f.read(2))[0]
        elif self == 254:
            self = struct.unpack("<I", f.read(4))[0]
        elif self == 255:
            self = struct.unpack("<Q", f.read(8))[0]
        return self

def deser_string(f):
    """Convert an array of bytes in the bitcoin P2P protocol format into a string

    >>> import io
    >>> deser_string(io.BytesIO(ser_string("The grid bug bites!  You get zapped!".encode()))).decode()
    'The grid bug bites!  You get zapped!'
    """
    nit = struct.unpack("<B", f.read(1))[0]
    if nit == 253:
        nit = struct.unpack("<H", f.read(2))[0]
    elif nit == 254:
        nit = struct.unpack("<I", f.read(4))[0]
    elif nit == 255:
        nit = struct.unpack("<Q", f.read(8))[0]
    return f.read(nit)

def deser_bytes(f):
    """Convert an array of bytes in the bitcoin P2P protocol format into a string

    >>> import io
    >>> deser_string(io.BytesIO(ser_string("The grid bug bites!  You get zapped!".encode()))).decode()
    'The grid bug bites!  You get zapped!'
    """
    nit = struct.unpack("<B", f.read(1))[0]
    if nit == 253:
        nit = struct.unpack("<H", f.read(2))[0]
    elif nit == 254:
        nit = struct.unpack("<I", f.read(4))[0]
    elif nit == 255:
        nit = struct.unpack("<Q", f.read(8))[0]
    return f.read(nit)


def ser_string(s):
    """convert a string into an array of bytes (in the bitcoin network format)

       >>> ser_string("The grid bug bites!  You get zapped!".encode())
       b'$The grid bug bites!  You get zapped!'
    """
    if len(s) < 253:
        return struct.pack("B", len(s)) + s
    elif len(s) < 0x10000:
        return struct.pack("<BH", 253, len(s)) + s
    elif len(s) < 0x100000000:
        return struct.pack("<BI", 254, len(s)) + s
    return struct.pack("<BQ", 255, len(s)) + s

def ser_bytes(s):
    """convert a string into an array of bytes (in the bitcoin network format)

       >>> ser_string("The grid bug bites!  You get zapped!".encode())
       b'$The grid bug bites!  You get zapped!'
    """
    if len(s) < 253:
        return struct.pack("B", len(s)) + s
    elif len(s) < 0x10000:
        return struct.pack("<BH", 253, len(s)) + s
    elif len(s) < 0x100000000:
        return struct.pack("<BI", 254, len(s)) + s
    return struct.pack("<BQ", 255, len(s)) + s


def uint256_from_str(s):
    """Decode a uint256 from a little-endian byte array or hex string (bitcoind strings are little-endian)
    """
    if len(s) == 64:
        s = unhexlify(s)
    r = 0
    t = struct.unpack("<IIIIIIII", s[:32])
    for i in range(8):
        r += t[i] << (i * 32)
    return r

def uint256_from_bigendian(s):
    """Decode a uint256 from a big-endian byte array or hex string (lexical order is big-endian)
    """
    if type(s) is str:
        s = unhexlify(s)
    r = 0
    t = struct.unpack(">QQQQ", s[:32])
    for i in t:
        r = (r << 64) | i
    return r


def uint256_from_compact(c):
    """Convert compact encoding to uint256

    Used for the nBits compact encoding of the target in the block header.
    """
    nbytes = (c >> 24) & 0xFF
    if nbytes <= 3:
        v = (c & 0xFFFFFF) >> 8 * (3 - nbytes)
    else:
        v = (c & 0xFFFFFF) << (8 * (nbytes - 3))
    return v

def compact_from_uint256(v):
    """Convert uint256 to compact encoding
    """
    nbytes = (v.bit_length() + 7) >> 3
    compact = 0
    if nbytes <= 3:
        compact = (v & 0xFFFFFF) << 8 * (3 - nbytes)
    else:
        compact = v >> 8 * (nbytes - 3)
        compact = compact & 0xFFFFFF

    # If the sign bit (0x00800000) is set, divide the mantissa by 256 and
    # increase the exponent to get an encoding without it set.
    if compact & 0x00800000:
        compact >>= 8
        nbytes += 1

    return compact | nbytes << 24


def deser_double(f):
    return struct.unpack("<d", f.read(8))[0]

def ser_double(d):
    return struct.pack("<d", d)

def deser_vector(f, c):
    nit = struct.unpack("<B", f.read(1))[0]
    if nit == 253:
        nit = struct.unpack("<H", f.read(2))[0]
    elif nit == 254:
        nit = struct.unpack("<I", f.read(4))[0]
    elif nit == 255:
        nit = struct.unpack("<Q", f.read(8))[0]
    r = []
    for i in range(nit):
        if type(c) is type(lambda: True):
            t = c(f)
        else: # class type
            t = c()
            t.deserialize(f)
            r.append(t)
    return r


def ser_vector(l, stype=SER_ID):
    r = b""
    if len(l) < 253:
        r = struct.pack("B", len(l))
    elif len(l) < 0x10000:
        r = struct.pack("<BH", 253, len(l))
    elif len(l) < 0x100000000:
        r = struct.pack("<BI", 254, len(l))
    else:
        r = struct.pack("<BQ", 255, len(l))
    for i in l:
        r += i.serialize(stype)
    return r


def deser_uint256_vector(f):
    nit = struct.unpack("<B", f.read(1))[0]
    if nit == 253:
        nit = struct.unpack("<H", f.read(2))[0]
    elif nit == 254:
        nit = struct.unpack("<I", f.read(4))[0]
    elif nit == 255:
        nit = struct.unpack("<Q", f.read(8))[0]
    r = []
    for i in range(nit):
        t = deser_uint256(f)
        r.append(t)
    return r


def ser_uint256_vector(l):
    r = b""
    if len(l) < 253:
        r = struct.pack("B", len(l))
    elif len(l) < 0x10000:
        r = struct.pack("<BH", 253, len(l))
    elif len(l) < 0x100000000:
        r = struct.pack("<BI", 254, len(l))
    else:
        r = struct.pack("<BQ", 255, len(l))
    for i in l:
        r += ser_uint256(i)
    return r

def ser_hash32_vector(l):
    """ Serializes a vector of 32 byte hashes supplied as a list of 32 byte 'bytes' objects  """
    r = b""
    if len(l) < 253:
        r = struct.pack("B", len(l))
    elif len(l) < 0x10000:
        r = struct.pack("<BH", 253, len(l))
    elif len(l) < 0x100000000:
        r = struct.pack("<BI", 254, len(l))
    else:
        r = struct.pack("<BQ", 255, len(l))
    for i in l:
        assert(len(i) == 32)
        r += i
    return r

def deser_hash32_vector(f):
    """ Deserializes a vector of 32 byte hashes, into a list of 32 byte 'bytes' objects """
    nit = struct.unpack("<B", f.read(1))[0]
    if nit == 253:
        nit = struct.unpack("<H", f.read(2))[0]
    elif nit == 254:
        nit = struct.unpack("<I", f.read(4))[0]
    elif nit == 255:
        nit = struct.unpack("<Q", f.read(8))[0]
    r = []
    for i in range(nit):
        t = f.read(32)
        r.append(t)
    return r


def ser_compact_size(l):
    r = b""
    if l < 253:
        r = struct.pack("B", l)
    elif l < 0x10000:
        r = struct.pack("<BH", 253, l)
    elif l < 0x100000000:
        r = struct.pack("<BI", 254, l)
    else:
        r = struct.pack("<BQ", 255, l)
    return r

def deser_compact_size(f):
    nit = struct.unpack("<B", f.read(1))[0]
    if nit == 253:
        nit = struct.unpack("<H", f.read(2))[0]
    elif nit == 254:
        nit = struct.unpack("<I", f.read(4))[0]
    elif nit == 255:
        nit = struct.unpack("<Q", f.read(8))[0]
    return nit

def deser_varint(f):
    done = False
    num = 0
    while True:
        b = struct.unpack("<B", f.read(1))[0]
        num = (num << 7) | (b&0x7F)
        if b&0x80:
            num += 1
        else:
            return num

def ser_varint(n):
    ret = bytearray()

    i = 0
    ret.append(0)
    while True:
        ret[i] = ret[i] | (n & 0x7F)
        if n <= 0x7F: break
        n = (n >> 7) - 1
        i += 1
        ret.append(0x80)

    return bytes(reversed(ret))



def deser_string_vector(f):
    nit = struct.unpack("<B", f.read(1))[0]
    if nit == 253:
        nit = struct.unpack("<H", f.read(2))[0]
    elif nit == 254:
        nit = struct.unpack("<I", f.read(4))[0]
    elif nit == 255:
        nit = struct.unpack("<Q", f.read(8))[0]
    r = []
    for i in range(nit):
        t = deser_string(f)
        r.append(t)
    return r

def ser_string_vector(l):
    r = b""
    if len(l) < 253:
        r = struct.pack("B", len(l))
    elif len(l) < 0x10000:
        r = struct.pack("<BH", 253, len(l))
    elif len(l) < 0x100000000:
        r = struct.pack("<BI", 254, len(l))
    else:
        r = struct.pack("<BQ", 255, len(l))
    for sv in l:
        r += ser_string(sv)
    return r


def deser_int_vector(f):
    nit = struct.unpack("<B", f.read(1))[0]
    if nit == 253:
        nit = struct.unpack("<H", f.read(2))[0]
    elif nit == 254:
        nit = struct.unpack("<I", f.read(4))[0]
    elif nit == 255:
        nit = struct.unpack("<Q", f.read(8))[0]
    r = []
    for i in range(nit):
        t = struct.unpack("<i", f.read(4))[0]
        r.append(t)
    return r


def ser_int_vector(l):
    r = b""
    if len(l) < 253:
        r = struct.pack("B", len(l))
    elif len(l) < 0x10000:
        r = struct.pack("<BH", 253, len(l))
    elif len(l) < 0x100000000:
        r = struct.pack("<BI", 254, len(l))
    else:
        r = struct.pack("<BQ", 255, len(l))
    for i in l:
        r += struct.pack("<i", i)
    return r

# Deserialize from a hex string representation (eg from RPC)


def FromHex(obj, hex_string):
    obj.deserialize(BytesIO(unhexlify(hex_string.strip().encode('ascii'))))
    return obj

# Convert a binary-serializable object to hex (eg for submission via RPC)


def ToHex(obj):
    if type(obj) is bytes:
        return hexlify(obj)
    return hexlify(obj.serialize()).decode('ascii')


# Objects that map to bitcoind objects, which can be serialized/deserialized

# because the nVersion field has not been passed before the VERSION message the protocol uses an old format for the CAddress (missing nTime)
# This class handles that old format
class CAddressInVersion(object):
    def __init__(self, ip="0.0.0.0", port=0):
        self.nServices = 1
        self.pchReserved = b"\x00" * 10 + b"\xff" * 2  # ip is 16 bytes on wire to handle v6
        self.ip = ip
        self.port = port

    def deserialize(self, f):
        self.nServices = struct.unpack("<Q", f.read(8))[0]
        self.pchReserved = f.read(12)
        self.ip = socket.inet_ntoa(f.read(4))
        self.port = struct.unpack(">H", f.read(2))[0]

    def serialize(self, stype=SER_DEFAULT):
        r = b""
        r += struct.pack("<Q", self.nServices)
        r += self.pchReserved
        r += socket.inet_aton(self.ip)
        r += struct.pack(">H", self.port)
        return r

    def __repr__(self):
        return "CAddressInVersion(nServices=%i ip=%s port=%i)" % (self.nServices, self.ip, self.port)

# Handle new-style CAddress objects (with nTime)
class CAddress(object):
    def __init__(self, ip="0.0.0.0", port=0):
        self.nServices = 1
        self.nTime = int(time.time())
        self.pchReserved = b"\x00" * 10 + b"\xff" * 2  # ip is 16 bytes on wire to handle v6
        self.ip = ip
        self.port = port

    def deserialize(self, f):
        self.nTime = struct.unpack("<L", f.read(4))[0]
        self.nServices = struct.unpack("<Q", f.read(8))[0]
        self.pchReserved = f.read(12)
        self.ip = socket.inet_ntoa(f.read(4))
        self.port = struct.unpack(">H", f.read(2))[0]

    def serialize(self, stype=SER_DEFAULT):
        r = b""
        r += struct.pack("<L", self.nTime)
        r += struct.pack("<Q", self.nServices)
        r += self.pchReserved
        r += socket.inet_aton(self.ip)
        r += struct.pack(">H", self.port)
        return r

    def __repr__(self):
        return "CAddress(nServices=%i ip=%s port=%i time=%d)" % (self.nServices, self.ip, self.port, self.nTime)


class CInv(object):
    MSG_TX = 1
    MSG_BLOCK = 2
    MSG_FILTERED_BLOCK = 3
    MSG_CMPCT_BLOCK = 4
    MSG_XTHINBLOCK = 5
    MSG_THINBLOCK = MSG_CMPCT_BLOCK
    typemap = {
        0: "Error",
        1: "TX",
        2: "Block",
        3: "FilteredBlock",
        4: "CompactBlock",
        5: "XThinBlock",
    }

    def __init__(self, t=0, h=0):
        assert type(t) is int
        if type(h) is bytes:
            h = deser_uint256(h)
        assert type(h) is int
        self.type = t
        self.hash = h

    def deserialize(self, f):
        self.type = struct.unpack("<i", f.read(4))[0]
        self.hash = deser_uint256(f)

    def serialize(self, stype=SER_DEFAULT):
        r = b""
        r += struct.pack("<i", self.type)
        r += ser_uint256(self.hash)
        return r

    def __repr__(self):
        return "CInv(type=%s hash=%064x)" \
            % (self.typemap[self.type], self.hash)


class CBlockLocator(object):
    def __init__(self):
        self.nVersion = MY_VERSION
        self.vHave = []

    def deserialize(self, f):
        self.nVersion = struct.unpack("<i", f.read(4))[0]
        self.vHave = deser_uint256_vector(f)

    def serialize(self, stype=SER_DEFAULT):
        r = b""
        r += struct.pack("<i", self.nVersion)
        r += ser_uint256_vector(self.vHave)
        return r

    def __repr__(self):
        return "CBlockLocator(nVersion=%i vHave=%s)" \
            % (self.nVersion, repr(self.vHave))


class COutPoint(object):
    def __init__(self, outpointHash=0):
        if type(outpointHash) is COutPoint:
            outpointHash = outpointHash.hash
        if type(outpointHash) is str:
            outpointHash = uint256_from_bigendian(outpointHash)
        if type(outpointHash) is bytes:
            outpointHash = uint256_from_str(outpointHash)
        self.hash = outpointHash

    def fromIdemAndIdx(self, txidem, n):
        if type(txidem) is str:
            txidem = uint256_from_bigendian(txidem)
        if type(txidem) is int:
            txidem = ser_uint256(txidem)
        r = txidem
        r += struct.pack("<I", n)
        self.hash = uint256_from_str(sha256(r))
        return self

    def deserialize(self, f):
        self.hash = deser_uint256(f)

    def serialize(self, stype=SER_DEFAULT):
        r = b""
        r += ser_uint256(self.hash)
        return r

    def rpcHex(self):
        return util.uint256ToRpcHex(self.hash)

    def __repr__(self):
        return "COutPoint(hash=%064x)" % (self.hash)


class CTxIn(object):
    UTXO = 0
    READONLY = 1
    def __init__(self, outpoint=None, amount=0, scriptSig=b"", nSequence=0):
        # ctor determination and input arg conversion
        if type(amount) is decimal.Decimal:
            amount = int(amount*COIN)
        assert(type(amount) is int)
        if scriptSig is None: scriptSig = b""
        assert(isinstance(scriptSig, bytes))

        # Initialization
        if outpoint is None:
            self.prevout = COutPoint()
        elif isinstance(outpoint, dict):
            self.fromRpcUtxo(outpoint)
            return
        elif type(outpoint) is str:
            self.prevout = COutPoint(outpoint)
        else:
            self.prevout = outpoint
        self.t = 0
        self.scriptSig = scriptSig
        self.nSequence = nSequence
        self.amount = amount

    def fromRpcUtxo(self, d):
        """Initialize this CTxIn from a dictionary received by the listunspent RPC call"""
        self.t = 0
        self.prevout = COutPoint(d["outpoint"])
        self.scriptSig = b""
        self.amount = int(d['amount']*COIN)
        self.nSequence = 0
        return self

    def deserialize(self, f):
        self.t = struct.unpack("<B", f.read(1))[0]
        self.prevout = COutPoint()
        self.prevout.deserialize(f)
        self.scriptSig = deser_string(f)
        self.nSequence = struct.unpack("<I", f.read(4))[0]
        self.amount = struct.unpack("<q", f.read(8))[0]

    def setUnlockingToTemplate(self, templateScript, constraintArgs, satisfierArgs):
        if satisfierArgs is None:
            satisfierArgs = []
        scr = [bytes(templateScript)]
        if constraintArgs != None: scr.append(bytes(constraintArgs))
        scr += satisfierArgs
        self.scriptSig = CScript(scr)
        return self

    def serialize(self, stype):
        r = b""
        r += struct.pack("<B", self.t)
        r += self.prevout.serialize()
        if stype != SER_IDEM:
            r += ser_string(self.scriptSig)
        r += struct.pack("<I", self.nSequence)
        r += struct.pack("<q", int(self.amount))
        return r

    def __repr__(self):
        return "CTxIn(prevout=%s amount=%d scriptSig=%s nSequence=%i)" % (repr(self.prevout), self.amount, hexlify(self.scriptSig), self.nSequence)

# General transaction output
class TxOut(object):
    TYPE_SATOSCRIPT = 0
    TYPE_TEMPLATE = 1

    def __init__(self, typ=0, nValue=0, scriptPubKey=b""):

        assert(isinstance(scriptPubKey,bytes))
        assert(type(typ) == int)
        self.t   = typ
        # if its a decimal, its assumed to be in COINs
        assert(type(nValue) == int or type(nValue) == decimal.Decimal)
        if type(nValue) == decimal.Decimal:
            self.nValue = int(nValue*COIN)
        else:
            self.nValue = nValue

        self.scriptPubKey = scriptPubKey

    def findIn(self, tx):
        """Return the index if this TxOut (compared by value) is in the passed transaction otherwise -1"""
        for idx, out in enumerate(tx.vout):
            if out.nValue == self.nValue and out.scriptPubKey == self.scriptPubKey:
                return idx
        return -1

    def isIn(self, tx):
        """Return true if this TxOut (compared by value) is in the passed transaction"""
        return self.findIn(tx) >= 0

    def setLockingToTemplate(self, templateScript, constraintArgs, publicArgs=None, group=None, groupQty=None):
        self.t = TxOut.TYPE_TEMPLATE
        if publicArgs is None: publicArgs = []
        hashTemplate = hash160(templateScript)
        hashArgs = hash160(constraintArgs) if (constraintArgs != None) else OP_0
        grpPfx = [ OP_0 ] if (group == None) else [ group, groupQty]
        self.scriptPubKey = CScript(grpPfx + [hashTemplate, hashArgs] + publicArgs)
        return self


    def deserialize(self, f):
        self.t   = struct.unpack("<B", f.read(1))[0]
        self.nValue = struct.unpack("<q", f.read(8))[0]
        self.scriptPubKey = deser_string(f)

    def serialize(self, serType=SER_DEFAULT):
        r =  struct.pack("<B", self.t)
        r += struct.pack("<q", int(self.nValue))
        r += ser_string(self.scriptPubKey)
        return r

    def fromHex(self, hexdata):
        """Overwrite the contents of this object with the deserialized data in the passed parameter"""
        self.deserialize(hexdata)
        return self
    def toHex(self):
        """Return the hex string serialization of this object"""
        return hexlify(self.serialize()).decode("utf-8")

    def __repr__(self):
        return "TxOut(type=%x, nValue=%i.%08i scriptPubKey=%s)" % (self.t, self.nValue // COIN, self.nValue % COIN, hexlify(self.scriptPubKey))

def anySpender(amount):
    """Creates a script template output that anyone can spend with no arguments"""
    ret = TxOut(TxOut.TYPE_TEMPLATE, amount)
    ret.setLockingToTemplate(CScript(), None)
    return ret

def anySpender1(amount):
    """Creates a script template output that anyone can spend with 1 push (of any value)"""
    ret = TxOut(TxOut.TYPE_TEMPLATE, amount)
    ret.setLockingToTemplate(CScript([OP_DROP]), None)
    return ret

# Legacy script mode tx out
class CTxOut(TxOut):
    def __init__(self, nValue=0, scriptPubKey=b""):
        TxOut.__init__(self, 0, nValue, scriptPubKey)


class CTransaction(object):
    def __init__(self, tx=None):
        self.id = None
        self.idem = None
        if isinstance(tx, dict): # handle result from RPC call
            self.fromHex(tx["hex"])
            assert util.uint256ToRpcHex(self.GetId()) == tx["txid"], "Deserialized id does not match what was received from RPC"
        elif isinstance(tx, str):
            self.fromHex(tx)
        elif tx is None:
            self.nVersion = 0
            self.vin = []
            self.vout = []
            self.nLockTime = 0
        else:
            self.nVersion = tx.nVersion
            self.vin = copy.deepcopy(tx.vin)
            self.vout = copy.deepcopy(tx.vout)
            self.nLockTime = tx.nLockTime

    def deserialize(self, f):
        if isinstance(f, str):
            # str - assumed to be hex string
            f = BytesIO(unhexlify(f))
        elif isinstance(f, bytes):
            f = BytesIO(f)
        self.nVersion = struct.unpack("<B", f.read(1))[0]
        self.vin = deser_vector(f, CTxIn)
        self.vout = deser_vector(f, CTxOut)
        self.nLockTime = struct.unpack("<I", f.read(4))[0]
        self.id = None
        self.idem = None
        return self

    def serialize(self, stype=SER_DEFAULT):
        r = b""
        r += struct.pack("<B", self.nVersion)
        r += ser_vector(self.vin, stype)
        r += ser_vector(self.vout, stype)
        r += struct.pack("<I", self.nLockTime)
        return r

    def fromHex(self, hexdata):
        self.deserialize(hexdata)
        return self
    def toHex(self):
        """Return the hex string serialization of this object"""
        return hexlify(self.serialize()).decode("utf-8")

    def rehash(self):
        self.id = None
        self.idem = None
        self.calcIdem()
        self.calcId()
        return self.id

    def GetId(self):
        """Returns the Id as bytes"""
        if self.id == None: self.calcId()
        return self.id
    def GetIdAsInt(self):
        """Returns the Id as a number"""
        return deser_uint256(self.GetId())
    def GetRpcHexId(self):
        """Returns the Id in the same format it would be returned via a RPC call"""
        return util.uint256ToRpcHex(self.GetId())

    def GetIdem(self):
        """Returns the Idem as bytes"""
        if self.idem == None: self.calcIdem()
        return self.idem
    def GetRpcHexIdem(self):
        """Returns the Idem in the same format it would be returned via a RPC call"""
        return util.uint256ToRpcHex(self.GetIdem())

    def calcIdem(self):
        self.idem = hash256(self.serialize(SER_IDEM))
        return self.idem

    def calcId(self):
        idemHash = self.calcIdem()
        sigs = []
        sigs.append(struct.pack("<I", len(self.vin)))
        for tin in self.vin:
            sigs.append(bytes(tin.scriptSig))
            sigs.append(INVALID_OPCODE)  # Separator
        sigs = b"".join(sigs)
        sigsHash = hash256(sigs)
        # print("sigsHash: " + util.uint256ToRpcHex(sigsHash) + "  len: " + str(len(sigs)) + " bytes: " + sigs.hex())
        self.id = hash256(idemHash + sigsHash)
        return self.id

    def is_valid(self):
        self.calc_sha256()
        for tout in self.vout:
            if tout.nValue < 0 or tout.nValue > 21000000000000 * COIN:
                return False
        return True

    def summary(self):
        self.calc_sha256()
        s = ["Transaction: %064x\n" % self.GetId()]
        s.append("%d inputs\n" % len(self.vin))
        for vin in self.vin:
            s.append("  %064x:%d\n" % (vin.prevout.hash, vin.prevout.n))
        s.append("%d outputs\n" % len(self.vout))
        for vout in self.vout:
            s.append("  %12d %s\n" % (vout.nValue, hexlify((vout.scriptPubKey))))
        return "".join(s)

    def OutpointAt(self, idx):
        assert idx < len(self.vout)
        return COutPoint().fromIdemAndIdx(self.GetIdem(), idx)

    def SpendOutput(self, idx, satisfierScript=None):
        assert idx < len(self.vout)
        return CTxIn(COutPoint().fromIdemAndIdx(self.GetIdem(), idx), self.vout[idx].nValue, satisfierScript)


    def __repr__(self):
        return "CTransaction(nVersion=%i vin=%s vout=%s nLockTime=%i)" \
            % (self.nVersion, repr(self.vin), repr(self.vout), self.nLockTime)

    def hashPrevoutsNexa(self, hashcode, in_number):
        if len(hashcode) == 0: hashcode = bytes([0])
        outCode = hashcode[0]&0xf0
        op_ser = b""
        if outCode == SIGHASH_ALL_IN or outCode == SIGHASH_FIRSTN_IN:
            loopEnd = len(self.vin) if outCode == SIGHASH_ALL_IN else hashcode[1]
            for i in range(0,loopEnd):
                inp = self.vin[i]
                op_ser += struct.pack("<B", inp.t)
                op_ser += inp.prevout.serialize(SER_IDEM)
        elif outCode == SIGHASH_THIS_IN:
            inp = self.vin[in_number]
            op_ser += struct.pack("<B", inp.t)
            op_ser += inp.prevout.serialize(SER_IDEM)
        else:
            assert false, "unknown hashcode"
        return hash256(op_ser)


    def hashInputAmountsNexa(self, hashcode, in_number):
        if len(hashcode) == 0: hashcode = bytes([0])
        outCode = hashcode[0]&0xf0
        op_ser = b""
        if outCode == SIGHASH_ALL_IN or outCode == SIGHASH_FIRSTN_IN:
            loopEnd = len(self.vin) if outCode == SIGHASH_ALL_IN else hashcode[1]
            for i in range(0,loopEnd):
                inp = self.vin[i]
                op_ser += struct.pack("<q", int(inp.amount))
        elif outCode == SIGHASH_THIS_IN:
            inp = self.vin[in_number]
            op_ser += struct.pack("<q", int(inp.amount))
        else:
            assert false, "unknown hashcode"
        return hash256(op_ser)


    def hashSequenceNexa(self, hashcode, in_number):
        if len(hashcode) == 0: hashcode = bytes([0])
        outCode = hashcode[0]&0xf0
        op_ser = b""
        if outCode == SIGHASH_ALL_IN or outCode == SIGHASH_FIRSTN_IN:
            loopEnd = len(self.vin) if outCode == SIGHASH_ALL_IN else hashcode[1]
            for i in range(0,loopEnd):
                inp = self.vin[i]
                op_ser += struct.pack("<I", inp.nSequence)
        elif outCode == SIGHASH_THIS_IN:
            inp = self.vin[in_number]
            op_ser += struct.pack("<I", inp.nSequence)
        else:
            assert false, "unknown hashcode"
        return hash256(op_ser)

    def hashOutputsNexa(self, hashcode, in_number):
        if len(hashcode) == 0: hashcode = bytes([0])
        outCode = hashcode[0]&0xf
        op_ser = b""
        if outCode == SIGHASH_ALL_OUT or outCode == SIGHASH_FIRSTN_OUT:
            loopEnd = len(self.vin) if outCode == SIGHASH_ALL_OUT else hashcode[1]
            for i in range(0,loopEnd):
                out = self.vout[i]
                op_ser += out.serialize()
        elif outCode == TWO_OUT:
            out = self.out[hashcode[1]]
            op_ser += struct.pack("<B", out.t)
            op_ser += out.serialize()
            out = self.out[hashcode[2]]
            op_ser += struct.pack("<B", out.t)
            op_ser += out.serialize()
        else:
            assert false, "unknown hashcode"
        return hash256(op_ser)

    def SignatureHashNexa(self, in_number, scriptCode, hashcode = SIGHASH_ALL, single = False, debug=False):
        """Calculate hash digest for given input. Returns it in binary, little-endian.

        txin is the corresponding input CTransaction. Supplying it is
        necessary to include the scriptPubKey in the hashed output.

        If single is True, just a single invocation of SHA256 is done,
        instead of the usual, expected double hashing. This is to aid
        applications such as CHECKDATASIG(VERIFY).
        """
        if type(hashcode) == int:  # easy API for single byte sighashtypes
            hashcode = bytes([hashcode])
        assert type(hashcode) == bytes  # New style sighashtype

        h_prevouts = self.hashPrevoutsNexa(hashcode, in_number)
        if debug:
            print("Hash prevouts:", hexlify(h_prevouts[::-1]))

        h_inputamounts = self.hashInputAmountsNexa(hashcode, in_number)
        if debug:
            print("Hash input amounts:", hexlify(h_inputamounts[::-1]))

        h_sequence = self.hashSequenceNexa(hashcode, in_number)
        if debug:
            print("Hash sequence:", hexlify(h_sequence[::-1]))

        h_outputs = self.hashOutputsNexa(hashcode, in_number)
        if debug:
            print("Hash outputs:", hexlify(h_outputs[::-1]))

        hashdata = struct.pack("<B", self.nVersion)
        hashdata += h_prevouts
        hashdata += h_inputamounts
        hashdata += h_sequence

        # FIXME: long scriptPubKeys not supported yet
        assert 75 >= len(scriptCode) > 0
        hashdata += struct.pack("<B", len(scriptCode))
        hashdata += scriptCode
        if debug:
            print("ScriptCode:", scriptCode.hex())

        hashdata += h_outputs
        hashdata += struct.pack("<I", self.nLockTime)
        if debug:
            print("locktime:", self.nLockTime)
        hashdata += hashcode
        if debug:
            print("hashcode: %s" % hexlify(hashcode))

        if debug:
            print("Hash all data:", hexlify(hashdata))
        if single:
            ret = sha256(hashdata)
            if debug:
                print("Final SHA256 sighash is: ", hexlify(ret[::-1]))
        else:
            ret = hash256(hashdata)
            if debug:
                print("Final Double SHA256 sighash is: ", hexlify(ret[::-1]))
        return ret

    def SignatureHashBCH(self, in_number, scriptCode, nValue, hashcode = BTCBCH_SIGHASH_ALL, single = False, debug=False):
        """Calculate hash digest for given input. Returns it in binary, little-endian.

        txin is the corresponding input CTransaction. Supplying it is
        necessary to include the scriptPubKey in the hashed output.

        If single is True, just a single invocation of SHA256 is done,
        instead of the usual, expected double hashing. This is to aid
        applications such as CHECKDATASIG(VERIFY).
        """
        hashdata = struct.pack("<B", self.nVersion)

        h_prevouts = self.hashPrevouts(hashcode)
        if debug:
            print("Hash prevouts:", hexlify(h_prevouts[::-1]))
        hashdata += h_prevouts
        h_inputamounts = self.hashInputAmounts(hashcode)
        if debug:
            print("Hash input amounts:", hexlify(h_inputamounts[::-1]))
        hashdata += h_inputamounts

        h_sequence = self.hashSequence(hashcode)
        if debug:
            print("Hash sequence:", hexlify(h_sequence[::-1]))

        hashdata += h_sequence
        hashdata += self.vin[in_number].prevout.serialize()

        # FIXME: long scriptPubKeys not supported yet
        assert 75 >= len(scriptCode) > 0
        hashdata += struct.pack("<B", len(scriptCode))
        hashdata += scriptCode
        if debug:
            print("ScriptCode:", scriptCode.hex())
        hashdata += struct.pack("<Q", nValue)
        if debug:
            print("Amount: ", nValue);
        hashdata += struct.pack("<I", self.vin[in_number].nSequence)
        if debug:
            print("sequence: ", self.vin[in_number].nSequence)

        h_outputs = self.hashOutputs(hashcode, in_number)
        if debug:
            print("Hash outputs:", hexlify(h_outputs[::-1]))
        hashdata += h_outputs
        hashdata += struct.pack("<I", self.nLockTime)
        if debug:
            print("locktime:", self.nLockTime)
        hashdata += struct.pack("<I", hashcode)
        if debug:
            print("hashcode: 0x%x" % hashcode)

        if debug:
            print("Hash all data:", hexlify(hashdata))
        if single:
            ret = sha256(hashdata)
            if debug:
                print("Final SHA256 sighash is: ", hexlify(ret[::-1]))
        else:
            ret = hash256(hashdata)
            if debug:
                print("Final Double SHA256 sighash is: ", hexlify(ret[::-1]))
        return ret

    def hashPrevouts(self, hashcode):
        if hashcode & BTCBCH_SIGHASH_ANYONECANPAY:
            return 32 * b"\x00"
        else:
            op_ser = b""
            for inp in self.vin:
                op_ser += struct.pack("<B", inp.t)
                op_ser += inp.prevout.serialize(SER_IDEM)
            return hash256(op_ser)

    def hashInputAmounts(self, hashcode):
        if hashcode & BTCBCH_SIGHASH_ANYONECANPAY:
            return 32 * b"\x00"
        else:
            op_ser = b""
            for inp in self.vin:
                op_ser += struct.pack("<q", int(inp.amount))
            return hash256(op_ser)


    def hashSequence(self, hashcode):
        if (hashcode & BTCBCH_SIGHASH_ANYONECANPAY or
            hashcode & 0x1f == BTCBCH_SIGHASH_SINGLE or
            hashcode & 0x1f == BTCBCH_SIGHASH_NONE):
            return 32 * b"\x00"
        else:
            seq_ser = b""
            for inp in self.vin:
                seq_ser += struct.pack("<I", inp.nSequence)
            return hash256(seq_ser)

    def hashOutputs(self, hashcode, in_number):
        if hashcode & 0x1f == BTCBCH_SIGHASH_SINGLE and in_number < len(self.vout):
            return hash256(self.vout[in_number].serialize())
        elif ((not (hashcode & 0x1f == BTCBCH_SIGHASH_SINGLE)) and
              (not (hashcode & 0x1f == BTCBCH_SIGHASH_NONE))):
            out_ser = b""
            for out in self.vout:
                out_ser += out.serialize()
            return hash256(out_ser)
        else:
            return 32 * b"\x00"

    def SignatureHashLegacy(self, script, inIdx, hashtype):
        """Consensus-correct SignatureHash (legacy variant)

        Returns (hash, err) to precisely match the consensus-critical behavior of
        the BTCBCH_SIGHASH_SINGLE bug. (inIdx is *not* checked for validity)
        """
        from .script import FindAndDelete, CScript, OP_CODESEPARATOR

        HASH_ONE = b'\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

        if inIdx >= len(self.vin):
            return (HASH_ONE, "inIdx %d out of range (%d)" % (inIdx, len(self.vin)))

        # create copy as it is going to be modified with FindAndDelete(..)
        txtmp = CTransaction(self)

        for txin in txtmp.vin:
            txin.scriptSig = b''
        txtmp.vin[inIdx].scriptSig = FindAndDelete(script, CScript([OP_CODESEPARATOR]))

        if (hashtype & 0x1f) == BTCBCH_SIGHASH_NONE:
            txtmp.vout = []

            for i in range(len(txtmp.vin)):
                if i != inIdx:
                    txtmp.vin[i].nSequence = 0

        elif (hashtype & 0x1f) == BTCBCH_SIGHASH_SINGLE:
            outIdx = inIdx
            if outIdx >= len(txtmp.vout):
                return (HASH_ONE, "outIdx %d out of range (%d)" % (outIdx, len(txtmp.vout)))

            tmp = txtmp.vout[outIdx]
            txtmp.vout = []
            for i in range(outIdx):
                txtmp.vout.append(CTxOut())
            txtmp.vout.append(tmp)

            for i in range(len(txtmp.vin)):
                if i != inIdx:
                    txtmp.vin[i].nSequence = 0

        if hashtype & BTCBCH_SIGHASH_ANYONECANPAY:
            tmp = txtmp.vin[inIdx]
            txtmp.vin = []
            txtmp.vin.append(tmp)

        s = txtmp.serialize()
        s += struct.pack(b"<I", hashtype)

        hash = hash256(s)

        return (hash, None)

class SatoshiBlockHeader(object):
    def __init__(self, header=None):
        if header is None:
            self.set_null()
        else:
            self.nVersion = header.nVersion
            self.hashPrevBlock = header.hashPrevBlock
            self.hashMerkleRoot = header.hashMerkleRoot
            self.nTime = header.nTime
            self.nBits = header.nBits
            self.nNonce = header.nNonce
            self.sha256 = header.sha256
            self.hash = header.hash
            self.calc_sha256()

    def set_null(self):
        self.nVersion = 1
        self.hashPrevBlock = 0
        self.hashMerkleRoot = 0
        self.nTime = 0
        self.nBits = 0
        self.nNonce = 0
        self.sha256 = None
        self.hash = None

    def deserialize(self, f):
        self.nVersion = struct.unpack("<i", f.read(4))[0]
        self.hashPrevBlock = deser_uint256(f)
        self.hashMerkleRoot = deser_uint256(f)
        self.nTime = struct.unpack("<I", f.read(4))[0]
        self.nBits = struct.unpack("<I", f.read(4))[0]
        self.nNonce = struct.unpack("<I", f.read(4))[0]
        self.sha256 = None
        self.hash = None

    def serialize(self, stype=SER_DEFAULT):
        r = b""
        r += struct.pack("<i", self.nVersion)
        r += ser_uint256(self.hashPrevBlock)
        r += ser_uint256(self.hashMerkleRoot)
        r += struct.pack("<I", self.nTime)
        r += struct.pack("<I", self.nBits)
        r += struct.pack("<I", self.nNonce)
        return r

    def calc_sha256(self):
        if self.sha256 is None:
            r = b""
            r += struct.pack("<i", self.nVersion)
            r += ser_uint256(self.hashPrevBlock)
            r += ser_uint256(self.hashMerkleRoot)
            r += struct.pack("<I", self.nTime)
            r += struct.pack("<I", self.nBits)
            r += struct.pack("<I", self.nNonce)
            self.sha256 = uint256_from_str(hash256(r))
            self.hash = encode(hash256(r)[::-1], 'hex_codec').decode('ascii')
        return self.hash

    def gethashprevblock(self, encoding = 'int'):
        assert encoding == 'hex' or encoding == 'int'
        if encoding == 'int':
            return self.hashPrevBlock
        return hex(self.hashPrevBlock)


    def gethash(self, encoding = 'int'):
        assert encoding == 'hex' or encoding == 'int'
        self.calc_sha256()
        if encoding == 'int':
            return self.sha256
        return hex(self.sha256)

    def rehash(self):
        self.sha256 = None
        self.calc_sha256()
        return self.sha256

    def summary(self):
        s = []
        s.append("Block:  %064x  Time:%s  Version:0x%x Bits:0x%08x\n" %
                 (self.gethash(), time.ctime(self.nTime), self.nVersion, self.nBits))
        s.append("Parent: %064x  Merkle: %064x" % (self.hashPrevBlock, self.hashMerkleRoot))
        return "".join(s)

    def __str__(self):
        return "SatoshiBlockHeader(hash=%064x nVersion=%i hashPrevBlock=%064x hashMerkleRoot=%064x nTime=%s nBits=%08x nNonce=%08x)" \
            % (self.gethash(), self.nVersion, self.hashPrevBlock, self.hashMerkleRoot, time.ctime(self.nTime), self.nBits, self.nNonce)

    def __repr__(self):
        return "SatoshiBlockHeader(nVersion=%i hashPrevBlock=%064x hashMerkleRoot=%064x nTime=%s nBits=%08x nNonce=%08x)" \
            % (self.nVersion, self.hashPrevBlock, self.hashMerkleRoot,
               time.ctime(self.nTime), self.nBits, self.nNonce)


class SatoshiBlock(SatoshiBlockHeader):
    def __init__(self, header=None):
        super(CBlock, self).__init__(header)
        self.vtx = []

    def deserialize(self, f):
        super(CBlock, self).deserialize(f)
        self.vtx = deser_vector(f, CTransaction)

    def serialize(self, stype=SER_DEFAULT):
        r = b""
        r += super(CBlock, self).serialize()
        r += ser_vector(self.vtx)
        return r

    def calc_merkle_root(self):
        hashes = []
        for tx in self.vtx:
            tx.GetId()
            hashes.append(ser_uint256(tx.sha256))
        while len(hashes) > 1:
            newhashes = []
            for i in range(0, len(hashes), 2):
                i2 = min(i + 1, len(hashes) - 1)
                newhashes.append(hash256(hashes[i] + hashes[i2]))
            hashes = newhashes
        if hashes:
            return uint256_from_str(hashes[0])
        return 0

    def is_valid(self):
        self.calc_sha256()
        target = uint256_from_compact(self.nBits)
        if self.sha256 > target:
            return False
        for tx in self.vtx:
            if not tx.is_valid():
                return False
        if self.calc_merkle_root() != self.hashMerkleRoot:
            return False
        return True

    def solve(self):
        self.sha256 = None

        target = uint256_from_compact(self.nBits)
        while True:

            r = b""
            r += struct.pack("<i", self.nVersion)
            r += ser_uint256(self.hashPrevBlock)
            r += ser_uint256(self.hashMerkleRoot)
            r += struct.pack("<I", self.nTime)
            r += struct.pack("<I", self.nBits)
            r += struct.pack("<I", self.nNonce)
            self.sha256 = uint256_from_str(hash256(r))
            self.hash = encode(hash256(r)[::-1], 'hex_codec').decode('ascii')

            # create a private key from the blockhash
            private_key = hash256(r)

            # create a schorr sig by signing with the sha256(blockhash) and, private key from above
            sig = sign(private_key, sha256(hash256(r)))

            # get the sha256 of the schnorr sig
            schnorr_sha256 = uint256_from_str(sha256(sig))
            if schnorr_sha256 < target:
                break

            self.nNonce += 1

    def __str__(self):
        return "CBlock(nVersion=%i hashPrevBlock=%064x hashMerkleRoot=%064x nTime=%s nBits=%08x nNonce=%08x vtx_len=%d)" \
            % (self.nVersion, self.hashPrevBlock, self.hashMerkleRoot,
               time.ctime(self.nTime), self.nBits, self.nNonce, len(self.vtx))

    def __repr__(self):
        return "CBlock(nVersion=%i hashPrevBlock=%064x hashMerkleRoot=%064x nTime=%s nBits=%08x nNonce=%08x vtx=%s)" \
            % (self.nVersion, self.hashPrevBlock, self.hashMerkleRoot,
               time.ctime(self.nTime), self.nBits, self.nNonce, repr(self.vtx))


class CBlockHeader(object):
    def __init__(self, header=None):
        if header is None:
            self.set_null()
        else:
            self.set(header)

    def set(self, header):
        self.hashPrevBlock = header.hashPrevBlock
        self.nBits = header.nBits
        self.hashAncestor = header.hashAncestor
        self.hashMerkleRoot = header.hashMerkleRoot
        self.hashTxFilter = header.hashTxFilter
        self.nTime = header.nTime
        self.height = header.height
        self.chainWork = header.chainWork
        self.size = header.size
        self.txCount = header.txCount
        self.feePoolAmt = header.feePoolAmt
        self.utxoCommitment = header.utxoCommitment
        self.minerData = header.minerData
        self.nonce = header.nonce
        self.hashNum = None
        self.calc_hash()

    def set_null(self):
        self.hashPrevBlock = 0
        self.nBits = 0
        self.hashAncestor = 0
        self.hashMerkleRoot = 0
        self.hashTxFilter = 0
        self.nTime = 0
        self.height = 0
        self.chainWork = 0
        self.size = 0
        self.txCount = 0
        self.feePoolAmt = 0
        self.utxoCommitment = b""
        self.minerData = b""
        self.nonce = None
        self.hashNum = None
        self.hash = None

    def deserialize(self, f):
        self.hashPrevBlock = deser_uint256(f)
        self.nBits = struct.unpack("<I", f.read(4))[0]
        self.hashAncestor = deser_uint256(f)
        self.hashMerkleRoot = deser_uint256(f)
        self.hashTxFilter = deser_uint256(f)
        self.nTime = struct.unpack("<I", f.read(4))[0]
        self.height = deser_varint(f)
        self.chainWork = deser_uint256(f)
        self.size = struct.unpack("<Q", f.read(8))[0]
        self.txCount = deser_varint(f)
        self.feePoolAmt = deser_varint(f)
        self.utxoCommitment = deser_string(f)
        self.minerData = deser_string(f)
        self.nonce = deser_string(f)
        self.hashNum = None
        self.hash = None

    def serialize(self, stype=SER_DEFAULT):
        r = b""
        r += ser_uint256(self.hashPrevBlock)
        r += struct.pack("<I", self.nBits)
        r += ser_uint256(self.hashAncestor)
        r += ser_uint256(self.hashMerkleRoot)
        r += ser_uint256(self.hashTxFilter)
        r += struct.pack("<I", self.nTime)
        r += ser_varint(self.height)
        r += ser_uint256(self.chainWork)
        r += struct.pack("<Q", self.size)
        r += ser_varint(self.txCount)
        r += ser_varint(self.feePoolAmt)
        r += ser_string(self.utxoCommitment)
        r += ser_string(self.minerData)
        r += ser_string(self.nonce)
        return r

    def HexStr(self):
        """ Match the C++ equivalent"""
        return self.serialize().hex()

    def calc_mining_commitment(self):
        if True:
            hpv = ser_uint256(self.hashPrevBlock)
            mh = b""
            mh += hpv
            mh += struct.pack("<I", self.nBits)
            # print("mh bytes: " + mh.hex())
            shaMh = sha256(mh)
            # print("miniheader: " + shaMh[::-1].hex())  # note bitcoind prints hash backwards from how it uses it so that's why [::-1]

            eh = b""
            eh += ser_uint256(self.hashAncestor)
            eh += ser_uint256(self.hashTxFilter)
            eh += ser_uint256(self.hashMerkleRoot)
            eh += struct.pack("<I", self.nTime)
            eh += struct.pack("<Q", self.height)
            eh += ser_uint256(self.chainWork)
            eh += struct.pack("<Q", self.size)
            eh += struct.pack("<Q", self.txCount)
            eh += struct.pack("<Q", self.feePoolAmt)
            eh += ser_string(self.utxoCommitment)
            eh += ser_string(self.minerData)
            shaEh = sha256(eh)
            # print("extended bytes: " + eh.hex())
            # print("ext: " + shaEh[::-1].hex())

            hashBytes = sha256(shaMh + shaEh)
            # print("full mining commitment: " + hashBytes.hex())
            return hashBytes

    def calc_hash(self):
        if self.hashNum is None:
            mh = b""
            mh += ser_uint256(self.hashPrevBlock)
            mh += struct.pack("<I", self.nBits)
            shaMh = sha256(mh)

            eh = b""
            eh += ser_uint256(self.hashAncestor)
            eh += ser_uint256(self.hashTxFilter)
            eh += ser_uint256(self.hashMerkleRoot)
            eh += struct.pack("<I", self.nTime)
            eh += struct.pack("<Q", self.height)
            eh += ser_uint256(self.chainWork)
            eh += struct.pack("<Q", self.size)
            eh += struct.pack("<Q", self.txCount)
            eh += struct.pack("<Q", self.feePoolAmt)
            eh += ser_string(self.utxoCommitment)
            eh += ser_string(self.minerData)
            eh += ser_string(self.nonce)

            shaEh = sha256(eh)
            hashBytes = sha256(shaMh + shaEh)
            self.hashNum = uint256_from_str(hashBytes)
            self.hash = encode(hashBytes[::-1], 'hex_codec').decode('ascii')
        return self.hash

    def gethashprevblock(self, encoding = 'int'):
        assert encoding == 'hex' or encoding == 'int'
        if encoding == 'int':
            return self.hashPrevBlock
        return hex(self.hashPrevBlock)


    def gethash(self, encoding = 'int'):
        assert encoding == 'hex' or encoding == 'int'
        self.calc_hash()
        if encoding == 'int':
            return self.hashNum
        return hex(self.hashNum)

    def gethashhex(self):
        self.calc_hash()
        return self.hash

    def rehash(self):
        self.hashNum = None
        self.calc_hash()
        return self.hashNum

    def summary(self):
        s = []
        s.append("Block:  %064x  Time:%s  Version:0x%x Bits:0x%08x\n" %
                 (self.gethash(), time.ctime(self.nTime), self.nVersion, self.nBits))
        s.append("Parent: %064x  Merkle: %064x" % (self.hashPrevBlock, self.hashMerkleRoot))
        return "".join(s)

    def __str__(self):
        return "CBlockHeader(hash=%064x height=%d hashPrevBlock=%064x hashAncestor=%064x hashMerkleRoot=%064x nTime=%s nBits=%08x nonce=%s)" \
            % (self.gethash(), self.height, self.hashPrevBlock, self.hashAncestor, self.hashMerkleRoot, time.ctime(self.nTime), self.nBits, self.nonce.hex())

    def __repr__(self):
        return "CBlockHeader(hash=%064x height=%d hashPrevBlock=%064x hashAncestor=%064x hashMerkleRoot=%064x nTime=%s nBits=%08x nonce=%s)" \
            % (self.gethash(), self.height, self.hashPrevBlock, self.hashAncestor, self.hashMerkleRoot, time.ctime(self.nTime), self.nBits, self.nonce.hex())


class CBlock(CBlockHeader):
    def __init__(self, header=None):
        if type(header) is str:
            FromHex(self, header)
        else:
            super(CBlock, self).__init__(header)
            self.vtx = []

    def deserialize(self, f):
        super(CBlock, self).deserialize(f)
        self.vtx = deser_vector(f, CTransaction)

    def serialize(self, stype=SER_DEFAULT):
        r = b""
        r += super(CBlock, self).serialize(stype)
        r += ser_vector(self.vtx)
        return r

    def update_fields(self):
        self.hashMerkleRoot = self.calc_merkle_root()
        self.calc_size()
        self.txCount = len(self.vtx)
        self.hashNum = None # force recalculation of hash since block changed
        self.hash = None

    def calc_merkle_root(self, debug=False):
        hashes = []
        for tx in self.vtx:
            hashes.append(tx.GetId())

        if debug:
            print("merkle root hashes:")
            for x in hashes:
                print(util.uint256ToRpcHex(x))
        while len(hashes) > 1:
            newhashes = []
            for i in range(0, len(hashes), 2):
                i2 = min(i + 1, len(hashes) - 1)
                newhashes.append(hash256(hashes[i] + hashes[i2]))
            hashes = newhashes
        if hashes:
            return uint256_from_str(hashes[0])
        return 0

    def calc_size(self):
         self.size = len(self.serialize()) - (len(self.nonce) + 1)

    def calc_mining_hash(self):
        assert 0  # TODO

    def is_valid(self):
        miningHash = self.calc_mining_hash()
        target = uint256_from_compact(self.nBits)
        if miningHash > target:
            return False
        for tx in self.vtx:
            if not tx.is_valid():
                return False
        if self.calc_merkle_root() != self.hashMerkleRoot:
            return False
        return True

    def solve(self):

        assert self.txCount == len(self.vtx)
        assert self.size == len(self.serialize()) - (len(self.nonce) + 1)

        target = uint256_from_compact(self.nBits)
        mining_commitment = uint256_from_str(self.calc_mining_commitment())
        # print("Mining block commitment: %x" % mining_commitment)
        while True:

            r = b""
            r += ser_uint256(mining_commitment)
            r += ser_string(self.nonce)
            miningHash = hash256(r)
            sha256ofMh = sha256(miningHash)

            # create a private key from the blockhash
            private_key = miningHash

            # create a schorr sig by signing with the sha256(blockhash) and, private key from above
            sig = sign(private_key, sha256ofMh)

            # get the sha256 of the schnorr sig
            schnorr_sha256 = uint256_from_str(sha256(sig))
            if schnorr_sha256 < target:
                break

            # Roll 3 bytes TODO: verify that nonce is big enough
            if self.nonce[0] == 255:
                if len(self.nonce) == 1: self.nonce.append(0)
                if self.nonce[1] == 255:
                    if len(self.nonce) == 2: self.nonce.append(0)
                    self.nonce[2] += 1
                self.nonce[1] += 1
            self.nonce[0] += 1
        self.hashNum = None # force recalculation of hash since block changed
        self.hash = None

    def __str__(self):
        return "CBlock(hashPrevBlock=%064x hashMerkleRoot=%064x nTime=%s nBits=%08x nonce=%s vtx_len=%d)" \
            % (self.hashPrevBlock, self.hashMerkleRoot,
               time.ctime(self.nTime), self.nBits, self.nonce.hex(), len(self.vtx))

    def __repr__(self):
        return "CBlock(hashPrevBlock=%064x hashMerkleRoot=%064x nTime=%s nBits=%08x nonce=%s vtx=%s)" \
            % (self.hashPrevBlock, self.hashMerkleRoot,
               time.ctime(self.nTime), self.nBits, self.nonce.hex(), repr(self.vtx))

class CMerkleBlock(CBlockHeader):
    def __init__(self):
        super(CMerkleBlock, self).__init__()
        self.nTransactions = 0
        self.vHash = []
        self.vBytes = b""

    def deserialize(self, f):
        super(CMerkleBlock, self).deserialize(f)
        self.nTransactions = struct.unpack("<I", f.read(4))[0]
        self.vHash = deser_uint256_vector(f)
        self.vBytes = deser_bytes(f)

    def serialize(self, stype=SER_DEFAULT):
        r = b""
        r += super(CMerkleBlock, self).serialize(stype)
        r += struct.pack("<I", self.nTransactions)
        r += ser_uint256_vector(self.vHash)
        r += ser_bytes(self.vBytes)
        return r

    def __str__(self):
        return "CMerkleBlock(hashPrevBlock=%064x hashMerkleRoot=%064x nTime=%s nBits=%08x nonce=%s vhash_len=%d)" \
            % (self.hashPrevBlock, self.hashMerkleRoot,
               time.ctime(self.nTime), self.nBits, self.nonce.hex(), len(self.vHash))

    def __repr__(self):
        return "CMerkleBlock(hashPrevBlock=%064x hashMerkleRoot=%064x nTime=%s nBits=%08x nonce=%s vhash_len=%s)" \
            % (self.hashPrevBlock, self.hashMerkleRoot,
               time.ctime(self.nTime), self.nBits, self.nonce.hex(), repr(self.vHash))

class CUnsignedAlert(object):
    def __init__(self):
        self.nVersion = 1
        self.nRelayUntil = 0
        self.nExpiration = 0
        self.nID = 0
        self.nCancel = 0
        self.setCancel = []
        self.nMinVer = 0
        self.nMaxVer = 0
        self.setSubVer = []
        self.nPriority = 0
        self.strComment = b""
        self.strStatusBar = b""
        self.strReserved = b""

    def deserialize(self, f):
        self.nVersion = struct.unpack("<i", f.read(4))[0]
        self.nRelayUntil = struct.unpack("<q", f.read(8))[0]
        self.nExpiration = struct.unpack("<q", f.read(8))[0]
        self.nID = struct.unpack("<i", f.read(4))[0]
        self.nCancel = struct.unpack("<i", f.read(4))[0]
        self.setCancel = deser_int_vector(f)
        self.nMinVer = struct.unpack("<i", f.read(4))[0]
        self.nMaxVer = struct.unpack("<i", f.read(4))[0]
        self.setSubVer = deser_string_vector(f)
        self.nPriority = struct.unpack("<i", f.read(4))[0]
        self.strComment = deser_string(f)
        self.strStatusBar = deser_string(f)
        self.strReserved = deser_string(f)

    def serialize(self, stype=SER_DEFAULT):
        r = b""
        r += struct.pack("<i", self.nVersion)
        r += struct.pack("<q", self.nRelayUntil)
        r += struct.pack("<q", self.nExpiration)
        r += struct.pack("<i", self.nID)
        r += struct.pack("<i", self.nCancel)
        r += ser_int_vector(self.setCancel)
        r += struct.pack("<i", self.nMinVer)
        r += struct.pack("<i", self.nMaxVer)
        r += ser_string_vector(self.setSubVer)
        r += struct.pack("<i", self.nPriority)
        r += ser_string(self.strComment)
        r += ser_string(self.strStatusBar)
        r += ser_string(self.strReserved)
        return r

    def __repr__(self):
        return "CUnsignedAlert(nVersion %d, nRelayUntil %d, nExpiration %d, nID %d, nCancel %d, nMinVer %d, nMaxVer %d, nPriority %d, strComment %s, strStatusBar %s, strReserved %s)" \
            % (self.nVersion, self.nRelayUntil, self.nExpiration, self.nID,
               self.nCancel, self.nMinVer, self.nMaxVer, self.nPriority,
               self.strComment, self.strStatusBar, self.strReserved)


class CAlert(object):
    def __init__(self):
        self.vchMsg = b""
        self.vchSig = b""

    def deserialize(self, f):
        self.vchMsg = deser_string(f)
        self.vchSig = deser_string(f)

    def serialize(self, stype=SER_DEFAULT):
        r = b""
        r += ser_string(self.vchMsg)
        r += ser_string(self.vchSig)
        return r

    def __repr__(self):
        return "CAlert(vchMsg.sz %d, vchSig.sz %d)" \
            % (len(self.vchMsg), len(self.vchSig))


class PrefilledTransaction(object):
    def __init__(self, index=0, tx = None):
        self.index = index
        self.tx = tx

    def deserialize(self, f):
        self.index = deser_compact_size(f)
        self.tx = CTransaction()
        self.tx.deserialize(f)

    def serialize(self, stype=SER_DEFAULT):
        r = b""
        r += ser_compact_size(self.index)
        r += self.tx.serialize(stype)
        return r

    def __repr__(self):
        return "PrefilledTransaction(index=%d, tx=%s)" % (self.index, repr(self.tx))

# This is what we send on the wire, in a cmpctblock message.
class P2PHeaderAndShortIDs(object):
    def __init__(self):
        self.header = CBlockHeader()
        self.nonce = 0
        self.shortids_length = 0
        self.shortids = []
        self.prefilled_txn_length = 0
        self.prefilled_txn = []

    def deserialize(self, f):
        self.header.deserialize(f)
        self.nonce = struct.unpack("<Q", f.read(8))[0]
        self.shortids_length = deser_compact_size(f)
        for i in range(self.shortids_length):
            # shortids are defined to be 6 bytes in the spec, so append
            # two zero bytes and read it in as an 8-byte number
            self.shortids.append(struct.unpack("<Q", f.read(6) + b'\x00\x00')[0])
        self.prefilled_txn = deser_vector(f, PrefilledTransaction)
        self.prefilled_txn_length = len(self.prefilled_txn)

    def serialize(self, stype=SER_DEFAULT):
        r = b""
        r += self.header.serialize(stype)
        r += struct.pack("<Q", self.nonce)
        r += ser_compact_size(self.shortids_length)
        for x in self.shortids:
            # We only want the first 6 bytes
            r += struct.pack("<Q", x)[0:6]
        r += ser_vector(self.prefilled_txn)
        return r

    def __repr__(self):
        return "P2PHeaderAndShortIDs(header=%s, nonce=%d, shortids_length=%d, shortids=%s, prefilled_txn_length=%d, prefilledtxn=%s" % (repr(self.header), self.nonce, self.shortids_length, repr(self.shortids), self.prefilled_txn_length, repr(self.prefilled_txn))


# Calculate the BIP 152-compact blocks shortid for a given transaction hash
def calculate_shortid(k0, k1, tx_hash):
    expected_shortid = siphash256(k0, k1, tx_hash)
    expected_shortid &= 0x0000ffffffffffff
    return expected_shortid

# This version gets rid of the array lengths, and reinterprets the differential
# encoding into indices that can be used for lookup.
class HeaderAndShortIDs(object):
    def __init__(self, p2pheaders_and_shortids = None):
        self.header = CBlockHeader()
        self.nonce = 0
        self.shortids = []
        self.prefilled_txn = []

        if p2pheaders_and_shortids != None:
            self.header = p2pheaders_and_shortids.header
            self.nonce = p2pheaders_and_shortids.nonce
            self.shortids = p2pheaders_and_shortids.shortids
            last_index = -1
            for x in p2pheaders_and_shortids.prefilled_txn:
                self.prefilled_txn.append(PrefilledTransaction(x.index + last_index + 1, x.tx))
                last_index = self.prefilled_txn[-1].index

    def to_p2p(self):
        ret = P2PHeaderAndShortIDs()
        ret.header = self.header
        ret.nonce = self.nonce
        ret.shortids_length = len(self.shortids)
        ret.shortids = self.shortids
        ret.prefilled_txn_length = len(self.prefilled_txn)
        ret.prefilled_txn = []
        last_index = -1
        for x in self.prefilled_txn:
            ret.prefilled_txn.append(PrefilledTransaction(x.index - last_index - 1, x.tx))
            last_index = x.index
        return ret

    def get_siphash_keys(self):
        header_nonce = self.header.serialize()
        header_nonce += struct.pack("<Q", self.nonce)
        hash_header_nonce_as_str = sha256(header_nonce)
        key0 = struct.unpack("<Q", hash_header_nonce_as_str[0:8])[0]
        key1 = struct.unpack("<Q", hash_header_nonce_as_str[8:16])[0]
        return [ key0, key1 ]

    def initialize_from_block(self, block, nonce=0, prefill_list = [0]):
        self.header = CBlockHeader(block)
        self.nonce = nonce
        self.prefilled_txn = [ PrefilledTransaction(i, block.vtx[i]) for i in prefill_list ]
        self.shortids = []
        [k0, k1] = self.get_siphash_keys()
        for i in range(len(block.vtx)):
            if i not in prefill_list:
                self.shortids.append(calculate_shortid(k0, k1, block.vtx[i].GetIdAsInt()))

    def __repr__(self):
        return "HeaderAndShortIDs(header=%s, nonce=%d, shortids=%s, prefilledtxn=%s" % (repr(self.header), self.nonce, repr(self.shortids), repr(self.prefilled_txn))


class BlockTransactionsRequest(object):

    def __init__(self, blockhash=0, indexes = None):
        self.blockhash = blockhash
        self.indexes = indexes if indexes != None else []

    def deserialize(self, f):
        self.blockhash = deser_uint256(f)
        indexes_length = deser_compact_size(f)
        for i in range(indexes_length):
            self.indexes.append(deser_compact_size(f))

    def serialize(self, stype=SER_DEFAULT):
        r = b""
        r += ser_uint256(self.blockhash)
        r += ser_compact_size(len(self.indexes))
        for x in self.indexes:
            r += ser_compact_size(x)
        return r

    # helper to set the differentially encoded indexes from absolute ones
    def from_absolute(self, absolute_indexes):
        self.indexes = []
        last_index = -1
        for x in absolute_indexes:
            self.indexes.append(x-last_index-1)
            last_index = x

    def to_absolute(self):
        absolute_indexes = []
        last_index = -1
        for x in self.indexes:
            absolute_indexes.append(x+last_index+1)
            last_index = absolute_indexes[-1]
        return absolute_indexes

    def __repr__(self):
        return "BlockTransactionsRequest(hash=%064x indexes=%s)" % (self.blockhash, repr(self.indexes))


class BlockTransactions(object):

    def __init__(self, blockhash=0, transactions = None):
        assert blockhash != None
        self.blockhash = blockhash
        self.transactions = transactions if transactions != None else []

    def deserialize(self, f):
        self.blockhash = deser_uint256(f)
        self.transactions = deser_vector(f, CTransaction)

    def serialize(self, with_witness=False, stype=SER_DEFAULT):
        assert type(with_witness) is bool
        r = b""
        r += ser_uint256(self.blockhash)
        if with_witness:
            r += ser_vector(self.transactions, "serialize_with_witness")
        else:
            r += ser_vector(self.transactions)
        return r

    def __repr__(self):
        return "BlockTransactions(hash=%064x transactions=%s)" % (self.blockhash, repr(self.transactions))

# Objects that correspond to messages on the wire
class msg_version(object):
    command = b"version"

    def __init__(self):
        self.nVersion = MY_VERSION
        self.nServices = 1
        self.nTime = int(time.time())
        self.addrTo = CAddressInVersion()
        self.addrFrom = CAddressInVersion()
        self.nNonce = random.getrandbits(64)
        self.strSubVer = MY_SUBVERSION
        self.nStartingHeight = -1

    def deserialize(self, f):
        self.nVersion = struct.unpack("<i", f.read(4))[0]
        self.nServices = struct.unpack("<Q", f.read(8))[0]
        self.nTime = struct.unpack("<q", f.read(8))[0]
        self.addrTo = CAddressInVersion()
        self.addrTo.deserialize(f)
        if self.nVersion >= 106:
            self.addrFrom = CAddressInVersion()
            self.addrFrom.deserialize(f)
            self.nNonce = struct.unpack("<Q", f.read(8))[0]
            self.strSubVer = deser_string(f)
            if self.nVersion >= 209:
                self.nStartingHeight = struct.unpack("<i", f.read(4))[0]
            else:
                self.nStartingHeight = None
        else:
            self.addrFrom = None
            self.nNonce = None
            self.strSubVer = None
            self.nStartingHeight = None

    def serialize(self, stype=SER_DEFAULT):
        r = b""
        r += struct.pack("<i", self.nVersion)
        r += struct.pack("<Q", self.nServices)
        r += struct.pack("<q", self.nTime)
        r += self.addrTo.serialize()
        r += self.addrFrom.serialize()
        r += struct.pack("<Q", self.nNonce)
        r += ser_string(self.strSubVer)
        r += struct.pack("<i", self.nStartingHeight)
        return r

    def __repr__(self):
        return 'msg_version(nVersion=%i nServices=%i nTime=%s addrTo=%s addrFrom=%s nNonce=0x%016X strSubVer=%s nStartingHeight=%i)' \
            % (self.nVersion, self.nServices, time.ctime(self.nTime),
               repr(self.addrTo), repr(self.addrFrom), self.nNonce,
               self.strSubVer, self.nStartingHeight)


class msg_verack(object):
    command = b"verack"

    def __init__(self):
        pass

    def deserialize(self, f):
        pass

    def serialize(self):
        return b""

    def __repr__(self):
        return "msg_verack()"

class msg_extversion(object):
    command = b"extversion"

    def __init__(self, xver = {}):
        self.xver = xver

    def deserialize(self, f):
        map_size = CompactSize().deserialize(f)
        self.xver = {}
        for i in range(map_size):
            key = CompactSize().deserialize(f)
            val_size = CompactSize().deserialize(f)
            value = f.read(val_size)
            self.xver[key] = value

    def serialize(self, stype=SER_DEFAULT):
        res = CompactSize(len(self.xver)).serialize()
        for k, v in self.xver.items():
            res += CompactSize(k).serialize()
            if type(v) is int:  # serialize integers in compact format inside the vector
                v = CompactSize(v).serialize()
            res += CompactSize(len(v)).serialize()
            res += v
        return res

    def __repr__(self):
        return "msg_extversion(%s)" % repr(self.xver)

class msg_xupdate(object):
    command = b"xupdate"

    def __init__(self, xver = {}):
        self.xver = xver

    def deserialize(self, f):
        map_size = CompactSize().deserialize(f)
        self.xver = {}
        for i in range(map_size):
            key = CompactSize().deserialize(f)
            val_size = CompactSize().deserialize(f)
            value = f.read(val_size)
            self.xver[key] = value

    def serialize(self, stype=SER_DEFAULT):
        res = CompactSize(len(self.xver)).serialize(stype)
        for k, v in self.xver.items():
            res += CompactSize(k).serialize(stype)
            if type(v) is int:  # serialize integers in compact format inside the vector
                v = CompactSize(v).serialize(stype)
            res += CompactSize(len(v)).serialize(stype)
            res += v
        return res

    def __repr__(self):
        return "msg_xupdate(%s)" % repr(self.xver)


class msg_addr(object):
    command = b"addr"

    def __init__(self):
        self.addrs = []

    def deserialize(self, f):
        self.addrs = deser_vector(f, CAddress)

    def serialize(self, stype=SER_DEFAULT):
        return ser_vector(self.addrs)

    def __repr__(self):
        return "msg_addr(addrs=%s)" % (repr(self.addrs))


class msg_alert(object):
    command = b"alert"

    def __init__(self):
        self.alert = CAlert()

    def deserialize(self, f):
        self.alert = CAlert()
        self.alert.deserialize(f)

    def serialize(self, stype=SER_DEFAULT):
        r = b""
        r += self.alert.serialize()
        return r

    def __repr__(self):
        return "msg_alert(alert=%s)" % (repr(self.alert), )


class msg_inv(object):
    command = b"inv"

    def __init__(self, inv=None):
        if inv is None:
            self.inv = []
        elif type(inv) is list:
            self.inv = inv
        elif type(inv) is CInv:
            self.inv = [inv]
        else:
            raise Exception("bad object passed to msg inv; it needs to be a CInv or list of CInv")

    def deserialize(self, f):
        self.inv = deser_vector(f, CInv)

    def serialize(self, stype=SER_DEFAULT):
        return ser_vector(self.inv)

    def __repr__(self):
        return "msg_inv(inv=%s)" % (repr(self.inv))

class msg_getdata(object):
    command = b"getdata"

    def __init__(self, inv=None):
        if inv is None:
            self.inv = []
        elif type(inv) == list:
            self.inv = inv
        elif type(inv) is CInv:
            self.inv = [inv]
        else:
            raise Exception("bad object passed to msg inv; it needs to be a CInv or list of CInv")

    def deserialize(self, f):
        self.inv = deser_vector(f, CInv)

    def serialize(self, stype=SER_DEFAULT):
        return ser_vector(self.inv)

    def __repr__(self):
        return "msg_getdata(inv=%s)" % (repr(self.inv))

class msg_notfound(object):
    command = b"notfound"

    def __init__(self, inv=None):
        if inv is None:
            self.inv = []
        elif type(inv) == list:
            self.inv = inv
        else:
            self.inv = [inv]

    def deserialize(self, f):
        self.inv = deser_vector(f, CInv)

    def serialize(self, stype=SER_DEFAULT):
        return ser_vector(self.inv)

    def __repr__(self):
        return "msg_notfound(inv=%s)" % (repr(self.inv))


class msg_getblocks(object):
    command = b"getblocks"

    def __init__(self):
        self.locator = CBlockLocator()
        self.hashstop = 0

    def deserialize(self, f):
        self.locator = CBlockLocator()
        self.locator.deserialize(f)
        self.hashstop = deser_uint256(f)

    def serialize(self, stype=SER_DEFAULT):
        r = b""
        r += self.locator.serialize()
        r += ser_uint256(self.hashstop)
        return r

    def __repr__(self):
        return "msg_getblocks(locator=%s hashstop=%064x)" \
            % (repr(self.locator), self.hashstop)


class msg_tx(object):
    command = b"tx"

    def __init__(self, tx=CTransaction()):
        self.tx = tx

    def deserialize(self, f):
        self.tx.deserialize(f)

    def serialize(self, stype=SER_DEFAULT):
        return self.tx.serialize()

    def __repr__(self):
        return "msg_tx(tx=%s)" % (repr(self.tx))


class msg_block(object):
    command = b"block"

    def __init__(self, block=None):
        if block is None:
            self.block = CBlock()
        else:
            self.block = block

    def deserialize(self, f):
        self.block.deserialize(f)

    def serialize(self, stype=SER_DEFAULT):
        return self.block.serialize()

    def __str__(self):
        return "msg_block(block=%s)" % (str(self.block))

    def __repr__(self):
        return "msg_block(block=%s)" % (repr(self.block))

class msg_merkleblock(object):
    command = b"merkleblock"

    def __init__(self, block=None):
        if block is None:
            self.block = CMerkleBlock()
        else:
            self.block = block

    def deserialize(self, f):
        self.block.deserialize(f)

    def serialize(self, stype=SER_DEFAULT):
        return self.block.serialize()

    def __str__(self):
        return "msg_filteredblock(block=%s)" % (str(self.block))

    def __repr__(self):
        return "msg_filteredblock(block=%s)" % (repr(self.block))


class msg_getaddr(object):
    command = b"getaddr"

    def __init__(self):
        pass

    def deserialize(self, f):
        pass # This message has no addtl data

    def serialize(self, stype=SER_DEFAULT):
        return b""  # This message has no addtl data

    def __repr__(self):
        return "msg_getaddr()"

class msg_getheaderpath(object):
    command = b"gethdrpath"

    def __init__(self, fromHeight, fromHash, toHeight, toHash):
        self.fromHeight = fromHeight
        #if type(fromHash) is int:
        #    fromHash = ser_uint256(fromHash)
        #if type(toHash) is int:
        #    toHash = ser_uint256(toHash)
        #assert len(fromHash) == 32
        #assert len(toHash) == 32

        self.fromHash = fromHash
        self.toHeight = toHeight
        self.toHash = toHash

    def deserialize(self, f):
        self.fromHeight = struct.unpack("<I", f.read(4))[0]
        self.fromHash = deser_uint256(f)
        self.toHeight = struct.unpack("<I", f.read(4))[0]
        self.toHash = deser_uint256(f)

    def serialize(self, stype=SER_DEFAULT):
        r = b""
        r += struct.pack("<I", self.fromHeight)
        r += ser_uint256(self.fromHash)
        r += struct.pack("<I", self.toHeight)
        r += ser_uint256(self.toHash)
        return r

    def __repr__(self):
        return "msg_getheaderpath(fromHeight=%d, fromHash=%064x, toHeight=%d, toHash=%064x)" % (self.fromHeight, self.fromHash, self.toHeight, self.toHash)

class msg_headerpath(object):
    command = b"hdrpath"

    def __init__(self, headers = None):
        self.headers = [] if headers is None else headers

    def deserialize(self, f):
        self.headers = deser_vector(f, CBlockHeader)

    def serialize(self, stype=SER_DEFAULT):
        for x in self.headers:
            assert type(x) is CBlockHeader
        return ser_vector(self.headers, stype)

    def __repr__(self):
        return "msg_headerpath(headers=%s)" % repr(self.headers)


class msg_ping(object):
    command = b"ping"

    def __init__(self, nonce=0):
        self.nonce = nonce

    def deserialize(self, f):
        self.nonce = struct.unpack("<Q", f.read(8))[0]

    def serialize(self, stype=SER_DEFAULT):
        r = b""
        r += struct.pack("<Q", self.nonce)
        return r

    def __repr__(self):
        return "msg_ping(nonce=%08x)" % self.nonce


class msg_pong(object):
    command = b"pong"

    def __init__(self, nonce=0):
        self.nonce = nonce

    def deserialize(self, f):
        self.nonce = struct.unpack("<Q", f.read(8))[0]

    def serialize(self, stype=SER_DEFAULT):
        r = b""
        r += struct.pack("<Q", self.nonce)
        return r

    def __repr__(self):
        return "msg_pong(nonce=%08x)" % self.nonce


class msg_mempool(object):
    command = b"mempool"

    def __init__(self):
        pass

    def deserialize(self, f):
        pass

    def serialize(self, stype=SER_DEFAULT):
        return b""

    def __repr__(self):
        return "msg_mempool()"


class msg_sendheaders(object):
    command = b"sendheaders"

    def __init__(self):
        pass

    def deserialize(self, f):
        pass

    def serialize(self, stype=SER_DEFAULT):
        return b""

    def __repr__(self):
        return "msg_sendheaders()"



class msg_getheaders(object):
    """
    getheaders message has
    locator: CBlockLocator object that identifies what block to start with
    hash_stop: hash of last desired block header, 0 to get as many as possible
    """
    command = b"getheaders"

    def __init__(self):
        self.locator = CBlockLocator()
        self.hashstop = 0

    def deserialize(self, f):
        self.locator = CBlockLocator()
        self.locator.deserialize(f)
        self.hashstop = deser_uint256(f)

    def serialize(self, stype=SER_DEFAULT):
        r = b""
        r += self.locator.serialize()
        r += ser_uint256(self.hashstop)
        return r

    def __repr__(self):
        return "msg_getheaders(locator=%s, stop=%064x)" \
            % (repr(self.locator), self.hashstop)


class msg_headers(object):
    """
    headers message has
    <count> <vector of block headers>
    """
    command = b"headers"

    def __init__(self, headers = None):
        self.headers = [] if headers is None else headers

    def deserialize(self, f):
        # In BCH/BTC these are serialized/deserialized as blocks with 0 transactions (regardless of the actual # tx)
        # In Nexa these are serialized/deserialized as block headers
        self.headers = deser_vector(f, CBlockHeader)

    def serialize(self, stype=SER_DEFAULT):
        for x in self.headers:
            assert type(x) is CBlockHeader
        return ser_vector(self.headers, stype)

    def __repr__(self):
        return "msg_headers(headers=%s)" % repr(self.headers)


class msg_reject(object):
    command = b"reject"
    # Must match src/consensus/validation.h
    REJECT_MALFORMED = 1
    REJECT_INVALID = 0x10
    REJECT_OBSOLETE = 0x11
    REJECT_DUPLICATE = 0x12
    REJECT_NONSTANDARD = 0x40
    REJECT_DUST = 0x41
    REJECT_INSUFFICIENTFEE = 0x42
    REJECT_FORK = 0x43
    REJECT_WAITING = 0x44
    REJECT_MULTIPLE_INPUTS = 0x45 # Used if we restrict transaction inputs in txadmission
    REJECT_CHECKPOINT = 0x46
    # Used when static node policy prevents the reply.  REJECT_RETRY will be returned if this is a transient issue
    REJECT_LIMITED = 0x47
    # used when a temporary condition (such as a buffer overflow) prevents the processing of a response
    REJECT_RETRY = 0x48

    def __init__(self):
        self.message = b""
        self.code = 0
        self.reason = b""
        self.data = 0

    def deserialize(self, f):
        self.message = deser_string(f)
        self.code = struct.unpack("<B", f.read(1))[0]
        self.reason = deser_string(f)
        if (self.code != self.REJECT_MALFORMED and
                (self.message == b"block" or self.message == b"tx")):
            self.data = deser_uint256(f)

    def serialize(self, stype=SER_DEFAULT):
        r = ser_string(self.message)
        r += struct.pack("<B", self.code)
        r += ser_string(self.reason)
        if (self.code != self.REJECT_MALFORMED and
                (self.message == b"block" or self.message == b"tx")):
            r += ser_uint256(self.data)
        return r

    def __repr__(self):
        return "msg_reject: message=%s code=%d reason=%s data=[%064x]" \
            % (self.message, self.code, self.reason, self.data)

class msg_sendcmpct(object):
    command = b"sendcmpct"

    def __init__(self):
        self.announce = False
        self.version = 1

    def deserialize(self, f):
        self.announce = struct.unpack("<?", f.read(1))[0]
        self.version = struct.unpack("<Q", f.read(8))[0]

    def serialize(self, stype=SER_DEFAULT):
        r = b""
        r += struct.pack("<?", self.announce)
        r += struct.pack("<Q", self.version)
        return r

    def __repr__(self):
        return "msg_sendcmpct(announce=%s, version=%lu)" % (self.announce, self.version)

class msg_cmpctblock(object):
    command = b"cmpctblock"

    def __init__(self, header_and_shortids = None):
        self.header_and_shortids = header_and_shortids

    def deserialize(self, f):
        self.header_and_shortids = P2PHeaderAndShortIDs()
        self.header_and_shortids.deserialize(f)

    def serialize(self, stype=SER_DEFAULT):
        r = b""
        r += self.header_and_shortids.serialize()
        return r

    def __repr__(self):
        return "msg_cmpctblock(HeaderAndShortIDs=%s)" % repr(self.header_and_shortids)

class msg_getblocktxn(object):
    command = b"getblocktxn"

    def __init__(self):
        self.block_txn_request = None

    def deserialize(self, f):
        self.block_txn_request = BlockTransactionsRequest()
        self.block_txn_request.deserialize(f)

    def serialize(self, stype=SER_DEFAULT):
        r = b""
        r += self.block_txn_request.serialize()
        return r

    def __repr__(self):
        return "msg_getblocktxn(block_txn_request=%s)" % (repr(self.block_txn_request))

class msg_blocktxn(object):
    command = b"blocktxn"

    def __init__(self):
        self.block_transactions = BlockTransactions()

    def deserialize(self, f):
        self.block_transactions.deserialize(f)

    def serialize(self, stype=SER_DEFAULT):
        r = b""
        r += self.block_transactions.serialize()
        return r

    def __repr__(self):
        return "msg_blocktxn(block_transactions=%s)" % (repr(self.block_transactions))

def fundSignSend(node, tx):
    """Fund, sign, then send the passed CTransaction, returning the final CTransaction"""
    frtReturn = node.fundrawtransaction(tx.toHex())
    sgnReturn = node.signrawtransaction(frtReturn["hex"])
    fundedTx = CTransaction().fromHex(sgnReturn["hex"])
    node.sendrawtransaction(fundedTx.toHex())
    return fundedTx

def fundSignSendSpend(node, tx, finalOutScript=None, relay=True):
    """Fund, sign, then send the passed CTransaction.  Then spend all its (non-change) outputs, (with the expectation that a valid sigScript is null)"""
    fundedTx = fundSignSend(node, tx)
    txs = CTransaction()
    amountIn = 0
    for idx, vout in enumerate(fundedTx.vout):
        if vout.isIn(tx):  # if the output is in the original tx
            txs.vin.append(fundedTx.SpendOutput(idx))
            amountIn += vout.nValue
    if finalOutScript is None: finalOutScript = CScript([OP_1])
    if len(txs.serialize()) < 100:
        txs.vout.append(CTxOut(0, CScript([OP_RETURN, b"                                                                      "])))
    feeGuess = len(txs.serialize()) + 100
    txs.vout.append(CTxOut(amountIn-feeGuess, finalOutScript))
    if relay: node.sendrawtransaction(txs)
    return txs



def Test():
    import doctest
    import sys
    varint_test()
    print(doctest.testmod(sys.modules[__name__],verbose=True))

def varint_test():
    def cv(array, val):
        a = io.BytesIO(bytes(array))
        vi = deser_varint(a)
        assert vi == val
        va = ser_varint(val)
        assert list(va) == array

    cv([0], 0)
    cv([1], 1)
    cv([0x7f], 127)
    cv([0x80, 0x00], 128)
    cv([0x80,0x7F], 255 )
    cv([0x81, 0x00], 256 )
    cv([0xFE, 0x7F], 16383)
    cv([0xFF, 0x00], 16384)
    cv([0xFF, 0x7F], 16511)
    cv([0x82, 0xFE, 0x7F], 65535)
    cv([0x8E, 0xFE, 0xFE, 0xFF, 0x00], 2**32)

## py.test code
def testCTransactionCopyConstruct():
    a = CTransaction()
    b = CTransaction(a)


