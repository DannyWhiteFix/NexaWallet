#!/usr/bin/env python3
# Copyright (c) 2015-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

#
# script.py
#
# This file is modified from python-bitcoinlib.
#

"""Scripts

Functionality to build scripts, as well as SignatureHash().
"""

from sys import stdout
from binascii import hexlify
from .constants import (SIGHASH_ALL, SIGHASH_NONE, SIGHASH_ANYONECANPAY)
from .scriptop import *

import struct
from .bignum import bn2vch

MAX_SCRIPT_SIZE = 10000
MAX_SCRIPT_ELEMENT_SIZE = 520
MAX_SCRIPT_OPCODES = 201

class CScriptInvalidError(Exception):
    """Base class for CScript exceptions"""
    pass

class CScriptTruncatedPushDataError(CScriptInvalidError):
    """Invalid pushdata due to truncation"""
    def __init__(self, msg, data):
        self.data = data
        super(CScriptTruncatedPushDataError, self).__init__(msg)

# This is used, eg, for blockchain heights in coinbase scripts (bip34)
class CScriptNum(object):
    def __init__(self, d=0):
        self.value = d

    @staticmethod
    def encode(obj):
        r = bytearray(0)
        if obj.value == 0:
            return bytes(r)
        neg = obj.value < 0
        absvalue = -obj.value if neg else obj.value
        while (absvalue):
            r.append(absvalue & 0xff)
            absvalue >>= 8
        if r[-1] & 0x80:
            r.append(0x80 if neg else 0)
        elif neg:
            r[-1] |= 0x80
        return bytes(bchr(len(r)) + r)


class CScript(bytes):
    """Serialized script

    A bytes subclass, so you can use this directly whenever bytes are accepted.
    Note that this means that indexing does *not* work - you'll get an index by
    byte rather than opcode. This format was chosen for efficiency so that the
    general case would not require creating a lot of little CScriptOP objects.

    iter(script) however does iterate by opcode.
    """
    @classmethod
    def __coerce_instance(cls, other):
        # Coerce other into bytes
        if isinstance(other, CScriptOp):
            other = bchr(other)
        elif isinstance(other, CScriptNum):
            if (other.value == 0):
                other = bchr(CScriptOp(OP_0))
            else:
                other = CScriptNum.encode(other)
        elif isinstance(other, int):
            if 0 <= other <= 16:
                other = bytes(bchr(CScriptOp.encode_op_n(other)))
            elif other == -1:
                other = bytes(bchr(OP_1NEGATE))
            else:
                other = CScriptOp.encode_op_pushdata(bn2vch(other))
        elif isinstance(other, (bytes, bytearray)):
            other = CScriptOp.encode_op_pushdata(other)
        return other

    def __add__(self, other):
        # Do the coercion outside of the try block so that errors in it are
        # noticed.
        other = self.__coerce_instance(other)

        try:
            # bytes.__add__ always returns bytes instances unfortunately
            return CScript(super(CScript, self).__add__(other))
        except TypeError:
            raise TypeError('Can not add a %r instance to a CScript' % other.__class__)

    def join(self, iterable):
        # join makes no sense for a CScript()
        raise NotImplementedError

    def __new__(cls, value=b''):
        if isinstance(value, bytes) or isinstance(value, bytearray):
            return super(CScript, cls).__new__(cls, value)
        elif isinstance(value, str):
            return super(CScript, cls).__new__(cls, bytearray.fromhex(value))
        else:
            def coerce_iterable(iterable):
                for instance in iterable:
                    yield cls.__coerce_instance(instance)
            # Annoyingly on both python2 and python3 bytes.join() always
            # returns a bytes instance even when subclassed.
            return super(CScript, cls).__new__(cls, b''.join(coerce_iterable(value)))

    def raw_iter(self):
        """Raw iteration

        Yields tuples of (opcode, data, sop_idx) so that the different possible
        PUSHDATA encodings can be accurately distinguished, as well as
        determining the exact opcode byte indexes. (sop_idx)
        """
        i = 0
        while i < len(self):
            sop_idx = i
            opcode = bord(self[i])
            i += 1

            if opcode > OP_PUSHDATA4:
                yield (opcode, None, sop_idx)
            else:
                datasize = None
                pushdata_type = None
                if opcode < OP_PUSHDATA1:
                    pushdata_type = 'PUSHDATA(%d)' % opcode
                    datasize = opcode

                elif opcode == OP_PUSHDATA1:
                    pushdata_type = 'PUSHDATA1'
                    if i >= len(self):
                        raise CScriptInvalidError('PUSHDATA1: missing data length')
                    datasize = bord(self[i])
                    i += 1

                elif opcode == OP_PUSHDATA2:
                    pushdata_type = 'PUSHDATA2'
                    if i + 1 >= len(self):
                        raise CScriptInvalidError('PUSHDATA2: missing data length')
                    datasize = bord(self[i]) + (bord(self[i+1]) << 8)
                    i += 2

                elif opcode == OP_PUSHDATA4:
                    pushdata_type = 'PUSHDATA4'
                    if i + 3 >= len(self):
                        raise CScriptInvalidError('PUSHDATA4: missing data length')
                    datasize = bord(self[i]) + (bord(self[i+1]) << 8) + (bord(self[i+2]) << 16) + (bord(self[i+3]) << 24)
                    i += 4

                else:
                    assert False # shouldn't happen


                data = bytes(self[i:i+datasize])

                # Check for truncation
                if len(data) < datasize:
                    raise CScriptTruncatedPushDataError('%s: truncated data' % pushdata_type, data)

                i += datasize

                yield (opcode, data, sop_idx)

    def nth(self, n):
        """Return the nth statement in this script (0-based)."""
        cnt = 0
        for op in self:
            if cnt == n: return op
            cnt+=1
        return None
    
    def __iter__(self):
        """'Cooked' iteration

        Returns either a CScriptOP instance, an integer, or bytes, as
        appropriate.

        See raw_iter() if you need to distinguish the different possible
        PUSHDATA encodings.
        """
        for (opcode, data, sop_idx) in self.raw_iter():
            if data is not None:
                yield data
            else:
                opcode = CScriptOp(opcode)

                if opcode.is_small_int():
                    yield opcode.decode_op_n()
                else:
                    yield CScriptOp(opcode)

    def __repr__(self):
        def _repr(o):
            if isinstance(o, bytes):
                return "x('%s')" % hexlify(o).decode('ascii')
            else:
                return repr(o)

        ops = []
        i = iter(self)
        while True:
            op = None
            try:
                op = _repr(next(i))
            except CScriptTruncatedPushDataError as err:
                op = '%s...<ERROR: %s>' % (_repr(err.data), err)
                break
            except CScriptInvalidError as err:
                op = '<ERROR: %s>' % err
                break
            except StopIteration:
                break
            finally:
                if op is not None:
                    ops.append(op)

        return "CScript([%s])" % ', '.join(ops)

    def prettyprint(self, outfile = stdout):
        indent = 0
        newline = False
        for op in iter(self):
            if isinstance(op, bytes):
                rop = hexlify(op).decode("ascii")
            else:
                rop = repr(op)

            if op in [OP_ELSE, OP_ENDIF, OP_NOTIF, OP_IF] and not newline:
                print(file = outfile)
                newline = True
            if op in [OP_ELSE, OP_ENDIF, OP_NOTIF]:
                indent -=1
            if newline:
                print(4 * indent * " ", file = outfile, end = '')
            newline = ("VERIFY" in rop or
                       op in [OP_IF, OP_ELSE, OP_ENDIF, OP_NOTIF, OP_RETURN])
            print(rop+" ", file = outfile, end='\n' if newline else '')
            if op in [OP_ELSE, OP_IF]:
                indent +=1

    def GetSigOpCount(self, fAccurate):
        """Get the SigOp count.

        fAccurate - Accurately count CHECKMULTISIG, see BIP16 for details.

        Note that this is consensus-critical.
        """
        n = 0
        lastOpcode = OP_INVALIDOPCODE
        for (opcode, data, sop_idx) in self.raw_iter():
            if opcode in (OP_CHECKSIG, OP_CHECKSIGVERIFY,
                          OP_CHECKDATASIG, OP_CHECKDATASIGVERIFY):
                n += 1
            elif opcode in (OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY):
                if fAccurate and (OP_1 <= lastOpcode <= OP_16):
                    n += opcode.decode_op_n()
                else:
                    n += 20
            lastOpcode = opcode
        return n

    def serialize(self,  serType=0):
        return bytes(self)

def FindAndDelete(script, sig):
    """Consensus critical, see FindAndDelete() in Satoshi codebase"""
    r = b''
    last_sop_idx = sop_idx = 0
    skip = True
    for (opcode, data, sop_idx) in script.raw_iter():
        if not skip:
            r += script[last_sop_idx:sop_idx]
        last_sop_idx = sop_idx
        if script[sop_idx:sop_idx + len(sig)] == sig:
            skip = True
        else:
            skip = False
    if not skip:
        r += script[last_sop_idx:]
    return CScript(r)


## py.test code
def testScriptRepr():
    x = CScript([OP_CHECKDATASIG])+b"\x11\x22\x33"
    # make sure repr doesn't fail
    assert "112233" in repr(x)

# Wrapper function to ease porting ABC tests.
def SignatureHash(script, txTo, inIdx, hashtype, amount):
    return txTo.SignatureHash(
        scriptCode = script,
        in_number = inIdx,
        nValue = amount,
        hashcode = hashtype)


