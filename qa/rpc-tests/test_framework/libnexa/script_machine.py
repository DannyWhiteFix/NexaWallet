# Copyright (c) 2018-2022 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from .libnexa_api_wrapper import *

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

# match this with value in stackitem.h
class StackItemType(IntEnum):
    BYTES = 0
    BIGNUM = 1

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
    SCRIPT_ERR_INVALID_REGISTER = 107

    SCRIPT_ERR_STACK_BYTES = 108
    SCRIPT_ERR_PARSE = 109
    SCRIPT_ERR_INVALID_JUMP = 110
    SCRIPT_ERR_INVALID_PARAMETER = 111

    SCRIPT_ERR_ERROR_COUNT = 112

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
                self.smId = get_libnexa().CreateNoContextScriptMachine(self.flags)
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

                self.smId = get_libnexa().CreateScriptMachine(self.flags, inputIdx, txbin, len(txbin), prevoutsBin, len(prevoutsBin))
        self.curPos = 0
        self.script = None

    def __del__(self):
        if hasattr(self, 'smId'):
            if self.smId: self.cleanup()

    def clone(self):
        sm = ScriptMachine(self.flags, nocreate=True)
        sm.smId = get_libnexa().SmClone(self.smId)
        sm.curPos = self.curPos
        sm.script = self.script
        return sm

    def cleanup(self):
        """Call to explicitly free the resources used by this script machine"""
        if self.smId:
            get_libnexa().SmRelease(self.smId)
            self.smId = 0
        else:
            raise Error("accessed inactive script machine")

    def reset(self):
        if self.smId==0: raise Error("accessed inactive script machine")
        get_libnexa().SmReset(self.smId)
        self.curPos = 0

    def eval(self, script):
        if self.smId==0: raise Error("accessed inactive script machine")
        if type(script) == str:
            script = unhexlify(script)
        ret = get_libnexa().SmEval(self.smId, script, len(script))
        return ret

    def begin(self, script):
        """Start stepping through the provided script"""
        if self.smId==0: raise Error("accessed inactive script machine")
        if type(script) == str:
            script = unhexlify(script)
        ret = get_libnexa().SmBeginStep(self.smId, script, len(script))
        self.curPos = 0
        self.script = script
        return ret

    def step(self):
        """Step forward 1 instruction"""
        if self.smId==0: raise Error("accessed inactive script machine")
        if self.curPos >= len(self.script):
            raise Error("stepped beyond end of script")
        ret = get_libnexa().SmStep(self.smId)
        if ret == 0:
            raise Error("execution error")
        self.curPos = get_libnexa().SmPos(self.smId)
        return self.curPos

    def error(self):
        if self.smId==0: raise Error("accessed inactive script machine")
        return (ScriptError(get_libnexa().SmGetError(self.smId)), get_libnexa().SmPos(self.smId))

    def pos(self):
        return self.curPos

    def end(self):
        """Call when script is complete to do final script checks"""
        if self.smId==0: raise Error("accessed inactive script machine")
        ret = get_libnexa().SmEndStep(self.smId)
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
            result = get_libnexa().SmGetStackItem(self.smId, which, idx, itemType, item)
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
        get_libnexa().SmSetStackItem(self.smId, which, idx, int(itemType), value, len(value))
