import sys
import struct
import binascii
bchr = chr
bord = ord
if sys.version > '3':
    long = int
    bchr = lambda x: bytes([x])
    bord = lambda x: x

OPCODE_NAMES = {}

_opcode_instances = []
class CScriptOp(int):
    """A single script opcode"""
    __slots__ = []

    @staticmethod
    def encode_op_pushdata(d):
        """Encode a PUSHDATA op, returning bytes"""
        if len(d) < 0x4c:
            return b'' + bchr(len(d)) + d # OP_PUSHDATA
        elif len(d) <= 0xff:
            return b'\x4c' + bchr(len(d)) + d # OP_PUSHDATA1
        elif len(d) <= 0xffff:
            return b'\x4d' + struct.pack(b'<H', len(d)) + d # OP_PUSHDATA2
        elif len(d) <= 0xffffffff:
            return b'\x4e' + struct.pack(b'<I', len(d)) + d # OP_PUSHDATA4
        else:
            raise ValueError("Data too long to encode in a PUSHDATA op")

    @staticmethod
    def encode_op_n(n):
        """Encode a small integer op, returning an opcode"""
        if not (0 <= n <= 16):
            raise ValueError('Integer must be in range 0 <= n <= 16, got %d' % n)

        if n == 0:
            return OP_0
        else:
            return CScriptOp(OP_1 + n-1)

    def decode_op_n(self):
        """Decode a small integer opcode, returning an integer"""
        if self == OP_0:
            return 0

        if not (self == OP_0 or OP_1 <= self <= OP_16):
            raise ValueError('op %r is not an OP_N' % self)

        return int(self - OP_1+1)

    def is_small_int(self):
        """Return true if the op pushes a small integer to the stack"""
        if 0x51 <= self <= 0x60 or self == 0:
            return True
        else:
            return False

    def toHex(self):
        """Return the hex representation of this opcode"""
        return binascii.hexlify(self.to_bytes(1,"little")).decode()

    def toBin(self):
        """Return the binary representation of this opcode"""
        return self.to_bytes(1,"little")

    def __str__(self):
        return repr(self)

    def __repr__(self):
        if self in OPCODE_NAMES:
            return OPCODE_NAMES[self]
        else:
            return 'CScriptOp(0x%x)' % self

    def __new__(cls, n):
        try:
            return _opcode_instances[n]
        except IndexError:
            assert len(_opcode_instances) == n
            _opcode_instances.append(super(CScriptOp, cls).__new__(cls, n))
            return _opcode_instances[n]

# Populate opcode instance table
for n in range(0xff+1):
    CScriptOp(n)


# push value
OP_0 = CScriptOp(0x00)
OP_FALSE = OP_0
OP_PUSHDATA1 = CScriptOp(0x4c)
OP_PUSHDATA2 = CScriptOp(0x4d)
OP_PUSHDATA4 = CScriptOp(0x4e)
OP_1NEGATE = CScriptOp(0x4f)
OP_RESERVED = CScriptOp(0x50)
OP_1 = CScriptOp(0x51)
OP_TRUE=OP_1
OP_2 = CScriptOp(0x52)
OP_3 = CScriptOp(0x53)
OP_4 = CScriptOp(0x54)
OP_5 = CScriptOp(0x55)
OP_6 = CScriptOp(0x56)
OP_7 = CScriptOp(0x57)
OP_8 = CScriptOp(0x58)
OP_9 = CScriptOp(0x59)
OP_10 = CScriptOp(0x5a)
OP_11 = CScriptOp(0x5b)
OP_12 = CScriptOp(0x5c)
OP_13 = CScriptOp(0x5d)
OP_14 = CScriptOp(0x5e)
OP_15 = CScriptOp(0x5f)
OP_16 = CScriptOp(0x60)

# control
OP_NOP = CScriptOp(0x61)
OP_VER = CScriptOp(0x62)
OP_IF = CScriptOp(0x63)
OP_NOTIF = CScriptOp(0x64)
OP_VERIF = CScriptOp(0x65)
OP_VERNOTIF = CScriptOp(0x66)
OP_ELSE = CScriptOp(0x67)
OP_ENDIF = CScriptOp(0x68)
OP_VERIFY = CScriptOp(0x69)
OP_RETURN = CScriptOp(0x6a)

# stack ops
OP_TOALTSTACK = CScriptOp(0x6b)
OP_FROMALTSTACK = CScriptOp(0x6c)
OP_2DROP = CScriptOp(0x6d)
OP_2DUP = CScriptOp(0x6e)
OP_3DUP = CScriptOp(0x6f)
OP_2OVER = CScriptOp(0x70)
OP_2ROT = CScriptOp(0x71)
OP_2SWAP = CScriptOp(0x72)
OP_IFDUP = CScriptOp(0x73)
OP_DEPTH = CScriptOp(0x74)
OP_DROP = CScriptOp(0x75)
OP_DUP = CScriptOp(0x76)
OP_NIP = CScriptOp(0x77)
OP_OVER = CScriptOp(0x78)
OP_PICK = CScriptOp(0x79)
OP_ROLL = CScriptOp(0x7a)
OP_ROT = CScriptOp(0x7b)
OP_SWAP = CScriptOp(0x7c)
OP_TUCK = CScriptOp(0x7d)

# splice ops
OP_CAT = CScriptOp(0x7e)
OP_SPLIT = CScriptOp(0x7f)
OP_NUM2BIN = CScriptOp(0x80)
OP_BIN2NUM = CScriptOp(0x81)
OP_SIZE = CScriptOp(0x82)

# bit logic
OP_INVERT = CScriptOp(0x83)
OP_AND = CScriptOp(0x84)
OP_OR = CScriptOp(0x85)
OP_XOR = CScriptOp(0x86)
OP_EQUAL = CScriptOp(0x87)
OP_EQUALVERIFY = CScriptOp(0x88)
OP_RESERVED1 = CScriptOp(0x89)
OP_RESERVED2 = CScriptOp(0x8a)

# numeric
OP_1ADD = CScriptOp(0x8b)
OP_1SUB = CScriptOp(0x8c)
OP_2MUL = CScriptOp(0x8d)
OP_2DIV = CScriptOp(0x8e)
OP_NEGATE = CScriptOp(0x8f)
OP_ABS = CScriptOp(0x90)
OP_NOT = CScriptOp(0x91)
OP_0NOTEQUAL = CScriptOp(0x92)

OP_ADD = CScriptOp(0x93)
OP_SUB = CScriptOp(0x94)
OP_MUL = CScriptOp(0x95)
OP_DIV = CScriptOp(0x96)
OP_MOD = CScriptOp(0x97)
OP_LSHIFT = CScriptOp(0x98)
OP_RSHIFT = CScriptOp(0x99)

OP_BOOLAND = CScriptOp(0x9a)
OP_BOOLOR = CScriptOp(0x9b)
OP_NUMEQUAL = CScriptOp(0x9c)
OP_NUMEQUALVERIFY = CScriptOp(0x9d)
OP_NUMNOTEQUAL = CScriptOp(0x9e)
OP_LESSTHAN = CScriptOp(0x9f)
OP_GREATERTHAN = CScriptOp(0xa0)
OP_LESSTHANOREQUAL = CScriptOp(0xa1)
OP_GREATERTHANOREQUAL = CScriptOp(0xa2)
OP_MIN = CScriptOp(0xa3)
OP_MAX = CScriptOp(0xa4)

OP_WITHIN = CScriptOp(0xa5)

# crypto
OP_RIPEMD160 = CScriptOp(0xa6)
OP_SHA1 = CScriptOp(0xa7)
OP_SHA256 = CScriptOp(0xa8)
OP_HASH160 = CScriptOp(0xa9)
OP_HASH256 = CScriptOp(0xaa)
OP_CODESEPARATOR = CScriptOp(0xab)
OP_CHECKSIG = CScriptOp(0xac)
OP_CHECKSIGVERIFY = CScriptOp(0xad)
OP_CHECKMULTISIG = CScriptOp(0xae)
OP_CHECKMULTISIGVERIFY = CScriptOp(0xaf)
OP_CHECKDATASIG = CScriptOp(0xba)
OP_CHECKDATASIGVERIFY = CScriptOp(0xbb)

# additional byte string operations
OP_REVERSEBYTES = CScriptOp(0xbc)

# expansion
OP_NOP1 = CScriptOp(0xb0)
OP_CHECKLOCKTIMEVERIFY = CScriptOp(0xb1)
OP_CHECKSEQUENCEVERIFY = CScriptOp(0xb2)
OP_NOP4 = CScriptOp(0xb3)
OP_NOP5 = CScriptOp(0xb4)
OP_NOP6 = CScriptOp(0xb5)
OP_NOP7 = CScriptOp(0xb6)
OP_NOP8 = CScriptOp(0xb7)
OP_NOP9 = CScriptOp(0xb8)
OP_NOP10 = CScriptOp(0xb9)

# native introspection
OP_INPUTINDEX = CScriptOp(0xc0)
OP_ACTIVEBYTECODE = CScriptOp(0xc1)
OP_TXVERSION = CScriptOp(0xc2)
OP_TXINPUTCOUNT = CScriptOp(0xc3)
OP_TXOUTPUTCOUNT = CScriptOp(0xc4)
OP_TXLOCKTIME = CScriptOp(0xc5)
OP_UTXOVALUE = CScriptOp(0xc6)
OP_UTXOBYTECODE = CScriptOp(0xc7)
OP_OUTPOINTTXHASH = CScriptOp(0xc8)
OP_OUTPOINTINDEX = CScriptOp(0xc9)
OP_INPUTBYTECODE = CScriptOp(0xca)
OP_INPUTSEQUENCENUMBER = CScriptOp(0xcb)
OP_OUTPUTVALUE = CScriptOp(0xcc)
OP_OUTPUTBYTECODE = CScriptOp(0xcd)
OP_INPUTTYPE = CScriptOp(0xce)
OP_OUTPUTTYPE = CScriptOp(0xcf)
OP_INPUTVALUE = CScriptOp(0xd0)

# Nexa
OP_PARSE = CScriptOp(0xe6)
OP_PLACE = CScriptOp(0xe9)
OP_PUSH_TX_STATE = CScriptOp(0xea)
OP_SETBMD = CScriptOp(0xeb)
OP_BIN2BIGNUM = CScriptOp(0xec)
OP_EXEC = CScriptOp(0xed)
OP_GROUP = CScriptOp(0xee)
OP_TEMPLATE = CScriptOp(0xef)

# template matching params
OP_SMALLINTEGER = CScriptOp(0xfa)
OP_PUBKEYS = CScriptOp(0xfb)
OP_PUBKEYHASH = CScriptOp(0xfd)
OP_PUBKEY = CScriptOp(0xfe)

OP_INVALIDOPCODE = CScriptOp(0xff)

VALID_OPCODES = {
    OP_1NEGATE,
    OP_RESERVED,
    OP_1,
    OP_2,
    OP_3,
    OP_4,
    OP_5,
    OP_6,
    OP_7,
    OP_8,
    OP_9,
    OP_10,
    OP_11,
    OP_12,
    OP_13,
    OP_14,
    OP_15,
    OP_16,

    OP_NOP,
    OP_VER,
    OP_IF,
    OP_NOTIF,
    OP_VERIF,
    OP_VERNOTIF,
    OP_ELSE,
    OP_ENDIF,
    OP_VERIFY,
    OP_RETURN,

    OP_TOALTSTACK,
    OP_FROMALTSTACK,
    OP_2DROP,
    OP_2DUP,
    OP_3DUP,
    OP_2OVER,
    OP_2ROT,
    OP_2SWAP,
    OP_IFDUP,
    OP_DEPTH,
    OP_DROP,
    OP_DUP,
    OP_NIP,
    OP_OVER,
    OP_PICK,
    OP_ROLL,
    OP_ROT,
    OP_SWAP,
    OP_TUCK,

    OP_CAT,
    OP_SPLIT,
    OP_NUM2BIN,
    OP_BIN2NUM,
    OP_SIZE,

    OP_INVERT,
    OP_AND,
    OP_OR,
    OP_XOR,
    OP_EQUAL,
    OP_EQUALVERIFY,
    OP_RESERVED1,
    OP_RESERVED2,

    OP_1ADD,
    OP_1SUB,
    OP_2MUL,
    OP_2DIV,
    OP_NEGATE,
    OP_ABS,
    OP_NOT,
    OP_0NOTEQUAL,

    OP_ADD,
    OP_SUB,
    OP_MUL,
    OP_DIV,
    OP_MOD,
    OP_LSHIFT,
    OP_RSHIFT,

    OP_BOOLAND,
    OP_BOOLOR,
    OP_NUMEQUAL,
    OP_NUMEQUALVERIFY,
    OP_NUMNOTEQUAL,
    OP_LESSTHAN,
    OP_GREATERTHAN,
    OP_LESSTHANOREQUAL,
    OP_GREATERTHANOREQUAL,
    OP_MIN,
    OP_MAX,

    OP_WITHIN,

    OP_RIPEMD160,
    OP_SHA1,
    OP_SHA256,
    OP_HASH160,
    OP_HASH256,
    OP_CODESEPARATOR,
    OP_CHECKSIG,
    OP_CHECKSIGVERIFY,
    OP_CHECKMULTISIG,
    OP_CHECKMULTISIGVERIFY,
    OP_CHECKDATASIG,
    OP_CHECKDATASIGVERIFY,

    OP_NOP1,
    OP_CHECKLOCKTIMEVERIFY,
    OP_CHECKSEQUENCEVERIFY,
    OP_NOP4,
    OP_NOP5,
    OP_NOP6,
    OP_NOP7,
    OP_NOP8,
    OP_NOP9,
    OP_NOP10,

    OP_INPUTINDEX,
    OP_ACTIVEBYTECODE,
    OP_TXVERSION,
    OP_TXINPUTCOUNT,
    OP_TXOUTPUTCOUNT,
    OP_TXLOCKTIME,
    OP_UTXOVALUE,
    OP_UTXOBYTECODE,
    OP_OUTPOINTTXHASH,
    OP_OUTPOINTINDEX,
    OP_INPUTBYTECODE,
    OP_INPUTSEQUENCENUMBER,
    OP_OUTPUTVALUE,
    OP_OUTPUTBYTECODE,
    OP_INPUTTYPE,
    OP_OUTPUTTYPE,
    OP_INPUTVALUE,

    OP_PLACE,
    OP_PUSH_TX_STATE,
    OP_SETBMD,
    OP_BIN2BIGNUM,
    OP_EXEC,
    OP_GROUP,
    OP_TEMPLATE,

    OP_SMALLINTEGER,
    OP_PUBKEYS,
    OP_PUBKEYHASH,
    OP_PUBKEY,
}

OPCODE_NAMES.update({
    OP_0 : 'OP_0',
    OP_PUSHDATA1 : 'OP_PUSHDATA1',
    OP_PUSHDATA2 : 'OP_PUSHDATA2',
    OP_PUSHDATA4 : 'OP_PUSHDATA4',
    OP_1NEGATE : 'OP_1NEGATE',
    OP_RESERVED : 'OP_RESERVED',
    OP_1 : 'OP_1',
    OP_2 : 'OP_2',
    OP_3 : 'OP_3',
    OP_4 : 'OP_4',
    OP_5 : 'OP_5',
    OP_6 : 'OP_6',
    OP_7 : 'OP_7',
    OP_8 : 'OP_8',
    OP_9 : 'OP_9',
    OP_10 : 'OP_10',
    OP_11 : 'OP_11',
    OP_12 : 'OP_12',
    OP_13 : 'OP_13',
    OP_14 : 'OP_14',
    OP_15 : 'OP_15',
    OP_16 : 'OP_16',
    OP_NOP : 'OP_NOP',
    OP_VER : 'OP_VER',
    OP_IF : 'OP_IF',
    OP_NOTIF : 'OP_NOTIF',
    OP_VERIF : 'OP_VERIF',
    OP_VERNOTIF : 'OP_VERNOTIF',
    OP_ELSE : 'OP_ELSE',
    OP_ENDIF : 'OP_ENDIF',
    OP_VERIFY : 'OP_VERIFY',
    OP_RETURN : 'OP_RETURN',
    OP_TOALTSTACK : 'OP_TOALTSTACK',
    OP_FROMALTSTACK : 'OP_FROMALTSTACK',
    OP_2DROP : 'OP_2DROP',
    OP_2DUP : 'OP_2DUP',
    OP_3DUP : 'OP_3DUP',
    OP_2OVER : 'OP_2OVER',
    OP_2ROT : 'OP_2ROT',
    OP_2SWAP : 'OP_2SWAP',
    OP_IFDUP : 'OP_IFDUP',
    OP_DEPTH : 'OP_DEPTH',
    OP_DROP : 'OP_DROP',
    OP_DUP : 'OP_DUP',
    OP_NIP : 'OP_NIP',
    OP_OVER : 'OP_OVER',
    OP_PICK : 'OP_PICK',
    OP_ROLL : 'OP_ROLL',
    OP_ROT : 'OP_ROT',
    OP_SWAP : 'OP_SWAP',
    OP_TUCK : 'OP_TUCK',
    OP_CAT : 'OP_CAT',
    OP_SPLIT : 'OP_SPLIT',
    OP_NUM2BIN : 'OP_NUM2BIN',
    OP_BIN2NUM : 'OP_BIN2NUM',
    OP_SIZE : 'OP_SIZE',
    OP_INVERT : 'OP_INVERT',
    OP_AND : 'OP_AND',
    OP_OR : 'OP_OR',
    OP_XOR : 'OP_XOR',
    OP_EQUAL : 'OP_EQUAL',
    OP_EQUALVERIFY : 'OP_EQUALVERIFY',
    OP_RESERVED1 : 'OP_RESERVED1',
    OP_RESERVED2 : 'OP_RESERVED2',
    OP_1ADD : 'OP_1ADD',
    OP_1SUB : 'OP_1SUB',
    OP_2MUL : 'OP_2MUL',
    OP_2DIV : 'OP_2DIV',
    OP_NEGATE : 'OP_NEGATE',
    OP_ABS : 'OP_ABS',
    OP_NOT : 'OP_NOT',
    OP_0NOTEQUAL : 'OP_0NOTEQUAL',
    OP_ADD : 'OP_ADD',
    OP_SUB : 'OP_SUB',
    OP_MUL : 'OP_MUL',
    OP_DIV : 'OP_DIV',
    OP_MOD : 'OP_MOD',
    OP_LSHIFT : 'OP_LSHIFT',
    OP_RSHIFT : 'OP_RSHIFT',
    OP_BOOLAND : 'OP_BOOLAND',
    OP_BOOLOR : 'OP_BOOLOR',
    OP_NUMEQUAL : 'OP_NUMEQUAL',
    OP_NUMEQUALVERIFY : 'OP_NUMEQUALVERIFY',
    OP_NUMNOTEQUAL : 'OP_NUMNOTEQUAL',
    OP_LESSTHAN : 'OP_LESSTHAN',
    OP_GREATERTHAN : 'OP_GREATERTHAN',
    OP_LESSTHANOREQUAL : 'OP_LESSTHANOREQUAL',
    OP_GREATERTHANOREQUAL : 'OP_GREATERTHANOREQUAL',
    OP_MIN : 'OP_MIN',
    OP_MAX : 'OP_MAX',
    OP_WITHIN : 'OP_WITHIN',
    OP_RIPEMD160 : 'OP_RIPEMD160',
    OP_SHA1 : 'OP_SHA1',
    OP_SHA256 : 'OP_SHA256',
    OP_HASH160 : 'OP_HASH160',
    OP_HASH256 : 'OP_HASH256',
    OP_CODESEPARATOR : 'OP_CODESEPARATOR',
    OP_CHECKSIG : 'OP_CHECKSIG',
    OP_CHECKSIGVERIFY : 'OP_CHECKSIGVERIFY',
    OP_CHECKMULTISIG : 'OP_CHECKMULTISIG',
    OP_CHECKMULTISIGVERIFY : 'OP_CHECKMULTISIGVERIFY',
    OP_CHECKDATASIG : 'OP_CHECKDATASIG',
    OP_CHECKDATASIGVERIFY : 'OP_CHECKDATASIGVERIFY',
    OP_NOP1 : 'OP_NOP1',
    OP_CHECKLOCKTIMEVERIFY : 'OP_CHECKLOCKTIMEVERIFY',
    OP_CHECKSEQUENCEVERIFY : 'OP_CHECKSEQUENCEVERIFY',
    OP_NOP4 : 'OP_NOP4',
    OP_NOP5 : 'OP_NOP5',
    OP_NOP6 : 'OP_NOP6',
    OP_NOP7 : 'OP_NOP7',
    OP_NOP8 : 'OP_NOP8',
    OP_NOP9 : 'OP_NOP9',
    OP_NOP10 : 'OP_NOP10',

    OP_INPUTINDEX : 'OP_INPUTINDEX',
    OP_ACTIVEBYTECODE : 'OP_ACTIVEBYTECODE',
    OP_TXVERSION : 'OP_TXVERSION',
    OP_TXINPUTCOUNT : 'OP_TXINPUTCOUNT',
    OP_TXOUTPUTCOUNT : 'OP_TXOUTPUTCOUNT',
    OP_TXLOCKTIME : 'OP_TXLOCKTIME',
    OP_UTXOVALUE : 'OP_UTXOVALUE',
    OP_UTXOBYTECODE : 'OP_UTXOBYTECODE',
    OP_OUTPOINTTXHASH : 'OP_OUTPOINTTXHASH',
    OP_OUTPOINTINDEX : 'OP_OUTPOINTINDEX',
    OP_INPUTBYTECODE : 'OP_INPUTBYTECODE',
    OP_INPUTSEQUENCENUMBER : 'OP_INPUTSEQUENCENUMBER',
    OP_OUTPUTVALUE : 'OP_OUTPUTVALUE',
    OP_OUTPUTBYTECODE : 'OP_OUTPUTBYTECODE',
    OP_INPUTTYPE : 'OP_INPUTTYPE',
    OP_OUTPUTTYPE : 'OP_OUTPUTTYPE',
    OP_INPUTVALUE : 'OP_INPUTVALUE',

    OP_PLACE: 'OP_PLACE',
    OP_PUSH_TX_STATE: 'OP_PUSH_TX_STATE',
    OP_SETBMD: 'OP_SETBMD',
    OP_BIN2BIGNUM: 'OP_BIN2BIGNUM',
    OP_EXEC: 'OP_EXEC',
    OP_GROUP: 'OP_GROUP',
    OP_TEMPLATE: 'OP_TEMPLATE',

    OP_SMALLINTEGER : 'OP_SMALLINTEGER',
    OP_PUBKEYS : 'OP_PUBKEYS',
    OP_PUBKEYHASH : 'OP_PUBKEYHASH',
    OP_PUBKEY : 'OP_PUBKEY',
    OP_INVALIDOPCODE : 'OP_INVALIDOPCODE',
})

OPCODES_BY_NAME = {
    'OP_0' : OP_0,
    'OP_PUSHDATA1' : OP_PUSHDATA1,
    'OP_PUSHDATA2' : OP_PUSHDATA2,
    'OP_PUSHDATA4' : OP_PUSHDATA4,
    'OP_1NEGATE' : OP_1NEGATE,
    'OP_RESERVED' : OP_RESERVED,
    'OP_1' : OP_1,
    'OP_2' : OP_2,
    'OP_3' : OP_3,
    'OP_4' : OP_4,
    'OP_5' : OP_5,
    'OP_6' : OP_6,
    'OP_7' : OP_7,
    'OP_8' : OP_8,
    'OP_9' : OP_9,
    'OP_10' : OP_10,
    'OP_11' : OP_11,
    'OP_12' : OP_12,
    'OP_13' : OP_13,
    'OP_14' : OP_14,
    'OP_15' : OP_15,
    'OP_16' : OP_16,
    'OP_NOP' : OP_NOP,
    'OP_VER' : OP_VER,
    'OP_IF' : OP_IF,
    'OP_NOTIF' : OP_NOTIF,
    'OP_VERIF' : OP_VERIF,
    'OP_VERNOTIF' : OP_VERNOTIF,
    'OP_ELSE' : OP_ELSE,
    'OP_ENDIF' : OP_ENDIF,
    'OP_VERIFY' : OP_VERIFY,
    'OP_RETURN' : OP_RETURN,
    'OP_TOALTSTACK' : OP_TOALTSTACK,
    'OP_FROMALTSTACK' : OP_FROMALTSTACK,
    'OP_2DROP' : OP_2DROP,
    'OP_2DUP' : OP_2DUP,
    'OP_3DUP' : OP_3DUP,
    'OP_2OVER' : OP_2OVER,
    'OP_2ROT' : OP_2ROT,
    'OP_2SWAP' : OP_2SWAP,
    'OP_IFDUP' : OP_IFDUP,
    'OP_DEPTH' : OP_DEPTH,
    'OP_DROP' : OP_DROP,
    'OP_DUP' : OP_DUP,
    'OP_NIP' : OP_NIP,
    'OP_OVER' : OP_OVER,
    'OP_PICK' : OP_PICK,
    'OP_ROLL' : OP_ROLL,
    'OP_ROT' : OP_ROT,
    'OP_SWAP' : OP_SWAP,
    'OP_TUCK' : OP_TUCK,
    'OP_CAT' : OP_CAT,
    'OP_SPLIT' : OP_SPLIT,
    'OP_NUM2BIN' : OP_NUM2BIN,
    'OP_BIN2NUM' : OP_BIN2NUM,
    'OP_SIZE' : OP_SIZE,
    'OP_INVERT' : OP_INVERT,
    'OP_AND' : OP_AND,
    'OP_OR' : OP_OR,
    'OP_XOR' : OP_XOR,
    'OP_EQUAL' : OP_EQUAL,
    'OP_EQUALVERIFY' : OP_EQUALVERIFY,
    'OP_RESERVED1' : OP_RESERVED1,
    'OP_RESERVED2' : OP_RESERVED2,
    'OP_1ADD' : OP_1ADD,
    'OP_1SUB' : OP_1SUB,
    'OP_2MUL' : OP_2MUL,
    'OP_2DIV' : OP_2DIV,
    'OP_NEGATE' : OP_NEGATE,
    'OP_ABS' : OP_ABS,
    'OP_NOT' : OP_NOT,
    'OP_0NOTEQUAL' : OP_0NOTEQUAL,
    'OP_ADD' : OP_ADD,
    'OP_SUB' : OP_SUB,
    'OP_MUL' : OP_MUL,
    'OP_DIV' : OP_DIV,
    'OP_MOD' : OP_MOD,
    'OP_LSHIFT' : OP_LSHIFT,
    'OP_RSHIFT' : OP_RSHIFT,
    'OP_BOOLAND' : OP_BOOLAND,
    'OP_BOOLOR' : OP_BOOLOR,
    'OP_NUMEQUAL' : OP_NUMEQUAL,
    'OP_NUMEQUALVERIFY' : OP_NUMEQUALVERIFY,
    'OP_NUMNOTEQUAL' : OP_NUMNOTEQUAL,
    'OP_LESSTHAN' : OP_LESSTHAN,
    'OP_GREATERTHAN' : OP_GREATERTHAN,
    'OP_LESSTHANOREQUAL' : OP_LESSTHANOREQUAL,
    'OP_GREATERTHANOREQUAL' : OP_GREATERTHANOREQUAL,
    'OP_MIN' : OP_MIN,
    'OP_MAX' : OP_MAX,
    'OP_WITHIN' : OP_WITHIN,
    'OP_RIPEMD160' : OP_RIPEMD160,
    'OP_SHA1' : OP_SHA1,
    'OP_SHA256' : OP_SHA256,
    'OP_HASH160' : OP_HASH160,
    'OP_HASH256' : OP_HASH256,
    'OP_CODESEPARATOR' : OP_CODESEPARATOR,
    'OP_CHECKSIG' : OP_CHECKSIG,
    'OP_CHECKSIGVERIFY' : OP_CHECKSIGVERIFY,
    'OP_CHECKMULTISIG' : OP_CHECKMULTISIG,
    'OP_CHECKMULTISIGVERIFY' : OP_CHECKMULTISIGVERIFY,
    'OP_CHECKDATASIG' : OP_CHECKDATASIG,
    'OP_CHECKDATASIGVERIFY' : OP_CHECKDATASIGVERIFY,
    'OP_NOP1' : OP_NOP1,
    'OP_CHECKLOCKTIMEVERIFY' : OP_CHECKLOCKTIMEVERIFY,
    'OP_CHECKSEQUENCEVERIFY' : OP_CHECKSEQUENCEVERIFY,
    'OP_NOP4' : OP_NOP4,
    'OP_NOP5' : OP_NOP5,
    'OP_NOP6' : OP_NOP6,
    'OP_NOP7' : OP_NOP7,
    'OP_NOP8' : OP_NOP8,
    'OP_NOP9' : OP_NOP9,
    'OP_NOP10' : OP_NOP10,

    'OP_INPUTINDEX':OP_INPUTINDEX,
    'OP_ACTIVEBYTECODE':OP_ACTIVEBYTECODE,
    'OP_TXVERSION':OP_TXVERSION,
    'OP_TXINPUTCOUNT':OP_TXINPUTCOUNT,
    'OP_TXOUTPUTCOUNT':OP_TXOUTPUTCOUNT,
    'OP_TXLOCKTIME':OP_TXLOCKTIME,
    'OP_UTXOVALUE':OP_UTXOVALUE,
    'OP_UTXOBYTECODE':OP_UTXOBYTECODE,
    'OP_OUTPOINTTXHASH':OP_OUTPOINTTXHASH,
    'OP_OUTPOINTINDEX':OP_OUTPOINTINDEX,
    'OP_INPUTBYTECODE':OP_INPUTBYTECODE,
    'OP_INPUTSEQUENCENUMBER':OP_INPUTSEQUENCENUMBER,
    'OP_OUTPUTVALUE':OP_OUTPUTVALUE,
    'OP_OUTPUTBYTECODE':OP_OUTPUTBYTECODE,
    'OP_INPUTTYPE':OP_INPUTTYPE,
    'OP_OUTPUTTYPE':OP_OUTPUTTYPE,
    'OP_INPUTVALUE':OP_INPUTVALUE,

    'OP_PLACE' : OP_PLACE,
    'OP_PUSH_TX_STATE' : OP_PUSH_TX_STATE,
    'OP_SETBMD' : OP_SETBMD,
    'OP_BIN2BIGNUM' : OP_BIN2BIGNUM,
    'OP_EXEC' : OP_EXEC,
    'OP_GROUP' : OP_GROUP,
    'OP_TEMPLATE': OP_TEMPLATE,

    'OP_SMALLINTEGER' : OP_SMALLINTEGER,
    'OP_PUBKEYS' : OP_PUBKEYS,
    'OP_PUBKEYHASH' : OP_PUBKEYHASH,
    'OP_PUBKEY' : OP_PUBKEY,
}
