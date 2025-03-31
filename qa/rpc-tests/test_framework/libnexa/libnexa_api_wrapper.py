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


def init(libnexa_file=None):
    global libnexa
    if libnexa_file is None:
        libnexa_file = "libnexa.so"
        try:
            libnexa = CDLL(libnexa_file)
            print("Loaded %s" % libnexa_file)
        except OSError:
            import os
            dir_path = os.path.dirname(os.path.realpath(__file__))
            libnexa = CDLL(dir_path + os.sep + libnexa_file)
            print("Loaded %s" % (dir_path + os.sep + libnexa_file))
    else:
        libnexa = CDLL(libnexa_file)
        print("Loaded %s" % libnexa_file)
    if libnexa is None:
        raise Error("Cannot find %s shared library", libnexa_file)
    # NOTE: None, integers, bytes objects and (unicode) strings are the only native
    # Python objects that can directly be used as parameters in these function calls
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

    libnexa.libnexaVersion.restype = c_int
    libnexa.libnexaVersion.argtypes = [ ]
    libnexa.get_libnexa_error.restype = c_int
    libnexa.get_libnexa_error.argtypes = [ ]
    libnexa.get_libnexa_error_string.restype = None
    libnexa.get_libnexa_error_string.argtypes = [ c_char_p, c_uint64 ]
    libnexa.encode64.restype = c_int
    libnexa.encode64.argtypes = [ c_char_p, c_int, c_char_p, c_int ]
    libnexa.decode64.restype = c_int
    libnexa.decode64.argtypes = [ c_char_p, c_char_p, c_int ]
    libnexa.Bin2Hex.restype = c_int
    libnexa.Bin2Hex.argtypes = [ c_char_p, c_int, c_char_p, c_uint ]
    libnexa.hd44DeriveChildKey.restype = c_int
    libnexa.hd44DeriveChildKey.argtypes = [ c_char_p, c_uint, c_uint, c_uint, c_uint, c_bool, c_uint, c_char_p, c_char_p ]
    libnexa.GetPubKey.restype = c_int
    libnexa.GetPubKey.argtypes = [ c_char_p, c_char_p, c_uint ]
    libnexa.SignHashEDCSA.restype = c_int
    libnexa.SignHashEDCSA.argtypes = [ c_char_p, c_int, c_char_p, c_char_p, c_int ]
    libnexa.txid.restype = c_int
    libnexa.txid.argtypes = [ c_char_p, c_int, c_char_p ]
    libnexa.txidem.restype = c_int
    libnexa.txidem.argtypes = [ c_char_p, c_int, c_char_p ]
    libnexa.blockHash.restype = c_int
    libnexa.blockHash.argtypes = [ c_char_p, c_int, c_char_p ]
    libnexa.SignTxECDSA.restype = c_int
    libnexa.SignTxECDSA.argtypes = [ c_char_p, c_int, c_uint, c_int64, c_char_p, c_uint32, c_uint32, c_char_p, c_char_p, c_uint ]
    libnexa.signBchTxOneInputUsingSchnorr.restype = c_int
    libnexa.signBchTxOneInputUsingSchnorr.argtypes = [ c_char_p, c_int, c_uint, c_int64, c_char_p, c_uint32, c_uint32, c_char_p, c_char_p, c_uint ]
    libnexa.signTxOneInputUsingSchnorr.restype = c_int
    libnexa.signTxOneInputUsingSchnorr.argtypes = [ c_char_p, c_int, c_uint, c_int64, c_char_p, c_uint32, c_char_p, c_uint, c_char_p, c_char_p, c_uint ]
    libnexa.SignTxSchnorr.restype = c_int
    libnexa.SignTxSchnorr.argtypes = [ c_char_p, c_int, c_uint, c_int64, c_char_p, c_uint32, c_char_p, c_uint, c_char_p, c_char_p, c_uint ]
    libnexa.signHashSchnorr.restype = c_int
    libnexa.signHashSchnorr.argtypes = [ c_char_p, c_char_p, c_char_p ]
    libnexa.signHashSchnorrWithNonce.restype = c_int
    libnexa.signHashSchnorrWithNonce.argtypes = [ c_char_p, c_char_p, c_char_p, c_char_p ]
    libnexa.parseGroupDescription.restype = c_int
    libnexa.parseGroupDescription.argtypes = [ c_char_p, c_uint64, c_char_p, c_uint64 ]
    libnexa.getArgsHashFromScriptPubkey.restype = c_int
    libnexa.getArgsHashFromScriptPubkey.argtypes = [ c_char_p, c_uint64, c_char_p, c_uint64 ]
    libnexa.getTemplateHashFromScriptPubkey.restype = c_int
    libnexa.getTemplateHashFromScriptPubkey.argtypes = [ c_char_p, c_uint64, c_char_p, c_uint64 ]
    libnexa.getGroupTokenInfoFromScriptPubkey.restype = c_int
    libnexa.getGroupTokenInfoFromScriptPubkey.argtypes = [ c_char_p, c_uint64, c_char_p, c_uint64, POINTER(c_uint64), POINTER(c_int64) ]
    libnexa.signMessage.restype = c_int
    libnexa.signMessage.argtypes = [ c_char_p, c_uint, c_char_p, c_uint, c_char_p, c_uint ]
    libnexa.verifyMessage.restype = c_int
    libnexa.verifyMessage.argtypes = [ c_char_p, c_uint, c_char_p, c_uint, c_char_p, c_uint, c_char_p, c_uint ]
    libnexa.verifyBlockHeader.restype = c_bool
    libnexa.verifyBlockHeader.argtypes = [ c_int, c_char_p, c_int ]
    libnexa.encodeCashAddr.restype = c_int
    libnexa.encodeCashAddr.argtypes = [ c_int, c_int, c_char_p, c_int, c_char_p, c_int ]
    libnexa.decodeCashAddr.restype = c_int
    libnexa.decodeCashAddr.argtypes = [ c_int, c_char_p, c_char_p, c_int ]
    libnexa.decodeCashAddrContent.restype = c_int
    libnexa.decodeCashAddrContent.argtypes = [ c_int, c_char_p, c_char_p, c_int, c_char_p ]
    libnexa.serializeScript.restype = c_int
    libnexa.serializeScript.argtypes = [ c_char_p, c_uint, c_char_p, c_int ]
    libnexa.pubkeyToScriptTemplate.restype = c_int
    libnexa.pubkeyToScriptTemplate.argtypes = [ c_char_p, c_int, c_char_p, c_int ]
    libnexa.groupIdFromAddr.restype = c_int
    libnexa.groupIdFromAddr.argtypes = [ c_int, c_char_p, c_char_p, c_int ]
    libnexa.groupIdToAddr.restype = c_int
    libnexa.groupIdToAddr.argtypes = [ c_int, c_char_p, c_int, c_char_p, c_int ]
    libnexa.decodeWifPrivateKey.restype = c_int
    libnexa.decodeWifPrivateKey.argtypes = [ c_int, c_char_p, c_char_p, c_int ]
    libnexa.sha256.restype = None
    libnexa.sha256.argtypes = [ c_char_p, c_uint, c_char_p ]
    libnexa.hash256.restype = None
    libnexa.hash256.argtypes = [ c_char_p, c_uint, c_char_p ]
    libnexa.hash160.restype = None
    libnexa.hash160.argtypes = [ c_char_p, c_uint, c_char_p ]
    libnexa.getWorkFromDifficultyBits.restype = None
    libnexa.getWorkFromDifficultyBits.argtypes = [ c_ulong, c_char_p ]
    libnexa.getDifficultyBitsFromWork.restype = c_uint
    libnexa.getDifficultyBitsFromWork.argtypes = [ c_char_p ]
    libnexa.createBloomFilter.restype = c_int
    libnexa.createBloomFilter.argtypes = [ c_char_p, c_uint, c_double, c_int, c_int, c_int, c_int, c_char_p ]
    libnexa.extractFromMerkleBlock.restype = c_int
    libnexa.extractFromMerkleBlock.argtypes = [ c_int, c_char_p, c_int, c_char_p, c_int, c_char_p, c_int ]
    libnexa.capdSolve.restype = c_int
    libnexa.capdSolve.argtypes = [ c_char_p, c_uint, c_char_p, c_uint ]
    libnexa.capdCheck.restype = c_int
    libnexa.capdCheck.argtypes = [ c_char_p, c_uint ]
    libnexa.capdHash.restype = c_int
    libnexa.capdHash.argtypes = [ c_char_p, c_uint, c_char_p, c_uint ]
    libnexa.capdSetPowTargetHarderThanPriority.restype = c_int
    libnexa.capdSetPowTargetHarderThanPriority.argtypes = [ c_char_p, c_uint, c_double, c_char_p, c_uint ]
    libnexa.cryptAES256CBC.restype = c_int
    libnexa.cryptAES256CBC.argtypes = [ c_uint, c_char_p, c_uint, c_char_p, c_char_p, c_char_p]
    libnexa.verifyDataSchnorr.restype = c_bool
    libnexa.verifyDataSchnorr.argtypes = [ c_char_p, c_uint, c_char_p, c_int, c_char_p ]
    libnexa.verifyHashSchnorr.restype = c_bool
    libnexa.verifyHashSchnorr.argtypes = [ c_char_p, c_char_p, c_int, c_char_p ]
    libnexa.RandomBytes.restype = c_int
    libnexa.RandomBytes.argtypes = [ c_char_p, c_int ]


# hacky fix for creating response buffers, nothing should ever be this big
C_STR_BUF_SIZE = 1000

class LIBNEXA_ERROR(IntEnum):
    SUCCESS_NO_ERROR = 0,   # success
    INVALID_ARG = 1,        # an arg is either NULL or has an invalid size
    DECODE_FAILURE = 2,     # failed to decode some array of bytes passed in
    RETURN_FAILURE = 3,     # unable to return the result for some reason
    INTERNAL_ERROR = 4,     # critical logic or implementation error somewhere

# Hack to get script machine to work without edits for now
def get_libnexa():
    return libnexa

def libnexaVersion():
    version = libnexa.libnexaVersion()
    return version

def get_libnexa_error():
    res = libnexa.get_libnexa_error()
    return res

def get_libnexa_error_string() -> str:
    res_buf = create_string_buffer(C_STR_BUF_SIZE)
    libnexa.get_libnexa_error_string(res_buf, C_STR_BUF_SIZE)
    res = res_buf.raw.decode("UTF-8").strip()
    return res

def encode64(input_data: bytes) -> bytes:
    res_buf = create_string_buffer(C_STR_BUF_SIZE)
    res_size = libnexa.encode64(input_data, len(input_data), res_buf, C_STR_BUF_SIZE)
    if res_size <= 0:
        return None
    return res_buf.raw[0:res_size]

def decode64(input_data: bytes) -> bytes:
    res_buf = create_string_buffer(C_STR_BUF_SIZE)
    res_size = libnexa.decode64(input_data, res_buf, C_STR_BUF_SIZE)
    if res_size <= 0:
        return None
    return res_buf.raw[0:res_size]

def Bin2Hex(input_data: bytes) -> bytes:
    res_buf = create_string_buffer(C_STR_BUF_SIZE)
    res_size = libnexa.Bin2Hex(input_data, len(input_data), res_buf, C_STR_BUF_SIZE)
    if res_size <= 0:
        return None
    return res_buf.raw[0:res_size]

def hd44DeriveChildKey(seed: bytes, purpose: int, coin_type: int, account: int, change: bool, index: int) -> bytes:
    res_buf = create_string_buffer(C_STR_BUF_SIZE)
    null_ptr = POINTER(c_char)()
    res_size = libnexa.hd44DeriveChildKey(seed, len(seed), purpose, coin_type, account, change, index, res_buf, null_ptr)
    # secret returned is always assumed to be 32 bytes
    return res_buf.raw[0:32]

def GetPubKey(privkey_bytes: bytes) -> bytes:
    res_buf = create_string_buffer(C_STR_BUF_SIZE)
    res_size = libnexa.GetPubKey(privkey_bytes, res_buf, C_STR_BUF_SIZE)
    if res_size <= 0:
        return None
    return res_buf.raw[0:res_size]

def SignHashEDCSA(input_data: bytes, privkey_bytes: bytes) -> bytes:
    res_buf = create_string_buffer(C_STR_BUF_SIZE)
    res_size = libnexa.SignHashEDCSA(input_data, len(input_data), privkey_bytes, res_buf, C_STR_BUF_SIZE)
    if res_size <= 0:
        return None
    return res_buf.raw[0:res_size]

def txid(input_data: bytes) -> bytes:
    res_buf = create_string_buffer(C_STR_BUF_SIZE)
    res_size = libnexa.txid(input_data, len(input_data), res_buf)
    if res_size <= 0:
        return None
    return res_buf.raw[0:res_size]

def txidem(input_data: bytes) -> bytes:
    res_buf = create_string_buffer(C_STR_BUF_SIZE)
    res_size = libnexa.txidem(input_data, len(input_data), res_buf)
    if res_size <= 0:
        return None
    return res_buf.raw[0:res_size]

def blockHash(input_data: bytes) -> bytes:
    res_buf = create_string_buffer(C_STR_BUF_SIZE)
    res_size = libnexa.blockHash(input_data, len(input_data), res_buf)
    if res_size <= 0:
        return None
    return res_buf.raw[0:res_size]


def SignTxECDSA(tx_data: bytes, input_index: int, input_amount: int,
                prevout_script: bytes, hash_type: int, privkey_bytes: bytes) -> bytes:
    res_buf = create_string_buffer(C_STR_BUF_SIZE)
    res_size = libnexa.SignTxECDSA(tx_data, len(tx_data), input_index, input_amount,
                                    prevout_script, len(prevout_script), hash_type,
                                    privkey_bytes, res_buf, C_STR_BUF_SIZE)
    if res_size <= 0:
        return None
    return res_buf.raw[0:res_size]


def signBchTxOneInputUsingSchnorr(tx_data: bytes, input_index: int,
                input_amount: int, prevout_script: bytes, hash_type: int,
                privkey_bytes: bytes) -> bytes:
    res_buf = create_string_buffer(C_STR_BUF_SIZE)
    res_size = libnexa.signBchTxOneInputUsingSchnorr(tx_data, len(tx_data), input_index, input_amount,
                                    prevout_script, len(prevout_script), hash_type,
                                    privkey_bytes, res_buf, C_STR_BUF_SIZE)
    if res_size <= 0:
        return None
    return res_buf.raw[0:res_size]


def signTxOneInputUsingSchnorr(tx_data: bytes, input_index: int,
                input_amount: int, prevout_script: bytes, hash_type: int,
                privkey_bytes: bytes) -> bytes:
    if type(hash_type) == int:
        hash_type = bytes([hash_type])
    res_buf = create_string_buffer(C_STR_BUF_SIZE)
    res_size = libnexa.signTxOneInputUsingSchnorr(tx_data, len(tx_data), input_index, input_amount,
                                    prevout_script, len(prevout_script), hash_type, len(hash_type),
                                    privkey_bytes, res_buf, C_STR_BUF_SIZE)
    if res_size <= 0:
        return None
    return res_buf.raw[0:res_size]

def SignTxSchnorr(tx_data: bytes, input_index: int, input_amount: int,
                prevout_script: bytes, hash_type: int, privkey_bytes: bytes) -> bytes:
    if type(hash_type) == int:
        hash_type = bytes([hash_type])
    res_buf = create_string_buffer(C_STR_BUF_SIZE)
    res_size = libnexa.SignTxSchnorr(tx_data, len(tx_data), input_index, input_amount,
                                    prevout_script, len(prevout_script), hash_type, len(hash_type),
                                    privkey_bytes, res_buf, C_STR_BUF_SIZE)
    if res_size <= 0:
        return None
    return res_buf.raw[0:res_size]

def signHashSchnorr(hash: bytes, privkey: bytes) -> bytes:
    res_buf = create_string_buffer(C_STR_BUF_SIZE)
    res_size = libnexa.signHashSchnorr(hash, privkey, res_buf)
    if res_size <= 0:
        return None
    return res_buf.raw[0:res_size]

def signHashSchnorrWithNonce(hash: bytes, privkey: bytes, nonce: bytes) -> bytes:
    res_buf = create_string_buffer(C_STR_BUF_SIZE)
    res_size = libnexa.signHashSchnorrWithNonce(hash, privkey, nonce, res_buf)
    if res_size <= 0:
        return None
    return res_buf.raw[0:res_size]

def parseGroupDescription(op_return: bytes) -> bytes:
    res_buf = create_string_buffer(C_STR_BUF_SIZE)
    res_size = libnexa.parseGroupDescription(op_return, len(op_return), res_buf, C_STR_BUF_SIZE)
    if res_size <= 0:
        return None
    return res_buf.raw[0:res_size]

def getArgsHashFromScriptPubkey(serailised_pubkey: bytes) -> bytes:
    res_buf = create_string_buffer(C_STR_BUF_SIZE)
    res_size = libnexa.getArgsHashFromScriptPubkey(serailised_pubkey, len(serailised_pubkey), res_buf, C_STR_BUF_SIZE)
    if res_size <= 0:
        return None
    return res_buf.raw[0:res_size]

def getTemplateHashFromScriptPubkey(serailised_pubkey: bytes) -> bytes:
    res_buf = create_string_buffer(C_STR_BUF_SIZE)
    res_size = libnexa.getTemplateHashFromScriptPubkey(serailised_pubkey, len(serailised_pubkey), res_buf, C_STR_BUF_SIZE)
    if res_size <= 0:
        return None
    return res_buf.raw[0:res_size]

def getGroupTokenInfoFromScriptPubkey(serialised_pubkey: bytes) -> (bytes, int, int):
    group_id_buf = create_string_buffer(C_STR_BUF_SIZE)
    group_flags = c_ulonglong(0)
    group_amount = c_longlong(0)
    group_id_size = libnexa.getGroupTokenInfoFromScriptPubkey(serailised_pubkey, len(serailised_pubkey),
                            group_id_buf, C_STR_BUF_SIZE, pointer(group_flags), pointer(group_amount))
    if group_id_size <= 0:
        return None, None, None
    return group_id_buf.raw[0:group_id_size], group_amount.value, group_flags.value

def signMessage(privkey: bytes , msg: bytes) -> bytes:
    res_buf = create_string_buffer(C_STR_BUF_SIZE)
    res_size = libnexa.signMessage(msg, len(msg), privkey, len(privkey), res_buf, C_STR_BUF_SIZE)
    if res_size <= 0:
        return None
    return res_buf.raw[0:res_size]

def verifyMessage(addr: bytes, msg: bytes, sig: bytes) -> bytes:
    res_buf = create_string_buffer(C_STR_BUF_SIZE)
    res_size = libnexa.verifyMessage(msg, len(msg), addr, len(addr), sig, len(sig), res_buf, C_STR_BUF_SIZE)
    if res_size <= 0:
        return None
    return res_buf.raw[0:res_size]

def verifyBlockHeader(chain: int, serialised_header: bytes) -> bool:
    res = libnexa.verifyBlockHeader(chain, serialised_header, len(serialised_header))
    return res

def encodeCashAddr(chain: int, type: int, data: bytes) -> bytes:
    res_buf = create_string_buffer(C_STR_BUF_SIZE)
    res_size = libnexa.encodeCashAddr(chain, type, data, len(data), res_buf, C_STR_BUF_SIZE)
    if res_size <= 0:
        return None
    return res_buf.raw[0:res_size]

def decodeCashAddr(chain: int, addr: str) -> (int, bytes):
    res_buf = create_string_buffer(C_STR_BUF_SIZE)
    utf8_addr = addr.encode("UTF-8")
    res_size = libnexa.decodeCashAddr(chain, utf8_addr, res_buf, C_STR_BUF_SIZE)
    if res_size <= 0:
        return None
    return int(res_buf.raw[0]), res_buf.raw[1:res_size]

def decodeCashAddrContent(chain: int, addr: str) -> (bytes, bytes):
    res_buf = create_string_buffer(C_STR_BUF_SIZE)
    addr_type = create_string_buffer(1)
    utf8_addr = addr.encode("UTF-8")
    res_size = libnexa.decodeCashAddrContent(chain, utf8_addr, res_buf, C_STR_BUF_SIZE, addr_type)
    if res_size <= 0:
        return None, None
    return addr_type.raw[0:1], res_buf.raw[0:res_size]

def serializeScript(script: bytes) -> bytes:
    res_buf = create_string_buffer(C_STR_BUF_SIZE)
    res_size = libnexa.serializeScript(script, len(script), res_buf, C_STR_BUF_SIZE)
    if res_size <= 0:
        return None
    return res_buf.raw[0:res_size]

def pubkeyToScriptTemplate(pubkey: bytes) -> bytes:
    res_buf = create_string_buffer(C_STR_BUF_SIZE)
    res_size = libnexa.pubkeyToScriptTemplate(pubkey, len(pubkey), res_buf, C_STR_BUF_SIZE)
    if res_size <= 0:
        return None
    return res_buf.raw[0:res_size]

def groupIdFromAddr(chain: int, addr: str) -> bytes:
    res_buf = create_string_buffer(C_STR_BUF_SIZE)
    res_size = libnexa.groupIdFromAddr(chain, addr, res_buf, C_STR_BUF_SIZE)
    if res_size <= 0:
        return None
    return res_buf.raw[0:res_size]

def groupIdToAddr(chain: int, group_id: bytes) -> bytes:
    res_buf = create_string_buffer(C_STR_BUF_SIZE)
    res_size = libnexa.groupIdToAddr(chain, group_id, len(group_id), res_buf, C_STR_BUF_SIZE)
    if res_size <= 0:
        return None
    return res_buf.raw[0:res_size]

def decodeWifPrivateKey(chain: int, wif_string: str) -> bytes:
    res_buf = create_string_buffer(C_STR_BUF_SIZE)
    res_size = libnexa.decodeWifPrivateKey(chain, wif_string, res_buf, C_STR_BUF_SIZE)
    if res_size <= 0:
        return None
    return res_buf.raw[0:res_size]

def sha256(data: bytes) -> bytes:
    res_buf = create_string_buffer(C_STR_BUF_SIZE)
    libnexa.sha256(data, len(data), res_buf)
    return res_buf.raw[0:32]

def hash256(data: bytes) -> bytes:
    res_buf = create_string_buffer(C_STR_BUF_SIZE)
    libnexa.hash256(data, len(data), res_buf)
    return res_buf.raw[0:32]

def hash160(data: bytes) -> bytes:
    res_buf = create_string_buffer(C_STR_BUF_SIZE)
    libnexa.hash160(data, len(data), res_buf)
    return res_buf.raw[0:20]

def getWorkFromDifficultyBits(bits: int) -> bytes:
    res_buf = create_string_buffer(C_STR_BUF_SIZE)
    c_bits = c_ulong(bits)
    libnexa.getWorkFromDifficultyBits(c_bits, res_buf)
    return res_buf.raw[0:32]

def getDifficultyBitsFromWork(work_bytes: bytes) -> int:
    res = libnexa.getDifficultyBitsFromWork(work_bytes)
    return res

def createBloomFilter(data: bytes, false_pos_rate: float, capacity: int, max_size: int, flags: int, tweak: int) -> bytes:
    res_buf = create_string_buffer(max_size)
    res_size = libnexa.createBloomFilter(data, len(data), false_pos_rate, capacity, max_size, flags, tweak, res_buf)
    if res_size <= 0:
        return None
    return res_buf.raw[0:res_size]

def extractFromMerkleBlock(num_txes: int, merkle_proof_path: bytes, hash_in: bytes, num_hashes: int) -> (int, bytes):
    res_buf = create_string_buffer(C_STR_BUF_SIZE)
    res = libnexa.extractFromMerkleBlock(num_txes, merkle_proof_path, len(merkle_proof_path),
                                        hash_in, len(hash_in), num_hashes, res_buf, C_STR_BUF_SIZE)
    return int(res), res_buf.raw[0:(res*32)]

def capdSolve(message: bytes) -> bytes:
    res_size_buf = create_string_buffer(C_STR_BUF_SIZE)
    res = libnexa.capdSolve(message, len(message), res_buf, C_STR_BUF_SIZE)
    if res_size <= 0:
        return None
    return res_buf.raw[0:res_size]

def capdCheck(message: bytes) -> bool:
    return libnexa.capdCheck(message, len(message))

def capdHash(message: bytes) -> bytes:
    res_buf = create_string_buffer(C_STR_BUF_SIZE)
    res_size = libnexa.capdHash(message, len(message), res_buf, C_STR_BUF_SIZE)
    if res_size <= 0:
        return None
    return res_buf.raw[0:res_size]

def capdSetPowTargetHarderThanPriority(message: bytes, priority: float) -> bytes:
    res_buf = create_string_buffer(C_STR_BUF_SIZE)
    res_size = libnexa.capdSetPowTargetHarderThanPriority(message, len(message), priority, res_buf, C_STR_BUF_SIZE)
    if res_size <= 0:
        return None
    return res_buf.raw[0:res_size]

def cryptAES256CBC(encrypt: int, data: bytes, privkey: bytes, iv: bytes) -> bytes:
    res_buf = create_string_buffer(C_STR_BUF_SIZE)
    res_size = libnexa.cryptAES256CBC(encrypt, data, len(data), privkey, iv, res_buf)
    if res_size <= 0:
        return None
    return res_buf.raw[0:res_size]

def verifyDataSchnorr(message: bytes, pubkey: bytes, signature: bytes) -> bool:
    res = libnexa.verifyDataSchnorr(message, len(message), pubkey, len(pubkey), signature)
    return bool(res)

def verifyHashSchnorr(hash: bytes, pubkey: bytes, signature: bytes) -> bool:
    res = libnexa.verifyHashSchnorr(hash, pubkey, len(pubkey), signature)
    return bool(res)

def RandomBytes(num_bytes: int) -> bytes:
    res_buf = create_string_buffer(num_bytes)
    res_size = libnexa.RandomBytes(res_buf, num_bytes)
    return res_buf.raw[0:res_size]
