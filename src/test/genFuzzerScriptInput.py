#!/usr/bin/python3
# Copyright (c) 2018-2022 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# This program generates fuzzing input scripts by converting the BCHScript programs specified
# in fuzzScriptStarter.bch to binary input files needed for test_bitcoin_fuzzy.cpp and AFL.

import os
import re
import sys
import argparse
import io
import struct
import pdb

modDir = os.path.dirname(os.path.realpath(__file__))

def ser_string(s):
    if len(s) < 253:
        return struct.pack("B", len(s)) + s
    elif len(s) < 0x10000:
        return struct.pack("<BH", 253, len(s)) + s
    elif len(s) < 0x100000000:
        return struct.pack("<BI", 254, len(s)) + s
    return struct.pack("<BQ", 255, len(s)) + s

scripts = [ "515293",
            "515c95529856",
            "51995604123456788184",
            "020100816081965297",
            "0201008160819452939a9b",
            "52529576549599",

            "5352559376957d936c93048237785485055aa55aa5007b7c859304ffffff7f85",
            "5380060102030405066c76a87c76aa7ca97b7b7e7c7eaa7c88",
            "06000201030405060102030405066c78867d63756967697568",
            "06000201030405060102030405066c767e787e7c7e787e787e787e7c7e767e7c7e7601147f7b01327f537a7b7e7b7e7c7eaa69"
            ]

def Test():
    try:
        os.mkdir("scriptFuzzInputs")
    except OSError:
        pass # already exists

    # file is whitespace separated:
    # inputIdx hexTx hexPrevouts
    fname = modDir + os.sep + "fuzzScriptStarterState.tx"
    scriptState = open(modDir + os.sep + "fuzzScriptStarterState.tx", "r").read()

    parts = scriptState.split()
    inputIdx = int(parts[0])
    hexTx = parts[1]
    hexPrevouts = parts[2]

    binTx = bytearray.fromhex(hexTx)
    binPrevouts = bytearray.fromhex(hexPrevouts)

    ret = []
    for s in scripts:
        ret.append(bytes.fromhex(s))

    inp = bytes()
    k = 0
    for out in ret:
        fname = "scriptFuzzInputs/aflinput%s.bin" % k
        print("Creating %s" % fname)
        f = open(fname,"wb")
        flags = 0xd47df # standard + opcode enabling flags
        version = 1  # protocol version -- unused in this
        result = struct.pack("<I",version)
        f.write(result)
        result = struct.pack("<I",flags)
        f.write(result)
        result = struct.pack("<I",inputIdx)
        f.write(result)
        f.write(ser_string(inp))
        f.write(ser_string(out))
        f.write(ser_string(binTx))
        f.write(ser_string(binPrevouts))
        f.close()
        k+=1
    fname = modDir + os.sep + "scriptnumAFL.hex"
    allScripts = open(fname, "r").read()
    allScripts = allScripts.split()
    k = 0
    inp = bytes([0x61])  # no-op input for these scripts
    for scriptHex in allScripts:
        fname = "scriptFuzzInputs/aflscriptnuminput%s.bin" % k
        f = open(fname,"wb")
        print("Creating %s" % fname)
        binScript = bytearray.fromhex(scriptHex)
        flags = 0xd47df # standard + opcode enabling flags
        version = 1  # protocol version -- unused in this
        result = struct.pack("<I",version)
        f.write(result)
        result = struct.pack("<I",flags)
        f.write(result)
        result = struct.pack("<I",inputIdx)
        f.write(result)
        f.write(ser_string(inp))
        f.write(ser_string(binScript))
        f.write(ser_string(binTx))
        f.write(ser_string(binPrevouts))
        f.close()
        k+=1

if __name__== "__main__":
    Test()
