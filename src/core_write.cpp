// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "core_io.h"

#include "dstencode.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "script/sighashtype.h"
#include "script/stackitem.h"
#include "script/standard.h"
#include "serialize.h"
#include "streams.h"
#include "util.h"
#include "utilmoneystr.h"
#include "utilstrencodings.h"
#include <univalue.h>

using namespace std;

string FormatScript(const CScript &script)
{
    string ret;
    CScript::const_iterator it = script.begin();
    opcodetype op;
    while (it != script.end())
    {
        CScript::const_iterator it2 = it;
        StackItem data;
        if (script.GetOp2(it, op, &data))
        {
            if (op == OP_0)
            {
                ret += "0 ";
                continue;
            }
            else if ((op >= OP_1 && op <= OP_16) || op == OP_1NEGATE)
            {
                ret += strprintf("%i ", op - OP_1NEGATE - 1);
                continue;
            }

            if (op >= OP_NOP && op < FIRST_UNDEFINED_OP_VALUE)
            {
                string str(GetOpName(op));
                if (str.substr(0, 3) == string("OP_"))
                {
                    ret += str.substr(3, string::npos) + " ";
                    continue;
                }
            }
            if (data.size() > 0)
            {
                const vector<unsigned char> &vch = data.data();
                ret += strprintf("0x%x 0x%x ", HexStr(it2, it - vch.size()), HexStr(it - vch.size(), it));
            }
            else
            {
                ret += strprintf("0x%x ", HexStr(it2, it));
            }
            continue;
        }
        ret += strprintf("0x%x ", HexStr(it2, script.end()));
        break;
    }
    return ret.substr(0, ret.size() - 1);
}


string EncodeHexTx(const CTransaction &tx)
{
    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << tx;
    return HexStr(ssTx.begin(), ssTx.end());
}

void ScriptPubKeyToUniv(const CScript &scriptPubKey, UniValue &out, bool fIncludeHex)
{
    txnouttype type;
    vector<CTxDestination> addresses;
    int nRequired;

    out.pushKV("asm", ScriptToAsmStr(scriptPubKey));
    if (fIncludeHex)
        out.pushKV("hex", HexStr(scriptPubKey.begin(), scriptPubKey.end()));

    if (!ExtractDestinations(scriptPubKey, type, addresses, nRequired))
    {
        out.pushKV("type", GetTxnOutputType(type));
        return;
    }

    out.pushKV("reqSigs", nRequired);
    out.pushKV("type", GetTxnOutputType(type));

    UniValue a(UniValue::VARR);
    for (const CTxDestination &addr : addresses)
    {
        a.push_back(EncodeDestination(addr));
    }
    out.pushKV("addresses", a);
}

void TxToUniv(const CTransaction &tx, const uint256 &hashBlock, UniValue &entry)
{
    entry.pushKV("txid", tx.GetId().GetHex());
    entry.pushKV("txidem", tx.GetIdem().GetHex());
    entry.pushKV("version", tx.nVersion);
    entry.pushKV("locktime", (int64_t)tx.nLockTime);

    UniValue vin(UniValue::VARR);
    for (const CTxIn &txin : tx.vin)
    {
        UniValue in(UniValue::VOBJ);
        if (tx.IsCoinBase())
            in.pushKV("coinbase", HexStr(txin.scriptSig.begin(), txin.scriptSig.end()));
        else
        {
            in.pushKV("outpoint", txin.prevout.GetHex());
            UniValue o(UniValue::VOBJ);
            o.pushKV("asm", ScriptToAsmStr(txin.scriptSig, true));
            o.pushKV("hex", HexStr(txin.scriptSig.begin(), txin.scriptSig.end()));
            in.pushKV("scriptSig", o);
        }
        in.pushKV("sequence", (int64_t)txin.nSequence);
        vin.push_back(in);
    }
    entry.pushKV("vin", vin);

    UniValue vout(UniValue::VARR);
    for (unsigned int i = 0; i < tx.vout.size(); i++)
    {
        const CTxOut &txout = tx.vout[i];

        UniValue out(UniValue::VOBJ);

        UniValue outValue(UniValue::VNUM, FormatMoney(txout.nValue));
        out.pushKV("value", outValue);
        out.pushKV("n", (int64_t)i);

        UniValue o(UniValue::VOBJ);
        ScriptPubKeyToUniv(txout.scriptPubKey, o, true);
        out.pushKV("scriptPubKey", o);
        vout.push_back(out);
    }
    entry.pushKV("vout", vout);

    if (!hashBlock.IsNull())
        entry.pushKV("blockhash", hashBlock.GetHex());

    // the hex-encoded transaction. used the name "hex" to be consistent with the verbose output of "getrawtransaction".
    entry.pushKV("hex", EncodeHexTx(tx));
}
