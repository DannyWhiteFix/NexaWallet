// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_SCRIPT_STANDARD_H
#define NEXA_SCRIPT_STANDARD_H

#include "consensus/grouptokens.h"
#include "script/interpreter.h"
#include "script/scripttemplate.h"
#include "streams.h"
#include "uint256.h"

#include <stdint.h>
#include <variant>

class CKeyID;
class CScript;

/** A reference to a CScript: the Hash160 of its serialization (see script.h) */
class CScriptID : public uint160
{
public:
    CScriptID() : uint160() {}
    CScriptID(const CScript &in);
    CScriptID(const uint160 &in) : uint160(in) {}
};

class ScriptTemplateDestination
{
public:
    CScript output;
    ScriptTemplateDestination() {}
    ScriptTemplateDestination(const CScript &script) : output(script) {}

    // This destination is a serialized CScript so serialization methods are used to convert this into a binary
    // form that is then encoded via bech32 or base58 into text.
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(*(CScriptBase *)(&output));
        output.type = ScriptType::TEMPLATE;
    }

    /** Convert this destination to a CScript suitable for use in a transaction output (CTxOut).
        Since this type of destination IS a CScript, there is nothing to do
     */
    CScript toScript() const
    {
        assert(output.type == ScriptType::TEMPLATE);
        return output;
    }

    /** Convert this Destination to a CScript suitable for use in a transaction output (CTxOut).
        Override the group and quantity in this Destination (if any) with the passed one and return the needed
        output script.  If the passed group == NoGroup, the group and quantity is stripped from this output.
        If quantity is -1, an illegal quantity is encoded (OP_0).  This is used for addresses which want to encode
        a token type but not a quantity.  If this address is used as a script (without overriding this invalid
        quantity field), the transaction will not validate.
    */
    CScript toScript(CGroupTokenID group, CAmount grpQuantity = -1) const
    {
        assert(output.type == ScriptType::TEMPLATE);
        CGroupTokenInfo currentGroupInfo;
        VchType scriptHash;
        VchType argsHash;
        CScript::const_iterator rest = output.begin();

        // Pull this output apart and then recombine with the new group and grpQuantity info.
        ScriptTemplateError error = GetScriptTemplate(output, &currentGroupInfo, &scriptHash, &argsHash, &rest);
        if (error == ScriptTemplateError::OK)
        {
            CScript ret;
            if (group != NoGroup)
            {
                if (grpQuantity != -1)
                {
                    ret = (CScript(ScriptType::TEMPLATE)
                              << group.bytes() << SerializeAmount(grpQuantity) << scriptHash << argsHash) +
                          CScript(rest, output.end());
                }
                else
                {
                    ret = (CScript(ScriptType::TEMPLATE) << group.bytes() << OP_0 << scriptHash << argsHash) +
                          CScript(rest, output.end());
                }
            }
            else // Not grouped
            {
                ret = (CScript(ScriptType::TEMPLATE) << OP_0 << scriptHash << argsHash) + CScript(rest, output.end());
            }
            return ret;
        }
        else
        {
            // All of these destinations should be templates, but if not return a script that won't work so money isnt
            // lost if used.
            return CScript().SetInvalid();
        }
    }

    /** Appends the binary serialization of this destination to the passed byte vector, and returns that vector */
    std::vector<uint8_t> appendTo(const std::vector<uint8_t> &data) const
    {
        CDataStream strm(data, SER_NETWORK, PROTOCOL_VERSION);
        strm << *this;
        return std::vector<uint8_t>(strm.begin(), strm.end());
    }

    // some ordering is needed for std::map, etc
    friend inline bool operator<(const ScriptTemplateDestination &a, const ScriptTemplateDestination &b)
    {
        return a.output < b.output;
    }

    friend inline bool operator==(const ScriptTemplateDestination &a, const ScriptTemplateDestination &b)
    {
        return a.output == b.output;
    }

    CGroupTokenID Group() const { return GetGroupToken(output); }
};


enum txnouttype
{
    TX_NONSTANDARD,
    // 'standard' transaction types:
    TX_PUBKEY,
    TX_PUBKEYHASH,
    TX_SCRIPTHASH,
    TX_MULTISIG,
    TX_CLTV,
    TX_LABELPUBLIC,
    TX_NULL_DATA,
    TX_GRP_PUBKEYHASH,
    TX_GRP_SCRIPTHASH,
    TX_SCRIPT_TEMPLATE
};

class CNoDestination
{
public:
    friend bool operator==(const CNoDestination &a, const CNoDestination &b) { return true; }
    friend bool operator<(const CNoDestination &a, const CNoDestination &b) { return true; }
};

/**
 * A txout script template with a specific destination. It is either:
 *  * CNoDestination: no destination set
 *  * CKeyID: TX_PUBKEYHASH destination
 *  * CScriptID: TX_SCRIPTHASH destination
 *  A CTxDestination is the internal data type encoded in an address
 */
typedef std::variant<CNoDestination, CKeyID, CScriptID, ScriptTemplateDestination> CTxDestination;

const char *GetTxnOutputType(txnouttype t);

bool ExtendedSolver(const CScript &scriptPubKey,
    txnouttype &typeRet,
    std::vector<std::vector<unsigned char> > &vSolutionsRet,
    CGroupTokenInfo &grp);
bool Solver(const CScript &scriptPubKey, txnouttype &typeRet, std::vector<std::vector<unsigned char> > &vSolutionsRet);
bool ExtractDestination(const CScript &scriptPubKey, CTxDestination &addressRet);
bool ExtractDestinationAndType(const CScript &scriptPubKey, CTxDestination &addressRet, txnouttype &whichType);
bool ExtractDestinations(const CScript &scriptPubKey,
    txnouttype &typeRet,
    std::vector<CTxDestination> &addressRet,
    int &nRequiredRet);

const char *GetTxnOutputType(txnouttype t);

CScript GetScriptForDestination(const CTxDestination &dest);
CScript GetScriptForRawPubKey(const CPubKey &pubkey);
CScript GetScriptForMultisig(int nRequired, const std::vector<CPubKey> &keys);
CScript GetScriptForFreeze(CScriptNum nLockTime, const CPubKey &pubKey);
CScript GetScriptLabelPublic(const std::string &labelPublic);


#endif // NEXA_SCRIPT_STANDARD_H
