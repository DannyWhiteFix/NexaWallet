// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_SCRIPT_DESTINATIONS_H
#define NEXA_SCRIPT_DESTINATIONS_H

#include "crypto/hash160.h"
#include "datastream.h"
#include "keyid.h"
#include "script/script.h" // pulls in bignum, script_error, stackitem
#include "uint256.h"
#include "version.h"

#include <variant>
#include <vector>

class CNoDestination
{
public:
    friend bool operator==(const CNoDestination &a, const CNoDestination &b) { return true; }
    friend bool operator<(const CNoDestination &a, const CNoDestination &b) { return true; }
};

class CKeyID;

/** A reference to a CScript: the Hash160 of its serialization (see script.h) */
class CScriptID : public uint160
{
public:
    CScriptID() : uint160() {}
    CScriptID(const uint160 &in) : uint160(in) {}
    CScriptID(const CScript &in) : uint160(Hash160(in.begin(), in.end())) {}
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

    // some ordering is needed for std::map, etc
    friend inline bool operator<(const ScriptTemplateDestination &a, const ScriptTemplateDestination &b)
    {
        return a.output < b.output;
    }

    friend inline bool operator==(const ScriptTemplateDestination &a, const ScriptTemplateDestination &b)
    {
        return a.output == b.output;
    }

    /** Appends the binary serialization of this destination to the passed byte vector, and returns that vector */
    std::vector<uint8_t> appendTo(const std::vector<uint8_t> &data) const
    {
        CDataStream strm(data, SER_NETWORK, PROTOCOL_VERSION);
        strm << *this;
        return std::vector<uint8_t>(strm.begin(), strm.end());
    }

    /** Convert this destination to a CScript suitable for use in a transaction output (CTxOut).
        Since this type of destination IS a CScript, there is nothing to do
     */
    CScript toScript() const
    {
        assert(output.type == ScriptType::TEMPLATE);
        return output;
    }
};

/**
 * A txout script template with a specific destination. It is either:
 *  * CNoDestination: no destination set
 *  * CKeyID: TX_PUBKEYHASH destination
 *  * CScriptID: TX_SCRIPTHASH destination
 *  * ScriptTemplateDestination: TX_SCRIPT_TEMPLATE destination
 *  A CTxDestination is the internal data type encoded in an address
 */
typedef std::variant<CNoDestination, CKeyID, CScriptID, ScriptTemplateDestination> CTxDestination;

#endif // NEXA_SCRIPT_DESTINATIONS_H
