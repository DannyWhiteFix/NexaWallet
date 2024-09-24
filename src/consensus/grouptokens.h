// Copyright (c) 2018-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_TOKEN_GROUPS_H
#define NEXA_TOKEN_GROUPS_H

#include "chainparams.h"
#include "pubkey.h"
#include <unordered_map>
class CWallet;
class CCoinsViewCache;
class CValidationState;
/** Transaction cannot be committed on my fork */
static const unsigned int REJECT_GROUP_IMBALANCE = 0x104;

enum class GroupTokenIdFlags : uint16_t
{
    NONE = 0,
    COVENANT = 1U, // covenants/ encumberances -- output script template must match input
    HOLDS_NEX = 1U << 1, // group inputs and outputs must balance NEX, token quantity MUST be 0
    GROUP_RESERVED_BITS = 0xFFFF & ~(COVENANT | HOLDS_NEX),
    DEFAULT = 0
};

enum class GroupAuthorityFlags : uint64_t
{
    AUTHORITY = 1ULL << 63, // Is this a controller utxo (forces negative number in amount)
    MINT = 1ULL << 62, // Can mint tokens
    MELT = 1ULL << 61, // Can melt tokens,
    BATON = 1ULL << 60, // Can create controller outputs
    RESCRIPT = 1ULL << 59, // Can change the redeem script
    SUBGROUP = 1ULL << 58,

    NONE = 0,
    ACTIVE_FLAG_BITS = AUTHORITY | MINT | MELT | BATON | RESCRIPT | SUBGROUP,
    ALL_FLAG_BITS = 0xffffULL << (64 - 16),
    RESERVED_FLAG_BITS = ACTIVE_FLAG_BITS & ~ALL_FLAG_BITS
};


enum class ScriptTemplateError : uint8_t
{
    OK = 0,
    NOT_A_TEMPLATE = 1U,
    INVALID = 2U
};

inline GroupTokenIdFlags operator|(const GroupTokenIdFlags a, const GroupTokenIdFlags b)
{
    GroupTokenIdFlags ret = (GroupTokenIdFlags)(((uint8_t)a) | ((uint8_t)b));
    return ret;
}

inline GroupTokenIdFlags operator~(const GroupTokenIdFlags a)
{
    GroupTokenIdFlags ret = (GroupTokenIdFlags)(~((uint8_t)a));
    return ret;
}

inline GroupTokenIdFlags operator&(const GroupTokenIdFlags a, const GroupTokenIdFlags b)
{
    GroupTokenIdFlags ret = (GroupTokenIdFlags)(((uint8_t)a) & ((uint8_t)b));
    return ret;
}

inline GroupTokenIdFlags &operator|=(GroupTokenIdFlags &a, const GroupTokenIdFlags b)
{
    a = (GroupTokenIdFlags)(((uint8_t)a) | ((uint8_t)b));
    return a;
}

inline GroupTokenIdFlags &operator&=(GroupTokenIdFlags &a, const GroupTokenIdFlags b)
{
    a = (GroupTokenIdFlags)(((uint8_t)a) & ((uint8_t)b));
    return a;
}
inline bool hasGroupTokenIdFlag(GroupTokenIdFlags object, GroupTokenIdFlags flag)
{
    return (((uint16_t)object) & ((uint16_t)flag)) == (uint16_t)flag;
}

// The definitions below are used internally.  They are defined here for use in unit tests.
class CGroupTokenID
{
protected:
    std::vector<unsigned char> data;
    enum
    {
        PARENT_GROUP_ID_SIZE = 32
    };

public:
    //* no token group
    CGroupTokenID() {}
    //* for testing only -- force a fake group ID
    CGroupTokenID(unsigned char c, GroupTokenIdFlags flags = GroupTokenIdFlags::NONE) : data(PARENT_GROUP_ID_SIZE)
    {
        data[0] = c;
        data[30] = ((unsigned int)flags) >> 8;
        data[31] = ((unsigned int)flags) & 255;
    }
    //* handles CKeyID and CScriptID
    CGroupTokenID(const uint160 &id) : data(ToByteVector(id)) {}
    //* handles single mint group id, and possibly future larger size CScriptID
    CGroupTokenID(const uint256 &id) : data(ToByteVector(id)) {}
    //* Assign the groupID from a vector
    CGroupTokenID(const std::vector<unsigned char> &id) : data(id)
    {
        // Token group IDs must be able to be pushed onto the stack, but this check interferes with consensus tests
        // DbgAssert(id.size() <= MAX_SCRIPT_ELEMENT_SIZE, );
    }
    //* Assign the groupID from a buffer (copies the buffer)
    CGroupTokenID(const uint8_t *ptr, size_t len) : data(ptr, ptr + len) {}

    void NoGroup(void) { data.resize(0); }
    bool operator==(const CGroupTokenID &id) const { return data == id.data; }
    bool operator!=(const CGroupTokenID &id) const { return data != id.data; }
    bool operator<(const CGroupTokenID &id) const { return data < id.data; }
    bool operator>(const CGroupTokenID &id) const { return data > id.data; }
    bool operator<=(const CGroupTokenID &id) const { return data <= id.data; }
    bool operator>=(const CGroupTokenID &id) const { return data >= id.data; }
    //* returns true if this is a user-defined group -- ie NOT nexa or no group
    bool isUserGroup(void) const;
    //* returns true if this is a subgroup
    bool isSubgroup(void) const;
    //* returns the data portion of a subgroup */
    std::vector<unsigned char> getSubgroupData(void);
    //* returns the parent group if this is a subgroup or itself.
    CGroupTokenID parentGroup(void) const;

    const std::vector<unsigned char> &bytes(void) const { return data; }
    //* Convert this token group ID into a mint/melt address
    // CTxDestination ControllingAddress(txnouttype addrType) const;
    //* Returns this groupID as a string in cashaddr format
    // std::string Encode(const CChainParams &params = Params()) const;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(data);
    }

    bool hasFlag(GroupTokenIdFlags flag) const;
};

/** Convert a groupID to a string */
std::string EncodeGroupToken(const CGroupTokenID &grp, const CChainParams &params = Params());
/** Convert a string to a groupID */
CGroupTokenID DecodeGroupToken(const std::string &addr, const CChainParams &params = Params());

namespace std
{
template <>
struct hash<CGroupTokenID>
{
public:
    size_t operator()(const CGroupTokenID &s) const
    {
        const std::vector<unsigned char> &v = s.bytes();
        int sz = v.size();
        if (sz >= 4)
            return (v[0] << 24) | (v[1] << 16) | (v[2] << 8) << v[3];
        else if (sz > 0)
            return v[0]; // It would be better to return all bytes but sizes 1 to 3 currently unused
        else
            return 0;
    }
};
} // namespace std

/** Keeps track of per group statistics for a transaction
 * the amounts of each group coming into and going out of a transaction
 * the activated authority flags
 * the covenant
 * the number of inputs and outputs
 */
class GroupBalance
{
public:
    GroupBalance()
        : ctrlPerms(GroupAuthorityFlags::NONE), allowedCtrlOutputPerms(GroupAuthorityFlags::NONE),
          allowedSubgroupCtrlOutputPerms(GroupAuthorityFlags::NONE), ctrlOutputPerms(GroupAuthorityFlags::NONE)
    {
    }
    GroupAuthorityFlags ctrlPerms; // what permissions are provided in inputs
    GroupAuthorityFlags allowedCtrlOutputPerms; // What permissions are provided in inputs with CHILD set
    GroupAuthorityFlags allowedSubgroupCtrlOutputPerms; // What permissions are provided in inputs with CHILD set
    GroupAuthorityFlags ctrlOutputPerms; // What permissions are enabled in outputs
    CAmount input = 0;
    CAmount output = 0;
    uint64_t numOutputs = 0;
    uint64_t numInputs = 0;
    // If covenant restricted, the hash of the first grouped & templated input's prevout is this group's covenant.
    VchType covenant;
};


typedef std::unordered_map<CGroupTokenID, GroupBalance> GroupBalanceMap;
typedef std::shared_ptr<GroupBalanceMap> GroupBalanceMapRef;
static inline GroupBalanceMapRef MakeGroupBalanceMapRef() { return std::make_shared<GroupBalanceMap>(); }


inline GroupAuthorityFlags operator|(const GroupAuthorityFlags a, const GroupAuthorityFlags b)
{
    GroupAuthorityFlags ret = (GroupAuthorityFlags)(((uint64_t)a) | ((uint64_t)b));
    return ret;
}

inline GroupAuthorityFlags operator~(const GroupAuthorityFlags a)
{
    GroupAuthorityFlags ret = (GroupAuthorityFlags)(~((uint64_t)a));
    return ret;
}

inline GroupAuthorityFlags operator&(const GroupAuthorityFlags a, const GroupAuthorityFlags b)
{
    GroupAuthorityFlags ret = (GroupAuthorityFlags)(((uint64_t)a) & ((uint64_t)b));
    return ret;
}

inline GroupAuthorityFlags &operator|=(GroupAuthorityFlags &a, const GroupAuthorityFlags b)
{
    a = (GroupAuthorityFlags)(((uint64_t)a) | ((uint64_t)b));
    return a;
}

inline GroupAuthorityFlags &operator&=(GroupAuthorityFlags &a, const GroupAuthorityFlags b)
{
    a = (GroupAuthorityFlags)(((uint64_t)a) & ((uint64_t)b));
    return a;
}

inline bool hasCapability(GroupAuthorityFlags object, const GroupAuthorityFlags capability)
{
    return (((uint64_t)object) & ((uint64_t)capability)) != 0;
}

inline CAmount toAmount(GroupAuthorityFlags f) { return (CAmount)f; }
class CGroupTokenInfo
{
public:
    CGroupTokenInfo() : associatedGroup(), controllingGroupFlags(GroupAuthorityFlags::NONE), quantity(0), invalid(true)
    {
    }
    CGroupTokenInfo(const CGroupTokenID &associated, const GroupAuthorityFlags _controllingGroupFlags, CAmount qty = 0)
        : associatedGroup(associated), controllingGroupFlags(_controllingGroupFlags), quantity(qty), invalid(false)
    {
    }
    CGroupTokenInfo(const CKeyID &associated, const GroupAuthorityFlags _controllingGroupFlags, CAmount qty = 0)
        : associatedGroup(associated), controllingGroupFlags(_controllingGroupFlags), quantity(qty), invalid(false)
    {
    }
    // Return the controlling (can mint and burn) and associated (OP_GROUP in script) group of a script
    CGroupTokenInfo(const CScript &script);

    // Return the controlling (can mint and burn) and associated (OP_GROUP in script) group of a script
    CGroupTokenInfo(const CTxOut &output);

    /** Reset the info in this object for subsequent use, equivalent to the default ctor */
    void clear()
    {
        associatedGroup = CGroupTokenID();
        controllingGroupFlags = GroupAuthorityFlags(GroupAuthorityFlags::NONE);
        quantity = 0;
        invalid = false;
    }

    CGroupTokenID associatedGroup; // The group announced by the script (or the nexa group if no OP_GROUP)
    GroupAuthorityFlags controllingGroupFlags; // if the utxo is a controller this is not NONE
    CAmount quantity; // The number of tokens specified in this script
    bool invalid;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action, int nType, int nVersion)
    {
        READWRITE(this->associatedGroup);
        READWRITE(this->quantity);
        READWRITE(this->invalid);
    }

    // return true if this object is a token authority.
    bool isAuthority() const
    {
        return ((controllingGroupFlags & GroupAuthorityFlags::AUTHORITY) == GroupAuthorityFlags::AUTHORITY);
    }
    // return true if this object is a new token creation output.
    // Note that the group creation nonce cannot be 0
    bool isGroupCreation(GroupTokenIdFlags tokenGroupIdFlags = GroupTokenIdFlags::NONE) const
    {
        bool hasNonce = ((uint64_t)quantity & (uint64_t)~GroupAuthorityFlags::ALL_FLAG_BITS) != 0;

        return (((controllingGroupFlags & GroupAuthorityFlags::AUTHORITY) == GroupAuthorityFlags::AUTHORITY) &&
                hasNonce && associatedGroup.hasFlag(tokenGroupIdFlags));
    }
    // return true if this object allows minting.
    bool allowsMint() const
    {
        return (controllingGroupFlags & (GroupAuthorityFlags::AUTHORITY | GroupAuthorityFlags::MINT)) ==
               (GroupAuthorityFlags::AUTHORITY | GroupAuthorityFlags::MINT);
    }
    // return true if this object allows melting.
    bool allowsMelt() const
    {
        return (controllingGroupFlags & (GroupAuthorityFlags::AUTHORITY | GroupAuthorityFlags::MELT)) ==
               (GroupAuthorityFlags::AUTHORITY | GroupAuthorityFlags::MELT);
    }
    // return true if this object allows child controllers.
    bool allowsRenew() const
    {
        return (controllingGroupFlags & (GroupAuthorityFlags::AUTHORITY | GroupAuthorityFlags::BATON)) ==
               (GroupAuthorityFlags::AUTHORITY | GroupAuthorityFlags::BATON);
    }
    // return true if this object allows rescripting.
    bool allowsRescript() const
    {
        return (controllingGroupFlags & (GroupAuthorityFlags::AUTHORITY | GroupAuthorityFlags::RESCRIPT)) ==
               (GroupAuthorityFlags::AUTHORITY | GroupAuthorityFlags::RESCRIPT);
    }
    // return true if this object allows subgroups.
    bool allowsSubgroup() const
    {
        return (controllingGroupFlags & (GroupAuthorityFlags::AUTHORITY | GroupAuthorityFlags::SUBGROUP)) ==
               (GroupAuthorityFlags::AUTHORITY | GroupAuthorityFlags::SUBGROUP);
    }

    bool isInvalid() const { return invalid; };
    bool operator==(const CGroupTokenInfo &g)
    {
        if (g.invalid || invalid)
            return false;
        return ((associatedGroup == g.associatedGroup) && (controllingGroupFlags == g.controllingGroupFlags));
    }
};

// Verify that the token groups in this transaction properly balance
bool CheckGroupTokens(const CTransaction &tx,
    CValidationState &state,
    const CCoinsViewCache &view,
    const CCoinsViewCache &readonlyCoins);

// Return true if any output in this transaction is part of a group
bool IsAnyTxOutputGrouped(const CTransaction &tx);

bool IsAnyTxOutputGroupedCreation(const CTransaction &tx,
    const GroupTokenIdFlags tokenGroupIdFlags = GroupTokenIdFlags::NONE);

// Serialize a CAmount into an array of bytes.
// This serialization does not store the length of the serialized data within the serialized data.
// It is therefore useful only within a system that already identifies the length of this field (such as a CScript).
std::vector<unsigned char> SerializeAmount(CAmount num);

// Deserialize a CAmount from an array of bytes.
// This function uses the size of the vector to determine how many bytes were used in serialization.
// It is therefore useful only within a system that already identifies the length of this field (such as a CScript).
CAmount DeserializeAmount(opcodetype opcodeQty, std::vector<unsigned char> &vec);

/** Identify OP_GROUP script attribute sequence (i.e. data, data, OP_GROUP, OP_DROP, OP_DROP)
        @param[in] The script
        @param[inout] offsetInOut If not null, start at this offset in hashBytes, and if this a group attribute
                           advance this "program counter" to the byte AFTER the OP_GROUP attribute.
        @param[out] grp If not null, set to group info read from the script.
        @return true If this pointed to an OP_GROUP attribute sequence
*/
bool IsScriptGrouped(const CScript &script, CScript::const_iterator *pc = nullptr, CGroupTokenInfo *grp = nullptr);

// Convenience function to just extract the group from a script
inline CGroupTokenID GetGroupToken(const CScript &script) { return CGroupTokenInfo(script).associatedGroup; }
extern CGroupTokenID NoGroup;

#endif // NEXA_TOKEN_GROUPS_H
