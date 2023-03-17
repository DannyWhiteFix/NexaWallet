#include "consensus/grouptokens.h"
#include "interpreter.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "script/scripttemplate.h"
#include "streams.h"
#include <vector>

CGroupTokenID NoGroup; // No group specified.

static bool IsPushOpcode(opcodetype opcode) { return opcode <= OP_16; }
CAmount DeserializeAmount(opcodetype opcodeQty, std::vector<unsigned char> &vec)
{
    /* Disallow raw opcodes or single byte sizes, because having them is an unnecessary decode complication
    if ((opcodeQty >= OP_1) && (opcodeQty <= OP_16))
    {
        return opcodeQty-OP_1+1;
    }
    if (opcodeQty == OP_1NEGATE)
    {
        return 0x81;
    }

    int sz = vec.size();
    if (sz == 1)
    {
        return vec[0];
    }
    */
    int sz = vec.size();
    // client version is 0 because it is unneeded for this read and is unavailable in libraries that include this code
    CDataStream strm(vec, SER_NETWORK, 0);
    if (sz == 2)
    {
        return ser_readdata16(strm);
    }
    if (sz == 4)
    {
        return ser_readdata32(strm);
    }
    if (sz == 8)
    {
        uint64_t v = ser_readdata64(strm);
        return (CAmount)v;
    }
    throw std::ios_base::failure("DeserializeAmount(): invalid format");
}

bool IsScriptGrouped(const CScript &script, CScript::const_iterator *pcin, CGroupTokenInfo *grp)
{
    CScript::const_iterator pc = pcin ? *pcin : script.begin();
    // If the caller isn't interested in the group data, then just dump it here.
    CGroupTokenInfo extra;
    if (grp == nullptr)
        grp = &extra;
    else
        grp->clear();

    std::vector<unsigned char> groupId;
    std::vector<unsigned char> tokenQty;
    std::vector<unsigned char> data;
    opcodetype opcodeGrp;
    opcodetype opcodeQty;
    const ScriptType scriptType = script.type;
    // This API should never be called for satisfier or args scripts
    DbgAssert(scriptType != ScriptType::PUSH_ONLY, return false);
    if (scriptType == ScriptType::SATOSCRIPT)
    {
        grp->associatedGroup = NoGroup;
        grp->invalid = false;
        return true; // Script is "grouped" but the group is the native token
    }
    else if (scriptType == ScriptType::TEMPLATE)
    {
        if (!script.GetOp(pc, opcodeGrp, groupId))
        {
            grp->associatedGroup = NoGroup;
            grp->invalid = true;
            return false; // Script is bad
        }
        if (opcodeGrp == OP_0)
        {
            grp->associatedGroup = NoGroup;
            grp->quantity = 0;
            grp->invalid = false;
            // Since the script matched the opgroup syntax, move the caller's pc foward.
            if (pcin)
                *pcin = pc;
            return true; // Script is "grouped" but the group is the native token
        }
        // Ok its a real group, get the quantity
        if (!script.GetOp(pc, opcodeQty, tokenQty))
        {
            grp->associatedGroup = NoGroup;
            grp->invalid = true;
            return false;
        }
    }
    else
    {
        grp->associatedGroup = NoGroup;
        return false;
    }

    // group must be 32 bytes or more
    // recall that opcodes lower than PUSHDATA1 (0x4c) push that many bytes onto the stack
    if (opcodeGrp < 0x20)
    {
        grp->invalid = true;
        return false;
    }
    // Must be true based on the opcode test
    DbgAssert(groupId.size() >= 0x20, {
        grp->invalid = true;
        return false;
    });

    // Quantity must be a 2, 4, or 8 byte number
    if ((opcodeQty != 2) && (opcodeQty != 4) && (opcodeQty != 8))
    {
        grp->invalid = true;
        return false;
    }

    try
    {
        grp->quantity = DeserializeAmount(opcodeQty, tokenQty);
    }
    catch (std::ios_base::failure &f)
    {
        grp->invalid = true;
        return false;
    }
    if (grp->quantity < 0)
    {
        grp->controllingGroupFlags = (GroupAuthorityFlags)grp->quantity;
    }
    grp->associatedGroup = groupId;
    grp->invalid = false;
    // Since the script matched the opgroup syntax, move the caller's pc foward.
    if (pcin)
        *pcin = pc;
    return true;
}

/* nonstandard
bool MatchGroupedPayToPubkey(const CScript &script, valtype &pubkey, CGroupTokenInfo& grp)
{
    // Standard tx, sender provides pubkey, receiver adds signature
    // Template: "CScript() << OP_PUBKEY << OP_CHECKSIG"
    CScript::const_iterator pc = script.begin();
    if (!IsScriptGrouped(script, &pc, &grp)) return false;
    unsigned int offset = &pc[0] - &begin()[0];

    if ((script.size() == offset + CPubKey::PUBLIC_KEY_SIZE + 2) && (script[0] == CPubKey::PUBLIC_KEY_SIZE) &&
        (script.back() == OP_CHECKSIG))
    {
        pubkey = valtype(pc + 1, pc + CPubKey::PUBLIC_KEY_SIZE + 1);
        return CPubKey::ValidSize(pubkey);
    }

    if ((script.size() == offset + CPubKey::COMPRESSED_PUBLIC_KEY_SIZE + 2) &&
        (script[0] == CPubKey::COMPRESSED_PUBLIC_KEY_SIZE) &&
        (script.back() == OP_CHECKSIG))
    {
        pubkey = valtype(pc + 1, pc + CPubKey::COMPRESSED_PUBLIC_KEY_SIZE + 1);
        return CPubKey::ValidSize(pubkey);
    }
    return false;
}
*/


ScriptTemplateError GetScriptTemplate(const CScript &script,
    CGroupTokenInfo *groupInfo,
    std::vector<unsigned char> *templateHash,
    std::vector<unsigned char> *argsHash,
    CScript::const_iterator *pcout)
{
    if (templateHash)
        templateHash->clear();
    if (argsHash)
        argsHash->clear();
    if (groupInfo)
        groupInfo->clear();
    ScriptType scriptType = script.type;
    // a push only script is not a template, but you should not be calling this API for input or args scripts
    DbgAssert(scriptType != ScriptType::PUSH_ONLY, return ScriptTemplateError::NOT_A_TEMPLATE);
    // SATOSCRIPT scripts cannot have script templates
    if (scriptType == ScriptType::SATOSCRIPT)
        return ScriptTemplateError::NOT_A_TEMPLATE;
    // Right now we only support 2 types so any other scriptType is an invalid script
    if (scriptType != ScriptType::TEMPLATE)
        return ScriptTemplateError::INVALID;
    opcodetype opcode;
    CScript::const_iterator pc = script.begin();

    // Group ID is first info
    bool ok = IsScriptGrouped(script, &pc, groupInfo);
    // In the general format think of it as if every script is "grouped", with the native group indicated by OP_0
    // This means that a false return can only happen due to badly formatted code.
    if (!ok)
    {
        return ScriptTemplateError::INVALID;
    }

    // template hash is second
    std::vector<unsigned char> vchTemplateHash; // If caller doesn't care about this value, give some temp space
    if (!templateHash)
        templateHash = &vchTemplateHash;

    if (!script.GetOp(pc, opcode, *templateHash))
    {
        return ScriptTemplateError::INVALID;
    }
    if (!IsPushOpcode(opcode))
        return ScriptTemplateError::INVALID;
    NumericOpcodeToVector(opcode, *templateHash);
    size_t templateHashSize = templateHash->size();
    if ((templateHashSize != CHash160::OUTPUT_SIZE) && (templateHashSize != CHash256::OUTPUT_SIZE))
    {
        if (templateHashSize > 0 && templateHashSize < 2) // check for valid well known script template
        {
            VchType tmp = *templateHash;
            CScript unused;
            if (ConvertWellKnownTemplateHash(tmp, unused) != SCRIPT_ERR_OK)
            {
                return ScriptTemplateError::INVALID;
            }
        }
        else
            return ScriptTemplateError::INVALID;
    }

    // args hash is third
    std::vector<unsigned char> vchArgsHash;
    if (!argsHash)
        argsHash = &vchArgsHash;
    if (!script.GetOp(pc, opcode, *argsHash))
    {
        return ScriptTemplateError::INVALID;
    }
    if (!IsPushOpcode(opcode))
        return ScriptTemplateError::INVALID;
    size_t argsHashSize = templateHash->size();
    if (templateHash->size() > 0 && templateHash->size() <= 2) // This may be a "well-known" template
    {
        // Check all possible well known templates here
        if (*templateHash == P2PKT_ID)
        {
        }
        else
        {
            return ScriptTemplateError::INVALID;
        }
    }
    else // allow 2 different hash types, or no hashed args
    {
        if ((argsHashSize != CHash160::OUTPUT_SIZE) && (argsHashSize != CHash256::OUTPUT_SIZE) && (argsHashSize != 0))
        {
            return ScriptTemplateError::INVALID;
        }
    }

    // Additional stuff is valid (visible script args)
    // For example, contract state data

    if (pcout)
        *pcout = pc;
    return ScriptTemplateError::OK;
}
