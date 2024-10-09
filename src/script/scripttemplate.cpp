// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "interpreter.h"

#include "bitfield.h"
#include "bitmanip.h"
#include "crypto/ripemd160.h"
#include "crypto/sha1.h"
#include "crypto/sha256.h"
#include "hashwrapper.h"
#include "primitives/transaction.h"
#include "pubkey.h"
#include "interpreter.h"
#include "script/script.h"
#include "script/script_error.h"
#include "script/scripttemplate.h"
#include "uint256.h"
#include "util.h"
#include "consensus/grouptokens.h"

const CScript p2pkt(CScript() << OP_FROMALTSTACK << OP_CHECKSIGVERIFY);
const std::vector<unsigned char> P2PKT_ID = { 1 };
const std::vector<unsigned char> P2PKT_HASH = VchHash160(p2pkt.begin(), p2pkt.end());

typedef std::vector<unsigned char> valtype;
extern bool CastToBool(const StackItem &vch);

bool VerifyTemplate(const CScript &templat,
    const CScript &constraint,
    const CScript &satisfier,
    unsigned int flags,
    unsigned int maxOps,
    unsigned int maxActualSigops,
    const ScriptImportedState &sis,
    ScriptError *serror,
    ScriptMachineResourceTracker *tracker)
{
    set_error(serror, SCRIPT_ERR_UNKNOWN_ERROR);

    if (!satisfier.IsPushOnly())
    {
        LOG(SCRIPT, "Template script: Satisfier is not push-only");
        return set_error(serror, SCRIPT_ERR_SIG_PUSHONLY);
    }

    // Note, if the constraint script is allowed to look at the satisfier stack and modify is own output stack,
    // then it could prevent the satisfier from executing certain template codepaths by identifying them based
    // on satisfier data and deliberately failing.

    // If there is any use case for "allowing the constraint script is allowed to look at the satisfier stack",
    // then an option is to disregard any errors in the constraint script execution (i.e. a bad constraint script
    // execution does not render the tx invalid).

    // However, for now, do not let the constraint script see the satisfier data, and so we can insist on push-only
    if (!constraint.IsPushOnly())
    {
        LOG(SCRIPT, "Template script: Constraint is not push-only");
        return set_error(serror, SCRIPT_ERR_SIG_PUSHONLY);
    }

    ScriptMachine ssm(flags, sis, maxOps, maxActualSigops);
    // Increase the satisfier script max size after fork1 so you can push entire scripts as args to OP_PARSE if needed
    // Since the satisfier appears in the tx inputs, this has no effect on the UTXO
    if (flags & SCRIPT_FORK1_OPCODES) ssm.maxScriptSize = MAX_SCRIPT_TEMPLATE_SIZE;

    // Step 1, evaluate the satisfier to produce a stack
    if (!ssm.Eval(satisfier))
    {
        if (serror)
            *serror = ssm.getError();
        return false;
    }

    // Step 2, evaluate the constraint script
    ScriptMachine sm = ssm;  // Keep the operation counts
    sm.maxScriptSize = MAX_SCRIPT_TEMPLATE_SIZE;
    sm.ClearStack();
    // Allowing the constraint script to look at (but not modify!!) the satisfier stack may have value but its use
    // is unclear at this time.  So right now the constraint script is limited to push-only opcodes, and therefore
    // there is no reason to offer the satisfier stack to the constraint.
    //sm.setAltStack(ssm.stack());  // constraint can look at the stack the satisfier will provide
    sm.ClearAltStack();

    if (!sm.Eval(constraint))
    {
        if (serror)
            *serror = sm.getError();
        return false;
    }

    // The data the constraint script leaves for the template goes on the altstack.
    sm.setAltStack(sm.getStack(), sm.stackSize);
    // The data the satisfier script leaves for the template goes on the main stack (just like traditional BTC).
    sm.setStack(ssm.getStack(), ssm.stackSize);

    // Step 3, evaluate the template
    if (!sm.Eval(templat))
    {
        if (serror)
            *serror = sm.getError();
        return false;
    }

    if (tracker)
    {
        auto smStats = sm.getStats();
        tracker->update(smStats);
    }

    const Stack &smStack = sm.getStack();
    if (smStack.size() != 0)
    {
        LOG(SCRIPT, "Script template: final stack has %d items (must be 0)", smStack.size());
        return set_error(serror, SCRIPT_ERR_CLEANSTACK);
    }
    return set_success(serror);
}

// TODO: this must exist somewhere else
void NumericOpcodeToVector(opcodetype opcode, VchType &templateHash)
{
    if (opcode == OP_1)
    {
        VchType one = {1};
        templateHash = one;
    }
}

ScriptTemplateError ParseWellKnownTemplateHashArg(VchType &templateHash, CScript &templateScript)
{
    size_t templateHashSize = templateHash.size();
    if ((templateHashSize != CHash160::OUTPUT_SIZE) && (templateHashSize != CHash256::OUTPUT_SIZE))
    {
        if (templateHashSize > 0 && templateHashSize < 2) // check for valid well known script template
        {
            VchType tmp(templateHash.begin(), templateHash.end());
            CScript unused;
            if (ConvertWellKnownTemplateHash(tmp, unused) != SCRIPT_ERR_OK)
            {
                return ScriptTemplateError::INVALID;
            }
        }
        else
            return ScriptTemplateError::INVALID;
    }
    return ScriptTemplateError::OK;
}

ScriptError ConvertWellKnownTemplateHash(VchType &templateHash, CScript &templateScript)
{
    // You shouldn't be calling this function for out-of-size values.
    // But in release mode the best we can do is report no known conversion.
    DbgAssert(templateHash.size() <= 2, return SCRIPT_ERR_TEMPLATE);

    if (templateHash == P2PKT_ID)
    {
        templateHash = P2PKT_HASH;
        templateScript = p2pkt;
        return SCRIPT_ERR_OK;
    }
    return SCRIPT_ERR_TEMPLATE; // All unknown values are illegal.
}

// This function looks at the input script and templateHash, extracts the template script, and verifies it.
// Satisfier is input-only,
// satisfierIter, and templateHash are input-output.  The satisfierIter is advanced if needed, the templateHash is
// updated to an actual hash if it encodes a well-known shorthand.
// templateScript is output-only.
//
ScriptError LoadCheckTemplateHash(const CScript &satisfier,
    CScript::const_iterator &satisfierIter,
    VchType &templateHash,
    CScript &templateScript)
{
    // Handle well-known template identifiers
    // Note that if the template is well-known there is NO value (not even OP_0) within the satisfier script.
    // This is why well known templates are checked here, before the satisfier script is used.
    size_t templateHashSize = templateHash.size();
    if (templateHashSize>0 && templateHashSize<=2)
    {
        return ConvertWellKnownTemplateHash(templateHash, templateScript);
    }

    std::vector<unsigned char> templateScriptBytes;
    opcodetype templateDataOpcode;
    if (!satisfier.GetOp(satisfierIter, templateDataOpcode, templateScriptBytes))
    {
        LOG(SCRIPT, "Script template: satisfier has bad opcode");
        return SCRIPT_ERR_TEMPLATE;
    }
    templateScript = CScript(templateScriptBytes.begin(), templateScriptBytes.end());

    if (templateHashSize == CHash160::OUTPUT_SIZE)
    {
        // Make sure that the passed template matches the template hash
        VchType actualTemplateHash(CHash160::OUTPUT_SIZE);
        CHash160()
            .Write(begin_ptr(templateScriptBytes), templateScriptBytes.size())
            .Finalize(&actualTemplateHash.front());
        if (actualTemplateHash != templateHash)
        {
            LOG(SCRIPT, "Script template: template is incorrect preimage");
            return SCRIPT_ERR_TEMPLATE;
        }
    }
    else if (templateHashSize == CHash256::OUTPUT_SIZE)
    {
        // Make sure that the passed template matches the template hash
        VchType actualTemplateHash(CHash256::OUTPUT_SIZE);
        CHash256()
            .Write(begin_ptr(templateScriptBytes), templateScriptBytes.size())
            .Finalize(&actualTemplateHash.front());
        if (actualTemplateHash != templateHash)
        {
            LOG(SCRIPT, "Script template: template is incorrect preimage");
            return SCRIPT_ERR_TEMPLATE;
        }
    }
    else
    {
        LOG(SCRIPT, "Script template: template hash is incorrect size");
        return SCRIPT_ERR_TEMPLATE;
    }
    return SCRIPT_ERR_OK;
}

CScript ScriptTemplateLock(const VchType& scriptHash, const VchType &argsHash, const VchType &visibleArgs, const CGroupTokenID& group, CAmount grpQuantity)
{
    CScript ret;
    if (group != NoGroup)
    {
        if (grpQuantity != -1)
        {
            ret = (CScript(ScriptType::TEMPLATE) << group.bytes() << SerializeAmount(grpQuantity) << scriptHash << argsHash) + CScript(visibleArgs.begin(), visibleArgs.end());
        }
        else  // Encodes an invalid quantity (for use within addresses)
        {
            ret = (CScript(ScriptType::TEMPLATE) << group.bytes() << OP_0 << scriptHash << argsHash) + CScript(visibleArgs.begin(), visibleArgs.end());
        }
    }
    else  // Not grouped
    {
        ret = (CScript(ScriptType::TEMPLATE) << OP_0 << scriptHash << argsHash) + CScript(visibleArgs.begin(), visibleArgs.end());
    }
    return ret;
}

CScript ScriptTemplateLock(const VchType& scriptHash, const VchType &argsHash, const CScript &visibleArgs, const CGroupTokenID& group, CAmount grpQuantity)
{
    CScript ret;
    if (group != NoGroup)
    {
        if (grpQuantity != -1)
        {
            ret = (CScript(ScriptType::TEMPLATE) << group.bytes() << SerializeAmount(grpQuantity) << scriptHash << argsHash) + CScript(visibleArgs.begin(), visibleArgs.end());
        }
        else  // Encodes an invalid quantity (for use within addresses)
        {
            ret = (CScript(ScriptType::TEMPLATE) << group.bytes() << OP_0 << scriptHash << argsHash) + CScript(visibleArgs.begin(), visibleArgs.end());
        }
    }
    else  // Not grouped
    {
        ret = (CScript(ScriptType::TEMPLATE) << OP_0 << scriptHash << argsHash) + visibleArgs;
    }
    return ret;
}

CScript ScriptWellKnownTemplateLock(const uint64_t wellKnownId, const VchType &argsHash, const VchType &visibleArgs, const CGroupTokenID& group, CAmount grpQuantity)
{
    CScript ret;
    VchType constraint;
    if (wellKnownId == 1) constraint = P2PKT_ID;
    else assert(false);
    if (group != NoGroup)
    {
        if (grpQuantity != -1)
        {
            ret = (CScript(ScriptType::TEMPLATE) << group.bytes() << SerializeAmount(grpQuantity) << wellKnownId << argsHash) + CScript(visibleArgs.begin(), visibleArgs.end());
        }
        else  // Encodes an invalid quantity (for use within addresses)
        {
            ret = (CScript(ScriptType::TEMPLATE) << group.bytes() << OP_0 << wellKnownId << argsHash) + CScript(visibleArgs.begin(), visibleArgs.end());
        }
    }
    else  // Not grouped
    {
        ret = (CScript(ScriptType::TEMPLATE) << OP_0 << wellKnownId << argsHash) + CScript(visibleArgs.begin(), visibleArgs.end());
    }
    return ret;
}



CScript ScriptTemplateLock(const CScript &constraintScript, const CScript &argsScript,
    const CScript &visibleArgsScript, const CGroupTokenID &group,
    CAmount grpQuantity, uint8_t useHash256)
{
    VchType argsHash;
    if (argsScript.size() > 0) argsHash = (useHash256 & 2) ? argsScript.Hash256() : argsScript.Hash160();
    VchType constraintHash = (useHash256 & 1) ?  constraintScript.Hash256() : constraintScript.Hash160();
    return ScriptTemplateLock(constraintHash, argsHash, visibleArgsScript, group, grpQuantity);
}

CScript ScriptTemplateLock(const CScript &templateIn, const CGroupTokenID& group, CAmount grpQuantity)
{
    CGroupTokenInfo currentGroupInfo;
    VchType scriptHash;
    VchType argsHash;
    CScript::const_iterator rest = templateIn.begin();

    // Pull this output apart and then recombine with the new group and grpQuantity info.
    ScriptTemplateError error = GetScriptTemplate(templateIn, &currentGroupInfo, &scriptHash, &argsHash, &rest);
    if (error == ScriptTemplateError::OK)
    {
        VchType restOfScript(rest, templateIn.end());
        return ScriptTemplateOutput(scriptHash, argsHash, restOfScript, group, grpQuantity);
    }
    else
    {
        // All of these destinations should be templates, but if not return a script that won't work so money isnt
        // lost if used.
        return CScript().SetInvalid();
    }
}

CScript ScriptTemplateUnlock(const CScript &constraintScript,
                             const CScript &satisfierScript, const CScript &argsScript)
{
    auto ret = CScript();
    ret << constraintScript.ToVch();
    if (argsScript.size() > 0) ret << argsScript.ToVch();
    return ret + satisfierScript;
}

CScript ScriptWellKnownTemplateUnlock(uint64_t wellKnownId, const CScript &satisfierScript, const CScript &argsScript)
{
    auto ret = CScript();
    // We do not actually need the constraint script's well known id, we just need to know its is one.
    if (argsScript.size() > 0) ret << argsScript.ToVch();
    return ret + satisfierScript;
}


CScript P2pktOutput(const VchType &argsHash, const CGroupTokenID& group, CAmount grpQuantity)
{
    return ScriptTemplateOutput(P2PKT_ID, argsHash, VchType(), group, grpQuantity);
}

CScript P2pktOutput(const CPubKey &pubkey, const CGroupTokenID& group, CAmount grpQuantity)
{
    CScript tArgs = CScript() << ToByteVector(pubkey);
    return ScriptTemplateOutput(P2PKT_ID, VchHash160(tArgs), VchType(), group, grpQuantity);
}


CScript UngroupedScriptTemplate(const CScript &templateIn)
{
    CScript::const_iterator rest = templateIn.begin();
    CGroupTokenInfo groupInfo;
    VchType templateHash;
    VchType argsHash;
    ScriptTemplateError terror = GetScriptTemplate(templateIn, &groupInfo, &templateHash, &argsHash, &rest);
    if (terror == ScriptTemplateError::OK)
    {
        VchType restOfScript(rest, templateIn.end());
        return ScriptTemplateOutput(templateHash, argsHash, restOfScript);
    }
    DbgAssert(false, return templateIn);
}
