#include "script/interpreter.h"
#include "script/script.h"
#include "script/script_error.h"
#include "script/scripttemplate.h"

bool ScriptMachine::EvalParseBytecode(int64_t first, int64_t count, const CScript &pscript)
{
    auto bgn = pscript.begin();
    return EvalParseBytecode(first, count, pscript, bgn, pscript.end());
}

bool ScriptMachine::EvalParseBytecode(int64_t first,
    int64_t count,
    const CScript &pscript,
    CScript::const_iterator &parsePc,
    const CScript::const_iterator &end)
{
    if (count == 0)
        return true;
    int64_t pushPos = 0;
    int64_t pushedCount = 0;
    while (parsePc != end)
    {
        opcodetype opcode;
        std::vector<unsigned char> pushedData;
        if (!pscript.GetOp(parsePc, opcode, pushedData)) // Also advances pc
        {
            return set_error(&error, SCRIPT_ERR_PARSE);
        }
        if (IsPushOpcode(opcode))
        {
            if (pushPos >= first)
            {
                if (((opcode >= OP_1 && opcode <= OP_16)) || opcode == OP_1NEGATE)
                {
                    CScriptNum bn = CScriptNum::fromIntUnchecked(int(opcode) - int(OP_1 - 1));
                    PushStack(bn.vchStackItem());
                }
                else
                    PushStack(pushedData);
                pushedCount++;
                if (pushedCount == count)
                    return true;
            }
            pushPos++;
        }
    }
    return set_error(&error, SCRIPT_ERR_PARSE);
}


// gets the Mth piece of data from a template output, as if the output was fully expanded.
// In other words, the data is presented as if any concise shortcuts (like skipping the group amount if no group)
// do not exist.
// m =
// 0 = Group id (OP_0 if no group)
// 1 = Group amount (OP_0 if no group or is an authority)
// 2 = Group authority flags (OP_0 if no group or not an authority)
// 3 = template hash, ALWAYS actual hash even if well known (future proof)
// 4 = args hash of the nth output
// 5,6,7 = OP_0
// 8 onwards = the subsequent pushes in this output (visible args and non-arg data)
bool ScriptMachine::EvalParseCanonicalLockingBytecode(int64_t first, int64_t count, const CScript &pscript)
{
    CGroupTokenInfo grp;
    VchType templateHash;
    VchType argsHash;
    CScript::const_iterator rest = pscript.begin();
    VchType zero; // OP_0 is pushing an empty item
    if (count == 0)
        return true;

    ScriptTemplateError ret = GetScriptTemplate(pscript, &grp, &templateHash, &argsHash, &rest);
    if (ret != ScriptTemplateError::OK)
    {
        return set_error(&error, SCRIPT_ERR_PARSE);
    }

    int64_t pushedCount = 0;
    auto idx = first;
    for (int64_t i = 0; i < count; i++)
    {
        idx = first + i;
        if (idx >= 8)
            break; // grabbing pushes from the "rest" script
        switch (idx)
        {
        case 0: // group ID
            if (grp.invalid || (grp.associatedGroup == NoGroup))
                PushStack(zero);
            else
                PushStack(grp.associatedGroup.bytes());
            pushedCount++;
            break;
        case 1: // amount
            if (grp.invalid || (grp.associatedGroup == NoGroup))
                PushStack(zero);
            else
            {
                if (grp.isAuthority())
                    PushStack(zero);
                else
                {
                    CScriptNum bn = CScriptNum::fromIntUnchecked(grp.quantity);
                    PushStack(bn.vchStackItem());
                }
            }
            pushedCount++;
            break;
        case 2: // authority flags
            if (grp.invalid || (grp.associatedGroup == NoGroup))
                PushStack(zero);
            else
            {
                if (!grp.isAuthority())
                    PushStack(zero);
                else
                {
                    CScriptNum bn = CScriptNum::fromIntUnchecked(static_cast<uint64_t>(grp.controllingGroupFlags));
                    PushStack(bn.vchStackItem());
                }
            }
            pushedCount++;
            break;
        case 3:
            PushStack(templateHash);
            pushedCount++;
            break;
        case 4:
            PushStack(argsHash);
            pushedCount++;
            break;
        case 5:
        case 6:
        case 7:
            PushStack(zero);
            pushedCount++;
            break;
        default:
            break;
        }
    }

    if (pushedCount < count)
        return EvalParseBytecode(idx - 8, count - pushedCount, pscript, rest, pscript.end());
    return true;
}


// If this is a template spend,
// 0 = template code
// 1 = args code
// 8 onwards = satisfier pushes
bool ScriptMachine::EvalParseUnlockingTemplateBytecode(int64_t first,
    int64_t count,
    const CScript &unlockingScript,
    const CScript &lockingScript)
{
    CGroupTokenInfo grp;
    VchType templateHash;
    VchType argsHash;
    CScript::const_iterator lockingRest = lockingScript.begin();
    VchType zero; // OP_0 is pushing an empty item
    if (count == 0)
        return true;

    // Parse the lockingScript into its pieces so we know what to expect in the unlocking script
    ScriptTemplateError ret = GetScriptTemplate(lockingScript, &grp, &templateHash, &argsHash, &lockingRest);
    if (ret != ScriptTemplateError::OK)
    {
        return set_error(&error, SCRIPT_ERR_PARSE);
    }
    CScript::const_iterator satisfierBegin = unlockingScript.begin();
    CScript constraintScript;
    std::vector<unsigned char> argsScriptBytes;
    ScriptError templateLoadError =
        LoadCheckTemplateHash(unlockingScript, satisfierBegin, templateHash, constraintScript);
    if (templateLoadError != SCRIPT_ERR_OK)
    {
        return set_error(&error, templateLoadError);
    }
    if (argsHash.size() != 0) // no hash (OP_0) means no args
    {
        // Grab the args script (its the 2nd data push in the scriptSig)
        opcodetype argsDataOpcode;
        if (!unlockingScript.GetOp(satisfierBegin, argsDataOpcode, argsScriptBytes))
        {
            return set_error(&error, SCRIPT_ERR_TEMPLATE);
        }
    }

    // The rest of the unlockingScript is the satisfier
    CScript satisfier(satisfierBegin, unlockingScript.end());

    // Now provide the requested items
    int64_t pushedCount = 0;
    auto idx = first;
    for (int64_t i = 0; i < count; i++)
    {
        idx = first + i;
        if (idx >= 8)
            break; // grabbing pushes from the "rest" script
        switch (idx)
        {
        case 0: // template code
        {
            PushStack(constraintScript.ToVch());
            pushedCount++;
        }
        break;
        case 1: // args code
            PushStack(argsScriptBytes);
            pushedCount++;
            break;
        case 2:
        case 3:
        case 4:
        case 5:
        case 6:
        case 7:
            PushStack(zero);
            pushedCount++;
            break;
        default:
            break;
        }
    }

    if (pushedCount < count)
        return EvalParseBytecode(idx - 8, count - pushedCount, unlockingScript, satisfierBegin, unlockingScript.end());
    return true;
}
