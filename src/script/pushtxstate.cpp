// Copyright (c) 2020 G. Andrew Stone
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "script/pushtxstate.h"
#include "amount.h"
#include "consensus/consensus.h"
#include "hashwrapper.h"
#include "primitives/transaction.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "script/sign.h"
#include "uint256.h"

ScriptError EvalPushTxState(const VchType &specifier, ScriptMachine &sm)
{
    const ScriptImportedState &sis = sm.sis;
    ScriptError ret = SCRIPT_ERR_OK;

    auto specIter = specifier.begin();
    auto specEnd = specifier.end();
    if (specEnd == specIter)
        return SCRIPT_ERR_INVALID_STATE_SPECIFIER;
    if (!sis.tx)
        return SCRIPT_ERR_DATA_REQUIRED;

    auto specCur = specIter;
    specIter++;
    switch (*specCur)
    {
    case PushTxStateSpecifier::TX_ID:
    {
        uint256 hash = sis.tx->GetId();
        sm.PushStack(StackItem(hash.begin(), hash.end()));
    }
    break;
    case PushTxStateSpecifier::TX_IDEM:
    {
        uint256 hash = sis.tx->GetIdem();
        sm.PushStack(StackItem(hash.begin(), hash.end()));
    }
    break;
    case PushTxStateSpecifier::TX_INCOMING_AMOUNT:
    {
        CScriptNum bn = CScriptNum::fromIntUnchecked(sis.txInAmount);
        sm.PushStack(bn.vchStackItem());
    }
    break;
    case PushTxStateSpecifier::TX_OUTGOING_AMOUNT:
    {
        CScriptNum bn = CScriptNum::fromIntUnchecked(sis.txOutAmount);
        sm.PushStack(bn.vchStackItem());
    }
    break;

    case PushTxStateSpecifier::GROUP_NTH_INPUT:
    case PushTxStateSpecifier::GROUP_NTH_OUTPUT:
    {
        // Grab the "nth" index as a 2 byte value:
        // encode this in nexascript: PUSH X, PUSH 2, BIN2NUM
        if (specEnd - specIter < 2)
        {
            return SCRIPT_ERR_INVALID_STATE_SPECIFIER;
        }
        VchType nthSerialized(specIter, specIter + 2);
        CScriptNum nthScriptNum(nthSerialized, false, 65536);
        int64_t nth = nthScriptNum.getint64(); // can't be > than a 2 byte integer anyway
        if (nth < 0 || nth >= MAX_TX_NUM_VOUT)
        {
            return SCRIPT_ERR_INVALID_STATE_SPECIFIER;
        }
        specIter += 2;
        if (specEnd - specIter < (int)sizeof(uint256))
            return SCRIPT_ERR_INVALID_STATE_SPECIFIER;
        VchType grpVch(specIter, specEnd);
        CGroupTokenID grpId(grpVch);

        bool found = false;
        if (*specCur == PushTxStateSpecifier::GROUP_NTH_OUTPUT)
        {
            for (uint64_t vIdx = 0; vIdx < sis.tx->vout.size() && !found; vIdx++)
            {
                const CTxOut &outp = sis.tx->vout[vIdx];
                CGroupTokenInfo ginfo(outp);
                if (ginfo.associatedGroup == grpId)
                {
                    if (nth == 0)
                    {
                        CScriptNum bn = CScriptNum::fromIntUnchecked(vIdx);
                        sm.PushStack(bn.vchStackItem());
                        found = true;
                        break;
                    }
                    nth--;
                }
            }
        }
        else if (*specCur == PushTxStateSpecifier::GROUP_NTH_INPUT)
        {
            // remember that the spentCoins vector corresponds idx-to-idx to the tx->vin input vector
            for (uint64_t vIdx = 0; vIdx < sis.spentCoins.size() && !found; vIdx++)
            {
                const CTxOut &inp = sis.spentCoins[vIdx];
                CGroupTokenInfo ginfo(inp);
                if (ginfo.associatedGroup == grpId)
                {
                    if (nth == 0)
                    {
                        CScriptNum bn = CScriptNum::fromIntUnchecked(vIdx);
                        sm.PushStack(bn.vchStackItem());
                        found = true;
                        break;
                    }
                    nth--;
                }
            }
        }
        // We can fail the script if there isn't an Nth without loss of generality, because
        // the script can know the number of outputs using GROUP_INCOMING/OUTGOING_COUNT.
        if (!found)
        {
            return SCRIPT_ERR_INVALID_STATE_SPECIFIER;
        }
    }
    break;
    // All specifiers that take only a group as their argument
    case PushTxStateSpecifier::GROUP_INCOMING_AMOUNT:
    case PushTxStateSpecifier::GROUP_OUTGOING_AMOUNT:
    case PushTxStateSpecifier::GROUP_INCOMING_COUNT:
    case PushTxStateSpecifier::GROUP_OUTGOING_COUNT:
    case PushTxStateSpecifier::GROUP_COVENANT_HASH:
    {
        if (!sis.groupState)
            return SCRIPT_ERR_DATA_REQUIRED;
        if (specEnd - specIter < (int)sizeof(uint256))
            return SCRIPT_ERR_INVALID_STATE_SPECIFIER;
        VchType grpVch(specIter, specEnd);
        CGroupTokenID grpId(grpVch);
        auto grpIter = sis.groupState->find(grpId);
        bool nogrp = (grpIter == sis.groupState->end());
        GroupBalance *gb = nullptr;
        if (!nogrp)
            gb = &grpIter->second;
        CScriptNum zero = CScriptNum::fromIntUnchecked(0);
        switch (*specCur)
        {
        case PushTxStateSpecifier::GROUP_INCOMING_AMOUNT:
            sm.PushStack((nogrp ? zero : CScriptNum::fromIntUnchecked(gb->input)).vchStackItem());
            break;
        case PushTxStateSpecifier::GROUP_OUTGOING_AMOUNT:
            sm.PushStack((nogrp ? zero : CScriptNum::fromIntUnchecked(gb->output)).vchStackItem());
            break;
        case PushTxStateSpecifier::GROUP_INCOMING_COUNT:
            sm.PushStack((nogrp ? zero : CScriptNum::fromIntUnchecked(gb->numInputs)).vchStackItem());
            break;
        case PushTxStateSpecifier::GROUP_OUTGOING_COUNT:
            sm.PushStack((nogrp ? zero : CScriptNum::fromIntUnchecked(gb->numOutputs)).vchStackItem());
            break;
        case PushTxStateSpecifier::GROUP_COVENANT_HASH:
            if ((nogrp) || (gb->covenant.size() == 0))
            {
                sm.PushStack(OP_FALSE);
            }
            else
            {
                StackItem si(gb->covenant.begin(), gb->covenant.end());
                sm.PushStack(si);
            }
            break;
        case PushTxStateSpecifier::GROUP_AUTHORITY_FLAGS:
            sm.PushStack(nogrp ? zero.vchStackItem() : StackItem((uint64_t)gb->ctrlPerms));
            break;
        }
    }
    break;
    default: // Unknown specifier
        return SCRIPT_ERR_INVALID_STATE_SPECIFIER;
    }

    return ret;
}
