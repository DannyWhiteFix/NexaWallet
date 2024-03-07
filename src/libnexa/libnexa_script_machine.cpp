// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "libnexa_script_machine.h"

#ifndef LIGHT

// Create a ScriptMachine with no transaction context -- useful for tests and debugging
// This ScriptMachine can't CHECKSIG or CHECKSIGVERIFY
SLAPI void *CreateNoContextScriptMachine(unsigned int flags)
{
    ScriptMachineData *smd = new ScriptMachineData();
    smd->sis = std::make_shared<ScriptImportedState>();
    smd->sm = new ScriptMachine(flags, *smd->sis, 0xffffffff, 0xffffffff);
    return (void *)smd;
}

// Create a ScriptMachine operating in the context of a particular transaction and input.
// The transaction, input index, and input amount are used in CHECKSIG and CHECKSIGVERIFY to generate the hash that
// the signature validates.
void *CreateScriptMachine(unsigned int flags,
    unsigned int inputIdx,
    unsigned char *txData,
    int txbuflen,
    unsigned char *coinData,
    int coinbuflen,
    std::string *errorDetails)
{
    checkSigInit();

    ScriptMachineData *smd = new ScriptMachineData();
    std::shared_ptr<CTransaction> txref = std::make_shared<CTransaction>();
    std::vector<CTxOut> coins;

    {
        CDataStream ssData((char *)txData, (char *)txData + txbuflen, SER_NETWORK, PROTOCOL_VERSION);
        try
        {
            ssData >> *txref;
        }
        catch (const std::exception &)
        {
            if (errorDetails)
            {
                *errorDetails = "Error deserializing transaction";
            }
            delete smd;
            return 0;
        }
    }

    {
        CDataStream ssData((char *)coinData, (char *)coinData + coinbuflen, SER_NETWORK, PROTOCOL_VERSION);
        try
        {
            ssData >> coins;
        }
        catch (const std::exception &)
        {
            if (errorDetails)
            {
                *errorDetails = "Error deserializing UTXO list";
            }
            delete smd;
            return 0;
        }
    }

    // The passed coins vector needs to be the txout for each vin, so the sizes must be the same
    if (coins.size() != txref->vin.size())
    {
        if (errorDetails)
        {
            *errorDetails = "Error: UTXO list length does not match tx vin length";
        }
        delete smd;
        return 0;
    }

    CValidationState state;
    {
        // Construct a view of all the supplied coins
        CCoinsView coinsDummy;
        CCoinsViewCache prevouts(&coinsDummy);
        for (size_t i = 0; i < coins.size(); i++)
        {
            // We assume that the passed coins are in the proper order so their outpoint is what is specified
            // in the tx.  We further assume height 1 and not coinbase.  These fields are not accessible from scripts
            // so should not affect execution.
            prevouts.AddCoin(txref->vin[i].prevout, Coin(coins[i], 1, false), false);
        }

        // Fill the validation state with derived data about this transaction
        /* This pulls in too much stuff (in particular it needs to determine input coin height,
           to check coinbase spendability, which requires knowing the tip height).
           Think about refactoring CheckTxInputs to take the tip height as a parameter for functional isolation
           For now, calculate the needed data directly.
           Leaving this "canonical" code in for reference purposes
        if (!Consensus::CheckTxInputs(txref, state, prevouts))
        {
            delete smd;
            return 0;
        }
        */
        CAmount amountIn = 0;
        for (size_t i = 0; i < txref->vin.size(); i++)
        {
            amountIn += txref->vin[i].amount;
        }
        CAmount amountOut = 0;
        for (size_t i = 0; i < txref->vout.size(); i++)
        {
            amountOut += txref->vout[i].nValue;
        }
        state.inAmount = amountIn;
        state.outAmount = amountOut;
        state.fee = amountIn - amountOut;
        if (!CheckGroupTokens(*txref, state, prevouts))
        {
            if (errorDetails)
            {
                *errorDetails = std::string("Error: ") + state.GetRejectReason() + " " + state.GetDebugMessage();
            }
            delete smd;
            return 0;
        }
    }

    smd->tx = txref;
    // Its ok to get the bare tx pointer: the life of the CTransaction is the same as TransactionSignatureChecker
    // -1 is the inputAmount -- no longer used
    smd->checker = std::make_shared<TransactionSignatureChecker>(smd->tx.get(), inputIdx, flags);
    smd->sis = std::make_shared<ScriptImportedState>(&(*smd->checker), smd->tx, state, coins, inputIdx);
    // max ops and max sigchecks are set to the maximum value with the intention that the caller will check these if
    // needed because many uses of the script machine are for debugging and experimental scripts.
    smd->sm = new ScriptMachine(flags, *smd->sis, 0xffffffff, 0xffffffff);
    return (void *)smd;
}

// Create a ScriptMachine operating in the context of a particular transaction and input.
// The transaction, input index, and input amount are used in CHECKSIG and CHECKSIGVERIFY to generate the hash that
// the signature validates.
SLAPI void *CreateScriptMachine(unsigned int flags,
    unsigned int inputIdx,
    unsigned char *txData,
    int txbuflen,
    unsigned char *coinData,
    int coinbuflen)
{
    return CreateScriptMachine(flags, inputIdx, txData, txbuflen, coinData, coinbuflen, nullptr);
}


// Release a ScriptMachine context
SLAPI void SmRelease(void *smId)
{
    ScriptMachineData *smd = (ScriptMachineData *)smId;
    if (!smd)
    {
        return;
    }
    delete smd;
}

// Copy the provided ScriptMachine, returning a new ScriptMachine id that exactly matches the current one
SLAPI void *SmClone(void *smId)
{
    ScriptMachineData *from = (ScriptMachineData *)smId;
    ScriptMachineData *to = new ScriptMachineData();
    to->script = from->script;
    to->sis = from->sis;
    to->tx = from->tx;
    to->sis->tx = to->tx; // Get it pointing to the right object even though they are currently the same
    to->sm = new ScriptMachine(*from->sm);
    return (void *)to;
}

// Evaluate a script within the context of this script machine
SLAPI bool SmEval(void *smId, unsigned char *scriptBuf, unsigned int scriptLen)
{
    ScriptMachineData *smd = (ScriptMachineData *)smId;

    CScript script(scriptBuf, scriptBuf + scriptLen);
    bool ret = smd->sm->Eval(script);
    return ret;
}

// Step-by-step interface: start evaluating a script within the context of this script machine
SLAPI bool SmBeginStep(void *smId, unsigned char *scriptBuf, unsigned int scriptLen)
{
    ScriptMachineData *smd = (ScriptMachineData *)smId;
    // shared_ptr will auto-release the old one
    smd->script = std::make_shared<CScript>(scriptBuf, scriptBuf + scriptLen);
    bool ret = smd->sm->BeginStep(*smd->script);
    return ret;
}

// Step-by-step interface: execute the next instruction in the script
SLAPI unsigned int SmStep(void *smId)
{
    ScriptMachineData *smd = (ScriptMachineData *)smId;
    unsigned int ret = smd->sm->Step();
    return ret;
}

// Step-by-step interface: get the current position in this script, specified in bytes offset from the script start
SLAPI int SmPos(void *smId)
{
    ScriptMachineData *smd = (ScriptMachineData *)smId;
    return smd->sm->getPos();
}


// Step-by-step interface: End script evaluation
SLAPI bool SmEndStep(void *smId)
{
    ScriptMachineData *smd = (ScriptMachineData *)smId;
    bool ret = smd->sm->EndStep();
    return ret;
}

// Revert the script machine to initial conditions
SLAPI void SmReset(void *smId)
{
    ScriptMachineData *smd = (ScriptMachineData *)smId;
    smd->sm->Reset();
}

// Get a stack item, 0 = stack, 1 = altstack,  pass a buffer at least 520 bytes in size
// returns length of the item or -1 if no item.  0 is the stack top
SLAPI void SmSetStackItem(void *smId,
    unsigned int stack,
    int index,
    StackElementType t,
    const unsigned char *value,
    unsigned int valsize)
{
    ScriptMachineData *smd = (ScriptMachineData *)smId;

    const std::vector<StackItem> &stk = (stack == 0) ? smd->sm->getStack() : smd->sm->getAltStack();
    if (((int)stk.size()) <= index)
    {
        return;
    }
    StackItem si;
    if (t == StackElementType::VCH)
    {
        si = StackItem(value, value + valsize);
    }
    else if (t == StackElementType::BIGNUM)
    {
        BigNum bn;
        bn.deserialize(value, valsize);
        si = StackItem(bn);
    }
    else
    {
        return;
    }

    if (stack == 0)
    {
        smd->sm->setStackItem(index, si);
    }
    else if (stack == 1)
    {
        smd->sm->setAltStackItem(index, si);
    }
}

// Get a stack item, 0 = stack, 1 = altstack,  pass a buffer at least 520 bytes in size
// returns length of the item or -1 if no item.  0 is the stack top
SLAPI int SmGetStackItem(void *smId, unsigned int stack, unsigned int index, StackElementType *t, unsigned char *result)
{
    ScriptMachineData *smd = (ScriptMachineData *)smId;

    const std::vector<StackItem> &stk = (stack == 0) ? smd->sm->getStack() : smd->sm->getAltStack();
    if (stk.size() <= index)
    {
        return -1;
    }
    index = stk.size() - index - 1; // reverse it so 0 is stack top

    const StackItem &item = stk[index];

    *t = item.type;
    if (item.type == StackElementType::VCH)
    {
        int sz = item.size();
        memcpy(result, item.data().data(), sz);
        return sz;
    }
    else if (item.type == StackElementType::BIGNUM)
    {
        int sz = item.num().serialize(result, 512);
        return (sz);
    }
    else
    {
        return 0;
    }
}

// Returns the last error generated during script evaluation (if any)
SLAPI unsigned int SmGetError(void *smId)
{
    ScriptMachineData *smd = (ScriptMachineData *)smId;
    return (unsigned int)smd->sm->getError();
}

#endif // LIGHT
