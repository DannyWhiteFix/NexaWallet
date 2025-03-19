// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef LIBNEXA_SCRIPTMACHINE_H
#define LIBNEXA_SCRIPTMACHINE_H

#include "libnexa_common.h"

#ifndef LIGHT // The script interpreter is not available in light clients

/*
Since the ScriptMachine is often going to be initialized, called and destructed within a single stack frame, it
does not make copies of the data it is using.  But higher-level language and debugging interaction use the
ScriptMachine across stack frames.  Therefore it is necessary to create a class to hold all of this data on behalf
of the ScriptMachine.
 */
class ScriptMachineData
{
public:
    ScriptMachineData() : sm(nullptr), tx(nullptr), sis(nullptr), script(nullptr) {}
    ScriptMachine *sm;

    CTransactionRef tx;
    std::shared_ptr<BaseSignatureChecker> checker;
    std::shared_ptr<ScriptImportedState> sis;
    std::shared_ptr<CScript> script;

    ~ScriptMachineData()
    {
        if (sm)
        {
            delete sm;
            sm = nullptr;
        }
    }
};

// Create a ScriptMachine with no transaction context -- useful for tests and debugging
// This ScriptMachine can't CHECKSIG or CHECKSIGVERIFY
SLAPI void *CreateNoContextScriptMachine(unsigned int flags);

// Create a ScriptMachine operating in the context of a particular transaction and input.
// The transaction, input index, and input amount are used in CHECKSIG and CHECKSIGVERIFY to generate the hash that
// the signature validates.
void *CreateScriptMachine(unsigned int flags,
    unsigned int inputIdx,
    unsigned char *txData,
    int txbuflen,
    unsigned char *coinData,
    int coinbuflen,
    std::string *errorDetails);

// Create a ScriptMachine operating in the context of a particular transaction and input.
// The transaction, input index, and input amount are used in CHECKSIG and CHECKSIGVERIFY to generate the hash that
// the signature validates.
SLAPI void *CreateScriptMachine(unsigned int flags,
    unsigned int inputIdx,
    unsigned char *txData,
    int txbuflen,
    unsigned char *coinData,
    int coinbuflen);

// Release a ScriptMachine context
SLAPI void SmRelease(void *smId);

// Copy the provided ScriptMachine, returning a new ScriptMachine id that exactly matches the current one
SLAPI void *SmClone(void *smId);

// Evaluate a script within the context of this script machine
SLAPI bool SmEval(void *smId, unsigned char *scriptBuf, unsigned int scriptLen);

// Step-by-step interface: start evaluating a script within the context of this script machine
SLAPI bool SmBeginStep(void *smId, unsigned char *scriptBuf, unsigned int scriptLen);

// Step-by-step interface: execute the next instruction in the script
SLAPI unsigned int SmStep(void *smId);

// Step-by-step interface: get the current position in this script, specified in bytes offset from the script start
SLAPI int SmPos(void *smId);

// Step-by-step interface: End script evaluation
SLAPI bool SmEndStep(void *smId);

// Revert the script machine to initial conditions
SLAPI void SmReset(void *smId);

// Get a stack item, 0 = stack, 1 = altstack,  pass a buffer at least 520 bytes in size
// returns length of the item or -1 if no item.  0 is the stack top
SLAPI void SmSetStackItem(void *smId,
    unsigned int stack,
    int index,
    StackElementType t,
    const unsigned char *value,
    unsigned int valsize);

// Get a stack item, 0 = stack, 1 = altstack,  pass a buffer at least 520 bytes in size
// returns length of the item or -1 if no item.  0 is the stack top
SLAPI int SmGetStackItem(void *smId,
    unsigned int stack,
    unsigned int index,
    StackElementType *t,
    unsigned char *result);

// Returns the last error generated during script evaluation (if any)
SLAPI unsigned int SmGetError(void *smId);

#endif // LIGHT

#endif // LIBNEXA_SCRIPTMACHINE_H
