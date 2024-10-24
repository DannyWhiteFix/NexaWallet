// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_SCRIPT_INTERPRETER_H
#define NEXA_SCRIPT_INTERPRETER_H

#include "consensus/grouptokens.h"
#include "primitives/transaction.h"
#include "script/bignum.h"
#include "script/script_flags.h"
#include "script/stackitem.h"
#include "script_error.h"

#include <stdint.h>
#include <string>
#include <vector>

class CPubKey;
class CScript;
class CTransaction;
class uint256;

#define NUM_SCRIPT_REGISTERS 32

/** Signature types */
enum
{
    // Removed in Nexa: SIGTYPE_ECDSA = 0,
    SIGTYPE_SCHNORR = 1,
};


class BaseSignatureChecker;

bool CheckSignatureEncoding(const std::vector<unsigned char> &vchSig, unsigned int flags, ScriptError *serror);

/**
 * Check that the signature provided on some data is properly encoded.
 * Signatures passed to OP_CHECKDATASIG and its verify variant must be checked
 * using this function.
 */
bool CheckDataSignatureEncoding(const std::vector<uint8_t> &vchSig, uint32_t flags, ScriptError *serror);

// WARNING:
// SIGNATURE_HASH_ERROR represents the special value of uint256(1) that is used by the legacy SignatureHash
// function to signal errors in calculating the signature hash. This export is ONLY meant to check for the
// consensus-critical oddities of the legacy signature validation code and SHOULD NOT be used to signal
// problems during signature hash calculations for any current BCH signature hash functions!
extern const uint256 SIGNATURE_HASH_ERROR;


class BaseSignatureChecker
{
protected:
    unsigned int nFlags = SCRIPT_ENABLE_SIGHASH_FORKID;

public:
    //! Verifies a signature given the pubkey, signature and sighash
    virtual bool VerifySignature(const std::vector<uint8_t> &vchSig,
        const CPubKey &vchPubKey,
        const uint256 &sighash) const;

    //! Verifies a signature given the pubkey, signature, script, and transaction (member var)
    virtual bool CheckSig(const std::vector<uint8_t> &scriptSig,
        const std::vector<uint8_t> &vchPubKey,
        const CScript &scriptCode) const
    {
        return false;
    }

    virtual bool CheckLockTime(const CScriptNum &nLockTime) const { return false; }
    virtual bool CheckSequence(const CScriptNum &nSequence) const { return false; }
    virtual ~BaseSignatureChecker() {}

    unsigned int flags() const { return nFlags; }
};

class TransactionSignatureChecker : public BaseSignatureChecker
{
protected:
    const CTransaction *txTo = nullptr;
    unsigned int nIn = 0;
    mutable size_t nBytesHashed = 0;
    mutable size_t nSigops = 0;

public:
    TransactionSignatureChecker(const CTransaction *txToIn,
        unsigned int nInIn,
        unsigned int flags = SCRIPT_ENABLE_SIGHASH_FORKID)
        : txTo(txToIn), nIn(nInIn), nBytesHashed(0), nSigops(0)
    {
        nFlags = flags;
    }
    TransactionSignatureChecker() {} // 2 phase initialization
    void Init(const CTransaction *txToIn, unsigned int nInIn, unsigned int flags = SCRIPT_ENABLE_SIGHASH_FORKID)
    {
        txTo = txToIn;
        nIn = nInIn;
        nFlags = flags;
        nBytesHashed = 0;
        nSigops = 0;
    }

    bool CheckSig(const std::vector<uint8_t> &scriptSig,
        const std::vector<uint8_t> &vchPubKey,
        const CScript &scriptCode) const;
    bool CheckLockTime(const CScriptNum &nLockTime) const;
    bool CheckSequence(const CScriptNum &nSequence) const;
    size_t GetBytesHashed() const { return nBytesHashed; }
    size_t GetNumSigops() const { return nSigops; }
};

class MutableTransactionSignatureChecker : public TransactionSignatureChecker
{
private:
    const CTransaction txTo;

public:
    MutableTransactionSignatureChecker(const CMutableTransaction *txToIn,
        unsigned int nInIn,
        const CAmount &amountIn,
        unsigned int flags = SCRIPT_ENABLE_SIGHASH_FORKID)
        : TransactionSignatureChecker(), txTo(*txToIn)
    {
        Init(&txTo, nInIn, flags);
    }
};

typedef StackItem StackDataType;
typedef std::vector<StackItem> Stack;

/** All external state that a script is allowed to access must be provided here.
 */
class ScriptImportedState
{
public:
    const BaseSignatureChecker *checker = nullptr;
    CTransactionRef tx = nullptr;
    std::vector<CTxOut> spentCoins;
    unsigned int nIn = (unsigned int)-1;
    CAmount txInAmount = -1;
    CAmount txOutAmount = -1;
    CAmount fee = -1;
    GroupBalanceMapRef groupState = nullptr;

    /** Use this constructor to build the full state needed for the script interpreter */
    ScriptImportedState(const BaseSignatureChecker *c,
        CTransactionRef t,
        const CValidationState &validationData,
        const std::vector<CTxOut> &coins,
        unsigned int inputIdx);

    ScriptImportedState() {}
    ScriptImportedState(const BaseSignatureChecker *c) : checker(c) {}
};

class ScriptImportedStateSig : public ScriptImportedState
{
public:
    TransactionSignatureChecker tsc;

    ScriptImportedStateSig(const CMutableTransaction *txToIn,
        unsigned int inIndex,
        const CAmount &amountObsolete,
        unsigned int flags = SCRIPT_ENABLE_SIGHASH_FORKID)
    {
        tx = MakeTransactionRef(*txToIn);
        nIn = inIndex;
        tsc.Init(&(*tx), nIn, flags);
        checker = &tsc;
    }
    ScriptImportedStateSig(const CTransaction *txToIn,
        unsigned int inIndex,
        const CAmount &amountObsolete,
        unsigned int flags = SCRIPT_ENABLE_SIGHASH_FORKID)
    {
        tx = MakeTransactionRef(*txToIn);
        nIn = inIndex;
        tsc.Init(&(*tx), nIn, flags);
        checker = &tsc;
    }
    ScriptImportedStateSig(const CTransactionRef txToIn,
        unsigned int inIndex,
        const CAmount &amountObsolete,
        unsigned int flags = SCRIPT_ENABLE_SIGHASH_FORKID)
    {
        tx = txToIn;
        nIn = inIndex;
        tsc.Init(&(*tx), nIn, flags);
        checker = &tsc;
    }
};

/**
 * Class that keeps track of number of signature operations
 * and bytes hashed to compute signature hashes.
 */
class ScriptMachineResourceTracker
{
public:
    /** 2020-05-15 sigchecks consensus rule */
    uint64_t consensusSigCheckCount = 0;
    /** Number of instructions executed */
    unsigned int nOpCount = 0;
    /** Number of op_execs executed */
    unsigned int nOpExec = 0;

    /** Maximum number of bytes used in both stacks */
    unsigned int maxStackBytes = 0;

    ScriptMachineResourceTracker() {}
    /** Combine the results of this tracker and another tracker.
        @param parentsCurrentStackUse: you may provide a baseline of stack use which gets added to the stats to
                  determine total use.
     */
    void update(const ScriptMachineResourceTracker &stats, unsigned int parentsCurrentStackUse = 0)
    {
        consensusSigCheckCount += stats.consensusSigCheckCount;
        nOpCount += stats.nOpCount;
        nOpExec += stats.nOpExec;
        // Update the max used stack bytes if it exceeds ours (plus a baseline use)
        unsigned int totalUse = parentsCurrentStackUse + stats.maxStackBytes;
        if (maxStackBytes < totalUse)
            maxStackBytes = totalUse;
    }

    /** Set all tracked values to zero */
    void clear(void)
    {
        consensusSigCheckCount = 0;
        nOpCount = 0;
        nOpExec = 0;
    }
};

class ScriptMachine
{
protected:
    unsigned int flags;
    Stack stack;
    Stack altstack;
    unsigned int stackSize = 0;
    unsigned int altStackSize = 0;
    const CScript *script;
    ScriptError error = SCRIPT_ERR_INITIAL_STATE;

    CScript::const_iterator pc;
    CScript::const_iterator pbegin;
    CScript::const_iterator pend;
    CScript::const_iterator pbegincodehash;

    /** Maximum number of instructions to be executed -- script will abort with error if this number is exceeded */
    unsigned int maxOps;
    /** Maximum number of 2020-05-15 sigchecks allowed -- script will abort with error if this number is exceeded */
    unsigned int maxConsensusSigOps;

    /** Maximum combined size of both stacks allowed -- script will abort with error if this number is exceeded */
    unsigned int maxStackUse = 0;

    /** Maximum combined number of elements in both stacks -- script will abort with error if this number is exceeded */
    unsigned int maxStackItems = 0;

    /** Tracks current values of script execution metrics */
    ScriptMachineResourceTracker stats;

private:
    /** A data type to abstract out the condition stack during script execution.
     *
     * Conceptually it acts like a vector of booleans, one for each level of nested
     * IF/THEN/ELSE, indicating whether we're in the active or inactive branch of
     * each.
     *
     * The elements on the stack cannot be observed individually; we only need to
     * expose whether the stack is empty and whether or not any false values are
     * present at all. To implement OP_ELSE, a toggle_top modifier is added, which
     * flips the last value without returning it.
     *
     * This uses an optimized implementation that does not materialize the
     * actual stack. Instead, it just stores the size of the would-be stack,
     * and the position of the first false value in it.
     */
    class ConditionStack
    {
    private:
        //! A constant for m_first_false_pos to indicate there are no falses.
        static constexpr uint32_t NO_FALSE = std::numeric_limits<uint32_t>::max();

        //! The size of the implied stack.
        uint32_t m_stack_size = 0;
        //! The position of the first false value on the implied stack, or NO_FALSE if all true.
        uint32_t m_first_false_pos = NO_FALSE;

    public:
        bool empty() { return m_stack_size == 0; }
        bool all_true() { return m_first_false_pos == NO_FALSE; }
        void clear()
        {
            m_stack_size = 0;
            m_first_false_pos = NO_FALSE;
        }
        void push_back(bool f)
        {
            if (m_first_false_pos == NO_FALSE && !f)
            {
                // The stack consists of all true values, and a false is added.
                // The first false value will appear at the current size.
                m_first_false_pos = m_stack_size;
            }
            ++m_stack_size;
        }
        void pop_back()
        {
            assert(m_stack_size > 0);
            --m_stack_size;
            if (m_first_false_pos == m_stack_size)
            {
                // When popping off the first false value, everything becomes true.
                m_first_false_pos = NO_FALSE;
            }
        }
        void toggle_top()
        {
            assert(m_stack_size > 0);
            if (m_first_false_pos == NO_FALSE)
            {
                // The current stack is all true values; the first false will be the top.
                m_first_false_pos = m_stack_size - 1;
            }
            else if (m_first_false_pos == m_stack_size - 1)
            {
                // The top is the first false value; toggling it will make everything true.
                m_first_false_pos = NO_FALSE;
            }
            else
            {
                // There is a false value, but not on top. No action is needed as toggling
                // anything but the first false value is unobservable.
            }
        }
    };

protected:
    ConditionStack vfExec;
    // note - default constructor is used in an array, all registers get initialised to
    // have a StackItem() : type(StackElementType::VCH), vch(0) {}
    std::array<StackItem, NUM_SCRIPT_REGISTERS> arrRegisters;

public:
    /** All the external information that this virtual machine is allowed to access */
    const ScriptImportedState &sis;

    /** Bignum modulo (every bignum operation is modulo this number */
    BigNum bigNumModulo = 0x10000000000000000_BN; // 64 bit magnitude

    /** The maximum script size executable in the virtual machine */
    uint64_t maxScriptSize = MAX_SCRIPT_SIZE;

    ScriptMachine(const ScriptMachine &from)
        : pc(from.pc), pbegin(from.pbegin), pend(from.pend), pbegincodehash(from.pbegincodehash), sis(from.sis)
    {
        flags = from.flags;
        stack = from.stack;
        stackSize = from.stackSize;
        altstack = from.altstack;
        altStackSize = from.altStackSize;
        script = from.script;
        error = from.error;
        vfExec = from.vfExec;
        maxOps = from.maxOps;
        maxConsensusSigOps = from.maxConsensusSigOps;
        maxStackUse = from.maxStackUse;
        maxStackItems = from.maxStackItems;
        bigNumModulo = from.bigNumModulo;
        maxScriptSize = from.maxScriptSize;
        stats = from.stats;
    }

    ScriptMachine(unsigned int _flags, const ScriptImportedState &_sis, unsigned int _maxOps, unsigned int _maxSigOps)
        : flags(_flags), script(nullptr), pc(CScript().end()), pbegin(CScript().end()), pend(CScript().end()),
          pbegincodehash(CScript().end()), maxOps(_maxOps), maxConsensusSigOps(_maxSigOps), sis(_sis)
    {
        if (flags & SCRIPT_ENFORCE_STACK_TOTAL)
        {
            maxStackUse = MAX_SCRIPT_STACK_SIZE;
            maxStackItems = MAX_STACK_ITEMS;
        }
        else
        {
            maxStackUse = std::numeric_limits<unsigned int>::max();
            maxStackItems = GENESIS_MAX_STACK_ITEMS;
        }
    }

    const VchType &stacktop(int i);

    // Modifiable stack element: when using this API, you MUST NOT change the size of the item!
    // i must be a negative offset from the stack top, where -1 references the top element.
    // The caller must verify that i is within the stack bounds.
    VchType &mstacktop(int i);

    /** get altstack element (if it is a VchType).  This API is deprecated and should be replaced with
     altstackItemAt.
     i must be a negative offset from the stack top, where -1 references the top element.
     The caller must verify that i is within the stack bounds.
    */
    const VchType &altstacktop(int i);

    /** Get the item from a position indexed in negative numbers from the top of the stack
        @param i Should be a negative number where -1 is the top of the stack
        @returns StackItem object
    */
    const StackItem &stackItemAt(int i);

    /** Get a mutable reference to the item from a position indexed in negative numbers from the top of the stack.
        **DO NOT CHANGE the total size of the stack when using this API.**
        This API is dangerous, and only exposed to optimize specific opcodes (like stack position swaps).
        @param i Should be a negative number where -1 is the top of the stack
        @returns StackItem object
    */
    StackItem &mstackItemAt(int i);


    /** Get the item from a position indexed in negative numbers from the top of the altstack
        @param i Should be a negative number where -1 is the top of the stack
        @returns StackItem object
    */
    const StackItem &altstackItemAt(int i);

    // How many OP_EXECs have been called recursively
    unsigned int execDepth = 0;

    // Execute the passed script starting at the current machine state (stack and altstack are not cleared).
    bool Eval(const CScript &_script);

    // Start a stepwise execution of a script, starting at the current machine state
    // If BeginStep succeeds, you must keep script alive until EndStep() returns
    bool BeginStep(const CScript &_script);
    // Execute the next instruction of a script (you must have previously BeginStep()ed).
    bool Step();
    // Keep stepping until finished, problem or n steps. EndStep() (finish script eval) is NOT called.
    // nsteps default is 2^32-1 (a number bigger than any script will ever be)
    bool Continue(size_t nSteps = 0x7FFFFFFFUL);
    // Modifies the script in-place, by overriding its const designator. Only use during script debugging
    bool ModifyScript(int position, uint8_t *data, size_t dataLength);
    // Do final checks once the script is complete.
    bool EndStep();
    // Return true if there are more steps in this script
    bool isMoreSteps() { return (pc < pend); }
    // Return the current offset from the beginning of the script. -1 if ended
    int getPos();
    // Moves the instruction pointer
    int setPos(size_t offset);

    bool withinStackWidth(unsigned int size) { return ::withinStackWidth(size, flags); }

    // Returns info about the next instruction to be run:
    // first bool is true if the instruction will be executed (false if this is passing across a not-taken branch)
    std::tuple<bool, opcodetype, StackItem, ScriptError> Peek();

    // Remove all items from the altstack
    void ClearAltStack()
    {
        altstack.clear();
        altStackSize = 0;
    }
    // Remove all items from the stack
    void ClearStack()
    {
        stack.clear();
        stackSize = 0;
    }
    /** remove a single item from the top of the stack.  If the stack is empty, std::runtime_error is thrown. */
    void PopStack();
    /** remove a single item negative 1-indexed from the stack top (stack.end() + idx). */
    void EraseStackItemAt(int idx);

    /* Throw an error if the passed item size causes the stack to exceed limits,
       otherwise, update the current values (under the assumption that the caller will place an item
       of the passed size onto the stack when this function is complete).
       Its possible for itemSize to be negative if the caller intends to replace a stack item with a shorter one
    */
    void CheckAndUpdateStackSize(int itemSize);

    /* Push an item to the main stack */
    void PushStack(const StackItem &item);
    /* Push a byte vector to the main stack, given its beginning and end
       (optimization to prevent byte array copies, that replaces emplace_back) */
    void PushStack(const unsigned char *begin, const unsigned char *end);
    /* Push a byte vector to the main stack, given its beginning and end
       (optimization to prevent byte array copies, that replaces emplace_back) */
    void PushStack(const CScript::const_iterator &begin, const CScript::const_iterator &end);
    /** remove a single item from the top of the stack.  If the stack is empty, std::runtime_error is thrown. */
    void PopAltStack();
    /** Push an item to the altstack */
    void PushAltStack(const StackItem &item);

    /** just like std::vector reserve, this function helps efficiency by suggesting how big
        the stack may become, so the underlying data structure can pre-reserve that memory.  */
    void StackReserve(int numItems) { stack.reserve(numItems); }

    /** just like std::vector reserve, this function helps efficiency by suggesting how big
        the stack may become, so the underlying data structure can pre-reserve that memory.  */
    void AltStackReserve(int numItems) { altstack.reserve(numItems); }

    // From a consensus perspective, moving data from one stack to the other takes no temporary space.
    // In practice an embedded, memory sensitive implementation should move just a buffer pointer so it actually
    // will not take extra space.
    void MoveAltToStack()
    {
        if (altstack.empty())
        {
            throw std::runtime_error("ScriptMachine.PopAltStack: stack empty");
        }
        // This is done without calling the Push and Pop member functions so that the
        // stack bytes checks are not done
        auto &elem = altstack.at(altstack.size() - 1);
        int elemSize = elem.size();
        stackSize += elemSize;
        altStackSize -= elemSize;
        stack.push_back(elem);
        altstack.pop_back();
    }

    // From a consensus perspective, moving data from one stack to the other takes no temporary space
    // In practice an embedded, memory sensitive implementation should move just a buffer pointer so it actually
    // will not take extra space.
    void MoveStackToAlt()
    {
        if (stack.empty())
        {
            throw std::runtime_error("ScriptMachine.PopStack: stack empty");
        }
        auto &elem = stack.at(stack.size() - 1);
        int elemSize = elem.size();
        altStackSize += elemSize;
        stackSize -= elemSize;
        altstack.push_back(elem);
        stack.pop_back();
    }

    /** A No-op in release mode, this function executes various internal checks on the script machine and asserts
        if there is a problem.
        It incurs a significant performance penalty.
    */
    void DbgConsistencyCheck();

    /** Reserve capacity in the passed stack, if needed.  Iterators and references MAY be invalidated.  Use this
        function to control when these are invalidated (for example, to avoid invalidation during subsequent
        push_back calls).

        Returns false if stack usage exceeded.
    */
    bool reserveIfNeeded(Stack &s, unsigned int amt)
    {
        const int extra = 10;
        auto curSz = s.size();
        if (curSz + amt > s.capacity())
        {
            s.reserve(curSz + amt + extra);
        }
        return true;
    }

    /** Clear all state except for configuration like maximums, and the imported state (ScriptImportedState).

     */
    void Reset()
    {
        ClearAltStack();
        ClearStack();
        vfExec.clear();
        stats.clear();
        bigNumModulo = 0x10000000000000000_BN;
        execDepth = 0;
        for (auto i = 0; i < NUM_SCRIPT_REGISTERS; i++)
            arrRegisters[i] = StackItem();
        error = SCRIPT_ERR_INITIAL_STATE;
    }

    // Set the main stack to the passed data
    void setStack(const Stack &stk, int newSize = -1)
    {
        if (newSize == -1)
        {
            int count = 0;
            for (auto &item : stk)
            {
                count += item.size();
            }
            newSize = count;
        }
        stack = stk;
        stackSize = newSize;
    }
    // Overwrite a stack entry with the passed data.  0 is the stack top, -1 is a special number indicating to push
    // an item onto the stack top.
    void setStackItem(int idxFromEnd, const StackItem &item)
    {
        if (idxFromEnd == -1)
        {
            PushStack(item);
        }
        else
        {
            // idxFromEnd labels elements in the array backwards.  0 refers to stack[stack.size()-1].
            // So first convert idxFromEnd to indexing from the beginning of the std::vector
            int index = stack.size() - idxFromEnd - 1;
            if ((index >= (int)stack.size()) || (index < 0))
            {
                throw std::runtime_error("ScriptMachine.setStackItem: access beyond the end of the stack");
            }
            // Now grab the item at that index
            StackItem &cur = stack.at(index);
            // Get the sizes of the items that we are removing and adding
            int curSize = cur.size();
            int itemSize = item.size();
            // Check the total based on those sizes
            CheckAndUpdateStackSize(itemSize - curSize);
            // finally replace the item
            stack.at(index) = item;
        }
    }

    // Overwrite an altstack entry with the passed data.  0 is the stack top, -1 is a special number indicating to push
    // the item onto the top.
    void setAltStackItem(int idxFromEnd, const StackItem &item)
    {
        if (idxFromEnd == -1)
        {
            PushAltStack(item);
        }
        else
        {
            // idxFromEnd labels elements in the array backwards.  0 refers to altstack[altstack.size()-1].
            // So first convert idxFromEnd to indexing from the beginning of the std::vector
            int index = altstack.size() - idxFromEnd - 1;
            if ((index >= (int)stack.size()) || (index < 0))
            {
                throw std::runtime_error("ScriptMachine.setAltstackItem: access beyond the end of the altstack");
            }
            // Now grab the item at that index
            StackItem &cur = altstack.at(index);
            // Get the sizes of the items that we are removing and adding
            unsigned int curSize = cur.size();
            unsigned int itemSize = item.size();
            // Check the total based on those sizes
            unsigned int currentTotal = altStackSize + stackSize + itemSize - curSize;
            if (currentTotal > maxStackUse)
            {
                throw std::runtime_error("ScriptMachine.setAltStackItem: stack memory exceeded");
            }
            // Update the stats if we have a new max altstack use
            if (currentTotal > stats.maxStackBytes)
                stats.maxStackBytes = currentTotal;
            // update the total altstack size
            altStackSize += itemSize - curSize;
            // finally replace the item
            altstack.at(index) = item;
        }
    }

    // Load or modify the main stack
    // Stack &modifyStack() { return stack; }
    // Load or modify the alt stack
    // Stack &modifyAltStack() { return altstack; }
    // Set the alt stack to the passed data
    void setAltStack(const Stack &stk, int newSize = -1)
    {
        if (newSize == -1)
        {
            int count = 0;
            for (auto &item : stk)
            {
                count += item.size();
            }
            newSize = count;
        }

        altstack = stk;
        altStackSize = newSize;
    }
    // Get the main stack
    const Stack &getStack() { return stack; }
    // Get the alt stack
    const Stack &getAltStack() { return altstack; }
    // Get any error that may have occurred
    const ScriptError &getError() { return error; }
    // Return the number of instructions executed since the last Reset()
    unsigned int getOpCount() { return stats.nOpCount; }
    /** Return execution statistics */
    const ScriptMachineResourceTracker &getStats() { return stats; }

    friend bool VerifyTemplate(const CScript &templat,
        const CScript &constraint,
        const CScript &satisfier,
        unsigned int flags,
        unsigned int maxOps,
        unsigned int maxActualSigops,
        const ScriptImportedState &sis,
        ScriptError *serror,
        ScriptMachineResourceTracker *tracker);

    bool EvalParseBytecode(int64_t first, int64_t count, const CScript &pscript);
    bool EvalParseBytecode(int64_t first,
        int64_t count,
        const CScript &pscript,
        CScript::const_iterator &pc,
        const CScript::const_iterator &end);
    bool EvalParseCanonicalLockingBytecode(int64_t first, int64_t count, const CScript &pscript);
    bool EvalParseUnlockingTemplateBytecode(int64_t first,
        int64_t count,
        const CScript &unlockingScript,
        const CScript &constraintScript);
};

bool EvalScript(Stack &stack,
    const CScript &script,
    unsigned int flags,
    unsigned int maxOps,
    const ScriptImportedState &sis,
    ScriptError *error = nullptr);

bool VerifyScript(const CScript &scriptSig,
    const CScript &scriptPubKey,
    unsigned int flags,
    const ScriptImportedState &sis,
    ScriptError *error = nullptr,
    ScriptMachineResourceTracker *tracker = nullptr);

bool VerifySatoScript(const CScript &scriptSig,
    const CScript &scriptPubKey,
    unsigned int flags,
    unsigned int maxOps,
    const ScriptImportedState &sis,
    ScriptError *error = nullptr,
    ScriptMachineResourceTracker *tracker = nullptr);

bool VerifyTemplate(const CScript &templat,
    const CScript &constraint,
    const CScript &satisfier,
    unsigned int flags,
    unsigned int maxOps,
    unsigned int maxActualSigops,
    const ScriptImportedState &sis,
    ScriptError *serror,
    ScriptMachineResourceTracker *tracker);

// string prefixed to data when validating signed messages via RPC call.  This ensures
// that the signature was intended for use on this blockchain.
extern const std::string strMessageMagic;

bool CheckPubKeyEncoding(const std::vector<uint8_t> &vchSig, unsigned int flags, ScriptError *serror);

extern uint64_t maxSatoScriptOps;
extern uint64_t maxScriptTemplateOps;

#endif // NEXA_SCRIPT_INTERPRETER_H
