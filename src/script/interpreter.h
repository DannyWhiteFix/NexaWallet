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
#include "script/stackitem.h"
#include "script_error.h"

#include <stdint.h>
#include <string>
#include <vector>

class CPubKey;
class CScript;
class CTransaction;
class uint256;

/** Signature types */
enum
{
    // Removed in Nexa: SIGTYPE_ECDSA = 0,
    SIGTYPE_SCHNORR = 1,
};

/** Script verification flags */
enum
{
    SCRIPT_VERIFY_NONE = 0,

    // Evaluate P2SH subscripts (softfork safe, BIP16).
    // Note: The Segwit Recovery feature is an exception to P2SH
    SCRIPT_VERIFY_P2SH = (1U << 0),

    // Passing a non-strict-DER signature to a checksig operation causes script failure.
    // Evaluating a pubkey that is not (0x04 + 64 bytes) or (0x02 or 0x03 + 32 bytes) by checksig causes script failure.
    // (softfork safe, but not used or intended as a consensus rule).
    SCRIPT_VERIFY_STRICTENC = (1U << 1),

    // Passing a non-strict-DER signature to a checksig operation causes script failure
    // (BIP62 rule 1)
    SCRIPT_VERIFY_DERSIG = (1U << 2),

    // Passing a non-strict-DER signature or one with S > order/2 to a checksig operation
    // causes script failure
    // (BIP62 rule 5)
    SCRIPT_VERIFY_LOW_S = (1U << 3),

    // Using a non-push operator in the scriptSig causes script failure
    // (BIP62 rule 2).
    SCRIPT_VERIFY_SIGPUSHONLY = (1U << 5),

    // Require minimal encodings for all push operations (OP_0... OP_16, OP_1NEGATE where possible, direct
    // pushes up to 75 bytes, OP_PUSHDATA up to 255 bytes, OP_PUSHDATA2 for anything larger). Evaluating
    // any other push causes the script to fail (BIP62 rule 3).
    // In addition, whenever a stack element is interpreted as a number, it must be of minimal length (BIP62 rule 4).
    SCRIPT_VERIFY_MINIMALDATA = (1U << 6),

    // Discourage use of NOPs reserved for upgrades (NOP1-10)
    //
    // Provided so that nodes can avoid accepting or mining transactions
    // containing executed NOP's whose meaning may change after a soft-fork,
    // thus rendering the script invalid; with this flag set executing
    // discouraged NOPs fails the script. This verification flag will never be
    // a mandatory flag applied to scripts in a block. NOPs that are not
    // executed, e.g.  within an unexecuted IF ENDIF block, are *not* rejected.
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS = (1U << 7),

    // Require that only a single stack element remains after evaluation. This changes the success criterion from
    // "At least one stack element must remain, and when interpreted as a boolean, it must be true" to
    // "Exactly one stack element must remain, and when interpreted as a boolean, it must be true".
    // (softfork safe, BIP62 rule 6)
    // Note: CLEANSTACK should never be used without P2SH.
    // Note: The Segwit Recovery feature is an exception to CLEANSTACK
    SCRIPT_VERIFY_CLEANSTACK = (1U << 8),

    // Verify CHECKLOCKTIMEVERIFY
    //
    // See BIP65 for details.
    SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY = (1U << 9),

    // support CHECKSEQUENCEVERIFY opcode
    //
    // See BIP112 for details
    SCRIPT_VERIFY_CHECKSEQUENCEVERIFY = (1U << 10),

    // Require the argument of OP_IF/NOTIF to be exactly 0x01 or empty vector
    //
    SCRIPT_VERIFY_MINIMALIF = (1U << 13),

    // Signature(s) must be empty vector if an CHECK(MULTI)SIG operation failed
    SCRIPT_VERIFY_NULLFAIL = (1U << 14),

    // Public keys in scripts must be compressed
    //
    SCRIPT_VERIFY_COMPRESSED_PUBKEYTYPE = (1U << 15),

    // Do we accept signature using SIGHASH_FORKID
    //
    SCRIPT_ENABLE_SIGHASH_FORKID = (1U << 16),

    // Count sigops for OP_CHECKDATASIG and variant. The interpreter treats
    // OP_CHECKDATASIG(VERIFY) as always valid, this flag only affects sigops
    // counting.
    //
    SCRIPT_ENABLE_CHECKDATASIG = (1U << 18),

    // Flag which determines if the script interpreter should allow
    // 64-bit integer arithmetic and the return of OP_MUL or use the previous
    // semantics.
    SCRIPT_ALLOW_64_BIT_INTEGERS = (1U << 24),

    // Flag which determines if the script interpretor should allow
    // Native Introspection opcodes.
    SCRIPT_ALLOW_NATIVE_INTROSPECTION = (1U << 25),
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

    ScriptMachineResourceTracker() {}
    /** Combine the results of this tracker and another tracker */
    void update(const ScriptMachineResourceTracker &stats)
    {
        consensusSigCheckCount += stats.consensusSigCheckCount;
        nOpCount += stats.nOpCount;
        nOpExec += stats.nOpExec;
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
        altstack = from.altstack;
        script = from.script;
        error = from.error;
        vfExec = from.vfExec;
        maxOps = from.maxOps;
        maxConsensusSigOps = from.maxConsensusSigOps;
        stats = from.stats;
    }

    ScriptMachine(unsigned int _flags, const ScriptImportedState &_sis, unsigned int _maxOps, unsigned int _maxSigOps)
        : flags(_flags), script(nullptr), pc(CScript().end()), pbegin(CScript().end()), pend(CScript().end()),
          pbegincodehash(CScript().end()), maxOps(_maxOps), maxConsensusSigOps(_maxSigOps), sis(_sis)
    {
    }

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

    // Returns info about the next instruction to be run:
    // first bool is true if the instruction will be executed (false if this is passing across a not-taken branch)
    std::tuple<bool, opcodetype, StackItem, ScriptError> Peek();

    // Remove all items from the altstack
    void ClearAltStack() { altstack.clear(); }
    // Remove all items from the stack
    void ClearStack() { stack.clear(); }
    /** remove a single item from the top of the stack.  If the stack is empty, std::runtime_error is thrown. */
    void PopStack()
    {
        if (stack.empty())
        {
            throw std::runtime_error("ScriptMachine.PopStack: stack empty");
        }
        stack.pop_back();
    }

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

    // clear all state except for configuration like maximums
    void Reset()
    {
        altstack.clear();
        stack.clear();
        vfExec.clear();
        stats.clear();
    }

    // Set the main stack to the passed data
    void setStack(const Stack &stk) { stack = stk; }
    // Overwrite a stack entry with the passed data.  0 is the stack top, -1 is a special number indicating to push
    // an item onto the stack top.
    void setStackItem(int idx, const StackItem &item)
    {
        if (idx == -1)
        {
            stack.push_back(item);
        }
        else
        {
            stack[stack.size() - idx - 1] = item;
        }
    }

    // Overwrite an altstack entry with the passed data.  0 is the stack top, -1 is a special number indicating to push
    // the item onto the top.
    void setAltStackItem(int idx, const StackItem &item)
    {
        if (idx == -1)
        {
            altstack.push_back(item);
        }
        else
        {
            altstack[altstack.size() - idx - 1] = item;
        }
    }

    // Load or modify the main stack
    Stack &modifyStack() { return stack; }
    // Load or modify the alt stack
    Stack &modifyAltStack() { return stack; }
    // Set the alt stack to the passed data
    void setAltStack(const Stack &stk) { altstack = stk; }
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

// Applies the specifier to the data in sis to generate items that are pushed onto the passed stack.
ScriptError EvalPushTxState(const VchType &specifier, const ScriptImportedState &sis, Stack &stack);

extern uint64_t maxSatoScriptOps;
extern uint64_t maxScriptTemplateOps;

#endif // NEXA_SCRIPT_INTERPRETER_H
