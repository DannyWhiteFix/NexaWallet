// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "interpreter.h"

#include "bignum.h"
#include "bitfield.h"
#include "bitmanip.h"
#include "consensus/grouptokens.h"
#include "consensus/validation.h"
#include "crypto/ripemd160.h"
#include "crypto/sha1.h"
#include "crypto/sha256.h"
#include "primitives/transaction.h"
#include "pubkey.h"
#include "script/pushtxstate.h"
#include "script/script.h"
#include "script/script_error.h"
#include "script/scripttemplate.h"
#include "sighashtype.h"
#include "uint256.h"
#include "util.h"

uint64_t maxSatoScriptOps = MAX_OPS_PER_SCRIPT;
uint64_t maxScriptTemplateOps = MAX_OPS_PER_SCRIPT_TEMPLATE;

/** Implements script binary arithmetic and comparison opcodes that use BigNums.
    Declared here because its only needed in the interpreter even though it is implemented in BigNum.cpp
*/
bool BigNumScriptOp(BigNum &bn,
    opcodetype opcode,
    const BigNum &bn1,
    const BigNum &bn2,
    const BigNum &bmd,
    ScriptError *serror);

const std::string strMessageMagic = "Bitcoin Signed Message:\n";

using namespace std;

typedef vector<uint8_t> valtype;

ScriptImportedState::ScriptImportedState(const BaseSignatureChecker *c,
    CTransactionRef t,
    const CValidationState &validationData,
    const std::vector<CTxOut> &coins,
    unsigned int inputIdx)
    : checker(c), tx(t), spentCoins(coins), nIn(inputIdx)
{
    txInAmount = validationData.inAmount;
    txOutAmount = validationData.outAmount;
    fee = validationData.fee;
    groupState = validationData.groupState;
}

bool CastToBool(const valtype &vch)
{
    for (size_t i = 0; i < vch.size(); i++)
    {
        if (vch[i] != 0)
        {
            // Can be negative zero
            if (i == vch.size() - 1 && vch[i] == 0x80)
            {
                return false;
            }
            return true;
        }
    }
    return false;
}

bool CastToBool(const StackItem &si)
{
    if (si.isBigNum()) // A bignum is true if not zero
    {
        return !(si.num() == (long int)0);
    }
    else
    {
        return CastToBool(si.data());
    }
    return false;
}

/**
 * Script is a stack machine (like Forth) that evaluates a predicate
 * returning a bool indicating valid or not.  There are no loops.
 */

#if 0
static void CleanupScriptCode(CScript &scriptCode, const std::vector<uint8_t> &vchSig, uint32_t flags)
{
    // Drop the signature in scripts when SIGHASH_FORKID is not used.
    SigHashType sigHashType(vchSig);
    if (!(flags & SCRIPT_ENABLE_SIGHASH_FORKID) || sigHashType.isBtc())
    {
        scriptCode.FindAndDelete(CScript(vchSig));
    }
}
#endif

bool static IsCompressedOrUncompressedPubKey(const valtype &vchPubKey)
{
    if (vchPubKey.size() < CPubKey::COMPRESSED_PUBLIC_KEY_SIZE)
    {
        //  Non-canonical public key: too short
        return false;
    }
    if (vchPubKey[0] == 0x04)
    {
        if (vchPubKey.size() != CPubKey::PUBLIC_KEY_SIZE)
        {
            //  Non-canonical public key: invalid length for uncompressed key
            return false;
        }
    }
    else if (vchPubKey[0] == 0x02 || vchPubKey[0] == 0x03)
    {
        if (vchPubKey.size() != 33)
        {
            //  Non-canonical public key: invalid length for compressed key
            return false;
        }
    }
    else
    {
        //  Non-canonical public key: neither compressed nor uncompressed
        return false;
    }
    return true;
}

static bool IsCompressedPubKey(const valtype &vchPubKey)
{
    if (vchPubKey.size() != CPubKey::COMPRESSED_PUBLIC_KEY_SIZE)
    {
        //  Non-canonical public key: invalid length for compressed key
        return false;
    }
    if (vchPubKey[0] != 0x02 && vchPubKey[0] != 0x03)
    {
        //  Non-canonical public key: invalid prefix for compressed key
        return false;
    }
    return true;
}


static bool CheckSignatureEncodingSigHashChoice(const vector<unsigned char> &vchSig,
    unsigned int flags,
    ScriptError *serror,
    const bool check_sighash)
{
    size_t sigSize = vchSig.size();
    // Empty signature. Not strictly DER encoded, but allowed to provide a
    // compact way to provide an invalid signature for use with CHECK(MULTI)SIG
    if (sigSize == 0)
    {
        return true;
    }

    // Schnorr signatures must be 64 bytes plus the sighashtype (if the caller left that in vchSig)
    if ((!check_sighash) && (sigSize != 64))
        set_error(serror, SCRIPT_ERR_SIG_NONSCHNORR);

    if ((sigSize < 64) || (sigSize > 64 + SigHashType::MAX_LEN))
        return set_error(serror, SCRIPT_ERR_SIG_NONSCHNORR);

    if (check_sighash)
    {
        SigHashType sighashtype = SigHashType(vchSig);
        if (!sighashtype.isDefined())
            return set_error(serror, SCRIPT_ERR_SIG_HASHTYPE);
    }
    return true;
}


// For CHECKSIG etc.
bool CheckSignatureEncoding(const vector<unsigned char> &vchSig, unsigned int flags, ScriptError *serror)
{
    return CheckSignatureEncodingSigHashChoice(vchSig, flags, serror, true);
}

// For CHECKDATASIG / CHECKDATASIGVERIFY
bool CheckDataSignatureEncoding(const valtype &vchSig, uint32_t flags, ScriptError *serror)
{
    return CheckSignatureEncodingSigHashChoice(vchSig, flags, serror, false);
}

/**
 * Check that the signature provided to authenticate a transaction is properly
 * encoded Schnorr signature (or null). Signatures passed to the new-mode
 * OP_CHECKMULTISIG and its verify variant must be checked using this function.
 */
static bool CheckTransactionSchnorrSignatureEncoding(const valtype &vchSig, uint32_t flags, ScriptError *serror)
{
    // Since we only accept Schnorr sigs, this is a pass through
    return CheckSignatureEncodingSigHashChoice(vchSig, flags, serror, true);
}

bool CheckPubKeyEncoding(const valtype &vchPubKey, unsigned int flags, ScriptError *serror)
{
    if ((flags & SCRIPT_VERIFY_STRICTENC) != 0 && !IsCompressedOrUncompressedPubKey(vchPubKey))
    {
        return set_error(serror, SCRIPT_ERR_PUBKEYTYPE);
    }

    // Only compressed keys are accepted when
    // SCRIPT_VERIFY_COMPRESSED_PUBKEYTYPE is enabled.
    if (flags & SCRIPT_VERIFY_COMPRESSED_PUBKEYTYPE && !IsCompressedPubKey(vchPubKey))
    {
        return set_error(serror, SCRIPT_ERR_NONCOMPRESSED_PUBKEY);
    }
    return true;
}

static inline bool IsOpcodeDisabled(opcodetype opcode, uint32_t flags)
{
    switch (opcode)
    {
    case OP_2MUL:
    case OP_2DIV:
    case OP_INVERT:
        // disabled opcodes
        return true;
    default:
        break;
    }
    return false;
}

bool EvalScript(Stack &stack,
    const CScript &script,
    unsigned int flags,
    unsigned int maxOps,
    const ScriptImportedState &sis,
    ScriptError *serror)
{
    ScriptMachine sm(flags, sis, maxOps, 0xffffffff);
    sm.setStack(stack);
    bool result = sm.Eval(script);
    stack = sm.getStack();
    if (serror)
    {
        *serror = sm.getError();
    }
    return result;
}


static const auto snZero = CScriptNum::fromIntUnchecked(0);
// put them back if used
// static const auto snOne = CScriptNum::fromIntUnchecked(1);
// static const auto snFalse = CScriptNum::fromIntUnchecked(0);
// static const auto snTrue = CScriptNum::fromIntUnchecked(1);

static const StackItem vchFalse(VchStack, 0);
static const StackItem vchZero(VchStack, 0);
static const StackItem vchTrue(VchStack, 1, 1);

// Returns info about the next instruction to be run
std::tuple<bool, opcodetype, StackItem, ScriptError> ScriptMachine::Peek()
{
    ScriptError err = SCRIPT_ERR_OK;
    opcodetype opcode;
    StackItem vchPushValue;
    auto oldpc = pc;
    if (!script->GetOp(pc, opcode, vchPushValue))
    {
        LOG(SCRIPT, "Peek GetOp failed at offset %d", pc - pbegin);
        set_error(&err, SCRIPT_ERR_BAD_OPCODE);
    }
    else if (!withinStackWidth(vchPushValue.size()))
        set_error(&err, SCRIPT_ERR_PUSH_SIZE);

    pc = oldpc;
    bool fExec = vfExec.all_true();
    return std::tuple<bool, opcodetype, StackItem, ScriptError>(fExec, opcode, vchPushValue, err);
}


bool ScriptMachine::BeginStep(const CScript &_script)
{
    script = &_script;
    pc = pbegin = script->begin();
    pend = script->end();
    pbegincodehash = pc;

    stats.nOpCount = 0;
    vfExec.clear();

    set_error(&error, SCRIPT_ERR_INITIAL_STATE);
    if (script->size() > maxScriptSize)
    {
        script = nullptr;
        return set_error(&error, SCRIPT_ERR_SCRIPT_SIZE);
    }
    return true;
}

bool ScriptMachine::Continue(size_t nSteps)
{
    bool ret = true;
    while ((pc < pend) && (nSteps > 0))
    {
        ret = Step();
        DbgConsistencyCheck();
        if (!ret)
            break;
        nSteps--;
    }
    return ret;
}

bool ScriptMachine::ModifyScript(int position, uint8_t *data, size_t dataLength)
{
    CScript *s = (CScript *)script;
    if (!s)
        return false;

    if (s->size() < position + dataLength)
        s->resize(position + dataLength);
    uint8_t *spos = &((*s)[position]);
    if (!spos)
        return false;
    memcpy(spos, data, dataLength);
    return true;
}

/** remove a single item from the top of the stack.  If the stack is empty, std::runtime_error is thrown. */
void ScriptMachine::PopStack()
{
    if (stack.empty())
    {
        throw script_error(SCRIPT_ERR_STACK_BYTES, "ScriptMachine.PopStack: stack empty");
    }
    StackItem &item = stack.at(stack.size() - 1);
    assert(stackSize >= item.size());
    stackSize -= item.size();
    stack.pop_back();
}

/** remove a single item from the top of the stack.  If the stack is empty, std::runtime_error is thrown. */
void ScriptMachine::EraseStackItemAt(int idx)
{
    if (-idx > (int)stack.size())
    {
        throw script_error(SCRIPT_ERR_STACK_BYTES, "ScriptMachine.EraseStackItemAt: access beyond stack end");
    }
    // StackItem &item = stack.at(stack.size() + idx);
    auto iter = stack.end() + idx;
    StackItem &item = *iter;
    assert(stackSize >= item.size());
    stackSize -= item.size();
    stack.erase(iter);
}

/* Push an item to the main stack */
void ScriptMachine::CheckAndUpdateStackSize(int itemSize)
{
    int currentTotal = altStackSize + stackSize + itemSize;
    if (currentTotal < 0)
        throw script_error(SCRIPT_ERR_STACK_BYTES, "ScriptMachine: stack memory underflow");
    if ((unsigned int)currentTotal > maxStackUse)
    {
        throw script_error(SCRIPT_ERR_STACK_BYTES, "ScriptMachine: stack memory exceeded");
    }
    if ((unsigned int)currentTotal > stats.maxStackBytes)
        stats.maxStackBytes = currentTotal;
    stackSize += itemSize;
}


/* Push an item to the main stack */
void ScriptMachine::PushStack(const StackItem &item)
{
    unsigned int itemSize = item.size();
    CheckAndUpdateStackSize(itemSize);
    stack.push_back(item);
}

/* Push an item to the main stack */
void ScriptMachine::PushStack(const unsigned char *begin, const unsigned char *end)
{
    unsigned int itemSize = end - begin;
    CheckAndUpdateStackSize(itemSize);
    stack.emplace_back(begin, end);
}

/* Push an item to the main stack */
void ScriptMachine::PushStack(const CScript::const_iterator &begin, const CScript::const_iterator &end)
{
    unsigned int itemSize = end - begin;
    CheckAndUpdateStackSize(itemSize);
    stack.emplace_back(begin, end);
}

VchType &ScriptMachine::mstacktop(int i) { return mstackItemAt(i).mdata(); }

const VchType &ScriptMachine::stacktop(int i) { return stackItemAt(i).data(); }

StackItem &ScriptMachine::mstackItemAt(int i)
{
    int pos = stack.size() + i;
    // These are DbgAsserts because the caller must verify bounds before using this API.
    // However, in released code the best option is to reject the script that causes this problem.
    DbgAssert(pos >= 0, throw script_error(SCRIPT_ERR_STACK_BYTES, "ScriptMachine: access outside of stack"));
    DbgAssert(
        pos < (int)stack.size(), throw script_error(SCRIPT_ERR_STACK_BYTES, "ScriptMachine: access outside of stack"));
    return stack.at(pos);
}

const StackItem &ScriptMachine::stackItemAt(int i) { return mstackItemAt(i); }


const StackItem &ScriptMachine::altstackItemAt(int i)
{
    int pos = altstack.size() + i;
    // These are DbgAsserts because the caller must verify bounds before using this API.
    // However, in released code the best option is to reject the script that causes this problem.
    DbgAssert(pos >= 0, throw script_error(SCRIPT_ERR_STACK_BYTES, "ScriptMachine: access outside of altstack"));
    DbgAssert(pos < (int)altstack.size(),
        throw script_error(SCRIPT_ERR_STACK_BYTES, "ScriptMachine: access outside of altstack"));
    return altstack.at(pos);
}

const VchType &ScriptMachine::altstacktop(int i) { return altstackItemAt(i).data(); }


/** remove a single item from the top of the altstack.  If the altstack is empty, std::runtime_error is thrown. */
void ScriptMachine::PopAltStack()
{
    if (altstack.empty())
    {
        throw script_error(SCRIPT_ERR_STACK_BYTES, "ScriptMachine.PopAltStack: altstack empty");
    }
    StackItem &item = altstack.at(altstack.size() - 1);
    assert(altStackSize >= item.size());
    altStackSize -= item.size();
    altstack.pop_back();
}

/** Push an item to the altstack */
void ScriptMachine::PushAltStack(const StackItem &item)
{
    unsigned int itemSize = item.size();
    unsigned int currentTotal = altStackSize + stackSize + itemSize;
    if (currentTotal > maxStackUse)
    {
        throw script_error(SCRIPT_ERR_STACK_BYTES, "ScriptMachine.PushAltStack: stack memory exceeded");
    }
    if (currentTotal > stats.maxStackBytes)
        stats.maxStackBytes = currentTotal;
    altStackSize += itemSize;
    altstack.push_back(item);
}


int ScriptMachine::getPos() { return (pc - pbegin); }

int ScriptMachine::setPos(size_t offset)
{
    if (!script)
        return -1;
    if (pbegin + ((long unsigned int)offset) > pend)
        pc = pend;
    else
        pc = pbegin + ((long unsigned int)offset);
    return (pc - pbegin);
}

bool ScriptMachine::Eval(const CScript &_script)
{
    bool ret;

    if (!(ret = BeginStep(_script)))
        return ret;

    while (pc < pend)
    {
        ret = Step();
        DbgConsistencyCheck();

        if (!ret)
            break;
    }
    if (ret)
        ret = EndStep();
    script = nullptr; // Ensure that the ScriptMachine does not hold script for longer than this scope

    return ret;
}

bool ScriptMachine::EndStep()
{
    script = nullptr; // let go of our use of the script
    if (!vfExec.empty())
        return set_error(&error, SCRIPT_ERR_UNBALANCED_CONDITIONAL);
    return set_success(&error);
}

bool ScriptMachine::Step()
{
    bool fRequireMinimal = (flags & SCRIPT_VERIFY_MINIMALDATA) != 0;
    const bool integers64Bit = (flags & SCRIPT_ALLOW_64_BIT_INTEGERS) != 0;
    const bool nativeIntrospection = (flags & SCRIPT_ALLOW_NATIVE_INTROSPECTION) != 0;

    const bool negativeOP_ROLL_OP_PICK = (flags & SCRIPT_FORK1_OPCODES) != 0;
    const bool opParseEnabled = (flags & SCRIPT_FORK1_OPCODES) != 0;
    const bool extendedIntrospectionEnabled = (flags & SCRIPT_FORK1_OPCODES) != 0;
    const bool fscriptRegisters = (flags & SCRIPT_FORK1_OPCODES) != 0;
    const bool enableJump = (flags & SCRIPT_FORK1_OPCODES) != 0;

    const size_t maxIntegerSize =
        integers64Bit ? CScriptNum::MAXIMUM_ELEMENT_SIZE_64_BIT : CScriptNum::MAXIMUM_ELEMENT_SIZE_32_BIT;

    const ScriptError_t invalidNumberRangeError = ScriptError_t::SCRIPT_ERR_INVALID_NUMBER_RANGE;

    opcodetype opcode;
    StackItem vchPushValue;
    ScriptError *serror = &error;
    if (!script)
        return false;
    try
    {
        {
            bool fExec = vfExec.all_true();

            //
            // Read instruction
            //
            if (!script->GetOp(pc, opcode, vchPushValue))
            {
                LOG(SCRIPT, "Step GetOp failed at offset %d", pc - pbegin);
                return set_error(serror, SCRIPT_ERR_BAD_OPCODE);
            }
            if (!withinStackWidth(vchPushValue.size()))
            {
                return set_error(serror, SCRIPT_ERR_PUSH_SIZE);
            }
            // Note how OP_RESERVED does not count towards the opcode limit.
            if (opcode > OP_16 && ++stats.nOpCount > maxOps)
            {
                return set_error(serror, SCRIPT_ERR_OP_COUNT);
            }
            // Some opcodes are disabled.
            if (IsOpcodeDisabled(opcode, flags))
            {
                return set_error(serror, SCRIPT_ERR_DISABLED_OPCODE);
            }
            if (fExec && 0 <= opcode && opcode <= OP_PUSHDATA4)
            {
                if (fRequireMinimal && !CheckMinimalPush(vchPushValue.data(), opcode))
                {
                    return set_error(serror, SCRIPT_ERR_MINIMALDATA);
                }
                PushStack(vchPushValue);
            }
            else if (fExec || (OP_IF <= opcode && opcode <= OP_ENDIF))
            {
                switch (opcode)
                {
                //
                // Push value
                //
                case OP_1NEGATE:
                case OP_1:
                case OP_2:
                case OP_3:
                case OP_4:
                case OP_5:
                case OP_6:
                case OP_7:
                case OP_8:
                case OP_9:
                case OP_10:
                case OP_11:
                case OP_12:
                case OP_13:
                case OP_14:
                case OP_15:
                case OP_16:
                {
                    // ( -- value)
                    CScriptNum bn = CScriptNum::fromIntUnchecked(int(opcode) - int(OP_1 - 1));
                    PushStack(bn.vchStackItem());
                    // The result of these opcodes should always be the minimal way to push the data
                    // they push, so no need for a CheckMinimalPush here.
                }
                break;

                //
                // Control
                //
                case OP_NOP:
                    break;

                case OP_CHECKLOCKTIMEVERIFY:
                {
                    if (!(flags & SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY))
                    {
                        break;
                    }

                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                    // Note that elsewhere numeric opcodes are limited to
                    // operands in the range -2**31+1 to 2**31-1, however it is
                    // legal for opcodes to produce results exceeding that
                    // range. This limitation is implemented by CScriptNum's
                    // default 4-byte limit.
                    //
                    // If we kept to that limit we'd have a year 2038 problem,
                    // even though the nLockTime field in transactions
                    // themselves is uint32 which only becomes meaningless
                    // after the year 2106.
                    //
                    // Thus as a special case we tell CScriptNum to accept up
                    // to 5-byte bignums, which are good until 2**39-1, well
                    // beyond the 2**32-1 limit of the nLockTime field itself.
                    const CScriptNum nLockTime(stacktop(-1), fRequireMinimal, 5);

                    // In the rare event that the argument may be < 0 due to
                    // some arithmetic being done first, you can always use
                    // 0 MAX CHECKLOCKTIMEVERIFY.
                    if (nLockTime < 0)
                    {
                        return set_error(serror, SCRIPT_ERR_NEGATIVE_LOCKTIME);
                    }

                    // Actually compare the specified lock time with the transaction.
                    if (!sis.checker)
                        return set_error(serror, SCRIPT_ERR_DATA_REQUIRED);
                    if (!sis.checker->CheckLockTime(nLockTime))
                    {
                        return set_error(serror, SCRIPT_ERR_UNSATISFIED_LOCKTIME);
                    }

                    break;
                }

                case OP_CHECKSEQUENCEVERIFY:
                {
                    if (!(flags & SCRIPT_VERIFY_CHECKSEQUENCEVERIFY))
                    {
                        break;
                    }

                    if (stack.size() < 1)
                    {
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    }

                    // nSequence, like nLockTime, is a 32-bit unsigned integer
                    // field. See the comment in CHECKLOCKTIMEVERIFY regarding
                    // 5-byte numeric operands.
                    const CScriptNum nSequence(stacktop(-1), fRequireMinimal, 5);

                    // In the rare event that the argument may be < 0 due to
                    // some arithmetic being done first, you can always use
                    // 0 MAX CHECKSEQUENCEVERIFY.
                    if (nSequence < 0)
                    {
                        return set_error(serror, SCRIPT_ERR_NEGATIVE_LOCKTIME);
                    }

                    // To provide for future soft-fork extensibility, if the
                    // operand has the disabled lock-time flag set,
                    // CHECKSEQUENCEVERIFY behaves as a NOP.
                    auto res = nSequence.safeBitwiseAnd(CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG);
                    if (!res)
                    {
                        // Defensive programming: It is impossible for the following exception to be
                        // thrown unless the current values of the operands are changed.
                        return set_error(serror, SCRIPT_ERR_INVALID_NUMBER_RANGE);
                    }
                    if (*res != 0)
                    {
                        break;
                    }
                    if (!sis.checker)
                        return set_error(serror, SCRIPT_ERR_DATA_REQUIRED);
                    // Compare the specified sequence number with the input.
                    if (!sis.checker->CheckSequence(nSequence))
                    {
                        return set_error(serror, SCRIPT_ERR_UNSATISFIED_LOCKTIME);
                    }
                    break;
                }

                case OP_NOP1:
                case OP_NOP4:
                case OP_NOP5:
                case OP_NOP6:
                case OP_NOP7:
                case OP_NOP8:
                case OP_NOP9:
                case OP_NOP10:
                {
                    if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS)
                    {
                        return set_error(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
                    }
                }
                break;

                case OP_LSHIFT:
                {
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                    const StackItem &a = stackItemAt(-1); // Shift amount
                    const StackItem &b = stackItemAt(-2); // number
                    BigNum ret;
                    if (a.isBigNum())
                    {
                        if (a.num() < bnZero)
                            throw BadOpOnType("Negative shift");
                        if (a.num() > BigNum(MAX_BIGNUM_BITSHIFT_SIZE))
                        {
                            return set_error(serror, SCRIPT_ERR_INVALID_NUMBER_RANGE);
                        }
                    }

                    if (b.isBigNum())
                    {
                        ret = b.num() << a.asUint64(fRequireMinimal);
                        ret = ret.tdiv(bigNumModulo);
                    }
                    else
                    {
                        return set_error(serror, SCRIPT_ERR_DISABLED_OPCODE);
                    }
                    PopStack();
                    PopStack();
                    PushStack(StackItem(ret));
                }
                break;
                case OP_RSHIFT:
                {
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                    const StackItem &a = stackItemAt(-1); // Shift amount
                    const StackItem &b = stackItemAt(-2); // number
                    BigNum ret;
                    if (b.isBigNum())
                    {
                        if (a.isBigNum())
                        {
                            if (a.num() < bnZero)
                                throw BadOpOnType("Negative shift");
                            if (a.num() > BigNum(MAX_BIGNUM_BITSHIFT_SIZE))
                                ret = bnZero;
                            else
                                ret = b.num() >> a.asUint64(fRequireMinimal);
                        }
                        else
                        {
                            ret = b.num() >> a.asUint64(fRequireMinimal);
                        }

                        ret = ret.tdiv(bigNumModulo); // If the BMD changed, this may need to occur
                        PopStack();
                        PopStack();
                        PushStack(StackItem(ret));
                    }
                    else
                    {
                        return set_error(serror, SCRIPT_ERR_DISABLED_OPCODE);
                    }
                }
                break;

                case OP_PUSH_TX_STATE:
                {
                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    const StackItem &s = stackItemAt(-1);
                    if (!s.isVch())
                        return set_error(serror, SCRIPT_ERR_BAD_OPERATION_ON_TYPE);
                    VchType specifier = s.asVch();
                    PopStack();
                    ScriptError err = EvalPushTxState(specifier, *this);
                    if (err != SCRIPT_ERR_OK)
                        return set_error(serror, err);
                }
                break;

                case OP_EXEC:
                {
                    if (execDepth >= MAX_EXEC_DEPTH)
                        return set_error(serror, SCRIPT_ERR_EXEC_DEPTH_EXCEEDED);
                    if (stats.nOpExec >= MAX_OP_EXEC)
                        return set_error(serror, SCRIPT_ERR_EXEC_COUNT_EXCEEDED);

                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    // current script (template) generally pushes this since it subsequently uses the return values
                    int64_t returnedParamQty = stackItemAt(-1).asInt64(fRequireMinimal);
                    // the parameters to the function are pushed here
                    int64_t paramQty = stackItemAt(-2).asInt64(fRequireMinimal); // number of parameters
                    if (paramQty < 0)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    if ((int64_t)stack.size() < 3 + paramQty) // 3 because 2 qty params and code
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                    const valtype code = stacktop(-3 - paramQty);

                    PopStack(); // remove returnedParamQty
                    PopStack(); // remove paramQty

                    ScriptMachine sm(
                        flags, sis, maxOps - stats.nOpCount, maxConsensusSigOps - stats.consensusSigCheckCount);
                    sm.execDepth = execDepth + 1;
                    sm.StackReserve(paramQty);
                    for (int i = 0; i < paramQty; i++)
                    {
                        sm.PushStack(stacktop(-1));
                        PopStack();
                    }
                    PopStack(); // remove code

                    // The maximum stack usage of the child execution is the max use of the parent
                    // minus what the parent is currently using
                    sm.maxStackUse = maxStackUse - (stackSize + altStackSize);
                    stats.nOpExec++;
                    sm.Eval(CScript(code.begin(), code.end()));
                    stats.update(sm.stats, stackSize + altStackSize);
                    // If the evaluation of the subscript results in too many op_exec abort
                    if (stats.nOpExec > MAX_OP_EXEC)
                        return set_error(serror, SCRIPT_ERR_EXEC_COUNT_EXCEEDED);

                    ScriptError result = sm.getError();
                    if (result != SCRIPT_ERR_OK)
                        return set_error(serror, result);

                    // transfer the top paramQty stack items from the subscript's stack to the caller's stack
                    auto &outStack = sm.getStack();
                    int sz = outStack.size();
                    if (returnedParamQty < 0)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    if (sz < returnedParamQty)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    for (int i = sz - returnedParamQty; i < sz; i++)
                    {
                        PushStack(outStack[i]);
                    }
                }
                break;
                case OP_JUMP:
                {
                    if (!enableJump)
                    {
                        return set_error(serror, SCRIPT_ERR_BAD_OPCODE);
                    }
                    if (stack.size() < 1)
                    {
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    }
                    const StackItem &si = stackItemAt(-1);
                    int64_t offset = si.asInt64(false);
                    if (offset != 0) // any form of false does not jump.
                    {
                        // + 1 the offset because the pc got advanced by 1 byte for OP_IFJUMP already
                        auto temp = pc - (1 + offset);
                        if (temp < pbegin)
                            return set_error(serror, SCRIPT_ERR_INVALID_JUMP);
                        if (temp > pend)
                            return set_error(serror, SCRIPT_ERR_INVALID_JUMP);
                        pc = temp;
                    }
                    PopStack(); // Pop the arg from the stack last so we can use the arg by reference
                }
                break;
                case OP_IF:
                case OP_NOTIF:
                {
                    // <expression> if [statements] [else [statements]] endif
                    bool fValue = false;
                    if (fExec)
                    {
                        if (stack.size() < 1)
                        {
                            return set_error(serror, SCRIPT_ERR_UNBALANCED_CONDITIONAL);
                        }
                        const valtype &vch = stacktop(-1);
                        fValue = CastToBool(vch);
                        if (opcode == OP_NOTIF)
                        {
                            fValue = !fValue;
                        }
                        PopStack();
                    }
                    vfExec.push_back(fValue);
                }
                break;

                case OP_ELSE:
                {
                    if (vfExec.empty())
                    {
                        return set_error(serror, SCRIPT_ERR_UNBALANCED_CONDITIONAL);
                    }
                    vfExec.toggle_top();
                }
                break;

                case OP_ENDIF:
                {
                    if (vfExec.empty())
                    {
                        return set_error(serror, SCRIPT_ERR_UNBALANCED_CONDITIONAL);
                    }
                    vfExec.pop_back();
                }
                break;

                case OP_VERIFY:
                {
                    // (true -- ) or
                    // (false -- false) and return
                    if (stack.size() < 1)
                    {
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    }
                    bool fValue = CastToBool(stacktop(-1));
                    if (fValue)
                    {
                        PopStack();
                    }
                    else
                    {
                        return set_error(serror, SCRIPT_ERR_VERIFY);
                    }
                }
                break;

                case OP_RETURN:
                {
                    return set_error(serror, SCRIPT_ERR_OP_RETURN);
                }
                break;


                //
                // Stack ops
                //
                case OP_TOALTSTACK:
                {
                    if (stack.size() < 1)
                    {
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    }
                    MoveStackToAlt();
                }
                break;

                case OP_FROMALTSTACK:
                {
                    if (altstack.size() < 1)
                    {
                        return set_error(serror, SCRIPT_ERR_INVALID_ALTSTACK_OPERATION);
                    }
                    MoveAltToStack();
                }
                break;

                case OP_2DROP:
                {
                    // (x1 x2 -- )
                    if (stack.size() < 2)
                    {
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    }
                    PopStack();
                    PopStack();
                }
                break;

                case OP_2DUP:
                {
                    // (x1 x2 -- x1 x2 x1 x2)
                    if (stack.size() < 2)
                    {
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    }
                    if (!reserveIfNeeded(stack, 2))
                        return set_error(serror, SCRIPT_ERR_STACK_LIMIT_EXCEEDED);
                    const StackItem &si1 = stackItemAt(-2);
                    const StackItem &si2 = stackItemAt(-1);
                    PushStack(si1);
                    PushStack(si2);
                }
                break;

                case OP_3DUP:
                {
                    // (x1 x2 x3 -- x1 x2 x3 x1 x2 x3)
                    if (stack.size() < 3)
                    {
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    }
                    if (!reserveIfNeeded(stack, 3))
                        return set_error(serror, SCRIPT_ERR_STACK_LIMIT_EXCEEDED);
                    const StackItem &si1 = stackItemAt(-3);
                    const StackItem &si2 = stackItemAt(-2);
                    const StackItem &si3 = stackItemAt(-1);
                    PushStack(si1);
                    PushStack(si2);
                    PushStack(si3);
                }
                break;

                case OP_2OVER:
                {
                    // (x1 x2 x3 x4 -- x1 x2 x3 x4 x1 x2)
                    if (stack.size() < 4)
                    {
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    }
                    if (!reserveIfNeeded(stack, 2))
                        return set_error(serror, SCRIPT_ERR_STACK_LIMIT_EXCEEDED);
                    const StackItem &si1 = stackItemAt(-4);
                    const StackItem &si2 = stackItemAt(-3);
                    PushStack(si1);
                    PushStack(si2);
                }
                break;

                case OP_2ROT:
                {
                    // (x1 x2 x3 x4 x5 x6 -- x3 x4 x5 x6 x1 x2)
                    if (stack.size() < 6)
                    {
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    }
                    const StackItem si1 = stackItemAt(-6); // copy not refs so erase ok
                    const StackItem si2 = stackItemAt(-5);
                    // Since this operation just moves stack items, the total stack length is not changed.
                    // This means we can use stack primitives rather than PushStack and PopStack
                    stack.erase(stack.end() - 6, stack.end() - 4);
                    stack.push_back(si1);
                    stack.push_back(si2);
                }
                break;

                case OP_2SWAP:
                {
                    // (x1 x2 x3 x4 -- x3 x4 x1 x2)
                    if (stack.size() < 4)
                    {
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    }
                    swap(mstackItemAt(-4), mstackItemAt(-2));
                    swap(mstackItemAt(-3), mstackItemAt(-1));
                }
                break;

                case OP_IFDUP:
                {
                    // (x - 0 | x x)
                    if (stack.size() < 1)
                    {
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    }
                    valtype vch = stacktop(-1);
                    if (CastToBool(vch))
                    {
                        PushStack(vch);
                    }
                }
                break;

                case OP_DEPTH:
                {
                    // -- stacksize
                    const auto bn = CScriptNum::fromIntUnchecked(stack.size());
                    PushStack(bn.getvch());
                }
                break;

                case OP_DROP:
                {
                    // (x -- )
                    if (stack.size() < 1)
                    {
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    }
                    PopStack();
                }
                break;

                case OP_DUP:
                {
                    // (x -- x x)
                    if (stack.size() < 1)
                    {
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    }
                    auto &si = stackItemAt(-1);
                    PushStack(si);
                }
                break;

                case OP_NIP:
                {
                    // (x1 x2 -- x2)
                    if (stack.size() < 2)
                    {
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    }
                    EraseStackItemAt(-2);
                }
                break;

                case OP_OVER:
                {
                    // (x1 x2 -- x1 x2 x1)
                    if (stack.size() < 2)
                    {
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    }
                    if (!reserveIfNeeded(stack, 1))
                        return set_error(serror, SCRIPT_ERR_STACK_LIMIT_EXCEEDED);
                    const StackItem &si1 = stackItemAt(-2);
                    PushStack(si1);
                }
                break;

                case OP_PICK:
                case OP_ROLL:
                {
                    // (xn ... x2 x1 x0 n - xn ... x2 x1 x0 xn)
                    // (xn ... x2 x1 x0 n - ... x2 x1 x0 xn)
                    if (stack.size() < 2)
                    {
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    }
                    // get top stack as script num
                    const CScriptNum sc_n = CScriptNum(stacktop(-1), fRequireMinimal, maxIntegerSize);
                    PopStack();
                    // get modulus / absolute value
                    const std::optional<CScriptNum> abs_n = sc_n.abs();
                    // This is only false if value is -2^63
                    if (!abs_n)
                    {
                        return set_error(serror, SCRIPT_ERR_INVALID_NUMBER_RANGE);
                    }
                    int64_t n = abs_n->getint64();
                    // 0 is the same result either way, consider it positive for historical reasons
                    const bool positive = (sc_n >= 0);
                    // if n was positive before we took the abs, copy/move the item at
                    // index n to the top of the stack. if n was negative, copy/move
                    // the top stack item to index abs(n) in the stack (it is now index
                    // n pushing everything after it back(down) 1)
                    //
                    // order of operations: evaluate the stack for index n, perform the
                    // copy/move, if move, erase element that was moved
                    //
                    if (positive)
                    {
                        // we do not allow == stack.size() because we would be copy/moving
                        // the item after the last item (random memory)
                        if (uint64_t(n) >= stack.size())
                        {
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                        }
                        // copy/move stack item at index N to the top of the stack
                        StackItem si = stackItemAt(-n - 1);
                        if (opcode == OP_ROLL)
                        {
                            // In the roll case, items are moved, so no stack size change occurs
                            stack.push_back(si);
                            // another item was added to the stack, index -n-1 is now
                            // off by one, subtract 1 to compensate
                            stack.erase(stack.end() - n - 1 - 1);
                        }
                        else
                        {
                            // in the pick case, an item is added so use the helper function that tracks
                            // stack size changes.
                            PushStack(si);
                        }
                    }
                    else
                    {
                        if (!negativeOP_ROLL_OP_PICK)
                        {
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                        }
                        // we allow == stack.size() because it is possible to copy/move an item
                        // to be the new last item
                        if (uint64_t(n) > stack.size())
                        {
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                        }
                        // copy/move stack item at the top of the stack to index N
                        StackItem si = stacktop(-1);
                        // inserts are always done before an index but we read the stack backwards
                        // from its internal data structure representation, to compensate do not
                        // subtract 1 from n to offset the end
                        if (opcode == OP_ROLL)
                        {
                            // No size change because we are moving the item
                            stack.insert(stack.end() - n, si);
                            stack.pop_back();
                        }
                        else
                        {
                            // Inserting the item, so the size changes
                            CheckAndUpdateStackSize(si.size());
                            stack.insert(stack.end() - n, si);
                        }
                    }
                }
                break;

                case OP_ROT:
                {
                    // (x1 x2 x3 -- x2 x3 x1)
                    //  x2 x1 x3  after first swap
                    //  x2 x3 x1  after second swap
                    if (stack.size() < 3)
                    {
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    }
                    swap(mstackItemAt(-3), mstackItemAt(-2));
                    swap(mstackItemAt(-2), mstackItemAt(-1));
                }
                break;

                case OP_SWAP:
                {
                    // (x1 x2 -- x2 x1)
                    if (stack.size() < 2)
                    {
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    }
                    swap(mstackItemAt(-2), mstackItemAt(-1));
                }
                break;

                case OP_TUCK:
                {
                    // (x1 x2 -- x2 x1 x2)
                    if (stack.size() < 2)
                    {
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    }
                    const StackItem &si = stackItemAt(-1);
                    CheckAndUpdateStackSize(si.size());
                    stack.insert(stack.end() - 2, si); // si is invalid after this insert!!
                }
                break;


                case OP_SIZE:
                {
                    // (in -- in size)
                    if (stack.size() < 1)
                    {
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    }
                    const auto bn = CScriptNum::fromIntUnchecked(stacktop(-1).size());
                    PushStack(bn.getvch());
                }
                break;

                case OP_STORE:
                {
                    if (!fscriptRegisters)
                    {
                        return set_error(serror, SCRIPT_ERR_BAD_OPCODE);
                    }
                    if (stack.size() < 2)
                    {
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    }
                    const StackItem &register_value = stackItemAt(-2);
                    const int64_t register_num = CScriptNum(stacktop(-1), fRequireMinimal, maxIntegerSize).getint64();
                    // negative register indexes are not possible
                    if (register_num < 0)
                    {
                        return set_error(serror, SCRIPT_ERR_INVALID_REGISTER);
                    }
                    // attempting to store to a register higher than NUM_SCRIPT_REGISTERS
                    if (register_num >= NUM_SCRIPT_REGISTERS) // >= because 0 array is 0 indexed
                    {
                        return set_error(serror, SCRIPT_ERR_INVALID_REGISTER);
                    }
                    // store the value in the register
                    arrRegisters[register_num] = register_value;
                    PopStack(); // pop the register number off the stack
                    PopStack(); // pop the stored value off the stack
                }
                break;

                case OP_LOAD:
                {
                    if (!fscriptRegisters)
                    {
                        return set_error(serror, SCRIPT_ERR_BAD_OPCODE);
                    }
                    if (stack.size() < 1)
                    {
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    }
                    const int64_t register_num = CScriptNum(stacktop(-1), fRequireMinimal, maxIntegerSize).getint64();
                    // negative register indexes are not possible
                    if (register_num < 0)
                    {
                        return set_error(serror, SCRIPT_ERR_INVALID_REGISTER);
                    }
                    // attempting to store to a register higher than NUM_SCRIPT_REGISTERS
                    if (register_num >= NUM_SCRIPT_REGISTERS) // >= because 0 array is 0 indexed
                    {
                        return set_error(serror, SCRIPT_ERR_INVALID_REGISTER);
                    }
                    // load the value in the register
                    const StackItem &register_value = arrRegisters[register_num];
                    PopStack(); // pop the register number off the stack
                    PushStack(register_value); // push the loaded value on to the stack
                }
                break;

                //
                // Bitwise logic
                //
                case OP_AND:
                case OP_OR:
                case OP_XOR:
                {
                    // (x1 x2 - out)
                    if (stack.size() < 2)
                    {
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    }
                    valtype &vch1 = mstacktop(-2);
                    const valtype &vch2 = stacktop(-1);

                    // Inputs must be the same size
                    if (vch1.size() != vch2.size())
                    {
                        return set_error(serror, SCRIPT_ERR_INVALID_OPERAND_SIZE);
                    }

                    // To avoid allocating, we modify vch1 in place.
                    switch (opcode)
                    {
                    case OP_AND:
                        for (size_t i = 0; i < vch1.size(); ++i)
                        {
                            vch1[i] &= vch2[i];
                        }
                        break;
                    case OP_OR:
                        for (size_t i = 0; i < vch1.size(); ++i)
                        {
                            vch1[i] |= vch2[i];
                        }
                        break;
                    case OP_XOR:
                        for (size_t i = 0; i < vch1.size(); ++i)
                        {
                            vch1[i] ^= vch2[i];
                        }
                        break;
                    default:
                        break;
                    }

                    // And pop vch2.
                    PopStack();
                }
                break;

                case OP_EQUAL:
                case OP_EQUALVERIFY:
                    // case OP_NOTEQUAL: // use OP_NUMNOTEQUAL
                    {
                        bool fEqual = false;
                        // (x1 x2 - bool)
                        if (stack.size() < 2)
                        {
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                        }
                        const StackItem &a = stackItemAt(-1);
                        const StackItem &b = stackItemAt(-2);
                        if (a.isBigNum() && b.isBigNum())
                        {
                            fEqual = (a.num() == b.num());
                        }
                        else if (a.isVch() && b.isVch())
                        {
                            const valtype &vch1 = stacktop(-2);
                            const valtype &vch2 = stacktop(-1);
                            fEqual = (vch1 == vch2);
                            /*  Super-useful script debugging printout
                            if (opcode == OP_EQUALVERIFY)
                            {
                                if (!fEqual)
                                    printf("%s", strprintf("EQUALVERIFY failed: top: %s != 2nd: %s\n", HexStr(vch2),
                                                     HexStr(vch1))
                                                     .c_str());
                                else
                                    printf("%s", strprintf("EQUALVERIFY success: top: %s \n", HexStr(vch2)).c_str());
                            }
                            */
                            // OP_NOTEQUAL is disabled because it would be too easy to say
                            // something like n != 1 and have some wiseguy pass in 1 with extra
                            // zero bytes after it (numerically, 0x01 == 0x0001 == 0x000001)
                            // if (opcode == OP_NOTEQUAL)
                            //    fEqual = !fEqual;
                        }
                        else // different types are never equal
                        {
                            fEqual = false;
                        }
                        PopStack();
                        PopStack();
                        PushStack(fEqual ? vchTrue : vchFalse);
                        if (opcode == OP_EQUALVERIFY)
                        {
                            if (fEqual)
                            {
                                PopStack();
                            }
                            else
                            {
                                return set_error(serror, SCRIPT_ERR_EQUALVERIFY);
                            }
                        }
                    }
                    break;


                //
                // Numeric
                //
                case OP_1ADD:
                case OP_1SUB:
                case OP_NEGATE:
                case OP_ABS:
                case OP_NOT:
                case OP_0NOTEQUAL:
                {
                    // (in -- out)
                    if (stack.size() < 1)
                    {
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    }
                    CScriptNum bn(stacktop(-1), fRequireMinimal, maxIntegerSize);
                    switch (opcode)
                    {
                    case OP_1ADD:
                    {
                        auto res = bn.safeAdd(1);
                        if (!res)
                        {
                            return set_error(serror, SCRIPT_ERR_INVALID_NUMBER_RANGE);
                        }
                        bn = *res;
                        break;
                    }
                    case OP_1SUB:
                    {
                        auto res = bn.safeSub(1);
                        if (!res)
                        {
                            return set_error(serror, SCRIPT_ERR_INVALID_NUMBER_RANGE);
                        }
                        bn = *res;
                        break;
                    }
                    case OP_NEGATE:
                        bn = -bn;
                        break;
                    case OP_ABS:
                        if (bn < snZero)
                        {
                            bn = -bn;
                        }
                        break;
                    case OP_NOT:
                        bn = CScriptNum::fromIntUnchecked(bn == snZero);
                        break;
                    case OP_0NOTEQUAL:
                        bn = CScriptNum::fromIntUnchecked(bn != snZero);
                        break;
                    default:
                        assert(!"invalid opcode");
                        break;
                    }
                    PopStack();
                    PushStack(bn.getvch());
                }
                break;

                case OP_ADD:
                case OP_SUB:
                case OP_MUL:
                case OP_DIV:
                case OP_MOD:
                case OP_BOOLAND:
                case OP_BOOLOR:
                case OP_NUMEQUAL:
                case OP_NUMEQUALVERIFY:
                case OP_NUMNOTEQUAL:
                case OP_LESSTHAN:
                case OP_GREATERTHAN:
                case OP_LESSTHANOREQUAL:
                case OP_GREATERTHANOREQUAL:
                case OP_MIN:
                case OP_MAX:
                {
                    // (x1 x2 -- out)
                    if (stack.size() < 2)
                    {
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    }
                    const StackItem &a = stackItemAt(-1);
                    const StackItem &b = stackItemAt(-2);
                    if (a.isBigNum() || b.isBigNum())
                    {
                        BigNum ret;
                        if (!BigNumScriptOp(
                                ret, opcode, a.asBigNum(bigNumModulo), b.asBigNum(bigNumModulo), bigNumModulo, serror))
                            return false;
                        PopStack();
                        PopStack();
                        PushStack(StackItem(ret));
                    }
                    else
                    {
                        CScriptNum bn1(stacktop(-2), fRequireMinimal, maxIntegerSize);
                        CScriptNum bn2(stacktop(-1), fRequireMinimal, maxIntegerSize);
                        auto bn = CScriptNum::fromIntUnchecked(0);
                        switch (opcode)
                        {
                        case OP_ADD:
                        {
                            auto res = bn1.safeAdd(bn2);
                            if (!res)
                            {
                                return set_error(serror, SCRIPT_ERR_INVALID_NUMBER_RANGE);
                            }
                            bn = *res;
                            break;
                        }

                        case OP_SUB:
                        {
                            auto res = bn1.safeSub(bn2);
                            if (!res)
                            {
                                return set_error(serror, SCRIPT_ERR_INVALID_NUMBER_RANGE);
                            }
                            bn = *res;
                            break;
                        }

                        case OP_MUL:
                        {
                            auto res = bn1.safeMul(bn2);
                            if (!res)
                            {
                                return set_error(serror, SCRIPT_ERR_INVALID_NUMBER_RANGE);
                            }
                            bn = *res;
                            break;
                        }

                        case OP_DIV:
                            // denominator must not be 0
                            if (bn2 == 0)
                            {
                                return set_error(serror, SCRIPT_ERR_DIV_BY_ZERO);
                            }
                            bn = bn1 / bn2;
                            break;

                        case OP_MOD:
                            // divisor must not be 0
                            if (bn2 == 0)
                            {
                                return set_error(serror, SCRIPT_ERR_MOD_BY_ZERO);
                            }
                            bn = bn1 % bn2;
                            break;

                        case OP_BOOLAND:
                            bn = CScriptNum::fromIntUnchecked(bn1 != snZero && bn2 != snZero);
                            break;
                        case OP_BOOLOR:
                            bn = CScriptNum::fromIntUnchecked(bn1 != snZero || bn2 != snZero);
                            break;
                        case OP_NUMEQUAL:
                            bn = CScriptNum::fromIntUnchecked(bn1 == bn2);
                            break;
                        case OP_NUMEQUALVERIFY:
                            bn = CScriptNum::fromIntUnchecked(bn1 == bn2);
                            break;
                        case OP_NUMNOTEQUAL:
                            bn = CScriptNum::fromIntUnchecked(bn1 != bn2);
                            break;
                        case OP_LESSTHAN:
                            bn = CScriptNum::fromIntUnchecked(bn1 < bn2);
                            break;
                        case OP_GREATERTHAN:
                            bn = CScriptNum::fromIntUnchecked(bn1 > bn2);
                            break;
                        case OP_LESSTHANOREQUAL:
                            bn = CScriptNum::fromIntUnchecked(bn1 <= bn2);
                            break;
                        case OP_GREATERTHANOREQUAL:
                            bn = CScriptNum::fromIntUnchecked(bn1 >= bn2);
                            break;
                        case OP_MIN:
                            bn = (bn1 < bn2 ? bn1 : bn2);
                            break;
                        case OP_MAX:
                            bn = (bn1 > bn2 ? bn1 : bn2);
                            break;
                        default:
                            assert(!"invalid opcode");
                            break;
                        }

                        PopStack();
                        PopStack();
                        PushStack(bn.getvch());
                    }

                    if (opcode == OP_NUMEQUALVERIFY)
                    {
                        if ((bool)stackItemAt(-1))
                        {
                            PopStack();
                        }
                        else
                        {
                            return set_error(serror, SCRIPT_ERR_NUMEQUALVERIFY);
                        }
                    }
                }
                break;

                case OP_WITHIN:
                {
                    // (x min max -- out)
                    if (stack.size() < 3)
                    {
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    }
                    CScriptNum bn1(stacktop(-3), fRequireMinimal, maxIntegerSize);
                    CScriptNum bn2(stacktop(-2), fRequireMinimal, maxIntegerSize);
                    CScriptNum bn3(stacktop(-1), fRequireMinimal, maxIntegerSize);
                    bool fValue = (bn2 <= bn1 && bn1 < bn3);
                    PopStack();
                    PopStack();
                    PopStack();
                    PushStack(fValue ? vchTrue : vchFalse);
                }
                break;


                //
                // Crypto
                //
                case OP_RIPEMD160:
                case OP_SHA1:
                case OP_SHA256:
                case OP_HASH160:
                case OP_HASH256:
                {
                    // (in -- hash)
                    if (stack.size() < 1)
                    {
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    }
                    const valtype &vch = stacktop(-1);
                    valtype vchHash((opcode == OP_RIPEMD160 || opcode == OP_SHA1 || opcode == OP_HASH160) ? 20 : 32);
                    if (opcode == OP_RIPEMD160)
                    {
                        CRIPEMD160().Write(begin_ptr(vch), vch.size()).Finalize(begin_ptr(vchHash));
                    }
                    else if (opcode == OP_SHA1)
                    {
                        CSHA1().Write(begin_ptr(vch), vch.size()).Finalize(begin_ptr(vchHash));
                    }
                    else if (opcode == OP_SHA256)
                    {
                        CSHA256().Write(begin_ptr(vch), vch.size()).Finalize(begin_ptr(vchHash));
                    }
                    else if (opcode == OP_HASH160)
                    {
                        CHash160().Write(begin_ptr(vch), vch.size()).Finalize(begin_ptr(vchHash));
                    }
                    else if (opcode == OP_HASH256)
                    {
                        CHash256().Write(begin_ptr(vch), vch.size()).Finalize(begin_ptr(vchHash));
                    }
                    PopStack();
                    PushStack(vchHash);
                }
                break;

                case OP_CODESEPARATOR:
                {
                    // Hash starts after the code separator
                    pbegincodehash = pc;
                }
                break;

                case OP_CHECKSIG:
                case OP_CHECKSIGVERIFY:
                {
                    // (sig pubkey -- bool)
                    if (stack.size() < 2)
                    {
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    }

                    const valtype &vchSig = stacktop(-2);
                    const valtype &vchPubKey = stacktop(-1);

                    // Subset of script starting at the most recent codeseparator
                    CScript scriptCode(pbegincodehash, pend);

                    // Drop the signature, since there's no way for a signature to sign itself
                    scriptCode.FindAndDelete(CScript(vchSig));

                    if (vchSig.size() != 0)
                    {
                        // Checking for > or = here because I'm about to do another one so that will make it >
                        if (stats.consensusSigCheckCount >= maxConsensusSigOps)
                        {
                            return set_error(serror, SCRIPT_ERR_SIGCHECKS_LIMIT_EXCEEDED);
                        }
                        stats.consensusSigCheckCount += 1; // 2020-05-15 sigchecks consensus rule
                    }

                    if (!CheckSignatureEncoding(vchSig, flags, serror) ||
                        !CheckPubKeyEncoding(vchPubKey, flags, serror))
                    {
                        // serror is set
                        return false;
                    }
                    if (!sis.checker)
                        return set_error(serror, SCRIPT_ERR_DATA_REQUIRED);
                    bool fSuccess = sis.checker->CheckSig(vchSig, vchPubKey, scriptCode);

                    if (!fSuccess && (flags & SCRIPT_VERIFY_NULLFAIL) && vchSig.size())
                    {
                        return set_error(serror, SCRIPT_ERR_SIG_NULLFAIL);
                    }

                    PopStack();
                    PopStack();
                    PushStack(fSuccess ? vchTrue : vchFalse);
                    if (opcode == OP_CHECKSIGVERIFY)
                    {
                        if (fSuccess)
                        {
                            PopStack();
                        }
                        else
                        {
                            return set_error(serror, SCRIPT_ERR_CHECKSIGVERIFY);
                        }
                    }
                }
                break;

                case OP_CHECKMULTISIG:
                case OP_CHECKMULTISIGVERIFY:
                {
                    // ([sig ...] num_of_signatures [pubkey ...] num_of_pubkeys -- bool)

                    const int64_t idxKeyCount = 1;
                    if (stack.size() < idxKeyCount)
                    {
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    }

                    const int64_t nKeysCount =
                        CScriptNum(stacktop(-idxKeyCount), fRequireMinimal, maxIntegerSize).getint64();
                    if (nKeysCount < 0 || nKeysCount > MAX_PUBKEYS_PER_MULTISIG)
                    {
                        return set_error(serror, SCRIPT_ERR_PUBKEY_COUNT);
                    }
                    stats.nOpCount += nKeysCount;
                    if (stats.nOpCount > maxOps)
                    {
                        return set_error(serror, SCRIPT_ERR_OP_COUNT);
                    }
                    const uint64_t idxTopKey = idxKeyCount + 1;

                    // stack depth of nSigsCount
                    const int64_t idxSigCount = idxTopKey + nKeysCount;
                    if ((int64_t)stack.size() < idxSigCount)
                    {
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    }

                    const int64_t nSigsCount =
                        CScriptNum(stacktop(-idxSigCount), fRequireMinimal, maxIntegerSize).getint64();
                    if (nSigsCount < 0 || nSigsCount > nKeysCount)
                    {
                        return set_error(serror, SCRIPT_ERR_SIG_COUNT);
                    }

                    // stack depth of the top signature
                    const uint64_t idxTopSig = idxSigCount + 1;

                    // stack depth of the dummy element
                    const uint64_t idxDummy = idxTopSig + nSigsCount;
                    if (stack.size() < idxDummy)
                    {
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    }

                    // Subset of script starting at the most recent codeseparator
                    CScript scriptCode(pbegincodehash, pend);

                    // 0 size is no bits so invalid bit count
                    bool fSuccess = false;
                    if (stacktop(-idxDummy).size() != 0) // if checkBits is empty, "soft" fail (push false on stack)
                    {
                        // Assuming success is usually a bad idea, but the schnorr path can only succeed.
                        fSuccess = true;
                        stats.consensusSigCheckCount += nSigsCount; // 2020-05-15 sigchecks consensus rule
                        // SCHNORR MULTISIG
                        static_assert(
                            MAX_PUBKEYS_PER_MULTISIG < 32, "Multisig bitfield can't represent more than 32 keys");

                        // Decode the bitfield
                        uint32_t checkBits = 0;
                        const valtype &vchDummy = stacktop(-idxDummy); // which pubkeys should be checked
                        if (flags & SCRIPT_ENFORCE_STACK_TOTAL) // hardfork1 activated
                        {
                            if (!DecodeBitfield(
                                    vchDummy, nKeysCount, checkBits, serror, flags, fRequireMinimal, maxIntegerSize))
                            {
                                // serror is set
                                return false;
                            }
                        }
                        else
                        {
                            if (!DecodeBitfield(vchDummy, nKeysCount, checkBits, serror))
                            {
                                // serror is set
                                return false;
                            }
                        }

                        // Check that the bitfield sets the right number of signatures.
                        if (countBits(checkBits) != uint32_t(nSigsCount))
                        {
                            return set_error(serror, SCRIPT_ERR_INVALID_BIT_COUNT);
                        }

                        const uint64_t idxBottomKey = idxTopKey + nKeysCount - 1;
                        const uint64_t idxBottomSig = idxTopSig + nSigsCount - 1;

                        int32_t iKey = 0;
                        for (int64_t iSig = 0; iSig < nSigsCount; iSig++, iKey++)
                        {
                            if ((checkBits >> iKey) == 0)
                            {
                                // This is a sanity check and should be unreacheable because we've checked above that
                                // the number of bits in checkBits == the number of signatures.
                                // But just in case this check ensures termination of the subsequent while loop.
                                return set_error(serror, SCRIPT_ERR_INVALID_BIT_RANGE);
                            }

                            // Find the next suitable key.
                            while (((checkBits >> iKey) & 0x01) == 0)
                            {
                                iKey++;
                            }

                            if (iKey >= nKeysCount)
                            {
                                // This is a sanity check and should be unreacheable.
                                return set_error(serror, SCRIPT_ERR_PUBKEY_COUNT);
                            }

                            // Check the signature.
                            const valtype &vchSig = stacktop(-idxBottomSig + iSig);
                            const valtype &vchPubKey = stacktop(-idxBottomKey + iKey);

                            // Note that only pubkeys associated with a signature are checked for validity.
                            if (!CheckTransactionSchnorrSignatureEncoding(vchSig, flags, serror) ||
                                !CheckPubKeyEncoding(vchPubKey, flags, serror))
                            {
                                // serror is set
                                return false;
                            }

                            if (!sis.checker)
                                return set_error(serror, SCRIPT_ERR_DATA_REQUIRED);
                            // Check signature
                            if (!sis.checker->CheckSig(vchSig, vchPubKey, scriptCode))
                            {
                                // The only way to "soft" fail the MULTISIG is to give no signatures
                                return set_error(serror, SCRIPT_ERR_CHECKMULTISIGVERIFY);
                            }
                        }

                        if ((checkBits >> iKey) != 0)
                        {
                            // This is a sanity check and should be unreacheable.
                            return set_error(serror, SCRIPT_ERR_INVALID_BIT_COUNT);
                        }
                        // If the operation failed, we require that all signatures must be empty vector
                        if (!fSuccess && (flags & SCRIPT_VERIFY_NULLFAIL))
                        {
                            return set_error(serror, SCRIPT_ERR_MULTISIG_NULLFAIL);
                        }
                    }

                    // Clean up stack of all arguments
                    for (uint64_t i = 0; i < idxDummy; i++)
                    {
                        PopStack();
                    }

                    if (opcode == OP_CHECKMULTISIGVERIFY)
                    {
                        if (!fSuccess)
                        {
                            return set_error(serror, SCRIPT_ERR_CHECKMULTISIGVERIFY);
                        }
                    }
                    else
                    {
                        PushStack(fSuccess ? vchTrue : vchFalse);
                    }
                }
                break;

                case OP_CHECKDATASIG:
                case OP_CHECKDATASIGVERIFY:
                {
                    // (sig message pubkey -- bool)
                    if (stack.size() < 3)
                    {
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    }

                    const valtype &vchSig = stacktop(-3);
                    const valtype &vchMessage = stacktop(-2);
                    const valtype &vchPubKey = stacktop(-1);

                    if (!CheckDataSignatureEncoding(vchSig, flags, serror) ||
                        !CheckPubKeyEncoding(vchPubKey, flags, serror))
                    {
                        // serror is set
                        return false;
                    }

                    // Checking for > or = here because I'm about to do another one so that will make it >
                    if (stats.consensusSigCheckCount >= maxConsensusSigOps)
                    {
                        return set_error(serror, SCRIPT_ERR_SIGCHECKS_LIMIT_EXCEEDED);
                    }

                    bool fSuccess = false;
                    if (vchSig.size())
                    {
                        valtype vchHash(32);
                        CSHA256().Write(vchMessage.data(), vchMessage.size()).Finalize(vchHash.data());
                        uint256 messagehash(vchHash);
                        CPubKey pubkey(vchPubKey);
                        if (!sis.checker)
                            return set_error(serror, SCRIPT_ERR_DATA_REQUIRED);
                        fSuccess = sis.checker->VerifySignature(vchSig, pubkey, messagehash);
                        stats.consensusSigCheckCount += 1; // 2020-05-15 sigchecks consensus rule
                    }

                    if (!fSuccess && (flags & SCRIPT_VERIFY_NULLFAIL) && vchSig.size())
                    {
                        return set_error(serror, SCRIPT_ERR_SIG_NULLFAIL);
                    }

                    PopStack();
                    PopStack();
                    PopStack();
                    PushStack(fSuccess ? vchTrue : vchFalse);
                    if (opcode == OP_CHECKDATASIGVERIFY)
                    {
                        if (fSuccess)
                        {
                            PopStack();
                        }
                        else
                        {
                            return set_error(serror, SCRIPT_ERR_CHECKDATASIGVERIFY);
                        }
                    }
                }
                break;

                //
                // Byte string operations
                //
                case OP_CAT:
                {
                    // (x1 x2 -- out)
                    if (stack.size() < 2)
                    {
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    }
                    valtype &vch1 = mstacktop(-2);
                    const valtype &vch2 = stacktop(-1);
                    if (!withinStackWidth(vch1.size() + vch2.size()))
                    {
                        return set_error(serror, SCRIPT_ERR_PUSH_SIZE);
                    }
                    // The total stack size in bytes isn't changing in op_cat
                    vch1.insert(vch1.end(), vch2.begin(), vch2.end());
                    // so its ok to pop manually
                    stack.pop_back();
                }
                break;

                case OP_SPLIT:
                {
                    // (in position -- x1 x2)
                    if (stack.size() < 2)
                    {
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    }

                    const valtype &data = stacktop(-2);

                    // Make sure the split point is apropriate.
                    int64_t position = CScriptNum(stacktop(-1), fRequireMinimal, maxIntegerSize).getint64();
                    if (position < 0 || (uint64_t)position > data.size())
                    {
                        return set_error(serror, SCRIPT_ERR_INVALID_SPLIT_RANGE);
                    }

                    // Prepare the results in their own buffer as `data`
                    // will be invalidated.
                    valtype n1(data.begin(), data.begin() + position);
                    valtype n2(data.begin() + position, data.end());

                    // Replace existing stack values by the new values.
                    setStackItem(1, n1);
                    setStackItem(0, n2);
                }
                break;

                case OP_REVERSEBYTES:
                {
                    // (in -- out)
                    if (stack.size() < 1)
                    {
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    }

                    // The size doesn't change when reversing so we can do it in places
                    valtype &data = mstacktop(-1);
                    std::reverse(data.begin(), data.end());
                }
                break;

                // gitlab.com/GeneralProtocols/research/chips/-/blob/master/CHIP-2021-02-Add-Native-Introspection-Opcodes.md
                // (TODO: link to reference.cash)
                // Transaction Introspection Opcodes: see https:

                // Native Introspection opcodes (Nullary, consumes no items)
                case OP_INPUTINDEX:
                case OP_ACTIVEBYTECODE:
                case OP_TXVERSION:
                case OP_TXINPUTCOUNT:
                case OP_TXOUTPUTCOUNT:
                case OP_TXLOCKTIME:
                {
                    if (!nativeIntrospection)
                    {
                        LOG(SCRIPT, "Native Introspection is off; opcode rejected");
                        return set_error(serror, SCRIPT_ERR_BAD_OPCODE);
                    }
                    if (!sis.tx)
                    {
                        return set_error(serror, SCRIPT_ERR_DATA_REQUIRED);
                    }
                    switch (opcode)
                    {
                    case OP_INPUTINDEX:
                    {
                        const CScriptNum sn = CScriptNum::fromIntUnchecked(sis.nIn);
                        PushStack(sn.getvch());
                    }
                    break;
                    case OP_ACTIVEBYTECODE:
                    {
                        // Should be impossible for normal script machine use
                        if (!script)
                        {
                            return set_error(serror, SCRIPT_ERR_DATA_REQUIRED);
                        }
                        // Subset of script starting at the most recent codeseparator
                        CScript scriptCode(pbegincodehash, pend);
                        if (!withinStackWidth(scriptCode.size()))
                        {
                            return set_error(serror, SCRIPT_ERR_PUSH_SIZE);
                        }
                        PushStack(scriptCode.begin(), scriptCode.end());
                    }
                    break;
                    case OP_TXVERSION:
                    {
                        const CScriptNum sn = CScriptNum::fromIntUnchecked(sis.tx->nVersion);
                        PushStack(sn.getvch());
                    }
                    break;
                    case OP_TXINPUTCOUNT:
                    {
                        const CScriptNum sn = CScriptNum::fromIntUnchecked(sis.tx->vin.size());
                        PushStack(sn.getvch());
                    }
                    break;
                    case OP_TXOUTPUTCOUNT:
                    {
                        const CScriptNum sn = CScriptNum::fromIntUnchecked(sis.tx->vout.size());
                        PushStack(sn.getvch());
                    }
                    break;
                    case OP_TXLOCKTIME:
                    {
                        const CScriptNum sn = CScriptNum::fromIntUnchecked(sis.tx->nLockTime);
                        PushStack(sn.getvch());
                    }
                    break;

                    default:
                        break;
                    }
                }
                break; // end of Native Introspection opcodes (Nullary)

                // Native Introspection opcodes (Unary, consume top item)
                case OP_UTXOVALUE:
                case OP_UTXOBYTECODE:
                case OP_OUTPOINTHASH:
                case OP_INPUTBYTECODE:
                case OP_INPUTSEQUENCENUMBER:
                case OP_OUTPUTVALUE:
                case OP_OUTPUTBYTECODE:
                case OP_INPUTTYPE:
                case OP_OUTPUTTYPE:
                case OP_INPUTVALUE:
                {
                    if (!nativeIntrospection)
                    {
                        LOG(SCRIPT, "Native Introspection is off; opcode rejected");
                        return set_error(serror, SCRIPT_ERR_BAD_OPCODE);
                    }
                    if (!sis.tx)
                    {
                        return set_error(serror, SCRIPT_ERR_DATA_REQUIRED);
                    }
                    if (stack.size() < 1)
                    {
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    }
                    const CScriptNum top(stacktop(-1), fRequireMinimal, maxIntegerSize);
                    // consume top element
                    PopStack();

                    switch (opcode)
                    {
                    case OP_UTXOVALUE:
                    case OP_UTXOBYTECODE:
                    case OP_OUTPOINTHASH:
                    case OP_INPUTBYTECODE:
                    case OP_INPUTSEQUENCENUMBER:
                    case OP_INPUTTYPE:
                    case OP_INPUTVALUE:
                    {
                        int32_t idx = top.getint32();
                        if (idx < 0 || size_t(idx) >= sis.tx->vin.size())
                        {
                            return set_error(serror, SCRIPT_ERR_INVALID_TX_INPUT_INDEX);
                        }
                        const CTxIn &input = sis.tx->vin[idx];
                        switch (opcode)
                        {
                        case OP_UTXOVALUE:
                        {
                            if (idx >= (int32_t)sis.spentCoins.size())
                            {
                                // The code should have provided 1 spent coin per input.  But since
                                // we checked idx against tx->vin above, we know that the problem is that
                                // not enough spent coins data was provided
                                return set_error(serror, SCRIPT_ERR_DATA_REQUIRED);
                            }
                            const auto bn = CScriptNum::fromInt(sis.spentCoins[idx].nValue);
                            // This is only false if nVaue is -2^63, should not be possible
                            if (!bn)
                            {
                                return set_error(serror, SCRIPT_ERR_INVALID_NUMBER_RANGE);
                            }
                            PushStack(bn->getvch());
                        }
                        break;
                        case OP_UTXOBYTECODE:
                        {
                            if (idx >= (int32_t)sis.spentCoins.size())
                            {
                                // The code should have provided 1 spent coin per input.  But since
                                // we checked idx against tx->vin above, we know that the problem is that
                                // not enough spent coins data was provided
                                return set_error(serror, SCRIPT_ERR_DATA_REQUIRED);
                            }
                            const auto &utxoScript = sis.spentCoins[idx].scriptPubKey;
                            if (!withinStackWidth(utxoScript.size()))
                            {
                                return set_error(serror, SCRIPT_ERR_PUSH_SIZE);
                            }
                            PushStack(utxoScript.begin(), utxoScript.end());
                        }
                        break;
                        case OP_OUTPOINTHASH:
                        {
                            const uint256 &hash = input.prevout.hash;
                            PushStack(hash.begin(), hash.end());
                        }
                        break;
                        case OP_INPUTBYTECODE:
                        {
                            if (!withinStackWidth(input.scriptSig.size()))
                            {
                                return set_error(serror, SCRIPT_ERR_PUSH_SIZE);
                            }
                            PushStack(input.scriptSig.begin(), input.scriptSig.end());
                        }
                        break;
                        case OP_INPUTTYPE:
                        {
                            if (!extendedIntrospectionEnabled)
                                return set_error(serror, SCRIPT_ERR_BAD_OPCODE);
                            const auto n = CScriptNum::fromIntUnchecked(input.type);
                            PushStack(n.getvch());
                        }
                        break;
                        case OP_INPUTVALUE:
                        {
                            if (!extendedIntrospectionEnabled)
                                return set_error(serror, SCRIPT_ERR_BAD_OPCODE);
                            const auto n = CScriptNum::fromInt(input.amount);
                            // This is only false if nVaue is -2^63, should not be possible
                            if (!n)
                            {
                                return set_error(serror, SCRIPT_ERR_INVALID_NUMBER_RANGE);
                            }
                            PushStack(n->getvch());
                        }
                        break;
                        case OP_INPUTSEQUENCENUMBER:
                        {
                            const CScriptNum sn = CScriptNum::fromIntUnchecked(input.nSequence);
                            PushStack(sn.getvch());
                        }
                        break;

                        default:
                            break;
                        }
                    }
                    break;

                    case OP_OUTPUTVALUE:
                    case OP_OUTPUTBYTECODE:
                    case OP_OUTPUTTYPE:
                    {
                        int32_t idx = top.getint32();
                        if (idx < 0 || size_t(idx) >= sis.tx->vout.size())
                        {
                            return set_error(serror, SCRIPT_ERR_INVALID_TX_OUTPUT_INDEX);
                        }
                        const CTxOut &output = sis.tx->vout[idx];
                        switch (opcode)
                        {
                        case OP_OUTPUTVALUE:
                        {
                            const auto bn = CScriptNum::fromInt(output.nValue);
                            // This is only false if nVaue is -2^63, should not be possible
                            if (!bn)
                            {
                                return set_error(serror, SCRIPT_ERR_INVALID_NUMBER_RANGE);
                            }
                            PushStack(bn->getvch());
                        }
                        break;
                        case OP_OUTPUTTYPE:
                        {
                            if (!extendedIntrospectionEnabled)
                                return set_error(serror, SCRIPT_ERR_BAD_OPCODE);
                            const auto n = CScriptNum::fromInt(output.type);
                            PushStack(n->getvch());
                        }
                        break;
                        case OP_OUTPUTBYTECODE:
                        {
                            if (!withinStackWidth(output.scriptPubKey.size()))
                            {
                                return set_error(serror, SCRIPT_ERR_PUSH_SIZE);
                            }
                            PushStack(output.scriptPubKey.begin(), output.scriptPubKey.end());
                        }
                        break;
                        default:
                            break;
                        }
                    }
                    break;
                    default:
                        break;
                    }
                }
                break; // end of Native Introspection opcodes (Unary)

                case OP_PARSE:
                {
                    if (!opParseEnabled)
                    {
                        return set_error(serror, SCRIPT_ERR_BAD_OPCODE);
                    }

                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    ParseOption parseOption = (ParseOption)CScriptNum(stackItemAt(-1), true, 1).getint64();
                    PopStack();

                    if (parseOption == ParseOption::OUTPUT_DATA)
                    {
                        if (stack.size() < 3)
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                        int64_t count =
                            CScriptNum(stackItemAt(-1), false, CScriptNum::MAXIMUM_ELEMENT_SIZE_64_BIT).getint64();
                        int64_t first =
                            CScriptNum(stackItemAt(-2), false, CScriptNum::MAXIMUM_ELEMENT_SIZE_64_BIT).getint64();
                        int64_t whichOutput =
                            CScriptNum(stackItemAt(-3), false, CScriptNum::MAXIMUM_ELEMENT_SIZE_64_BIT).getint64();
                        PopStack();
                        PopStack();
                        PopStack();
                        if (first < 0 || count < 0 || whichOutput < 0)
                            return set_error(serror, SCRIPT_ERR_INVALID_NUMBER_RANGE);
                        if (whichOutput >= (int64_t)sis.tx->vout.size())
                            return set_error(serror, SCRIPT_ERR_INVALID_TX_OUTPUT_INDEX);
                        if (sis.tx->vout[whichOutput].type == CTxOut::TEMPLATE)
                        {
                            if (!EvalParseCanonicalLockingBytecode(
                                    first, count, sis.tx->vout[whichOutput].scriptPubKey))
                                return false;
                        }
                        else if (sis.tx->vout[whichOutput].type == CTxOut::SATOSCRIPT)
                        {
                            if (!EvalParseBytecode(first, count, sis.tx->vout[whichOutput].scriptPubKey))
                                return false;
                        }
                        else // the transaction should have been checked for validity first, but clearly was not
                            return set_error(serror, SCRIPT_ERR_BAD_OPERATION_ON_TYPE);
                    }
                    else if (parseOption == ParseOption::PREVOUT_DATA)
                    {
                        // You need to have provided the script machine with the prevouts to use this
                        DbgAssert(sis.spentCoins.size() == sis.tx->vin.size(),
                            return set_error(serror, SCRIPT_ERR_DATA_REQUIRED));

                        if (stack.size() < 3)
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                        int64_t count =
                            CScriptNum(stackItemAt(-1), false, CScriptNum::MAXIMUM_ELEMENT_SIZE_64_BIT).getint64();
                        int64_t first =
                            CScriptNum(stackItemAt(-2), false, CScriptNum::MAXIMUM_ELEMENT_SIZE_64_BIT).getint64();
                        int64_t whichInput =
                            CScriptNum(stackItemAt(-3), false, CScriptNum::MAXIMUM_ELEMENT_SIZE_64_BIT).getint64();
                        PopStack();
                        PopStack();
                        PopStack();
                        if (first < 0 || count < 0 || whichInput < 0)
                            return set_error(serror, SCRIPT_ERR_INVALID_NUMBER_RANGE);
                        if (whichInput >= (int64_t)sis.tx->vin.size())
                            return set_error(serror, SCRIPT_ERR_INVALID_TX_INPUT_INDEX);
                        if (sis.spentCoins[whichInput].type == CTxOut::TEMPLATE)
                        {
                            if (!EvalParseCanonicalLockingBytecode(
                                    first, count, sis.spentCoins[whichInput].scriptPubKey))
                                return false;
                        }
                        else if (sis.spentCoins[whichInput].type == CTxOut::SATOSCRIPT)
                        {
                            if (!EvalParseBytecode(first, count, sis.spentCoins[whichInput].scriptPubKey))
                                return false;
                        }
                        else // the transaction should have been checked for validity first, but clearly was not
                            return set_error(serror, SCRIPT_ERR_BAD_OPERATION_ON_TYPE);
                    }
                    else if (parseOption == ParseOption::INPUT_DATA)
                    {
                        // You need to have provided the script machine with the prevouts to use this
                        DbgAssert(sis.spentCoins.size() == sis.tx->vin.size(),
                            return set_error(serror, SCRIPT_ERR_DATA_REQUIRED));

                        if (stack.size() < 3)
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                        int64_t count =
                            CScriptNum(stackItemAt(-1), false, CScriptNum::MAXIMUM_ELEMENT_SIZE_64_BIT).getint64();
                        int64_t first =
                            CScriptNum(stackItemAt(-2), false, CScriptNum::MAXIMUM_ELEMENT_SIZE_64_BIT).getint64();
                        int64_t whichInput =
                            CScriptNum(stackItemAt(-3), false, CScriptNum::MAXIMUM_ELEMENT_SIZE_64_BIT).getint64();
                        PopStack();
                        PopStack();
                        PopStack();
                        if (first < 0 || count < 0 || whichInput < 0)
                            return set_error(serror, SCRIPT_ERR_INVALID_NUMBER_RANGE);
                        if (whichInput >= (int64_t)sis.tx->vin.size())
                            return set_error(serror, SCRIPT_ERR_INVALID_TX_INPUT_INDEX);

                        auto &coin = sis.spentCoins[whichInput];
                        if (coin.type == CTxOut::TEMPLATE)
                        {
                            if (!EvalParseUnlockingTemplateBytecode(
                                    first, count, sis.tx->vin[whichInput].scriptSig, coin.scriptPubKey))
                                return false;
                        }
                        else if (sis.spentCoins[whichInput].type == CTxOut::SATOSCRIPT)
                        {
                            if (!EvalParseBytecode(first, count, sis.tx->vin[whichInput].scriptSig))
                                return false;
                        }
                        else // the transaction should have been checked for validity first, but clearly was not
                            return set_error(serror, SCRIPT_ERR_BAD_OPERATION_ON_TYPE);
                    }

                    else if (parseOption == ParseOption::BYTECODE_DATA)
                    {
                        if (stack.size() < 3)
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                        int64_t count =
                            CScriptNum(stackItemAt(-1), false, CScriptNum::MAXIMUM_ELEMENT_SIZE_64_BIT).getint64();
                        int64_t first =
                            CScriptNum(stackItemAt(-2), false, CScriptNum::MAXIMUM_ELEMENT_SIZE_64_BIT).getint64();
                        VchType serializedScript = stackItemAt(-3).asVch();
                        PopStack();
                        PopStack();
                        PopStack();
                        if (first < 0 || count < 0)
                            return set_error(serror, SCRIPT_ERR_INVALID_NUMBER_RANGE);

                        if (!EvalParseBytecode(first, count, CScript(serializedScript.begin(), serializedScript.end())))
                            return false;
                    }
                    else
                        return set_error(serror, SCRIPT_ERR_BAD_OPCODE);
                }
                break;

                case OP_PLACE:
                {
                    if (stack.size() < 2)
                    {
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    }
                    int64_t count;
                    {
                        const StackItem &countStk = stackItemAt(-1);
                        count = countStk.asInt64(fRequireMinimal);
                        PopStack();
                    }
                    const StackItem &item = stackItemAt(-1);
                    if (count > 0)
                    {
                        if ((int64_t)stack.size() <= count)
                        {
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                        }
                        setStackItem(count, item);
                    }
                    else if ((int64_t)count < 0)
                    {
                        if ((int64_t)stack.size() <= (-1 * count) - 1)
                        {
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                        }
                        setStackItem(stack.size() + count, item);
                    }
                    // count == 0 is a no-op
                }
                break;
                case OP_SETBMD:
                {
                    if (stack.size() < 1)
                    {
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    }

                    const StackItem &top = stackItemAt(-1);
                    BigNum bn;
                    if (top.isBigNum())
                        bn = top.num();
                    else if (top.isVch())
                        bn.deserialize(top.data());
                    else
                    {
                        return set_error(serror, SCRIPT_ERR_BAD_OPERATION_ON_TYPE);
                    }
                    /* Implement R.O1: setbmd > 0 && <= 2^4096 */
                    if (bn > bigNumUpperLimit)
                        return set_error(serror, SCRIPT_ERR_INVALID_NUMBER_RANGE);
                    if (bn <= bnZero)
                        return set_error(serror, SCRIPT_ERR_INVALID_NUMBER_RANGE);
                    bigNumModulo = bn;
                    PopStack();
                }
                break;
                case OP_BIN2BIGNUM:
                {
                    if (stack.size() < 1)
                    {
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    }
                    StackItem top = stackItemAt(-1);
                    PopStack();
                    if (top.isBigNum()) // [op_bin2bignum.md#BIN2BIGNUM.O3]
                    {
                        StackItem item;
                        item.mnum() = top.num().tdiv(bigNumModulo);
                        PushStack(item);
                    }
                    else // [op_bin2bignum.md#BIN2BIGNUM.O1]
                    {
                        PushStack(BigNum().deserialize(top.asVch()).tdiv(bigNumModulo));
                    }
                }
                break;

                //
                // Conversion operations
                //
                case OP_NUM2BIN:
                {
                    // (in size -- out)
                    if (stack.size() < 2)
                    {
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    }

                    const uint64_t size = stackItemAt(-1).asUint64(fRequireMinimal);

                    if (stackItemAt(-2).isBigNum()) // Implement OP_BIGNUM2BIN
                    {
                        if (size > MAX_BIGNUM_MAGNITUDE_SIZE + 1)
                            return set_error(serror, SCRIPT_ERR_PUSH_SIZE);
                        PopStack();
                        StackItem bn = stackItemAt(-1);
                        std::vector<unsigned char> buf = bn.num().serialize(size);
                        bn.assign(buf);
                        PopStack();
                        PushStack(bn);
                        break;
                    }

                    if (!withinStackWidth(size))
                    {
                        return set_error(serror, SCRIPT_ERR_PUSH_SIZE);
                    }

                    PopStack();
                    valtype rawnum = stacktop(-1); // Take a copy

                    // Try to see if we can fit that number in the number of
                    // byte requested.
                    CScriptNum::MinimallyEncode(rawnum);
                    if ((uint64_t)rawnum.size() > size)
                    {
                        // We definitively cannot.
                        return set_error(serror, SCRIPT_ERR_IMPOSSIBLE_ENCODING);
                    }

                    // We already have an element of the right size, we
                    // don't need to do anything.
                    if ((uint64_t)rawnum.size() == size)
                    {
                        break;
                    }
                    PopStack();

                    uint8_t signbit = 0x00;
                    if (rawnum.size() > 0)
                    {
                        signbit = rawnum.back() & 0x80;
                        rawnum[rawnum.size() - 1] &= 0x7f;
                    }

                    rawnum.reserve(size);
                    while ((int)rawnum.size() < (int)size - 1)
                    {
                        rawnum.push_back(0x00);
                    }

                    rawnum.push_back(signbit);
                    PushStack(rawnum); // push the new bin array onto the stack top
                }
                break;

                case OP_BIN2NUM:
                {
                    // (in -- out)
                    if (stack.size() < 1)
                    {
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    }

                    valtype n = stacktop(-1); // Take a copy
                    CScriptNum::MinimallyEncode(n); // minimally encode it
                    PopStack(); // replace the top with the new value
                    PushStack(n); // using these ensures that the stack size tracking remains correct

                    // The resulting number must be a valid number.
                    if (!CScriptNum::IsMinimallyEncoded(n, maxIntegerSize))
                    {
                        return set_error(serror, invalidNumberRangeError);
                    }
                }
                break;

                default:
                    LOG(SCRIPT, "Unknown opcode rejected %d", opcode);
                    return set_error(serror, SCRIPT_ERR_BAD_OPCODE);
                }
            }

            // Size limits
            if (stack.size() + altstack.size() > maxStackItems)
                return set_error(serror, SCRIPT_ERR_STACK_SIZE);
        }
    }
    catch (script_error &e)
    {
        return set_error(serror, e.errNum);
    }
    catch (BadOpOnType &e)
    {
        return set_error(serror, SCRIPT_ERR_BAD_OPERATION_ON_TYPE);
    }
    catch (OutOfBounds &e)
    {
        return set_error(serror, SCRIPT_ERR_INVALID_NUMBER_RANGE);
    }
    catch (...)
    {
        return set_error(serror, SCRIPT_ERR_UNKNOWN_ERROR);
    }

    return set_success(serror);
}

bool BaseSignatureChecker::VerifySignature(const std::vector<uint8_t> &vchSig,
    const CPubKey &pubkey,
    const uint256 &sighash) const
{
    if (vchSig.size() == 64)
    {
        return pubkey.VerifySchnorr(sighash, vchSig);
    }
    return false;
}

bool TransactionSignatureChecker::CheckSig(const vector<uint8_t> &vchSigIn,
    const vector<uint8_t> &vchPubKey,
    const CScript &scriptCode) const
{
    CPubKey pubkey(vchPubKey);
    if (!pubkey.IsValid())
    {
        return false;
    }

    // Hash type is one byte tacked on to the end of the signature
    vector<unsigned char> vchSig(vchSigIn);
    if (vchSig.empty())
    {
        return false;
    }
    SigHashType sigHashType = GetSigHashType(vchSig);
    if (sigHashType.isInvalid())
        return false;
    RemoveSigHashType(vchSig);

    uint256 sighash;
    size_t nHashed = 0;
    if (txTo == nullptr || nIn >= txTo->vin.size())
        return false;
    if (!SignatureHashNexa(scriptCode, *txTo, nIn, sigHashType, sighash, &nHashed))
        return false;

    nBytesHashed += nHashed;
    ++nSigops;

    if (!VerifySignature(vchSig, pubkey, sighash))
    {
        return false;
    }

    return true;
}

bool TransactionSignatureChecker::CheckLockTime(const CScriptNum &nLockTime) const
{
    // There are two kinds of nLockTime: lock-by-blockheight
    // and lock-by-blocktime, distinguished by whether
    // nLockTime < LOCKTIME_THRESHOLD.
    //
    // We want to compare apples to apples, so fail the script
    // unless the type of nLockTime being tested is the same as
    // the nLockTime in the transaction.
    if (!((txTo->nLockTime < LOCKTIME_THRESHOLD && nLockTime < LOCKTIME_THRESHOLD) ||
            (txTo->nLockTime >= LOCKTIME_THRESHOLD && nLockTime >= LOCKTIME_THRESHOLD)))
    {
        return false;
    }

    // Now that we know we're comparing apples-to-apples, the
    // comparison is a simple numeric one.
    if (nLockTime > (int64_t)txTo->nLockTime)
    {
        return false;
    }

    // Finally the nLockTime feature can be disabled and thus
    // CHECKLOCKTIMEVERIFY bypassed if every txin has been
    // finalized by setting nSequence to maxint. The
    // transaction would be allowed into the blockchain, making
    // the opcode ineffective.
    //
    // Testing if this vin is not final is sufficient to
    // prevent this condition. Alternatively we could test all
    // inputs, but testing just this input minimizes the data
    // required to prove correct CHECKLOCKTIMEVERIFY execution.
    if (CTxIn::SEQUENCE_FINAL == txTo->vin[nIn].nSequence)
    {
        return false;
    }

    return true;
}

bool TransactionSignatureChecker::CheckSequence(const CScriptNum &nSequence) const
{
    // Relative lock times are supported by comparing the passed
    // in operand to the sequence number of the input.
    const int64_t txToSequence = (int64_t)txTo->vin[nIn].nSequence;

    // Sequence numbers with their most significant bit set are not
    // consensus constrained. Testing that the transaction's sequence
    // number do not have this bit set prevents using this property
    // to get around a CHECKSEQUENCEVERIFY check.
    if (txToSequence & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG)
    {
        return false;
    }

    // Mask off any bits that do not have consensus-enforced meaning
    // before doing the integer comparisons
    const uint32_t nLockTimeMask = CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG | CTxIn::SEQUENCE_LOCKTIME_MASK;
    const int64_t txToSequenceMasked = txToSequence & nLockTimeMask;
    const auto res = nSequence.safeBitwiseAnd(nLockTimeMask);
    if (!res)
    {
        // Defensive programming: It is impossible that this branch be taken unless the current
        // values of the operands are changed.
        return false;
    }
    const auto nSequenceMasked = *res;

    // There are two kinds of nSequence: lock-by-blockheight
    // and lock-by-blocktime, distinguished by whether
    // nSequenceMasked < CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG.
    //
    // We want to compare apples to apples, so fail the script
    // unless the type of nSequenceMasked being tested is the same as
    // the nSequenceMasked in the transaction.
    if (!((txToSequenceMasked < CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG &&
              nSequenceMasked < CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG) ||
            (txToSequenceMasked >= CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG &&
                nSequenceMasked >= CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG)))
    {
        return false;
    }

    // Now that we know we're comparing apples-to-apples, the
    // comparison is a simple numeric one.
    if (nSequenceMasked > txToSequenceMasked)
    {
        return false;
    }

    return true;
}

bool VerifySatoScript(const CScript &scriptSig,
    const CScript &scriptPubKey,
    unsigned int flags,
    unsigned int maxOps,
    const ScriptImportedState &sis,
    ScriptError *serror,
    ScriptMachineResourceTracker *tracker)
{
    set_error(serror, SCRIPT_ERR_UNKNOWN_ERROR);

    if ((flags & SCRIPT_VERIFY_SIGPUSHONLY) != 0 && !scriptSig.IsPushOnly())
    {
        LOG(SCRIPT, "Script: Scriptsig is not push-only");
        return set_error(serror, SCRIPT_ERR_SIG_PUSHONLY);
    }

    Stack stackCopy;
    ScriptMachine sm(flags, sis, maxOps, 0xffffffff);
    if (!sm.Eval(scriptSig))
    {
        if (serror)
        {
            *serror = sm.getError();
        }
        return false;
    }
    if (flags & SCRIPT_VERIFY_P2SH)
    {
        stackCopy = sm.getStack();
    }
    sm.ClearAltStack();
    if (!sm.Eval(scriptPubKey))
    {
        if (serror)
        {
            *serror = sm.getError();
        }
        return false;
    }

    {
        const Stack &smStack = sm.getStack();
        if (smStack.empty())
        {
            LOG(SCRIPT, "Script: Stack size is empty");
            return set_error(serror, SCRIPT_ERR_EVAL_FALSE);
        }
        if (((bool)smStack.back()) == false)
        {
            LOG(SCRIPT, "Script: Top of stack evaluates to false");
            return set_error(serror, SCRIPT_ERR_EVAL_FALSE);
        }
    }

    // Additional validation for spend-to-script-hash transactions:
    if ((flags & SCRIPT_VERIFY_P2SH) && scriptPubKey.IsPayToScriptHash())
    {
        // scriptSig must be literals-only or validation fails
        if (!scriptSig.IsPushOnly())
        {
            return set_error(serror, SCRIPT_ERR_SIG_PUSHONLY);
        }
        // Restore stack.
        sm.setStack(stackCopy);

        // stack cannot be empty here, because if it was the
        // P2SH  HASH <> EQUAL  scriptPubKey would be evaluated with
        // an empty stack and the EvalScript above would return false.
        assert(!stackCopy.empty());

        CScript pubKey2(stackCopy.back());
        sm.PopStack();

        sm.ClearAltStack();
        if (!sm.Eval(pubKey2))
        {
            if (serror)
            {
                *serror = sm.getError();
            }
            return false;
        }

        {
            const Stack &smStack = sm.getStack();
            if (smStack.empty())
            {
                LOG(SCRIPT, "Script: Stack size is empty");
                return set_error(serror, SCRIPT_ERR_EVAL_FALSE);
            }
            if (!((bool)smStack.back()))
            {
                LOG(SCRIPT, "Script: Top of stack evaluates to false");
                return set_error(serror, SCRIPT_ERR_EVAL_FALSE);
            }
        }
    }

    if (tracker)
    {
        auto smStats = sm.getStats();
        tracker->update(smStats);
    }

    // The CLEANSTACK check is only performed after potential P2SH evaluation,
    // as the non-P2SH evaluation of a P2SH script will obviously not result in
    // a clean stack (the P2SH inputs remain).
    if ((flags & SCRIPT_VERIFY_CLEANSTACK) != 0)
    {
        if (sm.getStack().size() != 1)
        {
            LOG(SCRIPT, "Script: Stack size is %d", sm.getStack().size());
            return set_error(serror, SCRIPT_ERR_CLEANSTACK);
        }
    }

    return set_success(serror);
}


bool VerifyScript(const CScript &scriptSig,
    const CScript &scriptPubKey,
    unsigned int flags,
    const ScriptImportedState &sis,
    ScriptError *serror,
    ScriptMachineResourceTracker *tracker)
{
    // Verify that flags are consistent, if not just continue in relase
    if (sis.checker)
        DbgAssert(flags == sis.checker->flags(), );
    unsigned int maxActualSigops = 0xFFFFFFFF; // TODO add sigop execution limits

    if (scriptPubKey.type == ScriptType::TEMPLATE)
    {
        CScript::const_iterator restOfOutput = scriptPubKey.begin();
        CGroupTokenInfo groupInfo;
        VchType templateHash;
        VchType argsHash;
        ScriptTemplateError terror =
            GetScriptTemplate(scriptPubKey, &groupInfo, &templateHash, &argsHash, &restOfOutput);
        if (terror == ScriptTemplateError::OK)
        {
            // Grab the template script (after the group in the scriptSig)
            CScript::const_iterator pc = scriptSig.begin();
            CScript templateScript;
            ScriptError templateLoadError = LoadCheckTemplateHash(scriptSig, pc, templateHash, templateScript);
            if (templateLoadError != SCRIPT_ERR_OK)
            {
                return set_error(serror, templateLoadError);
            }

            size_t argsHashSize = argsHash.size();
            std::vector<unsigned char> argsScriptBytes;
            if (argsHashSize != 0) // no hash (OP_0) means no args
            {
                // Grab the args script (its the 2nd data push in the scriptSig)
                opcodetype argsDataOpcode;
                if (!scriptSig.GetOp(pc, argsDataOpcode, argsScriptBytes))
                {
                    return set_error(serror, SCRIPT_ERR_TEMPLATE);
                }

                if (argsHashSize == CHash160::OUTPUT_SIZE)
                {
                    VchType actualArgsHash(CHash160::OUTPUT_SIZE);
                    CHash160()
                        .Write(begin_ptr(argsScriptBytes), argsScriptBytes.size())
                        .Finalize(&actualArgsHash.front());
                    if (actualArgsHash != argsHash)
                    {
                        LOG(SCRIPT, "Script template: args is incorrect preimage");
                        return set_error(serror, SCRIPT_ERR_TEMPLATE);
                    }
                }
                else if (argsHashSize == CHash256::OUTPUT_SIZE)
                {
                    VchType actualArgsHash(CHash256::OUTPUT_SIZE);
                    CHash256()
                        .Write(begin_ptr(argsScriptBytes), argsScriptBytes.size())
                        .Finalize(&actualArgsHash.front());
                    if (actualArgsHash != argsHash)
                    {
                        LOG(SCRIPT, "Script template: args is incorrect preimage");
                        return set_error(serror, SCRIPT_ERR_TEMPLATE);
                    }
                }
                else
                {
                    LOG(SCRIPT, "Script template: arg hash is incorrect size");
                    return set_error(serror, SCRIPT_ERR_TEMPLATE);
                }
            }

            CScript argsScript(argsScriptBytes.begin(), argsScriptBytes.end());
            // The visible args is the rest of the scriptPubKey
            argsScript += CScript(restOfOutput, scriptPubKey.end());
            // The rest of the scriptSig is the satisfier
            CScript satisfier(pc, scriptSig.end());

            return VerifyTemplate(templateScript, argsScript, satisfier, flags, maxScriptTemplateOps, maxActualSigops,
                sis, serror, tracker);
        }
        else
        {
            return set_error(serror, SCRIPT_ERR_TEMPLATE);
        }
    }
    else
    {
        // P2SH disabled on nexa mainnet.  Left on in regtest, testnet to maintain tests.
        if (Params().NetworkIDString() == "nexa")
            flags &= ~SCRIPT_VERIFY_P2SH;
        // Verify a "legacy"-mode script
        return VerifySatoScript(scriptSig, scriptPubKey, flags, maxSatoScriptOps, sis, serror, tracker);
    }

    // all cases should have been handled
    return set_error(serror, SCRIPT_ERR_UNKNOWN_ERROR);
}

void ScriptMachine::DbgConsistencyCheck()
{
#ifdef DEBUG
    unsigned int size = 0;
    for (auto &s : stack)
    {
        size += s.size();
    }
    unsigned int altsize = 0;
    for (auto &s : altstack)
    {
        altsize += s.size();
    }
    auto prevop = pc - 1;
    auto prevop2 = prevop;

    opcodetype opcode;
    StackItem vchPushValue;
    script->GetOp(prevop2, opcode, vchPushValue);

    // printf("%d: OP: %s pushsize: %d error: %s\n", (prevop - pbegin),GetOpName(opcode), (int) vchPushValue.size(),
    // ScriptErrorString(error)); printf("    STK: %d elems %d bytes ALT: %d elems %d bytes\n", (int) stack.size(),
    // size, (int) altstack.size(), altsize);

    DbgAssert(stackSize == size, );
    DbgAssert(stats.maxStackBytes <= MAX_SCRIPT_STACK_SIZE, );
    DbgAssert(altStackSize == altsize, );
#endif
}
