// Copyright (c) 2020 G. Andrew Stone
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "script/bignum.h"
#include "script/script.h"

#ifndef ANDROID
const BigNum bnZero = 0_BN;
const BigNum bnOne = 1_BN;
const BigNum bnInt64Max(std::numeric_limits<int64_t>::max());
const BigNum bnUint64Max = 0x10000000000000000_BN - 1; // can't use int ctor because it is not uint
const BigNum &bnFalse(bnZero);
const BigNum &bnTrue(bnOne);

BigNum bigNumUpperLimit = bnOne << 4096; // if !(x < upperLimit) throw NUMBER_OUT_OF_RANGE;
BigNum bigNumLowerLimit = -bigNumUpperLimit; // if !(x > lowerLimit) throw NUMBER_OUT_OF_RANGE;

bool BigNumScriptOp(BigNum &bn,
    opcodetype opcode,
    const BigNum &bn1,
    const BigNum &bn2,
    const BigNum &bmd,
    ScriptError *serror)
{
    switch (opcode)
    {
    case OP_ADD:
        bn = bn1 + bn2;
        break;

    case OP_SUB:
        bn = bn1 - bn2;
        break;

    case OP_DIV:
        // denominator must not be 0
        if (bn2 == bnZero)
        {
            return set_error(serror, SCRIPT_ERR_DIV_BY_ZERO);
        }
        bn = bn1 / bn2;
        break;

    case OP_MOD:
        // divisor must not be 0
        if (bn2 == bnZero)
        {
            return set_error(serror, SCRIPT_ERR_MOD_BY_ZERO);
        }
        bn = bn1 % bn2;
        break;

    case OP_BOOLAND:
        bn = (bn1 != bnZero && bn2 != bnZero);
        break;
    case OP_BOOLOR:
        bn = (bn1 != bnZero || bn2 != bnZero);
        break;
    case OP_NUMEQUAL:
        bn = (bn1 == bn2);
        break;
    case OP_NUMEQUALVERIFY:
        bn = (bn1 == bn2);
        break;
    case OP_NUMNOTEQUAL:
        bn = (bn1 != bn2);
        break;
    case OP_LESSTHAN:
        bn = (bn1 < bn2);
        break;
    case OP_GREATERTHAN:
        bn = (bn1 > bn2);
        break;
    case OP_LESSTHANOREQUAL:
        bn = (bn1 <= bn2);
        break;
    case OP_GREATERTHANOREQUAL:
        bn = (bn1 >= bn2);
        break;
    case OP_MIN:
        bn = (bn1 < bn2 ? bn1 : bn2);
        break;
    case OP_MAX:
        bn = (bn1 > bn2 ? bn1 : bn2);
        break;
    case OP_MUL:
        bn = bn1 * bn2;
        // gmp_printf("%Zd * %Zd = %Zd\n", bn1.n, bn2.n, bn.n);
        break;
    default:
        assert(!"invalid opcode");
        break;
    }
    bn.thisTdiv(bmd);
    // gmp_printf("bn: %Zd bmd: %Zd \n", bn.n, bmd.n);
    return true;
}

#else // None of this is implemented in android
const BigNum bnZero;
const BigNum bnOne;
const BigNum &bnFalse(bnZero);
const BigNum &bnTrue(bnOne);
const BigNum bnInt64Max;
const BigNum bnUint64Max;

BigNum bigNumUpperLimit;
BigNum bigNumLowerLimit;

bool BigNumScriptOp(BigNum &bn,
    opcodetype opcode,
    const BigNum &bn1,
    const BigNum &bn2,
    const BigNum &bmd,
    ScriptError *serror)
{
    return false;
}
#endif
