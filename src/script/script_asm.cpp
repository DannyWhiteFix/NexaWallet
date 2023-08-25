// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "script/script.h"
#include "script/sighashtype.h"
#include "tinyformat.h"

/**
 * Create the assembly string representation of a CScript object.
 * @param[in] script    CScript object to convert into the asm string representation.
 * @param[in] fAttemptSighashDecode    Whether to attempt to decode sighash types on data within the script that matches
 * the format
 *                                     of a signature. Only pass true for scripts you believe could contain signatures.
 * For example,
 *                                     pass false, or omit the this argument (defaults to false), for scriptPubKeys.
 */
std::string ScriptToAsmStr(const CScript &script, const bool fAttemptSighashDecode)
{
    std::string str;
    opcodetype opcode;
    std::vector<unsigned char> vch;
    CScript::const_iterator pc = script.begin();
    while (pc < script.end())
    {
        if (!str.empty())
        {
            str += " ";
        }
        if (!script.GetOp(pc, opcode, vch))
        {
            str += "[error]";
            return str;
        }
        if (0 <= opcode && opcode <= OP_PUSHDATA4)
        {
            if (vch.size() <= CScriptNum::MAXIMUM_ELEMENT_SIZE_64_BIT)
            {
                str += strprintf("%ld", CScriptNum(vch, false, CScriptNum::MAXIMUM_ELEMENT_SIZE_64_BIT).getint64());
            }
            else
            {
                // the IsUnspendable check makes sure not to try to decode OP_RETURN data that may match the format of a
                // signature
                if (fAttemptSighashDecode && !script.IsUnspendable())
                {
                    std::string strSigHashDecode;
                    // goal: only attempt to decode a defined sighash type from data that looks like a signature within
                    // a scriptSig.
                    // this won't decode correctly formatted public keys in Pubkey or Multisig scripts due to
                    // the restrictions on the pubkey formats (see IsCompressedOrUncompressedPubKey) being incongruous
                    // with the
                    // checks in CheckSignatureEncoding.
                    if (CheckSignatureEncoding(vch, SCRIPT_VERIFY_STRICTENC, nullptr))
                    {
                        const SigHashType sigHashType = GetSigHashType(vch);
                        // We are just guessing that this is a signature so the sighashtype should also be valid
                        // if it is
                        if (!sigHashType.isInvalid())
                        {
                            strSigHashDecode = "[" + sigHashType.ToString() + "]";
                            RemoveSigHashType(vch); // remove the sighash type byte. it will be replaced by the decode.
                        }
                    }
                    str += HexStr(vch) + strSigHashDecode;
                }
                else
                {
                    str += HexStr(vch);
                }
            }
        }
        else
        {
            str += GetOpName(opcode);
        }
    }
    return str;
}
