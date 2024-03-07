// Copyright (c) 2022-2024 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "utilgrouptoken.h"

bool GetTokenDescription(const CScript &script, std::vector<std::string> &_vDesc)
{
    _vDesc.clear();

    CScript::const_iterator pc = script.begin();
    opcodetype op;
    std::vector<unsigned char> vchRet;

    // Check we have an op_return
    script.GetOp(pc, op, vchRet);
    if (op != OP_RETURN)
        return false;

    // Check for correct group id
    script.GetOp(pc, op, vchRet);
    uint32_t grpId;
    std::stringstream ss;
    std::reverse(vchRet.begin(), vchRet.end());
    ss << std::hex << HexStr(vchRet);
    ss >> grpId;
    if (grpId != DEFAULT_OP_RETURN_GROUP_ID)
        return false;

    // Get labels
    int count = 0;
    while (script.GetOp(pc, op, vchRet))
    {
        if (op != OP_0)
        {
            if (count != 4)
            {
                if (count == 3)
                {
                    // Convert hash stored as a vector of unsigned chars to a string.
                    uint256 hash(&vchRet.data()[0]);
                    _vDesc.push_back(hash.ToString());
                }
                else
                {
                    std::string s(vchRet.begin(), vchRet.end());
                    _vDesc.push_back(s);
                }
            }
            else // 5th parameter in op return is the number of decimals
            {
                uint8_t amt;
                if (0 <= op && op <= OP_PUSHDATA4)
                {
                    amt = CScriptNum(vchRet, false, CScriptNum::MAXIMUM_ELEMENT_SIZE_64_BIT).getint64();
                }
                else if (op == 0)
                    amt = 0;
                else
                    amt = op - OP_1 + 1;
                _vDesc.push_back(std::to_string(amt));
            }
        }
        else
            _vDesc.push_back("");
        count++;
    }

    if (!_vDesc.empty())
    {
        while (_vDesc.size() < 4)
        {
            _vDesc.push_back("");
        }
        while (_vDesc.size() < 5)
        {
            _vDesc.push_back("0");
        }
    }
    else
    {
        std::vector<std::string> vEmptyDesc{"", "", "", "", "0"};
        _vDesc.swap(vEmptyDesc);
    }
    return true;
}
