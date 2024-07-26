// Copyright (c) 2019 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_SCRIPT_BITFIELD_H
#define NEXA_SCRIPT_BITFIELD_H

#include "script/script_error.h"

#include <cstdint>
#include <vector>

bool DecodeBitfield(const std::vector<uint8_t> &vch,
    uint32_t size,
    uint32_t &bitfield,
    ScriptError *serror,
    uint32_t _flags,
    bool _fRequireMinimal,
    size_t _maxIntegerSize);
bool DecodeBitfield(const std::vector<uint8_t> &vch, uint32_t size, uint32_t &bitfield, ScriptError *serror);

#endif // NEXA_SCRIPT_BITFIELD_H
