// Copyright (c) 2018 The Bitcoin developers
// Copyright (c) 2018-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_TEST_SCRIPTFLAGS_H
#define NEXA_TEST_SCRIPTFLAGS_H

#include <string>
#include <cstdint>

uint32_t ParseScriptFlags(std::string strFlags);
std::string FormatScriptFlags(uint32_t flags);

#endif // NEXA_TEST_SCRIPTFLAGS_H
