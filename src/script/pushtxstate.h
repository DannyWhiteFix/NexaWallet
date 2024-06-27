// Copyright (c) 2020 G. Andrew Stone
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_PUSHTXSTATE_H
#define NEXA_PUSHTXSTATE_H
#include "script/script_error.h"

#include <vector>

enum PushTxStateSpecifier
{
    TX_ID = 0x2,
    TX_IDEM = 0x3,
    TX_INCOMING_AMOUNT = 0x5,
    TX_OUTGOING_AMOUNT = 0x6,
    GROUP_INCOMING_AMOUNT = 0x7, // This is either the token amount for a particular group or the fenced Nexa amount
    GROUP_OUTGOING_AMOUNT = 0x8,
    GROUP_INCOMING_COUNT = 0x9, // COUNT is the number of inputs or outputs
    GROUP_OUTGOING_COUNT = 0xA,
    GROUP_NTH_INPUT = 0xB, // Returns the index of the Nth grouped (of the passed group) input
    GROUP_NTH_OUTPUT = 0xC, // Returns the index of the Nth grouped (of the passed group) output
    GROUP_COVENANT_HASH = 0xD,
    GROUP_AUTHORITY_FLAGS = 0xE,
};

class ScriptMachine;

typedef std::vector<unsigned char> VchType;

// Applies the specifier to the data in sm.sis to generate items that are pushed onto the passed stack.
ScriptError EvalPushTxState(const VchType &specifier, ScriptMachine &sm);

#endif
