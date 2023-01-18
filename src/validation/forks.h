// Copyright (c) 2018-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_FORKS_H
#define NEXA_FORKS_H

#include "amount.h"
#include "arith_uint256.h"
#include "chain.h"
#include "consensus/params.h"
#include "tweak.h"
#include "univalue/include/univalue.h"

#include <vector>

class CValidationState;
class CBlock;
class CTransaction;
class CBlockIndex;
class CScript;
class CTxMemPoolEntry;

/** Test if Nov 15th 2020 fork has activated */
// bool IsMay2022Enabled(const Consensus::Params &consensusparams, const CBlockIndex *pindexTip);

/** Check if the next will be the first block where the new set of rules will be enforced */
// bool IsMay2022Next(const Consensus::Params &consensusparams, const CBlockIndex *pindexTip);

#endif
