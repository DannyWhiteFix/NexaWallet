
// Copyright (c) 2025 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_HEADER_VALIDATION_H
#define NEXA_HEADER_VALIDATION_H

#include "consensus/validation.h"

/** Context-independent validity checks */
bool CheckBlockHeader(const Consensus::Params &consensusParams,
    const CBlockHeader &block,
    CValidationState &state,
    bool fCheckPOW = true);

bool CheckTailstormSummaryBlockProofOfWork(const Consensus::Params &consensusParams,
    const CBlockHeader &block,
    CValidationState &state);

#endif
