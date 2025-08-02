// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_POW_H
#define NEXA_POW_H

#include "consensus/params.h"
#include <stdint.h>

class CBlockHeader;
class CBlockIndex;
class uint256;
class arith_uint256;

/** Check whether a block hash satisfies the proof-of-work requirement specified by nBits */
bool CheckProofOfWork(const uint256 &hash, unsigned int nBits, const Consensus::Params &);

bool CheckProofOfWork(uint256 hash,
    const arith_uint256 &bnTarget,
    const Consensus::Params &params,
    arith_uint256 *hashout);

#endif // NEXA_POW_H
