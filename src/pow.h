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

/* Solve this block.  Not for performance use. The function modifies the nonce but does not change its size.
   NOTE: if nonce size is 0 or small, there may be no solution ever found!
 */
bool MineBlock(CBlockHeader &blockHeader, unsigned long int tries, const Consensus::Params &cparams);

unsigned int GetNextWorkRequired(const CBlockIndex *pindexLast, const CBlockHeader *pblock, const Consensus::Params &);

/** Check whether a block hash satisfies the proof-of-work requirement specified by nBits */
bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params &);

#endif // NEXA_POW_H
