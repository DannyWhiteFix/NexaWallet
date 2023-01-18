// Copyright (c) 2019-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_TXLOOKUP_H

#include <cstdint>

static const int64_t TX_NOT_FOUND = -1;

class CBlock;
class uint256;

/// Finds the position of a transaction in a block.
/// \return position in block, or negative value on error
int64_t FindTxPosition(const CBlock &block, const uint256 &txhash);

#endif
