// Copyright (c) 2019-2021 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "txlookup.h"
#include "primitives/block.h"
#include "uint256.h"

#include <algorithm>


static int64_t pos_lookup_by_idem(const CBlock &block, const uint256 &tx)
{
    for (size_t i = 0; i < block.vtx.size(); ++i)
    {
        if (block.vtx[i]->GetIdem() == tx)
        {
            return i;
        }
    }
    return TX_NOT_FOUND;
}

static int64_t ctor_pos_lookup(const CBlock &block, const uint256 &tx)
{
    // Coinbase is not sorted and thus needs special treatment
    if (block.vtx[0]->GetId() == tx)
    {
        return 0;
    }

    auto compare = [](auto &blocktx, const uint256 &lookuptx) { return blocktx->GetId() < lookuptx; };

    auto it = std::lower_bound(begin(block.vtx) + 1, end(block.vtx), tx, compare);

    if (it == end(block.vtx))
    {
        return TX_NOT_FOUND;
    }
    if ((*it)->GetId() == tx)
    {
        return std::distance(begin(block.vtx), it);
    }
    else
    {
        return TX_NOT_FOUND;
    }
}


/// Finds the position of a transaction in a block.
/// \return
int64_t FindTxPositionById(const CBlock &block, const uint256 &txhash)
{
    if (block.vtx.size() == 0)
    {
        // invalid block
        return TX_NOT_FOUND;
    }
    return ctor_pos_lookup(block, txhash);
}

/// Finds the position of a transaction in a block by idem.
/// \return
int64_t FindTxPosition(const CBlock &block, const uint256 &txhash)
{
    if (block.vtx.size() == 0)
    {
        // invalid block
        return TX_NOT_FOUND;
    }
    int64_t ret = ctor_pos_lookup(block, txhash);
    if (ret == TX_NOT_FOUND)
        return pos_lookup_by_idem(block, txhash);
    return ret;
}
