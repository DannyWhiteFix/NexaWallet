// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "checkpoints.h"

#include "chain.h"
#include "chainparams.h"
#include "main.h"
#include "uint256.h"

#include <stdint.h>

extern std::atomic<uint64_t> nTotalChainTx;

namespace Checkpoints
{
/**
 * How many times slower we expect checking transactions
 * to be (from checking signatures, which is skipped before the last 30 days of blocks).
 * This number is a compromise, as it can't be accurate
 * for every system. When reindexing from a fast disk with a slow CPU, it
 * can be up to 20, while when downloading from a slow network with a
 * fast multicore CPU, it won't be much higher than 1.
 */
static const double SIGCHECK_VERIFICATION_FACTOR = 5.0;

//! Guess how far we are in the verification process at the given block index
double GuessVerificationProgress(CBlockIndex *pindex, bool fSigchecks)
{
    if (pindex == nullptr || pindexBestHeader == nullptr || chainActive.Tip() == nullptr)
        return 0.0;

    // Calculate the total work to sync the chain
    uint64_t nChainHeight = chainActive.Height();
    uint64_t nScriptChecksWindow = checkScriptDays.Value() * ONE_DAY_OF_BLOCKS;
    uint64_t nStartSigChecksHeight = (nChainHeight > nScriptChecksWindow ? nChainHeight - nScriptChecksWindow : 0);

    double dTotalWorkDone = 0;
    double dTotalWork = 0;
    if (fSigchecks)
    {
        dTotalWork = SIGCHECK_VERIFICATION_FACTOR * nTotalChainTx.load();
        dTotalWorkDone = SIGCHECK_VERIFICATION_FACTOR * pindex->nChainTx;
    }
    else
    {
        uint64_t nChainTxForStartSigChecksHeight = chainActive._idx(nStartSigChecksHeight)->nChainTx;
        dTotalWork = 1.0 * nChainTxForStartSigChecksHeight;
        dTotalWork += SIGCHECK_VERIFICATION_FACTOR * (nTotalChainTx.load() - nChainTxForStartSigChecksHeight);

        if ((uint64_t)pindex->height() <= nStartSigChecksHeight)
        {
            dTotalWorkDone = 1.0 * pindex->nChainTx;
        }
        else
        {
            dTotalWorkDone = 1.0 * nChainTxForStartSigChecksHeight;
            dTotalWorkDone += SIGCHECK_VERIFICATION_FACTOR * (pindex->nChainTx - nChainTxForStartSigChecksHeight);
        }
    }

    double dVerificationProgress = dTotalWorkDone / dTotalWork;
    if (dTotalWork <= 0)
        return 0.0;
    else if (pindexBestHeader.load()->height() < Checkpoints::GetTotalBlocksEstimate(Params().Checkpoints()) &&
             dVerificationProgress == 1.0) // we don't want to return 1.0 (complete) at the very beginning of our sync
        return 0.0;
    else
        return dVerificationProgress;
}

int GetTotalBlocksEstimate(const CCheckpointData &data)
{
    const MapCheckpoints &checkpoints = data.mapCheckpoints;

    if (checkpoints.empty())
        return 0;

    return checkpoints.rbegin()->first;
}

CBlockIndex *GetLastCheckpoint(const CCheckpointData &data)
{
    const MapCheckpoints &checkpoints = data.mapCheckpoints;

    READLOCK(cs_mapBlockIndex);
    for (auto i = checkpoints.rbegin(); i != checkpoints.rend(); i++)
    {
        const uint256 &hash = i->second;
        BlockMap::const_iterator t = mapBlockIndex.find(hash);
        if (t != mapBlockIndex.end())
            return t->second;
    }
    return nullptr;
}
} // namespace Checkpoints
