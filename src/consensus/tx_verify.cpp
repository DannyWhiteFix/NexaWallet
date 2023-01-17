// Copyright (c) 2017-2017 The Bitcoin Core developers
// Copyright (c) 2017-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "tx_verify.h"

#include "consensus.h"
#include "grouptokens.h"
#include "main.h"
#include "primitives/transaction.h"
#include "script/interpreter.h"
#include "tweak.h"
#include "unlimited.h"
#include "validation.h"

// TODO remove the following dependencies
#include "chain.h"
#include "coins.h"
#include "utilmoneystr.h"

#include <boost/scope_exit.hpp>

extern CTweak<bool> enforceMinTxSize;

bool IsFinalTx(const CTransactionRef tx, int nBlockHeight, int64_t nBlockTime)
{
    return IsFinalTx(tx.get(), nBlockHeight, nBlockTime);
}

bool IsFinalTx(const CTransaction *tx, int nBlockHeight, int64_t nBlockTime)
{
    if (tx->nLockTime == 0)
        return true;
    if ((int64_t)tx->nLockTime < ((int64_t)tx->nLockTime < LOCKTIME_THRESHOLD ? (int64_t)nBlockHeight : nBlockTime))
        return true;
    for (const CTxIn &txin : tx->vin)
    {
        if (!(txin.nSequence == CTxIn::SEQUENCE_FINAL))
            return false;
    }
    return true;
}

std::pair<int, int64_t> CalculateSequenceLocks(const CTransactionRef tx,
    int flags,
    std::vector<int> *prevHeights,
    const CBlockIndex &block)
{
    assert(prevHeights->size() == tx->vin.size());

    // Will be set to the equivalent height- and time-based nLockTime
    // values that would be necessary to satisfy all relative lock-
    // time constraints given our view of block chain history.
    // The semantics of nLockTime are the last invalid height/time, so
    // use -1 to have the effect of any height or time being valid.
    int nMinHeight = -1;
    int64_t nMinTime = -1;

    for (size_t txinIndex = 0; txinIndex < tx->vin.size(); txinIndex++)
    {
        const CTxIn &txin = tx->vin[txinIndex];

        // Sequence numbers with the most significant bit set are not
        // treated as relative lock-times, nor are they given any
        // consensus-enforced meaning at this point.
        if (txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG)
        {
            // The height of this input is not relevant for sequence locks
            (*prevHeights)[txinIndex] = 0;
            continue;
        }

        int nCoinHeight = (*prevHeights)[txinIndex];

        if (txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG)
        {
            int64_t nCoinTime = block.GetAncestor(std::max(nCoinHeight - 1, 0))->GetMedianTimePast();
            // NOTE: Subtract 1 to maintain nLockTime semantics
            // BIP 68 relative lock times have the semantics of calculating
            // the first block or time at which the transaction would be
            // valid. When calculating the effective block time or height
            // for the entire transaction, we switch to using the
            // semantics of nLockTime which is the last invalid block
            // time or height.  Thus we subtract 1 from the calculated
            // time or height.

            // Time-based relative lock-times are measured from the
            // smallest allowed timestamp of the block containing the
            // txout being spent, which is the median time past of the
            // block prior.
            nMinTime = std::max(nMinTime, nCoinTime +
                                              (int64_t)((txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_MASK)
                                                        << CTxIn::SEQUENCE_LOCKTIME_GRANULARITY) -
                                              1);
        }
        else
        {
            nMinHeight = std::max(nMinHeight, nCoinHeight + (int)(txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_MASK) - 1);
        }
    }

    return std::make_pair(nMinHeight, nMinTime);
}

bool EvaluateSequenceLocks(const CBlockIndex &block, std::pair<int, int64_t> lockPair)
{
    assert(block.pprev);
    int64_t nBlockTime = block.pprev->GetMedianTimePast();
    if (lockPair.first >= block.height() || lockPair.second >= nBlockTime)
        return false;

    return true;
}

bool SequenceLocks(const CTransactionRef tx, int flags, std::vector<int> *prevHeights, const CBlockIndex &block)
{
    return EvaluateSequenceLocks(block, CalculateSequenceLocks(tx, flags, prevHeights, block));
}

// BU: This code is completely inaccurate if its used to determine the approximate time of transaction
// validation!!!  The sigop count in the output transactions are irrelevant, and the sigop count of the
// previous outputs are the most relevant, but not actually checked.
// The purpose of this is to limit the outputs of transactions so that other transactions' "prevout"
// is reasonably sized.
unsigned int GetLegacySigOpCount(const CTransactionRef tx, const uint32_t flags)
{
    unsigned int nSigOps = 0;
    for (const auto &txin : tx->vin)
    {
        nSigOps += txin.scriptSig.GetSigOpCount(flags, false);
    }
    for (const auto &txout : tx->vout)
    {
        nSigOps += txout.scriptPubKey.GetSigOpCount(flags, false);
    }
    return nSigOps;
}

unsigned int GetP2SHSigOpCount(const CTransactionRef tx, const CCoinsViewCache &inputs, const uint32_t flags)
{
    if ((flags & SCRIPT_VERIFY_P2SH) == 0 || tx->IsCoinBase())
        return 0;

    unsigned int nSigOps = 0;
    {
        for (unsigned int i = 0; i < tx->vin.size(); i++)
        {
            CoinAccessor coin(inputs, tx->vin[i].prevout);
            if (coin && coin->out.scriptPubKey.IsPayToScriptHash())
                nSigOps += coin->out.scriptPubKey.GetSigOpCount(flags, tx->vin[i].scriptSig);
        }
    }
    return nSigOps;
}

bool ContextualCheckTransaction(const CTransactionRef tx,
    CValidationState &state,
    CBlockIndex *const pindexPrev,
    const CChainParams &params)
{
    // Commented out until needed again.
    // const int nHeight = pindexPrev == nullptr ? 0 : pindexPrev->height() + 1;
    // auto consensusParams = params.GetConsensus();

    return true;
}

bool CheckTransaction(const CTransactionRef tx, CValidationState &state)
{
    // nVersion is uint8_t and cannot be negative
    if (tx->nVersion > CTransaction::CURRENT_VERSION)
    {
        return state.DoS(100, false, REJECT_INVALID, "bad-txns-version");
    }
    // Basic checks that don't depend on any context
    if (tx->vout.empty())
        return state.DoS(10, false, REJECT_INVALID, "bad-txns-vout-empty");

    // Size limit
    if (tx->GetTxSize() > DEFAULT_LARGEST_TRANSACTION)
    {
        return state.DoS(100, false, REJECT_INVALID, "bad-txns-oversize");
    }

    // Make sure tx size is equal to or above the minimum allowed
    if ((tx->GetTxSize() < MIN_TX_SIZE) && enforceMinTxSize.Value())
    {
        return state.DoS(
            10, error("%s: contains transactions that are too small", __func__), REJECT_INVALID, "txn-undersize");
    }

    if (tx->vout.size() > MAX_TX_NUM_VOUT)
        return state.DoS(100, false, REJECT_INVALID, "bad-txns-too-many-vout");
    if (tx->vin.size() > MAX_TX_NUM_VIN)
        return state.DoS(100, false, REJECT_INVALID, "bad-txns-too-many-vin");

    // Check for negative or overflow output values
    CAmount nValueOut = 0;
    for (const CTxOut &txout : tx->vout)
    {
        if ((txout.type != CTxOut::SATOSCRIPT) && (txout.type != CTxOut::TEMPLATE))
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-invalid-txout-type");
        if (txout.nValue < 0)
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-vout-negative");
        if (txout.nValue > MAX_MONEY)
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-vout-toolarge");
        nValueOut += txout.nValue;
        if (!MoneyRange(nValueOut))
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-txouttotal-toolarge");
    }

    if (tx->IsCoinBase())
    {
        // Coinbase tx can't have group outputs because it has no group inputs or mintable outputs
        if (IsAnyTxOutputGrouped(*tx))
            return state.DoS(100, false, REJECT_INVALID, "coinbase-has-group-outputs");
        // That the coinbase last vout is OP_RETURN, and that it has the proper height is validated in
        // ContextualCheckBlock.  We validate what we can here as well (cannot validate height)
        if (tx->vout.size() < 1)
            return state.DoS(100, false, REJECT_INVALID, "coinbase-last-vout-op-return");
        const CScript &script = tx->vout[tx->vout.size() - 1].scriptPubKey;
        if (script[0] != OP_RETURN)
            return state.DoS(100, false, REJECT_INVALID, "coinbase-last-vout-op-return");
    }
    else
    {
        if (tx->vin.empty())
            return state.DoS(10, false, REJECT_INVALID, "bad-txns-vin-empty");

        for (const CTxIn &txin : tx->vin)
        {
            if (txin.type != CTxIn::UTXO)
                return state.DoS(100, false, REJECT_INVALID, "bad-txns-invalid-txin-type");
        }

        // Check for duplicate inputs.
        // Simply checking every pair is O(n^2).
        // Sorting a vector and checking adjacent elements is O(n log n).
        // However, the vector requires a memory allocation, copying and sorting.
        // This is significantly slower for small transactions. The crossover point
        // was measured to be a vin.size() of about 120 on x86-64.
        if (tx->vin.size() < 120)
        {
            for (size_t i = 0; i < tx->vin.size(); ++i)
            {
                if (tx->vin[i].prevout.IsNull())
                {
                    return state.DoS(10, false, REJECT_INVALID, "bad-txns-prevout-null");
                }
                for (size_t j = i + 1; j < tx->vin.size(); ++j)
                {
                    if (tx->vin[i].prevout == tx->vin[j].prevout)
                    {
                        return state.DoS(100, false, REJECT_INVALID, "bad-txns-inputs-duplicate");
                    }
                }
            }
        }
        else
        {
            std::vector<const COutPoint *> sortedPrevOuts(tx->vin.size());
            for (size_t i = 0; i < tx->vin.size(); ++i)
            {
                if (tx->vin[i].prevout.IsNull())
                {
                    return state.DoS(10, false, REJECT_INVALID, "bad-txns-prevout-null");
                }
                sortedPrevOuts[i] = &tx->vin[i].prevout;
            }
            std::sort(sortedPrevOuts.begin(), sortedPrevOuts.end(),
                [](const COutPoint *a, const COutPoint *b) { return *a < *b; });
            auto it = std::adjacent_find(sortedPrevOuts.begin(), sortedPrevOuts.end(),
                [](const COutPoint *a, const COutPoint *b) { return *a == *b; });
            if (it != sortedPrevOuts.end())
            {
                return state.DoS(100, false, REJECT_INVALID, "bad-txns-inputs-duplicate");
            }
        }
    }

    return true;
}

/**
 * Return the spend height, which is one more than the inputs.GetBestBlock().
 * While checking, GetBestBlock() refers to the parent block. (protected by cs_main)
 * This is also true for mempool checks.
 */
static int GetSpendHeight(const CCoinsViewCache &inputs)
{
    READLOCK(cs_mapBlockIndex);
    BlockMap::iterator i = mapBlockIndex.find(inputs.GetBestBlock());
    if (i != mapBlockIndex.end())
    {
        CBlockIndex *pindexPrev = i->second;
        if (pindexPrev)
            return pindexPrev->height() + 1;
        else
        {
            throw std::runtime_error("GetSpendHeight(): mapBlockIndex contains null block");
        }
    }
    throw std::runtime_error("GetSpendHeight(): best block does not exist");
}

bool Consensus::CheckTxInputs(const CTransactionRef tx,
    CValidationState &state,
    const CCoinsViewCache &inputs,
    const CChainParams &chainparams)
{
    // This doesn't trigger the DoS code on purpose; if it did, it would make it easier
    // for an attacker to attempt to split the network.
    if (!inputs.HaveInputs(*tx))
        return state.Invalid(false, 0, "", "Inputs unavailable");

    CAmount nValueIn = 0;
    int nSpendHeight = -1;
    {
        for (unsigned int i = 0; i < tx->vin.size(); i++)
        {
            const COutPoint &prevout = tx->vin[i].prevout;
            Coin coin;
            inputs.GetCoin(prevout, coin); // Make a copy so I don't hold the utxo lock
            assert(!coin.IsSpent());

            // If prev is coinbase, check that it's matured
            if (coin.IsCoinBase())
            {
                // Copy these values here because once we unlock and re-lock cs_utxo we can't count on "coin"
                // still being valid.
                CAmount nCoinOutValue = coin.out.nValue;
                int nCoinHeight = coin.nHeight;

                // If there are multiple coinbase spends we still only need to get the spend height once.
                if (nSpendHeight == -1)
                {
                    nSpendHeight = GetSpendHeight(inputs);
                }
                if (nSpendHeight - nCoinHeight < chainparams.GetConsensus().coinbaseMaturity)
                    return state.Invalid(false, REJECT_INVALID, "bad-txns-premature-spend-of-coinbase",
                        strprintf("tried to spend coinbase at depth %d", nSpendHeight - nCoinHeight));

                // Check for negative or overflow input values.  We use nCoinOutValue which was copied before
                // we released cs_utxo, because we can't be certain the value didn't change during the time
                // cs_utxo was unlocked.
                nValueIn += nCoinOutValue;
                if (!MoneyRange(nCoinOutValue) || !MoneyRange(nValueIn))
                    return state.DoS(100, false, REJECT_INVALID, "bad-txns-inputvalues-outofrange");
            }
            else
            {
                // Check for negative or overflow input values
                nValueIn += coin.out.nValue;
                if (!MoneyRange(coin.out.nValue) || !MoneyRange(nValueIn))
                    return state.DoS(100, false, REJECT_INVALID, "bad-txns-inputvalues-outofrange");
            }
        }
    }

    CAmount outAmount = tx->GetValueOut();
    if (nValueIn < outAmount)
        return state.DoS(100, false, REJECT_INVALID, "bad-txns-in-belowout", false,
            strprintf("value in (%s) < value out (%s)", FormatMoney(nValueIn), FormatMoney(tx->GetValueOut())));

    // Tally transaction fees
    CAmount nTxFee = nValueIn - outAmount;
    if (nTxFee < 0)
        return state.DoS(100, false, REJECT_INVALID, "bad-txns-fee-negative");
    if (!MoneyRange(nTxFee))
        return state.DoS(100, false, REJECT_INVALID, "bad-txns-fee-outofrange");
    state.SetAmounts(nValueIn, outAmount, nTxFee);
    return true;
}

uint64_t GetTransactionSigOpCount(const CTransactionRef ptx, const CCoinsViewCache &coins, const uint32_t flags)
{
    return GetLegacySigOpCount(ptx, flags) + GetP2SHSigOpCount(ptx, coins, flags);
}
