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

bool ContextualCheckTransaction(const CTransactionRef tx,
    CValidationState &state,
    CBlockIndex *const pindexPrev,
    const CChainParams &params)
{
    for (const CTxIn &txin : tx->vin)
    {
        // if fork 1 has not yet been enabled, only fork 0 types are valid
        if (!IsFork1Activated(pindexPrev))
        {
            // check if the txin type is outside the range of valid types for the last fork
            // fork 0 means valid before the first HF
            if (txin.type > CTxIn::VALID_FORK0_TYPES)
            {
                return state.DoS(100, false, REJECT_INVALID, "invalid-txin-type-for-block");
            }
        }
        // template for further hard forks
        /*
        // if fork 2 has not yet been enabled, only fork 0 and 1 types are valid
        if (!IsFork2Enabled(pindexPrev))
        {
            if (txin.type > CTxIn::VALID_FORK1_TYPES)
            {
                return state.DoS(100, false, REJECT_INVALID, "invalid-txin-type-for-block");
            }
        }
        */
    }

    if (IsFork1Activated(pindexPrev) || IsFork1Pending(pindexPrev))
    {
        for (const CTxOut &txout : tx->vout)
        {
            // Only legacy non-template outputs are allowed now.  All real scripts MUST use the script template
            // system.
            if (txout.type == CTxOut::SATOSCRIPT)
            {
                txnouttype whichType;
                if (!IsStandard(txout.scriptPubKey, whichType))
                {
                    // We allow P2SH on regtest until all tests are converted over
                    if (!((whichType == TX_SCRIPTHASH) && (params.NetworkIDString() == "regtest")))
                        return state.DoS(100, false, REJECT_INVALID, "invalid-nonstandard-legacy-output");
                }
                // SCRIPT_HASH is already considered nonstandard, so is handled above
                if (whichType == TX_PUBKEY)
                {
                    return state.DoS(100, false, REJECT_INVALID, "invalid-legacy-output");
                }
            }

            if (txout.type == CTxOut::TEMPLATE)
            {
                CGroupTokenInfo groupInfo;
                std::vector<uint8_t> templateHash;
                std::vector<uint8_t> argsHash;
                ScriptTemplateError err =
                    GetScriptTemplate(txout.scriptPubKey, &groupInfo, &templateHash, &argsHash, nullptr);
                if (err != ScriptTemplateError::OK)
                    return state.DoS(100, false, REJECT_INVALID, "invalid-script-template");

                size_t argsHashSize = argsHash.size();
                // allow 2 different hash types, or no hashed args
                if ((argsHashSize != CHash160::OUTPUT_SIZE) && (argsHashSize != CHash256::OUTPUT_SIZE) &&
                    (argsHashSize != 0))
                {
                    return state.DoS(100, false, REJECT_INVALID, "invalid-script-template-argshash");
                }

                // Note the template hash size is constrained since genesis block in
                // GetScriptTemplate->ParseWellKnownTemplateHashArg
            }
        }
    }

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

        int nConsumed = 0;
        for (const CTxIn &txin : tx->vin)
        {
            if (txin.type >= CTxIn::INVALID)
            {
                return state.DoS(100, false, REJECT_INVALID, "bad-txns-invalid-txin-type");
            }
            if (txin.IsReadOnly())
            {
                if (txin.nSequence != 0)
                {
                    return state.DoS(100, false, REJECT_INVALID, "bad-txns-invalid-readonly-sequence");
                }
                if (txin.amount != 0)
                {
                    return state.DoS(100, false, REJECT_INVALID, "bad-txns-nonzero-readonly-amount");
                }
            }
            else
                nConsumed++;
        }

        if (nConsumed == 0)
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-vin-entirely-readonly");

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
    const CCoinsViewCache &readonlyCoins,
    const CChainParams &chainparams)
{
    // This doesn't trigger the DoS code on purpose; if it did, it would make it easier
    // for an attacker to attempt to split the network.
    for (const CTxIn &input : tx->vin)
    {
        if (input.IsReadOnly())
        {
            if (!readonlyCoins.HaveCoin(input.prevout))
            {
                return state.Invalid(false, 0, "", "Inputs unavailable");
            }
        }
        else
        {
            if (!inputs.HaveCoin(input.prevout))
            {
                return state.Invalid(false, 0, "", "Inputs unavailable");
            }
        }
    }

    CAmount nValueIn = 0;
    int nSpendHeight = -1;
    {
        for (unsigned int i = 0; i < tx->vin.size(); i++)
        {
            const COutPoint &prevout = tx->vin[i].prevout;
            Coin coin;
            // Make a copy so I don't hold the utxo lock
            if (tx->vin[i].IsReadOnly())
            {
                readonlyCoins.GetCoin(prevout, coin);
            }
            else
            {
                inputs.GetCoin(prevout, coin);
            }
            assert(!coin.IsSpent());
            CAmount nCoinOutValue = tx->vin[i].amount;
            // If prev is coinbase, check that it's matured
            if (coin.IsCoinBase())
            {
                // Copy these values here because once we unlock and re-lock cs_utxo we can't count on "coin"
                // still being valid.
                int nCoinHeight = coin.nHeight;

                // If there are multiple coinbase spends we still only need to get the spend height once.
                if (nSpendHeight == -1)
                {
                    nSpendHeight = GetSpendHeight(inputs);
                }
                if (nSpendHeight - nCoinHeight < chainparams.GetConsensus().coinbaseMaturity)
                    return state.Invalid(false, REJECT_INVALID, "bad-txns-premature-spend-of-coinbase",
                        strprintf("tried to spend coinbase at depth %d", nSpendHeight - nCoinHeight));
            }

            // Check for negative or overflow input values.  We use nCoinOutValue which was copied before
            // we released cs_utxo, because we can't be certain the value didn't change during the time
            // cs_utxo was unlocked.
            if (tx->vin[i].IsReadOnly() == false)
            {
                nValueIn += nCoinOutValue;
                if (!MoneyRange(nCoinOutValue) || !MoneyRange(nValueIn))
                    return state.DoS(100, false, REJECT_INVALID, "bad-txns-inputvalues-outofrange");
            }
        }
    }

    CAmount outAmount = tx->GetValueOut();
    if (nValueIn < outAmount)
    {
        return state.DoS(100, false, REJECT_INVALID, "bad-txns-in-belowout", false,
            strprintf("value in (%s) < value out (%s)", FormatMoney(nValueIn), FormatMoney(tx->GetValueOut())));
    }

    // Tally transaction fees
    CAmount nTxFee = nValueIn - outAmount;
    if (nTxFee < 0)
        return state.DoS(100, false, REJECT_INVALID, "bad-txns-fee-negative");
    if (!MoneyRange(nTxFee))
        return state.DoS(100, false, REJECT_INVALID, "bad-txns-fee-outofrange");
    state.SetAmounts(nValueIn, outAmount, nTxFee);
    return true;
}
