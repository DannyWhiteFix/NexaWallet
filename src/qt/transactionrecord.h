// Copyright (c) 2011-2013 The Bitcoin Core developers
// Copyright (c) 2015-2023 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_QT_TRANSACTIONRECORD_H
#define NEXA_QT_TRANSACTIONRECORD_H

#include "amount.h"
#include "uint256.h"
#include "wallet/wallet.h"

#include <QList>
#include <QString>

class CWallet;
class CWalletTx;
class CGroupTokenID;

// Addresses need to preserve their txout order for accurate display so implemented as list (instead of map)
typedef std::pair<std::string, CScript> Address;
typedef std::list<Address> AddressList;

// Get the decimals from th token description
uint32_t GetDecimal(CGroupTokenID _grpID);

/** UI model for transaction status. The transaction status is the part of a transaction that will change over time.
 */
class TransactionStatus
{
public:
    TransactionStatus()
        : countsForBalance(false), sortKey(""), matures_in(0), status(Offline), depth(0), open_for(0),
          cur_num_blocks(-1)
    {
    }

    enum Status
    {
        Confirmed, /**< Have 6 or more confirmations (normal tx) or fully mature (mined tx) **/
        /// Normal (sent/received) transactions
        OpenUntilDate, /**< Transaction not yet final, waiting for date */
        OpenUntilBlock, /**< Transaction not yet final, waiting for block */
        Offline, /**< Not sent to any other nodes **/
        Unconfirmed, /**< Not yet mined into a block **/
        Confirming, /**< Confirmed, but waiting for the recommended number of confirmations **/
        Conflicted, /**< Conflicts with other transaction or mempool **/
        DoubleSpent, /** Transaction has been double spent */
        Abandoned, /** Transaction has been abandoned and removed from the mempool */
        /// Generated (mined) transactions
        Immature, /**< Mined but waiting for maturity */
        MaturesWarning, /**< Transaction will likely not mature because no nodes have confirmed */
        NotAccepted, /**< Mined but not accepted */
    };

    /// Transaction counts towards available balance
    bool countsForBalance;
    /// Sorting key based on status
    std::string sortKey;

    /** @name Generated (mined) transactions
       @{*/
    int matures_in;
    /**@}*/

    /** @name Reported status
       @{*/
    Status status;
    qint64 depth;
    qint64 open_for; /**< Timestamp if status==OpenUntilDate, otherwise number
                      of additional blocks that need to be mined before
                      finalization */
    /**@}*/

    /** Current number of blocks (to know whether cached status is still valid) */
    int cur_num_blocks;
};

/** Each TransactionRecord may also have one or a number of TokenRecords associated with it */
class TokenRecord
{
public:
    enum Type
    {
        Other,
        Generated,
        SendToAddress,
        SendToOther,
        RecvWithAddress,
        RecvFromOther,
        SendToSelf,
        PublicLabel,
        Mint,
        Melt
    };

    TokenRecord() : grpID(), time(0), type(Other), debit(0), credit(0), decimal(0) {}
    TokenRecord(CGroupTokenID _grpID, qint64 _time)
        : grpID(_grpID), time(_time), type(Other), debit(0), credit(0), decimal(0)
    {
    }

    TokenRecord(CGroupTokenID _grpID,
        qint64 _time,
        Type _type,
        const CAmount &_debit,
        const CAmount &_credit,
        uint32_t &_decimal)
        : grpID(_grpID), time(_time), type(_type), debit(_debit), credit(_credit), decimal(_decimal)
    {
    }

    bool operator==(const TokenRecord &a) const { return a.grpID == grpID; }

    /** @name Immutable token attributes
      @{*/
    CGroupTokenID grpID;
    qint64 time;
    Type type;
    CAmount debit;
    CAmount credit;
    uint32_t decimal;
    /**@}*/
};


/** UI model for a transaction. A core transaction can be represented by multiple UI transactions if it has
    multiple outputs.
 */
class TransactionRecord
{
public:
    enum Type
    {
        Other,
        Generated,
        SendToAddress,
        SendToOther,
        RecvWithAddress,
        RecvFromOther,
        SendToSelf,
        PublicLabel,
        Mint,
        Melt
    };

    /** Number of confirmation recommended for accepting a transaction */
    static const int RecommendedNumConfirmations = 6;

    TransactionRecord() : hash(), time(0), type(Other), addresses(), debit(0), credit(0), idx(0) {}
    TransactionRecord(uint256 _hash, qint64 _time)
        : hash(_hash), time(_time), type(Other), addresses(), debit(0), credit(0), idx(0)
    {
    }

    TransactionRecord(uint256 _hash,
        qint64 _time,
        Type _type,
        const AddressList &_addresses,
        const CAmount &_debit,
        const CAmount &_credit)
        : hash(_hash), time(_time), type(_type), addresses(_addresses), debit(_debit), credit(_credit), idx(0)
    {
    }

    bool operator==(const TransactionRecord &a) const { return a.hash == hash; }

    /** Decompose CWallet transaction to model transaction records.
     */
    static bool showTransaction(const CWalletTx &wtx);
    static QList<TransactionRecord> decomposeTransaction(const CWallet *wallet, const CWalletTx &wtx);

    /** @name Immutable transaction attributes
      @{*/
    uint256 hash;
    qint64 time;
    Type type;
    AddressList addresses;
    CAmount debit;
    CAmount credit;

    std::map<CGroupTokenID, TokenRecord> mapTokens;

    /**@}*/

    /** Subtransaction index, for sort key */
    int idx;

    /** Status: can change with block chain update */
    TransactionStatus status;

    /** Whether the transaction was sent/received with a watch-only address */
    bool involvesWatchAddress;

    /** Return the unique identifier for this transaction (part) */
    QString getTxID() const;

    /** Return the output index of the subtransaction  */
    int getOutputIndex() const;

    /** Update status from core wallet tx.
     */
    void updateStatus(const CWalletTxRef &wtx);

    /** Return whether a status update is needed.
     */
    bool statusUpdateNeeded();
};

#endif // NEXA_QT_TRANSACTIONRECORD_H
