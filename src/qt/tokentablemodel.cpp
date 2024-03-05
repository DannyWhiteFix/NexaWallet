// Copyright (c) 2011-2015 The Bitcoin Core developers
// Copyright (c) 2015-2023 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "tokentablemodel.h"

#include "addresstablemodel.h"
#include "guiconstants.h"
#include "guiutil.h"
#include "optionsmodel.h"
#include "platformstyle.h"
#include "transactiondesc.h"
#include "walletmodel.h"

#include "core_io.h"
#include "main.h"
#include "sync.h"
#include "uint256.h"
#include "util.h"
#include "wallet/wallet.h"

#include <boost/algorithm/string/replace.hpp>

#include <QColor>
#include <QDateTime>
#include <QDebug>
#include <QIcon>
#include <QList>

#include <algorithm>
// Amount column is right-aligned it contains numbers
static int column_alignments[] = {
    Qt::AlignLeft | Qt::AlignVCenter, /* status */
    Qt::AlignLeft | Qt::AlignVCenter, /* watchonly */
    Qt::AlignLeft | Qt::AlignVCenter, /* date */
    Qt::AlignLeft | Qt::AlignVCenter, /* type */
    Qt::AlignLeft | Qt::AlignVCenter, /* address */
    Qt::AlignRight | Qt::AlignVCenter /* amount */
};

// Comparison operator for sort/binary search of model tx list
struct TxLessThan
{
    bool operator()(const TransactionRecord &a, const TransactionRecord &b) const { return a.hash < b.hash; }
    bool operator()(const TransactionRecord &a, const uint256 &b) const { return a.hash < b; }
    bool operator()(const uint256 &a, const TransactionRecord &b) const { return a < b.hash; }
};

// Private implementation
class TokenTablePriv
{
public:
    TokenTablePriv(CWallet *_wallet, TokenTableModel *_parent) : wallet(_wallet), parent(_parent) {}
    CWallet *wallet;
    TokenTableModel *parent;

    /* Local cache of wallet.
     * As it is in the same order as the CWallet, by definition
     * this is sorted by sha256.
     */
    QList<TransactionRecord> cachedWallet;

    /* Query entire wallet anew from core.
     */
    void refreshWallet()
    {
        qDebug() << "TokenTablePriv::refreshWallet";
        cachedWallet.clear();
        {
            LOCK2(cs_main, wallet->cs_wallet);
            for (MapWallet::iterator it = wallet->mapWallet.begin(); it != wallet->mapWallet.end(); ++it)
            {
                CWalletTxRef wtx = it->second.tx;
                if (it->first.hash == wtx->GetId())
                {
                    if (TransactionRecord::showTransaction(*wtx))
                    {
                        QList<TransactionRecord> txnRecord = TransactionRecord::decomposeTransaction(wallet, *wtx);
                        if (!(txnRecord.last().mapTokens.empty()))
                        {
                            cachedWallet.append(txnRecord);
                        }
                    }
                }
            }
        }
    }

    /* Update our model of the wallet incrementally, to synchronize our model of the wallet
       with that of the core.

       Call with transaction that was added, removed or changed.
     */
    void updateWallet(const uint256 &hash, int status, bool showTransaction)
    {
        qDebug() << "TokenTablePriv::updateWallet: " + QString::fromStdString(hash.ToString()) + " " +
                        QString::number(status);

        // Find bounds of this transaction in model
        QList<TransactionRecord>::iterator lower =
            std::lower_bound(cachedWallet.begin(), cachedWallet.end(), hash, TxLessThan());
        QList<TransactionRecord>::iterator upper =
            std::upper_bound(cachedWallet.begin(), cachedWallet.end(), hash, TxLessThan());
        int lowerIndex = (lower - cachedWallet.begin());
        int upperIndex = (upper - cachedWallet.begin());
        bool inModel = (lower != upper);

        if (status == CT_UPDATED)
        {
            if (showTransaction && !inModel)
                status = CT_NEW; /* Not in model, but want to show, treat as new */
            if (!showTransaction && inModel)
                status = CT_DELETED; /* In model, but want to hide, treat as deleted */
        }

        qDebug() << "    inModel=" + QString::number(inModel) + " Index=" + QString::number(lowerIndex) + "-" +
                        QString::number(upperIndex) + " showTransaction=" + QString::number(showTransaction) +
                        " derivedStatus=" + QString::number(status);

        switch (status)
        {
        case CT_NEW:
            if (inModel)
            {
                qWarning()
                    << "TokenTablePriv::updateWallet: Warning: Got CT_NEW, but transaction is already in model";
                break;
            }
            if (showTransaction)
            {
                LOCK2(cs_main, wallet->cs_wallet);
                // Find transaction in wallet
                CWalletTxRef wtx = wallet->GetWalletTx(hash);
                if (!wtx)
                {
                    qWarning()
                        << "TokenTablePriv::updateWallet: Warning: Got CT_NEW, but transaction is not in wallet";
                    break;
                }
                // Added -- insert at the right position
                QList<TransactionRecord> listRecords = TransactionRecord::decomposeTransaction(wallet, *wtx);
                QList<TransactionRecord> toInsert;
                int idx = 0;
                Q_FOREACH (const TransactionRecord &rec, listRecords)
                {
                    if (rec.mapTokens.empty() || cachedWallet.contains(rec) || toInsert.contains(rec))
                        continue;
                    toInsert.insert(idx, rec);
                    idx++;
                }

                if (!toInsert.isEmpty()) /* only if something to insert */
                {
                    parent->beginInsertRows(QModelIndex(), lowerIndex, lowerIndex + toInsert.size() - 1);
                    int insert_idx = lowerIndex;
                    Q_FOREACH (const TransactionRecord &rec, toInsert)
                    {
                        cachedWallet.insert(insert_idx, rec);
                        insert_idx += 1;
                    }
                    parent->endInsertRows();
                }
            }
            break;
        case CT_DELETED:
            if (!inModel)
            {
                qWarning()
                    << "TokenTablePriv::updateWallet: Warning: Got CT_DELETED, but transaction is not in model";
                break;
            }
            // Removed -- remove entire transaction from table
            parent->beginRemoveRows(QModelIndex(), lowerIndex, upperIndex - 1);
            cachedWallet.erase(lower, upper);
            parent->endRemoveRows();
            break;
        case CT_UPDATED:
            // Miscellaneous updates

            if (!inModel)
            {
                qWarning()
                    << "TransactionTablePriv::updateWallet: Warning: Got CT_UPDATED, but transaction is not in model";
                break;
            }

            LOCK2(cs_main, wallet->cs_wallet);
            // Find transaction in wallet
            CWalletTxRef wtx = wallet->GetWalletTx(hash);
            if (!wtx)
            {
                qWarning()
                    << "TransactionTablePriv::updateWallet: Warning: Got CT_NEW, but transaction is not in wallet";
                break;
            }

            // Added -- insert at the right position
            QList<TransactionRecord> tmp = TransactionRecord::decomposeTransaction(wallet, *wtx);
            QList<TransactionRecord> toUpdate;
            int idx = 0;
            Q_FOREACH (const TransactionRecord &rec, tmp)
            {
                if (!cachedWallet.contains(rec) || toUpdate.contains(rec) || rec.mapTokens.empty())
                    continue;

                toUpdate.insert(idx, rec);
                idx++;
            }

            if (!toUpdate.isEmpty()) /* only if something to update */
            {
                Q_FOREACH (const TransactionRecord &rec, toUpdate)
                {
                    QList<TransactionRecord>::iterator iter = std::find(cachedWallet.begin(), cachedWallet.end(), rec);
                    if (iter != cachedWallet.end())
                    {
                        // There is an edge scenario where a new token was created and tokens minted before
                        // the next block was mined. In this case we have to update the transaction record
                        // to reflect the correct decimal value after the next block is mined.
                        *iter = rec;

                        // Update the amount field in the UI
                        QModelIndex nIndex = parent->index(lowerIndex, TokenTableModel::Amount);
                        parent->dataChanged(nIndex, nIndex);
                    }
                }
            }

            break;
        }
    }

    int size() { return cachedWallet.size(); }
    TransactionRecord *index(int idx)
    {
        if (idx >= 0 && idx < cachedWallet.size())
        {
            TransactionRecord *rec = &cachedWallet[idx];

            // Get required locks upfront. This avoids the GUI from getting
            // stuck if the core is holding the locks for a longer time - for
            // example, during a wallet rescan.
            //
            // If a status update is needed (blocks came in since last check),
            //  update the status of this transaction from the wallet. Otherwise,
            // simply re-use the cached status.
            TRY_LOCK(wallet->cs_wallet, lockWallet);
            if (lockWallet)
            {
                CWalletTxRef wtx = wallet->GetWalletTx(rec->hash);
                if (wtx)
                {
                    if (rec->statusUpdateNeeded() || wtx->fDoubleSpent == true || wtx->isAbandoned())
                        rec->updateStatus(wtx);
                }
            }
            return rec;
        }
        return 0;
    }

    QString describe(TransactionRecord *rec, int unit)
    {
        {
            LOCK2(cs_main, wallet->cs_wallet);
            CWalletTxRef wtx = wallet->GetWalletTx(rec->hash);
            if (wtx)
            {
                return TransactionDesc::toHTML(wallet, *wtx, rec, unit);
            }
        }
        return QString();
    }

    QString getTxHex(TransactionRecord *rec)
    {
        LOCK2(cs_main, wallet->cs_wallet);
        CWalletTxRef wtx = wallet->GetWalletTx(rec->hash);
        if (wtx)
        {
            std::string strHex = EncodeHexTx(*wtx);
            return QString::fromStdString(strHex);
        }
        return QString();
    }
};

TokenTableModel::TokenTableModel(const PlatformStyle *_platformStyle, CWallet *_wallet, WalletModel *parent)
    : QAbstractTableModel(parent), wallet(_wallet), walletModel(parent), priv(new TokenTablePriv(wallet, this)),
      fProcessingQueuedTransactions(false), platformStyle(_platformStyle)
{
    columns << QString() << QString() << tr("Date") << tr("Type") << tr("Token ID") << tr("Net Amount");
    priv->refreshWallet();

    subscribeToCoreSignals();
}

TokenTableModel::~TokenTableModel()
{
    unsubscribeFromCoreSignals();
    delete priv;
}

void TokenTableModel::updateTransaction(const QString &hash, int status, bool showTransaction)
{
    uint256 updated;
    updated.SetHex(hash.toStdString());

    priv->updateWallet(updated, status, showTransaction);
}

void TokenTableModel::updateConfirmations()
{
    // Blocks came in since last poll.
    // Invalidate status (number of confirmations) and (possibly) description
    //  for all rows. Qt is smart enough to only actually request the data for the
    //  visible rows.
    Q_EMIT dataChanged(index(0, Status), index(priv->size() - 1, Status));
    Q_EMIT dataChanged(index(0, ToTokenID), index(priv->size() - 1, ToTokenID));
}

int TokenTableModel::rowCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    return priv->size();
}

int TokenTableModel::columnCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    return columns.length();
}

QString TokenTableModel::formatTxStatus(const TransactionRecord *wtx) const
{
    QString status;

    switch (wtx->status.status)
    {
    case TransactionStatus::OpenUntilBlock:
        status = tr("Open for %n more block(s)", "", wtx->status.open_for);
        break;
    case TransactionStatus::OpenUntilDate:
        status = tr("Open until %1").arg(GUIUtil::dateTimeStr(wtx->status.open_for));
        break;
    case TransactionStatus::Offline:
        status = tr("Offline");
        break;
    case TransactionStatus::Unconfirmed:
        status = tr("Unconfirmed");
        break;
    case TransactionStatus::Confirming:
        status = tr("Confirming (%1 of %2 recommended confirmations)")
                     .arg(wtx->status.depth)
                     .arg(TransactionRecord::RecommendedNumConfirmations);
        break;
    case TransactionStatus::Confirmed:
        status = tr("Confirmed (%1 confirmations)").arg(wtx->status.depth);
        break;
    case TransactionStatus::Conflicted:
        status = tr("Conflicted");
        break;
    case TransactionStatus::DoubleSpent:
        status = tr("Double Spent");
        break;
    case TransactionStatus::Abandoned:
        status = tr("Abandoned");
        break;
    case TransactionStatus::Immature:
        status = tr("Immature (%1 confirmations, will be available after %2)")
                     .arg(wtx->status.depth)
                     .arg(wtx->status.depth + wtx->status.matures_in);
        break;
    case TransactionStatus::MaturesWarning:
        status = tr("This block was not received by any other nodes and will probably not be accepted!");
        break;
    case TransactionStatus::NotAccepted:
        status = tr("Generated but not accepted");
        break;
    }

    return status;
}

QString TokenTableModel::formatTxDate(const TransactionRecord *wtx) const
{
    if (wtx->time)
    {
        return GUIUtil::dateTimeStr(wtx->time);
    }
    return QString();
}

/* Look up address in address book, if found return label (address)
   otherwise just return (address)
   OBSOLETE previously called from formatTxToAddress
 */
QString TokenTableModel::lookupAddress(const std::string &address, bool tooltip) const
{
    QString label = walletModel->getAddressTableModel()->labelForAddress(QString::fromStdString(address));
    QString description;
    if (!label.isEmpty())
    {
        description += label;
    }
    if (label.isEmpty() || tooltip)
    {
        description += QString(" (") + QString::fromStdString(address) + QString(")");
    }
    return description;
}

QString TokenTableModel::formatTxType(const TransactionRecord *wtx) const
{
    TransactionRecord::Type type = wtx->type;
    if (!wtx->mapTokens.empty())
    {
        // If we have a Mint or Melt then assign the correct type
        auto tmpType = wtx->mapTokens.begin()->second.type;
        if (tmpType == TokenRecord::Mint || tmpType == TokenRecord::Melt)
        {
            type = (TransactionRecord::Type)tmpType;
        }
    }

    switch (type)
    {
    case TransactionRecord::RecvWithAddress:
        return tr("Received with");
    case TransactionRecord::RecvFromOther:
        return tr("Received from");
    case TransactionRecord::SendToAddress:
    case TransactionRecord::SendToOther:
        return tr("Sent");
    case TransactionRecord::SendToSelf:
        return tr("Payment to yourself");
    case TransactionRecord::Mint:
        return tr("Mint");
    case TransactionRecord::Melt:
        return tr("Melt");
    case TransactionRecord::PublicLabel:
        return tr("Public label");
    case TransactionRecord::Other:
        return tr("Other");
    default:
        return QString();
    }
}

QVariant TokenTableModel::txAddressDecoration(const TransactionRecord *wtx) const
{
    TransactionRecord::Type type = wtx->type;
    if (!wtx->mapTokens.empty())
    {
        // If we have a Mint or Melt then assign the correct type
        auto tmpType = wtx->mapTokens.begin()->second.type;
        if (tmpType == TokenRecord::Mint || tmpType == TokenRecord::Melt)
        {
            type = (TransactionRecord::Type)tmpType;
        }
    }

    switch (type)
    {
    case TransactionRecord::Mint:
        return QIcon(":/icons/tx_mined");
    case TransactionRecord::Melt:
        return QIcon(":/icons/tx_mined");
    case TransactionRecord::RecvWithAddress:
    case TransactionRecord::RecvFromOther:
        return QIcon(":/icons/tx_input");
    case TransactionRecord::SendToAddress:
    case TransactionRecord::SendToOther:
        return QIcon(":/icons/tx_output");
    default:
        return QIcon(":/icons/tx_inout");
    }
}

QString TokenTableModel::formatTxToGrpID(const TransactionRecord *wtx, bool tooltip) const
{
    if (wtx->mapTokens.empty())
        return QString{};
    else
        return QString::fromStdString(EncodeGroupToken(wtx->mapTokens.begin()->first));
}

QVariant TokenTableModel::addressColor(const TransactionRecord *wtx) const
{
    // Show addresses without label in a less visible color
    switch (wtx->type)
    {
    case TransactionRecord::RecvWithAddress:
    case TransactionRecord::SendToAddress:
    case TransactionRecord::Generated:
    {
        auto firstAddr = wtx->addresses.begin();
        if (firstAddr == wtx->addresses.end())
            return COLOR_BAREADDRESS;
        QString label = walletModel->getAddressTableModel()->labelForAddress(QString::fromStdString(firstAddr->first));
        if (label.isEmpty())
            return COLOR_BAREADDRESS;
    }
    break;
    case TransactionRecord::SendToSelf:
        return COLOR_BAREADDRESS;
    default:
        break;
    }
    return QVariant();
}

QString TokenTableModel::formatTxAmount(const TransactionRecord *wtx,
    bool showUnconfirmed,
    BitcoinUnits::SeparatorStyle separators) const
{
    // Count up all the credits and debits for all the token records
    CAmount credits = 0;
    CAmount debits = 0;
    uint32_t decimal = 0;
    for (auto it : wtx->mapTokens)
    {
        credits += it.second.credit;
        if (it.second.type != TokenRecord::Mint)
        {
            debits += it.second.debit;
        }
        if (decimal < it.second.decimal)
            decimal = it.second.decimal;
    }

    QString str;
    if (!decimal)
    {
      str = QString::number(credits - debits);
    }
    else
    {
        int64_t nTokens = credits - debits;
        double nDisplayTokens = (double)(nTokens) / pow(10, decimal);
        str = QString::number(nDisplayTokens, 'f', decimal);
    }

    if (showUnconfirmed)
    {
        if (!wtx->status.countsForBalance)
        {
            str = QString("[") + str + QString("]");
        }
    }

    return str;
}

QVariant TokenTableModel::txStatusDecoration(const TransactionRecord *wtx) const
{
    switch (wtx->status.status)
    {
    case TransactionStatus::OpenUntilBlock:
    case TransactionStatus::OpenUntilDate:
        return COLOR_TX_STATUS_OPENUNTILDATE;
    case TransactionStatus::Offline:
        return COLOR_TX_STATUS_OFFLINE;
    case TransactionStatus::Unconfirmed:
        return QIcon(":/icons/transaction_0");
    case TransactionStatus::Confirming:
        switch (wtx->status.depth)
        {
        case 1:
            return QIcon(":/icons/transaction_1");
        case 2:
            return QIcon(":/icons/transaction_2");
        case 3:
            return QIcon(":/icons/transaction_3");
        case 4:
            return QIcon(":/icons/transaction_4");
        default:
            return QIcon(":/icons/transaction_5");
        };
    case TransactionStatus::Confirmed:
        return QIcon(":/icons/transaction_confirmed");
    case TransactionStatus::Conflicted:
        return QIcon(":/icons/transaction_conflicted");
    case TransactionStatus::DoubleSpent:
        return QIcon(":/icons/warning");
    case TransactionStatus::Abandoned:
        return QIcon(":/icons/remove");
    case TransactionStatus::Immature:
    {
        int total = wtx->status.depth + wtx->status.matures_in;
        int part = (wtx->status.depth * 4 / total) + 1;
        return QIcon(QString(":/icons/transaction_%1").arg(part));
    }
    case TransactionStatus::MaturesWarning:
    case TransactionStatus::NotAccepted:
        return QIcon(":/icons/transaction_0");
    default:
        return COLOR_BLACK;
    }
}

QVariant TokenTableModel::txWatchonlyDecoration(const TransactionRecord *wtx) const
{
    if (wtx->involvesWatchAddress)
        return QIcon(":/icons/eye");
    else
        return QVariant();
}

QString TokenTableModel::formatTooltip(const TransactionRecord *rec) const
{
    QString tooltip = formatTxStatus(rec) + QString("\n") + formatTxType(rec);
    if (rec->type == TransactionRecord::RecvFromOther || rec->type == TransactionRecord::SendToOther ||
        rec->type == TransactionRecord::SendToAddress || rec->type == TransactionRecord::RecvWithAddress)
    {
        tooltip += QString(" ") + formatTxToGrpID(rec, true);
    }
    return tooltip;
}

QString TokenTableModel::pickLabelWithAddress(AddressList listAddresses, std::string &address) const
{
    /* returns the first address wiith a label or the last address on the list */
    QString label = "";
    for (const std::pair<std::string, CScript> &addr : listAddresses)
    {
        address = addr.first;
        label = walletModel->getAddressTableModel()->labelForAddress(QString::fromStdString(address));
        if (label != "")
            break;
    }

    return label;
}

QVariant TokenTableModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid())
        return QVariant();
    TransactionRecord *rec = static_cast<TransactionRecord *>(index.internalPointer());

    /* For some roles prefer the address which has a label. */
    std::string address;
    QString label = pickLabelWithAddress(rec->addresses, address);

    switch (role)
    {
    case RawDecorationRole:
        switch (index.column())
        {
        case Status:
            return txStatusDecoration(rec);
        case Watchonly:
            return txWatchonlyDecoration(rec);
        case ToTokenID:
            return txAddressDecoration(rec);
        }
        break;
    case Qt::DecorationRole:
    {
        QIcon icon = qvariant_cast<QIcon>(index.data(RawDecorationRole));
        return platformStyle->TextColorIcon(icon);
    }
    case Qt::DisplayRole:
        switch (index.column())
        {
        case Date:
            return formatTxDate(rec);
        case Type:
            return formatTxType(rec);
        case ToTokenID:
            return formatTxToGrpID(rec, false);
        case Amount:
            return formatTxAmount(rec, true, BitcoinUnits::separatorAlways);
        }
        break;
    case Qt::EditRole:
        // Edit role is used for sorting, so return the unformatted values
        switch (index.column())
        {
        case Status:
            return QString::fromStdString(rec->status.sortKey);
        case Date:
            return rec->time;
        case Type:
            return formatTxType(rec);
        case Watchonly:
            return (rec->involvesWatchAddress ? 1 : 0);
        case ToTokenID:
            return formatTxToGrpID(rec, true);
        case Amount:
            return formatTxAmount(rec, false, BitcoinUnits::separatorNever);
        }
        break;
    case Qt::ToolTipRole:
        return formatTooltip(rec);
    case Qt::TextAlignmentRole:
        return column_alignments[index.column()];
    case Qt::ForegroundRole:
        // Non-confirmed (but not immature) as transactions are grey
        if (!rec->status.countsForBalance && rec->status.status != TransactionStatus::Immature)
        {
            return COLOR_UNCONFIRMED;
        }
        if (index.column() == Amount && formatTxAmount(rec, false, BitcoinUnits::separatorNever).toDouble() < 0)
        {
            return COLOR_NEGATIVE;
        }
        if (index.column() == ToTokenID)
        {
            return addressColor(rec);
        }
        break;
    case TypeRole:
        return rec->type;
    case DateRole:
        return QDateTime::fromTime_t(static_cast<uint>(rec->time));
    case WatchonlyRole:
        return rec->involvesWatchAddress;
    case WatchonlyDecorationRole:
        return txWatchonlyDecoration(rec);
    case LongDescriptionRole:
        return priv->describe(rec, walletModel->getOptionsModel()->getDisplayUnit());
    case AddressRole:
        return QString::fromStdString(address);
    case TokenIDRole:
        if (rec->mapTokens.empty())
            return QString{};
        else
            return QString::fromStdString(EncodeGroupToken(rec->mapTokens.begin()->first));
    case LabelRole:
        return label;
    case TxIDRole:
        return rec->getTxID();
    case TxHashRole:
        return QString::fromStdString(rec->hash.ToString());
    case TxHexRole:
        return priv->getTxHex(rec);
    case ConfirmedRole:
        return rec->status.countsForBalance;
    case FormattedAmountRole:
        // Used for copy/export, so don't include separators
        return formatTxAmount(rec, false, BitcoinUnits::separatorNever);
    case StatusRole:
        return rec->status.status;
    }
    return QVariant();
}

QVariant TokenTableModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation == Qt::Horizontal)
    {
        if (role == Qt::DisplayRole)
        {
            return columns[section];
        }
        else if (role == Qt::TextAlignmentRole)
        {
            return column_alignments[section];
        }
        else if (role == Qt::ToolTipRole)
        {
            switch (section)
            {
            case Status:
                return tr("Transaction status. Hover over this field to show number of confirmations.");
            case Date:
                return tr("Date and time that the transaction was received.");
            case Type:
                return tr("Type of transaction.");
            case Watchonly:
                return tr("Whether or not a watch-only address is involved in this transaction.");
            case ToTokenID:
                return tr("User-defined intent/purpose of the transaction.");
            case Amount:
                return tr("Amount removed from or added to balance.");
            }
        }
    }
    return QVariant();
}

QModelIndex TokenTableModel::index(int row, int column, const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    TransactionRecord *data = priv->index(row);
    if (data)
    {
        return createIndex(row, column, priv->index(row));
    }
    return QModelIndex();
}

// queue notifications to show a non freezing progress dialog e.g. for rescan
struct TransactionNotification
{
public:
    TransactionNotification() {}
    TransactionNotification(uint256 _hash, ChangeType _status, bool _showTransaction)
        : hash(_hash), status(_status), showTransaction(_showTransaction)
    {
    }

    void invoke(QObject *ttm)
    {
        QString strHash = QString::fromStdString(hash.GetHex());
        qDebug() << "NotifyTransactionChanged: " + strHash + " status= " + QString::number(status);
        QMetaObject::invokeMethod(ttm, "updateTransaction", Qt::QueuedConnection, Q_ARG(QString, strHash),
            Q_ARG(int, status), Q_ARG(bool, showTransaction));
    }

private:
    uint256 hash;
    ChangeType status;
    bool showTransaction;
};

static bool fQueueNotifications = false;
static std::vector<TransactionNotification> vQueueNotifications;

static void NotifyTransactionChanged(TokenTableModel *ttm,
    CWallet *wallet,
    const uint256 &hash,
    ChangeType status)
{
    // Find transaction in wallet
    CWalletTxRef wtx = wallet->GetWalletTx(hash);
    // Determine whether to show transaction or not (determine this here so that no relocking is needed in GUI thread)
    bool inWallet = (wtx) ? true : false;
    bool showTransaction = (inWallet && TransactionRecord::showTransaction(*wtx));

    TransactionNotification notification(hash, status, showTransaction);

    if (fQueueNotifications)
    {
        vQueueNotifications.push_back(notification);
        return;
    }
    notification.invoke(ttm);
}

static void ShowProgress(TokenTableModel *ttm, const std::string &title, int nProgress)
{
    if (nProgress == 0)
        fQueueNotifications = true;

    if (nProgress == 100)
    {
        fQueueNotifications = false;
        if (vQueueNotifications.size() > 10) // prevent balloon spam, show maximum 10 balloons
            QMetaObject::invokeMethod(ttm, "setProcessingQueuedTransactions", Qt::QueuedConnection, Q_ARG(bool, true));
        for (unsigned int i = 0; i < vQueueNotifications.size(); ++i)
        {
            if (vQueueNotifications.size() - i <= 10)
                QMetaObject::invokeMethod(
                    ttm, "setProcessingQueuedTransactions", Qt::QueuedConnection, Q_ARG(bool, false));

            vQueueNotifications[i].invoke(ttm);
        }
        std::vector<TransactionNotification>().swap(vQueueNotifications); // clear
    }
}

void TokenTableModel::subscribeToCoreSignals()
{
    // Connect signals to wallet
    wallet->NotifyTransactionChanged.connect(
        boost::bind(NotifyTransactionChanged, this, boost::arg<1>(), boost::arg<2>(), boost::arg<3>()));
    wallet->ShowProgress.connect(boost::bind(ShowProgress, this, boost::arg<1>(), boost::arg<2>()));
}

void TokenTableModel::unsubscribeFromCoreSignals()
{
    // Disconnect signals from wallet
    wallet->NotifyTransactionChanged.disconnect(
        boost::bind(NotifyTransactionChanged, this, boost::arg<1>(), boost::arg<2>(), boost::arg<3>()));
    wallet->ShowProgress.disconnect(boost::bind(ShowProgress, this, boost::arg<1>(), boost::arg<2>()));
}
