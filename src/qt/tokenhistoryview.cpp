// Copyright (c) 2011-2015 The Bitcoin Core developers
// Copyright (c) 2015-2023 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "tokenhistoryview.h"

#include "addresstablemodel.h"
#include "csvmodelwriter.h"
#include "editaddressdialog.h"
#include "guiutil.h"
#include "nexaunits.h"
#include "optionsmodel.h"
#include "platformstyle.h"
#include "tokentablemodel.h"
#include "transactiondescdialog.h"
#include "transactionfilterproxy.h"
#include "transactionrecord.h"
#include "transactiontablemodel.h"
#include "walletmodel.h"

#include "ui_interface.h"

#include <QComboBox>
#include <QDateTimeEdit>
#include <QDesktopServices>
#include <QDoubleValidator>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QPoint>
#include <QScrollBar>
#include <QSignalMapper>
#include <QTableView>
#include <QUrl>
#include <QVBoxLayout>

TokenHistoryView::TokenHistoryView(const PlatformStyle *platformStyle, QWidget *parent)
    : QWidget(parent), model(0), tokenProxyModel(0), tokenHistoryView(0), columnResizingFixer(0)
{
    // Build filter row
    setContentsMargins(0, 0, 0, 0);

    QHBoxLayout *hlayout = new QHBoxLayout();
    hlayout->setContentsMargins(0, 0, 0, 0);

    if (platformStyle->getUseExtraSpacing())
    {
        hlayout->setSpacing(5);
        hlayout->addSpacing(26);
    }
    else
    {
        hlayout->setSpacing(0);
        hlayout->addSpacing(23);
    }

    watchOnlyWidget = new QComboBox(this);
    watchOnlyWidget->setFixedWidth(24);
    watchOnlyWidget->addItem("", TransactionFilterProxy::WatchOnlyFilter_All);
    watchOnlyWidget->addItem(
        platformStyle->SingleColorIcon(":/icons/eye_plus"), "", TransactionFilterProxy::WatchOnlyFilter_Yes);
    watchOnlyWidget->addItem(
        platformStyle->SingleColorIcon(":/icons/eye_minus"), "", TransactionFilterProxy::WatchOnlyFilter_No);
    hlayout->addWidget(watchOnlyWidget);

    dateWidget = new QComboBox(this);
    if (platformStyle->getUseExtraSpacing())
    {
        dateWidget->setFixedWidth(121);
    }
    else
    {
        dateWidget->setFixedWidth(120);
    }
    dateWidget->addItem(tr("All"), All);
    dateWidget->addItem(tr("Today"), Today);
    dateWidget->addItem(tr("This week"), ThisWeek);
    dateWidget->addItem(tr("This month"), ThisMonth);
    dateWidget->addItem(tr("Last month"), LastMonth);
    dateWidget->addItem(tr("This year"), ThisYear);
    dateWidget->addItem(tr("Range..."), Range);
    hlayout->addWidget(dateWidget);

    typeWidget = new QComboBox(this);
    if (platformStyle->getUseExtraSpacing())
    {
        typeWidget->setFixedWidth(121);
    }
    else
    {
        typeWidget->setFixedWidth(120);
    }

    typeWidget->addItem(tr("All"), TransactionFilterProxy::ALL_TYPES);
    typeWidget->addItem(tr("Received with"), TransactionFilterProxy::TYPE(TransactionRecord::RecvWithAddress) |
                                                 TransactionFilterProxy::TYPE(TransactionRecord::RecvFromOther));
    typeWidget->addItem(tr("Sent"), TransactionFilterProxy::TYPE(TransactionRecord::SendToAddress) |
                                           TransactionFilterProxy::TYPE(TransactionRecord::SendToOther));
    typeWidget->addItem(tr("To yourself"), TransactionFilterProxy::TYPE(TransactionRecord::SendToSelf));
    typeWidget->addItem(tr("Mint"), TransactionFilterProxy::TYPE(TransactionRecord::Generated));
    typeWidget->addItem(tr("Other"), TransactionFilterProxy::TYPE(TransactionRecord::Other));

    hlayout->addWidget(typeWidget);

    addressWidget = new QLineEdit(this);
    addressWidget->setPlaceholderText(tr("Enter token ID to search"));
    hlayout->addWidget(addressWidget);

    amountWidget = new QLineEdit(this);
    amountWidget->setPlaceholderText(tr("Min amount"));
    if (platformStyle->getUseExtraSpacing())
    {
        amountWidget->setFixedWidth(97);
    }
    else
    {
        amountWidget->setFixedWidth(100);
    }
    amountWidget->setValidator(new QDoubleValidator(-1e20, 1e20, -1, this));
    hlayout->addWidget(amountWidget);

    QVBoxLayout *vlayout = new QVBoxLayout(this);
    vlayout->setContentsMargins(0, 0, 0, 0);
    vlayout->setSpacing(0);

    QTableView *view = new QTableView(this);
    vlayout->addLayout(hlayout);
    vlayout->addWidget(createDateRangeWidget());
    vlayout->addWidget(view);
    vlayout->setSpacing(0);
    int width = view->verticalScrollBar()->sizeHint().width();
    // Cover scroll bar width with spacing
    if (platformStyle->getUseExtraSpacing())
    {
        hlayout->addSpacing(width + 2);
    }
    else
    {
        hlayout->addSpacing(width);
    }
    // Always show scroll bar
    view->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOn);
    view->setTabKeyNavigation(false);
    view->setContextMenuPolicy(Qt::CustomContextMenu);

    view->installEventFilter(this);

    tokenHistoryView = view;

    // Actions
    QAction *copyGrpIDAction = new QAction(tr("Copy token id"), this);
    QAction *copyAmountAction = new QAction(tr("Copy amount"), this);
    QAction *copyTxIDAction = new QAction(tr("Copy transaction id"), this);
    QAction *copyTxIdemAction = new QAction(tr("Copy transaction idem"), this);
    QAction *copyTxHexAction = new QAction(tr("Copy raw transaction"), this);
    QAction *showDetailsAction = new QAction(tr("Show transaction details"), this);

    contextMenu = new QMenu(this);
    contextMenu->addAction(copyGrpIDAction);
    contextMenu->addAction(copyAmountAction);
    contextMenu->addAction(copyTxIDAction);
    contextMenu->addAction(copyTxIdemAction);
    contextMenu->addAction(copyTxHexAction);
    contextMenu->addAction(showDetailsAction);

    mapperThirdPartyTxUrls = new QSignalMapper(this);

    // Connect actions
    connect(mapperThirdPartyTxUrls, SIGNAL(mapped(QString)), this, SLOT(openThirdPartyTxUrl(QString)));

    connect(dateWidget, SIGNAL(activated(int)), this, SLOT(chooseDate(int)));
    connect(typeWidget, SIGNAL(activated(int)), this, SLOT(chooseType(int)));
    connect(watchOnlyWidget, SIGNAL(activated(int)), this, SLOT(chooseWatchonly(int)));
    connect(addressWidget, SIGNAL(textChanged(QString)), this, SLOT(changedPrefix(QString)));
    connect(amountWidget, SIGNAL(textChanged(QString)), this, SLOT(changedAmount(QString)));

    connect(view, SIGNAL(doubleClicked(QModelIndex)), this, SIGNAL(doubleClicked(QModelIndex)));
    connect(view, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(contextualMenu(QPoint)));

    connect(copyGrpIDAction, SIGNAL(triggered()), this, SLOT(copyGrpID()));
    connect(copyAmountAction, SIGNAL(triggered()), this, SLOT(copyAmount()));
    connect(copyTxIDAction, SIGNAL(triggered()), this, SLOT(copyTxID()));
    connect(copyTxIdemAction, SIGNAL(triggered()), this, SLOT(copyTxIdem()));
    connect(copyTxHexAction, SIGNAL(triggered()), this, SLOT(copyTxHex()));
    connect(showDetailsAction, SIGNAL(triggered()), this, SLOT(showDetails()));
}

void TokenHistoryView::setModel(WalletModel *_model)
{
    this->model = _model;
    if (_model)
    {
        tokenProxyModel = new TokenFilterProxy(this);
        tokenProxyModel->setSourceModel(_model->getTokenTableModel());
        tokenProxyModel->setDynamicSortFilter(true);
        tokenProxyModel->setSortCaseSensitivity(Qt::CaseInsensitive);
        tokenProxyModel->setFilterCaseSensitivity(Qt::CaseInsensitive);

        tokenProxyModel->setSortRole(Qt::EditRole);

        tokenHistoryView->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        tokenHistoryView->setModel(tokenProxyModel);
        tokenHistoryView->setAlternatingRowColors(true);
        tokenHistoryView->setSelectionBehavior(QAbstractItemView::SelectRows);
        tokenHistoryView->setSelectionMode(QAbstractItemView::ExtendedSelection);
        tokenHistoryView->setSortingEnabled(true);
        tokenHistoryView->sortByColumn(TokenTableModel::Status, Qt::DescendingOrder);
        tokenHistoryView->verticalHeader()->hide();

        tokenHistoryView->setColumnWidth(TokenTableModel::Status, STATUS_COLUMN_WIDTH);
        tokenHistoryView->setColumnWidth(TokenTableModel::Watchonly, WATCHONLY_COLUMN_WIDTH);
        tokenHistoryView->setColumnWidth(TokenTableModel::Date, DATE_COLUMN_WIDTH);
        tokenHistoryView->setColumnWidth(TokenTableModel::Type, TYPE_COLUMN_WIDTH);
        tokenHistoryView->setColumnWidth(TokenTableModel::Amount, AMOUNT_MINIMUM_COLUMN_WIDTH);

        columnResizingFixer = new GUIUtil::TableViewLastColumnResizingFixer(
            tokenHistoryView, AMOUNT_MINIMUM_COLUMN_WIDTH, MINIMUM_COLUMN_WIDTH, this);

        if (_model->getOptionsModel())
        {
            connect(_model->getOptionsModel(), SIGNAL(tokenWhitelistButtonChanged(bool)), _model->getTokenTableModel(),
                SLOT(updateDisplayedTokens(bool)));

            // Add third party transaction URLs to context menu
            QStringList listUrls = _model->getOptionsModel()->getThirdPartyTxUrls().split("|", QString::SkipEmptyParts);
            for (int i = 0; i < listUrls.size(); ++i)
            {
                QString host = QUrl(listUrls[i].trimmed(), QUrl::StrictMode).host();
                if (!host.isEmpty())
                {
                    QAction *thirdPartyTxUrlAction = new QAction(host, this); // use host as menu item label
                    if (i == 0)
                        contextMenu->addSeparator();
                    contextMenu->addAction(thirdPartyTxUrlAction);
                    connect(thirdPartyTxUrlAction, SIGNAL(triggered()), mapperThirdPartyTxUrls, SLOT(map()));
                    mapperThirdPartyTxUrls->setMapping(thirdPartyTxUrlAction, listUrls[i].trimmed());
                }
            }
        }

        // show/hide column Watch-only
        updateWatchOnlyColumn(_model->haveWatchOnly());

        // Watch-only signal
        connect(_model, SIGNAL(notifyWatchonlyChanged(bool)), this, SLOT(updateWatchOnlyColumn(bool)));
    }
}

void TokenHistoryView::chooseDate(int idx)
{
    if (!tokenProxyModel)
        return;
    QDate current = QDate::currentDate();
    dateRangeWidget->setVisible(false);
    switch (dateWidget->itemData(idx).toInt())
    {
    case All:
        tokenProxyModel->setDateRange(TokenFilterProxy::MIN_DATE, TokenFilterProxy::MAX_DATE);
        break;
    case Today:
        tokenProxyModel->setDateRange(QDateTime(current.currentDate()), TokenFilterProxy::MAX_DATE);
        break;
    case ThisWeek:
    {
        // Find last Monday
        QDate startOfWeek = current.addDays(-(current.dayOfWeek() - 1));
        tokenProxyModel->setDateRange(QDateTime(startOfWeek.currentDate()), TokenFilterProxy::MAX_DATE);
    }
    break;
    case ThisMonth:
        tokenProxyModel->setDateRange(
            QDateTime(QDate(current.year(), current.month(), 1).currentDate()), TokenFilterProxy::MAX_DATE);
        break;
    case LastMonth:
        tokenProxyModel->setDateRange(QDateTime(QDate(current.year(), current.month(), 1).addMonths(-1).currentDate()),
            QDateTime(QDate(current.year(), current.month(), 1).currentDate()));
        break;
    case ThisYear:
        tokenProxyModel->setDateRange(QDateTime(QDate(current.year(), 1, 1).currentDate()), TokenFilterProxy::MAX_DATE);
        break;
    case Range:
        dateRangeWidget->setVisible(true);
        dateRangeChanged();
        break;
    }
}

void TokenHistoryView::chooseType(int idx)
{
    if (!tokenProxyModel)
        return;
    tokenProxyModel->setTypeFilter(typeWidget->itemData(idx).toInt());
}

void TokenHistoryView::chooseWatchonly(int idx)
{
    if (!tokenProxyModel)
        return;
    tokenProxyModel->setWatchOnlyFilter(
        (TokenFilterProxy::WatchOnlyFilter)watchOnlyWidget->itemData(idx).toInt());
}

void TokenHistoryView::changedPrefix(const QString &prefix)
{
    if (!tokenProxyModel)
        return;
    tokenProxyModel->setAddressPrefix(prefix);
}

void TokenHistoryView::changedAmount(const QString &amount)
{
    if (!tokenProxyModel)
        return;

    tokenProxyModel->setMinAmount(amount.toDouble());

}

void TokenHistoryView::exportClicked()
{
    // CSV is currently the only supported format
    QString filename = GUIUtil::getSaveFileName(
        this, tr("Export Token History"), QString(), tr("Comma separated file (*.csv)"), nullptr);

    if (filename.isNull())
        return;

    CSVModelWriter writer(filename);

    // name, column, role
    writer.setModel(tokenProxyModel);
    writer.addColumn(tr("Confirmed"), 0, TokenTableModel::ConfirmedRole);
    if (model && model->haveWatchOnly())
        writer.addColumn(tr("Watch-only"), TokenTableModel::Watchonly);
    writer.addColumn(tr("Date"), 0, TokenTableModel::DateRole);
    writer.addColumn(tr("Type"), TokenTableModel::Type, Qt::EditRole);
    writer.addColumn(tr("Label"), 0, TokenTableModel::LabelRole);
    writer.addColumn(tr("Address"), 0, TokenTableModel::AddressRole);
    writer.addColumn(tr("Transaction ID"), 0, TokenTableModel::TxIDRole);
    writer.addColumn(tr("Transaction Idem"), 0, TokenTableModel::TxIdemRole);
    writer.addColumn(tr("Token ID"), 0, TokenTableModel::TokenIDRole);
    writer.addColumn(tr("Token Amount"), 0, TokenTableModel::FormattedAmountRole);

    if (!writer.write())
    {
        Q_EMIT message(tr("Exporting Failed"),
            tr("There was an error trying to save the token history to %1.").arg(filename),
            CClientUIInterface::MSG_ERROR);
    }
    else
    {
        Q_EMIT message(tr("Exporting Successful"),
            tr("The token history was successfully saved to %1.").arg(filename),
            CClientUIInterface::MSG_INFORMATION);
    }
}

void TokenHistoryView::contextualMenu(const QPoint &point)
{
    QModelIndex index = tokenHistoryView->indexAt(point);
    if (index.isValid())
    {
        contextMenu->exec(QCursor::pos());
    }
}

void TokenHistoryView::copyGrpID() { GUIUtil::copyEntryData(tokenHistoryView, 0, TokenTableModel::TokenIDRole); }
void TokenHistoryView::copyAmount()
{
    GUIUtil::copyEntryData(tokenHistoryView, 0, TokenTableModel::FormattedAmountRole);
}

void TokenHistoryView::copyTxID() { GUIUtil::copyEntryData(tokenHistoryView, 0, TokenTableModel::TxIDRole); }
void TokenHistoryView::copyTxIdem() { GUIUtil::copyEntryData(tokenHistoryView, 0, TokenTableModel::TxIdemRole); }
void TokenHistoryView::copyTxHex() { GUIUtil::copyEntryData(tokenHistoryView, 0, TokenTableModel::TxHexRole); }

void TokenHistoryView::showDetails()
{
    if (!tokenHistoryView->selectionModel())
        return;
    QModelIndexList selection = tokenHistoryView->selectionModel()->selectedRows();
    if (!selection.isEmpty())
    {
        TransactionDescDialog dlg(selection.at(0));
        dlg.exec();
    }
}

void TokenHistoryView::openThirdPartyTxUrl(QString url)
{
    if (!tokenHistoryView || !tokenHistoryView->selectionModel())
        return;
    QModelIndexList selection = tokenHistoryView->selectionModel()->selectedRows(0);
    if (!selection.isEmpty())
        QDesktopServices::openUrl(
            QUrl::fromUserInput(url.replace("%s", selection.at(0).data(TokenTableModel::TxHashRole).toString())));
}

QWidget *TokenHistoryView::createDateRangeWidget()
{
    dateRangeWidget = new QFrame();
    dateRangeWidget->setFrameStyle(QFrame::Panel | QFrame::Raised);
    dateRangeWidget->setContentsMargins(1, 1, 1, 1);
    QHBoxLayout *layout = new QHBoxLayout(dateRangeWidget);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->addSpacing(23);
    layout->addWidget(new QLabel(tr("Range:")));

    dateFrom = new QDateTimeEdit(this);
    dateFrom->setDisplayFormat("dd/MM/yy");
    dateFrom->setCalendarPopup(true);
    dateFrom->setMinimumWidth(100);
    dateFrom->setDate(QDate::currentDate().addDays(-7));
    layout->addWidget(dateFrom);
    layout->addWidget(new QLabel(tr("to")));

    dateTo = new QDateTimeEdit(this);
    dateTo->setDisplayFormat("dd/MM/yy");
    dateTo->setCalendarPopup(true);
    dateTo->setMinimumWidth(100);
    dateTo->setDate(QDate::currentDate());
    layout->addWidget(dateTo);
    layout->addStretch();

    // Hide by default
    dateRangeWidget->setVisible(false);

    // Notify on change
    connect(dateFrom, SIGNAL(dateChanged(QDate)), this, SLOT(dateRangeChanged()));
    connect(dateTo, SIGNAL(dateChanged(QDate)), this, SLOT(dateRangeChanged()));

    return dateRangeWidget;
}

void TokenHistoryView::dateRangeChanged()
{
    if (!tokenProxyModel)
        return;
    tokenProxyModel->setDateRange(QDateTime(dateFrom->date().currentDate()), QDateTime(dateTo->date().addDays(1).currentDate()));
}

void TokenHistoryView::focusTransaction(const QModelIndex &idx)
{
    if (!tokenProxyModel)
        return;
    QModelIndex targetIdx = tokenProxyModel->mapFromSource(idx);
    tokenHistoryView->scrollTo(targetIdx);
    tokenHistoryView->setCurrentIndex(targetIdx);
    tokenHistoryView->setFocus();
}

// We override the virtual resizeEvent of the QWidget to adjust tables column
// sizes as the tables width is proportional to the dialogs width.
void TokenHistoryView::resizeEvent(QResizeEvent *event)
{
    QWidget::resizeEvent(event);
    columnResizingFixer->stretchColumnWidth(TokenTableModel::ToTokenID);
}

// Need to override default Ctrl+C action for amount as default behaviour is just to copy DisplayRole text
bool TokenHistoryView::eventFilter(QObject *obj, QEvent *event)
{
    if (event->type() == QEvent::KeyPress)
    {
        QKeyEvent *ke = static_cast<QKeyEvent *>(event);
        if (ke->key() == Qt::Key_C && ke->modifiers().testFlag(Qt::ControlModifier))
        {
            QModelIndex i = this->tokenHistoryView->currentIndex();
            if (i.isValid() && i.column() == TokenTableModel::Amount)
            {
                GUIUtil::setClipboard(i.data(TokenTableModel::FormattedAmountRole).toString());
                return true;
            }
        }
    }
    return QWidget::eventFilter(obj, event);
}

// show/hide column Watch-only
void TokenHistoryView::updateWatchOnlyColumn(bool fHaveWatchOnly)
{
    watchOnlyWidget->setVisible(fHaveWatchOnly);
    tokenHistoryView->setColumnHidden(TokenTableModel::Watchonly, !fHaveWatchOnly);
}
