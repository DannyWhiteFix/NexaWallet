// Copyright (c) 2011-2015 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "tokendisplaydialog.h"
#include "ui_tokendisplaydialog.h"

#include "edittokendialog.h"
#include "guiutil.h"
#include "nexaunits.h"
#include "optionsmodel.h"
#include "platformstyle.h"
#include "txmempool.h"
#include "walletmodel.h"

#include "coincontrol.h"
#include "dstencode.h"
#include "init.h"
#include "main.h" // For minRelayTxFee
#include "policy/policy.h"
#include "wallet/grouptokenwallet.h"
#include "wallet/wallet.h"

#include <QApplication>
#include <QCheckBox>
#include <QCursor>
#include <QDialogButtonBox>
#include <QFlags>
#include <QIcon>
#include <QSettings>
#include <QString>
#include <QTreeWidget>
#include <QTreeWidgetItem>


TokenDisplayDialog::TokenDisplayDialog(const PlatformStyle *_platformStyle, QWidget *parent)
    : QDialog(parent), ui(new Ui::TokenDisplayDialog), model(0), platformStyle(_platformStyle)
{
    ui->setupUi(this);

    // context menu actions
    QAction *copyGroupIDAction = new QAction(tr("Copy GroupID"), this);
    QAction *copyTickerAction = new QAction(tr("Copy Token Ticker"), this);
    // context menu
    contextMenu = new QMenu(this);
    contextMenu->addAction(copyGroupIDAction);
    contextMenu->addAction(copyTickerAction);

    // context menu signals
    connect(ui->treeWidget, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(showMenu(QPoint)));
    connect(copyGroupIDAction, SIGNAL(triggered()), this, SLOT(copyGroupID()));
    connect(copyTickerAction, SIGNAL(triggered()), this, SLOT(copyTicker()));

    // click on checkbox
    connect(ui->treeWidget, SIGNAL(itemChanged(QTreeWidgetItem *, int)), this,
        SLOT(viewItemChanged(QTreeWidgetItem *, int)));

    // click on header
    ui->treeWidget->header()->setSectionsClickable(true);
    connect(ui->treeWidget->header(), SIGNAL(sectionClicked(int)), this, SLOT(headerSectionClicked(int)));

    // ok button
    connect(ui->buttonBox, SIGNAL(clicked(QAbstractButton *)), this, SLOT(buttonBoxClicked(QAbstractButton *)));

    // change coin control first column label due Qt4 bug.
    // see https://github.com/bitcoin/bitcoin/issues/5716
    ui->treeWidget->headerItem()->setText(COLUMN_CHECKBOX, QString());

    ui->treeWidget->setColumnWidth(COLUMN_CHECKBOX, 84);
    ui->treeWidget->setColumnWidth(COLUMN_TOKEN_TICKER, 100);
    ui->treeWidget->setColumnWidth(COLUMN_GROUPID, 170);

    // hide the remove functionality for now, it needs a second list to track it
    ui->removeTokenButton->setEnabled(false);
    ui->removeTokenButton->hide();

    // default view is sorted by amount desc
    sortView(COLUMN_TOKEN_TICKER, Qt::AscendingOrder);
}

TokenDisplayDialog::~TokenDisplayDialog()
{
    delete ui;
}

void TokenDisplayDialog::setModel(WalletModel *_model)
{
    this->model = _model;

    if (_model)
    {
        updateView();
    }
}

// helper function str_pad
QString TokenDisplayDialog::strPad(QString s, int nPadLength, QString sPadding)
{
    while (s.length() < nPadLength)
    {
        s = sPadding + s;
    }
    return s;
}

void TokenDisplayDialog::on_addTokenButton_clicked()
{
    EditTokenDialog dlg(EditTokenDialog::AddToken, this);
    dlg.setDialogReference(this);
    dlg.exec();
}

void TokenDisplayDialog::on_removeTokenButton_clicked()
{
    EditTokenDialog dlg(EditTokenDialog::RemoveToken, this);
    dlg.setDialogReference(this);
    dlg.exec();
}

// ok button
void TokenDisplayDialog::buttonBoxClicked(QAbstractButton *button)
{
    if (ui->buttonBox->buttonRole(button) == QDialogButtonBox::AcceptRole)
    {
        done(QDialog::Accepted); // closes the dialog
    }
}

// context menu
void TokenDisplayDialog::showMenu(const QPoint &point)
{
    QTreeWidgetItem *item = ui->treeWidget->itemAt(point);
    if (item)
    {
        contextMenuItem = item;
        // show context menu
        contextMenu->exec(QCursor::pos());
    }
}

// context menu action: copy GroupID
void TokenDisplayDialog::copyGroupID()
{
    GUIUtil::setClipboard(contextMenuItem->text(COLUMN_GROUPID));
}

// context menu action: copy label
void TokenDisplayDialog::copyTicker()
{
    GUIUtil::setClipboard(contextMenuItem->text(COLUMN_TOKEN_TICKER));
}

// treeview: sort
void TokenDisplayDialog::sortView(int column, Qt::SortOrder order)
{
    sortColumn = column;
    sortOrder = order;
    ui->treeWidget->sortItems(column, order);
    ui->treeWidget->header()->setSortIndicator(sortColumn, sortOrder);
}

// treeview: clicked on header
void TokenDisplayDialog::headerSectionClicked(int logicalIndex)
{
    if (logicalIndex == COLUMN_CHECKBOX) // click on most left column -> do nothing
    {
        ui->treeWidget->header()->setSortIndicator(sortColumn, sortOrder);
    }
    else
    {
        if (sortColumn == logicalIndex)
        {
            sortOrder = ((sortOrder == Qt::AscendingOrder) ? Qt::DescendingOrder : Qt::AscendingOrder);
        }
        else
        {
            sortColumn = logicalIndex;
            // if label or address then default => asc, else default => desc
            sortOrder = ((sortColumn == COLUMN_TOKEN_TICKER || sortColumn == COLUMN_GROUPID) ? Qt::AscendingOrder :
                                                                                        Qt::DescendingOrder);
        }
        sortView(sortColumn, sortOrder);
    }
}

// checkbox clicked by user
void TokenDisplayDialog::viewItemChanged(QTreeWidgetItem *item, int column)
{
    if (column == COLUMN_CHECKBOX)
    {
        const CGroupTokenID grpID = DecodeGroupToken(item->text(COLUMN_GROUPID).toStdString());
        const std::string strTokenTicker = item->text(COLUMN_TOKEN_TICKER).toStdString();

        if (item->checkState(COLUMN_CHECKBOX) == Qt::Unchecked)
        {
            model->RemoveTokenTracker(grpID);
        }
        else
        {
            model->AddTokenTracker(grpID, strTokenTicker);
        }
    }
}

void TokenDisplayDialog::updateView()
{
    // model is wallet model
    if (!model)
    {
        return;
    }
    ui->treeWidget->clear();
    // performance, otherwise updateLabels would be called for every checked checkbox
    ui->treeWidget->setEnabled(false);
    ui->treeWidget->setAlternatingRowColors(true);
    QFlags<Qt::ItemFlag> flgCheckbox = Qt::ItemIsSelectable | Qt::ItemIsEnabled | Qt::ItemIsUserCheckable;
    std::map<CGroupTokenID, std::string> mapTokens;
    model->listTokens(mapTokens);

    std::map<CGroupTokenID, std::string> mapTrackers;
    model->listTokenTrackers(mapTrackers);

    for (const auto &token : mapTokens)
    {
        QTreeWidgetItem *itemTokenTracker = new QTreeWidgetItem(ui->treeWidget);
        itemTokenTracker->setFlags(flgCheckbox);
        if (mapTrackers.count(token.first))
        {
            itemTokenTracker->setCheckState(COLUMN_CHECKBOX, Qt::Checked);
        }
        else
        {
            itemTokenTracker->setCheckState(COLUMN_CHECKBOX, Qt::Unchecked);
        }
        QString strTokenTicker = QString::fromStdString(token.second);
        itemTokenTracker->setText(COLUMN_TOKEN_TICKER, strTokenTicker);
        QString strGroupID = QString::fromStdString(EncodeGroupToken(token.first));
        itemTokenTracker->setText(COLUMN_GROUPID, strGroupID);
        ui->treeWidget->addTopLevelItem(itemTokenTracker);
    }
    for (const auto &token : mapTrackers)
    {
        // check if was already added to UI
        if (mapTokens.count(token.first))
        {
            // was already added
            continue;
        }
        QTreeWidgetItem *itemTokenTracker = new QTreeWidgetItem(ui->treeWidget);
        itemTokenTracker->setFlags(flgCheckbox);
        itemTokenTracker->setCheckState(COLUMN_CHECKBOX, Qt::Checked);
        QString strTokenTicker = QString::fromStdString(token.second);
        itemTokenTracker->setText(COLUMN_TOKEN_TICKER, strTokenTicker);
        QString strGroupID = QString::fromStdString(EncodeGroupToken(token.first));
        itemTokenTracker->setText(COLUMN_GROUPID, strGroupID);
        ui->treeWidget->addTopLevelItem(itemTokenTracker);
    }

    // sort view
    sortView(sortColumn, sortOrder);
    ui->treeWidget->setEnabled(true);
}

int TokenDisplayDialog::AddToken(const QString &strGroupID)
{
    const CGroupTokenID grpID = DecodeGroupToken(strGroupID.toStdString());
    if (grpID == CGroupTokenID() || grpID.isUserGroup() == false)
    {
        return -4;
    }
    std::string strTokenTicker;
    if (GetGroupTicker(grpID, strTokenTicker) == false)
    {
        strTokenTicker = "???";
    }
    int res = model->AddTokenTracker(grpID, strTokenTicker);
    if (res == 0)
    {
        updateView();
    }
    return res;
}

int TokenDisplayDialog::RemoveToken(const QString &strGroupID)
{
    const CGroupTokenID grpID = DecodeGroupToken(strGroupID.toStdString());
    int res = model->RemoveTokenTracker(grpID);
    if (res == 0)
    {
        updateView();
    }
    return res;
}
