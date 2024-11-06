// Copyright (c) 2015-2023 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "tokensviewdialog.h"
#include "ui_tokensviewdialog.h"

#include "addressbookpage.h"
#include "addresstablemodel.h"
#include "consensus/grouptokens.h"
#include "dstencode.h"
#include "guiutil.h"
#include "optionsmodel.h"
#include "platformstyle.h"
#include "qt/guiconstants.h"
#include "qt/guiutil.h"
#include "qt/tokendisplaydialog.h"
#include "qt/transactionrecord.h"
#include "tweak.h"
#include "wallet/grouptokencache.h"
#include "wallet/grouptokenwallet.h"
#include "wallet/wallet.h"

#include <algorithm>

#include <QClipboard>
#include <QDesktopServices>
#include <QHeaderView>
#include <QKeyEvent>
#include <QMessageBox>
#include <QPalette>
#include <QSignalMapper>

extern CTweak<bool> tokenWhitelist;

extern std::atomic<bool> fImporting;
extern std::atomic<bool> fReindex;
extern bool IsChainNearlySyncd();
extern CTweak<bool> instantTxns;
extern CTweak<uint32_t> instantTxnsDelay;

static void RefreshTokenWallet(TokensViewDialog *tokenwallet, CWallet *wallet, const uint256 &hash, ChangeType status)
{
    Q_UNUSED(wallet);
    Q_UNUSED(hash);
    Q_UNUSED(status);
    QMetaObject::invokeMethod(tokenwallet, "refresh", Qt::QueuedConnection);
}

static void RefreshTokenWallet2(TokensViewDialog *tokenwallet)
{
    QMetaObject::invokeMethod(tokenwallet, "refresh", Qt::QueuedConnection);
}

TokensViewDialog::TokensViewDialog(const PlatformStyle *_platformStyle, const Config *_cfg, QWidget *parent)
    : QDialog(parent), ui(new Ui::TokensViewDialog), model(0), platformStyle(_platformStyle), cfg(_cfg)
{
    ui->setupUi(this);
    ui->tokenTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->tokenTable->setSelectionMode(QAbstractItemView::SingleSelection);
    ui->tokenTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ui->tokenTable->setColumnWidth(0, 350);
    ui->tokenTable->setColumnWidth(5, 30);
    ui->tokenTable->setDragEnabled(false);
    ui->tokenTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    ui->tokenTable->setAutoScroll(false);
    ui->tokenTable->setContextMenuPolicy(Qt::CustomContextMenu);

    ui->addressBookButton->setIcon(platformStyle->SingleColorIcon(":/icons/address-book"));
    ui->pasteButton->setIcon(platformStyle->SingleColorIcon(":/icons/editpaste"));
    ui->deleteButton->setIcon(platformStyle->SingleColorIcon(":/icons/remove"));

    QPalette p = palette();
    p.setColor(QPalette::Inactive, QPalette::Highlight, p.color(QPalette::Active, QPalette::Highlight));
    p.setColor(QPalette::Inactive, QPalette::HighlightedText, p.color(QPalette::Active, QPalette::HighlightedText));
    setPalette(p);

    GUIUtil::setupAddressWidget(ui->payTo, this, true);
    GUIUtil::setupAmountWidget(ui->payAmount, this, 0);

    // Actions
    mapperThirdPartyTokenUrls = new QSignalMapper(this);
    QAction *copyGrpIDAction = new QAction(tr("Copy token id"), this);

    contextMenu = new QMenu(this);
    contextMenu->addAction(copyGrpIDAction);

    // This timer will be fired repeatedly to update the table balances
    // and taking into account whether instant transaction is turned on or not.
    fForceCheckBalanceChanged = true;
    fInstantTransactions = instantTxns.Value();
    nStartCheck = GetTime();
    fRunOnce = true;
    nCurrentRowCount = 0;

    // The first sort must be done after the first refresh. This
    // ensures that when the token wallet is opened the first time that
    // the tokes are arranged in sort order by "name"
    {
        refresh();
        ui->tokenTable->sortByColumn(1, Qt::AscendingOrder);
    }

    pollTimer = new QTimer(this);
    connect(pollTimer, SIGNAL(timeout()), this, SLOT(checkBalanceChanged()));
    pollTimer->start(MODEL_UPDATE_DELAY1);

    setManageDisplayedTokensButton(tokenWhitelist.Value());

    // Connect actions
    connect(ui->tokenTable, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(contextualMenu(QPoint)));
    connect(copyGrpIDAction, SIGNAL(triggered()), this, SLOT(copyGrpID()));
    connect(mapperThirdPartyTokenUrls, SIGNAL(mapped(QString)), this, SLOT(openThirdPartyTokenUrl(QString)));

    // subscribe to core signals
    pwalletMain->NotifyTransactionChanged.connect(
        boost::bind(RefreshTokenWallet, this, boost::arg<1>(), boost::arg<2>(), boost::arg<3>()));
    pwalletMain->NotifyTokenTrackersChanged.connect(boost::bind(RefreshTokenWallet2, this));
}

TokensViewDialog::~TokensViewDialog()
{
    delete uiTokenDesc;
    delete ui;
}

void TokensViewDialog::contextualMenu(const QPoint &point)
{
    QList selectedItems = ui->tokenTable->selectedItems();
    if (selectedItems.size() >= 1)
    {
        contextMenu->exec(QCursor::pos());
    }
}
void TokensViewDialog::copyGrpID()
{
    QList selectedItems = ui->tokenTable->selectedItems();
    QString strGrpIDSelected;
    if (selectedItems.size() >= 1)
    {
        // get the grpID
        strGrpIDSelected = selectedItems[0]->text();

        // Copy first item
        GUIUtil::setClipboard(strGrpIDSelected);
    }
}

void TokensViewDialog::openThirdPartyTokenUrl(QString url)
{
    QList selectedItems = ui->tokenTable->selectedItems();
    QString strGrpIDSelected;
    if (selectedItems.size() >= 1)
    {
        // get the grpID
        strGrpIDSelected = selectedItems[0]->text();
    }
    QDesktopServices::openUrl(QUrl::fromUserInput(url.replace("%s", strGrpIDSelected)));
}

void TokensViewDialog::checkBalanceChanged()
{
    if (!pwalletMain)
        return;

    // Get required locks upfront. This avoids the GUI from getting stuck on
    // periodical polls if the core is holding the locks for a longer time -
    // for example, during a wallet rescan.
    TRY_LOCK(pwalletMain->cs_wallet, lockWallet);
    if (!lockWallet)
        return;

    // If instant transactions was modified then force a balance update. Although
    // we force a balance check again if instant txns is on, we need this switch here
    // for when instant txns is turned off.
    bool temp = instantTxns.Value();
    if (temp != fInstantTransactions)
    {
        fForceCheckBalanceChanged = true;
        fInstantTransactions = temp;
    }

    // If instant transactions is turned on then every few seconds force a balance check
    if (fInstantTransactions)
    {
        int64_t nNow = GetTime();
        if ((nNow - nStartCheck) > instantTxnsDelay.Value())
        {
            fForceCheckBalanceChanged = true;
            nStartCheck = nNow;
        }
    }

    if (fForceCheckBalanceChanged || fRunOnce)
    {
        refresh();
    }
}

void TokensViewDialog::refresh()
{
    // We must set this false here rather than at the end of this function in case the poll timer fires
    // again before we've finished.  This then causes sorting issues in the table since we have to turn
    // off sorting, rebuild the table, and then turn sort back on again before completing.
    fForceCheckBalanceChanged = false;

    // Because we can't try lock the wallet here we don't want to force an update of the token wallet
    // during a reindex or initial sync.
    if (fImporting || fReindex || (!IsChainNearlySyncd() && !fReindex && !fImporting))
        return;

    // refresh the table of token balances and descriptions
    std::unordered_map<CGroupTokenID, CAmount> balances;
    std::unordered_map<CGroupTokenID, CAmount> pending;

    std::set<CGroupTokenID> all_tokens;

    // Get Balances - this is quite performant since it only parses the much smaller unspent wallet map.
    if (pwalletMain)
    {
        bool fWhitelist = tokenWhitelist.Value();
        LOCK(pwalletMain->cs_wallet);
        for (MapWallet::const_iterator it = pwalletMain->mapWalletUnspent.begin();
             it != pwalletMain->mapWalletUnspent.end(); ++it)
        {
            CGroupTokenInfo tg(it->second.GetScriptPubKey());

            if (!pwalletMain->IsSpent(it->first) && tg.associatedGroup != NoGroup && !tg.isAuthority())
            {
                all_tokens.emplace(tg.associatedGroup);
            }

            if (fWhitelist && !pwalletMain->mapTokenTrackers.count(tg.associatedGroup))
            {
                continue;
            }
            const CWalletTxRef ptx = it->second.tx;
            if (ptx->IsTrusted())
            {
                if (!pwalletMain->IsSpent(it->first) && tg.associatedGroup != NoGroup && !tg.isAuthority())
                {
                    balances[tg.associatedGroup] += tg.quantity;
                }
            }
            else if (ptx->GetDepthInMainChain() == 0 && ptx->InMempool())
            {
                if (!pwalletMain->IsSpent(it->first) && tg.associatedGroup != NoGroup && !tg.isAuthority())
                {
                    pending[tg.associatedGroup] += tg.quantity;
                }
            }
        }
    }

    const size_t nTokensDisplayed = pending.size() + balances.size();

    ui->tokensInWalletLabel->setText(QString::fromStdString("Tokens in Wallet: " + std::to_string(all_tokens.size())));
    ui->tokensDisplayedLabel->setText(QString::fromStdString("Tokens Displayed: " + std::to_string(nTokensDisplayed)));


    // Get the current item if it is selected
    QList selectedItems = ui->tokenTable->selectedItems();
    QString strGrpIDSelected;
    if (selectedItems.size() >= 4)
    {
        // get the grpID
        strGrpIDSelected = selectedItems[0]->text();
    }

    // Add items to the table
    ui->tokenTable->setSortingEnabled(false);

    int row = 0;
    for (const auto &iter : balances)
    {
        // Add another row if needed
        if (row >= ui->tokenTable->rowCount())
            ui->tokenTable->insertRow(ui->tokenTable->rowCount());

        // Add group IDs
        CGroupTokenID grpID = iter.first;
        QTableWidgetItem *item1 = new QTableWidgetItem(EncodeGroupToken(grpID).c_str());
        ui->tokenTable->setItem(row, 0, item1);
        if (grpID.isSubgroup())
        {
            // Set the group id to the parent group so we can later get the parent ticker, name and decimals
            grpID = grpID.parentGroup();

            // add subgroup checkmark
            QLabel *checkmark = new QLabel();
            QIcon icon(":/icons/synced");
            checkmark->setPixmap(icon.pixmap(STATUSBAR_ICONSIZE, STATUSBAR_ICONSIZE));
            checkmark->setAlignment(Qt::AlignCenter);
            ui->tokenTable->setCellWidget(row, 5, checkmark);
        }
        else
        {
            ui->tokenTable->removeCellWidget(row, 5);
        }

        // Get the name/ticker and decimals
        auto info = tokencache.GetTokenDesc(grpID);
        std::string name = "";
        std::string ticker = "";
        if (info.size() >= 4)
        {
            name = info[1];
            ticker = info[0];
        }
        uint32_t nDecimal = 0;
        if (info.size() >= 5)
        {
            try
            {
                nDecimal = stoi(info[4]);
            }
            catch (...)
            {
                nDecimal = 0;
            }
        }

        // Add the descriptions and tickers
        QTableWidgetItem *item2 = new QTableWidgetItem(name.c_str());
        item2->setTextAlignment(Qt::AlignCenter);
        ui->tokenTable->setItem(row, 1, item2);

        QTableWidgetItem *item3 = new QTableWidgetItem(ticker.c_str());
        item3->setTextAlignment(Qt::AlignCenter);
        ui->tokenTable->setItem(row, 2, item3);

        // Add balances and pending entries taking into account any "decimals"
        uint64_t nTokens = iter.second;
        uint64_t nTokensPending = pending[grpID];
        {
            // balance
            double nDisplayTokens = (double)(nTokens) / pow(10, nDecimal);
            QString strDisplayTokens = QString::number(nDisplayTokens, 'f', nDecimal);
            QTableWidgetItem *item4 = new QTableWidgetItem(strDisplayTokens.toStdString().c_str());
            item4->setTextAlignment(Qt::AlignCenter);
            ui->tokenTable->setItem(row, 3, item4);

            // pending
            double nDisplayPendingTokens = (double)(nTokensPending) / pow(10, nDecimal);
            QString strDisplayPendingTokens = QString::number(nDisplayPendingTokens, 'f', nDecimal);
            QTableWidgetItem *item5 = new QTableWidgetItem(strDisplayPendingTokens.toStdString().c_str());
            item5->setTextAlignment(Qt::AlignCenter);
            ui->tokenTable->setItem(row, 4, item5);
        }

        row++;
    }
    // Resize table in the event that one item was removed as when
    // the full balance of a token would have been sent and we now
    // should show one less.  We could just resize to zero but doing
    // it this way prevents the scroll bar from moving to a different
    // position.
    nCurrentRowCount = row;
    ui->tokenTable->setRowCount(nCurrentRowCount);

    // After sorting is re-enabled make sure the any previously selected row remains selected.
    ui->tokenTable->setSortingEnabled(true);
    if (!strGrpIDSelected.isEmpty())
    {
        QList foundItems = ui->tokenTable->findItems(strGrpIDSelected, Qt::MatchExactly);
        if (foundItems.size() > 0)
        {
            ui->tokenTable->setCurrentItem(foundItems[0]);
            ui->tokenTable->selectRow(ui->tokenTable->currentRow());
        }
    }

    fRunOnce = false;
}

void TokensViewDialog::showEvent(QShowEvent *event) { ui->payAmount->setFocus(); }

// Select an address to send to from the wallet's address book
void TokensViewDialog::on_addressBookButton_clicked()
{
    AddressBookPage dlg(platformStyle, AddressBookPage::ForSelection, AddressBookPage::SendingTab, this);
    if (model)
    {
        dlg.setModel(model->getAddressTableModel());
        if (dlg.exec())
        {
            ui->payTo->setText(dlg.getReturnValue());
            ui->payAmount->setFocus();
        }
    }
}

// Clear entry fields
void TokensViewDialog::on_deleteButton_clicked()
{
    ui->payTo->clear();
    ui->payAmount->clear();
}

void TokensViewDialog::on_pasteButton_clicked()
{
    // Paste text from clipboard into recipient field
    ui->payTo->setText(QApplication::clipboard()->text());
}

void TokensViewDialog::on_tokenTable_itemClicked()
{
    QList selectedItems = ui->tokenTable->selectedItems();

    if (selectedItems.size() < 1)
    {
        InitWarning(_("Table not intialized. Try again."));
        return;
    }

    std::string strGrp = selectedItems[0]->text().toStdString();
    CGroupTokenID grpID;
    grpID = DecodeGroupToken(strGrp);
    if (!grpID.isUserGroup())
    {
        InitWarning(_("Token ID is not valid."));
        return;
    }

    GUIUtil::setupAmountWidget(ui->payAmount, this, GetDecimal(grpID));
    ui->payAmount->setFocus();
}

void TokensViewDialog::on_tokenTable_itemDoubleClicked()
{
    QList selectedItems = ui->tokenTable->selectedItems();
    std::string strGrp = selectedItems[0]->text().toStdString();
    CGroupTokenID grpID;
    grpID = DecodeGroupToken(strGrp);
    if (!grpID.isUserGroup())
    {
        InitWarning(_("Token ID is not valid."));
        return;
    }

    QString infoString;
    if (grpID.isSubgroup())
    {
        infoString.append("<b> Token ID:</b>  " + selectedItems[0]->text() + "<br>");
        std::vector<unsigned char> vData = grpID.getSubgroupData();
        std::string strData(vData.begin(), vData.end());
        infoString.append("<b> " + tr("Data") + " </b>(" + tr("string") + "):  " + QString(strData.c_str()) + "<br>");
        try
        {
            CDataStream ss(0, 0);
            for (auto c : vData)
                ss << c;
            uint64_t nData = ser_readdata64(ss);
            infoString.append("<b> " + tr("Data") + " </b>(" + tr("num") + "):  " + QString::number(nData) + "<br>");
        }
        catch (...)
        {
            infoString.append("<b> " + tr("Data") + " </b>(" + tr("num") + "):  <i>" + tr("NaN") + "</i><br>");
        }
        if (tokenmint.GetSyncFlag())
        {
            auto info = tokencache.GetTokenDesc(grpID.parentGroup());
            uint32_t nDecimal = 0;
            if (info.size() >= 5)
            {
                try
                {
                    nDecimal = stoi(info[4]);
                }
                catch (...)
                {
                    nDecimal = 0;
                }
            }

            if (nDecimal)
            {
                double nDisplayTokens = (double)(tokenmint.GetTokenMint(grpID).first) / pow(10, nDecimal);
                QString strDisplayMintage = QString::number(nDisplayTokens, 'f', nDecimal);
                infoString.append("<b> " + tr("Total Mintage:") + "</b>  " + strDisplayMintage + "<br>");
            }
            else
            {
                infoString.append("<b> " + tr("Total Mintage:") + "</b>  " +
                                  QString::number(tokenmint.GetTokenMint(grpID).first) + "<br>");
            }
        }
        else
        {
            infoString.append("<b> " + tr("Total Mintage:") + "</b><i>  (" +
                              tr("Token mintage is unavailable because the database needs a reindex") + ")</i><br>");
        }
        infoString.append("<br>");

        // Get the parent group and display it.  Also re-assign the grpID to be the parent group
        // which will be used down below to get the token descriptions.
        infoString.append("<b> Parent ID:</b>  " + QString(EncodeGroupToken(grpID.parentGroup()).c_str()) + "<br>");

        infoString.append("<b> " + tr("Name:") + "</b>  " + selectedItems[1]->text() + "<br>");
        infoString.append("<b> " + tr("Ticker:") + "</b>  " + selectedItems[2]->text() + "<br>");

        auto info = tokencache.GetTokenDesc(grpID.parentGroup());
        if (info.size() >= 4)
        {
            infoString.append("<b> " + tr("URL:") + "</b>  " + QString(info[2].c_str()) + "<br>");
            infoString.append("<b> " + tr("Hash:") + "</b>  " + QString(info[3].c_str()) + "<br>");
        }
        if (info.size() >= 5)
        {
            infoString.append("<b> " + tr("Decimals:") + "</b>  " + QString(info[4].c_str()) + "<br>");
        }
        // Authorities
        if (info.size() >= 10 && tokencache.GetSyncFlag())
        {
            infoString.append("<br>");
            infoString.append("<u><b> " + tr("Current Authorities:") + "</b></u><br><br>");
            infoString.append(
                "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;" + tr("Mint:") + "  " + QString(info[5].c_str()) + "<br>");
            infoString.append(
                "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;" + tr("Melt:") + "  " + QString(info[6].c_str()) + "<br>");
            infoString.append(
                "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;" + tr("Renew:") + "  " + QString(info[7].c_str()) + "<br>");
            infoString.append(
                "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;" + tr("Rescript:") + "  " + QString(info[8].c_str()) + "<br>");
            infoString.append(
                "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;" + tr("Subgroup:") + "  " + QString(info[9].c_str()) + "<br>");
        }
        else
        {
            infoString.append("<b> " + tr("Current Authorities:") + "</b><i>  (" +
                              tr("Token authorities are unavailable because the database needs a reindex") +
                              ")</i><br>");
        }

        infoString.append("<hr></hr>");
        infoString.append("<b> " + tr("Balance:") + "</b>  " + selectedItems[3]->text() + "<br>");
        infoString.append("<b> " + tr("Pending:") + "</b>  " + selectedItems[4]->text() + "<br>");
    }
    else
    {
        infoString.append("<b> Token ID:</b>  " + selectedItems[0]->text() + "<br>");
        infoString.append("<b> " + tr("Name:") + "</b>  " + selectedItems[1]->text() + "<br>");
        infoString.append("<b> " + tr("Ticker:") + "</b>  " + selectedItems[2]->text() + "<br>");

        auto info = tokencache.GetTokenDesc(grpID);
        if (info.size() >= 4)
        {
            infoString.append("<b> " + tr("URL:") + "</b>  " + QString(info[2].c_str()) + "<br>");
            infoString.append("<b> " + tr("Hash:") + "</b>  " + QString(info[3].c_str()) + "<br>");
        }
        if (info.size() >= 5)
        {
            infoString.append("<b> " + tr("Decimals:") + "</b>  " + QString(info[4].c_str()) + "<br>");
        }
        if (tokenmint.GetSyncFlag())
        {
            uint32_t nDecimal = 0;
            if (info.size() >= 5)
            {
                try
                {
                    nDecimal = stoi(info[4]);
                }
                catch (...)
                {
                    nDecimal = 0;
                }
            }

            if (nDecimal)
            {
                double nDisplayTokens = (double)(tokenmint.GetTokenMint(grpID).first) / pow(10, nDecimal);
                QString strDisplayMintage = QString::number(nDisplayTokens, 'f', nDecimal);
                infoString.append("<b> " + tr("Total Mintage:") + "</b>  " + strDisplayMintage + "<br>");
            }
            else
            {
                infoString.append("<b> " + tr("Total Mintage:") + "</b>  " +
                                  QString::number(tokenmint.GetTokenMint(grpID).first) + "<br>");
            }
        }
        else
        {
            infoString.append("<b> " + tr("Total Mintage:") + "</b><i>  (" +
                              tr("Token mintage is unavailable because the database needs a reindex") + ")</i><br>");
        }

        // Authorities
        if (info.size() >= 10 && tokencache.GetSyncFlag())
        {
            infoString.append("<br>");
            infoString.append("<u><b> " + tr("Current Authorities:") + "</b></u><br><br>");
            infoString.append(
                "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;" + tr("Mint:") + "  " + QString(info[5].c_str()) + "<br>");
            infoString.append(
                "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;" + tr("Melt:") + "  " + QString(info[6].c_str()) + "<br>");
            infoString.append(
                "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;" + tr("Renew:") + "  " + QString(info[7].c_str()) + "<br>");
            infoString.append(
                "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;" + tr("Rescript:") + "  " + QString(info[8].c_str()) + "<br>");
            infoString.append(
                "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;" + tr("Subgroup:") + "  " + QString(info[9].c_str()) + "<br>");
        }
        else
        {
            infoString.append("<b> " + tr("Current Authorities:") + "</b><i>  (" +
                              tr("Token authorities are unavailable because the database needs a reindex") +
                              ")</i><br>");
        }


        infoString.append("<hr></hr>");
        infoString.append("<b> " + tr("Balance:") + "</b>  " + selectedItems[3]->text() + "<br>");
        infoString.append("<b> " + tr("Pending:") + "</b>  " + selectedItems[4]->text() + "<br>");
    }

    if (!uiTokenDesc || !uiTokenDesc->isVisible())
    {
        uiTokenDesc = new TokenDescDialog(&infoString, this);
        uiTokenDesc->exec();
    }
}

void TokensViewDialog::on_sendButton_clicked()
{
    // Check if wallet is unlocked and if not ask for passphrase
    WalletModel::UnlockContext ctx(model->requestUnlock());
    if (!ctx.isValid())
    {
        // Unlock wallet was cancelled
        return;
    }

    // Get group id from the table
    QList selectedItems = ui->tokenTable->selectedItems();
    if (selectedItems.empty())
    {
        InitWarning(_("You did not select a token from the list."));
        return;
    }
    if (selectedItems.size() < 4)
    {
        InitWarning(_("Table not intialized. Try again."));
        return;
    }

    std::string strGrp = selectedItems[0]->text().toStdString();
    CGroupTokenID grpID;
    grpID = DecodeGroupToken(strGrp);
    if (!grpID.isUserGroup())
    {
        InitWarning(_("Token ID is not valid."));
        return;
    }

    // Get amount to send as an integer value while adjusting for decimals
    QString strAmountToSend = ui->payAmount->text();
    double dAmountToSend = strAmountToSend.toDouble();
    uint32_t nDecimal = GetDecimal(grpID);
    if (nDecimal > 0)
        dAmountToSend *= pow(10, nDecimal);
    CAmount nAmountToSend = (uint64_t)(dAmountToSend);

    // Get text value from the table and adjust for the decimal before sending.
    std::string strTokensAvailable = selectedItems[3]->text().toStdString();
    double dAmountAvailable = strTokensAvailable.empty() ? (double)0 : selectedItems[3]->text().toDouble();
    if (nDecimal > 0)
        dAmountAvailable *= pow(10, nDecimal);
    CAmount nAmountAvailable = (uint64_t)(dAmountAvailable);
    if (nAmountToSend <= 0)
    {
        InitWarning(_("Amount to send must be greater than zero."));
        return;
    }
    if (nAmountToSend > nAmountAvailable)
    {
        double dAmountRequired = (double)((nAmountToSend - nAmountAvailable) / pow(10, nDecimal));
        QString strNeedMore = QString::number(dAmountRequired, 'f', nDecimal);

        InitWarning(
            strprintf(_("Insufficient funds for this token.  Need %s more."), strNeedMore.toStdString().c_str()));
        return;
    }

    // Get address to send to
    QString strPayTo = ui->payTo->text();
    if (!model->validateAddress(strPayTo))
    {
        InitWarning(_("Invalid send address."));
        return;
    }
    const std::string strAddress = strPayTo.toStdString();

    // Create recipients vector.
    CTxDestination destination = DecodeDestination(strAddress);
    CScript scriptPubKey = GetScriptForDestination(destination, grpID, nAmountToSend);
    bool fSubtractFeeFromAmount = false;
    std::vector<CRecipient> outputs = {{scriptPubKey, CFeeRate().GetDust(), fSubtractFeeFromAmount}};

    // Send
    QStringList formatted;
    QString questionString = tr("Are you sure you want to send?");
    questionString.append("<br /><br />%1");

    QString strToken = tr("<b>Token(s)</b>");
    if (!selectedItems[1]->text().isEmpty() && !selectedItems[2]->text().isEmpty())
    {
        strToken = "<b>" + selectedItems[2]->text() + "</b>" + " (" + selectedItems[1]->text() + ")";
    }
    else if (selectedItems[1]->text().isEmpty() && !selectedItems[2]->text().isEmpty())
    {
        strToken = "<b>" + selectedItems[2]->text() + "</b>";
    }
    else if (!selectedItems[1]->text().isEmpty() && selectedItems[2]->text().isEmpty())
    {
        strToken = "<b>" + selectedItems[1]->text() + "</b>";
    }

    // generate amount, and token to send, string
    QString amount = "<b>" + strAmountToSend + "</b> " + strToken;
    QString grpid;
    grpid = "Token ID: " + selectedItems[0]->text();

    // generate monospace address string
    QString address = "<br><b>To: </b><span style='font-family: monospace;'>" + strPayTo + "</span></br>";

    // create the formatted list
    formatted.append(amount);
    formatted.append(grpid);
    formatted.append(address);

    QMessageBox::StandardButton retval = QMessageBox::question(this, tr("Confirm send tokens"),
        questionString.arg(formatted.join("<br />")), QMessageBox::Yes | QMessageBox::Cancel, QMessageBox::Cancel);
    if (retval != QMessageBox::Yes)
    {
        return;
    }

    CWalletTx wtx;
    std::string strError;
    bool fRPC = false;
    bool ret = GroupSend(wtx, grpID, outputs, nAmountToSend, pwalletMain, &strError, fRPC);
    if (!ret)
    {
        if (!strError.empty())
        {
            InitWarning(strError);
        }
        else
        {
            InitWarning(_("Send failed."));
        }
    }
    ui->payTo->clear();
    ui->payAmount->clear();
    ui->payAmount->setFocus();
    ui->tokenTable->clearSelection();

    return;
}

// Coin Control: settings menu - coin control enabled/disabled by user
void TokensViewDialog::setManageDisplayedTokensButton(bool checked)
{
    ui->manageDisplayedTokensButton->setVisible(checked);
    ui->manageDisplayedTokensButton->setEnabled(checked);
    ui->tokensInWalletLabel->setVisible(checked);
    ui->tokensDisplayedLabel->setVisible(checked);
}

void TokensViewDialog::on_manageDisplayedTokensButton_clicked()
{
    TokenDisplayDialog dlg(platformStyle);
    dlg.setModel(model);
    dlg.exec();
}

void TokensViewDialog::keyPressEvent(QKeyEvent *event)
{
    // prevent the escape key from closing the tokens tab.
    if (event->key() == Qt::Key_Escape)
    {
        event->ignore();
    }
}

void TokensViewDialog::setModel(WalletModel *_model)
{
    this->model = _model; // need this for the send address selection dialog
    connect(_model->getOptionsModel(), SIGNAL(tokenWhitelistButtonChanged(bool)), this,
        SLOT(setManageDisplayedTokensButton(bool)));

    if (_model->getOptionsModel())
    {
        // Add third party transaction URLs to context menu
        QStringList listUrls = model->getOptionsModel()->getThirdPartyTokenUrls().split("|", QString::SkipEmptyParts);
        for (int i = 0; i < listUrls.size(); ++i)
        {
            QString host = QUrl(listUrls[i].trimmed(), QUrl::StrictMode).host();
            if (!host.isEmpty())
            {
                QAction *thirdPartyTokenUrlAction = new QAction(host, this); // use host as menu item label
                if (i == 0)
                    contextMenu->addSeparator();
                contextMenu->addAction(thirdPartyTokenUrlAction);
                connect(thirdPartyTokenUrlAction, SIGNAL(triggered()), mapperThirdPartyTokenUrls, SLOT(map()));
                mapperThirdPartyTokenUrls->setMapping(thirdPartyTokenUrlAction, listUrls[i].trimmed());
            }
        }
    }
}
