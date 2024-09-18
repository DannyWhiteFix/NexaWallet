// Copyright (c) 2015-2023 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_QT_TOKENSVIEWDIALOG_H
#define NEXA_QT_TOKENSVIEWDIALOG_H

#include "config.h"
#include "guiutil.h"
#include "qt/tokendescdialog.h"
#include "walletmodel.h"

#include <QDialog>
#include <QTimer>


class Config;
class PlatformStyle;

QT_BEGIN_NAMESPACE
class QMenu;
class QSignalMapper;
QT_END_NAMESPACE

namespace Ui
{
class TokensViewDialog;
}

class TokensViewDialog : public QDialog
{
    Q_OBJECT

public:
    explicit TokensViewDialog(const PlatformStyle *platformStyle, const Config *cfg, QWidget *parent = 0);
    ~TokensViewDialog();

    void setModel(WalletModel *_model);
    bool fIsTokenDescDialogOpen;

private:
    Ui::TokensViewDialog *ui;
    WalletModel *model;

    QMenu *contextMenu;
    QSignalMapper *mapperThirdPartyTokenUrls;

    const PlatformStyle *platformStyle;
    const Config *cfg;

    QTimer *pollTimer;
    bool fForceCheckBalanceChanged;
    bool fInstantTransactions;
    int64_t nStartCheck;
    bool fRunOnce;
    int nCurrentRowCount;
    TokenDescDialog *uiTokenDesc = nullptr;

public Q_SLOTS:
    void checkBalanceChanged();
    void refresh();

private Q_SLOTS:
    void contextualMenu(const QPoint &point);
    void copyGrpID();
    void openThirdPartyTokenUrl(QString url);
    void showEvent(QShowEvent *event);
    void on_addressBookButton_clicked();
    void on_deleteButton_clicked();
    void on_pasteButton_clicked();
    void on_tokenTable_itemClicked();
    void on_tokenTable_itemDoubleClicked();
    void on_sendButton_clicked();
    void setManageDisplayedTokensButton(bool);
    void on_manageDisplayedTokensButton_clicked();
    void keyPressEvent(QKeyEvent *event);
};

#endif // NEXA_QT_TOKENSVIEWDIALOG_H
