// Copyright (c) 2011-2015 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_QT_TokenDisplayDialog_H
#define NEXA_QT_TokenDisplayDialog_H

#include "amount.h"

#include <QAbstractButton>
#include <QAction>
#include <QDialog>
#include <QList>
#include <QMenu>
#include <QPoint>
#include <QString>
#include <QTreeWidgetItem>

class PlatformStyle;
class WalletModel;

class CCoinControl;
class CTxMemPool;

namespace Ui
{
class TokenDisplayDialog;
}

#define ASYMP_UTF8 "\xE2\x89\x88"

class TokenDisplayDialog : public QDialog
{
    Q_OBJECT

public:
    explicit TokenDisplayDialog(const PlatformStyle *platformStyle, QWidget *parent = 0);
    ~TokenDisplayDialog();

    void setModel(WalletModel *model);
    int AddToken(const QString &strGroupID);
    int RemoveToken(const QString &strGroupID);

private:
    Ui::TokenDisplayDialog *ui;
    WalletModel *model;
    int sortColumn;
    Qt::SortOrder sortOrder;

    QMenu *contextMenu;
    QTreeWidgetItem *contextMenuItem;

    const PlatformStyle *platformStyle;

    QString strPad(QString, int, QString);
    void sortView(int, Qt::SortOrder);
    void updateView();

    enum
    {
        COLUMN_CHECKBOX,
        COLUMN_TOKEN_TICKER,
        COLUMN_GROUPID,
    };

private Q_SLOTS:
    void showMenu(const QPoint &);
    void copyGroupID();
    void copyTicker();
    void viewItemChanged(QTreeWidgetItem *, int);
    void headerSectionClicked(int);
    void buttonBoxClicked(QAbstractButton *);
    void on_addTokenButton_clicked();
    void on_removeTokenButton_clicked();
};

#endif // NEXA_QT_TokenDisplayDialog_H
