// Copyright (c) 2015-2023 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_QT_TOKENDESCDIALOG_H
#define NEXA_QT_TOKENDESCDIALOG_H

#include <QDialog>

namespace Ui
{
class TokenDescDialog;
}

/** Dialog showing token details. */
class TokenDescDialog : public QDialog
{
    Q_OBJECT

public:
    explicit TokenDescDialog(QString *desc, QWidget *parent = nullptr);
    ~TokenDescDialog();

private:
    Ui::TokenDescDialog *ui;
};

#endif // NEXA_QT_TOKENDESCDIALOG_H
