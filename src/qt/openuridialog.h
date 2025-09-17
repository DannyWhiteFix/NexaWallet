// Copyright (c) 2011-2015 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_QT_OPENURIDIALOG_H
#define NEXA_QT_OPENURIDIALOG_H

#include <QDialog>

class Config;

namespace Ui
{
class OpenURIDialog;
}

class OpenURIDialog : public QDialog
{
    Q_OBJECT

public:
    explicit OpenURIDialog(const Config *cfg, QWidget *parent);
    ~OpenURIDialog();

    QString getURI();

protected Q_SLOTS:
    void accept();

private:
    Ui::OpenURIDialog *ui;
    const Config *cfg;
};

#endif // NEXA_QT_OPENURIDIALOG_H
