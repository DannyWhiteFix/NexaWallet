// Copyright (c) 2011-2015 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_QT_ADDTOKENDIALOG_H
#define NEXA_QT_ADDTOKENDIALOG_H

#include <QDialog>

class TokenDisplayDialog;

namespace Ui
{
class EditTokenDialog;
}

QT_BEGIN_NAMESPACE
class QDataWidgetMapper;
QT_END_NAMESPACE

/** Dialog for editing an address and associated information.
 */
class EditTokenDialog : public QDialog
{
    Q_OBJECT

public:
    enum Mode
    {
        AddToken,
        RemoveToken,
    };

    explicit EditTokenDialog(Mode mode, QWidget *parent);
    ~EditTokenDialog();

    void setDialogReference(TokenDisplayDialog *model);
    void loadRow(int row);

public Q_SLOTS:
    void accept();

private:
    bool saveCurrentRow();

    Ui::EditTokenDialog *ui;
    QDataWidgetMapper *mapper;
    Mode mode;
    TokenDisplayDialog *model;
};

#endif // NEXA_QT_ADDTOKENDIALOG_H
