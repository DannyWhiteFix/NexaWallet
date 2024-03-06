// Copyright (c) 2011-2013 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "edittokendialog.h"
#include "ui_edittokendialog.h"

#include "tokendisplaydialog.h"
#include "guiutil.h"

#include <QDataWidgetMapper>
#include <QMessageBox>

EditTokenDialog::EditTokenDialog(Mode _mode, QWidget *parent)
    : QDialog(parent), ui(new Ui::EditTokenDialog), mapper(0), mode(_mode), model(0)
{
    ui->setupUi(this);

    //GUIUtil::setupAddressWidget(ui->addressEdit, this);

    switch (mode)
    {
    case AddToken:
        setWindowTitle(tr("Add new token"));
        break;
    case RemoveToken:
        setWindowTitle(tr("Remove existing token"));
        break;
    default:
        setWindowTitle(tr("Token Dialog Error! Please notify a developer"));
        ui->groupIDEdit->setEnabled(false);
    }
    mapper = new QDataWidgetMapper(this);
    mapper->setSubmitPolicy(QDataWidgetMapper::ManualSubmit);
}

EditTokenDialog::~EditTokenDialog() { delete ui; }
void EditTokenDialog::setDialogReference(TokenDisplayDialog *_model)
{
    this->model = _model;
}

void EditTokenDialog::accept()
{
    if (!model)
    {
        return;
    }
    if (mode == AddToken)
    {
        if (ui->groupIDEdit->text() == "")
        {
            QMessageBox::warning(this, windowTitle(), tr("Group ID required."), QMessageBox::Ok, QMessageBox::Ok);
            return;
        }
        int res = model->AddToken(ui->groupIDEdit->text());
        // check for error
        if (res < 0)
        {
            if (res == -4)
            {
                QMessageBox::warning(this, windowTitle(), tr("Failed to add token: Invalid Group ID."), QMessageBox::Ok, QMessageBox::Ok);
                return;
            }
            QMessageBox::warning(this, windowTitle(), tr("Failed to add token."), QMessageBox::Ok, QMessageBox::Ok);
            return;
        }
    }
    else if(mode == RemoveToken)
    {
        if (ui->groupIDEdit->text() == "")
        {
            QMessageBox::warning(this, windowTitle(), tr("Group ID required."), QMessageBox::Ok, QMessageBox::Ok);
            return;
        }
        int res = model->RemoveToken(ui->groupIDEdit->text());
        // check for error
        if (res < 0)
        {
            QMessageBox::warning(this, windowTitle(), tr("Failed to remove token."), QMessageBox::Ok, QMessageBox::Ok);
            return;
        }

    }
    // fall through and do nothing
    QDialog::accept();
}
