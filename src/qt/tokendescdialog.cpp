// Copyright (c) 2015-2023 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "tokendescdialog.h"
#include "ui_tokendescdialog.h"


TokenDescDialog::TokenDescDialog(QString *desc, QWidget *parent)
    : ui(new Ui::TokenDescDialog)
{
    ui->setupUi(this);
    ui->detailText->setHtml(*desc);
}

TokenDescDialog::~TokenDescDialog() { delete ui; }
