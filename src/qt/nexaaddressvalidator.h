// Copyright (c) 2011-2014 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Copyright (c) 2017 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_QT_NEXAADDRESSVALIDATOR_H
#define NEXA_QT_NEXAADDRESSVALIDATOR_H

#include <QValidator>

/**
 * Address entry widget validator, checks for valid characters and
 * removes some whitespace.
 */
class AddressEntryValidator : public QValidator
{
    Q_OBJECT

public:
    explicit AddressEntryValidator(const std::string &cashaddrprefix, QObject *parent);

    State validate(QString &input, int &pos) const;

private:
    std::string cashaddrprefix;
};

/** Address widget validator, checks for a valid address.
 */
class AddressCheckValidator : public QValidator
{
    Q_OBJECT

public:
    explicit AddressCheckValidator(QObject *parent, bool _fTokens = false);

    State validate(QString &input, int &pos) const;

private:
    bool fTokens; // is this for validating and address to send tokens to.
};

#endif // NEXA_QT_NEXAADDRESSVALIDATOR_H
