// Copyright (c) 2011-2015 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "paymentserver.h"

#include "guiutil.h"
#include "nexaunits.h"
#include "optionsmodel.h"

#include "chainparams.h"
#include "config.h"
#include "dstencode.h"
#include "main.h" // For minRelayTxFee
#include "policy/policy.h"
#include "ui_interface.h"
#include "util.h"
#include "wallet/wallet.h"

#include <cstdlib>

#include <QApplication>
#include <QByteArray>
#include <QDataStream>
#include <QDateTime>
#include <QDebug>
#include <QFile>
#include <QFileOpenEvent>
#include <QHash>
#include <QList>
#include <QLocalServer>
#include <QLocalSocket>
#include <QStringList>
#include <QUrlQuery>

const int NEXA_IPC_CONNECT_TIMEOUT = 1000; // milliseconds

//
// Create a name that is unique for:
//  testnet / non-testnet
//  data directory
//
static QString ipcServerName()
{
    QString name("NexaQt");

    // Append a simple hash of the datadir
    // Note that GetDataDir(true) returns a different path
    // for -testnet versus main net
    QString ddir(QString::fromStdString(GetDataDir(true).string()));
    name.append(QString::number(qHash(ddir)));

    return name;
}

//
// We store payment URIs and requests received before
// the main GUI window is up and ready to ask the user
// to send payment.

static QList<QString> savedPaymentRequests;

static std::string ipcParseURI(const QString &arg, const CChainParams &params, bool useCashAddr)
{
    const QString scheme = GUIUtil::bitcoinURIScheme(params, useCashAddr);
    if (!arg.startsWith(scheme + ":", Qt::CaseInsensitive))
    {
        return {};
    }

    SendCoinsRecipient r;
    if (!GUIUtil::parseBitcoinURI(scheme, arg, &r))
    {
        return {};
    }

    return r.address.toStdString();
}

static bool ipcCanParseCashAddrURI(const QString &arg, const std::string &network)
{
    const CChainParams &params(Params(network));
    std::string addr = ipcParseURI(arg, params, true);
    return IsValidDestinationString(addr, params);
}

static bool ipcCanParseLegacyURI(const QString &arg, const std::string &network)
{
    const CChainParams &params(Params(network));
    std::string addr = ipcParseURI(arg, params, false);
    return IsValidDestinationString(addr, params);
}

//
// Sending to the server is done synchronously, at startup.
// If the server isn't already running, startup continues,
// and the items in savedPaymentRequest will be handled
// when uiReady() is called.
//
// Warning: ipcSendCommandLine() is called early in init,
// so don't use "Q_EMIT message()", but "QMessageBox::"!
//
void PaymentServer::ipcParseCommandLine(int argc, char *argv[])
{
    std::array<const std::string *, 3> networks = {
        {&CBaseChainParams::NEXA, &CBaseChainParams::TESTNET, &CBaseChainParams::REGTEST}};

    const std::string *chosenNetwork = nullptr;

    for (int i = 1; i < argc; i++)
    {
        QString arg(argv[i]);
        if (arg.startsWith("-"))
            continue;

        const std::string *itemNetwork = nullptr;

        // Try to parse as a URI
        for (auto net : networks)
        {
            if (ipcCanParseCashAddrURI(arg, *net))
            {
                itemNetwork = net;
                break;
            }

            if (ipcCanParseLegacyURI(arg, *net))
            {
                itemNetwork = net;
                break;
            }
        }

        if (chosenNetwork && chosenNetwork != itemNetwork)
        {
            qWarning() << "PaymentServer::ipcSendCommandLine: Payment request "
                          "from network "
                       << QString(itemNetwork->c_str()) << " does not match already chosen network "
                       << QString(chosenNetwork->c_str());
            continue;
        }

        savedPaymentRequests.append(arg);
        chosenNetwork = itemNetwork;
    }

    if (chosenNetwork)
    {
        SelectParams(*chosenNetwork);
    }
}

//
// Sending to the server is done synchronously, at startup.
// If the server isn't already running, startup continues,
// and the items in savedPaymentRequest will be handled
// when uiReady() is called.
//
bool PaymentServer::ipcSendCommandLine()
{
    bool fResult = false;
    Q_FOREACH (const QString &r, savedPaymentRequests)
    {
        QLocalSocket *socket = new QLocalSocket();
        socket->connectToServer(ipcServerName(), QIODevice::WriteOnly);
        if (!socket->waitForConnected(NEXA_IPC_CONNECT_TIMEOUT))
        {
            delete socket;
            socket = nullptr;
            return false;
        }

        QByteArray block;
        QDataStream out(&block, QIODevice::WriteOnly);
        out.setVersion(QDataStream::Qt_4_0);
        out << r;
        out.device()->seek(0);

        socket->write(block);
        socket->flush();
        socket->waitForBytesWritten(NEXA_IPC_CONNECT_TIMEOUT);
        socket->disconnectFromServer();

        delete socket;
        socket = nullptr;
        fResult = true;
    }

    return fResult;
}

PaymentServer::PaymentServer(QObject *parent, bool startLocalServer)
    : QObject(parent), saveURIs(true), uriServer(0), optionsModel(0)
{
    // Install global event filter to catch QFileOpenEvents
    // on Mac: sent when you click nexa: links
    // other OSes: helpful when dealing with payment request files
    if (parent)
        parent->installEventFilter(this);

    QString name = ipcServerName();

    // Clean up old socket leftover from a crash:
    QLocalServer::removeServer(name);

    if (startLocalServer)
    {
        uriServer = new QLocalServer(this);

        if (!uriServer->listen(name))
        {
            // constructor is called early in init, so don't use "Q_EMIT
            // message()" here
            QMessageBox::critical(0, tr("Payment request error"), tr("Cannot start click-to-pay handler"));
        }
        else
        {
            connect(uriServer, SIGNAL(newConnection()), this, SLOT(handleURIConnection()));
        }
    }
}

PaymentServer::~PaymentServer() {}
//
// OSX-specific way of handling nexa: URIs.
//
bool PaymentServer::eventFilter(QObject *object, QEvent *event)
{
    if (event->type() == QEvent::FileOpen)
    {
        QFileOpenEvent *fileEvent = static_cast<QFileOpenEvent *>(event);
        if (!fileEvent->file().isEmpty())
            handleURIOrFile(fileEvent->file());
        else if (!fileEvent->url().isEmpty())
            handleURIOrFile(fileEvent->url().toString());

        return true;
    }

    return QObject::eventFilter(object, event);
}

void PaymentServer::uiReady()
{
    saveURIs = false;
    Q_FOREACH (const QString &s, savedPaymentRequests)
    {
        handleURIOrFile(s);
    }
    savedPaymentRequests.clear();
}

bool PaymentServer::handleURI(const QString &scheme, const QString &s)
{
    if (!s.startsWith(scheme + ":", Qt::CaseInsensitive))
    {
        return false;
    }

    QUrlQuery uri((QUrl(s)));
    // normal URI
    SendCoinsRecipient recipient;
    if (GUIUtil::parseBitcoinURI(scheme, s, &recipient))
    {
        if (!IsValidDestinationString(recipient.address.toStdString()))
        {
            Q_EMIT message(tr("URI handling"), tr("Invalid payment address %1").arg(recipient.address),
                CClientUIInterface::MSG_ERROR);
        }
        else
        {
            Q_EMIT receivedPaymentRequest(recipient);
        }
    }
    else
    {
        Q_EMIT message(tr("URI handling"),
            tr("URI cannot be parsed! This can be caused by an invalid "
               "Nexa address or malformed URI parameters."),
            CClientUIInterface::ICON_WARNING);
    }

    return true;
}

void PaymentServer::handleURIOrFile(const QString &s)
{
    if (saveURIs)
    {
        savedPaymentRequests.append(s);
        return;
    }

    // nexa: CashAddr URI
    QString schemeCash = GUIUtil::bitcoinURIScheme(Params(), true);
    if (handleURI(schemeCash, s))
    {
        return;
    }

    // nexa: Legacy URI
    QString schemeLegacy = GUIUtil::bitcoinURIScheme(Params(), false);
    if (handleURI(schemeLegacy, s))
    {
        return;
    }
}

void PaymentServer::handleURIConnection()
{
    QLocalSocket *clientConnection = uriServer->nextPendingConnection();

    while (clientConnection->bytesAvailable() < (int)sizeof(quint32))
        clientConnection->waitForReadyRead();

    connect(clientConnection, SIGNAL(disconnected()), clientConnection, SLOT(deleteLater()));

    QDataStream in(clientConnection);
    in.setVersion(QDataStream::Qt_4_0);
    if (clientConnection->bytesAvailable() < (int)sizeof(quint16))
    {
        return;
    }
    QString msg;
    in >> msg;

    handleURIOrFile(msg);
}

void PaymentServer::setOptionsModel(OptionsModel *_optionsModel) { this->optionsModel = _optionsModel; }
