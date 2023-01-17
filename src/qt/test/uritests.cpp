// Copyright (c) 2009-2014 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Copyright (c) 2017 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "uritests.h"

#include "chainparams.h"
#include "config.h"
#include "guiutil.h"
#include "walletmodel.h"

#include <QUrl>

void URITests::uriTestsBase58()
{
    SendCoinsRecipient rv;
    QString scheme =
        QString::fromStdString(Params(CBaseChainParams::NEXA).CashAddrPrefix());
    QUrl uri;
    uri.setUrl(QString("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?req-dontexist="));
    QVERIFY(!GUIUtil::parseBitcoinURI(scheme, uri, &rv));

    uri.setUrl(QString("nexa:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?dontexist="));
    QVERIFY(GUIUtil::parseBitcoinURI(scheme, uri, &rv));
    QVERIFY(rv.address == QString("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"));
    QVERIFY(rv.label == QString());
    QVERIFY(rv.amount == 0);

    uri.setUrl(QString("nexa:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?label=Wikipedia Example Address"));
    QVERIFY(GUIUtil::parseBitcoinURI(scheme, uri, &rv));
    QVERIFY(rv.address == QString("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"));
    QVERIFY(rv.label == QString("Wikipedia Example Address"));
    QVERIFY(rv.amount == 0);

    uri.setUrl(QString("nexa:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=0.01"));
    QVERIFY(GUIUtil::parseBitcoinURI(scheme, uri, &rv));
    QVERIFY(rv.address == QString("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"));
    QVERIFY(rv.label == QString());
    QVERIFY(rv.amount == 1);

    uri.setUrl(QString("nexa:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=100.01"));
    QVERIFY(GUIUtil::parseBitcoinURI(scheme, uri, &rv));
    QVERIFY(rv.address == QString("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"));
    QVERIFY(rv.label == QString());
    QVERIFY(rv.amount == 10001);

    uri.setUrl(QString("nexa:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=10000&label=Wikipedia Example"));
    QVERIFY(GUIUtil::parseBitcoinURI(scheme, uri, &rv));
    QVERIFY(rv.address == QString("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"));
    QVERIFY(rv.amount == 1000000LL);
    QVERIFY(rv.label == QString("Wikipedia Example"));

    uri.setUrl(QString("nexa:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?message=Wikipedia Example Address"));
    QVERIFY(GUIUtil::parseBitcoinURI(scheme, uri, &rv));
    QVERIFY(rv.address == QString("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"));
    QVERIFY(rv.label == QString());

    QVERIFY(GUIUtil::parseBitcoinURI(scheme, "nexa://175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?"
                                     "message=Wikipedia Example Address",
                                     &rv));
    QVERIFY(rv.address == QString("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"));
    QVERIFY(rv.label == QString());

    uri.setUrl(QString("nexa:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?req-message=Wikipedia Example Address"));
    QVERIFY(GUIUtil::parseBitcoinURI(scheme, uri, &rv));

    uri.setUrl(QString("nexa:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=1,000&label=Wikipedia Example"));
    QVERIFY(!GUIUtil::parseBitcoinURI(scheme, uri, &rv));

    uri.setUrl(QString("nexa:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=1,000.0&label=Wikipedia Example"));
    QVERIFY(!GUIUtil::parseBitcoinURI(scheme, uri, &rv));
}

void URITests::uriTestsCashAddr() {
    SendCoinsRecipient rv;
    QUrl uri;
    QString scheme =
        QString::fromStdString(Params(CBaseChainParams::NEXA).CashAddrPrefix());

    uri.setUrl(QString("nexa:nqtsq5g5afx6leupc52th7k3gf9vc3dxl6zfev63wp0y86n9?"
                       "req-dontexist="));
    QVERIFY(!GUIUtil::parseBitcoinURI(scheme, uri, &rv));

    uri.setUrl(QString("nexa:nqtsq5g5afx6leupc52th7k3gf9vc3dxl6zfev63wp0y86n9?"
                       "dontexist="));
    QVERIFY(GUIUtil::parseBitcoinURI(scheme, uri, &rv));
    QVERIFY(rv.address ==
            QString("nexa:nqtsq5g5afx6leupc52th7k3gf9vc3dxl6zfev63wp0y86n9"));
    QVERIFY(rv.label == QString());
    QVERIFY(rv.amount == 0);

    uri.setUrl(
        QString("nexa:nqtsq5g5afx6leupc52th7k3gf9vc3dxl6zfev63wp0y86n9?label="
                "Wikipedia Example Address"));
    QVERIFY(GUIUtil::parseBitcoinURI(scheme, uri, &rv));
    QVERIFY(rv.address ==
            QString("nexa:nqtsq5g5afx6leupc52th7k3gf9vc3dxl6zfev63wp0y86n9"));
    QVERIFY(rv.label == QString("Wikipedia Example Address"));
    QVERIFY(rv.amount == 0);

    uri.setUrl(QString(
        "nexa:nqtsq5g5afx6leupc52th7k3gf9vc3dxl6zfev63wp0y86n9?amount=0.01"));
    QVERIFY(GUIUtil::parseBitcoinURI(scheme, uri, &rv));
    QVERIFY(rv.address ==
            QString("nexa:nqtsq5g5afx6leupc52th7k3gf9vc3dxl6zfev63wp0y86n9"));
    QVERIFY(rv.label == QString());
    QVERIFY(rv.amount == 1);

    uri.setUrl(QString(
        "nexa:nqtsq5g5afx6leupc52th7k3gf9vc3dxl6zfev63wp0y86n9?amount=1.01"));
    QVERIFY(GUIUtil::parseBitcoinURI(scheme, uri, &rv));
    QVERIFY(rv.address ==
            QString("nexa:nqtsq5g5afx6leupc52th7k3gf9vc3dxl6zfev63wp0y86n9"));
    QVERIFY(rv.label == QString());
    QVERIFY(rv.amount == 101);

    uri.setUrl(QString(
        "nexa:nqtsq5g5afx6leupc52th7k3gf9vc3dxl6zfev63wp0y86n9?amount=100&"
        "label=Wikipedia Example"));
    QVERIFY(GUIUtil::parseBitcoinURI(scheme, uri, &rv));
    QVERIFY(rv.address ==
            QString("nexa:nqtsq5g5afx6leupc52th7k3gf9vc3dxl6zfev63wp0y86n9"));
    QVERIFY(rv.amount == 10000LL);
    QVERIFY(rv.label == QString("Wikipedia Example"));

    uri.setUrl(QString(
        "nexa:nqtsq5g5afx6leupc52th7k3gf9vc3dxl6zfev63wp0y86n9?message="
        "Wikipedia Example Address"));
    QVERIFY(GUIUtil::parseBitcoinURI(scheme, uri, &rv));
    QVERIFY(rv.address ==
            QString("nexa:nqtsq5g5afx6leupc52th7k3gf9vc3dxl6zfev63wp0y86n9"));
    QVERIFY(rv.label == QString());

    QVERIFY(GUIUtil::parseBitcoinURI(
        scheme, "nexa://nqtsq5g5afx6leupc52th7k3gf9vc3dxl6zfev63wp0y86n9?"
                "message=Wikipedia Example Address",
        &rv));
    QVERIFY(rv.address ==
            QString("nexa:nqtsq5g5afx6leupc52th7k3gf9vc3dxl6zfev63wp0y86n9"));
    QVERIFY(rv.label == QString());

    uri.setUrl(QString(
        "nexa:nqtsq5g5afx6leupc52th7k3gf9vc3dxl6zfev63wp0y86n9?req-message="
        "Wikipedia Example Address"));
    QVERIFY(GUIUtil::parseBitcoinURI(scheme, uri, &rv));

    uri.setUrl(QString(
        "nexa:nqtsq5g5afx6leupc52th7k3gf9vc3dxl6zfev63wp0y86n9?amount=1,"
        "000&label=Wikipedia Example"));
    QVERIFY(!GUIUtil::parseBitcoinURI(scheme, uri, &rv));

    uri.setUrl(QString(
        "nexa:nqtsq5g5afx6leupc52th7k3gf9vc3dxl6zfev63wp0y86n9?amount=1,"
        "000.0&label=Wikipedia Example"));
    QVERIFY(!GUIUtil::parseBitcoinURI(scheme, uri, &rv));
}

namespace {
class UriTestConfig : public DummyConfig {
public:
    UriTestConfig(bool _useCashAddr)
        : useCashAddr(_useCashAddr), net(CBaseChainParams::NEXA) {}
    bool UseCashAddrEncoding() const override { return useCashAddr; }
    const CChainParams &GetChainParams() const override { return Params(net); }
    void SetChainParams(const std::string &n) { net = n; }

private:
    bool useCashAddr;
    std::string net;
};

} // anon ns

void URITests::uriTestFormatURI() {
    {
        UriTestConfig cfg(true);
        SendCoinsRecipient r;
        r.address = "nexa:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a";
        r.message = "test";
        QString uri = GUIUtil::formatBitcoinURI(cfg, r);
        QVERIFY(uri == "nexa:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a?"
                       "message=test");
    }

    {
        UriTestConfig cfg(false);
        SendCoinsRecipient r;
        r.address = "175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W";
        r.message = "test";
        QString uri = GUIUtil::formatBitcoinURI(cfg, r);
        QVERIFY(uri ==
                "nexa:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?message=test");
    }
}

void URITests::uriTestScheme() {
    {
        // cashaddr - scheme depends on selected chain params
        UriTestConfig config(true);
        config.SetChainParams(CBaseChainParams::NEXA);
        QVERIFY("nexa" == GUIUtil::bitcoinURIScheme(config));
        config.SetChainParams(CBaseChainParams::TESTNET);
        QVERIFY("nexatest" == GUIUtil::bitcoinURIScheme(config));
        config.SetChainParams(CBaseChainParams::REGTEST);
        QVERIFY("nexareg" == GUIUtil::bitcoinURIScheme(config));
    }
    {
        // legacy - scheme is "nex" regardless of chain params
        UriTestConfig config(false);
        config.SetChainParams(CBaseChainParams::NEXA);
        QVERIFY("nexa" == GUIUtil::bitcoinURIScheme(config));
        config.SetChainParams(CBaseChainParams::TESTNET);
        QVERIFY("nexa" == GUIUtil::bitcoinURIScheme(config));
        config.SetChainParams(CBaseChainParams::REGTEST);
        QVERIFY("nexa" == GUIUtil::bitcoinURIScheme(config));
    }
}
