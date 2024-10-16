// Copyright (c) 2011-2015 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "transactiondesc.h"

#include "guiutil.h"
#include "nexaunits.h"
#include "paymentserver.h"
#include "transactionrecord.h"

#include "consensus/consensus.h"
#include "dstencode.h"
#include "main.h"
#include "script/script.h"
#include "timedata.h"
#include "txadmission.h"
#include "util.h"
#include "wallet/db.h"
#include "wallet/grouptokencache.h"
#include "wallet/grouptokenwallet.h"
#include "wallet/wallet.h"

#include <stdint.h>
#include <string>

QString TransactionDesc::FormatTxStatus(const CWalletTx &wtx)
{
    if (!CheckFinalTx(MakeTransactionRef(wtx)))
    {
        if (wtx.nLockTime < LOCKTIME_THRESHOLD)
            return tr("Open for %n more block(s)", "", wtx.nLockTime - chainActive.Height());
        else
            return tr("Open until %1").arg(GUIUtil::dateTimeStr(wtx.nLockTime));
    }
    else
    {
        int nDepth = wtx.GetDepthInMainChain();
        if (nDepth == 0 && wtx.fDoubleSpent)
            return tr("double spent");
        else if (wtx.isAbandoned())
            return tr("abandoned");
        else if (nDepth < 0)
            return tr("conflicted");
        else if (GetAdjustedTime() - wtx.nTimeReceived > 2 * 60 && wtx.GetRequestCount() == 0)
            return tr("%1/offline").arg(nDepth);
        else if (nDepth < 6)
            return tr("%1/unconfirmed").arg(nDepth);
        else
            return tr("%1 confirmations").arg(nDepth);
    }
}

QString TransactionDesc::toHTML(CWallet *wallet, CWalletTx &wtx, TransactionRecord *rec, int unit)
{
    QString strHTML;

    LOCK(wallet->cs_wallet);
    strHTML.reserve(4000);
    strHTML += "<html><font face='verdana, arial, helvetica, sans-serif'>";

    int64_t nTime = wtx.GetTxTime();
    CAmount nCredit = wtx.GetCredit(ISMINE_ALL);
    CAmount nDebit = wtx.GetDebit(ISMINE_ALL);
    CAmount nNet = nCredit - nDebit;

    strHTML += "<b>" + tr("Status") + ":</b> " + FormatTxStatus(wtx);
    int nRequests = wtx.GetRequestCount();
    if (nRequests != -1)
    {
        if (nRequests == 0)
            strHTML += tr(", has not been successfully broadcast yet");
        else if (nRequests > 0)
            strHTML += tr(", broadcast through %n node(s)", "", nRequests);
    }
    strHTML += "<br>";
    strHTML += "<b>" + tr("Date") + ":</b> " + (nTime ? GUIUtil::dateTimeStr(nTime) : "") + "<br>";

    //
    // From
    //
    if (wtx.IsCoinBase())
    {
        strHTML += "<b>" + tr("Source") + ":</b> " + tr("Generated") + "<br>";
        strHTML += "<b>" + tr("To") + ":</b> ";
        strHTML += GUIUtil::HtmlEscape(rec->addresses.begin()->first);
        strHTML += "<br>";
    }
    else if (wtx.mapValue.count("from") && !wtx.mapValue["from"].empty())
    {
        // Online transaction
        strHTML += "<b>" + tr("From") + ":</b> " + GUIUtil::HtmlEscape(wtx.mapValue["from"]) + "<br>";
    }
    else
    {
        // Offline transaction
        if (nNet > 0)
        {
            // Credit
            CTxDestination address = DecodeDestination(rec->addresses.begin()->first);
            if (IsValidDestination(address))
            {
                if (wallet->mapAddressBook.count(address))
                {
                    strHTML += "<b>" + tr("From") + ":</b> " + tr("unknown") + "<br>";
                    strHTML += "<b>" + tr("To") + ":</b> ";
                    strHTML += GUIUtil::HtmlEscape(rec->addresses.begin()->first);

                    QString addressOwned;
                    // Include in description label for change address, own address or watch-only
                    if (wtx.vout[0].nValue == wtx.GetChange() && wallet->IsMine(address) == ISMINE_SPENDABLE)
                        addressOwned = tr("change address");
                    else
                        (wallet->IsMine(address) == ISMINE_SPENDABLE) ? tr("own address") : tr("watch-only");

                    if (!wallet->mapAddressBook[address].name.empty())
                        strHTML += " (" + addressOwned + tr("label") + ": " +
                                   GUIUtil::HtmlEscape(wallet->mapAddressBook[address].name) + ")";
                    else
                        strHTML += " (" + addressOwned + ")";

                    strHTML += "<br>";
                }
            }
        }
    }

    //
    // To
    //
    if (wtx.mapValue.count("to") && !wtx.mapValue["to"].empty())
    {
        // Include in description public label if it exists
        std::string labelPublic = getLabelPublic(wtx.vout[0].scriptPubKey);
        if (!labelPublic.empty())
            strHTML += "<b>" + tr("Public label:") + "</b> " + labelPublic.c_str() + "<br>";

        // Online transaction
        CTxDestination address = DecodeDestination(rec->addresses.begin()->first);
        std::string strAddress = wtx.mapValue["to"];
        strHTML += "<b>" + tr("To") + ":</b> ";
        CTxDestination dest = DecodeDestination(strAddress);
        strHTML += GUIUtil::HtmlEscape(rec->addresses.begin()->first);
        if (!wallet->mapAddressBook[dest].name.empty())
            strHTML += " (" + tr("label") + ": " + GUIUtil::HtmlEscape(wallet->mapAddressBook[address].name) + ")";
        strHTML += "<br>";
    }

    //
    // Amount
    //
    if (wtx.IsCoinBase() && nCredit == 0)
    {
        //
        // Coinbase
        //
        CAmount nUnmatured = 0;
        for (const CTxOut &txout : wtx.vout)
        {
            nUnmatured += wallet->GetCredit(txout, ISMINE_ALL);
        }

        strHTML += "<b>" + tr("Credit") + ":</b> ";
        if (wtx.IsInMainChain())
            strHTML += BitcoinUnits::formatHtmlWithUnit(unit, nUnmatured) + " (" +
                       tr("matures in %n more block(s)", "", wtx.GetBlocksToMaturity()) + ")";
        else
            strHTML += "(" + tr("not accepted") + ")";
        strHTML += "<br>";
    }
    else if (nNet > 0)
    {
        // Include in description public label if it exists. If there are multiple outputs then
        // only show the public label associated with this output we are viewing.
        if (!wtx.IsCoinBase())
        {
            std::string labelPublic;
            CTxDestination address = DecodeDestination(rec->addresses.begin()->first);
            for (const CTxOut &txout : wtx.vout)
            {
                std::string tmp_labelPublic = getLabelPublic(txout.scriptPubKey);
                if (!tmp_labelPublic.empty())
                    labelPublic = tmp_labelPublic;

                CTxDestination txout_address;
                if (ExtractDestination(txout.scriptPubKey, txout_address))
                {
                    if (address == txout_address)
                    {
                        // Include in description public label if it exists
                        if (!labelPublic.empty())
                        {
                            strHTML += "<b>" + tr("Public label:") + "</b> " + labelPublic.c_str() + "<br>";
                            labelPublic.clear();
                        }
                    }
                }
            }
        }

        //
        // Credit
        //
        strHTML += "<b>" + tr("Credit") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, nNet) + "<br>";
    }
    else
    {
        isminetype fAllFromMe = ISMINE_SPENDABLE;
        for (const CTxIn &txin : wtx.vin)
        {
            isminetype mine = wallet->IsMine(txin);
            if (fAllFromMe > mine)
                fAllFromMe = mine;
        }

        isminetype fAllToMe = ISMINE_SPENDABLE;
        for (const CTxOut &txout : wtx.vout)
        {
            isminetype mine = wallet->IsMine(txout);
            if (fAllToMe > mine)
                fAllToMe = mine;
        }

        if (fAllFromMe)
        {
            if (fAllFromMe & ISMINE_WATCH_ONLY)
                strHTML += "<b>" + tr("From") + ":</b> " + tr("watch-only") + "<br>";

            //
            // Debit
            //
            CAmount nTotalDebit = 0;
            CAmount nTotalCredit = 0;
            for (const CTxOut &txout : wtx.vout)
            {
                // Ignore change
                isminetype toSelf = wallet->IsMine(txout);

                {
                    // Include in description public label if it exists
                    std::string labelPublic = getLabelPublic(txout.scriptPubKey);
                    if (labelPublic != "")
                        strHTML += "<b>" + tr("Public label:") + "</b> " + labelPublic.c_str() + "<br>";

                    if (!wtx.mapValue.count("to") || wtx.mapValue["to"].empty())
                    {
                        // Offline transaction
                        CTxDestination address;
                        if (ExtractDestination(txout.scriptPubKey, address))
                        {
                            strHTML += "<b>" + tr("To") + ":</b> ";
                            strHTML += GUIUtil::HtmlEscape(EncodeDestination(address));
                            if (wallet->mapAddressBook.count(address) && !wallet->mapAddressBook[address].name.empty())
                                strHTML += " (" + tr("label") + ": " +
                                           GUIUtil::HtmlEscape(wallet->mapAddressBook[address].name) + ")";
                            if (txout.nValue == wtx.GetChange() && toSelf == ISMINE_SPENDABLE)
                                strHTML += " (change address)";
                            else if (toSelf == ISMINE_SPENDABLE)
                                strHTML += " (own address)";
                            else if (toSelf & ISMINE_WATCH_ONLY)
                                strHTML += " (watch-only)";
                            strHTML += "<br>";
                        }
                    }

                    if (labelPublic == "") // hide on public label txout
                    {
                        if (toSelf && GetGroupToken(txout.scriptPubKey) == NoGroup)
                            strHTML += "<b>" + tr("Credit") + ":</b> " +
                                       BitcoinUnits::formatHtmlWithUnit(unit, txout.nValue) + " ";

                        strHTML += "<b>" + tr("Debit") + ":</b> " +
                                   BitcoinUnits::formatHtmlWithUnit(unit, -txout.nValue) + "<br>";
                    }

                    if (GetGroupToken(txout.scriptPubKey) == NoGroup)
                    {
                        nTotalCredit += txout.nValue;
                    }
                    nTotalDebit -= txout.nValue;
                }
            }
            strHTML += "<br>";

            CAmount nTxFee = nDebit - wtx.GetValueOut();
            if (fAllToMe)
            {
                // Payment to self
                strHTML += "<b>" + tr("Total debit") + ":</b> " +
                           BitcoinUnits::formatHtmlWithUnit(unit, nTotalDebit - nTxFee) + "<br>";
                strHTML += "<b>" + tr("Total credit") + ":</b> " +
                           BitcoinUnits::formatHtmlWithUnit(unit, nTotalCredit) + "<br>";
            }

            if (nTxFee > 0)
                strHTML +=
                    "<b>" + tr("Transaction fee") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, -nTxFee) + "<br>";
        }
        else
        {
            //
            // Mixed debit transaction
            //
            for (const CTxIn &txin : wtx.vin)
            {
                if (wallet->IsMine(txin))
                {
                    strHTML += "<b>" + tr("Debit") + ":</b> " +
                               BitcoinUnits::formatHtmlWithUnit(unit, -wallet->GetDebit(txin, ISMINE_ALL)) + "<br>";
                }
            }
            for (const CTxOut &txout : wtx.vout)
            {
                if (wallet->IsMine(txout))
                {
                    // Include in description public label if it exists
                    std::string labelPublic = getLabelPublic(txout.scriptPubKey);
                    if (!labelPublic.empty())
                        strHTML += "<b>" + tr("Public label:") + "</b> " + labelPublic.c_str() + "<br>";

                    strHTML += "<b>" + tr("Credit") + ":</b> " +
                               BitcoinUnits::formatHtmlWithUnit(unit, wallet->GetCredit(txout, ISMINE_ALL)) + "<br>";
                }
            }
        }
    }

    strHTML += "<b>" + tr("Net amount") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, nNet, true) + "<br>";

    //
    // Message
    //
    if (wtx.mapValue.count("message") && !wtx.mapValue["message"].empty())
        strHTML +=
            "<br><b>" + tr("Message") + ":</b><br>" + GUIUtil::HtmlEscape(wtx.mapValue["message"], true) + "<br>";
    if (wtx.mapValue.count("comment") && !wtx.mapValue["comment"].empty())
        strHTML +=
            "<br><b>" + tr("Comment") + ":</b><br>" + GUIUtil::HtmlEscape(wtx.mapValue["comment"], true) + "<br>";

    strHTML += "<b>" + tr("Transaction ID") + ":</b> " + rec->getTxID() + "<br>";
    strHTML += "<b>" + tr("Transaction Idem") + ":</b> " + rec->getTxIdem() + "<br>";
    strHTML += "<b>" + tr("Transaction size") + ":</b> " + QString::number(wtx.GetTxSize()) + " bytes<br>";

    // Message from normal bitcoincash:URI (bitcoincash:123...?message=example)
    for (const std::pair<std::string, std::string> &r : wtx.vOrderForm)
    {
        if (r.first == "Message")
            strHTML += "<br><b>" + tr("Message") + ":</b><br>" + GUIUtil::HtmlEscape(r.second, true) + "<br>";
    }

    //
    // PaymentRequest info:
    //
    for (const std::pair<std::string, std::string> &r : wtx.vOrderForm)
    {
        if (r.first == "PaymentRequest")
        {
            PaymentRequestPlus req;
            req.parse(QByteArray::fromRawData(r.second.data(), r.second.size()));
            QString merchant;
            if (req.getMerchant(PaymentServer::getCertStore(), merchant))
                strHTML += "<b>" + tr("Merchant") + ":</b> " + GUIUtil::HtmlEscape(merchant) + "<br>";
        }
    }

    if (wtx.IsCoinBase())
    {
        quint32 numBlocksToMaturity = Params().GetConsensus().coinbaseMaturity + 1;
        strHTML += "<br>" +
                   tr("Generated coins must mature %1 blocks before they can be spent. When you generated this block, "
                      "it was broadcast to the network to be added to the block chain. If it fails to get into the "
                      "chain, its state will change to \"not accepted\" and it won't be spendable. This may "
                      "occasionally happen if another node generates a block within a few seconds of yours.")
                       .arg(QString::number(numBlocksToMaturity)) +
                   "<br>";
    }

    //
    // Token Information
    //
    std::list<CGroupedOutputEntry> listReceived;
    std::list<CGroupedOutputEntry> listSent;
    CAmount nGroupFee = 0;
    std::string strSentAccount;
    CAmount nTokenInputs = 0;
    wtx.GetAmountsForTokenWalletDisplay(listReceived, listSent, nGroupFee, strSentAccount, ISMINE_ALL, nTokenInputs);

    // When minting to an address not in our wallet,
    // we need to know if we are sending to ourselves or not.
    //
    // Also need to know if we have melt authority to display any melting of tokens.
    bool fAllowsMelt = false;
    bool fAllToMe = true;
    for (const CTxOut &txout : wtx.vout)
    {
        isminetype mine = wallet->IsMine(txout);
        if (fAllToMe > mine)
            fAllToMe = mine;

        CGroupTokenInfo tg(txout.scriptPubKey);
        if (tg.isAuthority() && tg.allowsMelt())
        {
            fAllowsMelt = true;
        }
    }

    // Check for Token Mint
    bool fIsMint = false;
    if (nTokenInputs == 0)
        fIsMint = true;
    if (nTokenInputs == -1)
        fIsMint = false;

    // Check for Token Melt
    if (fAllowsMelt && fAllToMe && !fIsMint && listSent.empty() && listReceived.empty())
    {
        // Find the melt amount
        CAmount nMeltAmount = nTokenInputs;
        CGroupTokenID grpID;
        for (const CTxOut &txout : wtx.vout)
        {
            CGroupTokenInfo tg(txout.scriptPubKey);
            if (tg.associatedGroup != NoGroup && !tg.isAuthority())
            {
                nMeltAmount -= tg.quantity;
            }
            if (tg.isAuthority())
            {
                grpID = tg.associatedGroup;
            }
        }

        if (grpID != NoGroup)
        {
            strHTML += "<br>";
            strHTML += "<b>" + tr("Token ID") + ": </b>" + EncodeGroupToken(grpID).c_str() + "<br>";

            auto info = tokencache.GetTokenDesc(grpID);
            if (info.size() >= 4)
            {
                strHTML += "<b>" + tr("Ticker") + ": </b>" + info[0].c_str() + "<br>";
                strHTML += "<b>" + tr("Name") + ": </b>" + info[1].c_str() + "<br>";
            }

            int nDecimal = GetDecimal(grpID);
            strHTML += "<b>" + tr("Decimals") + ": </b>" + QString::number(nDecimal) + "<br>";

            if (nDecimal)
            {
                double nDisplayTokens = (double)(nMeltAmount) / pow(10, nDecimal);
                QString strDisplayMintage = QString::number(nDisplayTokens, 'f', nDecimal);
                strHTML += "<b>" + tr("Melt") + " " + tr("Amount") + ": </b>" + strDisplayMintage + "<br>";
            }
            else
            {
                strHTML += "<b>" + tr("Melt") + " " + tr("Amount") + ": </b>" + QString::number(nMeltAmount) + "<br>";
            }
        }
    }

    // Only show the sent amount. (This could be a mint but to a non-local address).
    if (!listSent.empty() && (!fAllToMe || nTokenInputs > 0))
    {
        strHTML += "<br>";
        for (const CGroupedOutputEntry &sent : listSent)
        {
            if (sent.grp != NoGroup)
            {
                strHTML += "<b>" + tr("Token ID") + ": </b>" + EncodeGroupToken(sent.grp).c_str() + "<br>";

                auto info = tokencache.GetTokenDesc(sent.grp);
                if (info.size() >= 4)
                {
                    strHTML += "<b>" + tr("Ticker") + ": </b>" + info[0].c_str() + "<br>";
                    strHTML += "<b>" + tr("Name") + ": </b>" + info[1].c_str() + "<br>";
                }
                int nDecimal = GetDecimal(sent.grp);
                strHTML += "<b>" + tr("Decimals") + ": </b>" + QString::number(nDecimal) + "<br>";

                if (listReceived.empty() && fIsMint)
                {
                    if (nDecimal)
                    {
                        double nDisplayTokens = (double)(sent.grpAmount) / pow(10, nDecimal);
                        QString strDisplayMintage = QString::number(nDisplayTokens, 'f', nDecimal);
                        strHTML += "<b>" + tr("Mint") + " " + tr("Amount") + ": </b>" + strDisplayMintage + "<br>";
                    }
                    else
                    {
                        strHTML += "<b>" + tr("Mint") + " " + tr("Amount") + ": </b>" +
                                   QString::number(sent.grpAmount) + "<br>";
                    }
                }

                if (nDecimal)
                {
                    double nDisplayTokens = (double)(sent.grpAmount) / pow(10, nDecimal);
                    QString strDisplayMintage = QString::number(nDisplayTokens, 'f', nDecimal);
                    strHTML += "<b>" + tr("Amount Sent") + ": </b>" + strDisplayMintage + "<br>";
                }
                else
                {
                    strHTML += "<b>" + tr("Amount Sent") + ": </b>" + QString::number(sent.grpAmount) + "<br>";
                }
            }
        }
    }

    // Tokens Received
    if (!listReceived.empty())
    {
        strHTML += "<br>";
        for (const CGroupedOutputEntry &recv : listReceived)
        {
            if (recv.grp != NoGroup)
            {
                strHTML += "<b>" + tr("Token ID") + ": </b>" + EncodeGroupToken(recv.grp).c_str() + "<br>";

                auto info = tokencache.GetTokenDesc(recv.grp);
                if (info.size() >= 4)
                {
                    strHTML += "<b>" + tr("Ticker") + ": </b>" + info[0].c_str() + "<br>";
                    strHTML += "<b>" + tr("Name") + ": </b>" + info[1].c_str() + "<br>";
                }
                int nDecimal = GetDecimal(recv.grp);
                strHTML += "<b>" + tr("Decimals") + ": </b>" + QString::number(nDecimal) + "<br>";
                if (!fIsMint)
                {
                    if (nDecimal)
                    {
                        double nDisplayTokens = (double)(recv.grpAmount) / pow(10, nDecimal);
                        QString strDisplayMintage = QString::number(nDisplayTokens, 'f', nDecimal);
                        strHTML += "<b>" + tr("Amount Received") + ": </b>" + strDisplayMintage + "<br>";
                    }
                    else
                    {
                        strHTML += "<b>" + tr("Amount Received") + ": </b>" + QString::number(recv.grpAmount) + "<br>";
                    }
                }
                else
                {
                    if (nDecimal)
                    {
                        double nDisplayTokens = (double)(recv.grpAmount) / pow(10, nDecimal);
                        QString strDisplayMintage = QString::number(nDisplayTokens, 'f', nDecimal);
                        strHTML += "<b>" + tr("Mint") + " " + tr("Amount") + ": </b>" + strDisplayMintage + "<br>";
                    }
                    else
                    {
                        strHTML += "<b>" + tr("Mint") + " " + tr("Amount") + ": </b>" +
                                   QString::number(recv.grpAmount) + "<br>";
                    }
                }
            }
        }
    }


    //
    // Debug view
    //
    if (fDebug)
    {
        strHTML += "<hr><br>" + tr("Debug information") + "<br><br>";
        for (const CTxIn &txin : wtx.vin)
        {
            if (wallet->IsMine(txin))
            {
                strHTML += "<b>" + tr("Debit") + ":</b> " +
                           BitcoinUnits::formatHtmlWithUnit(unit, -wallet->GetDebit(txin, ISMINE_ALL)) + "<br>";
            }
        }
        for (const CTxOut &txout : wtx.vout)
        {
            if (wallet->IsMine(txout))
            {
                strHTML += "<b>" + tr("Credit") + ":</b> " +
                           BitcoinUnits::formatHtmlWithUnit(unit, wallet->GetCredit(txout, ISMINE_ALL)) + "<br>";
            }
        }

        strHTML += "<br><b>" + tr("Transaction") + ":</b><br>";
        strHTML += GUIUtil::HtmlEscape(wtx.ToString(), true);

        strHTML += "<br><b>" + tr("Inputs") + ":</b>";
        strHTML += "<ul>";

        for (const CTxIn &txin : wtx.vin)
        {
            COutPoint prevout = txin.prevout;

            Coin prev;
            if (pcoinsTip->GetCoin(prevout, prev))
            {
                {
                    strHTML += "<li>";

                    const CTxOut &vout = prev.out;
                    CTxDestination address;
                    if (ExtractDestination(vout.scriptPubKey, address))
                    {
                        if (wallet->mapAddressBook.count(address) && !wallet->mapAddressBook[address].name.empty())
                            strHTML += GUIUtil::HtmlEscape(wallet->mapAddressBook[address].name) + " ";
                        strHTML += QString::fromStdString(EncodeDestination(address));
                    }

                    strHTML = strHTML + " " + tr("Amount") + "=" + BitcoinUnits::formatHtmlWithUnit(unit, vout.nValue);
                    strHTML = strHTML +
                              " IsMine=" + (wallet->IsMine(vout) & ISMINE_SPENDABLE ? tr("true") : tr("false")) +
                              "</li>";
                    strHTML = strHTML +
                              " IsWatchOnly=" + (wallet->IsMine(vout) & ISMINE_WATCH_ONLY ? tr("true") : tr("false")) +
                              "</li>";
                }
            }
        }

        strHTML += "</ul>";
    }

    strHTML += "</font></html>";
    return strHTML;
}
