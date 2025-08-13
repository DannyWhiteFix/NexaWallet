// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2018-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_NET_PROCESSING_H
#define NEXA_NET_PROCESSING_H

#include "net.h"

class CUtxo;

/** Process protocol messages received from a given node */
bool ProcessMessages(CNode *pfrom);


/** Process a single protocol messages received from a given node
    @param pfrom The node this message originated from
    @param strCommand The message type
    @param msgCookie A number passed by the requester that should be returned in the response
    @param vRecv The message contents
    @param nStopwatchTimeReceived Stopwatch time in microseconds indicating when this message was received
*/
bool ProcessMessage(CNode *pfrom,
    std::string strCommand,
    uint32_t msgCookie,
    CDataStream &vRecv,
    int64_t nStopwatchTimeReceived);

/**
 * Send queued protocol messages to be sent to a give node.
 *
 * @param[in]   pto             The node which we are sending messages to.
 */
bool SendMessages(CNode *pto);

/** Create a utxo object for sending back data to the requester */
void CreateUTXO(COutPoint &out, CUtxo &utxo);

#endif
