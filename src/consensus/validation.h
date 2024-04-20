// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_CONSENSUS_VALIDATION_H
#define NEXA_CONSENSUS_VALIDATION_H

#include <map>
#include <string>
#include <vector>

#include "grouptokens.h"
#include "logging.h"

/** "reject" message codes */
static const unsigned char REJECT_MALFORMED = 0x01;
static const unsigned char REJECT_INVALID = 0x10;
static const unsigned char REJECT_OBSOLETE = 0x11;
static const unsigned char REJECT_DUPLICATE = 0x12;
static const unsigned char REJECT_NONSTANDARD = 0x40;
static const unsigned char REJECT_DUST = 0x41;
static const unsigned char REJECT_INSUFFICIENTFEE = 0x42;
static const unsigned char REJECT_FORK = 0x43;
static const unsigned char REJECT_WAITING = 0x44;
static const unsigned char REJECT_MULTIPLE_INPUTS = 0x45; /* Used if we restrict transaction inputs in txadmission */
static const unsigned char REJECT_CHECKPOINT = 0x46;
/** Used when node policy will always prevent a reply from being issued.
 Currently used when the node is pruned so it does not have a block.
*/
static const unsigned char REJECT_LIMITED = 0x47;
/** Used when a temporary condition (such as rate limiting) prevents the processing of a response.
 Currently used when too many historical blocks have been requested.
*/
static const unsigned char REJECT_RETRY = 0x48;

/** Capture information about block/transaction validation */
class CValidationState
{
private:
    enum mode_state
    {
        MODE_VALID, //! everything ok
        MODE_INVALID, //! network rule violation (DoS value may be set)
        MODE_ERROR, //! run-time error
    } mode;
    int nDoS;
    std::string strRejectReason;
    unsigned int chRejectCode;
    bool corruptionPossible;
    std::string strDebugMessage;

public:
    CAmount inAmount = -1;
    CAmount outAmount = -1;
    CAmount fee = -1;
    GroupBalanceMapRef groupState = nullptr;

    CValidationState() : mode(MODE_VALID), nDoS(0), chRejectCode(0), corruptionPossible(false) {}
    bool DoS(int level,
        bool ret = false,
        unsigned int chRejectCodeIn = 0,
        const std::string &strRejectReasonIn = "",
        bool corruptionIn = false,
        const std::string &strDebugMessageIn = "")
    {
        chRejectCode = chRejectCodeIn;
        strRejectReason = strRejectReasonIn;
        corruptionPossible = corruptionIn;
        strDebugMessage = strDebugMessageIn;
        LOG(VALIDATION, "Validation DoS level: %d, Code: %d, Reason: %s, Message: %s\n", level, chRejectCode,
            strRejectReason, strDebugMessage);
        if (mode == MODE_ERROR)
            return ret;
        nDoS += level;
        mode = MODE_INVALID;
        return ret;
    }
    bool Invalid(bool ret = false,
        unsigned int _chRejectCode = 0,
        const std::string &_strRejectReason = "",
        const std::string &_strDebugMessage = "")
    {
        return DoS(0, ret, _chRejectCode, _strRejectReason, false, _strDebugMessage);
    }
    bool Error(const std::string &strRejectReasonIn)
    {
        LOG(VALIDATION, "Validation Error Reason: %s\n", strRejectReasonIn);
        if (mode == MODE_VALID)
            strRejectReason = strRejectReasonIn;
        mode = MODE_ERROR;
        return false;
    }
    bool IsValid() const { return mode == MODE_VALID; }
    bool IsInvalid() const { return mode == MODE_INVALID; }
    bool IsError() const { return mode == MODE_ERROR; }
    bool IsInvalid(int &nDoSOut) const
    {
        if (IsInvalid())
        {
            nDoSOut = nDoS;
            return true;
        }
        return false;
    }
    bool CorruptionPossible() const { return corruptionPossible; }
    void SetCorruptionPossible() { corruptionPossible = true; }
    unsigned int GetRejectCode() const { return chRejectCode; }
    std::string GetRejectReason() const { return strRejectReason; }
    std::string GetDebugMessage() const { return strDebugMessage; }
    void SetDebugMessage(const std::string &s) { strDebugMessage = s; }

    /** Set the quantity of satoshis used by this transaction */
    void SetAmounts(CAmount _inAmount, CAmount _outAmount, CAmount _fee)
    {
        assert(_fee + _outAmount == _inAmount);
        inAmount = _inAmount;
        outAmount = _outAmount;
        fee = _fee;
    }
};

#endif // NEXA_CONSENSUS_VALIDATION_H
