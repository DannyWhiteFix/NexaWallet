// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_BANENTRY_H
#define NEXA_BANENTRY_H

// NOTE: netaddress.h includes serialize.h which is required for serialization macros
#include "netaddress.h" // for CSubNet

typedef enum BanReason
{
    BanReasonUnknown = 0,
    BanReasonNodeMisbehaving = 1,
    BanReasonManuallyAdded = 2,
    BanReasonTooManyEvictions = 3,
    BanReasonTooManyConnectionAttempts = 4,
    BanReasonInvalidMessageStart = 5,
    BanReasonInvalidInventory = 6,
    BanReasonInvalidPeer = 7,
    BanReasonBadBlockData = 8,
    BanReasonIncorrectlyReconstructedBlock = 9,
    BanReasonNotInBlockIndex = 10,
    BanReasonInvalidHeader = 11,
    BanReasonUnrequestedBlock = 12,
    BanReasonHashIsNull = 13,
    BanReasonInvalidSize = 14,
    BanReasonInvalidFilter = 15,
    BanReasonBadConnectionHandshake = 16,
    BanReasonInvalidProtocolVersion = 17,
    BanReasonInvalidOrMissingInputs = 18,
    BanReasonNotAnExpeditedNode = 19,
    BanReasonInvalidBlock = 20,
    BanReasonInvalidPriority = 21,
    BanReasonDSProofOrphanExpiry = 22,
    BanReasonInvalidDSProof = 23,
    BanReasonUnsupportedPeer = 24,
    BanReasonMessageRequestsTooFrequent = 25,
    BanReasonUnrequestedObject = 26,
    BanReasonInvalidObject = 27,
    BanReasonIncorrectMerkleRoot = 28,
} BanReason;

class CBanEntry
{
public:
    static const int CURRENT_VERSION = 1;
    int nVersion;
    int64_t nCreateTime;
    int64_t nBanUntil;
    uint8_t banReason;
    std::string userAgent;

    CBanEntry();
    CBanEntry(int64_t nCreateTimeIn);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(this->nVersion);
        READWRITE(nCreateTime);
        READWRITE(nBanUntil);
        READWRITE(banReason);
        READWRITE(userAgent);
    }

    void SetNull();

    std::string banReasonToString();
};

typedef std::map<CSubNet, CBanEntry> banmap_t;

#endif // NEXA_BANENTRY_H
