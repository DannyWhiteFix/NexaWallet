// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef LIBNEXA_COMMON_H
#define LIBNEXA_COMMON_H

/* clang-format off */
// must be first for windows
#include "compat.h"
/* clang-format on */

#include <algorithm>
#include <chrono>
#include <ctime>
#include <string>
#include <vector>

#include "arith_uint256.h"
#include "base58.h"
#include "bloom.h"
#include "capd/capd.h"
#include "cashaddrenc.h"
#include "chainparams.h"
#include "coins.h"
#include "consensus/validation.h"
#include "crypto/aes.h"
#include "dstencode.h"
#include "merkleblock.h"
#include "policy/policy.h"
#include "random.h"
#include "script/scripttemplate.h"
#include "script/sign.h"
#include "streams.h"
#include "tinyformat.h"
#include "uint256.h"
#include "util.h"
#include "utilstrencodings.h"
#include "wallet/grouptokencache.h"

enum class LIBNEXA_ERROR : uint32_t
{
    SUCCESS_NO_ERROR = 0, // success
    INVALID_ARG = 1, // an arg is either NULL or has an invalid size
    DECODE_FAILURE = 2, // failed to decode some array of bytes passed in
    RETURN_FAILURE = 3, // unable to return the result for some reason
    INTERNAL_ERROR = 4, // critical logic or implementation error somewhere
};

uint32_t get_error_code();
void set_error(LIBNEXA_ERROR new_err, std::string new_err_str = "");
void get_error_string(char *buf, uint64_t buflen);

// DER-encoded ECDSA is more like 72 but better to be safe
// Schnorr is only 64, but this must also include a few extra bytes for the sighashtype
#define MAX_SIG_LEN 100

extern ECCVerifyHandle *verifyContext;
extern CChainParams *libnexaParams;

// Must match the equivalent object in calling language code (e.g. PayAddressType)
// Matches the CashAddrType enum used for address types in cashaddrenc.h with the addition of NONE
typedef enum
{
    PayAddressTypeP2PKH = 0,
    PayAddressTypeP2SH = 1,
    PayAddressTypeGROUP = 11, // This defines a group (not a destination address), is a placeholder only
    PayAddressTypeTEMPLATE = 19, // Generalized pay to script template
    PayAddressTypeNONE = 255 // arbitrary, use max value to signify no destination
} PayAddressType;

// Must match the equivalent object in calling language code (e.g. ChainSelector)
typedef enum
{
    AddrBlockchainNexa = 1,
    AddrBlockchainTestnet = 2,
    AddrBlockchainRegtest = 3,
    AddrBlockchainBCH = 4,
    AddrBlockchainBchTestnet = 5,
    AddrBlockchainBchRegtest = 6
} ChainSelector;

class PubkeyExtractor
{
protected:
    const CChainParams &params;
    std::vector<unsigned char> &dest;

public:
    PubkeyExtractor(std::vector<unsigned char> &destination, const CChainParams &p) : params(p), dest(destination) {}
    void operator()(const CKeyID &id) const
    {
        dest.resize(21);
        dest[0] = PayAddressTypeP2PKH;
        memcpy(&dest[1], id.begin(), 20); // pubkey is 20 bytes
    }
    void operator()(const CScriptID &id) const
    {
        dest.resize(21);
        dest[0] = PayAddressTypeP2SH;
        memcpy(&dest[1], id.begin(), 20); // pubkey is 20 bytes
    }
    void operator()(const CNoDestination &) const
    {
        dest.resize(1);
        dest[0] = PayAddressTypeNONE;
    }
    void operator()(const ScriptTemplateDestination &id) const
    {
        // There may be no pubkey here or we can't find it anyway... extract and return the script
        dest.resize(1);
        dest[0] = PayAddressTypeTEMPLATE;
        dest = id.appendTo(dest);
    }
};

class CDecodablePartialMerkleTree : public CPartialMerkleTree
{
public:
    std::vector<uint256> &accessHashes() { return vHash; }
    CDecodablePartialMerkleTree(unsigned int ntx, const unsigned char *bitField, int bitFieldLen)
    {
        nTransactions = ntx;
        vBits.resize(bitFieldLen * 8);
        for (unsigned int p = 0; p < vBits.size(); p++)
            vBits[p] = (bitField[p / 8] & (1 << (p % 8))) != 0;
        fBad = false;
    }
};

// libnexa does not support versionbits right now so just supply this which is used in chainparams
struct ForkDeploymentInfo
{
    /** Deployment name */
    const char *name;
    /** Whether GBT clients can safely ignore this rule in simplified usage */
    bool gbt_force;
    /** What is this client's vote? */
    bool myVote;
};
extern struct ForkDeploymentInfo VersionBitsDeploymentInfo[];

/**  Subset of BCH chainparams so we can convert addresses and do other light-client operations
 */
class BchRegtestParams : public CChainParams
{
public:
    BchRegtestParams()
    {
        strNetworkID = "regtest"; // Do not use the const string because of ctor execution order issues
        consensus.nSubsidyHalvingInterval = 150;
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.powAlgorithm = 0;
        consensus.initialSubsidy = 50 * COIN;
        // The half life for the ASERT DAA. For every (nASERTHalfLife) seconds behind schedule the blockchain gets,
        // difficulty is cut in half. Doubled if blocks are ahead of schedule.
        // Two days
        consensus.nASERTHalfLife = 2 * 24 * 60 * 60;

        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;
        /*
        pchCashMessageStart[0] = 0xda;
        pchCashMessageStart[1] = 0xb5;
        pchCashMessageStart[2] = 0xbf;
        pchCashMessageStart[3] = 0xfa;
        */
        nDefaultPort = DEFAULT_REGTESTNET_PORT;
        nPruneAfterHeight = 1000;

        vFixedSeeds.clear(); //! Regtest mode doesn't have any fixed seeds.
        vSeeds.clear(); //! Regtest mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;

        checkpointData =
            (CCheckpointData){{{0, uint256S("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206")}}, 0};
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<uint8_t>(1, 111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<uint8_t>(1, 196);
        base58Prefixes[SECRET_KEY] = std::vector<uint8_t>(1, 239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};
        cashaddrPrefix = "bchreg";
    }
};
static BchRegtestParams bchRegtestParams;

/**
 * Testnet (v4)
 */
class BchTestnet4Params : public CChainParams
{
public:
    BchTestnet4Params()
    {
        strNetworkID = "test4"; // Do not use the const string because of ctor execution order issues
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.powLimit = uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.powAlgorithm = 0;
        consensus.initialSubsidy = 50 * COIN;
        // The half life for the ASERT DAA. For every (nASERTHalfLife) seconds behind schedule the blockchain gets,
        // difficulty is cut in half. Doubled if blocks are ahead of schedule.
        // One hour
        consensus.nASERTHalfLife = 60 * 60;

        pchMessageStart[0] = 0xcd;
        pchMessageStart[1] = 0x22;
        pchMessageStart[2] = 0xa7;
        pchMessageStart[3] = 0x92;
        /*
        pchCashMessageStart[0] = 0xe2;
        pchCashMessageStart[1] = 0xb7;
        pchCashMessageStart[2] = 0xda;
        pchCashMessageStart[3] = 0xaf;
        */
        nDefaultPort = 28333;
        nPruneAfterHeight = 1000;

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        vSeeds.emplace_back(CDNSSeedData("bitcoinforks.org", "testnet4-seed-bch.bitcoinforks.org", true));
        vSeeds.emplace_back(CDNSSeedData("toom.im", "testnet4-seed-bch.toom.im", true));
        vSeeds.emplace_back(CDNSSeedData("loping.net", "seed.tbch4.loping.net", true));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<uint8_t>(1, 111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<uint8_t>(1, 196);
        base58Prefixes[SECRET_KEY] = std::vector<uint8_t>(1, 239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};
        cashaddrPrefix = "bchtest";

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;

        // clang-format off
        checkpointData = CCheckpointData();
        MapCheckpoints &checkpoints = checkpointData.mapCheckpoints;
        checkpoints[     0] = uint256S("0x000000001dd410c49a788668ce26751718cc797474d3152a5fc073dd44fd9f7b");
        checkpoints[ 16845] = uint256S("0x00000000fb325b8f34fe80c96a5f708a08699a68bbab82dba4474d86bd743077");
        // clang-format on

        // Data as of block
        // 0000000019df558b6686b1a1c3e7aee0535c38052651b711f84eebafc0cc4b5e
        // (height 5677)
        checkpointData.nTimeLastCheckpoint = 1599886634;
    }
};

static BchTestnet4Params bchTestnet4Params;

int64_t GetAdjustedTime();

#ifdef DEBUG_LOCKORDER // Not debugging the lockorder in libnexa even if its defined
void AssertLockHeldInternal(const char *pszName, const char *pszFile, unsigned int nLine, void *cs);
void AssertLockNotHeldInternal(const char *pszName, const char *pszFile, unsigned int nLine, void *cs);
void EnterCritical(const char *pszName,
    const char *pszFile,
    unsigned int nLine,
    void *cs,
    LockType locktype,
    OwnershipType ownership,
    bool fTry);
void LeaveCritical(void *cs);
void AssertWriteLockHeldInternal(const char *pszName,
    const char *pszFile,
    unsigned int nLine,
    CSharedCriticalSection *cs);
void AssertRecursiveWriteLockHeldInternal(const char *pszName,
    const char *pszFile,
    unsigned int nLine,
    CRecursiveSharedCriticalSection *cs);
#endif // DEBUG_LOCKORDER

#ifdef DEBUG_PAUSE
void DbgPause();
extern "C" void DbgResume();
#endif // DEBUG_PAUSE

int LogPrintStr(const std::string &str);
bool GetBoolArg(const std::string &strArg, bool fDefault);
CChainParams *GetChainParams(ChainSelector chainSelector);

void checkSigInit();
CKey LoadKey(const unsigned char *src);

#endif // LIBNEXA_COMMON_H
