// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "libnexa_common.h"

const int CLIENT_VERSION = 0; // 0 because app should report its version, not this lib

static thread_local LIBNEXA_ERROR lib_err = LIBNEXA_ERROR::SUCCESS_NO_ERROR;
static thread_local std::string str_lib_err = "";

uint32_t get_error_code() { return (uint32_t)lib_err; }

void set_error(LIBNEXA_ERROR new_err, std::string new_err_str)
{
    lib_err = new_err;
    str_lib_err = new_err_str;
}

static const std::string error_code_to_string(const LIBNEXA_ERROR _err)
{
    switch (_err)
    {
    case LIBNEXA_ERROR::SUCCESS_NO_ERROR:
        return "No error";
    case LIBNEXA_ERROR::INVALID_ARG:
        return "Invalid arg";
    case LIBNEXA_ERROR::DECODE_FAILURE:
        return "Decode failure";
    case LIBNEXA_ERROR::RETURN_FAILURE:
        return "Return failure";
    case LIBNEXA_ERROR::INTERNAL_ERROR:
        return "Internal error";
    default:
        break;
    }
    return "Unknown error";
}

void get_error_string(char *buf, uint64_t buflen)
{
    std::string str_err = error_code_to_string((LIBNEXA_ERROR)lib_err);
    if (str_lib_err.size() > 0)
    {
        str_err = str_err + ": " + str_lib_err;
    }
    size_t copyable = str_err.size() + 1; // add one for '\0'
    if (copyable > buflen)
    {
        copyable = buflen;
    }
    std::memcpy(buf, str_err.c_str(), copyable);
}

static bool sigInited = false;
ECCVerifyHandle *verifyContext = nullptr;
CChainParams *libnexaParams = nullptr;

ForkDeploymentInfo VersionBitsDeploymentInfo[Consensus::MAX_VERSION_BITS_DEPLOYMENTS];

// This section of this file provides simple or NO-OP implementations of functions used by the larger codebase
// The time stuff is reimplemented here to avoid a dependency on utiltime, which both
// implements mocktime (using atomics) and has other dependencies for time formatting and logging
int64_t GetAdjustedTime()
{
    time_t now = time(nullptr);
    return now;
}
int64_t GetTime()
{
    time_t now = time(nullptr);
    return now;
}
int64_t GetTimeMicros()
{
    std::chrono::time_point<std::chrono::system_clock> clock_now = std::chrono::system_clock::now();
    int64_t now = std::chrono::duration_cast<std::chrono::microseconds>(clock_now.time_since_epoch()).count();
    return now;
}

#ifdef DEBUG_LOCKORDER // Not debugging the lockorder in libnexa even if its defined
void AssertLockHeldInternal(const char *pszName, const char *pszFile, unsigned int nLine, void *cs) {}
void AssertLockNotHeldInternal(const char *pszName, const char *pszFile, unsigned int nLine, void *cs) {}
void EnterCritical(const char *pszName,
    const char *pszFile,
    unsigned int nLine,
    void *cs,
    LockType locktype,
    OwnershipType ownership,
    bool fTry)
{
}
void LeaveCritical(void *cs) {}
void AssertWriteLockHeldInternal(const char *pszName,
    const char *pszFile,
    unsigned int nLine,
    CSharedCriticalSection *cs)
{
}
void AssertRecursiveWriteLockHeldInternal(const char *pszName,
    const char *pszFile,
    unsigned int nLine,
    CRecursiveSharedCriticalSection *cs)
{
}
CCriticalSection::CCriticalSection() : name(nullptr) {}
CCriticalSection::CCriticalSection(const char *n) : name(n) {}
CCriticalSection::~CCriticalSection() {}
CSharedCriticalSection::CSharedCriticalSection() : name(nullptr) {}
CSharedCriticalSection::CSharedCriticalSection(const char *n) : name(n) {}
CSharedCriticalSection::~CSharedCriticalSection() {}
CRecursiveSharedCriticalSection::CRecursiveSharedCriticalSection() : name(nullptr) {}
CRecursiveSharedCriticalSection::CRecursiveSharedCriticalSection(const char *n) : name(n) {}
CRecursiveSharedCriticalSection::~CRecursiveSharedCriticalSection() {}
#endif // DEBUG_LOCKORDER

#ifdef DEBUG_PAUSE
bool pauseOnDbgAssert = false;
std::mutex dbgPauseMutex;
std::condition_variable dbgPauseCond;
void DbgPause()
{
#ifdef __linux__ // The thread ID returned by gettid is very useful since its shown in gdb
    printf("\n!!! Process %d, Thread %ld (%lx) paused !!!\n", getpid(), syscall(SYS_gettid), pthread_self());
#else
    printf("\n!!! Process %d paused !!!\n", getpid());
#endif
    std::unique_lock<std::mutex> lk(dbgPauseMutex);
    dbgPauseCond.wait(lk);
}
extern "C" void DbgResume() { dbgPauseCond.notify_all(); }

#endif // DEBUG_PAUSE

// Stop the logging.  TODO we can offer an API that lets the app install a log callback function and then call it
// here so that the app can get our logs and do whatever it wants with them.
int LogPrintStr(const std::string &str) { return str.size(); }
namespace Logging
{
std::atomic<uint64_t> categoriesEnabled = 0; // 64 bit log id mask.
};

// I don't want to pull in the args stuff so always pick the defaults
bool GetBoolArg(const std::string &strArg, bool fDefault) { return fDefault; }

CChainParams *GetChainParams(ChainSelector chainSelector)
{
    if (chainSelector == AddrBlockchainNexa)
        return &Params(CBaseChainParams::NEXA);
    else if (chainSelector == AddrBlockchainTestnet)
        return &Params(CBaseChainParams::TESTNET);
    else if (chainSelector == AddrBlockchainRegtest)
        return &Params(CBaseChainParams::REGTEST);
    else if (chainSelector == AddrBlockchainBCH)
        return &Params(CBaseChainParams::LEGACY_UNIT_TESTS);
    else if (chainSelector == AddrBlockchainBchTestnet)
        return &bchTestnet4Params;
    else if (chainSelector == AddrBlockchainBchRegtest)
        return &bchRegtestParams;
    else
        return nullptr;
}


// No-op this RPC function that is unused in .so context
extern UniValue token(const UniValue &params, bool fHelp) { return UniValue(); }

void checkSigInit()
{
    if (!sigInited)
    {
        sigInited = true;
        SHA256AutoDetect();
        ECC_Start();
        verifyContext = new ECCVerifyHandle();
    }
}

CKey LoadKey(const unsigned char *src)
{
    CKey secret;
    checkSigInit();
    secret.Set(src, src + 32, true);
    return secret;
}

#if 0
// This function is temporarily removed since it is not used.  However it will be needed for interfacing to
// languages that handle binary data poorly, since it allows transaction information to be communicated via hex strings

// From core_read.cpp #include "core_io.h"
    bool DecodeHexTx(CTransaction &tx, const std::string &strHexTx)
    {
        if (!IsHex(strHexTx))
            return false;

        std::vector<unsigned char> txData(ParseHex(strHexTx));
        CDataStream ssData(txData, SER_NETWORK, PROTOCOL_VERSION);
        try
        {
            ssData >> tx;
        }
        catch (const std::exception &)
        {
            return false;
        }

        return true;
    }
#endif
