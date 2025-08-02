// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Server/client environment: argument handling, config file parsing,
 * logging, thread wrappers, startup time
 */
#ifndef NEXA_LOGGING_H
#define NEXA_LOGGING_H

#include "fs.h"
#include "tinyformat.h"
#include "utiltime.h"

#include <algorithm>
#include <atomic>
#include <map>
#include <mutex>
#include <stdint.h>
#include <string>
#include <vector>

static const bool DEFAULT_LOGTIMEMICROS = false;
static const bool DEFAULT_LOGIPS = true;
static const bool DEFAULT_LOGTIMESTAMPS = true;

extern std::atomic<bool> fLogTimestamps;
extern std::atomic<bool> fLogTimeMicros;
extern std::atomic<bool> fPrintToConsole;
extern std::atomic<bool> fPrintToDebugLog;
extern std::atomic<bool> fReopenDebugLog;

extern std::atomic<std::mutex *> mutexDebugLog;
extern std::atomic<FILE *> logger_fileout;

extern fs::path pathDebugLog;

// Logging API:
// Use the two macros
// LOG(ctgr,...)
// LOGA(...)
// located further down.
// (Do not use the Logging functions directly)
// Log Categories:
// 64 Bits: (Define unique bits, not 'normal' numbers)
enum
{
    // Turn off clang formatting so we can keep the assignment alinged for readability
    // clang-format off
    NONE           = 0x0, // No logging
    ALL            = 0xFFFFFFFFFFFFFFFFUL, // Log everything

    // LOG Categories:
    THIN           = 0x1,
    MEMPOOL        = 0x2,
    COINDB         = 0x4,
    TOR            = 0x8,

    NET            = 0x10,
    ADDRMAN        = 0x20,
    LIBEVENT       = 0x40,
    HTTP           = 0x80,

    RPC            = 0x100,
    PARTITIONCHECK = 0x200,
    BENCH          = 0x400,
    PRUNE          = 0x800,

    REINDEX        = 0x1000,
    MEMPOOLREJ     = 0x2000,
    BLK            = 0x4000,
    EVICT          = 0x8000,

    PARALLEL       = 0x10000,
    RAND           = 0x20000,
    REQ            = 0x40000,
    BLOOM          = 0x80000,

    ESTIMATEFEE    = 0x100000,
    LCK            = 0x200000,
    PROXY          = 0x400000,
    DBASE          = 0x800000,

    SELECTCOINS    = 0x1000000,
    ZMQ            = 0x2000000,
    QT             = 0x4000000,
    IBD            = 0x8000000,

    GRAPHENE       = 0x10000000,
    RESPEND        = 0x20000000,
    TAIL           = 0x40000000,
    CMPCT          = 0x80000000, // compact blocks

    ELECTRUM       = 0x100000000,
    MPOOLSYNC      = 0x200000000,
    PRIORITYQ      = 0x400000000,
    DSPROOF        = 0x800000000,

    TWEAKS         = 0x1000000000,
    SCRIPT         = 0x2000000000,
    CAPD           = 0x4000000000,
    DAG            = 0x8000000000,
    VALIDATION     = 0x4000000000000000UL,
    TOKEN          = 0x8000000000000000UL
    // clang-format on
};

int LogPrintStr(const std::string &str);

namespace Logging
{
extern std::atomic<uint64_t> categoriesEnabled; // 64 bit log id mask.

void LogInit(std::vector<std::string> categories = {});
/**
 * Check if a category should be logged
 * @param[in] category
 * returns true if should be logged
 */
inline bool LogAcceptCategory(uint64_t category) { return (categoriesEnabled.load() & category); }

/**
 * Turn on/off logging for a category
 * @param[in] category
 * @param[in] on  True turn on, False turn off.
 */
void LogToggleCategory(uint64_t category, bool on);

/**
 * Log a string
 * @param[in] All parameters are "printf like args".
 */
template <typename T1, typename... Args>
inline void LogWrite(const char *fmt, const T1 &v1, const Args &...args)
{
    try
    {
        LogPrintStr(tfm::format(fmt, v1, args...));
    }
    catch (...)
    {
        // Number of format specifiers (%) do not match argument count, etc
    }
}

/**
 * Log a string
 * @param[in] str String to log.
 */
inline void LogWrite(const std::string &str)
{
    LogPrintStr(str); // No formatting for a simple string
}

/**
 * Get a category associated with a string.
 * @param[in] label string
 * returns category
 */
uint64_t LogFindCategory(const std::string &label);

/**
 * Get all categories and their state.
 * Formatted for display.
 * returns all categories and states
 */
// Return a string rapresentation of all debug categories and their current status,
// one category per line. If fEnabled is true it returns only the list of enabled
// debug categories concatenated in a single line.
std::string LogGetAllString(bool fEnabled = false,
    std::string categorySpacer = "\n",
    std::string on = "on ",
    std::string off = "   ");

} // namespace Logging

/**
 * LOGA macro: Always log a string.
 *
 * @param[in] ... "printf like args".
 */
#define LOGA(...) Logging::LogWrite(__VA_ARGS__)

// Logging API:
//
/**
 * LOG macro: Log a string if a category is enabled.
 * Note that categories can be ORed, such as: (NET|TOR)
 *
 * @param[in] category -Which category to log
 * @param[in] ... "printf like args".
 */
#define LOG(ctgr, ...)                        \
    do                                        \
    {                                         \
        using namespace Logging;              \
        if (Logging::LogAcceptCategory(ctgr)) \
            Logging::LogWrite(__VA_ARGS__);   \
    } while (0)


/**
 * Get the label / associated string for a category.
 * @param[in] category
 * returns label
 */
// note: only used in unit tests
std::string LogGetLabel(const uint64_t &category);

// Flush log file (if you know you are about to abort)
void LogFlush();

template <typename... Args>
inline bool error(const char *fmt, const Args &...args)
{
    LogPrintStr("ERROR: " + tfm::format(fmt, args...) + "\n");
    return false;
}


template <typename... Args>
inline bool error(uint64_t ctgr, const char *fmt, const Args &...args)
{
    if (Logging::LogAcceptCategory(ctgr))
    {
        LogPrintStr("ERROR: " + tfm::format(fmt, args...) + "\n");
    }
    return false;
}


#endif // NEXA_LOGGING_H
