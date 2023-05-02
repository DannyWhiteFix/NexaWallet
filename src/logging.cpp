// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "logging.h"

std::atomic<bool> fLogTimestamps{DEFAULT_LOGTIMESTAMPS};
std::atomic<bool> fLogTimeMicros{DEFAULT_LOGTIMEMICROS};
std::atomic<bool> fPrintToConsole{false};
std::atomic<bool> fPrintToDebugLog{false};
std::atomic<bool> fReopenDebugLog{false};

std::atomic<std::mutex *> mutexDebugLog{nullptr};
std::atomic<FILE *> logger_fileout{nullptr};

fs::path pathDebugLog;


/*
To add a new log category:
1) Create a unique 1 bit category mask. (Easiest is to 2* the last enum entry.)
   Put it at the end of enum above.
2) Add an category/string pair to LOGLABELMAP macro below.
*/

// Add corresponding lower case string for the category:
// clang-format off
#define LOGLABELMAP                             \
    {                                           \
        {NONE, "none"},                         \
        {ALL, "all"},                           \
        {ADDRMAN, "addrman"},                   \
        {BENCH, "bench"},                       \
        {BLK, "blk"},                           \
        {BLOOM, "bloom"},                       \
        {CAPD, "capd"},                         \
        {COINDB, "coindb"},                     \
        {CMPCT, "cmpctblock"},                  \
        {DBASE, "dbase"},                       \
        {DSPROOF, "dsproof"},                   \
        {ELECTRUM, "electrum"},                 \
        {ESTIMATEFEE, "estimatefee"},           \
        {EVICT, "evict"},                       \
        {GRAPHENE, "graphene"},                 \
        {HTTP, "http"},                         \
        {IBD, "ibd"},                           \
        {LCK, "lck"},                           \
        {LIBEVENT, "libevent"},                 \
        {MEMPOOL, "mempool"},                   \
        {MEMPOOLREJ, "mempoolrej"},             \
        {MPOOLSYNC, "mempoolsync"},             \
        {NET, "net"},                           \
        {PARALLEL, "parallel"},                 \
        {PARTITIONCHECK, "partitioncheck"},     \
        {PRIORITYQ, "priorityq"},               \
        {PROXY, "proxy"},                       \
        {PRUNE, "prune"},                       \
        {QT, "qt"},                             \
        {RAND, "rand"},                         \
        {REINDEX, "reindex"},                   \
        {REQ, "req"},                           \
        {RESPEND, "respend"},                   \
        {RPC, "rpc"},                           \
        {SCRIPT, "script"},                     \
        {SELECTCOINS, "selectcoins"},           \
        {THIN, "thin"},                         \
        {TOKEN, "token"},                       \
        {TOR, "tor"},                           \
        {TWEAKS, "tweaks"},                     \
        {VALIDATION, "validation"},             \
        {WB, "weakblocks"},                     \
        {ZMQ, "zmq"},                           \
    }
// clang-format on
static const std::map<uint64_t, std::string> logLabelMap = LOGLABELMAP; // Lookup log label from log id.


/** All logs are automatically CR terminated.  If you want to construct a single-line log out of multiple calls, don't.
    Make your own temporary.  You can make a multi-line log by adding \n in your temporary.
 */
std::string LogTimestampStr(const std::string &str, std::string &logbuf)
{
    if (!logbuf.size())
    {
        int64_t nTimeMicros = GetLogTimeMicros();
        if (fLogTimestamps)
        {
            logbuf = FormatISO8601DateTime(nTimeMicros / 1000000);
            if (fLogTimeMicros)
                logbuf += strprintf(".%06d", nTimeMicros % 1000000);
        }
        logbuf += ' ' + str;
    }
    else
    {
        logbuf += str;
    }

    if (logbuf.size() && logbuf[logbuf.size() - 1] != '\n')
    {
        logbuf += '\n';
    }

    std::string result = logbuf;
    logbuf.clear();
    return result;
}

void MonitorLogfile()
{
    // Check if debug.log has been deleted or moved.
    // If so re-open
    static int existcounter = 1;
    static fs::path fileName = pathDebugLog;
    existcounter++;
    // if we are to print
    if (!pathDebugLog.empty())
    {
        if (existcounter % 63 == 0) // Check every 64 log msgs
        {
            bool exists = fs::exists(fileName);
            if (!exists)
            {
                fReopenDebugLog = true;
            }
        }
    }
}

int FileWriteStr(const std::string &str, FILE *fp) { return fwrite(str.data(), 1, str.size(), fp); }

/** Send a string to the log output */
int LogPrintStr(const std::string &str)
{
    int ret = 0; // Returns total number of characters written
    std::string logbuf;
    std::string strTimestamped = LogTimestampStr(str, logbuf);

    if (!strTimestamped.size())
    {
        return 0;
    }
    if (fPrintToConsole.load())
    {
        // print to console
        ret = fwrite(strTimestamped.data(), 1, strTimestamped.size(), stdout);
        fflush(stdout);
    }
    if (fPrintToDebugLog.load())
    {
        std::scoped_lock scoped_lock(*mutexDebugLog.load());

        // buffer if we haven't opened the log yet
        if (logger_fileout == nullptr)
        {
            printf("Logger fileout is null. Did you specify an output file for the logger?\n");
            assert(logger_fileout != nullptr);
        }
        else
        {
            // reopen the log file, if requested
            // will never be true if pathDebugLog is empty().
            if (fReopenDebugLog)
            {
                fReopenDebugLog = false;
                fs::path pathDebug = pathDebugLog;
                if (fsbridge::freopen(pathDebug, "a", logger_fileout.load()) != nullptr)
                {
                    setbuf(logger_fileout.load(), nullptr); // unbuffered
                }
            }
            ret = FileWriteStr(strTimestamped, logger_fileout.load());
            MonitorLogfile();
        }
    }
    return ret;
}

namespace Logging
{
std::atomic<uint64_t> categoriesEnabled = 0; // 64 bit log id mask.

void LogToggleCategory(uint64_t category, bool on)
{
    if (on)
    {
        categoriesEnabled |= category;
    }
    else
    {
        categoriesEnabled &= ~category; // off
    }
}

/**
 * Get a category associated with a string.
 * @param[in] label string
 * returns category
 */
uint64_t LogFindCategory(const std::string &label)
{
    for (const auto &x : logLabelMap)
    {
        if ((std::string)x.second == label)
        {
            return (uint64_t)x.first;
        }
    }
    return NONE;
}

/**
 * Get all categories and their state.
 * Formatted for display.
 * returns all categories and states
 */
// Return a string rapresentation of all debug categories and their current status,
// one category per line. If enabled is true it returns only the list of enabled
// debug categories concatenated in a single line.
std::string LogGetAllString(bool fEnabled)
{
    std::string allCategories = "";
    std::string enabledCategories = "";
    for (auto &x : logLabelMap)
    {
        if (x.first == ALL || x.first == NONE)
        {
            continue;
        }
        if (LogAcceptCategory(x.first))
        {
            allCategories += "on ";
            if (fEnabled)
            {
                enabledCategories += (std::string)x.second + " ";
            }
        }
        else
        {
            allCategories += "   ";
        }
        allCategories += (std::string)x.second + "\n";
    }
    // strip last char from enabledCategories if it is eqaul to a blank space
    if (enabledCategories.length() > 0)
    {
        enabledCategories.pop_back();
    }
    return fEnabled ? enabledCategories : allCategories;
}


/**
 * Initialize
 */
void LogInit(std::vector<std::string> categories)
{
    // mutexDebugLog should always be nullptr before
    // the logger is initalised
    assert(mutexDebugLog.load() == nullptr);
    // make the mutex and the message vector
    mutexDebugLog.store(new std::mutex);
    if (pathDebugLog.empty())
    {
        // we can not write to a debug log that does not exist
        // this is safe to do because we always call LogInit after reading the
        // command line args for a datadir argument
        fPrintToDebugLog.store(false);
    }
    // when initialising the logger, check if we will use the debug log
    if (fPrintToDebugLog.load())
    {
        assert(logger_fileout == nullptr);
        fs::path pathDebug = pathDebugLog;
        // fopen returns a FILE*
        logger_fileout.store(fsbridge::fopen(pathDebug, "a"));
        if (logger_fileout.load())
        {
            setbuf(logger_fileout.load(), nullptr); // unbuffered
        }
    }

    uint64_t catg = NONE;

    // enable all when given -debug=1 or -debug
    if (categories.size() == 1 && (categories[0] == "" || categories[0] == "1"))
    {
        LogToggleCategory(ALL, true);
    }
    else
    {
        for (std::string &category : categories)
        {
            // it is ok to transform the categories vector itself as it is a copy
            std::transform(category.begin(), category.end(), category.begin(), ::tolower);
            // remove the category from the list of enables one
            // if label is suffixed with a dash
            bool toggle_flag = true;

            if (category.length() > 0 && category.at(0) == '-')
            {
                toggle_flag = false;
                category.erase(0, 1);
            }

            if (category == "" || category == "1")
            {
                category = "all";
            }

            catg = LogFindCategory(category);

            if (catg == NONE) // Not a valid category
            {
                continue;
            }

            LogToggleCategory(catg, toggle_flag);
        }
    }
    LOGA("List of enabled categories: %s\n", LogGetAllString(true));
}

} // namespace Logging

/**
 * Get the label / associated string for a category.
 * @param[in] category
 * returns label
 */
// note: only used in unit tests
std::string LogGetLabel(const uint64_t &category)
{
    std::map<uint64_t, std::string>::const_iterator iter = logLabelMap.find(category);
    if (iter != logLabelMap.end())
    {
        return iter->second;
    }
    return "none";
}

// Flush log file (if you know you are about to abort)
void LogFlush()
{
    if (fPrintToDebugLog.load())
    {
        // passing in a nullptr will flush all open output streams
        // we only call LogFlush when aborting or intentionally via rpc
        // so a potential nullptr here is ok
        fflush(logger_fileout.load());
    }
}
