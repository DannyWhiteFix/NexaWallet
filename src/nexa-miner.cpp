// Copyright (c) 2018-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#if defined(HAVE_CONFIG_H)
#include "nexa-config.h"
#endif

#include "allowed_args.h"
#include "arith_uint256.h"
#include "chainparams.h"
#include "chainparamsbase.h"
#include "consensus/params.h"
#include "fs.h"
#include "hashwrapper.h"
#include "key.h"
#include "pow.h"
#include "primitives/block.h"
#include "pubkey.h"
#include "rpc/client.h"
#include "rpc/protocol.h"
#include "streams.h"
#include "sync.h"
#include "util.h"
#include "utilstrencodings.h"
#include "utiltranslate.h"

#include <cstdlib>
#include <functional>
#include <random>
#include <stdio.h>

#include <event2/buffer.h>
#include <event2/event.h>
#include <event2/http.h>
#include <event2/keyvalq_struct.h>

#include <univalue.h>

// below two require C++11
#include <functional>
#include <random>

#include <boost/thread.hpp>

#ifdef DEBUG_LOCKORDER
std::atomic<bool> lockdataDestructed{false};
LockData lockdata;
#endif

// Lambda used to generate entropy, per-thread (see CpuMiner, et al below)
typedef std::function<uint32_t(void)> RandFunc;

CCriticalSection cs_commitment;
uint256 g_headerCommitment;
uint32_t g_nBits = 0;
UniValue g_id;
bool deterministicStartCount = false;

CCriticalSection cs_blockhash;
uint256 bestBlockHash;

std::string minerName;

int CpuMiner(int threadNum);

using namespace std;

std::mutex nowLock;
std::string now()
{
    nowLock.lock();
    std::time_t now_time = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    char *tmp = std::ctime(&now_time);
    std::string ret(tmp, tmp + strlen(tmp) - 1);
    nowLock.unlock();
    return ret;
}

class Secp256k1Init
{
    ECCVerifyHandle globalVerifyHandle;

public:
    Secp256k1Init() { ECC_Start(); }
    ~Secp256k1Init() { ECC_Stop(); }
};

class NexaMinerArgs : public AllowedArgs::NexaCli
{
public:
    NexaMinerArgs(CTweakMap *pTweaks = nullptr)
    {
        addHeader(_("Mining options:"))
            .addArg("blockversion=<n>", ::AllowedArgs::requiredInt,
                _("Set the block version number. For testing only. Value must be an integer"))
            .addArg("cpus=<n>", ::AllowedArgs::requiredInt,
                _("Number of cpus to use for mining (default: 1). Value must be an integer"))
            .addArg("duration=<n>", ::AllowedArgs::requiredInt,
                _("Number of seconds to mine a particular block candidate (default: 30). Value must be an integer"))
            .addArg("nblocks=<n>", ::AllowedArgs::requiredInt,
                _("Number of blocks to mine (default: mine forever / -1). Value must be an integer"))
            .addArg("coinbasesize=<n>", ::AllowedArgs::requiredInt,
                _("Get a fixed size coinbase Tx (default: do not use / 0). Value must be an integer"))
            // requiredAmount here validates a float
            .addArg("maxdifficulty=<f>", ::AllowedArgs::requiredAmount,
                _("Set the maximum difficulty (default: no maximum) we will mine. If difficulty exceeds this value we "
                  "sleep and poll every <duration> seconds until difficulty drops below this threshold. Value must be "
                  "a float or integer"))
            .addArg("address=<string>", ::AllowedArgs::requiredStr,
                _("The address to send the newly generated nexa to. If omitted, will default to an address in the "
                  "nexa daemon's wallet."))
            .addArg("name=<string>", ::AllowedArgs::requiredStr,
                _("Name for this mining machine for statistics tracking in the full node"))
            .addArg("deterministic[=boolean]", ::AllowedArgs::optionalBool,
                _("Instead of starting at a random nonce, start with 0x0N000001, where N is the thread number."
                  "  Default is false."));
    }
};


/*
static CBlockHeader CpuMinerJsonToHeader(const UniValue &params)
{
    // Does not set hashMerkleRoot (Does not exist in Mining-Candidate params).
    CBlockHeader blockheader;

    // hashPrevBlock
    string tmpstr = params["prevhash"].get_str();
    std::vector<unsigned char> vec = ParseHex(tmpstr);
    std::reverse(vec.begin(), vec.end()); // sent reversed
    blockheader.hashPrevBlock = uint256(vec);

    // nTime:
    blockheader.nTime = params["time"].get_int();

    // nBits
    {
        std::stringstream ss;
        ss << std::hex << params["nBits"].get_str();
        ss >> blockheader.nBits;
    }

    return blockheader;
}
*/

void static MinerThread(int threadNum)
{
    while (1)
    {
        try
        {
            CpuMiner(threadNum);
        }
        catch (const std::exception &e)
        {
            PrintExceptionContinue(&e, "CommandLineRPC()");
        }
        catch (...)
        {
            PrintExceptionContinue(nullptr, "CommandLineRPC()");
        }
    }
}

static bool CpuMinerJsonToData(const UniValue &params, uint256 &headerCommitment, uint32_t &nBits, UniValue &id)
{
    string tmpstr;
    tmpstr = params["headerCommitment"].get_str();
    std::vector<unsigned char> vec = ParseHex(tmpstr);
    std::reverse(vec.begin(), vec.end()); // sent reversed
    headerCommitment = uint256(vec);

    // nBits
    {
        std::stringstream ss;
        ss << std::hex << params["nBits"].get_str();
        ss >> nBits;
    }

    id = params["id"];

    return true;
}

static bool CpuMineBlockHasherNextChain(int &ntries,
    uint256 headerCommitment,
    uint32_t nBits,
    const RandFunc &randFunc,
    const Consensus::Params &conp,
    uint32_t &count,
    uint32_t rollAt,
    uint32_t extra,
    std::vector<unsigned char> &nonce)
{
    arith_uint256 hashTarget = arith_uint256().SetCompact(nBits);
    bool found = false;

    /* Eventually when hashing performance improved dramatically we may need to start with 6 bytes.

    // Note that since I have a coinbase that is unique to my hashing effort, my hashing won't duplicate a competitor's
    // efforts.  And a new candidate is generated every 30 seconds, so my hashing won't conflict with my earlier self.
    // So it does not matter that we all start with few nonce bits.
    if (nonce.size() < 6) nonce.resize(6);

    //uint32_t startCount = randFunc();
    nonce[4] = extra & 255;
    nonce[5] = (extra >> 8) & 255;
    */

    if (nonce.size() < 4)
        nonce.resize(4);

    nonce[3] = extra & 255;

    bool fNegative;
    bool fOverflow;
    arith_uint256 target;
    target.SetCompact(nBits, &fNegative, &fOverflow);
    arith_uint256 finalHash;
    while (!found)
    {
        // Search
        while (!found)
        {
            ++count;
            nonce[0] = count & 255;
            nonce[1] = (count >> 8) & 255;
            nonce[2] = (count >> 16) & 255;

            uint256 miningHash = GetMiningHash(headerCommitment, nonce);
            if (CheckProofOfWork(miningHash, target, conp, &finalHash))
            {
                // Found a solution
                found = true;
                printf("%s: proof-of-work found  \n  mining puzzle solution: %s  \n                  target: %s\n",
                    now().c_str(), finalHash.GetHex().c_str(), hashTarget.GetHex().c_str());
                break;
            }
            if (ntries-- < 1)
            {
                return false; // Give up leave
            }
        }
    }

    return found;
}

/* this is target inf float number rather than hex */
static double GetDifficulty(uint32_t nBits)
{
    int nShift = (nBits >> 24) & 0xff;

    double dDiff = (double)0x0000ffff / (double)(nBits & 0x00ffffff);

    while (nShift < 29)
    {
        dDiff *= 256.0;
        nShift++;
    }
    while (nShift > 29)
    {
        dDiff /= 256.0;
        nShift--;
    }
    return dDiff;
}

// trvially-constructible/copyable info for use in CpuMineBlock below to check if mining a stale block
struct BlkInfo
{
    uint64_t prevCheapHash = 0;
    uint32_t nBits = 0;
};
// Thread-safe version of above for the shared variable. We do it this way
// because std::atomic<struct> isn't always available on all platforms.
class SharedBlkInfo : protected BlkInfo
{
    mutable CCriticalSection lock;

public:
    void store(const BlkInfo &o)
    {
        LOCK(lock);
        prevCheapHash = o.prevCheapHash;
        nBits = o.nBits;
    }
    bool operator==(const BlkInfo &o) const
    {
        LOCK(lock);
        return prevCheapHash == o.prevCheapHash && nBits == o.nBits;
    }
};
// shared variable: used to inform all threads when the latest block or difficulty has changed
static SharedBlkInfo sharedBlkInfo;

static UniValue CpuMineBlock(unsigned int searchDuration, bool &found, const RandFunc &randFunc, int threadNum)
{
    UniValue ret(UniValue::VARR);
    const double maxdiff = GetDoubleArg("-maxdifficulty", 0.0);
    searchDuration *= 1000; // convert to millis
    found = false;

    uint256 headerCommitment;
    uint32_t nBits = 0;
    UniValue id;
    {
        LOCK(cs_commitment);
        headerCommitment = g_headerCommitment;
        nBits = g_nBits;
        id = g_id;
    }
    if (!nBits)
    {
        MilliSleep(1000);
        return ret;
    }

    // first check difficulty, and abort if it's lower than maxdifficulty from CLI
    const double difficulty = GetDifficulty(nBits);
    if (maxdiff > 0.0 && difficulty > maxdiff)
    {
        printf("Current difficulty: %3.2f > maxdifficulty: %3.2f, sleeping for %d seconds...\n", difficulty, maxdiff,
            searchDuration / 1000);
        MilliSleep(searchDuration);
        return ret;
    }

    // ok, difficulty check passed or not applicable, proceed
#if 0
    UniValue tmp(UniValue::VOBJ);
    string tmpstr;
    std::vector<uint256> merkleproof;
    vector<unsigned char> coinbaseBytes(ParseHex(params["coinbase"].get_str()));


    // re-create merkle branches:
    {
        UniValue uvMerkleproof = params["merkleProof"];
        for (unsigned int i = 0; i < uvMerkleproof.size(); i++)
        {
            tmpstr = uvMerkleproof[i].get_str();
            std::vector<unsigned char> mbr = ParseHex(tmpstr);
            std::reverse(mbr.begin(), mbr.end());
            merkleproof.push_back(uint256(mbr));
        }
    }
#endif

    const CChainParams &cparams = Params();
    auto conp = cparams.GetConsensus();

    bool fNegative;
    bool fOverflow;
    arith_uint256 target;
    target.SetCompact(nBits, &fNegative, &fOverflow);

    printf("%s: Mining: id: %x headerCommitment: %s bits: %x difficulty: %3.8f target: %s\n", now().c_str(),
        (unsigned int)id.get_int64(), headerCommitment.ToString().c_str(), nBits, difficulty, target.GetHex().c_str());

    int64_t start = GetTimeMillis();
    std::vector<unsigned char> nonce;
    int ChunkAmt = 10000;
    int checked = 0;
    uint32_t startCount = 1;
    if (!deterministicStartCount)
        startCount = randFunc();
    uint32_t rollAt = startCount - 1;
    const BlkInfo blkInfo = {headerCommitment.GetCheapHash(), nBits};

    while ((GetTimeMillis() < start + searchDuration) && !found && sharedBlkInfo == blkInfo)
    {
        // When mining mainnet, you would normally want to advance the time to keep the block time as close to the
        // real time as possible.  However, this CPU miner is only useful on testnet and in testnet the block difficulty
        // resets to 1 after 20 minutes.  This will cause the block's difficulty to mismatch the expected difficulty
        // and the block will be rejected.  So do not advance time (let it be advanced by nexad every time we
        // request a new block).
        // header.nTime = (header.nTime < GetTime()) ? GetTime() : header.nTime;
        int tries = ChunkAmt;
        found = CpuMineBlockHasherNextChain(
            tries, headerCommitment, nBits, randFunc, conp, startCount, rollAt, threadNum, nonce);
        checked += ChunkAmt - tries;
    }

    // Leave if not found:
    std::string rightnow = now();
    if (!found)
    {
        const float elapsed = GetTimeMillis() - start;
        printf("%s: Checked %d possibilities in %5.1f secs, %3.3f MH/s\n", rightnow.c_str(), checked, elapsed / 1000,
            (checked / 1e6) / (elapsed / 1e3));
        return ret;
    }

    printf("%s: Solution! Checked %d possibilities\n", rightnow.c_str(), checked);

    UniValue tmp(UniValue::VOBJ);
    tmp.pushKV("id", id);
    tmp.pushKV("nonce", HexStr(nonce));
    ret.push_back(tmp);

    return ret;
}

static UniValue RPCSubmitSolution(const UniValue &solution, int &nblocks)
{
    UniValue reply = CallRPC("submitminingsolution", solution);

    const UniValue &error = find_value(reply, "error");

    if (!error.isNull())
    {
        fprintf(stderr, "%s: Block Candidate submission error: %d %s\n", now().c_str(), error["code"].get_int(),
            error["message"].get_str().c_str());
        return reply;
    }

    const UniValue &result = find_value(reply, "result");

    if (result.isNull())
    {
        printf("%s: Unknown submission error, server gave no result\n", now().c_str());
    }
    else
    {
        const UniValue &errValue = find_value(result, "result");

        const UniValue &hashUV = find_value(result, "hash");
        std::string hashStr = hashUV.isNull() ? "" : hashUV.get_str();

        const UniValue &heightUV = find_value(result, "height");
        uint64_t height = heightUV.isNull() ? -1 : heightUV.get_int();


        if (errValue.isStr())
        {
            fprintf(stderr, "%s: Block Candidate %s rejected. Error: %s\n", now().c_str(), hashStr.c_str(),
                result.get_str().c_str());
            // Print some debug info if the block is rejected
            UniValue dbg = solution[0].get_obj();
            fprintf(stderr, "    id: 0x%x  nonce: %s \n", dbg["id"].get_int(), dbg["nonce"].get_str().c_str());
        }
        else
        {
            if (errValue.isNull())
            {
                printf("%s: Block Candidate %u:%s accepted.\n", now().c_str(), (unsigned int)height, hashStr.c_str());
                if (nblocks > 0)
                    nblocks--; // Processed a block
            }
            else
            {
                fprintf(stderr, "%s: Unknown \"submitminingsolution\" Error.\n", now().c_str());
            }
        }
    }

    return reply;
}

static bool FoundNewBlock()
{
    string strPrint;
    UniValue result;

    try
    {
        UniValue params(UniValue::VARR);
        UniValue replyAttempt = CallRPC("getbestblockhash", params);

        // Parse reply
        result = find_value(replyAttempt, "result");
        const UniValue &error = find_value(replyAttempt, "error");

        if (!error.isNull())
        {
            // Error
            int code = error["code"].get_int();
            if (code == RPC_IN_WARMUP)
                throw CConnectionFailed("server in warmup");
            strPrint = "error: " + error.write();
            if (error.isObject())
            {
                UniValue errCode = find_value(error, "code");
                UniValue errMsg = find_value(error, "message");
                strPrint = errCode.isNull() ? "" : "error code: " + errCode.getValStr() + "\n";

                if (errMsg.isStr())
                    strPrint += "error message:\n" + errMsg.get_str();
            }

            if (strPrint != "")
            {
                fprintf(stderr, "%s: %s\n", now().c_str(), strPrint.c_str());
            }
            MilliSleep(1000);
        }
        else
        {
            if (result.isStr() && !result.isNull())
            {
                // If the bestblockhash has changed then store it, and return true
                string tmpstr;
                tmpstr = result.get_str();
                std::vector<unsigned char> vec = ParseHex(tmpstr);
                std::reverse(vec.begin(), vec.end()); // sent reversed
                {
                    LOCK(cs_blockhash);
                    uint256 hash = uint256(vec);
                    if (hash != bestBlockHash)
                    {
                        bestBlockHash = hash;
                        return true;
                    }
                }
            }
        }
    }
    catch (const CConnectionFailed &c)
    {
        printf("%s: Warning: %s\n", now().c_str(), c.what());
        MilliSleep(1000);
    }

    return false;
}

static bool CheckForNewMiningCandidate()
{
    int coinbasesize = GetArg("-coinbasesize", 0);
    std::string address = GetArg("-address", "");

    string strPrint;
    UniValue result;

    try
    {
        UniValue replyAttempt;
        UniValue params(UniValue::VARR);
        {
            if (coinbasesize > 0)
            {
                params.push_back(UniValue(coinbasesize));
            }
            if (!address.empty())
            {
                if (params.empty())
                {
                    // param[0] must be coinbaseSize:
                    // push null in position 0 to use server default coinbaseSize
                    params.push_back(UniValue());
                }
                // this must be in position 1
                params.push_back(UniValue(address));
                params.push_back(minerName);
            }
            else if (!minerName.empty())
            {
                params.push_back(UniValue());
                params.push_back("");
                params.push_back(minerName);
            }
            replyAttempt = CallRPC("getminingcandidate", params);
        }

        // Parse reply
        result = find_value(replyAttempt, "result");
        const UniValue &error = find_value(replyAttempt, "error");

        if (!error.isNull())
        {
            // Error
            int code = error["code"].get_int();
            if (code == RPC_IN_WARMUP)
                throw CConnectionFailed("server in warmup");
            strPrint = "error: " + error.write();
            if (error.isObject())
            {
                UniValue errCode = find_value(error, "code");
                UniValue errMsg = find_value(error, "message");
                strPrint = errCode.isNull() ? "" : "error code: " + errCode.getValStr() + "\n";

                if (errMsg.isStr())
                    strPrint += "error message:\n" + errMsg.get_str();
            }

            if (strPrint != "")
            {
                fprintf(stderr, "%s: %s\n", now().c_str(), strPrint.c_str());
            }
            MilliSleep(1000);
        }
        else
        {
            if (!result.isNull() && !result.isStr())
            {
                // save the prev block CheapHash & current difficulty to the global shared
                // variable right away: this will potentially signal to other threads to return
                // early if they are still mining on top of an old block (assumption here is
                // that this block is the latest result from the RPC server, which is true 99.99999%
                // of the time.)
                uint256 headerCommitment;
                uint32_t nBits = 0;
                UniValue id;
                CpuMinerJsonToData(result, headerCommitment, nBits, id);

                {
                    LOCK(cs_commitment);
                    g_headerCommitment = headerCommitment;
                    g_nBits = nBits;
                    g_id = id;
                }
                const BlkInfo blkInfo = {headerCommitment.GetCheapHash(), nBits};
                sharedBlkInfo.store(blkInfo);
                return true;
            }
        }
    }
    catch (const CConnectionFailed &c)
    {
        printf("%s: Warning: %s\n", now().c_str(), c.what());
        MilliSleep(1000);
    }

    // Set the nBits to zero so that the miner threads will pause mining.
    LOCK(cs_commitment);
    g_nBits = 0;

    return false;
}

int CpuMiner(int threadNum)
{
    // Initialize random number generator lambda. This is per-thread and
    // is thread-safe.  std::rand() is not thread-safe and can result
    // in multiple threads doing redundant proof-of-work.
    std::random_device rd;
    // seed random number generator from system entropy source (implementation defined: usually HW)
    std::default_random_engine e1(rd());
    // returns a uniformly distributed random number in the inclusive range: [0, UINT_MAX]
    std::uniform_int_distribution<uint32_t> uniformGen(0);
    auto randFunc = [&](void) -> uint32_t { return uniformGen(e1); };

    int searchDuration = GetArg("-duration", 30);
    int nblocks = GetArg("-nblocks", -1); //-1 mine forever
    int coinbasesize = GetArg("-coinbasesize", 0);
    std::string address = GetArg("-address", "");

    if (coinbasesize < 0)
    {
        printf("%s: Negative coinbasesize not reasonable/supported.\n", now().c_str());
        return 0;
    }

    UniValue mineresult;
    bool found = false;

    if (0 == nblocks)
    {
        printf("%s: Nothing to do for zero (0) blocks\n", now().c_str());
        return 0;
    }

    while (0 != nblocks)
    {
        UniValue result;
        string strPrint;
        int nRet = 0;
        try
        {
            // Execute and handle connection failures with -rpcwait
            do
            {
                try
                {
                    UniValue replyAttempt;
                    if (found)
                    {
                        // Submit the solution.
                        // Called here so all exceptions are handled properly below.
                        replyAttempt = RPCSubmitSolution(mineresult, nblocks);
                        if (nblocks == 0)
                            return 0; // Done mining exit program
                        found = false; // Mine again

                        result = find_value(replyAttempt, "result");

                        UniValue params(UniValue::VARR);
                        if (coinbasesize > 0)
                        {
                            params.push_back(UniValue(coinbasesize));
                        }
                        if (!address.empty())
                        {
                            if (params.empty())
                            {
                                // param[0] must be coinbaseSize:
                                // push null in position 0 to use server default coinbaseSize
                                params.push_back(UniValue());
                            }
                            // this must be in position 1
                            params.push_back(UniValue(address));
                        }

                        replyAttempt = CallRPC("getminingcandidate", params);
                        result = find_value(replyAttempt, "result");

                        const UniValue &error = find_value(replyAttempt, "error");
                        if (!error.isNull())
                        {
                            // Error
                            int code = error["code"].get_int();
                            if (code == RPC_IN_WARMUP)
                                throw CConnectionFailed("server in warmup");
                            strPrint = "error: " + error.write();
                            nRet = abs(code);
                            if (error.isObject())
                            {
                                UniValue errCode = find_value(error, "code");
                                UniValue errMsg = find_value(error, "message");
                                strPrint = errCode.isNull() ? "" : "error code: " + errCode.getValStr() + "\n";

                                if (errMsg.isStr())
                                    strPrint += "error message:\n" + errMsg.get_str();
                            }
                            printf("%s: ERROR: %s\n", now().c_str(), strPrint.c_str());
                            throw;
                        }
                        else
                        {
                            // Result
                            if (result.isNull())
                                strPrint = "";
                            else if (result.isStr())
                                strPrint = result.get_str();
                        }

                        if (strPrint != "")
                        {
                            if (nRet != 0)
                            {
                                fprintf(stderr, "%s: %s\n", now().c_str(), strPrint.c_str());
                                return 0;
                            }
                            if (result.isStr())
                            {
                                // This can happen just after submitting a block and the old block template
                                // becomes stale
                                printf("%s: Not mining because: %s\n", now().c_str(), result.get_str().c_str());
                                return 0;
                            }
                        }
                        else if (result.isNull())
                        {
                            printf("%s: No result after submission\n", now().c_str());
                            MilliSleep(1000);
                        }
                        else
                        {
                            // Update the new best block hash.
                            FoundNewBlock();

                            // Block submission was successfull so retrieve the new mining candidate
                            printf("%s: Getting new Candidate after successful block submission\n", now().c_str());
                            if (!CheckForNewMiningCandidate())
                                return 0;
                        }
                    }

                    // Connection succeeded, no need to retry.
                    break;
                }
                catch (const CConnectionFailed &c)
                {
                    printf("%s: Warning: %s\n", now().c_str(), c.what());
                    MilliSleep(1000);
                }
            } while (true);
        }
        catch (const boost::thread_interrupted &)
        {
            throw;
        }
        catch (const std::exception &e)
        {
            strPrint = string("error: ") + e.what();
            nRet = EXIT_FAILURE;
        }
        catch (...)
        {
            PrintExceptionContinue(nullptr, "CommandLineRPC()");
            throw;
        }


        // Actually do some mining
        found = false;
        mineresult = CpuMineBlock(searchDuration, found, randFunc, threadNum);
        if (!found)
        {
            mineresult.setNull();
        }
        // The result is sent to nexad above when the loop gets to it.
        // See:   RPCSubmitSolution(mineresult,nblocks);
        // This is so RPC Exceptions are handled in one place.
    }
    return 0;
}


int main(int argc, char *argv[])
{
    int ret = EXIT_FAILURE;

    Secp256k1Init secp;
    SetupEnvironment();
    if (!SetupNetworking())
    {
        fprintf(stderr, "Error: Initializing networking failed\n");
        exit(1);
    }

    try
    {
        std::string appname("nexa-miner");
        std::string usage = "\n" + _("Usage:") + "\n" + "  " + appname + " [options] " + "\n";
        ret = AppInitRPC("cpu miner", usage, NexaMinerArgs(), argc, argv);
        if (ret != CONTINUE_EXECUTION)
            return ret;
    }
    catch (const std::exception &e)
    {
        PrintExceptionContinue(&e, "AppInitRPC()");
        return EXIT_FAILURE;
    }
    catch (...)
    {
        PrintExceptionContinue(nullptr, "AppInitRPC()");
        return EXIT_FAILURE;
    }
    SelectParams(ChainNameFromCommandLine());

    minerName = GetArg("-name", "");

    // Launch miner threads
    int nThreads = GetArg("-cpus", 1);
    if (nThreads > 256)
    {
        nThreads = 256;
        printf("%s: Number of threads reduced to the maximum allowed value: %d.\n", now().c_str(), nThreads);
    }
    std::vector<std::thread> minerThreads;
    printf("%s: Running %d threads.\n", now().c_str(), nThreads);
    minerThreads.resize(nThreads);
    for (int i = 0; i < nThreads; i++)
        minerThreads[i] = std::thread(MinerThread, i);

    deterministicStartCount = GetBoolArg("-deterministic", false);

    // Start loop which checks whether we have a new mining candidate
    uint64_t nStartTime = 0;
    do
    {
        try
        {
            // only check for new candidates every 2 seconds, or if the bestblockhash has changed.
            if ((GetTimeMillis() - nStartTime > 2000) || FoundNewBlock())
            {
                nStartTime = GetTimeMillis();
                CheckForNewMiningCandidate();
            }
            MilliSleep(100);
        }
        catch (const std::exception &e)
        {
            PrintExceptionContinue(&e, "CommandLineRPC()");
            MilliSleep(1000);
        }
        catch (...)
        {
            PrintExceptionContinue(nullptr, "CommandLineRPC()");
            MilliSleep(1000);
        }
    } while (true);

    return ret;
}
