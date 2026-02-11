#include "chainparams.h"
#include "consensus/merkle.h"
#include "core_io.h"
#include "init.h"
#include "pow.h"
#include "unlimited.h"
#include "versionbits.h" // bip135 added

#include "rpc/server.h"
#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"
#include <assert.h>
#include <stdexcept>
#include <string>

#include <boost/assign/list_of.hpp>

#include "chainparamsseeds.h"

#ifdef ENABLE_WALLET
extern UniValue token(const UniValue &params, bool fHelp);
#endif
UniValue genesis(const UniValue &params, bool fHelp);

/* clang-format off */
static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         okSafeMode
  //  --------------------- ------------------------  -----------------------  ----------
    { "mining",             "genesis",                &genesis,                true  },
#ifdef ENABLE_WALLET
    { "wallet",             "token",                  &token,                  true  }
#endif
};
/* clang-format on */

void RegisterNexaRPCCommands(CRPCTable &table)
{
    for (auto cmd : commands)
        table.appendCommand(cmd);
}

extern CBlock CreateGenesisBlock(const char *genesisText,
    const CScript &genesisOutputScript,
    uint32_t nTime,
    const std::vector<unsigned char> &nonce,
    uint32_t nBits,
    const CAmount &genesisReward);

UniValue genesis(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() > 3)
        throw std::runtime_error("genesis\n"
                                 "\ncreate a genesis block"
                                 "  chainName (string) what chain parameters\n"
                                 "  minerComment (string) miner comment\n"
                                 "  difficulty (int) genesis difficulty in nBits format\n"
                                 "\nExamples:\n" +
                                 HelpExampleCli("genesis", "") + HelpExampleRpc("genesis", ""));

    std::string chainName = params[0].getValStr();
    std::string genesisComment = params[1].getValStr();
    std::string genesisDiffs = params[2].getValStr();
    int genesisDiff = std::stoi(genesisDiffs);
    const CChainParams &chp = Params(chainName);

    const CScript genesisOutputScript = CScript() << OP_1;
    // CAmount genesisReward(5000000000);
    CAmount genesisReward(0);
    CBlock block = CreateGenesisBlock(genesisComment.c_str(), genesisOutputScript, GetTime(),
        std::vector<unsigned char>(4), genesisDiff, genesisReward);

    CBlock *pblock = &block;
    const Consensus::Params &conp = chp.GetConsensus();

    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;
    bnTarget.SetCompact(genesisDiff, &fNegative, &fOverflow);
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(conp.powLimit))
        throw std::runtime_error("Invalid nBits difficulty");

    uint32_t count = 0;
    pblock->nonce.resize(4);
    pblock->GetBlockSize();
    uint256 dummyHash;
    while (!CheckProofOfWork(pblock->GetMiningHash(), dummyHash, pblock->nBits, conp))
    {
        ++count;
        pblock->nonce[0] = count & 255;
        pblock->nonce[0] = (count >> 8) & 255;
        pblock->nonce[0] = (count >> 16) & 255;
        pblock->nonce[0] = (count >> 24) & 255;
        if (ShutdownRequested())
            throw std::runtime_error("aborted");
        if ((count & 0xfff) == 0)
        {
            LOGA("GENESIS nonce: ", count);
        }
    }

    CDataStream ssBlock(SER_NETWORK, PROTOCOL_VERSION);
    ssBlock << block;
    std::string strHex = HexStr(ssBlock.begin(), ssBlock.end());

    std::ostringstream logs;
    logs << "GENESIS Block: Time: " << pblock->nTime << " Nonce: " << HexStr(pblock->nonce)
         << " Bits: " << pblock->nBits << " Reward: " << genesisReward << " Comment: " << genesisComment
         << " Script: " << FormatScript(genesisOutputScript) << " Hash: " << pblock->GetHash().GetHex()
         << " Hex: " << strHex << "\n";
    LOGA(logs.str().c_str());

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("time", (int64_t)pblock->nTime);
    ret.pushKV("nonce", HexStr(pblock->nonce));
    ret.pushKV("bits", (uint64_t)pblock->nBits);
    ret.pushKV("reward", genesisReward);
    ret.pushKV("comment", genesisComment);
    ret.pushKV("script", FormatScript(genesisOutputScript));
    ret.pushKV("hash", pblock->GetHash().GetHex());
    ret.pushKV("hex", strHex);
    return ret;
}
