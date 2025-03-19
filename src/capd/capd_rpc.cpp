// Copyright (c) 2020 G. Andrew Stone

// Counterparty and protocol discovery
#include "arith_uint256.h"
#include "capd.h"
#include "clientversion.h"
#include "dosman.h"
#include "net.h"
#include "serialize.h"
#include "streams.h"
#include "uint256.h"

#include "hashwrapper.h"
#include "httpserver.h"
#include "rpc/server.h"
#include "utilstrencodings.h"

UniValue CapdMsg2UniValue(CapdMsgRef msg)
{
    UniValue ret(UniValue::VOBJ);
    ret.pushKV("hash", msg->GetHash().ToString());
    ret.pushKV("created", msg->createTime);
    if (msg->expiration != std::numeric_limits<uint16_t>::max())
        ret.pushKV("expiration", msg->expiration);
    ret.pushKV("difficultyBits", (uint64_t)msg->difficultyBits);
    ret.pushKV("priority", msg->Priority());
    ret.pushKV("initialPriority", msg->InitialPriority());
    ret.pushKV("powTarget", msg->GetPowTarget().ToString());
    ret.pushKV("nonce", GetHex(msg->nonce));
    ret.pushKV("size", (uint64_t)msg->RamSize());
    ret.pushKV("data", GetHex(msg->data));

    return ret;
}

UniValue capdrpc(const UniValue &params, bool fHelp)
{
    if (fHelp)
        throw std::runtime_error("capd\n"
                                 "\nCAPD RPC calls, including info, send, get, list, remove and clear.\n"
                                 "capd clear: removes all messages from the pool.\n"
                                 "capd remove <message hash>: removes a particular message from the pool.\n"
                                 "capd get <message hash>: returns a particular message.\n"
                                 "capd info: returns information about the message pool.\n"
                                 "capd list: returns the hash of every message in the pool.\n"
                                 "capd send <message data>: sends hex (preferred) or ascii encoded message.\n"
                                 "    To force ascii encoding use a non-hex character.\n"
                                 "\nResult: \n"
                                 "capd info\n"
                                 "{                           (json object)\n"
                                 "  \"size\" : Integer current message pool size in bytes\n"
                                 "  \"count\" : Integer current number of messages in pool\n"
                                 "  \"minPriority\" : The minimum priority to enter the pool\n"
                                 "  \"maxPriority\" : The highest priority in the pool\n"
                                 "  \"relayPriority\" : The minimum priority message that will be relayed\n"
                                 "}\n"
                                 "\ncapd get\n"
                                 "{                           (json object)\n"
                                 "  \"hash\" : Message identifier\n"
                                 "  \"created\" : Message creation time in seconds since epoch\n"
                                 "  \"expiration\" : Message expiration time in seconds since epoch\n"
                                 "  \"difficultyBits\" : Message difficulty in 'nBits' format\n"
                                 "  \"difficulty\" : Message difficulty as a 256 bit number\n"
                                 "  \"priority\" : \n"
                                 "  \"initialPriority\" : \n"
                                 "  \"nonce\" : Hex string to solve the POW\n"
                                 "  \"size\" : Integer message size in ram bytes\n"
                                 "  \"data\" : Hex string of message payload\n"
                                 "}\n"
                                 "\ncapd list\n"
                                 "[ \"message id as hex string\", ... ] (json list)\n"
                                 "\nExamples:\n" +
                                 HelpExampleCli("capd", "info") + HelpExampleRpc("capd", "info"));

    if ((params.size() == 0) || (params[0].get_str() == "info"))
    {
        UniValue ret(UniValue::VOBJ);
        ret.pushKV("size", msgpool.Size());
        ret.pushKV("count", msgpool.Count());
        ret.pushKV("relayPriority", msgpool.GetRelayPriority());
        ret.pushKV("minPriority", msgpool.GetLocalPriority());
        ret.pushKV("maxPriority", msgpool.GetHighestPriority());
        return ret;
    }

    std::string cmd = params[0].get_str();
    if (cmd == "send")
    {
        if (params.size() != 2)
        {
            throw std::runtime_error("Incorrect number of parameters, missing data");
        }
        std::string s = params[1].get_str();
        std::vector<unsigned char> data;
        if (IsHex(s))
        {
            data = ParseHex(s);
        }
        else // Assume the data is the an ascii string
        {
            std::copy(s.begin(), s.end(), std::back_inserter(data));
        }

        CapdMsgRef msg = std::make_shared<CapdMsg>(data);
        msg->SetPowTargetHarderThanPriority(msgpool.GetRelayPriority());
        msg->Solve();
        msgpool.add(msg);

        // Check all query peers to see if they are interested in this new message
        if (true)
        {
            // Grab a copy of capd CNodes and add a ref so they can't be deleted
            std::vector<CNode *> capdNodes;
            {
                LOCK(cs_vNodes);
                for (CNode *pnode : vNodes)
                {
                    if (pnode->isCapdEnabled && pnode->capd)
                    {
                        capdNodes.push_back(pnode);
                        pnode->AddRef();
                    }
                }
            }

            // Now see if we need to relay this message to a query peer
            for (CNode *pnode : capdNodes)
            {
                pnode->capd->checkNotification(msg);
            }

            // Release our refs to these nodes
            for (CNode *pnode : capdNodes)
                pnode->Release();
        }

        return msg->GetHash().GetHex();
    }
    if (cmd == "get")
    {
        if (params.size() != 2)
        {
            throw std::runtime_error("Incorrect number of parameters, missing hash");
        }
        uint256 hash(uint256S(params[1].get_str()));
        CapdMsgRef msg = msgpool.find(hash);
        if (msg == nullptr)
        {
            throw std::runtime_error("no such message");
        }
        UniValue ret = CapdMsg2UniValue(msg);
        return ret;
    }
    if (cmd == "list")
    {
        UniValue ret(UniValue::VARR);
        msgpool.visit(
            [&ret](CapdMsgRef msg) -> bool
            {
                ret.push_back(msg->GetHash().GetHex());
                return true;
            });
        return ret;
    }
    if (cmd == "remove")
    {
        if (params.size() != 2)
        {
            throw std::runtime_error("Incorrect number of parameters, missing hash");
        }
        uint256 hash(uint256S(params[1].get_str()));
        msgpool.remove(hash);
        return UniValue();
    }
    if (cmd == "clear")
    {
        msgpool.clear();
        return UniValue();
    }
    throw std::runtime_error("unknown subcommand");
}

UniValue savemsgpool(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() != 0)
    {
        throw std::runtime_error("savemsgpool\n"
                                 "\nDumps the CAPD msgpool to disk.\n"
                                 "\nExamples:\n" +
                                 HelpExampleCli("savemsgpool", "") + HelpExampleRpc("savemsgpool", ""));
    }

    if (!msgpool.DumpMsgPool())
    {
        throw JSONRPCError(RPC_MISC_ERROR, "Unable to dump msgpool to disk");
    }

    return NullUniValue;
}


/* clang-format off */
static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         okSafeMode
  //  --------------------- ------------------------  -----------------------  ----------
    { "network",            "capd",                   &capdrpc,               true  },
    { "network",            "savemsgpool",            &savemsgpool,           true  }
};
/* clang-format on */

void RegisterCapdRPCCommands(CRPCTable &table)
{
    for (auto cmd : commands)
        table.appendCommand(cmd);
}
