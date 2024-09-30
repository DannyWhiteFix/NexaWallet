// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2023 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "blockrelay/blockrelay_common.h"
#include "dstencode.h"
#include "index/txindex.h"
#include "init.h"
#include "main.h"
#include "net.h"
#include "netbase.h"
#include "rpc/blockchain.h"
#include "rpc/server.h"
#include "timedata.h"
#include "util.h"
#include "utilstrencodings.h"
#include "validation/validation.h"
#include "wallet/grouptokencache.h"
#ifdef ENABLE_WALLET
#include "wallet/wallet.h"
#include "wallet/walletdb.h"
#endif

#include <stdint.h>
#include <univalue.h>

using namespace std;

/**
 * @note Do not add or change anything in the information returned by this
 * method. `getinfo` exists for backwards-compatibility only. It combines
 * information from wildly different sources in the program, which is a mess,
 * and is thus planned to be deprecated eventually.
 *
 * Based on the source of the information, new information should be added to:
 * - `getblockchaininfo`,
 * - `getnetworkinfo` or
 * - `getwalletinfo`
 *
 * Or alternatively, create a specific query method for the information.
 **/
UniValue getinfo(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getinfo\n"
            "Returns an object containing various state info.\n"
            "\nResult:\n"
            "{\n"
            "  \"version\": xxxxx,           (numeric) the server version\n"
            "  \"protocolversion\": xxxxx,   (numeric) the protocol version\n"
            "  \"walletversion\": xxxxx,     (numeric) the wallet version\n"
            "  \"balance\": xxxxxxx,         (numeric) the total  balance of the wallet\n"
            "  \"blocks\": xxxxxx,           (numeric) the current number of blocks processed in the server\n"
            "  \"headers\": xxxxxx,          (numeric) the current number of headers processed in the server\n"
            "  \"timeoffset\": xxxxx,        (numeric) the time offset\n"
            "  \"connections\": xxxxx,       (numeric) the number of connections\n"
            "  \"peers_graphene\": xxxxx     (numeric) the number of grapheneblock peers\n"
            "  \"peers_xthinblock\": xxxxx,  (numeric) the number of xthinblock peers\n"
            "  \"peers_cmpctblock\": xxxxx,  (numeric) the number of compactblock peers\n"
            "  \"proxy\": \"host:port\",     (string, optional) the proxy used by the server\n"
            "  \"difficulty\": xxxxxx,       (numeric) the current difficulty\n"
            "  \"testnet\": true|false,      (boolean) if the server is using testnet or not\n"
            "  \"keypoololdest\": xxxxxx,    (numeric) the timestamp (seconds since GMT epoch) of the oldest "
            "pre-generated key in the key pool\n"
            "  \"keypoolsize\": xxxx,        (numeric) how many new keys are pre-generated\n"
            "  \"unlocked_until\": ttt,      (numeric) the timestamp in seconds since epoch (midnight Jan 1 1970 GMT) "
            "that the wallet is unlocked for transfers, or 0 if the wallet is locked\n"
            "  \"paytxfee\": xxxx,           (numeric) the transaction fee set in "
            "sat/KB\n"
            "  \"relayfee\": xxxx,           (numeric) minimum relay fee for non-free transactions in "
            "sat/KB\n"
            "  \"status\":\"...\"            (string) long running operations are indicated here (rescan).\n"
            "  \"txindex\":\"synced|trailing|not ready\" (string) indicate the current state of the txindex.\n"
            "  \"errors\": \"...\"           (string) any error messages\n"
            "}\n"
            "\nExamples:\n" +
            HelpExampleCli("getinfo", "") + HelpExampleRpc("getinfo", ""));

    // Get size of vNodes first to avoid any locking order mixups
    // when/if cs_main as well as cs_wallet are taken
    int nNodes = 0;
    {
        LOCK(cs_vNodes);
        nNodes = vNodes.size();
    }

    proxyType proxy;
    GetProxy(NET_IPV4, proxy);

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("version", CLIENT_VERSION);
    obj.pushKV("protocolversion", PROTOCOL_VERSION);
#ifdef ENABLE_WALLET
    if (pwalletMain)
    {
        obj.pushKV("walletversion", pwalletMain->GetVersion());
        obj.pushKV("balance", ValueFromAmount(pwalletMain->GetBalance()));
    }
#endif
    uint64_t curHeight = chainActive.Height();
    obj.pushKV("blocks", (int)curHeight);
    if (pindexBestHeader)
        obj.pushKV("headers", (int)pindexBestHeader.load()->height());
    obj.pushKV("timeoffset", GetTimeOffset());
    obj.pushKV("connections", nNodes);
    obj.pushKV("peers_graphene", (int)thinrelay.GetGraphenePeers());
    obj.pushKV("peers_xthinblock", (int)thinrelay.GetThinBlockPeers());
    obj.pushKV("peers_cmpctblock", (int)thinrelay.GetCompactBlockPeers());
    obj.pushKV("proxy", (proxy.IsValid() ? proxy.proxy.ToStringIPPort() : string()));
    obj.pushKV("difficulty", (double)GetDifficulty());
    obj.pushKV("testnet", Params().TestnetToBeDeprecatedFieldRPC());
#ifdef ENABLE_WALLET
    if (pwalletMain)
    {
        LOCK(&pwalletMain->cs_wallet);
        obj.pushKV("keypoololdest", pwalletMain->GetOldestKeyPoolTime());
        obj.pushKV("keypoolsize", (int)pwalletMain->GetKeyPoolSize());
    }
    if (pwalletMain && pwalletMain->IsCrypted())
        obj.pushKV("unlocked_until", nWalletUnlockTime);
    obj.pushKV("paytxfee", CFeeRate(payTxFeeTweak.Value()).GetFeePerK());
#endif
    obj.pushKV("relayfee", ::minRelayTxFee.GetFeePerK());
    obj.pushKV("status", statusStrings.GetPrintable());
    obj.pushKV("txindex", IsTxIndexReady() ? (curHeight == TxIndexSyncHeight() ? "synced" : "trailing") : "not ready");
    obj.pushKV("tokendesc", tokencache.GetSyncFlag() ? "synced" : "needs reindex");
    obj.pushKV("tokenmint", tokenmint.GetSyncFlag() ? "synced" : "needs reindex");
    obj.pushKV("errors", GetWarnings("statusbar"));

    return obj;
}

UniValue logline(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error("logline 'string'\n"
                            "Writes a string into the log (prefixed with 'rpc-logline: ').\n"
                            "\nResult: None\n");
    LOGA("rpc-logline: %s\n", params[0].get_str());
    LogFlush();
    return NullUniValue;
}

#ifdef ENABLE_WALLET
class DescribeAddressVisitor : public boost::static_visitor<UniValue>
{
public:
    UniValue operator()(const CNoDestination &dest) const { return UniValue(UniValue::VOBJ); }
    UniValue operator()(const CKeyID &keyID) const
    {
        UniValue obj(UniValue::VOBJ);
        CPubKey vchPubKey;
        obj.pushKV("isscript", false);
        if (pwalletMain)
        {
            if (pwalletMain->GetPubKey(keyID, vchPubKey))
            {
                obj.pushKV("pubkey", HexStr(vchPubKey));
                obj.pushKV("iscompressed", vchPubKey.IsCompressed());
            }
            auto keyMd = pwalletMain->mapKeyMetadata.find(keyID);
            if ((keyMd != pwalletMain->mapKeyMetadata.end()) && !keyMd->second.hdKeypath.empty())
            {
                obj.pushKV("hdkeypath", keyMd->second.hdKeypath);
                obj.pushKV("hdmasterkeyid", keyMd->second.hdMasterKeyID.GetHex());
            }
        }
        return obj;
    }

    UniValue operator()(const CScriptID &scriptID) const
    {
        UniValue obj(UniValue::VOBJ);
        CScript subscript;
        obj.pushKV("isscript", true);
        if (pwalletMain && pwalletMain->GetCScript(scriptID, subscript))
        {
            std::vector<CTxDestination> addresses;
            txnouttype whichType;
            int nRequired;
            ExtractDestinations(subscript, whichType, addresses, nRequired);
            obj.pushKV("script", GetTxnOutputType(whichType));
            obj.pushKV("hex", HexStr(subscript.begin(), subscript.end()));
            UniValue a(UniValue::VARR);
            for (const CTxDestination &addr : addresses)
            {
                a.push_back(EncodeDestination(addr));
            }
            obj.pushKV("addresses", a);
            if (whichType == TX_MULTISIG)
                obj.pushKV("sigsrequired", nRequired);
        }
        return obj;
    }

    UniValue operator()(const ScriptTemplateDestination &id) const
    {
        UniValue obj(UniValue::VOBJ);
        CPubKey pub;
        // If we can get a controlling pubkey out of this script, print info about it
        if (pwalletMain && pwalletMain->CBasicKeyStore::GetPubKey(id, pub))
        {
            obj.pushKV("pubkey", HexStr(pub));
            obj.pushKV("iscompressed", pub.IsCompressed());
            const CKeyID &keyID = pub.GetID();
            auto keyMd = pwalletMain->mapKeyMetadata.find(keyID);
            if ((keyMd != pwalletMain->mapKeyMetadata.end()) && !keyMd->second.hdKeypath.empty())
            {
                obj.pushKV("hdkeypath", keyMd->second.hdKeypath);
                obj.pushKV("hdmasterkeyid", keyMd->second.hdMasterKeyID.GetHex());
            }
        }
        ScriptPubKeyToJSON(id.toScript(), obj, true);
        return obj;
    }
};
#endif

UniValue validateaddress(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "validateaddress \"address\"\n"
            "\nReturn information about the given  address.\n"
            "\nArguments:\n"
            "1. \"address\"     (string, required) The  address to validate\n"
            "\nResult:\n"
            "{\n"
            "  \"isvalid\" : true|false,       (boolean) If the address is valid or not. If not, this is the only "
            "property returned.\n"
            "  \"address\" : \"address\", (string) The  address validated\n"
            "  \"scriptPubKey\" : \"hex\",       (string) The hex encoded scriptPubKey generated by the address\n"
            "  \"ismine\" : true|false,        (boolean) If the address is yours or not\n"
            "  \"iswatchonly\" : true|false,   (boolean) If the address is watchonly\n"
            "  \"isscript\" : true|false,      (boolean) If the key is a script\n"
            "  \"pubkey\" : \"publickeyhex\",    (string) The hex value of the raw public key\n"
            "  \"iscompressed\" : true|false,  (boolean) If the address is compressed\n"
            "  \"account\" : \"account\"         (string) DEPRECATED. The account associated with the address, \"\" is "
            "the default account\n"
            "  \"hdkeypath\" : \"keypath\"       (string, optional) The HD keypath if the key is HD and available\n"
            "  \"hdmasterkeyid\" : \"<hash160>\" (hex string, optional) The Hash160 of the HD master pubkey\n"
            "}\n"
            "\nExamples:\n" +
            HelpExampleCli("validateaddress", "\"1PSSGeFHDnKNxiEyFrD1wcEaHr9hrQDDWc\"") +
            HelpExampleRpc("validateaddress", "\"1PSSGeFHDnKNxiEyFrD1wcEaHr9hrQDDWc\""));

#ifdef ENABLE_WALLET
    LOCK2(cs_main, pwalletMain ? &pwalletMain->cs_wallet : nullptr);
#else
    LOCK(cs_main);
#endif

    CTxDestination dest = DecodeDestination(params[0].get_str());
    bool isValid = IsValidDestination(dest);

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("isvalid", isValid);
    if (isValid)
    {
        std::string currentAddress = EncodeDestination(dest);
        ret.pushKV("address", currentAddress);

        CScript scriptPubKey = GetScriptForDestination(dest);
        ret.pushKV("scriptPubKey", HexStr(scriptPubKey.begin(), scriptPubKey.end()));

#ifdef ENABLE_WALLET
        isminetype mine = pwalletMain ? IsMine(*pwalletMain, dest, chainActive.Tip()) : ISMINE_NO;
        ret.pushKV("ismine", (mine & ISMINE_SPENDABLE) ? true : false);
        ret.pushKV("iswatchonly", (mine & ISMINE_WATCH_ONLY) ? true : false);
        UniValue detail = std::visit(DescribeAddressVisitor(), dest);
        ret.pushKVs(detail);
        if (pwalletMain && pwalletMain->mapAddressBook.count(dest))
            ret.pushKV("account", pwalletMain->mapAddressBook[dest].name);
#endif
    }
    return ret;
}

/**
 * Used by addmultisigaddress / createmultisig:
 */
CScript _createmultisig_redeemScript(const UniValue &params)
{
    int nRequired = params[0].get_int();
    const UniValue &keys = params[1].get_array();

    // Gather public keys
    if (nRequired < 1)
        throw runtime_error("a multisignature address must require at least one key to redeem");
    if ((int)keys.size() < nRequired)
        throw runtime_error(strprintf("not enough keys supplied "
                                      "(got %u keys, but need at least %d to redeem)",
            keys.size(), nRequired));
    if (keys.size() > MAX_PUBKEYS_PER_MULTISIG)
        throw runtime_error(strprintf(
            "Number of addresses involved in the multisignature address creation > %s", MAX_PUBKEYS_PER_MULTISIG));
    std::vector<CPubKey> pubkeys;
    pubkeys.resize(keys.size());
    for (unsigned int i = 0; i < keys.size(); i++)
    {
        const std::string &ks = keys[i].get_str();
#ifdef ENABLE_WALLET
        // Case 1: Nexa address and we have full public key:
        CTxDestination dest = DecodeDestination(ks);
        if (pwalletMain && IsValidDestination(dest))
        {
            const CKeyID *keyID = std::get_if<CKeyID>(&dest);
            if (!keyID)
            {
                throw std::runtime_error(strprintf("%s does not refer to a key", ks));
            }
            CPubKey vchPubKey;
            if (!pwalletMain->GetPubKey(*keyID, vchPubKey))
            {
                throw std::runtime_error(strprintf("no full public key for address %s", ks));
            }
            if (!vchPubKey.IsFullyValid())
                throw runtime_error(" Invalid public key: " + ks);
            pubkeys[i] = vchPubKey;
        }

        // Case 2: hex public key
        else
#endif
            if (IsHex(ks))
        {
            CPubKey vchPubKey(ParseHex(ks));
            if (!vchPubKey.IsFullyValid())
                throw runtime_error(" Invalid public key: " + ks);
            pubkeys[i] = vchPubKey;
        }
        else
        {
            throw runtime_error(" Invalid public key: " + ks);
        }
    }
    CScript result = GetScriptForMultisig(nRequired, pubkeys);

    if (!withinStackWidth(result.size(), GetBlockScriptFlags(chainActive.Tip(), Params().GetConsensus())))
        throw runtime_error(strprintf("redeemScript exceeds size limit: %d", result.size()));

    return result;
}

UniValue createmultisig(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 2)
    {
        string msg =
            "createmultisig nrequired [\"key\",...]\n"
            "\nCreates a multi-signature address with n signature of m keys required.\n"
            "It returns a json object with the address and redeemScript.\n"

            "\nArguments:\n"
            "1. nrequired      (numeric, required) The number of required signatures out of the n keys or addresses.\n"
            "2. \"keys\"       (string, required) A json array of keys which are  addresses or hex-encoded "
            "public keys\n"
            "     [\n"
            "       \"key\"    (string)  address or hex-encoded public key\n"
            "       ,...\n"
            "     ]\n"

            "\nResult:\n"
            "{\n"
            "  \"address\":\"multisigaddress\",  (string) The value of the new multisig address.\n"
            "  \"redeemScript\":\"script\"       (string) The string value of the hex-encoded redemption script.\n"
            "}\n"

            "\nExamples:\n"
            "\nCreate a multisig address from 2 addresses\n" +
            HelpExampleCli("createmultisig",
                "2 \"[\\\"16sSauSf5pF2UkUwvKGq4qjNRzBZYqgEL5\\\",\\\"171sgjn4YtPu27adkKGrdDwzRTxnRkBfKV\\\"]\"") +
            "\nAs a json rpc call\n" +
            HelpExampleRpc("createmultisig",
                "2, \"[\\\"16sSauSf5pF2UkUwvKGq4qjNRzBZYqgEL5\\\",\\\"171sgjn4YtPu27adkKGrdDwzRTxnRkBfKV\\\"]\"");
        throw runtime_error(msg);
    }

    // Construct using pay-to-script-hash:
    CScript inner = _createmultisig_redeemScript(params);
    CScriptID innerID(inner);

    UniValue result(UniValue::VOBJ);
    result.pushKV("address", EncodeDestination(innerID));
    result.pushKV("redeemScript", HexStr(inner.begin(), inner.end()));

    return result;
}

bool VerifyMessage(const UniValue &params, std::string &error)
{
    string strAddress = params[0].get_str();
    string strSign = params[1].get_str();
    string strMessage = params[2].get_str();

    CTxDestination destination = DecodeDestination(strAddress);
    if (!IsValidDestination(destination))
    {
        error = "Invalid address";
        return false;
    }

    bool fInvalid = false;
    vector<unsigned char> vchSig = DecodeBase64(strSign.c_str(), &fInvalid);

    if (fInvalid)
    {
        error = "Malformed base64 encoding";
        return false;
    }

    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << strMessage;

    CPubKey pubkey;
    if (!pubkey.RecoverCompact(ss.GetHash(), vchSig))
    {
        error = "Could not recover key";
        return false;
    }

    ScriptTemplateDestination *st = nullptr;
    const CKeyID *keyID = std::get_if<CKeyID>(&destination);
    if (keyID)
    {
        if (pubkey.GetID() == *keyID)
        {
            return true;
        }
        else
        {
            error = "Verify Message Failed";
            return false;
        }
    }
    else if ((st = std::get_if<ScriptTemplateDestination>(&destination)) != nullptr)
    {
        CGroupTokenInfo groupInfo;
        std::vector<unsigned char> templateHash;
        if (ScriptTemplateError::OK != GetScriptTemplate(st->toScript(), &groupInfo, &templateHash))
        {
            error = "Address cannot be resolved to a public key";
            return false;
        }
        if (templateHash != P2PKT_ID)
        {
            error = "Address cannot be resolved to a public key (template is not well-known)";
            return false;
        }
        ScriptTemplateDestination signedBy(P2pktOutput(pubkey));
        if (*st == signedBy)
        {
            return true;
        }
        else
        {
            error = "Verify Message Failed";
            return false;
        }
    }
    else
    {
        error = "Address does not refer to key";
        return false;
    }
}
UniValue verifymessage(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() != 3)
        throw runtime_error(
            "verifymessage \"address\" \"signature\" \"message\"\n"
            "\nVerify a signed message\n"
            "\nArguments:\n"
            "1. \"address\"  (string, required) The  address to use for the signature.\n"
            "2. \"signature\"       (string, required) The signature provided by the signer in base 64 encoding (see "
            "signmessage).\n"
            "3. \"message\"         (string, required) The message that was signed.\n"
            "\nResult:\n"
            "true|false   (boolean) If the signature is verified or not.\n"
            "\nExamples:\n"
            "\nUnlock the wallet for 30 seconds\n" +
            HelpExampleCli("walletpassphrase", "\"mypassphrase\" 30") + "\nCreate the signature\n" +
            HelpExampleCli("signmessage", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\" \"my message\"") +
            "\nVerify the signature\n" +
            HelpExampleCli("verifymessage", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\" \"signature\" \"my message\"") +
            "\nAs json rpc\n" +
            HelpExampleRpc("verifymessage", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\", \"signature\", \"my message\""));

    std::string error = "";
    if (!VerifyMessage(params, error))
    {
        return error;
    }
    else
    {
        return true;
    }
}

UniValue setmocktime(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error("setmocktime timestamp\n"
                            "\nSet the local time to given timestamp (-regtest only)\n"
                            "\nArguments:\n"
                            "1. timestamp  (integer, required) Unix seconds-since-epoch timestamp\n"
                            "   Pass 0 to go back to using the system time.");

    if (!Params().MineBlocksOnDemand())
        throw runtime_error("setmocktime for regression testing (-regtest mode) only");

    // cs_vNodes is locked and node send/receive times are updated
    // atomically with the time change to prevent peers from being
    // disconnected because we think we haven't communicated with them
    // in a long time.
    LOCK2(cs_main, cs_vNodes);

    RPCTypeCheck(params, {UniValue::VNUM});
    SetMockTime(params[0].get_int64());

    uint64_t t = GetTime();
    for (CNode *pnode : vNodes)
    {
        pnode->nLastSend = pnode->nLastRecv = t;
    }

    return NullUniValue;
}

static const CRPCCommand commands[] = {
    //  category              name                      actor (function)         okSafeMode
    //  --------------------- ------------------------  -----------------------  ----------
    {"control", "getinfo", &getinfo, true}, /* uses wallet if enabled */
    {"util", "validateaddress", &validateaddress, true}, /* uses wallet if enabled */
    {"util", "createmultisig", &createmultisig, true},
    {"util", "verifymessage", &verifymessage, true},
    {"util", "logline", &logline, true},

    /* Not shown in help */
    {"hidden", "setmocktime", &setmocktime, true},
};

void RegisterMiscRPCCommands(CRPCTable &table)
{
    for (auto cmd : commands)
        table.appendCommand(cmd);
}
