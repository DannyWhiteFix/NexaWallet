// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include "wallet/grouptokenwallet.h"
#include "base58.h"
#include "cashaddrenc.h"
#include "coincontrol.h"
#include "coins.h"
#include "consensus/grouptokens.h"
#include "consensus/validation.h"
#include "dstencode.h"
#include "prevector.h"
#include "primitives/transaction.h"
#include "pubkey.h"
#include "random.h"
#include "rpc/protocol.h"
#include "rpc/server.h"
#include "script/script.h"
#include "script/standard.h"
#include "txadmission.h"
#include "txdebugger.h"
#include "unlimited.h"
#include "utilmoneystr.h"
#include "wallet/wallet.h"
#include <algorithm>

#include "main.h" // for BlockMap

// allow this many times fee overpayment, rather than make a change output
#define FEE_FUDGE 2

// How many satoshis to add over the wallet-determined minimum fee for token operations
// (because different clients have different min fee policies)
#define TOKEN_EXTRA_FEE 10

extern CChain chainActive;
bool EnsureWalletIsAvailable(bool avoidException);
UniValue groupedlistsinceblock(const UniValue &params, bool fHelp);
UniValue groupedlisttransactions(const UniValue &params, bool fHelp);

// Number of satoshis we will put into a grouped output
CAmount GROUPED_SATOSHI_AMT = 0;

// Approximate size of signature in a script -- used for guessing fees
const unsigned int TX_SIG_SCRIPT_LEN = 80 + 32; // sig + pubkey

const unsigned int DEFAULT_OP_RETURN_GROUP_ID = 88888888;

/* Grouped transactions look like this:

GP2PKH:

OP_DATA(group identifier)
OP_DATA(SerializeAmount(amount))
OP_GROUP
OP_DUP
OP_HASH160
OP_DATA(pubkeyhash)
OP_EQUALVERIFY
OP_CHECKSIG

GP2SH:

OP_DATA(group identifier)
OP_DATA(CompactSize(amount))
OP_GROUP
OP_HASH160 [20-byte-hash-value] OP_EQUAL

FUTURE: GP2SH version 2:

OP_DATA(group identifier)
OP_DATA(CompactSize(amount))
OP_GROUP
OP_HASH256 [32-byte-hash-value] OP_EQUAL
*/

class CTxDestinationGroupTokenExtractor : public boost::static_visitor<CGroupTokenID>
{
public:
    CGroupTokenID operator()(const CKeyID &id) const { return CGroupTokenID(id); }
    CGroupTokenID operator()(const CScriptID &id) const { return CGroupTokenID(id); }
    CGroupTokenID operator()(const CNoDestination &) const { return CGroupTokenID(); }
    CGroupTokenID operator()(const ScriptTemplateDestination &id) const { return id.Group(); }
};

CGroupTokenID GetGroupToken(const CTxDestination &id) { return std::visit(CTxDestinationGroupTokenExtractor(), id); }

CTxDestination ControllingAddress(const CGroupTokenID &grp, txnouttype addrType)
{
    const std::vector<unsigned char> &data = grp.bytes();
    if (data.size() != 20) // this is a single mint so no controlling address
        return CNoDestination();
    if (addrType == TX_SCRIPTHASH)
        return CTxDestination(CScriptID(uint160(data)));
    return CTxDestination(CKeyID(uint160(data)));
}

class CGroupScriptVisitor : public boost::static_visitor<bool>
{
private:
    CScript *script;
    CGroupTokenID group;
    CAmount quantity;

public:
    CGroupScriptVisitor(CGroupTokenID grp, CAmount qty, CScript *scriptin) : group(grp), quantity(qty)
    {
        script = scriptin;
    }
    bool operator()(const CNoDestination &dest) const
    {
        script->clear();
        return false;
    }

    bool operator()(const CKeyID &keyID) const
    {
        script->clear();
        if (group.isUserGroup())
        {
            DbgAssert(false, return false); // Grouped things MUST use templates
        }
        else
        {
            *script << OP_DUP << OP_HASH160 << ToByteVector(keyID) << OP_EQUALVERIFY << OP_CHECKSIG;
        }
        return true;
    }

    bool operator()(const CScriptID &scriptID) const
    {
        script->clear();
        if (group.isUserGroup())
        {
            DbgAssert(false, return false); // Grouped things MUST use templates
        }
        else
        {
            *script << OP_HASH160 << ToByteVector(scriptID) << OP_EQUAL;
        }
        return true;
    }

    bool operator()(const ScriptTemplateDestination &id) const
    {
        *script = id.toScript(group, quantity);
        if (script->IsInvalid())
            return false;
        return true;
    }
};

std::vector<std::string> GetTokenDescription(const CScript &script)
{
    std::vector<std::string> vTokenDesc;

    CScript::const_iterator pc = script.begin();
    opcodetype op;
    std::vector<unsigned char> vchRet;

    // Check we have an op_return
    script.GetOp(pc, op, vchRet);
    if (op != OP_RETURN)
        return {};

    // Check for correct group id
    script.GetOp(pc, op, vchRet);
    uint32_t grpId;
    std::stringstream ss;
    std::reverse(vchRet.begin(), vchRet.end());
    ss << std::hex << HexStr(vchRet);
    ss >> grpId;
    if (grpId != DEFAULT_OP_RETURN_GROUP_ID)
        return {};

    // Get labels
    while (script.GetOp(pc, op, vchRet))
    {
        if (op != OP_0)
        {
            std::string s(vchRet.begin(), vchRet.end());
            vTokenDesc.push_back(s);
        }
        else
            vTokenDesc.push_back("");
    }

    return vTokenDesc;
}

CScript BuildTokenDescScript(const std::vector<std::vector<unsigned char> > &desc)
{
    // see https: github.com/bitcoincashorg/bitcoincash.org/blob/master/etc/protocols.csv
    CScript ret;
    ret << OP_RETURN << DEFAULT_OP_RETURN_GROUP_ID;
    for (auto &d : desc)
    {
        ret << d;
    }

    return ret;
}

void GetAllGroupDescriptions(const CWallet *wallet,
    std::unordered_map<CGroupTokenID, std::vector<std::string> > &desc,
    const CGroupTokenID &grpID)
{
    // Find all the coins that have a groupID
    std::vector<COutput> vCoins;
    {
        LOCK(wallet->cs_wallet);
        for (auto &iter : wallet->mapWallet)
        {
            const COutput &coin = iter.second;
            if (coin.isNull() || coin.txOnly())
                continue;
            CGroupTokenInfo tg(coin.GetScriptPubKey());
            if ((tg.associatedGroup != NoGroup) && tg.isAuthority())
            {
                if (grpID != NoGroup && tg.associatedGroup != grpID)
                    continue;
                vCoins.push_back(coin);
            }
        }
    }

    // parse through the transaction to find any op_returns, strip out the labels, and associated them with the groupIDs
    for (COutput &coin : vCoins)
    {
        // Get transaction
        const CWalletTxRef &wtx = coin.tx;
        CGroupTokenInfo tg(coin.GetScriptPubKey());
        bool fOpReturn = false;
        for (const CTxOut &out : wtx->vout)
        {
            // find op_return associated with the tx if there is one
            if (out.scriptPubKey[0] == OP_RETURN)
            {
                fOpReturn = true;
                desc[tg.associatedGroup] = GetTokenDescription(out.scriptPubKey);
                break;
            }
        }

        // If there is no OP_RETURN then just return empty strings for the token descriptions
        if (!fOpReturn)
        {
            desc[tg.associatedGroup] = std::vector<std::string>({"", "", "", ""});
        }
    }
}

void GetAllGroupBalances(const CWallet *wallet, std::unordered_map<CGroupTokenID, CAmount> &balances)
{
    std::vector<COutput> coins;
    wallet->FilterCoins(coins,
        [&balances](const COutput &coin)
        {
            CGroupTokenInfo tg(coin.GetScriptPubKey());
            if ((tg.associatedGroup != NoGroup) && !tg.isAuthority()) // must be sitting in any group address
            {
                if (tg.quantity > std::numeric_limits<CAmount>::max() - balances[tg.associatedGroup])
                    balances[tg.associatedGroup] = std::numeric_limits<CAmount>::max();
                else
                    balances[tg.associatedGroup] += tg.quantity;
            }
            return false; // I don't want to actually filter anything
        });
}

CAmount GetGroupBalance(const CGroupTokenID &grpID, const CTxDestination &dest, const CWallet *wallet)
{
    std::vector<COutput> coins;
    CAmount balance = 0;
    wallet->FilterCoins(coins,
        [grpID, dest, &balance](const COutput &coin)
        {
            CGroupTokenInfo tg(coin.GetScriptPubKey());
            if ((grpID == tg.associatedGroup) && !tg.isAuthority()) // must be sitting in group address
            {
                bool useit = dest == CTxDestination(CNoDestination());
                if (!useit)
                {
                    CTxDestination address;
                    txnouttype whichType;
                    if (ExtractDestinationAndType(coin.GetScriptPubKey(), address, whichType))
                    {
                        if (address == dest)
                            useit = true;
                    }
                }
                if (useit)
                {
                    if (tg.quantity > std::numeric_limits<CAmount>::max() - balance)
                        balance = std::numeric_limits<CAmount>::max();
                    else
                        balance += tg.quantity;
                }
            }
            return false;
        });
    return balance;
}

CScript GetScriptForDestination(const CTxDestination &dest, const CGroupTokenID &group, const CAmount &amount)
{
    CScript script;

    std::visit(CGroupScriptVisitor(group, amount, &script), dest);
    return script;
}

static CAmount AmountFromIntegralValue(const UniValue &value)
{
    if (!value.isNum() && !value.isStr())
        throw std::runtime_error("Amount is not a number or string");
    int64_t val = atoi64(value.getValStr());
    CAmount amount = val;
    return amount;
}

static GroupAuthorityFlags ParseAuthorityParams(const UniValue &params, unsigned int &curparam)
{
    GroupAuthorityFlags flags = GroupAuthorityFlags::AUTHORITY | GroupAuthorityFlags::BATON;
    while (1)
    {
        std::string sflag;
        std::string p = params[curparam].get_str();
        std::transform(p.begin(), p.end(), std::back_inserter(sflag), ::tolower);
        if (sflag == "mint")
            flags |= GroupAuthorityFlags::MINT;
        else if (sflag == "melt")
            flags |= GroupAuthorityFlags::MELT;
        else if (sflag == "nochild")
            flags &= ~GroupAuthorityFlags::BATON;
        else if (sflag == "child")
            flags |= GroupAuthorityFlags::BATON;
        else if (sflag == "rescript")
            flags |= GroupAuthorityFlags::RESCRIPT;
        else if (sflag == "subgroup")
            flags |= GroupAuthorityFlags::SUBGROUP;
        else
            break; // If param didn't match, then return because we've left the list of flags
        curparam++;
        if (curparam >= params.size())
            break;
    }
    return flags;
}

// extracts a common RPC call parameter pattern.  Returns curparam.
static unsigned int ParseGroupAddrValue(const UniValue &params,
    unsigned int curparam,
    CGroupTokenID &grpID,
    std::vector<CRecipient> &outputs,
    CAmount &totalValue,
    bool groupedOutputs)
{
    grpID = DecodeGroupToken(params[curparam].get_str());
    if (!grpID.isUserGroup())
    {
        throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid parameter: No group specified");
    }
    outputs.reserve(params.size() / 2);
    curparam++;
    totalValue = 0;
    while (curparam + 1 < params.size())
    {
        CTxDestination dst = DecodeDestination(params[curparam].get_str(), Params());
        if (dst == CTxDestination(CNoDestination()))
        {
            throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid parameter: destination address");
        }
        if (!std::get_if<ScriptTemplateDestination>(&dst))
        {
            throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid parameter: destination address must be script template");
        }

        CAmount amount = AmountFromIntegralValue(params[curparam + 1]);
        if (amount <= 0)
            throw JSONRPCError(RPC_TYPE_ERROR, "Invalid parameter: amount");
        CScript script;
        CRecipient recipient;
        if (groupedOutputs)
        {
            script = GetScriptForDestination(dst, grpID, amount);
            recipient = {script, GROUPED_SATOSHI_AMT, false};
        }
        else
        {
            script = GetScriptForDestination(dst, NoGroup, 0);
            recipient = {script, amount, false};
        }

        totalValue += amount;
        outputs.push_back(recipient);
        curparam += 2;
    }
    return curparam;
}

bool NearestGreaterCoin(const std::vector<COutput> &coins, CAmount amt, COutput &chosenCoin)
{
    bool ret = false;
    CAmount curBest = std::numeric_limits<CAmount>::max();

    for (const auto &coin : coins)
    {
        CAmount camt = coin.GetValue();
        if ((camt > amt) && (camt < curBest))
        {
            curBest = camt;
            chosenCoin = coin;
            ret = true;
        }
    }

    return ret;
}


CAmount CoinSelection(const std::vector<COutput> &coins, CAmount amt, std::vector<COutput> &chosenCoins)
{
    // simple algorithm grabs until amount exceeded
    CAmount cur = 0;

    for (const auto &coin : coins)
    {
        chosenCoins.push_back(coin);
        cur += coin.GetValue();
        if (cur >= amt)
            break;
    }
    return cur;
}

CAmount GroupCoinSelection(const std::vector<COutput> &coins, CAmount amt, std::vector<COutput> &chosenCoins)
{
    // simple algorithm grabs until amount exceeded
    CAmount cur = 0;

    for (const auto &coin : coins)
    {
        chosenCoins.push_back(coin);
        CGroupTokenInfo tg(coin.tx->vout[coin.i].scriptPubKey);
        cur += tg.quantity;
        if (cur >= amt)
            break;
    }
    return cur;
}

uint64_t RenewAuthority(const COutput &authority, std::vector<CRecipient> &outputs, CReserveKey &childAuthorityKey)
{
    // The melting authority is consumed.  A wallet can decide to create a child authority or not.
    // In this simple wallet, we will always create a new melting authority if we spend a renewable
    // (BATON is set) one.
    uint64_t totalBchNeeded = 0;
    CGroupTokenInfo tg(authority.GetScriptPubKey());

    if (tg.allowsRenew())
    {
        // Get a new address from the wallet to put the new mint authority in.
        CPubKey pubkey;
        childAuthorityKey.GetReservedKey(pubkey);
        CScript script = P2pktOutput(
            pubkey, tg.associatedGroup, (CAmount)(tg.controllingGroupFlags & GroupAuthorityFlags::ALL_FLAG_BITS));
        CRecipient recipient = {script, GROUPED_SATOSHI_AMT, false};
        outputs.push_back(recipient);
        totalBchNeeded += GROUPED_SATOSHI_AMT;
    }

    return totalBchNeeded;
}

void ConstructTx(CWalletTx &wtxNew,
    const std::vector<COutput> &chosenCoins,
    const std::vector<CRecipient> &outputs,
    CAmount totalAvailable,
    CAmount totalNeeded,
    CAmount totalGroupedAvailable,
    CAmount totalGroupedNeeded,
    CGroupTokenID grpID,
    CWallet *wallet)
{
    std::string strError;
    CMutableTransaction tx;
    CReserveKey groupChangeKeyReservation(wallet);
    CReserveKey feeChangeKeyReservation(wallet);

    {
        assert(tx.nLockTime <= (unsigned int)chainActive.Height());
        assert(tx.nLockTime < LOCKTIME_THRESHOLD);
        unsigned int approxSize = 4 * 4; // serialize nVersion, nLockTime, vector size for inputs and outputs

        // Add group outputs based on the passed recipient data to the tx.
        for (const CRecipient &recipient : outputs)
        {
            CTxOut txout(recipient.nAmount, recipient.scriptPubKey);
            tx.vout.push_back(txout);
            approxSize += ::GetSerializeSize(txout, SER_DISK, CLIENT_VERSION);
        }

        // Gather data on the provided inputs, and add them to the tx.
        unsigned int inpSize = 0;
        for (const auto &coin : chosenCoins)
        {
            CTxIn txin(coin.GetOutPoint(), coin.GetValue(), CScript(), std::numeric_limits<unsigned int>::max() - 1);
            tx.vin.push_back(txin);
            inpSize = ::GetSerializeSize(txin, SER_DISK, CLIENT_VERSION) + TX_SIG_SCRIPT_LEN;
            approxSize += inpSize;
        }

        if (totalGroupedAvailable > totalGroupedNeeded) // need to make a group change output
        {
            CPubKey newKey;

            if (!groupChangeKeyReservation.GetReservedKey(newKey))
                throw JSONRPCError(
                    RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");

            CTxOut txout(GROUPED_SATOSHI_AMT, P2pktOutput(newKey, grpID, totalGroupedAvailable - totalGroupedNeeded));
            tx.vout.push_back(txout);
            approxSize += ::GetSerializeSize(txout, SER_DISK, CLIENT_VERSION);
        }

        // Add another input for the coin used for the fee
        // this ignores the additional change output
        approxSize += inpSize;

        // Now add the fee
        CAmount fee = wallet->GetRequiredFee(approxSize) + TOKEN_EXTRA_FEE;

        if (totalAvailable < totalNeeded + fee) // need to find a fee input
        {
            // find a fee input
            std::vector<COutput> bchcoins;
            wallet->FilterCoins(bchcoins,
                [](const COutput &coin)
                {
                    CGroupTokenInfo tg(coin.GetScriptPubKey());
                    return NoGroup == tg.associatedGroup;
                });

            COutput feeCoin;
            if (!NearestGreaterCoin(bchcoins, fee, feeCoin))
            {
                strError = strprintf("Not enough funds for fee of %d.", FormatMoney(fee));
                throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, strError);
            }

            CTxIn txin(
                feeCoin.GetOutPoint(), feeCoin.GetValue(), CScript(), std::numeric_limits<unsigned int>::max() - 1);
            tx.vin.push_back(txin);
            totalAvailable += feeCoin.GetValue();
        }

        // make change if input is too big -- its okay to overpay by FEE_FUDGE rather than make dust.
        if (totalAvailable > totalNeeded + (FEE_FUDGE * fee))
        {
            CPubKey newKey;

            if (!feeChangeKeyReservation.GetReservedKey(newKey))
                throw JSONRPCError(
                    RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");

            CTxOut txout(totalAvailable - totalNeeded - fee, P2pktOutput(newKey));
            // figure out what the additional fee will be for the change output
            approxSize += ::GetSerializeSize(txout, SER_DISK, CLIENT_VERSION);
            fee = wallet->GetRequiredFee(approxSize) + TOKEN_EXTRA_FEE;
            txout.nValue = totalAvailable - totalNeeded - fee; // Adjust the value based on the new fee
            tx.vout.push_back(txout);
        }

        if (!wallet->SignTransaction(tx))
        {
            throw JSONRPCError(RPC_WALLET_ERROR, "Signing transaction failed (group token)");
        }
    }

    wtxNew.BindWallet(wallet);
    wtxNew.fFromMe = true;
    *static_cast<CTransaction *>(&wtxNew) = CTransaction(tx);
    // I'll manage my own keys because I have multiple.  Passing a valid key down breaks layering.
    CReserveKey dummy(wallet);
    if (!wallet->CommitTransaction(wtxNew, dummy))
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: The transaction was rejected! This might happen if some of the "
                                             "coins in your wallet were already spent, such as if you used a copy of "
                                             "wallet.dat and coins were spent in the copy but not marked as spent "
                                             "here.");

    feeChangeKeyReservation.KeepKey();
    groupChangeKeyReservation.KeepKey();
}


void GroupMelt(CWalletTx &wtxNew, const CGroupTokenID &grpID, CAmount totalNeeded, CWallet *wallet)
{
    std::string strError;
    std::vector<CRecipient> outputs; // Melt has no outputs (except change)
    CAmount totalAvailable = 0;
    CAmount totalBchAvailable = 0;
    CAmount totalBchNeeded = 0;
    LOCK(wallet->cs_wallet);

    // Find melt authority
    std::vector<COutput> coins;

    int nOptions = wallet->FilterCoins(coins,
        [grpID](const COutput &coin)
        {
            CGroupTokenInfo tg(coin.GetScriptPubKey());
            if ((tg.associatedGroup == grpID) && tg.allowsMelt())
            {
                return true;
            }
            return false;
        });

    // if its a subgroup look for a parent authority that will work
    // As an idiot-proofing step, we only allow parent authorities that can be renewed, but that is a
    // preference coded in this wallet, not a group token requirement.
    if ((nOptions == 0) && (grpID.isSubgroup()))
    {
        // if its a subgroup look for a parent authority that will work
        nOptions = wallet->FilterCoins(coins,
            [grpID](const COutput &coin)
            {
                CGroupTokenInfo tg(coin.GetScriptPubKey());
                if (tg.isAuthority() && tg.allowsRenew() && tg.allowsSubgroup() && tg.allowsMelt() &&
                    (tg.associatedGroup == grpID.parentGroup()))
                {
                    return true;
                }
                return false;
            });
    }

    if (nOptions == 0)
    {
        strError = strprintf("To melt coins, an authority output with melt capability is needed.");
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, strError);
    }
    COutput authority;
    // Just pick the first one for now.
    for (auto coin : coins)
    {
        totalBchAvailable += coin.tx->vout[coin.i].nValue; // The melt authority may have some BCH in it
        authority = coin;
        break;
    }

    // Find meltable coins
    coins.clear();
    wallet->FilterCoins(coins,
        [grpID](const COutput &coin)
        {
            CGroupTokenInfo tg(coin.GetScriptPubKey());
            // must be a grouped output sitting in group address
            return ((grpID == tg.associatedGroup) && !tg.isAuthority());
        });

    // Get a near but greater quantity
    std::vector<COutput> chosenCoins;
    totalAvailable = GroupCoinSelection(coins, totalNeeded, chosenCoins);

    if (totalAvailable < totalNeeded)
    {
        strError = strprintf("Not enough tokens in the wallet.  Need %d more.", totalNeeded - totalAvailable);
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, strError);
    }

    chosenCoins.push_back(authority);

    CReserveKey childAuthorityKey(wallet);
    totalBchNeeded += RenewAuthority(authority, outputs, childAuthorityKey);
    // by passing a fewer tokens available than are actually in the inputs, there is a surplus.
    // This surplus will be melted.
    ConstructTx(wtxNew, chosenCoins, outputs, totalBchAvailable, totalBchNeeded, totalAvailable - totalNeeded, 0, grpID,
        wallet);
    childAuthorityKey.KeepKey();
}

void GroupSend(CWalletTx &wtxNew,
    const CGroupTokenID &grpID,
    const std::vector<CRecipient> &outputs,
    CAmount totalNeeded,
    CWallet *wallet)
{
    LOCK(wallet->cs_wallet);
    std::string strError;
    std::vector<COutput> coins;
    CAmount totalAvailable = 0;
    CAmount totalBchNeeded = 0;
    wallet->FilterCoins(coins,
        [grpID, &totalAvailable](const COutput &coin)
        {
            CGroupTokenInfo tg(coin.GetScriptPubKey());
            if ((grpID == tg.associatedGroup) && !tg.isAuthority())
            {
                totalAvailable += tg.quantity;
                return true;
            }
            return false;
        });

    if (totalAvailable < totalNeeded)
    {
        strError = strprintf("Not enough tokens in the wallet.  Need %d more.", totalNeeded - totalAvailable);
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, strError);
    }

    // Account for the satoshi dust for each token output
    for (auto &out : outputs)
        totalBchNeeded += out.nAmount;

    // Get a near but greater quantity
    std::vector<COutput> chosenCoins;
    totalAvailable = GroupCoinSelection(coins, totalNeeded, chosenCoins);

    ConstructTx(wtxNew, chosenCoins, outputs, 0, totalBchNeeded, totalAvailable, totalNeeded, grpID, wallet);
}

std::vector<std::vector<unsigned char> > ParseGroupDescParams(const UniValue &params, unsigned int &curparam)
{
    std::vector<std::vector<unsigned char> > ret;
    std::string tickerStr = params[curparam].get_str();
    if (tickerStr.size() > 8)
    {
        std::string strError = strprintf("Ticker %s has too many characters (8 max)", tickerStr);
        throw JSONRPCError(RPC_INVALID_PARAMS, strError);
    }
    ret.push_back(std::vector<unsigned char>(tickerStr.begin(), tickerStr.end()));

    curparam++;
    if (curparam >= params.size())
    {
        throw JSONRPCError(RPC_INVALID_PARAMS, "Missing parameter: token name");
    }

    std::string name = params[curparam].get_str();
    ret.push_back(std::vector<unsigned char>(name.begin(), name.end()));
    curparam++;
    // we will accept just ticker and name
    if (curparam >= params.size())
    {
        ret.push_back(std::vector<unsigned char>());
        ret.push_back(std::vector<unsigned char>());
        return ret;
    }

    std::string url = params[curparam].get_str();
    // we could do a complete URL validity check here but for now just check for :
    if (url.find(":") == std::string::npos)
    {
        std::string strError = strprintf("Parameter %s is not a URL, missing colon", url);
        throw JSONRPCError(RPC_INVALID_PARAMS, strError);
    }
    ret.push_back(std::vector<unsigned char>(url.begin(), url.end()));

    curparam++;
    if (curparam >= params.size())
    {
        // If you have a URL to the TDD, you need to have a hash or the token creator
        // could change the document without holders knowing about it.
        throw JSONRPCError(RPC_INVALID_PARAMS, "Missing parameter: token description document hash");
    }

    std::string hexDocHash = params[curparam].get_str();
    uint256 docHash;
    docHash.SetHex(hexDocHash);
    ret.push_back(std::vector<unsigned char>(docHash.begin(), docHash.end()));
    return ret;
}


CGroupTokenID findGroupId(const COutPoint &input,
    CScript opRetTokDesc,
    GroupTokenIdFlags flags,
    GroupAuthorityFlags authorityFlags,
    uint64_t &nonce)
{
    CGroupTokenID ret;
    uint32_t foundGrpFlags = 0;
    do
    {
        nonce += 1;
        CHashWriter hasher(SER_GETHASH, PROTOCOL_VERSION);
        // mask off any nonce leak into flags and then or in the flags
        nonce = (nonce & ~((uint64_t)GroupAuthorityFlags::ALL_FLAG_BITS)) | ((uint64_t)authorityFlags); // REQ3.2.1.5
        hasher << input;

        if (!opRetTokDesc.empty())
        {
            std::vector<unsigned char> data(opRetTokDesc.begin(), opRetTokDesc.end());
            hasher << data;
        }
        hasher << nonce;
        ret = hasher.GetHash();
        foundGrpFlags = (ret.bytes()[30] << 8) | ret.bytes()[31];
    } while (foundGrpFlags != (uint16_t)flags);
    return ret;
}

extern UniValue token(const UniValue &params, bool fHelp)
{
    CWallet *wallet = pwalletMain;
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() < 1)
        throw std::runtime_error(
            "token [info, new, mint, melt, send] \n"
            "\nToken functions.\n"
            "'info' returns a list of all tokens with their groupId and associated token-name token-ticker "
            "and descUrl or descHash, but only for tokens created for addresses in this wallet\n"
            "'new' creates a new token type. args: [address] [token-ticker token-name [descUrl descHash]]\n"
            "'mint' creates new tokens. args: groupId address quantity\n"
            "'melt' removes tokens from circulation. args: groupId quantity\n"
            "'balance' reports quantity of this token. args: groupId [address]\n"
            "'send' sends tokens to a new address. args: groupId address quantity [address quantity...]\n"
            "'authority create' creates a new authority args: groupId address [mint melt nochild rescript]\n"
            "'subgroup' translates a group and additional data into a subgroup identifier. args: groupId data\n"
            "\nArguments:\n"
            "1. \"groupId\"           (string, required) the group identifier\n"
            "2. \"address\"           (string, required) the destination address\n"
            "3. \"quantity\"          (numeric, required) the quantity desired\n"
            "4. \"data\"              (number, 0xhex, or string) binary data\n"
            "5. \"token-ticker\"      (string, optional) the token's preferred ticker symbol\n"
            "6. \"token-name\"        (string, optional) the name of the token\n"
            "7. \"descUrl\"           (string, optional) the url of the token description json document\n"
            "8. \"descHash\"          (string, optional) the hash of the token description json document\n"
            "9. \"nochild\"           (string, optional) do not allow this authority to create child authorities\n"
            "10.\"rescript\"          (string, optional) for covenanted groups, this authority can change the\n"
            "                         constraint script hash\n"
            "\nResult:\n"
            "\n"
            "\nExamples:\n"
            "\nGet token info\n" +
            HelpExampleCli("token", "info") + "\nCreate a new token\n" + HelpExampleCli("token", "new APPL apple") +
            HelpExampleCli("token", "new nexa:nqtsq5g59472zwd85c2esgslh6wh025r0x43ttlv2xy98jd0 ORNGE orange") +
            HelpExampleCli("token", "new nexa:nqtsq5g5ltvwgj6ga6vlyxcay22uh2m8zy0rxzp8sf884gp9 GRP grape "
                                    "http://nexa.org "
                                    "1296fdd732e34fa750256095bb68dcd78091c49ab9382a35dce89ea15e055a63") +
            "\nMint tokens\n" +
            HelpExampleCli("token", "mint nexa:tpyte9hwr6ew0agt67a0y2fnnccc0d8r62lwryq44rfhzmv7ngqqqza82qdum "
                                    "nexa:nqtsq5g553andqv5p33ylx7xyr76vu0mh56x5nlylhfzcyj2 30000") +
            "\nMelt tokens\n" +
            HelpExampleCli("token", "mint nexa:tpyte9hwr6ew0agt67a0y2fnnccc0d8r62lwryq44rfhzmv7ngqqqza82qdum 500") +
            "\nGet wallet token balances\n" + HelpExampleCli("token", "balance") +
            HelpExampleCli("token", "balance nexa:tpyte9hwr6ew0agt67a0y2fnnccc0d8r62lwryq44rfhzmv7ngqqqza82qdum") +
            HelpExampleCli("token", "balance nexa:tpyte9hwr6ew0agt67a0y2fnnccc0d8r62lwryq44rfhzmv7ngqqqza82qdum "
                                    "nexa:nqtsq5g553andqv5p33ylx7xyr76vu0mh56x5nlylhfzcyj2") +
            "\nSend tokens\n" +
            HelpExampleCli("token", "send nexa:tpyte9hwr6ew0agt67a0y2fnnccc0d8r62lwryq44rfhzmv7ngqqqza82qdum "
                                    "nexa:nqtsq5g5swutfrulf565c6v42rk36gk9w9r8lwymly8ju76c 150") +
            HelpExampleCli("token", "send nexa:tpyte9hwr6ew0agt67a0y2fnnccc0d8r62lwryq44rfhzmv7ngqqqza82qdum "
                                    "nexa:nqtsq5g5swutfrulf565c6v42rk36gk9w9r8lwymly8ju76c 100 "
                                    "nexa:nqtsq5g563td29kuumldxk0u6lsfrjyapxth5jqwmyepjmlw 300") +
            "\nMake new authority\n" +
            HelpExampleCli("token",
                "authority create nexa:tpyte9hwr6ew0agt67a0y2fnnccc0d8r62lwryq44rfhzmv7ngqqqza82qdu0 "
                "nexa:nqtsq5g5t8hqv7gflfp3gshvck0srh2a0ktd53kzc97c26w0 mint melt nochild rescript") +
            "\nMake subgroups\n " +
            HelpExampleCli("token", "subgroup nexa:tpyte9hwr6ew0agt67a0y2fnnccc0d8r62lwryq44rfhzmv7ngqqqza82qdum 1"));

    std::string operation;
    std::string p0 = params[0].get_str();
    std::transform(p0.begin(), p0.end(), std::back_inserter(operation), ::tolower);
    EnsureWalletIsUnlocked();

    // Initialize the minimum amount to fill a group output.
    if (GROUPED_SATOSHI_AMT == 0)
    {
        GROUPED_SATOSHI_AMT = CFeeRate().GetDust();
    }

    if (operation == "listsinceblock")
    {
        return groupedlistsinceblock(params, fHelp);
    }
    if (operation == "listtransactions")
    {
        return groupedlisttransactions(params, fHelp);
    }
    if (operation == "subgroup")
    {
        unsigned int curparam = 1;
        if (curparam >= params.size())
        {
            throw JSONRPCError(RPC_INVALID_PARAMS, "Missing parameters");
        }
        CGroupTokenID grpID;
        std::vector<unsigned char> postfix;
        // Get the group id from the command line
        grpID = DecodeGroupToken(params[curparam].get_str());
        if (!grpID.isUserGroup())
        {
            throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid parameter: No group specified");
        }
        curparam++;

        int64_t postfixNum = 0;
        bool isNum = false;
        if (params[curparam].isNum())
        {
            postfixNum = params[curparam].get_int64();
            isNum = true;
        }
        else // assume string
        {
            std::string postfixStr = params[curparam].get_str();
            if ((postfixStr[0] == '0') && (postfixStr[0] == 'x'))
            {
                throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid parameter: Hex not implemented yet");
            }
            try
            {
                postfixNum = std::stoull(postfixStr);
                isNum = true;
            }
            catch (const std::invalid_argument &)
            {
                for (unsigned int i = 0; i < postfixStr.size(); i++)
                    postfix.push_back(postfixStr[i]);
            }
        }

        if (isNum)
        {
            CDataStream ss(0, 0);
            ser_writedata64(ss, postfixNum);
            for (auto c : ss)
                postfix.push_back(c);
        }

        if (postfix.size() == 0)
        {
            throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid parameter: no subgroup postfix provided");
        }
        std::vector<unsigned char> subgroupbytes(grpID.bytes().size() + postfix.size());
        unsigned int i;
        for (i = 0; i < grpID.bytes().size(); i++)
        {
            subgroupbytes[i] = grpID.bytes()[i];
        }
        for (unsigned int j = 0; j < postfix.size(); j++, i++)
        {
            subgroupbytes[i] = postfix[j];
        }
        CGroupTokenID subgrpID(subgroupbytes);
        return EncodeGroupToken(subgrpID);
    }
    else if (operation == "authority")
    {
        LOCK(wallet->cs_wallet);
        CAmount totalBchNeeded = 0;
        CAmount totalBchAvailable = 0;
        unsigned int curparam = 1;
        std::vector<COutput> chosenCoins;
        std::vector<CRecipient> outputs;
        if (curparam >= params.size())
        {
            throw JSONRPCError(RPC_INVALID_PARAMS, "Missing parameters");
        }
        std::string suboperation;
        std::string p1 = params[curparam].get_str();
        std::transform(p1.begin(), p1.end(), std::back_inserter(suboperation), ::tolower);
        curparam++;
        if (suboperation == "create")
        {
            CGroupTokenID grpID;
            GroupAuthorityFlags auth = GroupAuthorityFlags();
            // Get the group id from the command line
            grpID = DecodeGroupToken(params[curparam].get_str());
            if (!grpID.isUserGroup())
            {
                throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid parameter: No group specified");
            }

            // Get the destination address from the command line
            curparam++;
            CTxDestination dst = DecodeDestination(params[curparam].get_str(), Params());
            if (dst == CTxDestination(CNoDestination()))
            {
                throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid parameter: destination address");
            }
            if (!std::get_if<ScriptTemplateDestination>(&dst))
            {
                throw JSONRPCError(
                    RPC_INVALID_PARAMS, "Invalid parameter: destination address must be script template");
            }

            // Get what authority permissions the user wants from the command line
            curparam++;
            if (curparam < params.size()) // If flags are not specified, error.
            {
                auth = ParseAuthorityParams(params, curparam);
                if (curparam < params.size())
                {
                    std::string strError;
                    strError = strprintf("Invalid parameter: flag %s", params[curparam].get_str());
                    throw JSONRPCError(RPC_INVALID_PARAMS, strError);
                }
            }

            if (auth == GroupAuthorityFlags())
            {
                throw JSONRPCError(RPC_INVALID_PARAMS, "no authority flags specified");
            }

            // Now find a compatible authority
            std::vector<COutput> coins;
            int nOptions = wallet->FilterCoins(coins,
                [auth, grpID](const COutput &coin)
                {
                    CGroupTokenInfo tg(coin.GetScriptPubKey());
                    if ((tg.associatedGroup == grpID) && tg.isAuthority() && tg.allowsRenew())
                    {
                        // does this authority have at least the needed bits set?
                        if ((tg.controllingGroupFlags & auth) == auth)
                            return true;
                    }
                    return false;
                });

            // if its a subgroup look for a parent authority that will work
            if ((nOptions == 0) && (grpID.isSubgroup()))
            {
                // if its a subgroup look for a parent authority that will work
                nOptions = wallet->FilterCoins(coins,
                    [auth, grpID](const COutput &coin)
                    {
                        CGroupTokenInfo tg(coin.GetScriptPubKey());
                        if (tg.isAuthority() && tg.allowsRenew() && tg.allowsSubgroup() &&
                            (tg.associatedGroup == grpID.parentGroup()))
                        {
                            if ((tg.controllingGroupFlags & auth) == auth)
                                return true;
                        }
                        return false;
                    });
            }

            if (nOptions == 0) // TODO: look for multiple authorities that can be combined to form the required bits
            {
                throw JSONRPCError(RPC_INVALID_PARAMS, "No authority exists that can grant the requested priviledges.");
            }
            else
            {
                // Just pick the first compatible authority.
                for (auto coin : coins)
                {
                    totalBchAvailable += coin.tx->vout[coin.i].nValue;
                    chosenCoins.push_back(coin);
                    break;
                }
            }

            CReserveKey renewAuthorityKey(wallet);
            totalBchNeeded += RenewAuthority(chosenCoins[0], outputs, renewAuthorityKey);

            { // Construct the new authority
                CScript script = GetScriptForDestination(dst, grpID, (CAmount)auth);
                CRecipient recipient = {script, GROUPED_SATOSHI_AMT, false};
                outputs.push_back(recipient);
                totalBchNeeded += GROUPED_SATOSHI_AMT;
            }

            CWalletTx wtx;
            ConstructTx(wtx, chosenCoins, outputs, totalBchAvailable, totalBchNeeded, 0, 0, grpID, wallet);
            renewAuthorityKey.KeepKey();
            return wtx.GetIdem().GetHex();
        }
    }
    else if (operation == "new")
    {
        LOCK(wallet->cs_wallet);
        unsigned int curparam = 1;

        COutput coin;
        {
            std::vector<COutput> coins;
            CAmount lowest = MAX_MONEY;
            wallet->FilterCoins(coins,
                [&lowest](const COutput &tcoin)
                {
                    CGroupTokenInfo tg(tcoin.GetScriptPubKey());
                    // although its possible to spend a grouped input to produce
                    // a single mint group, I won't allow it to make the tx construction easier.
                    if ((tg.associatedGroup == NoGroup) && (tcoin.GetValue() < lowest))
                    {
                        lowest = tcoin.GetValue();
                        return true;
                    }
                    return false;
                });

            if (0 == coins.size())
            {
                throw JSONRPCError(RPC_INVALID_PARAMS, "No coins available in the wallet");
            }
            coin = coins[coins.size() - 1];
        }

        uint64_t grpNonce = 0;

        std::vector<COutput> chosenCoins;
        chosenCoins.push_back(coin);

        std::vector<CRecipient> outputs;

        CReserveKey authKeyReservation(wallet);
        CTxDestination authDest;
        CScript opretScript;
        if (curparam >= params.size())
        {
            CPubKey authKey;
            authKeyReservation.GetReservedKey(authKey);
            authDest = ScriptTemplateDestination(P2pktOutput(authKey));
        }
        else
        {
            authDest = DecodeDestination(params[curparam].get_str(), Params());
            if (authDest == CTxDestination(CNoDestination()))
            {
                CPubKey authKey;
                authKeyReservation.GetReservedKey(authKey);
                authDest = ScriptTemplateDestination(P2pktOutput(authKey));
            }
            else
            {
                curparam++;
            }

            // If token description info is supplied then parse it and create an OP_RETURN output.  Otherwise
            // do not create an OP_RETURN output
            if (curparam < params.size())
            {
                auto desc = ParseGroupDescParams(params, curparam);
                if (desc.size()) // Add an op_return if there's a token desc doc
                {
                    opretScript = BuildTokenDescScript(desc);
                    outputs.push_back(CRecipient{opretScript, 0, false});
                }
            }
        }

        CAmount totalNeeded = 0;
        CGroupTokenID grpID = findGroupId(
            coin.GetOutPoint(), opretScript, GroupTokenIdFlags::NONE, GroupAuthorityFlags::ACTIVE_FLAG_BITS, grpNonce);

        CScript script =
            GetScriptForDestination(authDest, grpID, (CAmount)GroupAuthorityFlags::ACTIVE_FLAG_BITS | grpNonce);
        if (script.size() == 0)
            throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid destination address (not a script template)");
        CRecipient recipient = {script, GROUPED_SATOSHI_AMT, false};
        outputs.push_back(recipient);
        totalNeeded += recipient.nAmount;

        CWalletTx wtx;
        ConstructTx(wtx, chosenCoins, outputs, coin.GetValue(), totalNeeded, 0, 0, grpID, wallet);
        authKeyReservation.KeepKey();
        UniValue ret(UniValue::VOBJ);
        ret.pushKV("groupIdentifier", EncodeGroupToken(grpID));
        ret.pushKV("transaction", wtx.GetIdem().GetHex());
        auto spentScript = chosenCoins[0].GetScriptPubKey();
        txnouttype whichType;
        std::vector<std::vector<unsigned char> > solutionsRet;
        // Need to solve for the coin I used to extract the pubkey so I can tell the creator what address to
        // use to sign coins
        std::string addr;
        if (Solver(spentScript, whichType, solutionsRet))
        {
            if (whichType == TX_PUBKEYHASH)
            {
                addr = EncodeCashAddr(solutionsRet[0], CashAddrType::PUBKEY_TYPE, Params());
            }
            else if (whichType == TX_SCRIPT_TEMPLATE)
            {
                CScript ug = UngroupedScriptTemplate(spentScript);
                ScriptTemplateDestination d(ug);
                addr = EncodeDestination(d);
            }
            ret.pushKV("tokenDescriptorSigningAddress", addr);
        }
        return ret;
    }


    else if (operation == "mint")
    {
        LOCK(wallet->cs_wallet); // because I am reserving UTXOs for use in a tx
        CGroupTokenID grpID;
        CAmount totalTokensNeeded = 0;
        CAmount totalBchNeeded = 0; // for the mint destination output
        unsigned int curparam = 1;
        std::vector<CRecipient> outputs;
        // Get data from the parameter line. this fills grpId and adds 1 output for the correct # of tokens
        curparam = ParseGroupAddrValue(params, curparam, grpID, outputs, totalTokensNeeded, true);

        if (outputs.empty())
        {
            throw JSONRPCError(RPC_INVALID_PARAMS, "No destination address or payment amount");
        }
        if (curparam != params.size())
        {
            throw JSONRPCError(RPC_INVALID_PARAMS, "Improper number of parameters, did you forget the payment amount?");
        }

        // Account for the satoshi dust for each token output
        for (auto &out : outputs)
            totalBchNeeded += out.nAmount;

        CCoinControl coinControl;
        coinControl.fAllowOtherInputs = true; // Allow a normal nexa input for change
        std::string strError;

        // Now find a mint authority
        std::vector<COutput> coins;
        int nOptions = wallet->FilterCoins(coins,
            [grpID](const COutput &coin)
            {
                CGroupTokenInfo tg(coin.GetScriptPubKey());
                if ((tg.associatedGroup == grpID) && tg.allowsMint())
                {
                    return true;
                }
                return false;
            });

        // if its a subgroup look for a parent authority that will work
        // As an idiot-proofing step, we only allow parent authorities that can be renewed, but that is a
        // preference coded in this wallet, not a group token requirement.
        if ((nOptions == 0) && (grpID.isSubgroup()))
        {
            // if its a subgroup look for a parent authority that will work
            nOptions = wallet->FilterCoins(coins,
                [grpID](const COutput &coin)
                {
                    CGroupTokenInfo tg(coin.GetScriptPubKey());
                    if (tg.isAuthority() && tg.allowsRenew() && tg.allowsSubgroup() && tg.allowsMint() &&
                        (tg.associatedGroup == grpID.parentGroup()))
                    {
                        return true;
                    }
                    return false;
                });
        }

        if (nOptions == 0)
        {
            strError = strprintf("To mint coins, an authority output with mint capability is needed.");
            throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, strError);
        }
        CAmount totalBchAvailable = 0;
        COutput authority;

        // Just pick the first one for now.
        for (auto coin : coins)
        {
            totalBchAvailable += coin.tx->vout[coin.i].nValue;
            authority = coin;
            break;
        }

        std::vector<COutput> chosenCoins;
        chosenCoins.push_back(authority);

        CReserveKey childAuthorityKey(wallet);
        totalBchNeeded += RenewAuthority(authority, outputs, childAuthorityKey);

        CWalletTx wtx;
        // I don't "need" tokens even though they are in the output because I'm minting, which is why
        // the token quantities are 0
        ConstructTx(wtx, chosenCoins, outputs, totalBchAvailable, totalBchNeeded, 0, 0, grpID, wallet);
        childAuthorityKey.KeepKey();
        return wtx.GetIdem().GetHex();
    }
    else if (operation == "info")
    {
        if (params.size() >= 3)
        {
            throw std::runtime_error("Invalid number of arguments for token info");
        }

        if (params.size() > 0 && params.size() <= 2)
        {
            CGroupTokenID grpID;
            if (params.size() == 2)
            {
                grpID = DecodeGroupToken(params[1].get_str());
                if (!grpID.isUserGroup())
                {
                    throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid parameter 1: No group specified");
                }
            }

            std::unordered_map<CGroupTokenID, std::vector<std::string> > desc;
            GetAllGroupDescriptions(wallet, desc, grpID);

            std::vector<COutput> coins;
            std::unordered_map<CGroupTokenID, CAmount> balances;
            wallet->FilterCoins(coins,
                [&balances](const COutput &coin)
                {
                    CGroupTokenInfo tg(coin.GetScriptPubKey());
                    if (tg.associatedGroup != NoGroup && !tg.isAuthority())
                    {
                        if (tg.quantity > std::numeric_limits<CAmount>::max() - balances[tg.associatedGroup])
                            balances[tg.associatedGroup] = std::numeric_limits<CAmount>::max();
                        else
                            balances[tg.associatedGroup] += tg.quantity;
                    }
                    return false; // I don't want to actually filter anything
                });

            UniValue ret(UniValue::VOBJ);
            for (const auto &item : desc)
            {
                UniValue entry(UniValue::VOBJ);
                if (desc[item.first].size() >= 4)
                {
                    entry.pushKV("name", desc[item.first][0]);
                    entry.pushKV("ticker", desc[item.first][1]);
                    entry.pushKV("url", desc[item.first][2]);

                    std::string s = desc[item.first][3];
                    if (s.size() != 32)
                    {
                        entry.pushKV("hash", "");
                    }
                    else
                    {
                        std::vector<unsigned char> vHash(s.begin(), s.end());
                        uint256 dochash(vHash);
                        if (!dochash.IsNull())
                            entry.pushKV("hash", dochash.ToString());
                    }
                }

                if (balances.count(item.first))
                    entry.pushKV("balance", balances[item.first]);
                else
                    entry.pushKV("balance", "0");

                ret.pushKV(EncodeGroupToken(item.first), entry);
            }
            return ret;
        }
    }
    else if (operation == "balance")
    {
        if (params.size() > 3)
        {
            throw std::runtime_error("Invalid number of argument to token balance");
        }
        if (params.size() == 1) // no group specified, show them all
        {
            std::unordered_map<CGroupTokenID, CAmount> balances;
            GetAllGroupBalances(wallet, balances);
            UniValue ret(UniValue::VOBJ);
            for (const auto &item : balances)
            {
                ret.pushKV(EncodeGroupToken(item.first), item.second);
            }
            return ret;
        }
        CGroupTokenID grpID = DecodeGroupToken(params[1].get_str());
        if (!grpID.isUserGroup())
        {
            throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid parameter 1: No group specified");
        }
        CTxDestination dst;
        if (params.size() > 2)
        {
            dst = DecodeDestination(params[2].get_str(), Params());
        }
        return UniValue(GetGroupBalance(grpID, dst, wallet));
    }
    else if (operation == "send")
    {
        CGroupTokenID grpID;
        CAmount totalTokensNeeded = 0;
        unsigned int curparam = 1;
        std::vector<CRecipient> outputs;
        curparam = ParseGroupAddrValue(params, curparam, grpID, outputs, totalTokensNeeded, true);

        if (outputs.empty())
        {
            throw JSONRPCError(RPC_INVALID_PARAMS, "No destination address or payment amount");
        }
        if (curparam != params.size())
        {
            throw JSONRPCError(RPC_INVALID_PARAMS, "Improper number of parameters, did you forget the payment amount?");
        }
        CWalletTx wtx;
        GroupSend(wtx, grpID, outputs, totalTokensNeeded, wallet);
        return wtx.GetIdem().GetHex();
    }
    else if (operation == "melt")
    {
        CGroupTokenID grpID;
        std::vector<CRecipient> outputs;

        grpID = DecodeGroupToken(params[1].get_str());
        if (!grpID.isUserGroup())
        {
            throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid parameter: No group specified");
        }

        CAmount totalNeeded = AmountFromIntegralValue(params[2]);

        CWalletTx wtx;
        GroupMelt(wtx, grpID, totalNeeded, wallet);
        return wtx.GetIdem().GetHex();
    }
    else
    {
        throw JSONRPCError(RPC_INVALID_REQUEST, "Unknown group operation");
    }
    return NullUniValue;
}


extern void WalletTxToJSON(const CWalletTx &wtx, UniValue &entry);
using namespace std;

static void MaybePushAddress(UniValue &entry, const CTxDestination &dest)
{
    if (IsValidDestination(dest))
    {
        entry.pushKV("address", EncodeDestination(dest));
    }
}

static void AcentryToJSON(const CAccountingEntry &acentry, const string &strAccount, UniValue &ret)
{
    bool fAllAccounts = (strAccount == string("*"));

    if (fAllAccounts || acentry.strAccount == strAccount)
    {
        UniValue entry(UniValue::VOBJ);
        entry.pushKV("account", acentry.strAccount);
        entry.pushKV("category", "move");
        entry.pushKV("time", acentry.nTime);
        entry.pushKV("amount", UniValue(acentry.nCreditDebit));
        entry.pushKV("otheraccount", acentry.strOtherAccount);
        entry.pushKV("comment", acentry.strComment);
        ret.push_back(entry);
    }
}

void ListGroupedTransactions(const CGroupTokenID &grp,
    const CWalletTx &wtx,
    const string &strAccount,
    int nMinDepth,
    bool fLong,
    UniValue &ret,
    const isminefilter &filter)
{
    CAmount nFee;
    string strSentAccount;
    list<COutputEntry> listReceived;
    list<COutputEntry> listSent;

    wtx.GetGroupAmounts(grp, listReceived, listSent, nFee, strSentAccount, filter);

    bool fAllAccounts = (strAccount == string("*"));
    bool involvesWatchonly = wtx.IsFromMe(ISMINE_WATCH_ONLY);

    // Sent
    if ((!listSent.empty() || nFee != 0) && (fAllAccounts || strAccount == strSentAccount))
    {
        for (const COutputEntry &s : listSent)
        {
            UniValue entry(UniValue::VOBJ);
            if (involvesWatchonly || (::IsMine(*pwalletMain, s.destination, chainActive.Tip()) & ISMINE_WATCH_ONLY))
                entry.pushKV("involvesWatchonly", true);
            entry.pushKV("account", strSentAccount);
            MaybePushAddress(entry, s.destination);
            entry.pushKV("category", "send");
            entry.pushKV("group", EncodeGroupToken(grp));
            entry.pushKV("amount", UniValue(-s.amount));
            if (pwalletMain->mapAddressBook.count(s.destination))
                entry.pushKV("label", pwalletMain->mapAddressBook[s.destination].name);
            entry.pushKV("vout", s.vout);
            entry.pushKV("fee", ValueFromAmount(-nFee));
            if (fLong)
                WalletTxToJSON(wtx, entry);
            entry.pushKV("abandoned", wtx.isAbandoned());
            ret.push_back(entry);
        }
    }

    // Received
    if (listReceived.size() > 0 && wtx.GetDepthInMainChain() >= nMinDepth)
    {
        for (const COutputEntry &r : listReceived)
        {
            string account;
            if (pwalletMain->mapAddressBook.count(r.destination))
                account = pwalletMain->mapAddressBook[r.destination].name;
            if (fAllAccounts || (account == strAccount))
            {
                UniValue entry(UniValue::VOBJ);
                if (involvesWatchonly || (::IsMine(*pwalletMain, r.destination, chainActive.Tip()) & ISMINE_WATCH_ONLY))
                    entry.pushKV("involvesWatchonly", true);
                entry.pushKV("account", account);
                MaybePushAddress(entry, r.destination);
                if (wtx.IsCoinBase())
                {
                    if (wtx.GetDepthInMainChain() < 1)
                        entry.pushKV("category", "orphan");
                    else if (wtx.GetBlocksToMaturity() > 0)
                        entry.pushKV("category", "immature");
                    else
                        entry.pushKV("category", "generate");
                }
                else
                {
                    entry.pushKV("category", "receive");
                }
                entry.pushKV("amount", UniValue(r.amount));
                entry.pushKV("group", EncodeGroupToken(grp));
                if (pwalletMain->mapAddressBook.count(r.destination))
                    entry.pushKV("label", account);
                entry.pushKV("vout", r.vout);
                if (fLong)
                    WalletTxToJSON(wtx, entry);
                ret.push_back(entry);
            }
        }
    }
}

UniValue groupedlisttransactions(const UniValue &params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() > 6)
        throw runtime_error(
            "listtransactions ( \"account\" count from includeWatchonly)\n"
            "\nReturns up to 'count' most recent transactions skipping the first 'from' transactions for account "
            "'account'.\n"
            "\nArguments:\n"
            "1. \"account\"    (string, optional) DEPRECATED. The account name. Should be \"*\".\n"
            "2. count          (numeric, optional, default=10) The number of transactions to return\n"
            "3. from           (numeric, optional, default=0) The number of transactions to skip\n"
            "4. includeWatchonly (bool, optional, default=false) Include transactions to watchonly addresses (see "
            "'importaddress')\n"
            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"account\":\"accountname\",       (string) DEPRECATED. The account name associated with the "
            "transaction. \n"
            "                                                It will be \"\" for the default account.\n"
            "    \"address\":\"nexaaddress\",       (string) The nexa address of the transaction. Not present for \n"
            "                                                move transactions (category = move).\n"
            "    \"category\":\"send|receive|move\", (string) The transaction category. 'move' is a local (off "
            "blockchain)\n"
            "                                                transaction between accounts, and not associated with an "
            "address,\n"
            "                                                transaction id or block. 'send' and 'receive' "
            "transactions are \n"
            "                                                associated with an address, transaction id and block "
            "details\n"
            "    \"amount\": x.xxx,          (numeric) The amount in " +
            CURRENCY_UNIT +
            ". This is negative for the 'send' category, and for the\n"
            "                                         'move' category for moves outbound. It is "
            "positive for the 'receive' category,\n"
            "                                         and for the 'move' category for inbound funds.\n"
            "    \"vout\": n,                (numeric) the vout value\n"
            "    \"fee\": x.xxx,             (numeric) The amount of the fee in " +
            CURRENCY_UNIT +
            ". This is negative and only available for the \n"
            "                                         'send' category of transactions.\n"
            "    \"confirmations\": n,       (numeric) The number of confirmations for the transaction. Available for "
            "'send' and \n"
            "                                         'receive' category of transactions. Negative confirmations "
            "indicate the\n"
            "                                         transaction conflicts with the block chain\n"
            "    \"trusted\": xxx            (bool) Whether we consider the outputs of this unconfirmed transaction "
            "safe to spend.\n"
            "    \"blockhash\": \"hashvalue\", (string) The block hash containing the transaction. Available for "
            "'send' and 'receive'\n"
            "                                          category of transactions.\n"
            "    \"blockindex\": n,          (numeric) The index of the transaction in the block that includes it. "
            "Available for 'send' and 'receive'\n"
            "                                          category of transactions.\n"
            "    \"blocktime\": xxx,         (numeric) The block time in seconds since epoch (1 Jan 1970 GMT).\n"
            "    \"txid\": \"transactionid\", (string) The transaction id. Available for 'send' and 'receive' category "
            "of transactions.\n"
            "    \"time\": xxx,              (numeric) The transaction time in seconds since epoch (midnight Jan 1 "
            "1970 GMT).\n"
            "    \"timereceived\": xxx,      (numeric) The time received in seconds since epoch (midnight Jan 1 1970 "
            "GMT). Available \n"
            "                                          for 'send' and 'receive' category of transactions.\n"
            "    \"comment\": \"...\",       (string) If a comment is associated with the transaction.\n"
            "    \"label\": \"label\"        (string) A comment for the address/transaction, if any\n"
            "    \"otheraccount\": \"accountname\",  (string) For the 'move' category of transactions, the account the "
            "funds came \n"
            "                                          from (for receiving funds, positive amounts), or went to (for "
            "sending funds,\n"
            "                                          negative amounts).\n"
            "    \"abandoned\": xxx          (bool) 'true' if the transaction has been abandoned (inputs are "
            "respendable). Only available for the \n"
            "                                         'send' category of transactions.\n"
            "  }\n"
            "]\n"

            "\nExamples:\n"
            "\nList the most recent 10 transactions in the systems\n" +
            HelpExampleCli("listtransactions", "") + "\nList transactions 100 to 120\n" +
            HelpExampleCli("listtransactions", "\"*\" 20 100") + "\nAs a json rpc call\n" +
            HelpExampleRpc("listtransactions", "\"*\", 20, 100"));

    LOCK(pwalletMain->cs_wallet);

    string strAccount = "*";

    if (params.size() == 1)
    {
        throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid parameter: No group specified");
    }
    CGroupTokenID grpID = DecodeGroupToken(params[1].get_str());
    if (!grpID.isUserGroup())
    {
        throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid parameter: No group specified");
    }

    if (params.size() > 2)
        strAccount = params[2].get_str();
    int nCount = 10;
    if (params.size() > 3)
        nCount = params[3].get_int();
    int nFrom = 0;
    if (params.size() > 4)
        nFrom = params[4].get_int();
    isminefilter filter = ISMINE_SPENDABLE;
    if (params.size() > 5)
        if (params[5].get_bool())
            filter = filter | ISMINE_WATCH_ONLY;

    if (nCount < 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative count");
    if (nFrom < 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative from");

    UniValue ret(UniValue::VARR);

    const CWallet::TxItems &txOrdered = pwalletMain->wtxOrdered;

    // iterate backwards until we have nCount items to return:
    for (CWallet::TxItems::const_reverse_iterator it = txOrdered.rbegin(); it != txOrdered.rend(); ++it)
    {
        CWalletTxRef pwtx = (*it).second.first;
        if (pwtx != nullptr)
            ListGroupedTransactions(grpID, *pwtx, strAccount, 0, true, ret, filter);
        CAccountingEntry *const pacentry = (*it).second.second;
        if (pacentry != 0)
            AcentryToJSON(*pacentry, strAccount, ret);

        if ((int)ret.size() >= (nCount + nFrom))
            break;
    }
    // ret is newest to oldest

    if (nFrom > (int)ret.size())
        nFrom = ret.size();
    if ((nFrom + nCount) > (int)ret.size())
        nCount = ret.size() - nFrom;

    vector<UniValue> arrTmp = ret.getValues();

    vector<UniValue>::iterator first = arrTmp.begin();
    std::advance(first, nFrom);
    vector<UniValue>::iterator last = arrTmp.begin();
    std::advance(last, nFrom + nCount);

    if (last != arrTmp.end())
        arrTmp.erase(last, arrTmp.end());
    if (first != arrTmp.begin())
        arrTmp.erase(arrTmp.begin(), first);

    std::reverse(arrTmp.begin(), arrTmp.end()); // Return oldest to newest

    ret.clear();
    ret.setArray();
    ret.push_backV(arrTmp);

    return ret;
}

UniValue groupedlistsinceblock(const UniValue &params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp)
        throw runtime_error(
            "token listsinceblock ( groupid \"blockhash\" target-confirmations includeWatchonly)\n"
            "\nGet all transactions in blocks since block [blockhash], or all transactions if omitted\n"
            "\nArguments:\n"
            "1. groupid (string, required) List transactions containing this group only\n"
            "2. \"blockhash\"   (string, optional) The block hash to list transactions since\n"
            "3. target-confirmations:    (numeric, optional) The confirmations required, must be 1 or more\n"
            "4. includeWatchonly:        (bool, optional, default=false) Include transactions to watchonly addresses "
            "(see 'importaddress')"
            "\nResult:\n"
            "{\n"
            "  \"transactions\": [\n"
            "    \"account\":\"accountname\",       (string) DEPRECATED. The account name associated with the "
            "transaction. Will be \"\" for the default account.\n"
            "    \"address\":\"nexaaddress\",       (string) The nexa address of the transaction. Not present for "
            "move transactions (category = move).\n"
            "    \"category\":\"send|receive\",     (string) The transaction category. 'send' has negative amounts, "
            "'receive' has positive amounts.\n"
            "    \"amount\": x.xxx,          (numeric) The amount in " +
            CURRENCY_UNIT +
            ". This is negative for the 'send' category, and for the 'move' category for moves \n"
            "                                          outbound. It is positive for the 'receive' "
            "category, and for the 'move' category for inbound funds.\n"
            "    \"vout\" : n,               (numeric) the vout value\n"
            "    \"fee\": x.xxx,             (numeric) The amount of the fee in " +
            CURRENCY_UNIT +
            ". This is negative and only available for the 'send' category of transactions.\n"
            "    \"confirmations\": n,       (numeric) The number of confirmations for the transaction. Available for "
            "'send' and 'receive' category of transactions.\n"
            "    \"blockhash\": \"hashvalue\",     (string) The block hash containing the transaction. Available for "
            "'send' and 'receive' category of transactions.\n"
            "    \"blockindex\": n,          (numeric) The index of the transaction in the block that includes it. "
            "Available for 'send' and 'receive' category of transactions.\n"
            "    \"blocktime\": xxx,         (numeric) The block time in seconds since epoch (1 Jan 1970 GMT).\n"
            "    \"txid\": \"transactionid\",  (string) The transaction id. Available for 'send' and 'receive' "
            "category of transactions.\n"
            "    \"time\": xxx,              (numeric) The transaction time in seconds since epoch (Jan 1 1970 GMT).\n"
            "    \"timereceived\": xxx,      (numeric) The time received in seconds since epoch (Jan 1 1970 GMT). "
            "Available for 'send' and 'receive' category of transactions.\n"
            "    \"abandoned\": xxx,         (bool) 'true' if the transaction has been abandoned (inputs are "
            "respendable). Only available for the 'send' category of transactions.\n"
            "    \"comment\": \"...\",       (string) If a comment is associated with the transaction.\n"
            "    \"label\" : \"label\"       (string) A comment for the address/transaction, if any\n"
            "    \"to\": \"...\",            (string) If a comment to is associated with the transaction.\n"
            "  ],\n"
            "  \"lastblock\": \"lastblockhash\"     (string) The hash of the last block\n"
            "}\n"
            "\nExamples:\n" +
            HelpExampleCli("listsinceblock", "") +
            HelpExampleCli("listsinceblock", "\"000000000000000bacf66f7497b7dc45ef753ee9a7d38571037cdb1a57f663ad\" 6") +
            HelpExampleRpc(
                "listsinceblock", "\"000000000000000bacf66f7497b7dc45ef753ee9a7d38571037cdb1a57f663ad\", 6"));

    LOCK(pwalletMain->cs_wallet);

    CBlockIndex *pindex = NULL;
    int target_confirms = 1;
    isminefilter filter = ISMINE_SPENDABLE;

    if (params.size() == 1)
    {
        throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid parameter: No group specified");
    }
    CGroupTokenID grpID = DecodeGroupToken(params[1].get_str());
    if (!grpID.isUserGroup())
    {
        throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid parameter: No group specified");
    }

    if (params.size() > 2)
    {
        uint256 blockId;

        blockId.SetHex(params[2].get_str());
        BlockMap::iterator it = mapBlockIndex.find(blockId);
        if (it != mapBlockIndex.end())
            pindex = it->second;
    }

    if (params.size() > 3)
    {
        target_confirms = std::stoul(params[3].get_str());

        if (target_confirms < 1)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter");
    }

    if (params.size() > 4)
        if (InterpretBool(params[4].get_str()))
            filter = filter | ISMINE_WATCH_ONLY;

    int depth = pindex ? (1 + chainActive.Height() - pindex->height()) : -1;

    UniValue transactions(UniValue::VARR);

    for (MapWallet::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); it++)
    {
        CWalletTxRef tx = (*it).second.tx;

        if (depth == -1 || tx->GetDepthInMainChain() < depth)
            ListGroupedTransactions(grpID, *tx, "*", 0, true, transactions, filter);
    }

    CBlockIndex *pblockLast = chainActive[chainActive.Height() + 1 - target_confirms];
    uint256 lastblock = pblockLast ? pblockLast->GetBlockHash() : uint256();

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("transactions", transactions);
    ret.pushKV("lastblock", lastblock.GetHex());

    return ret;
}
