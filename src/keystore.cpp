// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <variant>

#include "keystore.h"

#include "key.h"
#include "pubkey.h"
#include "script/sign.h"
#include "util.h"

bool CKeyStore::AddKey(const CKey &key) { return AddKeyPubKey(key, key.GetPubKey()); }
bool CBasicKeyStore::GetPubKey(const CKeyID &address, CPubKey &vchPubKeyOut) const
{
    LOCK(cs_KeyStore);
    CKey key;
    if (!GetKey(address, key))
    {
        WatchKeyMap::const_iterator it = mapWatchKeys.find(address);
        if (it != mapWatchKeys.end())
        {
            vchPubKeyOut = it->second;
            return true;
        }
        return false;
    }
    vchPubKeyOut = key.GetPubKey();
    return true;
}

bool CBasicKeyStore::AddKeyPubKey(const CKey &key, const CPubKey &pubkey)
{
    LOCK(cs_KeyStore);
    mapKeys[pubkey.GetID()] = key;
    // Add an entry for the standard pay-to-public-key-template script form.
    CScript output = P2pktOutput(pubkey);
    mapTemplates[output] = new SpendableP2PKT(pubkey, this);
    return true;
}

bool CBasicKeyStore::AddCScript(const CScript &redeemScript)
{
    LOCK(cs_KeyStore);
    mapScripts[CScriptID(redeemScript)] = redeemScript;
    return true;
}

bool CBasicKeyStore::HaveCScript(const CScriptID &hash) const
{
    LOCK(cs_KeyStore);
    return mapScripts.count(hash) > 0;
}

bool CBasicKeyStore::GetCScript(const CScriptID &hash, CScript &redeemScriptOut) const
{
    LOCK(cs_KeyStore);
    ScriptMap::const_iterator mi = mapScripts.find(hash);
    if (mi != mapScripts.end())
    {
        redeemScriptOut = (*mi).second;
        return true;
    }
    return false;
}

static bool ExtractPubKey(const CScript &dest, CPubKey &pubKeyOut)
{
    // TODO: Use Solver to extract this?
    CScript::const_iterator pc = dest.begin();
    opcodetype opcode;
    std::vector<unsigned char> vch;
    if (!dest.GetOp(pc, opcode, vch) || !CPubKey::ValidSize(vch))
        return false;
    pubKeyOut = CPubKey(vch);
    if (!pubKeyOut.IsFullyValid())
        return false;
    if (!dest.GetOp(pc, opcode, vch) || opcode != OP_CHECKSIG || dest.GetOp(pc, opcode, vch))
        return false;
    return true;
}

bool CBasicKeyStore::AddWatchOnly(const CScript &dest)
{
    LOCK(cs_KeyStore);
    setWatchOnly.insert(dest);
    CPubKey pubKey;
    if (ExtractPubKey(dest, pubKey))
        mapWatchKeys[pubKey.GetID()] = pubKey;
    return true;
}

bool CBasicKeyStore::RemoveWatchOnly(const CScript &dest)
{
    LOCK(cs_KeyStore);
    setWatchOnly.erase(dest);
    CPubKey pubKey;
    if (ExtractPubKey(dest, pubKey))
        mapWatchKeys.erase(pubKey.GetID());
    return true;
}

bool CBasicKeyStore::HaveWatchOnly(const CScript &dest) const
{
    LOCK(cs_KeyStore);
    return setWatchOnly.count(dest) > 0;
}

bool CBasicKeyStore::HaveWatchOnly() const
{
    LOCK(cs_KeyStore);
    return (!setWatchOnly.empty());
}

CBasicKeyStore::~CBasicKeyStore()
{
    LOCK(cs_KeyStore);
    for (const auto &sp : mapTemplates)
    {
        if (sp.second)
            delete sp.second;
    }
    mapTemplates.clear();
}

isminetype CBasicKeyStore::HaveTemplate(const CScript &output) const
{
    LOCK(cs_KeyStore);
    const Spendable *sp = _GetTemplate(output);
    isminetype ret = ISMINE_NO;
    if (sp)
        ret = sp->IsMine();
    if (ret == ISMINE_NO)
    {
        if (HaveWatchOnly(output))
            ret = ISMINE_WATCH_UNSOLVABLE;
    }
    return ret;
}

const Spendable *CBasicKeyStore::_GetTemplate(const CScript &output) const
{
    AssertLockHeld(cs_KeyStore);
    auto item = mapTemplates.find(output);
    if (item == mapTemplates.end())
    {
        // also check degrouped script, since grouping is irrelevant to
        // spendability.
        CScript tmp = UngroupedScriptTemplate(output);
        item = mapTemplates.find(tmp);
        if (item == mapTemplates.end())
        {
            return nullptr;
        }
    }
    return item->second;
}

bool CBasicKeyStore::GetPubKey(const ScriptTemplateDestination &address, CPubKey &pubKeyOut) const
{
    LOCK(cs_KeyStore);
    // any group is stripped from address inside _GetTemplate
    const Spendable *sp = _GetTemplate(address.toScript());
    if (!sp)
        return false;

    std::vector<CPubKey> pubs = sp->PubKeys();
    // It doesn't make much sense that 1 wallet would have N keys controlling a script but I suppose for completeness
    // this entire key extraction architecture should be expanded to capture the possibility.
    if (pubs.size() != 1)
        return false;
    pubKeyOut = pubs[0];
    return true;
}

bool CBasicKeyStore::GetKey(const CTxDestination &dest, CKey &keyOut) const
{
    const CKeyID *keyID = std::get_if<CKeyID>(&dest);
    if (keyID)
    {
        return GetKey(*keyID, keyOut);
    }
    const ScriptTemplateDestination *st = std::get_if<ScriptTemplateDestination>(&dest);
    if (st)
    {
        CPubKey pub;
        if (GetPubKey(*st, pub))
            return GetKey(pub.GetID(), keyOut);
    }
    return false;
}


Spendable::~Spendable() {}

SpendableP2PKT::~SpendableP2PKT() {}

isminetype SpendableP2PKT::IsMine() const
{
    if (pubkey.IsValid())
    {
        if (keystore && keystore->HaveKey(pubkey.GetID()))
            return ISMINE_SPENDABLE;
    }
    // We are interested in this or we would not have put it into the keystore.
    // But we don't have the private key. So its watch-only.
    // If we had the private key, we could spend it because we recognise this template as the standard p2pkt,
    // so this is a "solvable" template.
    return ISMINE_WATCH_SOLVABLE;
}

CScript SpendableP2PKT::SpendScript(const BaseSignatureCreator &creator) const
{
    CScript argsScript = CScript() << ToByteVector(pubkey);
    std::vector<unsigned char> vchSig;
    bool result = creator.CreateSig(vchSig, pubkey.GetID(), p2pkt);
    if (!result)
        return CScript();
    return (CScript() << ToByteVector(argsScript) << vchSig);
}

std::vector<CPubKey> SpendableP2PKT::PubKeys() const
{
    std::vector<CPubKey> ret;
    ret.push_back(pubkey);
    return ret;
}
