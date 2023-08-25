// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_KEYSTORE_H
#define NEXA_KEYSTORE_H

#include "key.h"
#include "pubkey.h"
#include "script/ismine.h"
#include "script/script.h"
#include "script/standard.h"
#include "sync.h"

class BaseSignatureCreator;

/** A virtual base class defining how to spend some output.
    Store ONLY Pubkeys in derived classes, and look up the associated CKey when needed.
    This allows the normal keystore logic to also work for crypted keystores.
 */
class Spendable
{
public:
    /** Generate the input script that will spend this output, given something capable of signing */
    virtual CScript SpendScript(const BaseSignatureCreator &creator) const = 0;
    /** Return a list of the pubkeys required to spend this output */
    virtual std::vector<CPubKey> PubKeys() const = 0;
    /** Return whether we can solve or spend this or not */
    virtual isminetype IsMine() const = 0;
    virtual ~Spendable() = 0;
};

/** A virtual base class for key stores */
class CKeyStore
{
public:
    /** This lock only needs to be explicitly taken by the caller if lock-free functions are called.  All lock-free
        functions are preceded by an _.  In general, use the locking functions.  Only use the lock-free functions
        for optimization of loops by factoring the lock out of the loop and calling the lock-free function in the loop.
    */
    mutable CCriticalSection cs_KeyStore;

    virtual ~CKeyStore() {}
    //! Add a key to the store.
    virtual bool AddKeyPubKey(const CKey &key, const CPubKey &pubkey) = 0;
    virtual bool AddKey(const CKey &key);

    //! Check whether a key corresponding to a given address is present in the store.
    virtual bool HaveKey(const CKeyID &address) const = 0;
    //! Check whether a key corresponding to a given address is present in the store, caller must hold cs_KeyStore
    virtual bool _HaveKey(const CKeyID &address) const = 0;

    virtual bool GetKey(const CTxDestination &dest, CKey &keyOut) const = 0;
    virtual bool GetKey(const CKeyID &address, CKey &keyOut) const = 0;
    virtual void GetKeys(std::set<CKeyID> &setAddress) const = 0;
    virtual bool GetPubKey(const CKeyID &address, CPubKey &vchPubKeyOut) const = 0;

    //! Support for BIP 0013 : see https://github.com/bitcoin/bips/blob/master/bip-0013.mediawiki
    virtual bool AddCScript(const CScript &redeemScript) = 0;
    virtual bool HaveCScript(const CScriptID &hash) const = 0;
    virtual bool GetCScript(const CScriptID &hash, CScript &redeemScriptOut) const = 0;

    virtual isminetype HaveTemplate(const CScript &output) const = 0;
    virtual const Spendable *_GetTemplate(const CScript &output) const = 0;

    //! Support for Watch-only addresses
    virtual bool AddWatchOnly(const CScript &dest) = 0;
    virtual bool RemoveWatchOnly(const CScript &dest) = 0;
    virtual bool HaveWatchOnly(const CScript &dest) const = 0;
    virtual bool HaveWatchOnly() const = 0;

    class CheckTxDestination
    {
        const CKeyStore *keystore;

    public:
        CheckTxDestination(const CKeyStore *_keystore) : keystore(_keystore) {}
        bool operator()(const CKeyID &id) const { return keystore->HaveKey(id); }
        bool operator()(const CScriptID &id) const { return keystore->HaveCScript(id); }
        bool operator()(const CNoDestination &) const { return false; }
        bool operator()(const ScriptTemplateDestination &id) const
        {
            // Whether grouped or not does not affect spendability
            CScript output = id.toScript();
            // any group is stripped from output inside HaveTemplate (_GetTemplate)
            return keystore->HaveTemplate(output);
        }
    };

    virtual bool HaveTxDestination(const CTxDestination &addr) { return std::visit(CheckTxDestination(this), addr); }
};

/** How to spend any pay-to-public-key-template output */
class SpendableP2PKT : public Spendable
{
    // Don't hold the private key so this works for crypted or non-crypted wallets.
    // You can look up the private key from this public key when needed if the wallet is unlocked...
    CKeyStore *keystore;
    const CPubKey pubkey;

public:
    SpendableP2PKT(const CPubKey &_pubkey, CKeyStore *_keystore) : keystore(_keystore), pubkey(_pubkey) {}
    /** Generate the input script that will spend this output, given something capable of signing */
    virtual CScript SpendScript(const BaseSignatureCreator &creator) const;
    /** Return the list of pubkeys that are involved in this destination (if any) */
    virtual std::vector<CPubKey> PubKeys() const;
    /** Return whether we can solve or spend this or not */
    virtual isminetype IsMine() const;

    virtual ~SpendableP2PKT();
};


typedef std::map<CKeyID, CKey> KeyMap;
typedef std::map<CKeyID, CPubKey> WatchKeyMap;
typedef std::map<CScriptID, CScript> ScriptMap;
typedef std::map<CScript, Spendable *> TemplateScriptMap;

typedef std::set<CScript> WatchOnlySet;

/** Basic key store, that keeps keys in an address->secret map */
class CBasicKeyStore : public CKeyStore
{
protected:
    KeyMap mapKeys GUARDED_BY(cs_KeyStore);
    WatchKeyMap mapWatchKeys GUARDED_BY(cs_KeyStore);
    ScriptMap mapScripts GUARDED_BY(cs_KeyStore);
    TemplateScriptMap mapTemplates GUARDED_BY(cs_KeyStore);
    WatchOnlySet setWatchOnly GUARDED_BY(cs_KeyStore);

public:
    ~CBasicKeyStore();
    bool AddKeyPubKey(const CKey &key, const CPubKey &pubkey);
    bool GetPubKey(const CKeyID &address, CPubKey &vchPubKeyOut) const;
    bool HaveKey(const CKeyID &address) const
    {
        bool result;
        {
            LOCK(cs_KeyStore);
            result = (mapKeys.count(address) > 0);
        }
        return result;
    }

    bool _HaveKey(const CKeyID &address) const
    {
        AssertLockHeld(cs_KeyStore);
        return (mapKeys.count(address) > 0);
    }

    void GetKeys(std::set<CKeyID> &setAddress) const
    {
        setAddress.clear();
        {
            LOCK(cs_KeyStore);
            KeyMap::const_iterator mi = mapKeys.begin();
            while (mi != mapKeys.end())
            {
                setAddress.insert((*mi).first);
                mi++;
            }
        }
    }

    bool GetPubKey(const ScriptTemplateDestination &address, CPubKey &keyOut) const;

    bool GetKey(const CKeyID &address, CKey &keyOut) const
    {
        {
            LOCK(cs_KeyStore);
            KeyMap::const_iterator mi = mapKeys.find(address);
            if (mi != mapKeys.end())
            {
                keyOut = CKey(mi->second);
                return true;
            }
        }
        return false;
    }

    bool GetKey(const CTxDestination &dest, CKey &keyOut) const;

    virtual bool AddCScript(const CScript &redeemScript);
    virtual bool HaveCScript(const CScriptID &hash) const;
    virtual bool GetCScript(const CScriptID &hash, CScript &redeemScriptOut) const;

    virtual isminetype HaveTemplate(const CScript &output) const;
    virtual const Spendable *_GetTemplate(const CScript &output) const;

    virtual bool AddWatchOnly(const CScript &dest);
    virtual bool RemoveWatchOnly(const CScript &dest);
    virtual bool HaveWatchOnly(const CScript &dest) const;
    virtual bool HaveWatchOnly() const;
};

typedef std::vector<unsigned char, secure_allocator<unsigned char> > CKeyingMaterial;
typedef std::map<CKeyID, std::pair<CPubKey, std::vector<unsigned char> > > CryptedKeyMap;

#endif // NEXA_KEYSTORE_H
