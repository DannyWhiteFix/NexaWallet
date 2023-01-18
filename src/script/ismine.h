// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_SCRIPT_ISMINE_H
#define NEXA_SCRIPT_ISMINE_H

#include <stdint.h>
#include <string>

#include "script/standard.h"

class CKeyStore;
class CScript;
class CScriptNum;
class CBlockIndex;

/** IsMine() return codes */
enum isminetype
{
    ISMINE_NO = 0,
    //! Indicates that we don't know how to create a scriptSig that would solve this if we were given the appropriate
    //! private keys
    ISMINE_WATCH_UNSOLVABLE = 1,
    //! Indicates that we know how to create a scriptSig that would solve this if we were given the appropriate private
    //! keys
    ISMINE_WATCH_SOLVABLE = 2,
    ISMINE_WATCH_ONLY = ISMINE_WATCH_SOLVABLE | ISMINE_WATCH_UNSOLVABLE,
    ISMINE_SPENDABLE = 4,
    ISMINE_ALL = ISMINE_WATCH_ONLY | ISMINE_SPENDABLE
};
/** used for bitflags of isminetype */
typedef uint8_t isminefilter;

std::string getLabelPublic(const CScript &scriptPubKey);
bool isFreezeCLTV(const CKeyStore &keystore, const CScript &scriptPubKey, CScriptNum &nFreezeLockTime); // Freeze
// bestBlock - Freeze CLTV

/** Determines if an output is spendable by this wallet
 */
isminetype IsMine(const CKeyStore &keystore, const CScript &scriptPubKey, CBlockIndex *bestBlock);

/** Determines if an output is spendable by this wallet
 */
isminetype IsMine(const CKeyStore &keystore, const CTxDestination &dest, CBlockIndex *bestBlock);

/** Determines if an output is spendable by this wallet -- lockless version (you must take cs_KeyStore)
 */
isminetype _IsMine(const CKeyStore &keystore, const CScript &scriptPubKey, CBlockIndex *bestBlock);


#endif // NEXA_SCRIPT_ISMINE_H
