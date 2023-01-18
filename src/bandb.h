// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_BANDB_H
#define NEXA_BANDB_H

#include "banentry.h" // for banmap_t

#include "fs.h"

/** Access to the banlist database (banlist.dat) */
class CBanDB
{
private:
    fs::path pathBanlist;

public:
    CBanDB();
    bool Write(const banmap_t &banSet);
    bool Read(banmap_t &banSet);

    // NOTE: Added for use in unit testing
    fs::path GetDatabasePath() const { return pathBanlist; }
};

#endif // NEXA_BANDB_H
