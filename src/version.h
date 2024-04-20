// Copyright (c) 2012-2014 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_VERSION_H
#define NEXA_VERSION_H

/**
 * network protocol versioning
 */

static const int PROTOCOL_VERSION = 80005;

//! initial proto version, to be increased after version/verack negotiation
static const int INIT_PROTO_VERSION = 80003;

//! disconnect from peers older than this proto version
static const int MIN_PEER_PROTO_VERSION = 80003;

#endif // NEXA_VERSION_H
