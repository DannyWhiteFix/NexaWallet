// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2023 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_INIT_H
#define NEXA_INIT_H

#include "threadgroup.h"
#include "tweak.h"
#include <string>

class Config;

void StartShutdown();
bool ShutdownRequested();
/** Interrupt threads */
void Interrupt();
void Shutdown();
//! Initialize the logging infrastructure
void InitLogging();
//! Parameter interaction: change current parameters depending on various rules
void InitParameterInteraction();
bool AppInit2(Config &config);

void MainCleanup();
void NetCleanup();

static const bool DEFAULT_PROXYRANDOMIZE = true;
static const bool DEFAULT_REST_ENABLE = false;
static const bool DEFAULT_DISABLE_SAFEMODE = false;
static const bool DEFAULT_STOPAFTERBLOCKIMPORT = false;

extern CTweak<uint32_t> minRelayFee;
extern CTweak<bool> avoidReconsiderMostWorkChain;

/** Returns licensing information (for -version) */
std::string LicenseInfo();

#endif // NEXA_INIT_H
