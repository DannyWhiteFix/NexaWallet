// Copyright (c) 2016 The Bitcoin Core developers
// Copyright (c) 2016-2021 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <iostream>

#include "bench.h"
#include "key.h"

/* Number of bytes to hash per iteration */
static const uint64_t BUFFER_SIZE = 1000 * 1000;

uint8_t vchPrivkey[32] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};

static void samePubkey(benchmark::State &state)
{
    ECC_Start();
    CKey privkey;
    CPubKey pubkey;
    privkey.Set(vchPrivkey, vchPrivkey + 32, true);
    while (state.KeepRunning())
    {
        pubkey = privkey.GetPubKey();
    }
    ECC_Stop();
}

static void pubkey(benchmark::State &state)
{
    ECC_Start();
    CKey privkey;
    CPubKey pubkey;
    privkey.Set(vchPrivkey, vchPrivkey + 32, true);
    int count = 0;
    while (state.KeepRunning())
    {
        do
        {
            vchPrivkey[count & 31] = vchPrivkey[count & 31] + 1;
            privkey.Set(vchPrivkey, vchPrivkey + 32, true);
            count++;
        } while (!privkey.IsValid());

        pubkey = privkey.GetPubKey();
    }
    ECC_Stop();
}


BENCHMARK(samePubkey, 10000);
BENCHMARK(pubkey, 10000);
