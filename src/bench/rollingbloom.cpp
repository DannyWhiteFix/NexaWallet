// Copyright (c) 2016 The Bitcoin Core developers
// Copyright (c) 2016-2021 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <iostream>

#include "bench.h"
#include "bloom.h"
#include "fastfilter.h"

#include <mutex>

// Add a lock guard since the bloom filter needs one
// and gives a more fair comparison with the fast filter version.  However
// the lock guard is so efficient it doesn't noticeably affect the tests results
// but is here for consistency in comparing results for different filter types.
static void RollingBloomFilter(benchmark::State &state)
{
    std::mutex cs_roll;

    CRollingBloomFilter filter(120000, 0.000001);
    std::vector<unsigned char> data(32);
    uint32_t count = 0;
    uint64_t match = 0;
    while (state.KeepRunning())
    {
        count++;
        data[0] = count;
        data[1] = count >> 8;
        data[2] = count >> 16;
        data[3] = count >> 24;
        uint256 tmp = Hash(data.begin(), data.end());

        {
            std::lock_guard<std::mutex> lock(cs_roll);
            filter.insert(tmp);
        }


        data[0] = count >> 24;
        data[1] = count >> 16;
        data[2] = count >> 8;
        data[3] = count;
        {
            std::lock_guard<std::mutex> lock(cs_roll);
            match += filter.contains(tmp);
        }
    }
}

// Rolling Fast filter has it's own internal locking so
// none added in the tests.
static void RollingFastFilter(benchmark::State &state)
{
    CRollingFastFilter<1024 * 1024> filter;
    std::vector<unsigned char> data(32);
    uint32_t count = 0;
    uint64_t match = 0;
    while (state.KeepRunning())
    {
        count++;
        data[0] = count;
        data[1] = count >> 8;
        data[2] = count >> 16;
        data[3] = count >> 24;
        uint256 tmp = Hash(data.begin(), data.end());
        filter.insert(tmp);

        data[0] = count >> 24;
        data[1] = count >> 16;
        data[2] = count >> 8;
        data[3] = count;
        match += filter.contains(tmp);
    }
}

// Legacy rolling fast filter can run lock free so we didn't
// add any locks in the test.
static void RollingFastFilter_Legacy(benchmark::State &state)
{
    CLegacyRollingFastFilter<1024 * 1024> filter;
    std::vector<unsigned char> data(32);
    uint32_t count = 0;
    uint64_t match = 0;
    while (state.KeepRunning())
    {
        count++;
        data[0] = count;
        data[1] = count >> 8;
        data[2] = count >> 16;
        data[3] = count >> 24;
        uint256 tmp = Hash(data.begin(), data.end());
        filter.insert(tmp);

        data[0] = count >> 24;
        data[1] = count >> 16;
        data[2] = count >> 8;
        data[3] = count;
        match += filter.contains(tmp);
    }
}

BENCHMARK(RollingBloomFilter, 1500 * 1000);
BENCHMARK(RollingFastFilter, 1500 * 1000);
BENCHMARK(RollingFastFilter_Legacy, 1500 * 1000);
