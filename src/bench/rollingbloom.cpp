// Copyright (c) 2016 The Bitcoin Core developers
// Copyright (c) 2016-2021 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <iostream>

#include "bench.h"
#include "bloom.h"
#include "fastfilter.h"

#include <mutex>

// Set up stuff that should not be timed
class SHA256
{
public:
    int amt = 100000;
    std::vector<uint256> data;

    SHA256()
    {
        data.reserve(amt);
        for (int i = 0; i < amt; i++)
        {
            uint256 num = GetRandHash();
            data.push_back(num);
        }
    }
};
SHA256 random_sha;

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
        for (int i = 0; i < 1000; i++)
        {
            count++;
            const uint256 &tmp = random_sha.data[i];

            {
                std::lock_guard<std::mutex> lock(cs_roll);
                filter.insert(tmp);
            }

            {
                std::lock_guard<std::mutex> lock(cs_roll);
                match += filter.contains(tmp);
            }
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
        for (int i = 0; i < 1000; i++)
        {
            count++;
            const uint256 &tmp = random_sha.data[i];
            filter.insert(tmp);
            match += filter.contains(tmp);
        }
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
        for (int i = 0; i < 1000; i++)
        {
            count++;
            const uint256 &tmp = random_sha.data[i];
            filter.insert(tmp);
            match += filter.contains(tmp);
        }
    }
}

BENCHMARK(RollingBloomFilter, 1);
BENCHMARK(RollingFastFilter, 1);
BENCHMARK(RollingFastFilter_Legacy, 1);
