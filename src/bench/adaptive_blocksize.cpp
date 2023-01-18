// Copyright (c) 2015 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "bench.h"
#include "consensus/adaptive_blocksize.h"
#include "random.h"
#include "utiltime.h"
#include "test/test_nexa.h"

#include <algorithm>
#include <random>

static void Sort1(benchmark::State &state)
{
    std::vector<uint64_t> vData;
    std::vector<uint64_t> vSizes;
    FastRandomContext seed(false);

    // create a large sorted list which we can append to
    for (int j = 0; j <= 50000; j++)
        vSizes.push_back(j);

    for (int j = 0; j <= 50000; j += 50)
        vData.push_back(j);
    std::shuffle(vData.begin(), vData.end(), std::default_random_engine(seed.rand32()));

    while (state.KeepRunning())
    {
        for (auto &i : vData)
        {
            vSizes.push_back(i);
            std::sort(vSizes.begin(), vSizes.end());
        }
    }
}

static void Sort2(benchmark::State &state)
{
    std::vector<uint64_t> vBlockSizes = {247, 248, 1000, 2000, 3000, 40000, 50000, 60000, 70000, 80000};
    std::vector<uint64_t> vSizes;

    // create a large sorted list which is comprised of many identical sizes
    // which we would typcially see in the blockindex
    for (int j = 0; j < 10; j++)
        for (int k = 0; k < 5000; k++)
            vSizes.push_back(vBlockSizes[j]);

    while (state.KeepRunning())
    {
        for (int j = 0; j <= 1000; j++)
        {
            vSizes.push_back(vBlockSizes[InsecureRandRange(10)]);
            std::sort(vSizes.begin(), vSizes.end());
        }
    }
}

static void Sort_InsertInOrder1(benchmark::State &state)
{
    std::vector<uint64_t> vData;
    std::vector<uint64_t> vSizes;
    FastRandomContext seed(false);

    // create a large sorted list which we can append to
    for (int j = 0; j <= 50000; j++)
        vSizes.push_back(j);

    for (int j = 0; j <= 50000; j += 50)
        vData.push_back(j);
    std::shuffle(vData.begin(), vData.end(), std::default_random_engine(seed.rand32()));

    while (state.KeepRunning())
    {
        for (auto &i : vData)
            InsertInSortedOrder(i, vSizes);
    }
}

static void Sort_InsertInOrder2(benchmark::State &state)
{
    std::vector<uint64_t> vBlockSizes = {247, 248, 1000, 2000, 3000, 40000, 50000, 60000, 70000, 80000};
    std::vector<uint64_t> vSizes;

    // create a large sorted list which is comprised of many identical sizes
    // which we would typcially see in the blockindex
    for (int j = 0; j < 10; j++)
        for (int k = 0; k < 5000; k++)
            vSizes.push_back(vBlockSizes[j]);

    while (state.KeepRunning())
    {
        for (int j = 0; j <= 1000; j++)
            InsertInSortedOrder(vBlockSizes[InsecureRandRange(10)], vSizes);
    }
}

BENCHMARK(Sort1, 1);
BENCHMARK(Sort2, 1);
BENCHMARK(Sort_InsertInOrder1, 1);
BENCHMARK(Sort_InsertInOrder2, 1);
