// Copyright (c) 2011-2015 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "coins.h"
#include "consensus/adaptive_blocksize.h"
#include "consensus/consensus.h"
#include "consensus/merkle.h"
#include "consensus/tx_verify.h"
#include "consensus/validation.h"
#include "init.h"
#include "main.h"
#include "miner.h"
#include "pubkey.h"
#include "script/standard.h"
#include "txadmission.h"
#include "txmempool.h"
#include "uint256.h"
#include "util.h"
#include "utilstrencodings.h"
#include "validation/validation.h"

#include "test/test_nexa.h"

#include <algorithm>
#include <boost/test/unit_test.hpp>
#include <random>

extern void dbgPrintBlock(CBlock &blk);
extern void dbgPrintMempool(CTxMemPool &pool);
extern CTweak<bool> xvalTweak;
extern CTweak<bool> enforceMinTxSize;
extern CTweak<bool> fastBlockTemplate;

static uint64_t CalculateMedian_OldCode(std::vector<uint64_t> &vData)
{
    if (!(vData.size() % 2))
        throw std::runtime_error("Data size does not contain an odd number of elements");

    std::sort(vData.begin(), vData.end());
    return *(vData.begin() + ((vData.size() - 1) / 2));
}

static bool CalculateMedianSize_OldCode(CBlockIndex *pindex,
    uint64_t nBlockSize,
    uint64_t nWindow,
    uint64_t &nMedianSize)
{
    std::vector<uint64_t> vSizes;
    vSizes.push_back(nBlockSize);
    for (uint64_t i = 0; i < nWindow; i++)
    {
        vSizes.push_back(pindex->GetBlockSize());
        if (!pindex->pprev)
        {
            break;
        }
        pindex = pindex->pprev;
    }
    if (vSizes.size() == nWindow + 1)
    {
        nMedianSize = CalculateMedian_OldCode(vSizes);
        return true;
    }
    return false;
}

BOOST_FIXTURE_TEST_SUITE(miner_tests, TestingSetup)


// BOOST_CHECK_EXCEPTION predicates to check the specific validation error
class HasReason
{
public:
    HasReason(const std::string &reason) : m_reason(reason) {}
    bool operator()(const std::runtime_error &e) const
    {
        bool ok = std::string(e.what()).find(m_reason) != std::string::npos;
        if (!ok)
            printf("Exception description is: %s, expected: %s\n", e.what(), m_reason.c_str());
        return ok;
    };

private:
    const std::string m_reason;
};

bool MiningLoop(const Consensus::Params &cparams,
    uint256 headerCommitment,
    std::vector<unsigned char> &nonce,
    uint32_t nBits,
    unsigned long int tries,
    std::atomic<bool> *abort)
{
    uint64_t count = 0;
    // printf("%s\n", HexStr(nonce).c_str());
    for (uint64_t x = 0; x < 8; x++)
        if (x < nonce.size())
            count = count | (nonce[x] << (x * 8ULL));

    uint64_t nsz = nonce.size();
    while ((tries > 0) && ((abort == nullptr) || (*abort == false)))
    {
        uint256 mhash = ::GetMiningHash(headerCommitment, nonce);
        if (CheckProofOfWork(mhash, nBits, cparams))
        {
            // printf("pow hash: %s\n", mhash.GetHex().c_str());
            return true;
        }
        ++count;
        for (uint64_t x = 0; x < 8; x++)
        {
            if (x < nsz)
            {
                nonce[x] = (count >> (x * 8)) & 255;
            }
            else
            {
                break;
            }
        }
        tries--;
    }
    return false;
}


bool ThreadedMineBlock(int nThreads,
    CBlockHeader &blockHeader,
    unsigned long int tries,
    const Consensus::Params &cparams)
{
    boost::thread_group minerThreads;
    std::vector<std::thread> grp;
    std::atomic<bool> done(false);
    std::mutex lock;

    uint256 headerCommitment = blockHeader.GetMiningHeaderCommitment();
    FastRandomContext insecure_rand;

    for (int i = 0; i < nThreads - 1; i++)
    {
        grp.emplace_back(
            [&](int idx)
            {
                std::vector<unsigned char> tnonce;
                tnonce.resize(5);
                tnonce[4] = idx;
                tnonce[3] = insecure_rand.rand32() & 255;
                bool result = MiningLoop(cparams, headerCommitment, tnonce, blockHeader.nBits, tries, &done);
                {
                    std::lock_guard<std::mutex> guard(lock);
                    if (result == true)
                    {
                        done = true;
                        blockHeader.nonce = tnonce;
                    }
                }
            },
            i);
    }

    for (auto &t : grp)
        t.join();

    return (done == true);
}


static struct
{
    std::string nonceHex;
} blockinfo[] = {
    {"030000d9ff"},
    {"0000004b0a"},
    {"060000dcff"},
    {"000000f704"},
    {"0000004606"},
    {"000000d209"},
    {"0000001203"},
    {"0000001602"},
    {"0000009e02"},
    {"000000c305"},
    {"000000d703"},
    {"0000004005"},
    {"000000c801"},
    {"0000004c06"},
    {"0000008707"},
    {"0000003000"},
    {"000000aa00"},
    {"0100004b00"},
    {"0000005100"},
    {"0000009f09"},
    {"000000c802"},
    {"000000bc07"},
    {"0000005000"},
    {"000000b700"},
    {"030000a7ff"},
    {"000000a300"},
    {"0000009007"},
    {"0000005701"},
    {"0000007e04"},
    {"0000002a00"},
    {"010000fbff"},
    {"0000005b04"},
    {"0000000605"},
    {"0000003301"},
    {"0000003f06"},
    {"0000009203"},
    {"000000bf00"},
    {"01000096ff"},
    {"040000dfff"},
    {"02000094ff"},
    {"0200003f00"},
    {"000000c200"},
    {"0000007408"},
    {"0100002300"},
    {"000000b903"},
    {"000000b809"},
    {"0000003407"},
    {"0100005e00"},
    {"0000001805"},
    {"040000caff"},
    {"0000002500"},
    {"0200000c00"},
    {"0100007800"},
    {"0000004f00"},
    {"0000001509"},
    {"0000007200"},
    {"0000005f02"},
    {"000000e008"},
    {"0000004400"},
    {"0000005704"},
    {"01000090ff"},
    {"0000000201"},
    {"010000b0ff"},
    {"000000ac07"},
    {"0000003206"},
    {"0000007503"},
    {"000000e400"},
    {"0000009a02"},
    {"0000002c04"},
    {"020000eaff"},
    {"000000fd00"},
    {"000000bd06"},
    {"0000006b07"},
    {"000000b100"},
    {"0000007b09"},
    {"0000009301"},
    {"0000006001"},
    {"000000fe04"},
    {"000000ef00"},
    {"0000005701"},
    {"0000004300"},
    {"0200001200"},
    {"0000008108"},
    {"040000e4ff"},
    {"000000b301"},
    {"0300000800"},
    {"000000a208"},
    {"0000003a00"},
    {"0000002300"},
    {"000000cb01"},
    {"030000d1ff"},
    {"0400003b00"},
    {"f60e00c5ff"},
    {"0000004c02"},
    {"0000009600"},
    {"000000cc00"},
    {"0100002e00"},
    {"0000009a01"},
    {"000000e702"},
    {"000000a600"},
    {"0000001101"},
    {"0100000900"},
    {"0000009f04"},
    {"0000008508"},
    {"000000b300"},
    {"000000fd00"},
    {"0000006c04"},
    {"0100006e00"},
    {"0000000003"},
    {"01000093ff"},
};

CBlockIndex CreateBlockIndex(int nHeight)
{
    CBlockHeader _header;
    CBlockIndex index;
    index.SetBlockHeader(std::make_shared<CBlockHeader>(_header));
    index.SetBlockHeaderHeight(nHeight);
    index.pprev = chainActive.Tip();
    return index;
}

bool TestSequenceLocks(const CTransaction &tx, int flags)
{
    READLOCK(mempool.cs_txmempool);
    return CheckSequenceLocks(MakeTransactionRef(tx), flags);
}

bool TxIn(uint256 txHash, std::vector<CTransactionRef> &vtx)
{
    for (const auto &tx : vtx)
        if (tx->GetId() == txHash)
            return true;
    return false;
}


// Test suite for ancestor feerate transaction selection.
// Implemented as an additional function, rather than a separate test case,
// to allow reusing the blockchain created in CreateNewBlock_validity.
// Note that this test assumes blockprioritysize is 0.
void TestPackageSelection(const CChainParams &chainparams, CScript scriptPubKey, std::vector<CTransactionRef> &txFirst)
{
    // Test the ancestor feerate transaction selection.
    TestMemPoolEntryHelper entry;
    auto cbAmt = chainparams.GetConsensus().initialSubsidy;

    SetArg("-blockprioritysize", std::to_string(0));
    minRelayFee.Set(1000);

    // Test that a medium fee transaction will be selected after a higher fee
    // rate package with a low fee rate parent.
    CMutableTransaction tx;
    tx.vin.resize(1);
    CScript op1Satisfier = CScript() << OP_1;
    tx.vin[0] = txFirst[0]->SpendOutput(0, op1Satisfier);
    tx.vout.resize(1);
    tx.vout[0].nValue = chainparams.GetConsensus().initialSubsidy - 1000;
    // This tx has a low fee: 1000 satoshis
    uint256 idemParentTx = tx.GetIdem(); // save this txid for later use
    mempool.addUnchecked(entry.Fee(1000).Time(GetTime()).SpendsCoinbase(true).FromTx(tx));

    // This tx has a medium fee: 10000 satoshis
    tx.vin[0] = txFirst[1]->SpendOutput(0, op1Satisfier);
    tx.vout[0].nValue = chainparams.GetConsensus().initialSubsidy - 10000;
    // uint256 idemMediumFeeTx = tx.GetIdem();
    mempool.addUnchecked(entry.Fee(10000).Time(GetTime()).SpendsCoinbase(true).FromTx(tx));

    // This tx has a high fee, but depends on the first transaction
    tx.vin[0].prevout = COutPoint(idemParentTx, 0);
    tx.vin[0].amount = chainparams.GetConsensus().initialSubsidy - 1000;
    tx.vout[0].nValue = chainparams.GetConsensus().initialSubsidy - 1000 - 50000; // 50k satoshi fee
    mempool.addUnchecked(entry.Fee(50000).Time(GetTime()).SpendsCoinbase(false).FromTx(tx));

    std::unique_ptr<CBlockTemplate> pblocktemplate = BlockAssembler(chainparams).CreateNewBlock(scriptPubKey);
    // Note the original code requires that the order of tx in the block matches the order tx were selected.
    // This is not necessarily true.  The best we can do is check that all tx were included in the block.
    BOOST_CHECK(pblocktemplate->block->vtx.size() == 4);

    // Test that a package below the min relay fee doesn't get included
    tx.vin[0] = txFirst[3]->SpendOutput(0, op1Satisfier);
    tx.vout[0].nValue = chainparams.GetConsensus().initialSubsidy - 1000 - 50000; // 0 fee
    uint256 idemFreeTx = tx.GetIdem();
    uint256 idFreeTx = tx.GetId();
    mempool.addUnchecked(entry.Fee(0).FromTx(tx));
    size_t freeTxSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);

    // Calculate a fee on child transaction that will put the package just
    // below the min relay fee (assuming 1 child tx of the same size).
    CAmount feeToUse = minRelayTxFee.GetFee(2 * freeTxSize) - 1;

    tx.vin[0].prevout = COutPoint(idemFreeTx, 0);
    tx.vin[0].amount = chainparams.GetConsensus().initialSubsidy - 1000 - 50000;
    tx.vout[0].nValue = chainparams.GetConsensus().initialSubsidy - 1000 - 50000 - feeToUse;
    uint256 idemLowFeeTx = tx.GetIdem();
    mempool.addUnchecked(entry.Fee(feeToUse).FromTx(tx));
    pblocktemplate = BlockAssembler(chainparams).CreateNewBlock(scriptPubKey);
    // Verify that the free tx and the low fee tx didn't get selected
    for (size_t i = 0; i < pblocktemplate->block->vtx.size(); ++i)
    {
        BOOST_CHECK(pblocktemplate->block->vtx[i]->GetIdem() != idemFreeTx);
        BOOST_CHECK(pblocktemplate->block->vtx[i]->GetIdem() != idemLowFeeTx);
    }

    // Test that packages above the min relay fee do get included, even if one
    // of the transactions is below the min relay fee
    // Remove the low fee transaction and replace with a higher fee transaction
    std::list<CTransactionRef> dummy;
    mempool.removeRecursive(tx, dummy);
    tx.vout[0].nValue -= 2; // Now we should be just over the min relay fee
    uint256 idLowFeeTx = tx.GetId();
    mempool.addUnchecked(entry.Fee(feeToUse + 2).FromTx(tx));
    pblocktemplate = BlockAssembler(chainparams).CreateNewBlock(scriptPubKey);
    BOOST_CHECK(TxIn(idFreeTx, pblocktemplate->block->vtx));
    BOOST_CHECK(TxIn(idLowFeeTx, pblocktemplate->block->vtx));

    // Test that transaction selection properly updates ancestor fee
    // calculations as ancestor transactions get included in a block.
    // Add a 0-fee transaction that has 2 outputs.
    tx.vin[0] = txFirst[2]->SpendOutput(0, op1Satisfier);
    tx.vout.resize(2);
    tx.vout[0].nValue = cbAmt - 100000000;
    tx.vout[1].nValue = 100000000; // 1BTC output
    uint256 idFreeTx2 = tx.GetId();
    uint256 idemFreeTx2 = tx.GetIdem();
    mempool.addUnchecked(entry.Fee(0).SpendsCoinbase(true).FromTx(tx));

    // This tx can't be mined by itself
    tx.vin[0].prevout = COutPoint(idemFreeTx2, 0);
    tx.vin[0].amount = cbAmt - 100000000;
    tx.vout.resize(1);
    feeToUse = minRelayTxFee.GetFee(freeTxSize);
    tx.vout[0].nValue = cbAmt - 100000000 - feeToUse;
    uint256 idLowFeeTx2 = tx.GetId();
    mempool.addUnchecked(entry.Fee(feeToUse).SpendsCoinbase(false).FromTx(tx));
    pblocktemplate = BlockAssembler(chainparams).CreateNewBlock(scriptPubKey);

    // Verify that this tx isn't selected.
    for (size_t i = 0; i < pblocktemplate->block->vtx.size(); ++i)
    {
        BOOST_CHECK(pblocktemplate->block->vtx[i]->GetId() != idFreeTx2);
        BOOST_CHECK(pblocktemplate->block->vtx[i]->GetId() != idLowFeeTx2);
    }

    // This tx will be mineable. And will also now allow idLowFeeTx2 to be
    // mined once idFreeTx2 and hashHighFeeTx2 are in the block.
    tx.vin[0].prevout = COutPoint(idemFreeTx2, 1);
    tx.vin[0].amount = 100000000;
    tx.vout[0].nValue = 100000000 - 10000; // 10k satoshi fee
    uint256 idHighFeeTx2 = tx.GetId();
    uint256 idemHighFeeTx2 = tx.GetIdem();
    CAmount idemHighFeeTxAmt = tx.vout[0].nValue;
    mempool.addUnchecked(entry.Fee(10000).FromTx(tx));
    pblocktemplate = BlockAssembler(chainparams).CreateNewBlock(scriptPubKey);
    // hashHighFeeTx2 now makes idFreeTx2 mineable.
    BOOST_CHECK(TxIn(idFreeTx2, pblocktemplate->block->vtx));
    BOOST_CHECK(TxIn(idHighFeeTx2, pblocktemplate->block->vtx));
    BOOST_CHECK(TxIn(idLowFeeTx2, pblocktemplate->block->vtx));

    // Test CPFP with AGT (ancestor grouped transactions)
    // Add another 0 fee tx to higher fee tx chain. This should also get mined
    // because the total package fees will still be above the minrelaytxfee
    tx.vin[0].prevout = COutPoint(idemHighFeeTx2, 0);
    tx.vin[0].amount = idemHighFeeTxAmt;
    feeToUse = 0;
    tx.vout[0].nValue = 100000000 - 10000 - feeToUse; // 0 fee
    uint256 idFreeTx3 = tx.GetId();
    mempool.addUnchecked(entry.Fee(feeToUse).SpendsCoinbase(false).FromTx(tx));
    pblocktemplate = BlockAssembler(chainparams).CreateNewBlock(scriptPubKey);
    // Although hashFreeTx3 is a zero fee it still gets mined before idLowFeeTx2 which
    // has a higher fee. This is because hashFreeTx3 is part of the ancestor grouping
    // along with hashHighFeeTx2 and idFreeTx2 and since it's "group" fee is higher
    // than idLowFeeTx2 then it will get mined first.
    BOOST_CHECK(TxIn(idFreeTx2, pblocktemplate->block->vtx));
    BOOST_CHECK(TxIn(idHighFeeTx2, pblocktemplate->block->vtx));
    BOOST_CHECK(TxIn(idFreeTx3, pblocktemplate->block->vtx));
    BOOST_CHECK(TxIn(idLowFeeTx2, pblocktemplate->block->vtx));
}

void GenerateBlocks(const CChainParams &chainparams,
    CScript scriptPubKey,
    uint64_t nStartSize,
    uint64_t nEndSize,
    uint64_t nIncrease)
{
    nTotalPackage = 0;

    // Now generate lots of blocks, increasing the block size on each iteration.
    uint64_t nTotalMine = 0;
    int nBlockCount = 0;
    uint64_t nTotalBlockSize = 0;
    uint64_t nTotalExpectedBlockSize = 0;
    std::unique_ptr<CBlockTemplate> pblocktemplate = BlockAssembler(chainparams).CreateNewBlock(scriptPubKey);
    for (unsigned int i = nStartSize; i <= nEndSize; i += nIncrease)
    {
        nBlockCount++;
        nTotalExpectedBlockSize += i;

        miningBlockSize.Set(i);
        uint64_t nStartMine = GetStopwatchMicros();
        pblocktemplate = BlockAssembler(chainparams).CreateNewBlock(scriptPubKey);
        nTotalBlockSize += pblocktemplate->block->GetBlockSize();
        nTotalMine += GetStopwatchMicros() - nStartMine;
        BOOST_CHECK(pblocktemplate);
        BOOST_CHECK(pblocktemplate->block->GetBlockSize() <= miningBlockSize.Value());
        unsigned int blockSize = pblocktemplate->block->GetBlockSize();
        BOOST_CHECK(blockSize <= miningBlockSize.Value());
        printf("%lu %lu:%lu <= %lu\n", (long unsigned int)blockSize,
            (long unsigned int)pblocktemplate->block->GetBlockSize(), pblocktemplate->block->vtx.size(),
            (long unsigned int)miningBlockSize.Value());
    }

    printf("mempool size : %ld\n", mempool.size());
    printf("mempool mapTx size : %ld\n", mempool.mapTx.size());
    printf("Avg Block Size %lu Expected Avg Block Size %lu\n",
        (long unsigned int)(nTotalBlockSize / (uint64_t)nBlockCount),
        (long unsigned int)(nTotalExpectedBlockSize / (uint64_t)nBlockCount));
    printf("Block fill ratio %5.2f\n",
        (double)(nTotalBlockSize / nBlockCount) * 100 / (nTotalExpectedBlockSize / nBlockCount));
    printf("Total mining time: %5.2f\n", (double)nTotalMine / 1000000);
    printf("packagetx mining %5.2f\n", (double)nTotalPackage / 1000000);

    mempool.clear();
}


// A peformance test suite for ancestor feerate transaction selection.
// Implemented as an additional function, rather than a separate test case,
// to allow reusing the blockchain created in CreateNewBlock_validity.
void PerformanceTest_PackageSelection(const CChainParams &chainparams,
    CScript scriptPubKey,
    std::vector<CTransactionRef> &txFirst)
{
    miningBlockSize.Set(10000000);
    minRelayFee.Set(1000);

    // Create many chains of transactions with varying fees such that we have many distinct packages within
    // each chain which could be mined as a Child Pays for Parent.
    TestMemPoolEntryHelper entry;
    SetArg("-blockprioritysize", std::to_string(0));
    CMutableTransaction tx;
    uint256 hash;
    FastRandomContext insecure_rand;

    // This script will make for a 250 byte transaction.
    CScript txnScript =
        CScript() << OP_0 << OP_0 << OP_0 << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP
                  << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP
                  << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP
                  << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP
                  << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP
                  << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP
                  << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP
                  << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP
                  << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP
                  << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP
                  << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP
                  << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP
                  << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP
                  << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP
                  << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP
                  << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP
                  << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP
                  << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP
                  << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_CHECKSIG
                  << OP_1;

    int64_t nStart = GetTimeMicros();
    for (size_t j = 0; j < 10; j++)
    {
        // Make a 250 byte txn
        tx.vin.resize(1);
        tx.vin[0] = txFirst[j]->SpendOutput(0);
        tx.vin[0].scriptSig = txnScript;
        tx.vout.resize(1);
        tx.vout[0].nValue = 5000000000LL;

        // Create a chain of transactions with varying fees applied to the descendants. This will create a chain
        // of descendant packages.
        for (unsigned int i = 0; i <= 2000; ++i)
        {
            int nFee = ((insecure_rand.rand32() % 10) * 10000);
            tx.vout[0].nValue -= nFee;
            hash = tx.GetIdem();
            bool spendsCoinbase = (i == 0) ? true : false; // only first tx spends coinbase
            // If we don't set the # of sig ops in the CTxMemPoolEntry, template creation fails
            mempool.addUnchecked(
                entry.Fee(nFee).Time(GetTime() + i).SpendsCoinbase(spendsCoinbase).SigOps(1).FromTx(tx));
            tx.vin[0].prevout = COutPoint(hash, 0);
            tx.vin[0].amount = tx.vout[0].nValue;
        }
    }
    printf("Time to load txns for %ld chains: %5.2f (secs)\n", txFirst.size(),
        (double)(GetTimeMicros() - nStart) / 1000000);
    GenerateBlocks(chainparams, scriptPubKey, 5000, 1000000, 5000);

    // Do the general run where we mine long chains where the fees are all the same. This is the most optimistic test.
    nStart = GetTimeMicros();
    for (size_t j = 0; j < 10; j++)
    {
        // Make a 250 byte txn
        tx.vin.resize(1);
        tx.vin[0] = txFirst[j]->SpendOutput(0);
        tx.vin[0].scriptSig = txnScript;
        tx.vout.resize(1);
        tx.vout[0].nValue = 5000000000LL;

        // Create a chain of transactions with varying fees applied to the descendants. This will create a chain
        // of descendant packages.
        for (unsigned int i = 0; i <= 2000; ++i)
        {
            int nFee = 1000;
            tx.vout[0].nValue -= nFee;
            hash = tx.GetIdem();
            bool spendsCoinbase = (i == 0) ? true : false; // only first tx spends coinbase
            // If we don't set the # of sig ops in the CTxMemPoolEntry, template creation fails
            mempool.addUnchecked(
                entry.Fee(nFee).Time(GetTime() + i).SpendsCoinbase(spendsCoinbase).SigOps(1).FromTx(tx));
            tx.vin[0].prevout = COutPoint(hash, 0);
            tx.vin[0].amount = tx.vout[0].nValue;
        }
    }
    printf("Time to load txns for second test: %5.2f (secs)\n", (double)(GetTimeMicros() - nStart) / 1000000);
    GenerateBlocks(chainparams, scriptPubKey, 5000, 1000000, 5000);
}

// NOTE: These tests rely on CreateNewBlock doing its own self-validation!
BOOST_AUTO_TEST_CASE(CreateNewBlock_validity)
{
    xvalTweak.Set(true);
    enforceMinTxSize.Set(false);

    // Note was MAIN, but takes too long to generate mainnet block for a test.  Need to pre-generate them.
    // Reducing MAIN powLimit breaks ASERT pow tests
    const CChainParams &chainparams = Params(CBaseChainParams::REGTEST);
    {
        LOCK(cs_main);
        UnloadBlockIndex();
        chainActive.reset();
        InitBlockIndex(chainparams);
    }

    assert(chainActive.Tip()->GetBlockHash() == chainparams.GetConsensus().hashGenesisBlock);
    CScript scriptPubKey = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f"
                                                 "6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f")
                                     << OP_CHECKSIG;
    std::unique_ptr<CBlockTemplate> pblocktemplate(new CBlockTemplate());
    CMutableTransaction tx, tx2;
    CScript script;
    uint256 hash;
    TestMemPoolEntryHelper entry;
    entry.nFee = 11;
    entry.dPriority = 111.0;
    entry.nHeight = 11;
    miningBlockSize.Set(100000);
    LOCK(cs_main);
    fCheckpointsEnabled = false;

    // Simple block creation, nothing special yet:
    BOOST_CHECK(pblocktemplate = BlockAssembler(chainparams).CreateNewBlock(scriptPubKey));

    // Simple block creation, with coinbase message
    BOOST_CHECK(pblocktemplate = BlockAssembler(chainparams).CreateNewBlock(scriptPubKey));

    // Simple block creation, with coinbase message and miner message.
    minerComment = "I am a meat popsicle.";
    BOOST_CHECK(pblocktemplate = BlockAssembler(chainparams).CreateNewBlock(scriptPubKey));

    minerComment = "flying is throwing yourself against the ground and missing.  This comment is "
                   "WAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY too long.";
    BOOST_CHECK(pblocktemplate = BlockAssembler(chainparams).CreateNewBlock(scriptPubKey));

    std::vector<CTransactionRef> txFirst;

    // We can't make transactions until we have inputs
    // Generate 110 blocks, trying pregenerated data first
    bool hadToGenerate = false;
    for (unsigned int i = 0; i < 110; ++i)
    {
        CBlockRef pblock = pblocktemplate->block; // pointer for convenience
        auto tip = chainActive.Tip();
        pblock->nTime = tip->GetMedianTimePast() + 1000;
        pblock->hashPrevBlock = tip->GetBlockHash();
        pblock->hashAncestor = tip->GetChildsConsensusAncestor()->GetBlockHash();
        BOOST_CHECK(pblock->hashAncestor != uint256()); // Ancestor hash must be something since this isn't the GB
        CMutableTransaction txCoinbase(*pblock->vtx[0]); // Grab a prior coinbase to get it mostly right
        txCoinbase.nVersion = 0;
        txCoinbase.vout[1].scriptPubKey = CScript() << OP_RETURN << (tip->height() + 1) << OP_0;
        txCoinbase.vout[0].scriptPubKey = CScript();
        pblock->vtx[0] = MakeTransactionRef(std::move(txCoinbase));
        if (txFirst.size() < 10)
            txFirst.push_back(pblock->vtx[0]);

        pblock->height = tip->height() + 1;
        pblock->nBits = GetNextWorkRequired(tip, pblock.get(), chainparams.GetConsensus());
        pblock->chainWork = ArithToUint256(tip->chainWork() + GetWorkForDifficultyBits(pblock->nBits));
        pblock->txCount = 1;

        pblock->nonce.resize(0);
        auto sz1 = pblock->CalculateBlockSize();
        pblock->nonce.resize(16);
        auto sz2 = pblock->CalculateBlockSize();
        pblock->nonce.resize(1);
        auto sz3 = pblock->CalculateBlockSize();
        BOOST_CHECK(sz1 == sz2);
        BOOST_CHECK(sz2 == sz3);

        if (i < sizeof(blockinfo) / sizeof(*blockinfo))
        {
            pblock->nonce = ParseHex(blockinfo[i].nonceHex); // start with the nonce that works
        }
        else
        {
            pblock->nonce.resize(5);
            for (int j = 0; j < 5; j++)
                pblock->nonce[i] = 0;
        }
        pblock->UpdateHeader();
        // Try the provided nonce first
        bool found = MineBlock(*pblock, 1UL, chainparams.GetConsensus());
        if (!found)
        {
            hadToGenerate = true;
            printf("Supplied nonce failed on index %d.  Generating a block with work %x\n", i, pblock->nBits);
            found = ThreadedMineBlock(12, *pblock, 1000000000UL, chainparams.GetConsensus());
            printf("Solution: { \"%s\" }\n", HexStr(pblock->nonce).c_str());
        }
        assert(found);
        // If this is extremely slow, you need to re-generate (changed mining alg or block format)
        // by taking these nonce printouts and copying them above
        CValidationState state;
        bool presult = ProcessNewBlock(state, chainparams, nullptr, pblock, true, nullptr, false);
        if (!presult)
        {
            printf("failed\n");
        }
        BOOST_CHECK(presult);
        BOOST_CHECK_MESSAGE(state.IsValid(), state.GetRejectReason() + " " + state.GetDebugMessage());
    }
    if (hadToGenerate)
    {
        printf("to speed this up paste this data in miner_tests.cpp blockinfo:\n");
        auto idx = chainActive.Tip();
        std::string dumpNonces;
        for (int i = 0; i < 110 && idx != nullptr && idx->pprev != nullptr; i++, idx = idx->pprev)
        {
            dumpNonces.insert(0, strprintf("{ \"%s\" },\n", HexStr(idx->nonce())));
        }
        printf("%s", dumpNonces.c_str());
        printf("chain generation/recovery finished\n");
    }

    // Just to make sure we can still make simple blocks
    BOOST_CHECK(pblocktemplate = BlockAssembler(chainparams).CreateNewBlock(scriptPubKey));

    mempool.clear();
    tx.vin.resize(1);
    // NOTE: OP_NOP is used to force 20 SigOps for the CHECKMULTISIG
    tx.vin[0].scriptSig = CScript() << OP_0 << OP_0 << OP_0 << OP_NOP << OP_CHECKMULTISIG << OP_1;
    tx.vin[0].prevout = txFirst[0]->OutpointAt(0);
    tx.vin[0].amount = txFirst[0]->vout[0].nValue;
    tx.vout.resize(1);

    tx.vout[0].nValue = chainparams.GetConsensus().initialSubsidy;

    for (unsigned int i = 0; i < 1001; ++i)
    {
        tx.vout[0].nValue -= 1000000 / 5;
        hash = tx.GetIdem();
        bool spendsCoinbase = (i == 0) ? true : false; // only first tx spends coinbase
        // If we do set the # of sig ops in the CTxMemPoolEntry, template creation passes
        mempool.addUnchecked(
            entry.Fee(1000000 / 5).Time(GetTime()).SpendsCoinbase(spendsCoinbase).SigOps(0).FromTx(tx));
        tx.vin[0].prevout = COutPoint(hash, 0);
        tx.vin[0].amount = tx.vout[0].nValue;
    }
    BOOST_CHECK(pblocktemplate = BlockAssembler(chainparams).CreateNewBlock(scriptPubKey));

    // Now generate lots of full size blocks and verify that none exceed the miningBlockSize value, the mempool has
    // 65k bytes of tx in it so this code will test both saturated and unsaturated blocks.
    for (unsigned int i = 2000; i <= 80000; i += 2000)
    {
        nextMaxBlockSize.Set(i);
        miningBlockSize.Set(nextMaxBlockSize.Value());

        pblocktemplate = BlockAssembler(chainparams).CreateNewBlock(scriptPubKey);
        BOOST_CHECK(pblocktemplate);
        BOOST_CHECK(pblocktemplate->block->GetBlockSize() <= miningBlockSize.Value());
        unsigned int blockSize = ::GetSerializeSize(*pblocktemplate->block, SER_NETWORK, PROTOCOL_VERSION) -
                                 ::GetSerializeSize(pblocktemplate->block->nonce, SER_NETWORK, PROTOCOL_VERSION);
        BOOST_CHECK(blockSize <= miningBlockSize.Value());
        // printf("%lu %lu <= %lu\n", (long unsigned int)blockSize,
        //    (long unsigned int)pblocktemplate->block->GetBlockSize(), (long unsigned int)miningBlockSize.Value());
    }

    BOOST_CHECK(chainActive.Tip()->height() == 110);
    int64_t minRoom = 1000;

    // Test no reserve and standard length miner comment
    coinbaseReserve.Set(0);
    minerComment = "I am a meat popsicle.";

    // Now generate lots of full size blocks and verify that none exceed the miningBlockSize value
    for (unsigned int i = 2000; i <= 30000; i += 967)
    {
        nextMaxBlockSize.Set(i);
        miningBlockSize.Set(nextMaxBlockSize.Value() - 100);

        pblocktemplate = BlockAssembler(chainparams).CreateNewBlock(scriptPubKey);
        BOOST_CHECK(pblocktemplate);
        BOOST_CHECK(pblocktemplate->block->GetBlockSize() <= miningBlockSize.Value());
        unsigned int blockSize = ::GetSerializeSize(*pblocktemplate->block, SER_NETWORK, PROTOCOL_VERSION) -
                                 ::GetSerializeSize(pblocktemplate->block->nonce, SER_NETWORK, PROTOCOL_VERSION);

        BOOST_CHECK(blockSize <= miningBlockSize.Value());

        // In the following caculation we have to remove the "used" portion of the padding above the 1 byte that
        // is already included in  initial empty serialized header.
        minRoom = std::min(minRoom,
            (int64_t)miningBlockSize.Value() - (int64_t)blockSize -
                (int64_t)(TXCOUNT_VARINT_PADDING -
                          (::GetSerializeSize(VARINT(pblocktemplate->block->txCount), SER_NETWORK, PROTOCOL_VERSION) -
                              1)) -
                (int64_t)(HEIGHT_VARINT_PADDING -
                          (::GetSerializeSize(VARINT(pblocktemplate->block->height), SER_NETWORK, PROTOCOL_VERSION) -
                              1)) -
                (int64_t)(FEEPOOL_VARINT_PADDING - (::GetSerializeSize(VARINT(pblocktemplate->block->feePoolAmt),
                                                        SER_NETWORK, PROTOCOL_VERSION) -
                                                       1)));
        // printf("%lu %lu <= %lu (%lu)\n", (long unsigned int)blockSize,
        //    (long unsigned int)pblocktemplate->block->GetBlockSize(), (long unsigned int)miningBlockSize.Value(),
        //    minRoom);
    }

    // Assert we went right up to the limit.  We reserved 4 bytes for height but only use 2 as height is 110.
    // We also reserved 5 bytes for tx count but only use 3 as we don't have > 65535 txs in a block
    BOOST_CHECK(minRoom >= 0);

    minRoom = 1000;
    std::string testMinerComment("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvw"
                                 "xyzABCDEFGHIJKLM__________");
    // Now generate lots of full size blocks and verify that none exceed the miningBlockSize value
    // printf("test mining with different sized miner comments");
    for (unsigned int i = 2000; i <= 40000; i += 1189)
    {
        nextMaxBlockSize.Set(i);
        miningBlockSize.Set(nextMaxBlockSize.Value());
        if ((i % 100) > 0)
            minerComment = testMinerComment.substr(0, i % 100);
        else
            minerComment = "";
        pblocktemplate = BlockAssembler(chainparams).CreateNewBlock(scriptPubKey);
        BOOST_CHECK(pblocktemplate);
        BOOST_CHECK(pblocktemplate->block->GetBlockSize() <= miningBlockSize.Value());
        unsigned int blockSize = ::GetSerializeSize(*pblocktemplate->block, SER_NETWORK, PROTOCOL_VERSION) -
                                 ::GetSerializeSize(pblocktemplate->block->nonce, SER_NETWORK, PROTOCOL_VERSION);
        BOOST_CHECK(blockSize <= miningBlockSize.Value());

        // In the following caculation we have to remove the "used" portion of the padding above the 1 byte that
        // is already included in  initial empty serialized header.
        minRoom = std::min(minRoom,
            (int64_t)miningBlockSize.Value() - (int64_t)blockSize -
                (int64_t)(TXCOUNT_VARINT_PADDING -
                          (::GetSerializeSize(VARINT(pblocktemplate->block->txCount), SER_NETWORK, PROTOCOL_VERSION) -
                              1)) -
                (int64_t)(HEIGHT_VARINT_PADDING -
                          (::GetSerializeSize(VARINT(pblocktemplate->block->height), SER_NETWORK, PROTOCOL_VERSION) -
                              1)) -
                (int64_t)(FEEPOOL_VARINT_PADDING - (::GetSerializeSize(VARINT(pblocktemplate->block->feePoolAmt),
                                                        SER_NETWORK, PROTOCOL_VERSION) -
                                                       1)));
        // printf("%lu %lu (miner comment is %d) <= %lu (%lu)\n", (long unsigned int)blockSize,
        //    (long unsigned int)pblocktemplate->block->GetBlockSize(), i % 100, (long unsigned
        //    int)miningBlockSize.Value(), minRoom);
    }
    BOOST_CHECK(minRoom >= 0);
    mempool.clear();

    // block size > limit
    tx.vin[0].scriptSig = CScript();
    // 18 * (520char + DROP) + OP_1 = 9433 bytes
    std::vector<unsigned char> vchData(520);
    for (unsigned int i = 0; i < 18; ++i)
        tx.vin[0].scriptSig << vchData << OP_DROP;
    tx.vin[0].scriptSig << OP_1;
    tx.vin[0].prevout = txFirst[0]->OutpointAt(0);
    tx.vin[0].amount = txFirst[0]->vout[0].nValue;
    tx.vout[0].nValue = chainparams.GetConsensus().initialSubsidy;

    for (unsigned int i = 0; i < 128; ++i)
    {
        tx.vout[0].nValue -= 1000000;
        hash = tx.GetIdem();
        bool spendsCoinbase = (i == 0) ? true : false; // only first tx spends coinbase
        mempool.addUnchecked(entry.Fee(100000).Time(GetTime()).SpendsCoinbase(spendsCoinbase).FromTx(tx));
        tx.vin[0].prevout = COutPoint(hash, 0);
        tx.vin[0].amount = tx.vout[0].nValue;
    }
    BOOST_CHECK(pblocktemplate = BlockAssembler(chainparams).CreateNewBlock(scriptPubKey));
    mempool.clear();

    // orphan in mempool, template creation fails
    mempool.addUnchecked(entry.Fee(1000000).Time(GetTime()).FromTx(tx));
    BOOST_CHECK_EXCEPTION(BlockAssembler(chainparams).CreateNewBlock(scriptPubKey), std::runtime_error,
        HasReason("bad-txns-inputs-missingorspent"));
    mempool.clear();

    // child with higher priority than parent
    tx.vin[0].scriptSig = CScript() << OP_1;
    tx.vin[0] = txFirst[1]->SpendOutput(0);
    tx.vout[0].nValue = 490000000LL;
    hash = tx.GetIdem();
    mempool.addUnchecked(entry.Fee(10000000LL).Time(GetTime()).SpendsCoinbase(true).FromTx(tx));
    tx.vin[0].prevout = COutPoint(hash, 0);
    tx.vin[0].amount = 490000000LL;
    ;
    tx.vin.resize(2);
    tx.vin[1] = txFirst[0]->SpendOutput(0);
    tx.vin[1].scriptSig = CScript() << OP_1;

    tx.vout[0].nValue = 590000000LL;
    mempool.addUnchecked(entry.Fee(40000000LL).Time(GetTime()).SpendsCoinbase(true).FromTx(tx));
    BOOST_CHECK(pblocktemplate = BlockAssembler(chainparams).CreateNewBlock(scriptPubKey));
    mempool.clear();

    // coinbase in mempool, template creation fails
    tx.vin.resize(0);
    tx.vout.resize(2);
    tx.vout[0].nValue = 0;
    tx.vout[1].nValue = 0;
    tx.vout[1].scriptPubKey = CScript() << OP_RETURN << (chainActive.Tip()->height() + 1);
    // give it a fee so it'll get mined
    mempool.addUnchecked(entry.Fee(100000).Time(GetTime()).SpendsCoinbase(false).FromTx(tx));
    // Should throw bad-cb-multiple
    BOOST_CHECK_EXCEPTION(
        BlockAssembler(chainparams).CreateNewBlock(scriptPubKey), std::runtime_error, HasReason("bad-cb-multiple"));
    mempool.clear();

    CAmount feeAmt = chainparams.GetConsensus().initialSubsidy / 1000LL;
    CAmount outAmt = chainparams.GetConsensus().initialSubsidy - feeAmt;
    // invalid txn in mempool, template creation fails
    tx.vin.resize(1);
    tx.vin[0] = txFirst[0]->SpendOutput(0);
    tx.vin[0].scriptSig = CScript() << OP_1;
    tx.vout.resize(1);
    tx.vout[0].nValue = outAmt;
    script = CScript() << OP_0;
    tx.vout[0].scriptPubKey = OP_0;
    hash = tx.GetIdem();
    mempool.addUnchecked(entry.Fee(feeAmt).Time(GetTime()).SpendsCoinbase(true).FromTx(tx));
    tx.vin[0].prevout = COutPoint(hash, 0);
    tx.vin[0].amount = outAmt;
    tx.vin[0].scriptSig = CScript();
    tx.vout[0].nValue -= feeAmt;
    mempool.addUnchecked(entry.Fee(feeAmt).Time(GetTime()).SpendsCoinbase(false).FromTx(tx));

    xvalTweak.Set(false);
    BOOST_CHECK_EXCEPTION(
        BlockAssembler(chainparams).CreateNewBlock(scriptPubKey), std::runtime_error, HasReason("bad-blk-signatures"));
    mempool.clear();
    xvalTweak.Set(true);

    // double spend txn pair in mempool, template creation fails
    tx.vin[0] = txFirst[0]->SpendOutput(0);
    tx.vin[0].scriptSig = CScript() << OP_1;
    tx.vout[0].nValue = outAmt;
    tx.vout[0].scriptPubKey = CScript() << OP_1;
    mempool.addUnchecked(entry.Fee(feeAmt).Time(GetTime()).SpendsCoinbase(true).FromTx(tx));
    tx.vout[0].scriptPubKey = CScript() << OP_2;
    mempool.addUnchecked(entry.Fee(feeAmt).Time(GetTime()).SpendsCoinbase(true).FromTx(tx));
    BOOST_CHECK_EXCEPTION(BlockAssembler(chainparams).CreateNewBlock(scriptPubKey), std::runtime_error,
        HasReason("bad-txns-inputs-missingorspent"));
    mempool.clear();

    // subsidy changing
    int nHeight = chainActive.Height();
    // Create an actual 209999-long block chain (without valid blocks).
    uint32_t chainTgtBits = UintToArith256(chainparams.GetConsensus().powLimit).GetCompact();
    while (chainActive.Tip()->height() < 209999)
    {
        CBlockIndex *prev = chainActive.Tip();
        CBlockIndex *next = new CBlockIndex();
        next->phashBlock = new uint256(InsecureRand256());
        pcoinsTip->SetBestBlock(next->GetBlockHash());
        next->pprev = prev;
        next->SetBlockHeaderBits(chainTgtBits);
        next->SetBlockHeaderChainWork(ArithToUint256(prev->chainWork() + GetBlockProof(*next)));
        next->SetBlockHeaderHeight(prev->height() + 1);
        next->nNextMaxBlockSize = DEFAULT_NEXT_MAX_BLOCK_SIZE;
        next->BuildSkip();
        chainActive.SetTip(next);
    }
    BOOST_CHECK(pblocktemplate = BlockAssembler(chainparams).CreateNewBlock(scriptPubKey));

    // Extend to a 210000-long block chain.
    while (chainActive.Tip()->height() < 210000)
    {
        CBlockIndex *prev = chainActive.Tip();
        CBlockIndex *next = new CBlockIndex();
        next->phashBlock = new uint256(InsecureRand256());
        pcoinsTip->SetBestBlock(next->GetBlockHash());
        next->pprev = prev;
        next->SetBlockHeaderHeight(prev->height() + 1);
        next->nNextMaxBlockSize = DEFAULT_NEXT_MAX_BLOCK_SIZE;
        next->BuildSkip();
        chainActive.SetTip(next);
    }
    BOOST_CHECK(pblocktemplate = BlockAssembler(chainparams).CreateNewBlock(scriptPubKey));

    // Delete the dummy blocks again.
    while (chainActive.Tip()->height() > nHeight)
    {
        CBlockIndex *del = chainActive.Tip();
        chainActive.SetTip(del->pprev);
        pcoinsTip->SetBestBlock(del->pprev->GetBlockHash());
        delete del->phashBlock;
        delete del;
    }

    // Do a performance test of package selection. This will typically be commented out unless one wants
    // to run the testing.
    mempool.clear();
    // PerformanceTest_PackageSelection(chainparams, scriptPubKey, txFirst);

    // Must reset this to "true" or you'll cause a thread to hang in the main test loop.
    fCheckpointsEnabled = true;

    enforceMinTxSize.Set(true);
    xvalTweak.Set(false);
}

BOOST_AUTO_TEST_CASE(AdaptiveBlockSize)
{
    // Test median calculation after randomly shuffling the data each iteration.
    std::vector<uint64_t> vData = {12, 1, 5, 7, 9, 4, 8, 1000, 98, 2, 9, 3, 9, 1, 9, 1234567890, 7, 8, 8};

    FastRandomContext seed(false);
    std::vector<uint64_t> vSizes1;
    for (int j = 1; j <= 20; j++)
    {
        vSizes1.clear();
        std::shuffle(vData.begin(), vData.end(), std::default_random_engine(seed.rand32()));
        for (uint64_t i : vData)
            InsertInSortedOrder(i, vSizes1);
        BOOST_CHECK_EQUAL(CalculateMedian(vSizes1), 8UL);
    }

    // Add data items to the front and back of the data range
    InsertInSortedOrder(12345678900, vSizes1);
    InsertInSortedOrder(12, vSizes1);
    BOOST_CHECK_EQUAL(CalculateMedian(vSizes1), 8UL);
    InsertInSortedOrder(0, vSizes1);
    InsertInSortedOrder(1, vSizes1);
    BOOST_CHECK_EQUAL(CalculateMedian(vSizes1), 8UL);

    vData.clear();
    for (int j = 0; j <= 1000; j++)
        vData.push_back(j);
    for (int j = 1; j <= 100; j++)
    {
        std::shuffle(vData.begin(), vData.end(), std::default_random_engine(seed.rand32()));
        std::vector<uint64_t> vSizes;
        for (auto &i : vData)
            InsertInSortedOrder(i, vSizes);
        BOOST_CHECK_EQUAL(CalculateMedian(vSizes), 500ULL);
        /* Good bit of debugging code if ever its needed to debug the InsertInSortedOrder() function
        if (CalculateMedian(vSizes) != 500)
        {
            for (auto d : vData)
               printf("vData sizes %ld size: %ld\n", vData.size(), d);

            for (auto d : vSizes)
               printf("vsizes %ld size: %ld\n", vSizes.size(), d);
            assert(0);
        }
        */
    }

    // Check Single element
    std::vector<uint64_t> vSizes1a = {1};
    BOOST_CHECK_EQUAL(CalculateMedian(vSizes1a), 1ULL);

    // Check we have an odd number of elements
    std::vector<uint64_t> vSizes2;
    BOOST_CHECK_EXCEPTION(CalculateMedian(vSizes2), std::runtime_error,
        HasReason("Data size does not contain an odd number of elements"));

    std::vector<uint64_t> vSizes2a = {12, 0, 5, 7, 9, 4, 8, 1000, 98, 44};
    std::sort(vSizes2a.begin(), vSizes2a.end());
    BOOST_CHECK_EXCEPTION(CalculateMedian(vSizes2a), std::runtime_error,
        HasReason("Data size does not contain an odd number of elements"));

    std::vector<uint64_t> vSizes2b = {12, 0};
    std::sort(vSizes2b.begin(), vSizes2b.end());
    BOOST_CHECK_EXCEPTION(CalculateMedian(vSizes2b), std::runtime_error,
        HasReason("Data size does not contain an odd number of elements"));


    // Create a blockindex which has random block sizes and multiple forks and
    // then test the old code vs the new code in regards to median blocksize calculation.
    std::vector<uint64_t> vSizes;
    std::deque<uint64_t> vSizes_Unsorted;
    bool fRunOnce = true;
    CBlockIndex *pindexTip = nullptr;
    uint64_t nWindow = 500;
    uint64_t nMultiplyer = 0;

    BlockMap mapIndex;
    CBlockIndex *pprev = nullptr;
    for (uint64_t nHeight = 1; nHeight <= 10000; nHeight++)
    {
        CBlockIndex *pindex = new CBlockIndex();
        uint64_t nBlockSize = ((nMultiplyer + 1) * 1000000) + (InsecureRandRange(256) * 1000 * 1000);
        if (InsecureRandRange(50) == 0)
            nMultiplyer = InsecureRandRange(100);
        CBlockHeader header;
        pindex->SetBlockHeader(std::make_shared<CBlockHeader>(header));
        pindex->SetBlockHeaderHeight(nHeight);
        pindex->SetBlockHeaderSize(nBlockSize);
        pindex->SetBlockHeaderBits(1);
        pindex->pprev = pprev;
        pprev = pindex;
        mapIndex.emplace(pindex->GetBlockHeader().GetHash(), pindex);

        if (!pindex->pprev)
            continue;

        uint64_t nMedian1 = 0;
        uint64_t nMedian2 = 0;
        bool fMedian1 =
            CalculateMedianSize(pindex, nBlockSize, nWindow, vSizes, vSizes_Unsorted, &pindexTip, fRunOnce, nMedian1);
        bool fMedian2 = CalculateMedianSize_OldCode(pindex->pprev, nBlockSize, nWindow, nMedian2);
        BOOST_CHECK_EQUAL(fMedian1, fMedian2);
        BOOST_CHECK_EQUAL(nMedian1, nMedian2);

        // Every once in a while create a new fork
        if (InsecureRandRange(10) == 0)
        {
            CBlockIndex *pindexFork = new CBlockIndex();
            // Block size must be at least 1 or certain debug assertion sanity checks are triggered
            uint64_t nBlockSizeFork = (nMultiplyer * 1000000) + (InsecureRandRange(256) * 1000 * 1000) + 1;
            CBlockHeader _header;
            pindexFork->SetBlockHeader(std::make_shared<CBlockHeader>(_header));
            pindexFork->SetBlockHeaderHeight(nHeight);
            pindexFork->SetBlockHeaderSize(nBlockSizeFork);
            pindexFork->SetBlockHeaderBits(1);
            pindexFork->pprev = pindex->pprev;
            pprev = pindexFork;
            mapIndex.emplace(pindexFork->GetBlockHeader().GetHash(), pindexFork);

            uint64_t nMedianFork1 = 0;
            uint64_t nMedianFork2 = 0;
            bool fMedianFork1 = CalculateMedianSize(
                pindexFork, nBlockSizeFork, nWindow, vSizes, vSizes_Unsorted, &pindexTip, fRunOnce, nMedianFork1);
            bool fMedianFork2 = CalculateMedianSize_OldCode(pindexFork->pprev, nBlockSizeFork, nWindow, nMedianFork2);
            BOOST_CHECK_EQUAL(fMedianFork1, fMedianFork2);
            BOOST_CHECK_EQUAL(nMedianFork1, nMedianFork2);
        }
    }

    // clean up the block index
    for (auto it : mapIndex)
    {
        delete it.second;
    }
}


BOOST_AUTO_TEST_CASE(AncestorTests)
{
    int64_t ancestorTestVector[][2] = {
        {1, 0}, {2, 0}, {5039, 0}, {5041, 1}, // Edge cases
        {100, 96}, {96, 64}, {64, 0}, {0xfffffe, 0xfffffc}, {0xfffffc, 0xfffff8}, {0xfffff8, 0xfffff0},
        {0xfffff0, 0xffffe0}, {0xffffe0, 0xffffc0}, {0xffffc0, 0xffff80}, {0xffff80, 0xffff00}, {0xffff00, 0xfffe00},

        {0, 0} // Terminator
    };

    for (int i = 0; ancestorTestVector[i][0] != 0; i++)
    {
        BOOST_CHECK(GetConsensusAncestorHeight(ancestorTestVector[i][0]) == ancestorTestVector[i][1]);
    }
}

BOOST_AUTO_TEST_SUITE_END()
