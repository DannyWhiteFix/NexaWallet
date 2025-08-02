// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2025 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "chainparamsbase.h"
#include "chainparamsseeds.h"
#include "consensus/merkle.h"
#include "policy/policy.h"
#include "versionbits.h" // bip135 added

#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>


/** Next protocol upgrade will be activated once MTP >= 12:00:00 PM, March 15th 2026, GMT
 */
const uint64_t NEXT_FORK_ACTIVATION_TIME = 1773576000;


// Must be zero on startup. Do not set this to any other value.
// To change consensus forktime you can either set the global value
// NEXT_FORK_ACTIVATION_TIME or you can modify an individual forktime
// by modifying consensus.nextForkActivationTime found in each
// chainparam setting in the sections below. NOTE: individual
// settings made will override the global setting.
uint64_t nMiningForkTime = 0;

SatoshiBlock CreateGenesisBlock(CScript prefix,
    const std::string &comment,
    const CScript &genesisOutputScript,
    uint32_t nTime,
    uint32_t nNonce,
    uint32_t nBits,
    int32_t nVersion,
    const CAmount &genesisReward)
{
    const unsigned char *pComment = (const unsigned char *)comment.c_str();
    std::vector<unsigned char> vComment(pComment, pComment + comment.length());

    CMutableTransaction txNew;
    txNew.nVersion = 0;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = prefix << vComment;
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    SatoshiBlock genesis;
    genesis.nTime = nTime;
    genesis.nBits = nBits;
    genesis.nNonce = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

CBlock CreateGenesisBlock(const char *genesisText,
    const CScript &genesisOutputScript,
    uint32_t nTime,
    const std::vector<unsigned char> &nonce,
    uint32_t nBits,
    const CAmount &genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 0;
    txNew.vin.resize(0);
    txNew.vout.resize(2);
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;
    txNew.vout[1].nValue = 0;
    txNew.vout[1].scriptPubKey = CScript() << OP_RETURN << ((int)0) << CScriptNum::fromIntUnchecked(7227)
                                           << std::vector<unsigned char>((const unsigned char *)genesisText,
                                                  (const unsigned char *)genesisText + strlen(genesisText));

    CBlock genesis;
    genesis.nTime = nTime;
    genesis.nBits = nBits;
    genesis.chainWork = ArithToUint256(GetWorkForDifficultyBits(nBits)); // chainWork includes this block's work
    genesis.nonce = nonce;
    genesis.vtx.push_back(MakeTransactionRef(txNew));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    genesis.UpdateHeader();
    return genesis;
}

#if 0 // Keep around for historical purposes
/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505,
 * nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase
 * 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static SatoshiBlock CreateSatoshiGenesisBlock(uint32_t nTime,
    uint32_t nNonce,
    uint32_t nBits,
    int32_t nVersion,
    const CAmount &genesisReward)
{
    const char *pszTimestamp = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";
    const CScript genesisOutputScript = CScript()
                                        << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb6"
                                                    "49f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f")
                                        << OP_CHECKSIG;
    return CreateGenesisBlock(CScript() << 486604799 << LegacyCScriptNum(4), pszTimestamp, genesisOutputScript, nTime,
        nNonce, nBits, nVersion, genesisReward);
}
#endif


// Temporarily here until we settle on the Genesis blocks
#include "key.h"

static uint256 sha256(uint256 data)
{
    uint256 ret;
    CSHA256 sha;
    sha.Write(data.begin(), 256 / 8);
    sha.Finalize(ret.begin());
    return ret;
}

bool CheckPow(uint256 hash, unsigned int nBits, const Consensus::Params &params)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    if (params.powAlgorithm == 1)
    {
        // This algorithm uses the hash as a priv key to sign sha256(hash) using deterministic k.
        // This means that any hardware optimization will need to implement signature generation.
        // What we really want is signature validation to be implemented in hardware, so more thought needs to
        // happen.
        uint256 h1 = sha256(hash);
        CKey k; // Use hash as a private key
        k.Set(hash.begin(), hash.end(), false);
        if (!k.IsValid())
            return false; // If we can't POW fails
        std::vector<uint8_t> vchSig;
        if (!k.SignSchnorr(h1, vchSig))
            return false; // Sign sha256(hash) with hash

        // sha256 the signed data to get back to 32 bytes
        CSHA256 sha;
        sha.Write(&vchSig[0], vchSig.size());
        sha.Finalize(hash.begin());
    }

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || (bnTarget == arith_uint256(0)) || fOverflow || bnTarget > UintToArith256(params.powLimit))
        return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}

bool MineIt(CBlockHeader &blockHeader, unsigned long int tries, const Consensus::Params &cparams)
{
    assert(blockHeader.size != 0); // Size must be properly calculated before we can figure out the hash
    unsigned long int count = 0;
    for (unsigned int x = 0; x < 8; x++)
    {
        if (x < blockHeader.nonce.size())
        {
            count = count | (blockHeader.nonce[x] << (x * 8));
        }
        else
            break;
    }

    uint256 headerCommitment = blockHeader.GetMiningHeaderCommitment();

    while (tries > 0)
    {
        if ((tries & ((1 << 12) - 1)) == 0)
            printf("nonce: %s\n", GetHex(blockHeader.nonce).c_str());
        uint256 mhash = ::GetMiningHash(headerCommitment, blockHeader.nonce);
        if (CheckPow(mhash, blockHeader.nBits, cparams))
        {
            // printf("pow hash: %s\n", mhash.GetHex().c_str());
            return true;
        }
        ++count;
        for (unsigned int x = 0; x < 8; x++)
        {
            if (x < blockHeader.nonce.size())
            {
                blockHeader.nonce[x] = (count >> (x * 8)) & 255;
            }
            else
                break;
        }
        tries--;
    }
    return false;
}
// end temporary

class CLegacyParams : public CChainParams
{
public:
    CLegacyParams()
    {
        nRPCPort = 7227;

        strNetworkID = "main"; // Do not use the const string because of ctor execution order issues
        nDefaultPort = BTCBCH_DEFAULT_MAINNET_PORT;
        nPruneAfterHeight = 100000;
        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = false;
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 0);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 5);
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 128);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};
        cashaddrPrefix = "bitcoincash";

        // this network is going to be deleted soon, still here to get some unit tests passing
        consensus.nSubsidyHalvingInterval = 210000;
        // 00000000000000ce80a7e057163a4db1d5ad7b20fb6f598c9597b9665c8fb0d4 - April 1, 2012

        uint32_t tgtBits = 0x1e0fffff;
        bool fNegative;
        bool fOverflow;
        arith_uint256 tmp;
        tmp.SetCompact(tgtBits, &fNegative, &fOverflow);
        // consensus.powLimit = ArithToUint256(tmp);  Better choice but breaks pow_tests.cpp
        consensus.powLimit = uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.powAlgorithm = 0;
        consensus.initialSubsidy = 50 * 1000000 * COIN;
        consensus.coinbaseMaturity = COINBASE_MATURITY_TESTNET;
        // The half life for the ASERT DAA. For every (nASERTHalfLife) seconds behind schedule the blockchain gets,
        // difficulty is cut in half. Doubled if blocks are ahead of schedule.
        // Two days
        consensus.nASERTHalfLife = 2 * 24 * 60 * 60;
        // testing bit
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601LL; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999LL; // December 31, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].windowsize = 2016;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].threshold = 1916; // 95% of 2016

        consensus.nextForkActivationTime = NEXT_FORK_ACTIVATION_TIME;

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xf9;
        pchMessageStart[1] = 0xbe;
        pchMessageStart[2] = 0xb4;
        pchMessageStart[3] = 0xd9;
        consensus.nShortBlockWindow = SHORT_BLOCK_WINDOW;
        consensus.nLongBlockWindow = LONG_BLOCK_WINDOW;
        consensus.nBlockSizeMultiplier = BLOCK_SIZE_MULTIPLIER;
        consensus.nNextMaxBlockSize = DEFAULT_NEXT_MAX_BLOCK_SIZE_FORK1;

        consensus.tailstorm_k = 0;
        consensus.tailstormEnforceDepth = 0;

        std::vector<unsigned char> nonce;
        std::vector<unsigned char> hardCodedNonce;
        nonce = hardCodedNonce = ParseHex("00000000");
        genesis = CreateGenesisBlock("This is a fake mainnet", CScript() << OP_1, 1626275623, nonce, tgtBits, 0 * COIN);
        // This creates a genesis block with invalid POW, but we don't care.  Mainnet is going away anyway to be
        // replaced by nexa

        consensus.hashGenesisBlock = genesis.GetHash();
        // printf("fakemainnet soln %d hex:%s\n", worked, HexStr(genesis.nonce).c_str());
        // printf("fakemainnet GB hash %s\n", consensus.hashGenesisBlock.GetHex().c_str());

        // List of Bitcoin Cash compatible seeders
        vSeeds.push_back(CDNSSeedData("bitcoinunlimited.info", "btccash-seeder.bitcoinunlimited.info", true));
        vSeeds.push_back(CDNSSeedData("bitcoinforks.org", "seed-bch.bitcoinforks.org", true));
        vSeeds.push_back(CDNSSeedData("bchd.cash", "seed.bchd.cash", true));
        vSeeds.push_back(CDNSSeedData("bch.loping.net", "seed.bch.loping.net", true));
        vSeeds.push_back(CDNSSeedData("electroncash.de", "dnsseed.electroncash.de", true));
        vSeeds.push_back(CDNSSeedData("flowee.cash", "seed.flowee.cash", true));

        // BITCOINUNLIMITED START
        vFixedSeeds = std::vector<SeedSpec6>();
        // BITCOINUNLIMITED END

        // clang-format off
        // checkpoint related to various network upgrades need to be the first block
        // for which the new rules are enforced, hence activation height + 1, where activation
        // height is the first block for which MTP <= upgrade activation time
        checkpointData = (CCheckpointData){
            {{0, consensus.hashGenesisBlock }}, 0};
        // clang-format on

        // * UNIX timestamp of last checkpoint block
        checkpointData.nTimeLastCheckpoint = 1573825449;

        nBlockFileSize = 0x8000000ULL; // 2GB
        nUndoFileSize = 0x2000000ULL; // 32MiB
    }
};

static CLegacyParams legacyParams;

/**
 * Regression test
 */
class CRegTestParams : public CChainParams
{
public:
    CRegTestParams()
    {
        nRPCPort = 18332;
        strDataDir = "regtest";

        strNetworkID = "regtest"; // Do not use the const string because of ctor execution order issues
        nDefaultPort = DEFAULT_REGTESTNET_PORT;
        nPruneAfterHeight = 1000;
        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<uint8_t>(1, 111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<uint8_t>(1, 196);
        base58Prefixes[SECRET_KEY] = std::vector<uint8_t>(1, 239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};
        base58Prefixes[SCRIPT_TEMPLATE_ADDRESS] = std::vector<unsigned char>(1, 8);
        cashaddrPrefix = "nexareg";

        consensus.nSubsidyHalvingInterval = 150;
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.powAlgorithm = 1;
        consensus.initialSubsidy = 10 * 1000000 * COIN;
        consensus.coinbaseMaturity = COINBASE_MATURITY_TESTNET;
        // The half life for the ASERT DAA. For every (nASERTHalfLife) seconds behind schedule the blockchain gets,
        // difficulty is cut in half. Doubled if blocks are ahead of schedule.
        // Two days
        consensus.nASERTHalfLife = 2 * 24 * 60 * 60;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 999999999999LL;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].windowsize = 144;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].threshold = 108; // 75% of 144

        consensus.nextForkActivationTime = NEXT_FORK_ACTIVATION_TIME;

        pchMessageStart[0] = 0xea;
        pchMessageStart[1] = 0xe5;
        pchMessageStart[2] = 0xef;
        pchMessageStart[3] = 0xea;
        consensus.nShortBlockWindow = SHORT_BLOCK_WINDOW_REGTEST;
        consensus.nLongBlockWindow = LONG_BLOCK_WINDOW_REGTEST;
        consensus.nBlockSizeMultiplier = BLOCK_SIZE_MULTIPLIER;
        consensus.nNextMaxBlockSize = DEFAULT_NEXT_MAX_BLOCK_SIZE_FORK1_REGTEST;

        consensus.tailstorm_k = 4;
        consensus.tailstormEnforceDepth = DEPTH_TO_ENFORCE_CORRECT_SUBBLOCKS;

        std::vector<unsigned char> nonce;
        nonce.resize(1);
        nonce[0] = 5;
        genesis = CreateGenesisBlock("This is regtest", CScript() << OP_1, 1626275623, nonce, 0x207fffff, 0 * COIN);
#if 0 // recalculate GB if needed (note that this code will not work with the java nexa shared library because it
      // must start before the random numbers (initialized in ECC_Start are hooked up).
        ECC_Start();
        bool worked = MineIt(genesis, 255, consensus);
        ECC_Stop();
        consensus.hashGenesisBlock = genesis.GetHash();
        if (genesis.nonce[0] != nonce[0])
        {
            printf("regtest GB nonce changed! hash %s\n", consensus.hashGenesisBlock.GetHex().c_str());
            printf("regtest soln %d hex:%s\n", worked, HexStr(genesis.nonce).c_str());
        }
#else
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(
            consensus.hashGenesisBlock == uint256S("d71ee431e307d12dfef31a6b21e071f1d5652c0eb6155c04e3222612c9d0b371"));
#endif

        vFixedSeeds.clear(); //! Regtest mode doesn't have any fixed seeds.
        vSeeds.clear(); //! Regtest mode doesn't have any DNS seeds.

        checkpointData = (CCheckpointData){{{0, consensus.hashGenesisBlock}}, 0};

        nBlockFileSize = 0x20000ULL; // 128KiB
        nUndoFileSize = 0x2000ULL; // 8KiB
    }
};
static CRegTestParams regTestParams;


class CTestNetParams : public CChainParams
{
public:
    CTestNetParams()
    {
        nRPCPort = 7229;
        strDataDir = "testnet";

        strNetworkID = "testnet"; // Do not use the const string because of ctor execution order issues
        nDefaultPort = NEXA_TESTNET_PORT;
        nPruneAfterHeight = 100000;
        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<uint8_t>(1, 111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<uint8_t>(1, 196);
        base58Prefixes[SECRET_KEY] = std::vector<uint8_t>(1, 239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};
        base58Prefixes[SCRIPT_TEMPLATE_ADDRESS] = std::vector<unsigned char>(1, 8);
        cashaddrPrefix = "nexatest";

        consensus.nSubsidyHalvingInterval = 210000 * 5; // 2 minute blocks rather than 10 min -> * 5
        uint32_t tgtBits = 0x1e0fffff;
        bool fNegative;
        bool fOverflow;
        arith_uint256 tmp;
        tmp.SetCompact(tgtBits, &fNegative, &fOverflow);
        consensus.powLimit = ArithToUint256(tmp);
        // consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetSpacing = 2 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.powAlgorithm = 1;
        consensus.initialSubsidy = 10 * 1000000 * COIN;
        consensus.coinbaseMaturity = COINBASE_MATURITY_TESTNET;
        // The half life for the ASERT DAA. For every (nASERTHalfLife) seconds behind schedule the blockchain gets,
        // difficulty is cut in half. Doubled if blocks are ahead of schedule.
        // Two days (in seconds)
        consensus.nASERTHalfLife = 2 * 24 * 60 * 60;

        consensus.nextForkActivationTime = NEXT_FORK_ACTIVATION_TIME;

        std::vector<unsigned char> nonce;
        std::vector<unsigned char> hardCodedNonce;
        nonce = hardCodedNonce = ParseHex("132a25");
        genesis = CreateGenesisBlock("this is nexa testnet", CScript() << OP_1, 1649953806, nonce, tgtBits, 0 * COIN);
#if 0 // recalculate GB if needed (note that this code will not work with the java nexa shared library because it
      // must start before the random numbers (initialized in ECC_Start are hooked up).
        ECC_Start();
        bool worked = MineIt(genesis, 1<<23, consensus);
        assert(worked);
        ECC_Stop();
        consensus.hashGenesisBlock = genesis.GetHash();
        if (genesis.nonce != hardCodedNonce)
        {
            printf("testnet nonce changed:  hex:%s\n", HexStr(genesis.nonce).c_str());
            printf("testnet GB hash %s\n", consensus.hashGenesisBlock.GetHex().c_str());
        }
#else // check GB is what is expected
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(
            consensus.hashGenesisBlock == uint256S("508c843a4b98fb25f57cf9ebafb245a5c16468f06519cdd467059a91e7b79d52"));
#endif
        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0x72;
        pchMessageStart[1] = 0x27;
        pchMessageStart[2] = 0x12;
        pchMessageStart[3] = 0x22;

        consensus.nShortBlockWindow = SHORT_BLOCK_WINDOW_TESTNET;
        consensus.nLongBlockWindow = LONG_BLOCK_WINDOW_TESTNET;
        consensus.nBlockSizeMultiplier = BLOCK_SIZE_MULTIPLIER;
        consensus.nNextMaxBlockSize = DEFAULT_NEXT_MAX_BLOCK_SIZE_FORK1;

        consensus.tailstorm_k = TAILSTORM_K;
        consensus.tailstormEnforceDepth = DEPTH_TO_ENFORCE_CORRECT_SUBBLOCKS;

        vFixedSeeds.clear();
        vSeeds.clear();
        vSeeds.push_back(CDNSSeedData("bitcoinunlimited.info", "nexa-testnet-seeder.bitcoinunlimited.info", true));
        vSeeds.push_back(CDNSSeedData("nexa.org", "testnetseeder.nexa.org", true));
        vFixedSeeds = std::vector<SeedSpec6>();

        // clang-format off
        // checkpoint related to various network upgrades need to be the first block
        // for which the new rules are enforced, hence activation height + 1, where activation
        // height is the first block for which MTP <= upgrade activation time
        checkpointData = CCheckpointData();
        MapCheckpoints &checkpoints = checkpointData.mapCheckpoints;
        checkpoints[100000] = uint256S("0x0acb69c056c86b62bc788bab58f5ed95f7c8cda63326b23e1d8cb349e1b5257f");
        // clang-format on

        // * UNIX timestamp of last checkpoint block
        checkpointData.nTimeLastCheckpoint = 1661700138;

        nBlockFileSize = 0x8000000ULL; // 128MiB
        nUndoFileSize = 0x800000ULL; // 8MiB
    }
};
CTestNetParams testNetParams;

class CStormParams : public CChainParams
{
public:
    CStormParams()
    {
        nRPCPort = 7231;

        strNetworkID = "stormtest"; // Do not use the const string because of ctor execution order issues
        nDefaultPort = NEXA_STORMTEST_PORT;
        nPruneAfterHeight = 100000;
        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = false;
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 25); // P2PKH addresses begin with B
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 68); // P2SH  addresses begin with U
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 35); // WIF   format begins with 2B or 2C
        base58Prefixes[EXT_PUBLIC_KEY] = {0x42, 0x69, 0x67, 0x20};
        base58Prefixes[EXT_SECRET_KEY] = {0x42, 0x6c, 0x6b, 0x73};
        // use 8 for prefix of N in base58
        // 19 for n in bech32
        base58Prefixes[SCRIPT_TEMPLATE_ADDRESS] = std::vector<unsigned char>(1, 8);
        cashaddrPrefix = strNetworkID;

        consensus.nSubsidyHalvingInterval = 210000 * 5; // 2 minute blocks rather than 10 min -> * 5
        std::vector<unsigned char> nonce;
        std::vector<unsigned char> hardCodedNonce;

        uint256 hashGenesis;
#if 0
        // slower mining like -testnet: use fPowNoRetargeting = false;
        uint32_t tgtBits = 506382016;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        nonce = hardCodedNonce = ParseHex("82333300");
        hashGenesis = uint256S("9d5165fd725811a2fcc4519735d79e7c7ea38d1b97d4ab4ce8d2b9a2b78e8fe9");
#else
        // faster mining of nearly 1 per second- use fPowNoReTargeting = true;
        uint32_t tgtBits = 0x1f0effff;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        nonce = hardCodedNonce = ParseHex("e8382500");
        hashGenesis = uint256S("0c33d2c4023d3071f4f71741556a0c4585586d28804f991d9266a2ee4aab58e6");
#endif

        bool fNegative;
        bool fOverflow;
        arith_uint256 tmp;
        tmp.SetCompact(tgtBits, &fNegative, &fOverflow);
        consensus.powLimit = ArithToUint256(tmp);
        consensus.nPowTargetSpacing = 2 * 60;
        consensus.powAlgorithm = 1;
        consensus.initialSubsidy = 10 * 1000000 * COIN;
        consensus.coinbaseMaturity = COINBASE_MATURITY_TESTNET;
        consensus.nextForkActivationTime = NEXT_FORK_ACTIVATION_TIME;

        // The half life for the ASERT DAA. For every (nASERTHalfLife) seconds behind schedule the blockchain gets,
        // difficulty is cut in half. Doubled if blocks are ahead of schedule.
        // Two days (in seconds)
        consensus.nASERTHalfLife = 2 * 24 * 60 * 60;

        genesis = CreateGenesisBlock("this is nexa stormtest", CScript() << OP_1, 1626275623, nonce, tgtBits, 0 * COIN);
        // Uncomment this code block when you want to enable extremely fast mining like found on regtest
        /*
        {
            consensus.fPowAllowMinDifficultyBlocks = true;
            consensus.fPowNoRetargeting = true;
            consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
            nonce.resize(1);
            nonce[0] = 5;
            hashGenesis = uint256S("d71ee431e307d12dfef31a6b21e071f1d5652c0eb6155c04e3222612c9d0b371");
            genesis = CreateGenesisBlock("This is regtest", CScript() << OP_1, 1626275623, nonce, 0x207fffff, 0 * COIN);
        }
        */

#if 0
        // recalculate GB if needed (note that this code will not work with the java nexa shared library because it
        // must start before the random numbers (initialized in ECC_Start are hooked up).
        ECC_Start();
        bool worked = MineIt(genesis, 1 << 23, consensus);
        assert(worked);
        ECC_Stop();
        consensus.hashGenesisBlock = genesis.GetHash();
        if (genesis.nonce != hardCodedNonce)
        {
            printf("stormtest nonce changed:  hex:%s\n", HexStr(genesis.nonce).c_str());
            printf("stormtest GB hash %s\n", consensus.hashGenesisBlock.GetHex().c_str());
        }
#else
        // check GB is what is expected
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == hashGenesis);
#endif
        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0x72;
        pchMessageStart[1] = 0x27;
        pchMessageStart[2] = 0x13;
        pchMessageStart[3] = 0x23;

        consensus.nShortBlockWindow = SHORT_BLOCK_WINDOW;
        consensus.nLongBlockWindow = LONG_BLOCK_WINDOW;
        consensus.nBlockSizeMultiplier = BLOCK_SIZE_MULTIPLIER;
        consensus.nNextMaxBlockSize = DEFAULT_NEXT_MAX_BLOCK_SIZE_FORK1;

        consensus.tailstorm_k = 4;
        consensus.tailstormEnforceDepth = DEPTH_TO_ENFORCE_CORRECT_SUBBLOCKS;

        vFixedSeeds.clear();
        vSeeds.clear();
        // vSeeds.push_back(CDNSSeedData("nextchain.cash", "seed.nextchain.cash", true));
        // vSeeds.push_back(CDNSSeedData("nexa.org", "seeder.nexa.org", true));
        // vSeeds.push_back(CDNSSeedData("bitcoinunlimited.info", "nexa-seeder.bitcoinunlimited.info", true));

        // vFixedSeeds = std::vector<SeedSpec6>();

        // clang-format off
        // checkpoint related to various network upgrades need to be the first block
        // for which the new rules are enforced, hence activation height + 1, where activation
        // height is the first block for which MTP <= upgrade activation time
        checkpointData = (CCheckpointData){{{0, consensus.hashGenesisBlock}}, 0};

        // clang-format on


        nBlockFileSize = 0x8000000ULL; // 128MiB
        nUndoFileSize = 0x800000ULL; // 8MiB
    }
};
CStormParams stormTestParams;

class CNexaParams : public CChainParams
{
public:
    CNexaParams()
    {
        nRPCPort = 7227;

        strNetworkID = "nexa"; // Do not use the const string because of ctor execution order issues
        nDefaultPort = NEXA_PORT;
        nPruneAfterHeight = 100000;
        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = false;
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 25); // P2PKH addresses begin with B
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 68); // P2SH  addresses begin with U
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 35); // WIF   format begins with 2B or 2C
        base58Prefixes[EXT_PUBLIC_KEY] = {0x42, 0x69, 0x67, 0x20};
        base58Prefixes[EXT_SECRET_KEY] = {0x42, 0x6c, 0x6b, 0x73};
        // use 8 for prefix of N in base58
        // 19 for n in bech32
        base58Prefixes[SCRIPT_TEMPLATE_ADDRESS] = std::vector<unsigned char>(1, 8);
        cashaddrPrefix = strNetworkID;

        consensus.nSubsidyHalvingInterval = 210000 * 5; // 2 minute blocks rather than 10 min -> * 5
        uint32_t tgtBits = 503382016;
        bool fNegative;
        bool fOverflow;
        arith_uint256 tmp;
        tmp.SetCompact(tgtBits, &fNegative, &fOverflow);
        consensus.powLimit = ArithToUint256(tmp);
        // consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetSpacing = 2 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.powAlgorithm = 1;
        consensus.initialSubsidy = 10 * 1000000 * COIN;
        consensus.coinbaseMaturity = COINBASE_MATURITY;
        // The half life for the ASERT DAA. For every (nASERTHalfLife) seconds behind schedule the blockchain gets,
        // difficulty is cut in half. Doubled if blocks are ahead of schedule.
        // Two days (in seconds)
        consensus.nASERTHalfLife = 2 * 24 * 60 * 60;

        consensus.nextForkActivationTime = NEXT_FORK_ACTIVATION_TIME;

        std::vector<unsigned char> nonce; // TODO make this difficulty higher and hard code solution
        std::vector<unsigned char> hardCodedNonce;
        nonce = hardCodedNonce = ParseHex("03001700");
        genesis = CreateGenesisBlock("Reuters: Japan PM Kishida backs BOJ ultra-easy policy while yen worries mount "
                                     "BTC:741711:000000000000000000075f4bc08e1d78a3ab3af8274d13334c0ac2de25309768",
            CScript() << OP_FALSE, 1655812800, nonce, tgtBits, 0);
#if 0 // recalculate GB if needed (note that this code will not work with the java nexa shared library because it
      // must start before the random numbers (initialized in ECC_Start are hooked up).
        ECC_Start();
        bool worked = MineIt(genesis, 10000000UL, consensus);
        assert(worked);
        ECC_Stop();
        consensus.hashGenesisBlock = genesis.GetHash();
        if (genesis.nonce != hardCodedNonce)
        {
            printf("nexa soln %d hex:%s\n", worked, HexStr(genesis.nonce).c_str());
            printf("nexa GB hash %s\n", consensus.hashGenesisBlock.GetHex().c_str());
        }
#else
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(
            consensus.hashGenesisBlock == uint256S("edc7144fe1ba4edd0edf35d7eea90f6cb1dba42314aa85da8207e97c5339c801"));
#endif
        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0x72;
        pchMessageStart[1] = 0x27;
        pchMessageStart[2] = 0x12;
        pchMessageStart[3] = 0x21;

        consensus.nShortBlockWindow = SHORT_BLOCK_WINDOW;
        consensus.nLongBlockWindow = LONG_BLOCK_WINDOW;
        consensus.nBlockSizeMultiplier = BLOCK_SIZE_MULTIPLIER;
        consensus.nNextMaxBlockSize = DEFAULT_NEXT_MAX_BLOCK_SIZE_FORK1;

        consensus.tailstorm_k = TAILSTORM_K;
        consensus.tailstormEnforceDepth = DEPTH_TO_ENFORCE_CORRECT_SUBBLOCKS;

        vFixedSeeds.clear();
        vSeeds.clear();
        vSeeds.push_back(CDNSSeedData("nextchain.cash", "seed.nextchain.cash", true));
        vSeeds.push_back(CDNSSeedData("nexa.org", "seeder.nexa.org", true));
        vSeeds.push_back(CDNSSeedData("bitcoinunlimited.info", "nexa-seeder.bitcoinunlimited.info", true));

        vFixedSeeds = std::vector<SeedSpec6>();

        // clang-format off
        // checkpoint related to various network upgrades need to be the first block
        // for which the new rules are enforced, hence activation height + 1, where activation
        // height is the first block for which MTP <= upgrade activation time
        checkpointData = CCheckpointData();
        MapCheckpoints &checkpoints = checkpointData.mapCheckpoints;
        checkpointData = (CCheckpointData){{{0, consensus.hashGenesisBlock}}, 0};
        checkpoints[57000] = uint256S("0xdda01c756107f5016e88aa9dc1b1896e616462b750dbcbbc91214237f557cb89");
        // first block of 2023 (UTC)
        checkpoints[171593] = uint256S("0x7320015a1da0de3ee16cbfbe2ea2ff0ac595ffdb3627fb69be89e7345b16a4d1");
        // block 200K, feb 2nd 2023
        checkpoints[200000] = uint256S("0x9ef5bc0a4cdd7e894c1a8496b25c206238dca9a4bdf79cca227f1807d37c8d99");
        // block 290K, jun 5 2023
        checkpoints[290000] = uint256S("0xc0f85055e25de9283ed3ebf29f8f06d4fc900f370c478de9f49f089841bc7395");
        // block 373813,  oct 1 2023
        checkpoints[373813] = uint256S("0xfdce97737c792e958030efc545aded1f25996a1eb42d25dfb8363246d5cc04ce");
        // block 766084,  March 31 2025
        checkpoints[766084] = uint256S("0xf8ca73d729b2d30616b2513db99eb15f59056232f633a595a2b90f00cd1c37d3");

        // clang-format on

        // * UNIX timestamp of last checkpoint block
        checkpointData.nTimeLastCheckpoint = 1743423742;

        nBlockFileSize = 0x8000000ULL; // 128MiB
        nUndoFileSize = 0x800000ULL; // 8MiB
    }
};
CNexaParams nexaParams;

CChainParams *pCurrentParams = 0;

const CChainParams &Params()
{
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams &Params(const std::string &chain)
{
    if (chain == CBaseChainParams::LEGACY_UNIT_TESTS)
        return legacyParams;
    else if (chain == CBaseChainParams::TESTNET)
        return testNetParams;
    else if (chain == CBaseChainParams::SCALENET)
        assert(0);
    else if (chain == CBaseChainParams::REGTEST)
        return regTestParams;
    else if (chain == CBaseChainParams::STORMTEST)
        return stormTestParams;
    else if (chain == CBaseChainParams::NEXA)
        return nexaParams;
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string &network)
{
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}


/**
 * Return a modifiable reference to the chain params
 */
CChainParams &ModifiableParams()
{
    assert(pCurrentParams);
    return *pCurrentParams;
}
// bip135 end
