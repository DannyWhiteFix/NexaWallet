// Copyright (c) 2016-2023 The Bitcoin Unlimited Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// All global variables that have construction/destruction dependencies
// must be placed in this file so that the ctor/dtor order is correct.

// Independent global variables may be placed here for organizational
// purposes.

#include "addrman.h"
#include "blockrelay/blockrelay_common.h"
#include "blockrelay/compactblock.h"
#include "blockrelay/graphene.h"
#include "blockrelay/mempool_sync.h"
#include "blockrelay/thinblock.h"
#include "blockstorage/blockcache.h"
#include "capd/capd.h"
#include "chain.h"
#include "chainparams.h"
#include "clientversion.h"
#include "consensus/consensus.h"
#include "consensus/params.h"
#include "consensus/validation.h"
#include "dosman.h"
#include "fastfilter.h"
#include "leakybucket.h"
#include "main.h"
#include "miner.h"
#include "netbase.h"
#include "nodestate.h"
#include "policy/policy.h"
#include "primitives/block.h"
#include "requestManager.h"
#include "respend/respendrelayer.h"
#include "rpc/server.h"
#include "script/standard.h"
#include "stat.h"
#include "sync.h"
#include "threadgroup.h"
#include "timedata.h"
#include "tinyformat.h"
#include "tweak.h"
#include "txadmission.h"
#include "txmempool.h"
#include "txorphanpool.h"
#include "ui_interface.h"
#include "util.h"
#include "utilstrencodings.h"
#include "utiltime.h"
#include "validation/parallel.h"
#include "validation/validation.h"
#include "validationinterface.h"
#include "version.h"
#include "versionbits.h"

// The group token cache can and should be compiled even when the wallet is disabled.
#include "wallet/grouptokencache.h"

#ifdef ENABLE_WALLET
#include "wallet/grouptokenwallet.h"
#include "wallet/wallet.h"
#endif

#include <atomic>
#include <boost/lexical_cast.hpp>
#include <chrono>
#include <inttypes.h>
#include <iomanip>
#include <list>
#include <queue>
#include <thread>

using namespace std;

#ifdef DEBUG_LOCKORDER
std::atomic<bool> lockdataDestructed{false};
LockData lockdata;
#endif

CAmount GROUPED_SATOSHI_AMT = 0;

// this flag is set to true when a wallet rescan has been invoked.
std::atomic<bool> fRescan{false};

/** Are we importing block files */
std::atomic<bool> fImporting{false};

/** Is a reindex in progress */
std::atomic<bool> fReindex{false};

/** Should we verify the database */
std::atomic<bool> fVerifyDB{false};

/** Indicates whether we should check if there are
 *  block/undo files that should be deleted.  Set on startup
 *  or if we allocate more file space when we're in prune mode
 */
std::atomic<bool> fCheckForPruning = false;

/** The largest next max block size found in the block index */
std::atomic<uint64_t> nLargestNextMaxBlockSize{0};

CStatusString statusStrings;

CCriticalSection cs_nTimeOffset;
int64_t nTimeOffset = 0;

CCriticalSection cs_rpcWarmup;

/** Dirty block index and mapBlockIndex are under the same lock. Once an new entry is made into
 *  mapBlockIndex then there is also a new entry in setDirtyBlockIndex.  The dirty block index
 *  is written later to disk when it's convenient with tracking for headers that need to be
 *  trimmed held in setOldDirtyBlockIndex.
 */
uint64_t nDiskBlockIndexVersion = 0;
CSharedCriticalSection cs_mapBlockIndex;
BlockMap mapBlockIndex GUARDED_BY(cs_mapBlockIndex);
std::set<CBlockIndex *> setDirtyBlockIndex GUARDED_BY(cs_mapBlockIndex);
std::set<CBlockIndex *> setOldDirtyBlockIndex GUARDED_BY(cs_mapBlockIndex);
// The set of blockindex values which are to have their headers trimmed from memory. This is a RAM saving feature.
std::set<const CBlockIndex *> setHeadersToTrim GUARDED_BY(cs_mapBlockIndex);
/** All pairs A->B, where A (or one of its ancestors) misses transactions, but B has transactions.
 * Pruned nodes may have entries where B is missing data.
 */
std::multimap<CBlockIndex *, CBlockIndex *> mapBlocksUnlinked GUARDED_BY(cs_mapBlockIndex);

std::atomic<CBlockIndex *> pindexBestHeader{nullptr};
std::atomic<CBlockIndex *> pindexBestInvalid{nullptr};

// This value (the number of transactions in the chain) is loaded at startup the the blocktree
// database if we're reindexing. It is needed to determine the amount of work we have to do for the reindex.
std::atomic<uint64_t> nTotalChainTx{0};

// The max allowed size of the in memory UTXO cache.
std::atomic<int64_t> nCoinCacheMaxSize{0};

// Indicates whether we're doing mempool tests or not when updating transaction chain state. This helps to simplify
// our unit testing and checking for dirty vs non-dirty states.
std::atomic<bool> fMempoolTests{false};

// The maximum buffer sizes allowed when sending and receving net messages
uint64_t nMaxReceiveBufferSize = 0;
uint64_t nMaxSendBufferSize = 0;

// Are we checking priority when doing tx admission
bool fRelayPriority = false;

// Are we printing out priority when mining a block.
bool fPrintPriority = false;

// Are we doing network message testing
uint32_t nFuzzMessages = 0;
uint32_t nDropMessages = 0;

CChain chainActive; // chainActive.Tip() is lock free, other APIs take the internal lock cs_chainLock

CFeeRate minRelayTxFee = CFeeRate(DEFAULT_MIN_RELAY_TX_FEE); // lock free - has an internal atomic value

/** A cache to store headers that have arrived but can not yet be connected **/
CCriticalSection csUnconnectedHeaders;
std::map<uint256, std::pair<CBlockHeader, int64_t> > mapUnConnectedHeaders GUARDED_BY(csUnconnectedHeaders);

CCriticalSection cs_main;
/**
 * Every received block is assigned a unique and increasing identifier, so we
 * know which one to give priority in case of a fork.
 */
/** Blocks loaded from disk are assigned id 0, so start the counter at 1. */
uint64_t nBlockSequenceId GUARDED_BY(cs_main) = 1;
/**
 * Sources of received blocks, saved to be able to send them reject
 * messages or ban them when processing happens afterwards. Protected by
 * cs_main.
 */
std::map<uint256, NodeId> mapBlockSource GUARDED_BY(cs_main);

/** Unguarded global state that gets modified only once during node startup */
bool fWhiteListRelay = false;
bool fWhiteListForceRelay = false;
bool fPruneMode = false;
uint64_t nPruneTarget = 0;
bool fTxIndex = false;
bool fIsBareMultisigStd = DEFAULT_PERMIT_BAREMULTISIG;
uint32_t nBytesPerSigOp = DEFAULT_BYTES_PER_SIGOP;
bool fCheckBlockIndex = false;
bool fCheckpointsEnabled = DEFAULT_CHECKPOINTS_ENABLED;
uint32_t nXthinBloomFilterSize = SMALLEST_MAX_BLOOM_FILTER_SIZE;
bool fBlocksOnly = DEFAULT_BLOCKSONLY;

CCriticalSection cs_LastBlockFile;
/** Dirty block file entries. */
std::set<int> setDirtyFileInfo GUARDED_BY(cs_LastBlockFile);
std::vector<CBlockFileInfo> vinfoBlockFile GUARDED_BY(cs_LastBlockFile);
int nLastBlockFile GUARDED_BY(cs_LastBlockFile) = 0;
uint64_t nDBUsedSpace GUARDED_BY(cs_LastBlockFile) = 0;
bool fHavePruned GUARDED_BY(cs_LastBlockFile) = false;

/** Hold current block templates size and transaction counts */
CCriticalSection csCurrentCandidate;
uint64_t nLastBlockTx GUARDED_BY(csCurrentCandidate) = 0;
uint64_t nLastBlockSize GUARDED_BY(csCurrentCandidate) = 0;

/** Holds temporary mining candidates */
CCriticalSection csMiningCandidates;
map<int64_t, CMiningCandidate> miningCandidatesMap GUARDED_BY(csMiningCandidates);

/** Flags for coinbase transactions we create */
CCriticalSection cs_coinbaseFlags;
CScript COINBASE_FLAGS;

/**
 * Filter for transactions that were recently rejected by
 * AcceptToMemoryPool. These are not rerequested until the chain tip
 * changes, at which point the entire filter is reset. Does not need mutex
 * protection.
 *
 * Without this filter we'd be re-requesting txs from each of our peers,
 * increasing bandwidth consumption considerably. For instance, with 100
 * peers, half of which relay a tx we don't accept, that might be a 50x
 * bandwidth increase. A flooding attacker attempting to roll-over the
 * filter using minimum-sized, 60byte, transactions might manage to send
 * 1000/sec if we have fast peers, so we pick 120,000 to give our peers a
 * two minute window to send invs to us.
 *
 * Decreasing the false positive rate is fairly cheap, so we pick one in a
 * million to make it highly unlikely for users to have issues with this
 * filter.
 *
 * Memory used: 1.7MB
 */
CRollingFastFilter<4 * 1024 * 1024> recentRejects;

/**
 * Keep track of transaction which were recently in a block and don't
 * request those again.
 *
 * Note that we dont actually ever clear this - in cases of reorgs where
 * transactions dropped out they were either added back to our mempool
 * or fell out due to size limitations (in which case we'll get them again
 * if the user really cares and re-sends).
 *
 * Does not need mutex protection.
 */
CRollingFastFilter<4 * 1024 * 1024> txRecentlyInBlock;

// Track which transactions we've seen before and attemped to process
CRollingFastFilter<32 * 1024 * 1024> filterTransactionKnown;

CWaitableCriticalSection csBestBlock;
CConditionVariable cvBlockChange;

proxyType proxyInfo[NET_MAX];
proxyType nameProxy;
CCriticalSection cs_proxyInfos;

CCriticalSection cs_mapLocalHost;
map<CNetAddr, LocalServiceInfo> mapLocalHost;

// critical sections from net.cpp
CCriticalSection cs_setservAddNodeAddresses;
CCriticalSection cs_vAddedNodes;
CCriticalSection cs_vUseDNSSeeds;
CCriticalSection cs_mapInboundConnectionTracker;
CCriticalSection cs_vOneShots;

CCriticalSection cs_statMap;

deque<string> vOneShots;
std::map<CNetAddr, ConnectionHistory> mapInboundConnectionTracker;
vector<std::string> vUseDNSSeeds;
vector<std::string> vAddedNodes;
set<CNetAddr> setservAddNodeAddresses;

int nMaxOutConnections = DEFAULT_MAX_OUTBOUND_CONNECTIONS;
uint32_t blockVersion = 0; // Overrides the mined block version if non-zero

std::vector<std::string> BUComments = std::vector<std::string>();
std::string minerComment;

CLeakyBucket receiveShaper(DEFAULT_MAX_RECV_BURST, DEFAULT_AVE_RECV);
CLeakyBucket sendShaper(DEFAULT_MAX_SEND_BURST, DEFAULT_AVE_SEND);
std::chrono::steady_clock CLeakyBucket::clock;

// Variables for statistics tracking, must be before the "requester" singleton instantiation
const char *sampleNames[] = {"sec10", "min5", "hourly", "daily", "monthly"};
int operateSampleCount[] = {30, 12, 24, 30};
int interruptIntervals[] = {30, 30 * 12, 30 * 12 * 24, 30 * 12 * 24 * 30};

std::chrono::milliseconds statMinInterval(10000);
boost::asio::io_context stat_io_service;

// Various caches
CBlockCache blockcache;
CTxMemPool mempool;
CTxOrphanPool orphanpool;
CTokenDescCache tokencache;
CTokenMintCache tokenmint;

std::list<CStatBase *> mallocedStats;
CStatMap statistics;
CTweakMap tweaks;

// Relay map and associated counters
CMapRelay maprelay;

CCriticalSection cs_vNodes;
vector<CNode *> vNodes GUARDED_BY(cs_vNodes);

CCriticalSection cs_vNodesDisconnected;
list<CNode *> vNodesDisconnected GUARDED_BY(cs_vNodesDisconnected);

CSemaphore *semOutbound = nullptr;
CSemaphore *semOutboundAddNode = nullptr; // BU: separate semaphore for -addnodes
CNodeSignals g_signals;
CAddrMan addrman;
CDoSManager dosMan;

// A message queue used for priority messages such as graheneblocks or other thintype block messages
std::atomic<bool> fPriorityRecvMsg{false};
std::atomic<bool> fPrioritySendMsg{false};
CCriticalSection cs_priorityRecvQ;
CCriticalSection cs_prioritySendQ;
deque<pair<CNodeRef, CNetMessage> > vPriorityRecvQ GUARDED_BY(cs_priorityRecvQ);
deque<CNodeRef> vPrioritySendQ GUARDED_BY(cs_prioritySendQ);

// Transaction mempool admission globals

// Transactions that are available to be added to the mempool, and protection
CCriticalSection csTxInQ;
CCond cvTxInQ;

// Finds transactions that may conflict with other pending transactions
CFastFilter<4 * 1024 * 1024> incomingConflicts GUARDED_BY(csTxInQ);

// Tranactions that are waiting for validation and are known not to conflict with others
std::queue<CTxInputData> txInQ GUARDED_BY(csTxInQ);
std::queue<CTxInputData> txOrphanQ GUARDED_BY(csTxInQ);

// Transaction that cannot be processed in this round (may potentially conflict with other tx)
std::queue<CTxInputData> txDeferQ GUARDED_BY(csTxInQ);


// Transactions that have been validated and are waiting to be committed into the mempool
CWaitableCriticalSection cs_CommitQCondVar;
CConditionVariable cvCommitQ GUARDED_BY(cs_CommitQCondVar);
CCriticalSection cs_commitQ;
CIndexedCommitQ *txCommitQ GUARDED_BY(cs_commitQ) = nullptr;

// Control the execution of the parallel tx validation and serial mempool commit phases
CThreadCorral txProcessingCorral;

// Configuration Tweaks

std::string bip135Vote;
CTweakRef<std::string> bip135VoteTweak("mining.vote",
    "Comma separated list of features to vote for in a block's nVersion field (as per BIP135)",
    &bip135Vote,
    &Bip135VoteValidator);

CTweak<uint64_t> pruneIntervalTweak("prune.pruneInterval",
    strprintf("How much block data (in MiB) is written to disk before trying to prune our block storage (default: %ld)",
        DEFAULT_PRUNE_INTERVAL),
    DEFAULT_PRUNE_INTERVAL);

CTweak<uint32_t> netMagic("net.magic", "Network prefix override. if 0 (default), do not override.", 0);

CTweak<uint32_t> randomlyDontInv("net.randomlyDontInv",
    "Skip sending an INV for some percent of transactions (default: 0)",
    0);

CTweakRef<uint64_t> capdPoolSize("cache.maxCapdPool",
    strprintf("Set the counterparty and protocol discovery message pool size (default: %d, 0 disables). "
              "Note that enabling CAPD will only happen for new node connections, and "
              "disabling will make this node silently drop incoming CAPD messages.",
        CapdMsgPool::DEFAULT_MSG_POOL_MAX_SIZE),
    &msgpoolMaxSize,
    &CapdMsgPoolSizeValidator);

CTweak<bool> ignoreNetTimeouts("net.ignoreTimeouts",
    "ignore inactivity timeouts, used during debugging (default: false)",
    false);
CTweakRef<bool> displayArchInSubver("net.displayArchInSubver",
    strprintf("Show box architecture, 32/64bit, in node user agent string (subver) (true/false - default: %d)",
        fDisplayArchInSubver),
    &fDisplayArchInSubver);

CTweak<bool> doubleSpendProofs("net.doubleSpendProofs",
    "Process and forward double spend proofs (default: true)",
    true);

CTweak<uint64_t> coinbaseReserve("mining.coinbaseReserve",
    strprintf("How much space to reserve for the coinbase transaction, in bytes (default: %d)",
        DEFAULT_COINBASE_RESERVE_SIZE),
    DEFAULT_COINBASE_RESERVE_SIZE);
CTweak<uint64_t> maxMiningCandidates("mining.maxCandidates",
    strprintf("How many simultaneous block candidates to track (default: %d)", DEFAULT_MAX_MINING_CANDIDATES),
    DEFAULT_MAX_MINING_CANDIDATES);

CTweak<uint64_t> minMiningCandidateInterval("mining.minCandidateInterval",
    strprintf("Reuse a block candidate if requested within this many seconds (default: %d)",
        DEFAULT_MIN_CANDIDATE_INTERVAL),
    DEFAULT_MIN_CANDIDATE_INTERVAL);

CTweakRef<std::string> miningCommentTweak("mining.comment", "Include this text in a block's coinbase.", &minerComment);

CTweak<uint64_t> miningBlockSize("mining.blockSize",
    strprintf(
        "Maximum block size in bytes.  The maximum block size returned from 'getblocktemplate' will be this "
        "value minus mining.coinbaseReserve. A value of Zero means use the adaptive block size algorithm (default: %d)",
        0),
    0);

CTweak<uint64_t> miningPrioritySize("mining.prioritySize",
    strprintf("Set maximum size, in bytes, of the high-priority/low-fee transaction area within a block(default: %d)",
        DEFAULT_BLOCK_PRIORITY_SIZE),
    DEFAULT_BLOCK_PRIORITY_SIZE);

CTweak<bool> fastBlockTemplate("mining.fastBlockTemplate",
    strprintf("Use the optimized getblocktemplate when the txpool is smaller than max block size (default: %u)",
        DEFAULT_FASTBLOCKTEMPLATE));


CTweakRef<uint64_t> miningForkTime("consensus.fork1Time",
    "Time in seconds since the epoch to initiate the Nexa Fork1 protocol upgrade.  A "
    "setting of 0 will turn on the fork at the appropriate time.",
    &nMiningForkTime,
    &ForkTimeValidator);

// needs to be declared independently with CTweakRef so libraries can use without tweaks.
extern uint64_t maxSatoScriptOps;
extern uint64_t maxScriptTemplateOps;

CTweakRef<uint64_t> maxSatoScriptOpsTweak("test.maxSatoScriptOps",
    strprintf("Maximum number of script operations allowed.  Stack pushes are excepted.  Change for testing only! "
              "(default: %ld)",
        MAX_OPS_PER_SCRIPT),
    &maxSatoScriptOps,
    nullptr);

CTweakRef<uint64_t> maxScriptTemplateOpsTweak("test.maxScriptTemplateOps",
    strprintf(
        "Maximum number of script template operations allowed.  Stack pushes are excepted.  Change for testing only! "
        "(default: %ld)",
        MAX_OPS_PER_SCRIPT_TEMPLATE),
    &maxScriptTemplateOps,
    nullptr);

CTweak<uint64_t> maxSigChecks("test.maxBlockSigChecks",
    strprintf(
        "Override the adaptive consensus parameter specifying the maximum sigchecks in a block. A value of zero means"
        " this override is turned off.  Use for testing only! (default: %ld)",
        0),
    0);

CTweak<bool> parallelTweak("test.parallel", "Turn Parallel Block Validation on or off (default: true)", true);
CTweak<bool> pvtest("test.pvtest",
    strprintf("Slow down input checking to 1 every second (default: %u)", DEFAULT_PV_TESTMODE),
    DEFAULT_PV_TESTMODE);

CTweak<bool> unsafeGetBlockTemplate("mining.unsafeGetBlockTemplate",
    "Allow getblocktemplate to succeed even if the chain tip is old or this node is not connected to other nodes "
    "(default: false)",
    false);

CTweak<bool> xvalTweak("mining.xval",
    strprintf("Turn on/off Xpress Validation when mining a new block(true/false - default: %d)", DEFAULT_XVAL_ENABLED),
    DEFAULT_XVAL_ENABLED);

CTweakRef<int> maxOutConnectionsTweak("net.maxOutboundConnections",
    "Maximum number of outbound connections",
    &nMaxOutConnections,
    &OutboundConnectionValidator);
CTweak<int> maxConnections("net.maxConnections",
    strprintf("Maximum number of connections (default: %d)", DEFAULT_MAX_PEER_CONNECTIONS),
    DEFAULT_MAX_PEER_CONNECTIONS);
CTweak<unsigned int> txRetryInterval("net.txRetryInterval",
    strprintf("How long to wait in microseconds before requesting a transaction from another source (default: %d)",
        DEFAULT_MIN_TX_REQUEST_RETRY_INTERVAL),
    DEFAULT_MIN_TX_REQUEST_RETRY_INTERVAL);
CTweak<unsigned int> blkRetryInterval("net.blockRetryInterval",
    strprintf("How long to wait in microseconds before requesting a block from another source (default: %d)",
        DEFAULT_MIN_BLK_REQUEST_RETRY_INTERVAL),
    DEFAULT_MIN_BLK_REQUEST_RETRY_INTERVAL);

CTweak<unsigned int> blockLookAheadInterval("test.blockLookAheadInterval",
    strprintf(
        "How long to wait in microseconds before requesting a block from another source when we currently downloading "
        "the block from another peer (default: %d)",
        DEFAULT_MIN_BLK_REQUEST_RETRY_INTERVAL),
    DEFAULT_MIN_BLK_REQUEST_RETRY_INTERVAL);

CTweak<uint64_t> maxAllowedNetMessage("test.maxAllowedNetMessage",
    strprintf("What is the maximum allowed net message size in bytes (zero means use adaptive setting, default: %d)",
        0),
    0);

CTweak<uint64_t> nextMaxBlockSize("test.nextMaxBlockSize",
    strprintf("What is the maximum allowed block size in bytes (zero means use adaptive setting, default: %d)", 0),
    0);

CTweakRef<std::string> subverOverrideTweak("net.subversionOverride",
    "If set, this field will override the normal subversion field.  This is useful if you need to hide your node",
    &subverOverride,
    &SubverValidator);

CTweak<unsigned int> numMsgHandlerThreads("net.msgHandlerThreads",
    "Max message handler threads. Auto detection is zero (default: 0).",
    0);
CTweak<unsigned int> numTxAdmissionThreads("net.txAdmissionThreads",
    "Max transaction mempool admission threads Auto detection is zero (default: 0).",
    0);

CTweak<bool> enforceMinTxSize("test.enforceMinTxSize",
    "Whether we will enforce the min tx size limit of 100 bytes or not (default: true)",
    true);

CTweak<bool> allowp2pTxVal("net.allowp2pTxVal",
    strprintf(
        "allow requests to check if a transaction would be accepted into the mempool via p2p message (default: false)"),
    false);

#ifdef ENABLE_WALLET
/** If transactions overpay by less than this amount in Satoshis, the extra will be put in the fee rather than a
    change address.  Zero means calculate this dynamically as a fraction of the current transaction fee
    (recommended). */
CTweak<unsigned int> txWalletDust("wallet.txFeeOverpay",
    "If transactions overpay by less than this amount in Satoshis, the extra will be put in the fee rather than a "
    "change address.  Zero means calculate this dynamically as a fraction of the current transaction fee "
    "(default: 0).",
    0);

/** When sending, how long should this wallet search for a more efficient or no-change payment solution in
    milliseconds.  A no-change solution reduces transaction fees, but is extremely unlikely unless your wallet
    is very large and well distributed because transaction fees add a small quantity of dust to the normal round
    numbers that humans use.
*/
CTweak<unsigned int> maxCoinSelSearchTime("wallet.coinSelSearchTime",
    "When sending, how long should this wallet search for a no-change payment solution in milliseconds.  A no-change "
    "solution reduces transaction fees (default: 25)",
    25);

/** How many UTXOs should be maintained in this wallet (on average).  If the number of UTXOs exceeds this value,
    transactions will be found that tend to have more inputs.  This will consolidate UTXOs.
 */
CTweak<unsigned int> preferredNumUTXO("wallet.preferredNumUTXO",
    "How many UTXOs should be maintained in this wallet (on average).  If the number of UTXOs exceeds this value, "
    "transactions will be found that tend to have more inputs.  This will consolidate UTXOs (default: 5000)",
    5000);

CTweak<bool> useBIP69("wallet.useBIP69",
    strprintf("sort input and outputs of created transactions in lexicographical order (default: true)"),
    true);

CTweak<bool> instantTxns("wallet.instant",
    strprintf("Are coins from unconfirmed transactions instantly spendable from the wallet (default: false)"),
    false);
CTweak<uint32_t> instantTxnsDelay("wallet.instantDelay",
    strprintf("Time in seconds to wait before making an instant transaction spendable (default: %d)",
        DEFAULT_INSTANT_TRANSACTION_DELAY),
    DEFAULT_INSTANT_TRANSACTION_DELAY);
CTweak<uint64_t> instantTxnsLimit("wallet.instantLimit",
    strprintf("The amount of NEX below which a transaction may be considered instantly confirmed. A zero "
              "means that this feature is turned off and all transctions will be candidates. (default: %d)",
        DEFAULT_INSTANT_TRANSACTION_CUTOFF),
    DEFAULT_INSTANT_TRANSACTION_CUTOFF);
CTweak<bool> autoTxns("wallet.auto",
    strprintf("Auto consolidate utxos by creating a valid chain of transactions during transaction creation, with"
              " each transaction not exceeding  the consensus input limit of %d  (default: false)",
        MAX_TX_NUM_VIN),
    false);

/** The maximum fee that can be applied to any one transaction */
CTweak<CAmount> maxTxFeeTweak("wallet.maxTxFee",
    strprintf("Maximum total fees (in satoshis) to use in a single wallet transaction or raw transaction; setting "
              "this too low may abort large transactions (default: %d)",
        DEFAULT_TRANSACTION_MAXFEE),
    DEFAULT_TRANSACTION_MAXFEE);

// A fee you add to every transaction */
CTweak<CAmount> payTxFeeTweak("wallet.payTxFee",
    strprintf("Fee (in sat/KB) to add to transactions you send (default: %s)", DEFAULT_TRANSACTION_FEE),
    DEFAULT_TRANSACTION_FEE);

// Should we get an estimate for how much fee we need to get into the next block */
CTweak<bool> feeEstimationTweak("wallet.feeEstimation",
    strprintf("Is fee estimation turned on (default: %s)", false),
    false);

// Should we get an estimate for how much fee we need to get into the next block */
CTweak<bool> tokenWhitelist("wallet.tokenWhitelist",
    "Is token whitelisting enabled (default in nexad: false, default in QT: true)",
    false,
    &TokenWalletUpdater);

#endif // ENABLE_WALLET

/** Number of blocks that can be requested at any given time from a single peer. */
CTweak<uint64_t> maxBlocksInTransitPerPeer("net.maxBlocksInTransitPerPeer",
    "Number of blocks that can be requested at any given time from a single peer. 0 means use algorithm (default: 0)",
    0);
/** Size of the "block download window": how far ahead of our current height do we fetch?
 *  Larger windows tolerate larger download speed differences between peer, but increase the potential
 *  degree of disordering of blocks on disk (which make reindexing and in the future perhaps pruning
 *  harder). We'll probably want to make this a per-peer adaptive value at some point. */
CTweak<unsigned int> blockDownloadWindow("net.blockDownloadWindow",
    "How far ahead of our current height do we fetch? 0 means use algorithm (default: 0)",
    0);


/** This setting specifies the minimum supported Graphene version (inclusive).
 *  The actual version used will be negotiated between sender and receiver.
 */
std::string grMinVerStr =
    "Minimum Graphene version supported (default: " + std::to_string(GRAPHENE_MIN_VERSION_SUPPORTED) + ")";
CTweak<uint64_t> grapheneMinVersionSupported("net.grapheneMinVersionSupported",
    grMinVerStr,
    GRAPHENE_MIN_VERSION_SUPPORTED);

/** This setting specifies the maximum supported Graphene version (inclusive).
 *  The actual version used will be negotiated between sender and receiver.
 */
std::string grMaxVerStr =
    "Maximum Graphene version supported (default: " + std::to_string(GRAPHENE_MAX_VERSION_SUPPORTED) + ")";
CTweak<uint64_t> grapheneMaxVersionSupported("net.grapheneMaxVersionSupported",
    grMaxVerStr,
    GRAPHENE_MAX_VERSION_SUPPORTED);

/** This setting dictates the peer's Bloom filter compatibility when sending and
 * receiving Graphene blocks. In this implementation, either regular or fast Bloom
 * filters are supported. However, other (or future) implementations may elect to
 * drop support for one or the other.
 */
CTweak<uint64_t> grapheneFastFilterCompatibility("net.grapheneFastFilterCompatibility",
    "Support fast Bloom filter: 0 - either, 1 - fast only, 2 - regular only (default: either)",
    GRAPHENE_FAST_FILTER_SUPPORT);

/** This setting overrides the number of cells (excluding overhead) in the initial IBLT
 * sent using Graphene. The intent is to enable the first stage of the Graphene protocol
 * to fail in order to test the second stage.
 */
CTweak<uint64_t> grapheneIbltSizeOverride("net.grapheneIbltSizeOverride",
    "Override size of Iblt to the indicated value (greater than 0): 0 for optimal (default: 0)",
    0);

/** This setting overrides the false positive rate in the initial Bloom filter sent using
 * Graphene. The intent is to enable the first stage of the Graphene protocol to fail in
 * order to test the second stage.
 */
CTweak<double> grapheneBloomFprOverride("net.grapheneBloomFprOverride",
    "Override size of Bloom filter to the indicated value (greater than 0.0): 0.0 for optimal (default: 0.0)",
    0.0);

CTweak<bool> syncMempoolWithPeers("net.syncMempoolWithPeers", "Synchronize mempool with peers (default: false)", false);

/** This setting specifies the minimum supported mempool sync version (inclusive).
 *  The actual version used will be negotiated between sender and receiver.
 */
std::string memSyncMinVerStr =
    "Minimum mempool sync version supported (default: " + std::to_string(DEFAULT_MEMPOOL_SYNC_MIN_VERSION_SUPPORTED) +
    ")";
CTweak<uint64_t> mempoolSyncMinVersionSupported("net.mempoolSyncMinVersionSupported",
    memSyncMinVerStr,
    DEFAULT_MEMPOOL_SYNC_MIN_VERSION_SUPPORTED);

/** This setting specifies the maximum supported mempool sync version (inclusive).
 *  The actual version used will be negotiated between sender and receiver.
 */
std::string memSyncMaxVerStr =
    "Maximum mempool sync version supported (default: " + std::to_string(DEFAULT_MEMPOOL_SYNC_MAX_VERSION_SUPPORTED) +
    ")";
CTweak<uint64_t> mempoolSyncMaxVersionSupported("net.mempoolSyncMaxVersionSupported",
    memSyncMaxVerStr,
    DEFAULT_MEMPOOL_SYNC_MAX_VERSION_SUPPORTED);

/** This is the initial size of CFileBuffer's RAM buffer during reindex.  A
larger size will result in a tiny bit better performance if blocks are that
size.
The real purpose of this parameter is to exhaustively test dynamic buffer resizes
during reindexing by allowing the size to be set to low and random values.
*/
CTweak<uint64_t> reindexTypicalBlockSize("reindex.typicalBlockSize",
    strprintf("Set larger than the typical block size.  The block data file's RAM buffer will initally be 2x this size "
              "(default: %d)",
        TYPICAL_BLOCK_SIZE),
    TYPICAL_BLOCK_SIZE);

/** This is the initial size of CFileBuffer's RAM buffer during reindex.  A
larger size will result in a tiny bit better performance if blocks are that
size.
The real purpose of this parameter is to exhaustively test dynamic buffer resizes
during reindexing by allowing the size to be set to low and random values.
*/
CTweak<uint64_t> checkScriptDays("blockchain.checkScriptDays",
    strprintf("The number of days in the past we check scripts during initial block download (default: %d)",
        DEFAULT_CHECKPOINT_DAYS),
    DEFAULT_CHECKPOINT_DAYS);

/** depth at which we mark blocks as final */
CTweak<int> maxReorgDepth("blockchain.maxReorgDepth",
    strprintf("After how many new blocks do we consider a block final(default: %ld)", DEFAULT_MAX_REORG_DEPTH),
    DEFAULT_MAX_REORG_DEPTH);

/** How large in MB do we allow in the transaction pool to get */
CTweak<uint64_t> maxTxPool("cache.maxTxPool",
    strprintf("Keep the transaction memory pool below <n> megabytes (default: %u)", DEFAULT_MAX_MEMPOOL_SIZE),
    DEFAULT_MAX_MEMPOOL_SIZE);

/** What is the maximum time, in hours, we keep transactions in the memory pool */
CTweak<uint32_t> txPoolExpiry("cache.txPoolExpiry",
    strprintf("Do not keep transactions in the mempool longer than <n> hours (default: %u)", DEFAULT_MEMPOOL_EXPIRY),
    DEFAULT_MEMPOOL_EXPIRY);

/** How many transactions do we allow in the orphan pool */
CTweak<uint32_t> maxOrphanPool("cache.maxOrphanPool",
    strprintf("Keep at most <n> unconnectable transactions (orphans) in memory (default: %u)",
        DEFAULT_MAX_ORPHAN_TRANSACTIONS),
    DEFAULT_MAX_ORPHAN_TRANSACTIONS);

/** What is the maximum time, in hours, we keep unconnected transactions in the orphan pool */
CTweak<uint32_t> orphanPoolExpiry("cache.orphanPoolExpiry",
    strprintf("Do not keep transactions in the orphanpool longer than <n> hours (default: %u)",
        DEFAULT_ORPHANPOOL_EXPIRY),
    DEFAULT_ORPHANPOOL_EXPIRY);

/** Are we going to save the mempool and orphanpool to disk on shutdown and load them on restart */
CTweak<bool> persistTxPool("cache.persistTxPool",
    strprintf("Whether to save the mempool and orphanpool on shutdown and load them on restart (default: %u)",
        DEFAULT_PERSIST_MEMPOOL),
    DEFAULT_PERSIST_MEMPOOL);

/** What is the maximum time, in hours, we keep unconnected transactions in the orphan pool */
// This tweak is initially set to zero by default, even through the default value is acutally nDefaultDbCache.
// The reason for this is that the automatic dbcache sizing function needs to know whether the user actually
// set a dbcache setting in the config file or not as evidenced by a non-zero value.  If there was no
// configuration set by the operator then in DiscoverCacheConfiguration() the correct cache size value will be returned
// using the auto sizing alogorithm, otherwise the user defined value will be used instead.
CTweak<uint64_t> dbcacheTweak("cache.dbcache",
    strprintf("Set database cache size in megabytes (%d to %d, default: %d). Zero means auto-size the cache.",
        nMinDbCache,
        nMaxDbCache,
        0),
    0);

/** What is the maximum number of headers to keep in the blockindex RAM */
CTweak<uint32_t> maxHeadersToKeepInRAM("cache.maxHeaders",
    strprintf("Maximum headers to keep in RAM (default: %u)", DEFAULT_HEADERS_TO_KEEP_IN_RAM),
    DEFAULT_HEADERS_TO_KEEP_IN_RAM);

/** Dust Threshold (in satoshis) defines the minimum quantity an output may contain for the
    transaction to be considered standard, and therefore relayable.
 */
CTweak<uint32_t> dustThreshold("relay.dustThreshold",
    strprintf("Dust Threshold in satoshis (default: %d)", DEFAULT_DUST_THRESHOLD),
    DEFAULT_DUST_THRESHOLD);

/** The minrelaytxfee (in satoshi's per KB) */
CTweak<uint32_t> minRelayFee("relay.minRelayTxFee",
    strprintf("Fees (in satoshi/KB) smaller than this are considered "
              "zero fee and subject to -relay.limitFreeRelay (default: %ld)",
        DEFAULT_MINRELAYTXFEE),
    DEFAULT_MINRELAYTXFEE);

/** The free relay limit (KB allowed per 1 minute period) */
CTweak<uint32_t> limitFreeRelay("relay.limitFreeRelay",
    strprintf("Continuously rate-limit free transactions to <n>*1000 bytes per minute (default: %u)",
        DEFAULT_LIMITFREERELAY),
    DEFAULT_LIMITFREERELAY);

/** The respend relay limit (KB allowed per 1 minute period) */
CTweak<uint32_t> limitRespendRelay("relay.limitRespendRelay",
    strprintf("Continuously rate-limit double spend transactions to <n>*1000 bytes per minute (default: %u)",
        respend::DEFAULT_LIMITRESPENDRELAY),
    respend::DEFAULT_LIMITRESPENDRELAY);

/** Relay priority */
CTweak<bool> relayPriority("relay.priority",
    strprintf("Require high priority for relaying free or low-fee transactions (default: %u)", DEFAULT_RELAYPRIORITY),
    DEFAULT_RELAYPRIORITY);

/** Data Carrier on/off */
CTweak<bool> dataCarrier("relay.dataCarrier",
    strprintf("Relay and mine OP_RETURN transactions (default: %d)", DEFAULT_ACCEPT_DATACARRIER),
    DEFAULT_ACCEPT_DATACARRIER);

/** The data carrier size in bytes */
CTweak<uint32_t> dataCarrierSize("relay.dataCarrierSize",
    strprintf("Maximum size of OP_RETURN data script in bytes that we relay and mine (default: %u)",
        MAX_OP_RETURN_RELAY),
    MAX_OP_RETURN_RELAY);

/** Disable reconsidermostworkchain during initial bootstrap when chain is not synced.
 * This is for testing purpose only and hence it is disabled by default.
 * This tweak will be useful during multiple clients interop network upgrade tests.
 * During this tests  official testnet is forked via invalidate block, that means that
 * if for what ever reason you need to restart your client during the test, you need to
 * rollbackchain and then reconsiderblock the first block of the forked testnet. This is because
 * if more than 1 block at time have to be invalidated so that the utxo may get undone correctly.
 */
CTweak<bool> avoidReconsiderMostWorkChain("test.avoidReconsiderMostWorkChain",
    "Disable reconsidermostworkchain during initial bootstrap when chain is not synced (default: false)",
    false);

// To test the behavior of the interaction between BU and other nodes that do not support extversion
// it's useful to be able to turn it off.
CTweak<bool> extVersionEnabled("test.extVersion", "Is extended version being used (default: true)", true);

CRequestManager requester; // after the maps nodes and tweaks
CState nodestate;
thread_group threadGroup;

CStatHistory<unsigned int> txAdded; //"memPool/txAdded");
CStatHistory<uint64_t, MinValMax<uint64_t> > poolSize; // "memPool/size",STAT_OP_AVE);
CStatHistory<uint64_t> recvAmt;
CStatHistory<uint64_t> sendAmt;
CStatHistory<uint64_t> nTxValidationTime("txValidationTime", STAT_OP_MAX | STAT_INDIVIDUAL);
CCriticalSection cs_blockvalidationtime;
CStatHistory<uint64_t> nBlockValidationTime("blockValidationTime", STAT_OP_MAX | STAT_INDIVIDUAL);

// Mining
CCriticalSection csMinerTracker;
std::map<std::string, MinerTracker> minerTracker GUARDED_BY(csMinerTracker);

CStatHistory<uint64_t> miningBlocks; //("mining/blocks");
CStatHistory<uint64_t> miningOrphanBlocks; //("mining/orphans");
CStatHistory<uint64_t, MinValMax<uint64_t> > miningNumMiners; //("mining/miners");


// Single classes for gather thin type block relay statistics
CThinBlockData thindata;
CGrapheneBlockData graphenedata;
CCompactBlockData compactdata;
ThinTypeRelay thinrelay;

// Data for doing mempool sync
CCriticalSection cs_mempoolsync;
std::map<NodeId, CMempoolSyncState> mempoolSyncRequested GUARDED_BY(cs_mempoolsync);
std::map<NodeId, CMempoolSyncState> mempoolSyncResponded GUARDED_BY(cs_mempoolsync);

std::atomic<uint64_t> lastMempoolSync{GetStopwatchMicros()};

// Are we shutting down. Replaces boost interrupts.
std::atomic<bool> shutdown_threads{false};

#ifdef ENABLE_MUTRACE
class CPrintSomePointers
{
public:
    CPrintSomePointers()
    {
        printf("csBestBlock %p\n", &csBestBlock);
        printf("cvBlockChange %p\n", &cvBlockChange);
        printf("cs_LastBlockFile %p\n", &cs_LastBlockFile);
        printf("cs_nTimeOffset %p\n", &cs_nTimeOffset);
        printf("cs_rpcWarmup %p\n", &cs_rpcWarmup);
        printf("cs_main %p\n", &cs_main);
        printf("csBestBlock %p\n", &csBestBlock);
        printf("cs_proxyInfos %p\n", &cs_proxyInfos);
        printf("cs_vNodes %p\n", &cs_vNodes);
        printf("cs_mapLocalHost %p\n", &cs_mapLocalHost);
        printf("CNode::cs_totalBytesRecv %p\n", &CNode::cs_totalBytesRecv);
        printf("CNode::cs_totalBytesSent %p\n", &CNode::cs_totalBytesSent);

        // critical sections from net.cpp
        printf("cs_setservAddNodeAddresses %p\n", &cs_setservAddNodeAddresses);
        printf("cs_vAddedNodes %p\n", &cs_vAddedNodes);
        printf("cs_vUseDNSSeeds %p\n", &cs_vUseDNSSeeds);
        printf("cs_mapInboundConnectionTracker %p\n", &cs_mapInboundConnectionTracker);
        printf("cs_vOneShots %p\n", &cs_vOneShots);

        printf("cs_statMap %p\n", &cs_statMap);

        printf("requester.cs_objDownloader %p\n", &requester.cs_objDownloader);

        printf("\nCondition variables:\n");
        printf("cvBlockChange %p\n", &cvBlockChange);
    }
};

static CPrintSomePointers unused;
#endif
