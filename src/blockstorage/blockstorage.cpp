// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "blockstorage.h"

#include "blockcache.h"
#include "chainparams.h"
#include "dbwrapper.h"
#include "fs.h"
#include "init.h"
#include "main.h"
#include "sequential_files.h"
#include "ui_interface.h"
#include "undo.h"
#include "utiltranslate.h"
#include "validation/validation.h"

extern bool AbortNode(CValidationState &state, const std::string &strMessage, const std::string &userMessage = "");
extern std::atomic<bool> fCheckForPruning;
extern CCriticalSection cs_LastBlockFile;
extern std::set<int> setDirtyFileInfo;
extern std::vector<CBlockFileInfo> vinfoBlockFile;
extern int nLastBlockFile;
extern CTweak<uint64_t> pruneIntervalTweak;
extern CTweak<uint64_t> dbcacheTweak;
extern CTweak<uint32_t> maxHeadersToKeepInRAM;
extern std::atomic<uint64_t> nTotalChainTx;

CCriticalSection cs_flushstate;

uint64_t blockfile_chunk_size = DEFAULT_BLOCKFILE_CHUNK_SIZE;
uint64_t undofile_chunk_size = DEFAULT_UNDOFILE_CHUNK_SIZE;

/**
 * Config param to determine what DB type we are using
 */

static void InitBlockIndexDatabases(std::string folder, uint64_t _nBlockTreeDBCache)
{
    // Check if we had scheduled a reindex on last shutdown
    uint64_t nChainTx = 0;
    uint32_t nCurrentBlockIndexVersion = 0;
    try
    {
        // Startup the database with the reindex (wipe database) flag set to false and get the value of nChainTx
        pblocktree = new CBlockTreeDB(_nBlockTreeDBCache, folder, false, false);
        pblockheaders = new CBlockHeadersDB(_nBlockTreeDBCache, folder, false, false);
        bool fScheduledReindex = false;
        bool fRead = pblocktree->ReadReindexing(fScheduledReindex);
        if (fRead && fScheduledReindex)
        {
            fReindex = true;
        }
        nChainTx = pblocktree->GetBestBlockHeaderChainTx();
        nCurrentBlockIndexVersion = pblocktree->GetBlockIndexVersion();
    }
    catch (...)
    {
        LOGA("Block index is corrupt.  Automatically initiating a reindex\n");
        fReindex = true;
    }
    if (fReindex)
    {
        delete pblocktree;
        pblocktree = nullptr;

        delete pblockheaders;
        pblockheaders = nullptr;

        // Restart the index database and wipe the data but re-add the nChainTx after restart.
        pblocktree = new CBlockTreeDB(_nBlockTreeDBCache, folder, false, true);
        pblocktree->WriteBestBlockHeaderChainTx(nChainTx);
        pblocktree->WriteBlockIndexVersion(nCurrentBlockIndexVersion);

        // Restart the database and wipe the data.
        pblockheaders = new CBlockHeadersDB(_nBlockTreeDBCache, folder, false, true);
    }
    nTotalChainTx.store(nChainTx);
}

void InitializeBlockStorage(const int64_t &_nBlockTreeDBCache)
{
    // If not pruning then raise the pre-allocation level to the maximum size. This keeps pruned nodes
    // from allocating very large files when they are not needed yet.
    if (!GetArg("-prune", 0))
    {
        // raise preallocation size of block and undo files
        blockfile_chunk_size = Params().nBlockFileSize;
        undofile_chunk_size = Params().nUndoFileSize;
    }

    blockcache.Init();
    InitBlockIndexDatabases("blocks", _nBlockTreeDBCache);
}

bool WriteBlockToDisk(const ConstCBlockRef pblock,
    CDiskBlockPos &pos,
    const CMessageHeader::MessageStartChars &messageStart,
    const int *pHeight)
{
    if (pHeight)
    {
        blockcache.AddBlock(pblock, *pHeight);
    }
    return WriteBlockToDiskSequential(*pblock, pos, messageStart);
}

ConstCBlockRef ReadBlockFromDisk(const CBlockIndex *pindex, const Consensus::Params &consensusParams)
{
    // First check the in memory cache
    ConstCBlockRef pblock = blockcache.GetBlock(pindex->GetBlockHash());
    if (pblock)
    {
        LOG(THIN | GRAPHENE | CMPCT | BLK, "Retrieved block from memory cache: %s\n",
            pblock->GetHash().ToString().c_str());
        return pblock;
    }
    pblock = ReadBlockFromDiskSequential(pindex->GetBlockPos(), consensusParams);
    if (!pblock)
    {
        return nullptr;
    }
    if (pblock->GetHash() != pindex->GetBlockHash())
    {
        LOGA("ERROR: ReadBlockFromDisk(CBlockRef, CBlockIndex*): GetHash() doesn't match index for %s at %s",
            pindex->ToString(), pindex->GetBlockPos().ToString());
        return nullptr;
    }
    return pblock;
}

bool WriteUndoToDisk(const CBlockUndo &blockundo,
    CDiskBlockPos &pos,
    const CBlockIndex *pindex,
    const CMessageHeader::MessageStartChars &messageStart)
{
    uint256 hashBlock;
    if (pindex)
    {
        hashBlock = pindex->GetBlockHash();
    }
    else
    {
        hashBlock.SetNull();
    }
    return WriteUndoToDiskSequenatial(blockundo, pos, hashBlock, messageStart);
}

/**
 * ReadUndoFromDisk only uses CDiskBlockPos for sequential files, not for blockdb
 */
bool ReadUndoFromDisk(CBlockUndo &blockundo, const CDiskBlockPos &pos, const CBlockIndex *pindex)
{
    if (pindex == nullptr)
    {
        return error("Null block has no undo information");
    }
    return ReadUndoFromDiskSequential(blockundo, pos, pindex->GetBlockHash());
}

/* Calculate the block/rev files that should be deleted to remain under target*/
void FindFilesToPrune(std::set<int> &setFilesToPrune, uint64_t nPruneAfterHeight)
{
    LOCK(cs_LastBlockFile);

    if (chainActive.Tip() == nullptr || nPruneTarget == 0)
    {
        return;
    }
    if ((uint64_t)chainActive.Tip()->height() <= nPruneAfterHeight)
    {
        return;
    }
    uint64_t nLastBlockWeCanPrune = chainActive.Tip()->height() - MIN_BLOCKS_TO_KEEP;
    FindFilesToPruneSequential(setFilesToPrune, nLastBlockWeCanPrune);
}

bool FlushStateToDiskInternal(CValidationState &state,
    FlushStateMode mode,
    bool fFlushForPrune,
    std::set<int> setFilesToPrune)
{
    static int64_t nLastWrite = 0;
    static int64_t nLastFlush = 0;
    static int64_t nLastSetChain = 0;
    static int64_t nLastCoinsCacheReset = 0;
    static size_t nLastMapBlockIndexFlushSize = maxHeadersToKeepInRAM.Value();

    TRY_LOCK(cs_flushstate, lock);
    if (!lock)
        return true;

    int64_t nNow = GetStopwatchMicros();
    // Avoid writing/flushing immediately after startup.
    if (nLastWrite == 0)
    {
        nLastWrite = nNow;
    }
    if (nLastFlush == 0)
    {
        nLastFlush = nNow;
    }
    if (nLastSetChain == 0)
    {
        nLastSetChain = nNow;
    }
    if (nLastCoinsCacheReset == 0)
    {
        nLastCoinsCacheReset = nNow;
    }


    // If possible adjust the max size of the coin cache (nCoinCacheMaxSize) based on current available memory. Do
    // this before determinining whether to flush the cache or not in the steps that follow.
    AdjustCoinCacheSize();

    size_t cacheSize = pcoinsTip->DynamicMemoryUsage();
    static int64_t nSizeAfterLastFlush = 0;
    // The cache is close to the limit. Try to flush and trim.
    bool fCacheCritical = cacheSize > (size_t)nCoinCacheMaxSize;
    // Flush more frequently when we have auto cache sizing is being used
    bool fAutoCache =
        (!dbcacheTweak.Value() && (cacheSize - nSizeAfterLastFlush > (int64_t)nMaxCacheIncreaseSinceLastFlush));
    // It's been a while since we wrote the block index to disk. Do this frequently, so we don't need to redownload
    // after a crash.
    bool fPeriodicWrite =
        (mode == FLUSH_STATE_PERIODIC && nNow > nLastWrite + (int64_t)DATABASE_WRITE_INTERVAL * 1000000) ||
        (IsInitialBlockDownload() && nNow > nLastWrite + (int64_t)IBD_DATABASE_WRITE_INTERVAL * 1000000);
    // It's been very long since we flushed the cache. Do this infrequently, to optimize cache usage.
    bool fPeriodicFlush =
        mode == FLUSH_STATE_PERIODIC && nNow > nLastFlush + (int64_t)DATABASE_FLUSH_INTERVAL * 1000000;
    // Combine all conditions that result in a full cache flush.
    bool fCoinCacheReset = nNow > nLastCoinsCacheReset + (int64_t)DATABASE_FLUSH_INTERVAL * 1000000;
    bool fDoFullFlush =
        (mode == FLUSH_STATE_ALWAYS) || fCacheCritical || fAutoCache || fPeriodicFlush || fCoinCacheReset;
    // if in IBD allow a larger window, otherwise flush the blockindex more often.
    size_t nFlushBlockIndexWindow = IsInitialBlockDownload() ? MAX_HEADERS_RESULTS : maxHeadersToKeepInRAM.Value();
    bool fFlushBlockIndex = ((mapBlockIndex.size() - nLastMapBlockIndexFlushSize) > nFlushBlockIndexWindow);

    // Write blocks and block index to disk.
    if (fDoFullFlush || fPeriodicWrite || fFlushForPrune || fFlushBlockIndex)
    {
        // Depend on nMinDiskSpace to ensure we can write block index
        if (!CheckDiskSpace(0))
        {
            return state.Error("out of disk space");
        }
        // First make sure all block and undo data is flushed to disk.
        FlushBlockFile();
        // Then update all block file information (which may refer to block and undo files).
        {
            int tmpLastBlockFile = 0;
            std::vector<std::pair<int, const CBlockFileInfo *> > vFiles;
            {
                LOCK(cs_LastBlockFile);
                vFiles.reserve(setDirtyFileInfo.size());
                for (std::set<int>::iterator it = setDirtyFileInfo.begin(); it != setDirtyFileInfo.end();)
                {
                    vFiles.push_back(std::make_pair(*it, &vinfoBlockFile[*it]));
                    setDirtyFileInfo.erase(it++);
                }
                tmpLastBlockFile = nLastBlockFile;
            }

            std::vector<const CBlockIndex *> vBlocks;
            vBlocks.reserve(setDirtyBlockIndex.size());
            {
                WRITELOCK(cs_mapBlockIndex);
                vBlocks.insert(vBlocks.begin(), setDirtyBlockIndex.begin(), setDirtyBlockIndex.end());
                setOldDirtyBlockIndex.insert(setDirtyBlockIndex.begin(), setDirtyBlockIndex.end());
                setDirtyBlockIndex.clear();
            }

            if (!pblocktree->WriteBatchSync(vFiles, tmpLastBlockFile, vBlocks))
            {
                return AbortNode(state, "Failed to write to block index database");
            }
            if (!pblockheaders->WriteBatchSync(vFiles, tmpLastBlockFile, vBlocks))
            {
                return AbortNode(state, "Failed to write to block headers database");
            }

            // Trim headers from the in memory blockindex if there are any to trim.
            // We have to check and remove only entries from the old dirty block index otherwise, due to the need
            // to release cs_mapBlockIndex above and reaquire it here, we may end up deleting headers that haven't
            // yet been commited to disk.
            if (!setHeadersToTrim.empty())
            {
                WRITELOCK(cs_mapBlockIndex);
                for (CBlockIndex *pindex : setOldDirtyBlockIndex)
                {
                    if (setHeadersToTrim.count(pindex))
                    {
                        pindex->SetBlockHeader(nullptr);
                        setHeadersToTrim.erase(pindex);
                    }
                }
                nLastMapBlockIndexFlushSize = mapBlockIndex.size();
            }
        }
        // Finally remove any pruned files, this will be empty for blockdb mode
        if (fFlushForPrune)
        {
            UnlinkPrunedFiles(setFilesToPrune);
        }
        nLastWrite = nNow;
    }
    // Flush best chain related state. This can only be done if the blocks / block index write was also done.
    if (fDoFullFlush)
    {
        // Typical Coin structures on disk are around 48 bytes in size.
        // Pushing a new one to the database can cause it to be written
        // twice (once in the log, and once in the tables). This is already
        // an overestimation, as most will delete an existing entry or
        // overwrite one. Still, use a conservative safety factor of 2.
        if (!CheckDiskSpace(48 * 2 * 2 * pcoinsTip->GetCacheSize()))
        {
            return state.Error("out of disk space");
        }
        // Flush the chainstate (which may refer to block index entries).
        if (!pcoinsTip->Flush())
        {
            return AbortNode(state, "Failed to write to coin database");
        }
        nLastFlush = nNow;
        // Trim any excess entries from the cache if needed.  If chain is not syncd then
        // trim extra so that we don't flush as often during IBD.
        if (IsChainNearlySyncd() && !fReindex && !fImporting)
        {
            pcoinsTip->Trim(nCoinCacheMaxSize * .95);
        }
        else if (!dbcacheTweak.Value())
        {
            // When no dbcache setting is in place then we default to flushing the cache
            // more frequently to support the automatic cache sizing function. If we don't
            // do this, then when flush time comes we can easily exceed the maxiumum memory,
            // particularly on Windows systems.
            // Trim, but never trim more than nMaxCacheIncreaseSinceLastFlush
            size_t nTrimSize = nCoinCacheMaxSize * .90;
            if (nCoinCacheMaxSize - nMaxCacheIncreaseSinceLastFlush > nTrimSize)
            {
                if (nCoinCacheMaxSize > (int64_t)nMaxCacheIncreaseSinceLastFlush)
                    nTrimSize = nCoinCacheMaxSize - nMaxCacheIncreaseSinceLastFlush;
            }
            pcoinsTip->Trim(nTrimSize);
        }
        else
        {
            // During IBD this is gives optimal performance, particularly on systems with
            // spinning disk. This is because we keep the number of databaase compactions
            // to a minimum.
            pcoinsTip->Trim(nCoinCacheMaxSize * .90);
        }

        nSizeAfterLastFlush = pcoinsTip->DynamicMemoryUsage();
    }
    if (fDoFullFlush || fFlushForPrune ||
        ((mode == FLUSH_STATE_ALWAYS || mode == FLUSH_STATE_PERIODIC) &&
            nNow > nLastSetChain + (int64_t)DATABASE_WRITE_INTERVAL * 1000000))
    {
        // Update best block in wallet (so we can detect restored wallets).
        GetMainSignals().SetBestChain(chainActive.GetLocator());
        nLastSetChain = nNow;
    }

    // As a safeguard, periodically check and correct any drift in the value of cachedCoinsUsage.  While a
    // correction should never be needed, resetting the value allows the node to continue operating, and only
    // an error is reported if the new and old values do not match.
    if (fCoinCacheReset)
    {
        pcoinsTip->ResetCachedCoinUsage();
        nLastCoinsCacheReset = nNow;
    }
    return true;
}

/**
 * Update the on-disk chain state.
 * The caches and indexes are flushed depending on the mode we're called with
 * if they're too large, if it's been a while since the last write,
 * or always and in all cases if we're in prune mode and are deleting files.
 */
bool FlushStateToDisk(CValidationState &state, FlushStateMode mode)
{
    const CChainParams &chainparams = Params();
    std::set<int> setFilesToPrune;
    bool fFlushForPrune = false;
    try
    {
        if (fPruneMode && fCheckForPruning && !fReindex)
        {
            FindFilesToPrune(setFilesToPrune, chainparams.PruneAfterHeight());
            fCheckForPruning = false;
            if (!setFilesToPrune.empty())
            {
                fFlushForPrune = true;

                LOCK(cs_LastBlockFile);
                if (!fHavePruned)
                {
                    pblocktree->WriteFlag("prunedblockfiles", true);
                    fHavePruned = true;
                }
            }
        }
        return FlushStateToDiskInternal(state, mode, fFlushForPrune, setFilesToPrune);
    }
    catch (const std::runtime_error &e)
    {
        if (ShutdownRequested())
            return false;
        else
            return AbortNode(state, std::string("System error while flushing: ") + e.what());
    }
}

void FlushStateToDisk()
{
    CValidationState state;
    FlushStateToDisk(state, FLUSH_STATE_ALWAYS);
}

void PruneAndFlush()
{
    CValidationState state;
    fCheckForPruning = true;
    FlushStateToDisk(state, FLUSH_STATE_NONE);
}

bool FindBlockPos(CValidationState &state,
    CDiskBlockPos &pos,
    uint64_t nAddSize,
    unsigned int nHeight,
    uint64_t nTime,
    bool fKnown)
{
    LOCK(cs_LastBlockFile);

    unsigned int nFile = fKnown ? pos.nFile : nLastBlockFile;
    if (vinfoBlockFile.size() <= nFile)
    {
        vinfoBlockFile.resize(nFile + 1);
    }

    if (!fKnown)
    {
        while (
            (vinfoBlockFile[nFile].nSize != 0) && (vinfoBlockFile[nFile].nSize + nAddSize >= Params().nBlockFileSize))
        {
            nFile++;
            if (vinfoBlockFile.size() <= nFile)
            {
                vinfoBlockFile.resize(nFile + 1);
            }
        }
        pos.nFile = nFile;
        pos.nPos = vinfoBlockFile[nFile].nSize;
    }

    if ((int)nFile != nLastBlockFile)
    {
        if (!fKnown)
        {
            LOGA("Leaving block file %i: %s\n", nLastBlockFile, vinfoBlockFile[nLastBlockFile].ToString());
        }
        FlushBlockFile(!fKnown);
        nLastBlockFile = nFile;
    }

    vinfoBlockFile[nFile].AddBlock(nHeight, nTime);
    if (fKnown)
    {
        vinfoBlockFile[nFile].nSize = std::max(pos.nPos + nAddSize, vinfoBlockFile[nFile].nSize);
    }
    else
    {
        vinfoBlockFile[nFile].nSize += nAddSize;
    }

    if (!fKnown)
    {
        uint64_t nOldChunks = (pos.nPos + blockfile_chunk_size - 1) / blockfile_chunk_size;
        uint64_t nNewChunks = (vinfoBlockFile[nFile].nSize + blockfile_chunk_size - 1) / blockfile_chunk_size;
        if (nNewChunks > nOldChunks)
        {
            if (fPruneMode)
            {
                fCheckForPruning = true;
            }
            {
                if (CheckDiskSpace(nNewChunks * blockfile_chunk_size - pos.nPos))
                {
                    FILE *file = OpenBlockFile(pos);
                    if (file)
                    {
                        LOGA("Pre-allocating blockfile up to position 0x%x in blk%05u.dat\n",
                            nNewChunks * blockfile_chunk_size, pos.nFile);
                        AllocateFileRange(file, pos.nPos, nNewChunks * blockfile_chunk_size - pos.nPos);
                        fclose(file);
                    }
                }
                else
                    return state.Error("out of disk space");
            }
        }
    }

    setDirtyFileInfo.insert(nFile);
    return true;
}

bool FindUndoPos(CValidationState &state, int nFile, CDiskBlockPos &pos, uint64_t nAddSize)
{
    pos.nFile = nFile;

    LOCK(cs_LastBlockFile);

    uint64_t nNewSize;
    pos.nPos = vinfoBlockFile[nFile].nUndoSize;
    nNewSize = vinfoBlockFile[nFile].nUndoSize += nAddSize;
    setDirtyFileInfo.insert(nFile);

    uint64_t nOldChunks = (pos.nPos + undofile_chunk_size - 1) / undofile_chunk_size;
    uint64_t nNewChunks = (nNewSize + undofile_chunk_size - 1) / undofile_chunk_size;
    if (nNewChunks > nOldChunks)
    {
        if (fPruneMode)
        {
            fCheckForPruning = true;
        }
        {
            if (CheckDiskSpace(nNewChunks * undofile_chunk_size - pos.nPos))
            {
                FILE *file = OpenUndoFile(pos);
                if (file)
                {
                    LOGA("Pre-allocating undofile up to position 0x%x in rev%05u.dat\n",
                        nNewChunks * undofile_chunk_size, pos.nFile);
                    AllocateFileRange(file, pos.nPos, nNewChunks * undofile_chunk_size - pos.nPos);
                    fclose(file);
                }
            }
            else
            {
                return state.Error("out of disk space");
            }
        }
    }

    return true;
}
