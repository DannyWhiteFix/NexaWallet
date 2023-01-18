// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_PRIMITIVES_BLOCK_H
#define NEXA_PRIMITIVES_BLOCK_H

#include "arith_uint256.h"
#include "primitives/transaction.h"
#include "protocol.h"
#include "satoshiblock.h"
#include "serialize.h"
#include "uint256.h"

class CXThinBlock;
class CThinBlock;
class CompactBlock;
class CGrapheneBlock;
namespace Consensus
{
struct Params;
}

/** Get the work equivalent for the supplied nBits of difficulty */
arith_uint256 GetWorkForDifficultyBits(uint32_t nBits);

/** Nodes collect new transactions into a block, hash them into a hash tree,
 * and scan through nonce values to make the block's hash satisfy proof-of-work
 * requirements.  When they solve the proof-of-work, they broadcast the block
 * to everyone and the block is added to the block chain.  The first transaction
 * in the block is a special one that creates a new coin owned by the creator
 * of the block.
 */

class CBlockHeader
{
public:
    enum
    {
        MAX_NONCE_SIZE = 16
    };

    /** Hash of the parent block */
    uint256 hashPrevBlock;
    /** difficulty target specified in a compact format (see detailed docs for exact format) */
    uint32_t nBits;
    /** Hash of a specific ancestor block (see detailed docs for exact ancestor) */
    uint256 hashAncestor;
    /** Root of the merkle tree containing all transactions in this block */
    uint256 hashMerkleRoot;
    /** commitment to a probabilistic transaction/address filter that allows light clients to discover if they may
        need the block. (e.g. neutrino)
    */
    uint256 hashTxFilter;
    /** miner-reported block creation time in seconds since the epoch */
    uint32_t nTime;

    /** Height of this block */
    // At 2 minute blocks this overflows in (2**32-1)/(30*24*265) = 16343 years (but its serialized as a varint
    // and hashed as a uint64_t anyway)
    uint32_t height;
    /** Cumulative work in the chain */
    uint256 chainWork;
    /** Block size in bytes -- mutable because it is calculated from the other fields */
    mutable uint64_t size;
    /** Number of transactions in the block */
    uint64_t txCount;
    /** quantity of satoshis in fee pool AFTER transaction evaluation (algorithmically determined, but part of hash
        commitment). */
    uint64_t feePoolAmt;
    /** commitment to a data structure containing all unspent coins */
    std::vector<unsigned char> utxoCommitment; // MUST be len 0 for now. MUST be < 128 bytes
    /** miner-specific data -- this is not a free-for all field.  It must follow documented conventions */
    std::vector<unsigned char> minerData; // MUST be len 0 for now
    /** mining nonce */
    // nonce length must be <= 16 bytes.  This means the header hash + nonce fit in 1 sha256 round (with spare room)
    std::vector<unsigned char> nonce;

    /** Convenience function to get the chain work as an arith_uint256 */
    arith_uint256 aChainWork() const { return UintToArith256(chainWork); }
    /** Convenience function to set the chain work from an arith_uint256 */
    void SetChainWork(const arith_uint256 &v) { chainWork = ArithToUint256(v); }

    CBlockHeader() { SetNull(); }
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(hashPrevBlock);
        READWRITE(nBits);
        READWRITE(hashAncestor);
        READWRITE(hashMerkleRoot);
        READWRITE(hashTxFilter);

        READWRITE(nTime);
        READWRITE(VARINT(height));
        READWRITE(chainWork);
        READWRITE(size); // Can't be a varint or it relies on itself.  Does not include the nonce size
        READWRITE(VARINT(txCount));

        READWRITE(VARINT(feePoolAmt));
        READWRITE(utxoCommitment);
        READWRITE(minerData);
        READWRITE(nonce);
    }

    bool operator==(const CBlockHeader &b)
    {
        return (hashPrevBlock == b.hashPrevBlock && hashAncestor == b.hashAncestor &&
                hashMerkleRoot == b.hashMerkleRoot && hashTxFilter == b.hashTxFilter && nTime == b.nTime &&
                nBits == b.nBits && height == b.height && chainWork == b.chainWork && size == b.size &&
                txCount == b.txCount && feePoolAmt == b.feePoolAmt && nonce == b.nonce &&
                utxoCommitment == b.utxoCommitment && minerData == b.minerData);
    }

    void SetNull()
    {
        hashPrevBlock.SetNull();
        hashAncestor.SetNull();
        hashMerkleRoot.SetNull();
        hashTxFilter.SetNull();
        nTime = 0;
        nBits = 0;
        height = 0;
        chainWork.SetNull();
        size = 0;
        txCount = 0;
        feePoolAmt = 0;
        nonce.clear();
        utxoCommitment.clear();
        minerData.clear();
    }

    /** Return true if this data structure is empty */
    bool IsNull() const { return (nBits == 0); }

    /** Hash for identification, not mining */
    uint256 GetHash() const;

    /* The block header is formed by the sha256 of the sha256 of the mini-header and the sha256 of the extended header.
       This allows extra-light (mini-headers only) clients to only keep the mini-header the extended header
       commitment, and the nonce. */

    /** Returns the sha256 of the block header (except nonce),
       which is combined with the nonce to produce the mining target */
    uint256 GetMiningHeaderCommitment() const;

    /** convenient but inefficient for mining.  For mining use GetMiningHeaderCommitment() and loop {
       modify nonce; ::GetMiningHash(...) } */
    uint256 GetMiningHash() const;

    /* Solve this block.  Not for performance use. The function modifies the nonce but does not change its size.
       NOTE: if nonce size is 0 or small, there may be no solution ever found!

       This cannot be a member function because the POW functionality is not included in as many products
       as the block header, so is not part of various libraries.  Instead call the global function:

       bool ::MineBlock(const CBlockHeader& block, int nTries, const Consensus::Params &cparams);
    */

    /** Return the miner-reported time that block was created */
    int64_t GetBlockTime() const { return (int64_t)nTime; }
};

/** Combine a hashed header with a nonce to get the hash value used in proof-of-work calculations */
uint256 GetMiningHash(const uint256 &headerCommitment, const std::vector<unsigned char> &nonce);


class CBlock : public CBlockHeader
{
public:
    // Xpress Validation: (memory only)
    //! Orphans, or Missing transactions that have been re-requested, are stored here.
    std::set<uint256> setUnVerifiedTxns;

    // Xpress Validation: (memory only)
    //! A flag which when true indicates that Xpress validation is enabled for this block.
    bool fXVal;

public:
    // network and disk
    std::vector<CTransactionRef> vtx;

    // memory only
    // 0.11: mutable std::vector<uint256> vMerkleTree;
    mutable bool fChecked;

    CBlock() { SetNull(); }
    CBlock(const CBlockHeader &header)
    {
        SetNull();
        *((CBlockHeader *)this) = header;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(*(CBlockHeader *)this);
        READWRITE(vtx);
    }

    /** Returns the block's height as specified in its header */
    uint64_t GetHeight() const { return height; }

    /** Clear all fields in this object */
    void SetNull()
    {
        CBlockHeader::SetNull();
        vtx.clear();
        fChecked = false;
        fXVal = false;
    }

    /** Return this blocks header */
    const CBlockHeader GetBlockHeader() const { return *this; }

    /** return a human readable description of this block */
    std::string ToString() const;

    /** return the network serialization of this block as a hex string */
    std::string GetHex() const;

    /**
    Return the serialized block size in bytes. This is only done once and then the result stored
    in the header's "size" field for future reference, saving unncessary and expensive serializations.
    The block size does NOT include the nonce size, because the nonce size may change while solving the block
    */
    uint64_t GetBlockSize() const;

    /** Recalculate the block's serialized size, not counting the nonce field */
    uint64_t CalculateBlockSize() const;

    /** Update the header based on changes to the block's contents (i.e. tx added, size changed) */
    void UpdateHeader();
};

/**
 * Used for thin type blocks that we want to reconstruct into a full block. All the data
 * necessary to recreate the block are held within the thinrelay objects which are subsequently
 * stored within this class as smart pointers.
 */
class CBlockThinRelay : public CBlock
{
public:
    //! thinrelay block types: (memory only)
    std::shared_ptr<CThinBlock> thinblock;
    std::shared_ptr<CXThinBlock> xthinblock;
    std::shared_ptr<CompactBlock> cmpctblock;
    std::shared_ptr<CGrapheneBlock> grapheneblock;

    //! Track the current block size during reconstruction: (memory only)
    uint64_t nCurrentBlockSize;

    CBlockThinRelay() { SetNull(); }
    ~CBlockThinRelay() { SetNull(); }
    void SetNull()
    {
        CBlock::SetNull();
        nCurrentBlockSize = 0;
        thinblock.reset();
        xthinblock.reset();
        cmpctblock.reset();
        grapheneblock.reset();
    }
};

/** Describes a place in the block chain to another node such that if the
 * other node doesn't have the same branch, it can find a recent common trunk.
 * The further back it is, the further before the fork it may be.
 */
struct CBlockLocator
{
    std::vector<uint256> vHave;

    CBlockLocator() {}
    CBlockLocator(const std::vector<uint256> &vHaveIn) { vHave = vHaveIn; }
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        int nVersion = s.GetVersion();
        if (!(s.GetType() & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(vHave);
    }

    void SetNull() { vHave.clear(); }
    bool IsNull() const { return vHave.empty(); }
};

typedef std::shared_ptr<CBlock> CBlockRef;
typedef std::shared_ptr<const CBlock> ConstCBlockRef;

static inline CBlockRef MakeBlockRef() { return std::make_shared<CBlock>(); }
template <typename Blk>
static inline CBlockRef MakeBlockRef(Blk &&blkIn)
{
    return std::make_shared<CBlock>(std::forward<Blk>(blkIn));
}

#endif // NEXA_PRIMITIVES_BLOCK_H
