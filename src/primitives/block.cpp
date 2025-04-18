// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/block.h"

#include "arith_uint256.h"
#include "consensus/merkle.h"
#include "crypto/common.h"
#include "hashwrapper.h"
#include "pow.h"
#include "streams.h"
#include "tailstorm.h"
#include "tinyformat.h"
#include "utilstrencodings.h"

uint256 CBlockHeader::GetMiningHeaderCommitment() const
{
    CSHA256Writer miniHeader;
    miniHeader << hashPrevBlock << nBits;
    uint256 miniHash = miniHeader.GetHash();

    CSHA256Writer extHeader;
    extHeader << hashAncestor << hashTxFilter << hashMerkleRoot << nTime << ((uint64_t)height) << chainWork << size
              << txCount << feePoolAmt << utxoCommitment << minerData;
    uint256 extHash = extHeader.GetHash();

    CSHA256Writer commitment;
    commitment << miniHash << extHash;
    uint256 ret = commitment.GetHash();
    return ret;
}


uint256 GetMiningHash(const uint256 &headerCommitment, const std::vector<unsigned char> &nonce)
{
    CHashWriter ret(SER_GETHASH, 0);
    DbgAssert(nonce.size() <= CBlockHeader::MAX_NONCE_SIZE, );
    ret << headerCommitment << nonce;
    uint256 r = ret.GetHash();
    return r;
}

uint64_t CBlockHeader::NumSubblocks() const
{
    auto subblks = ParseMinerData(minerData);
    return subblks.size();
}

uint256 CBlockHeader::GetHash() const
{
    DbgAssert(size != 0, ); // Size must be properly calculated before we can figure out the hash

    // The hash is calculated similarly to the mining header commitment, except that the nonce is included in the
    // extended header.  This means that a very-light client can keep a very small header for uninteresting blocks
    // consisting of the hashPrevBlock, nbits and sha256(extended header).  This data is sufficient to construct
    // the block's identity hash and therefore to prove the chain of blocks and work.
    CSHA256Writer miniHeader;
    miniHeader << hashPrevBlock << nBits;
    CSHA256Writer extHeader;
    extHeader << hashAncestor << hashTxFilter << hashMerkleRoot << nTime << ((uint64_t)height) << chainWork << size
              << txCount << feePoolAmt << utxoCommitment << minerData << nonce;

    CSHA256Writer commitment;
    commitment << miniHeader.GetHash() << extHeader.GetHash();
    uint256 ret = commitment.GetHash();
    return ret;
}

uint256 CBlockHeader::GetMiningHash() const
{
    DbgAssert(size != 0, ); // Size must be properly calculated before we can figure out the hash
    return ::GetMiningHash(GetMiningHeaderCommitment(), nonce);
}

uint256 CBlockHeader::SubblockId() const { return GetMiningHash(); }

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, height=%d, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, txCount=%u "
                   ", size=%d, feePool=%d, nonce=%s, utxo=%s)\n",
        GetHash().ToString(), height, hashPrevBlock.ToString(), hashMerkleRoot.ToString(), nTime, nBits, vtx.size(),
        size, feePoolAmt, HexStr(nonce), HexStr(utxoCommitment));
    for (unsigned int i = 0; i < vtx.size(); i++)
    {
        s << "  " << vtx[i]->ToString() << "\n";
    }
    return s.str();
}

void dbgPrintBlock(CBlock &blk) { printf("%s\n", blk.ToString().c_str()); }

std::string CBlock::GetHex() const
{
    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << *this;
    std::string strHex = HexStr(stream.begin(), stream.end());
    return strHex;
}

void CBlock::UpdateHeader()
{
    txCount = vtx.size();
    hashMerkleRoot = BlockMerkleRoot(*this);
    size = CalculateBlockSize();
}

uint64_t CBlock::CalculateBlockSize() const
{
    uint64_t nonceSerializedSize = nonce.size() + 1; // short array serialization is 1 byte of length + the array
    return ::GetSerializeSize(*this, SER_NETWORK, PROTOCOL_VERSION) - nonceSerializedSize;
}

uint64_t CBlock::GetBlockSize() const
{
    if (size == 0)
    {
        size = CalculateBlockSize();
    }
    return size;
}


arith_uint256 GetWorkForDifficultyBits(uint32_t nBits)
{
    arith_uint256 bnTarget;
    bool fNegative;
    bool fOverflow;
    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);
    if (fNegative || fOverflow || bnTarget == arith_uint256(0))
        return 0;
    // We need to compute 2**256 / (bnTarget+1), but we can't represent 2**256
    // as it's too large for a arith_uint256. However, as 2**256 is at least as large
    // as bnTarget+1, it is equal to ((2**256 - bnTarget - 1) / (bnTarget+1)) + 1,
    // or ~bnTarget / (nTarget+1) + 1.
    return (~bnTarget / (bnTarget + 1)) + 1;
}
