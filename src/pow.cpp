#include "pow.h"

#include "arith_uint256.h"
#include "chain.h"
#include "crypto/sha256.h"
#include "key.h"
#include "primitives/block.h"
#include "uint256.h"
#include "util.h"
#include "validation/forks.h"

static uint256 sha256(uint256 &data)
{
    uint256 ret;
    CSHA256 sha;
    sha.Write(data.begin(), 32);
    sha.Finalize(ret.begin());
    return ret;
}

bool CheckProofOfWork(const uint256 &hash, unsigned int nBits, const Consensus::Params &params)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 target;
    target.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || target == 0 || fOverflow || target > UintToArith256(params.powLimit))
        return false;
    return CheckProofOfWork(hash, target, params, nullptr);
}

bool CheckProofOfWork(uint256 hash,
    const arith_uint256 &bnTarget,
    const Consensus::Params &params,
    arith_uint256 *hashout)
{
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

    auto tmp = UintToArith256(hash);
    if (hashout != nullptr)
        *hashout = tmp;
    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}
