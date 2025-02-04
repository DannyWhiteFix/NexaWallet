#include "script/merkleproof.h"
#include "script/interpreter.h"
#include "script/stackitem.h"
#include <stack>


/** A hasher class for Bitcoin's 256-bit hash (double SHA-256). */
class MpHash
{
protected:
    CSHA256 sha256;
    CRIPEMD160 ripemd160;
    CHash160 hash160;
    CHash256 hash256;

    MerkleRootAlg alg;

public:
    MpHash(MerkleRootAlg a) : alg(a) {}

    void Finalize(unsigned char *hash)
    {
        switch (alg)
        {
        case MerkleRootAlg::SHA256:
        {
            sha256.Finalize(hash);
        }
        break;
        case MerkleRootAlg::RIPEMD160:
        {
            ripemd160.Finalize(hash);
        }
        break;
        case MerkleRootAlg::HASH160:
        {
            hash160.Finalize(hash);
        }
        break;
        case MerkleRootAlg::HASH256:
        {
            hash256.Finalize(hash);
        }
        break;
        default:
            throw script_error(SCRIPT_ERR_INVALID_PARAMETER, "Merkle root algorithm is invalid");
            break;
        }
    }

    MpHash &Write(const unsigned char *data, size_t len)
    {
        switch (alg)
        {
        case MerkleRootAlg::SHA256:
        {
            sha256.Write(data, len);
        }
        break;
        case MerkleRootAlg::RIPEMD160:
        {
            ripemd160.Write(data, len);
        }
        break;
        case MerkleRootAlg::HASH160:
        {
            hash160.Write(data, len);
        }
        break;
        case MerkleRootAlg::HASH256:
        {
            hash256.Write(data, len);
        }
        break;
        default:
            throw script_error(SCRIPT_ERR_INVALID_PARAMETER, "Merkle root algorithm is invalid");
            break;
        }
        return *this;
    }

    MpHash &Reset()
    {
        switch (alg)
        {
        case MerkleRootAlg::SHA256:
        {
            sha256.Reset();
        }
        break;
        case MerkleRootAlg::RIPEMD160:
        {
            ripemd160.Reset();
        }
        break;
        case MerkleRootAlg::HASH160:
        {
            hash160.Reset();
        }
        break;
        case MerkleRootAlg::HASH256:
        {
            hash256.Reset();
        }
        break;
        default:
            throw script_error(SCRIPT_ERR_INVALID_PARAMETER, "Merkle root algorithm is invalid");
            break;
        }
        return *this;
    }
};


static void HashMpLeaf(MerkleRootAlg alg, const VchType in, VchType &out)
{
    if (in.size() == 0) // empty element
    {
        out.resize(0); // hashes to the empty element;
        return;
    }

    switch (alg)
    {
    case MerkleRootAlg::SHA256:
    {
        out.resize(32);
        CSHA256().Write(begin_ptr(in), in.size()).Finalize(begin_ptr(out));
    }
    break;
    case MerkleRootAlg::RIPEMD160:
    {
        out.resize(20);
        CRIPEMD160().Write(begin_ptr(in), in.size()).Finalize(begin_ptr(out));
    }
    break;
    case MerkleRootAlg::HASH160:
    {
        out.resize(20);
        CHash160().Write(begin_ptr(in), in.size()).Finalize(begin_ptr(out));
    }
    break;
    case MerkleRootAlg::HASH256:
    {
        out.resize(32);
        CHash256().Write(begin_ptr(in), in.size()).Finalize(begin_ptr(out));
        CHash256 h;
    }
    break;
    default:
        throw script_error(SCRIPT_ERR_INVALID_PARAMETER, "Merkle root algorithm is invalid");
        break;
    }
}

/*
Format:

  (top of stack is shown last -- basically this means its shown in push order)

  proof elements num_elements option OP_MERKLEROOT ->

  adjacency... (num elements 8-bit bitmaps pushed)
  depth... (num_elements scriptnums pushed)
  index... (num_elements scriptnums pushed)
  merkle root

  If the merkle root cannot be calculated, the script fails.
  If the provided merkle proof does not involve all provided elements, the script fails.
  option, num_elements, and elements can be bytes/scriptnums OR bignums.
  proof must be bytes

  If raw (unhashed) elements are provided the empty stack item (e.g. OP_FALSE) is considered the empty element
  If hashed elements are provided, OP_FALSE or a single byte 0 is considered the empty element
*/

bool ScriptMachine::opMerkleRoot()
{
    // proof, at least 1 element, num_elements, and option
    // But I need to recheck this once I know num_elements
    if (stack.size() < 4)
        return set_error(&error, SCRIPT_ERR_INVALID_STACK_OPERATION);

    // Grab the selected options and make sure its valid
    uint64_t opt = stackItemAt(-1).asUint64(false);
    if ((opt & (~(uint64_t)MerkleRootFlags::USED_BITS)) != 0)
        return set_error(&error, SCRIPT_ERR_INVALID_BIT_RANGE);

    uint64_t num_elements = stackItemAt(-2).asUint64(false);

    if (num_elements < 1) // You need to prove at least one element
        return set_error(&error, SCRIPT_ERR_INVALID_PARAMETER);
    if (num_elements > 256) // Too many elements
        return set_error(&error, SCRIPT_ERR_INVALID_PARAMETER);
    if (stack.size() < 3 + num_elements)
        return set_error(&error, SCRIPT_ERR_INVALID_STACK_OPERATION);

    uint64_t leafAlgSize = 32;
    uint64_t nodeAlgSize = 32;
    MerkleRootAlg nodeAlg = (MerkleRootAlg)(opt & (uint64_t)MerkleRootFlags::ALG_BITS);
    MerkleRootAlg leafAlg = (MerkleRootAlg)((opt >> 8) & (uint64_t)MerkleRootFlags::ALG_BITS);
    if ((leafAlg == MerkleRootAlg::RIPEMD160) || (leafAlg == MerkleRootAlg::HASH160))
        leafAlgSize = 20;
    if ((nodeAlg == MerkleRootAlg::RIPEMD160) || (nodeAlg == MerkleRootAlg::HASH160))
        nodeAlgSize = 20;

    // Incompatible algorithms
    if (nodeAlgSize != leafAlgSize)
        return set_error(&error, SCRIPT_ERR_INVALID_PARAMETER);

    PopStack();
    PopStack();
    // proof and elements... still on the stack

    // load the elements into an array.
    std::vector<VchType> elements(num_elements);

    for (uint64_t i = 0; i < num_elements; i++)
    {
        // If caller does not want to hash the elements, they better already be hashed
        if ((opt & MerkleRootFlags::HASH_ELEMENTS) == 0)
        {
            elements[i] = stackItemAt(-1).asVch();
            // check element length
            auto sz = elements[i].size();
            // this is the empty element                      or  size is right
            if ((sz == 0) || ((sz == 1) && (elements[i][0] == 0)) || (sz == leafAlgSize))
            {
            }
            else
            {
                return set_error(&error, SCRIPT_ERR_INVALID_PARAMETER);
            }
        }
        else
        {
            auto tmp = stackItemAt(-1).asVch();
            HashMpLeaf(leafAlg, tmp, elements[i]);
        }
        PopStack();
    }


    const VchType proof = stackItemAt(-1).data();
    PopStack();
    MpHash hasher(nodeAlg);

    std::vector<uint64_t> returnIndex;
    std::vector<uint64_t> returnDepth;
    std::vector<uint8_t> returnAdjacent;
    VchType root;

    if (nodeAlgSize == 20)
    {
        MerkleProof<MpHash, 20> mp(hasher);
        root = mp.computeMultiproofRoot(elements, proof, &returnIndex, &returnDepth, &returnAdjacent);
    }
    else if (nodeAlgSize == 32)
    {
        MerkleProof<MpHash, 32> mp(hasher);
        root = mp.computeMultiproofRoot(elements, proof, &returnIndex, &returnDepth, &returnAdjacent);
    }
    else // bad hash size (should never happen; not exposed)
    {
        assert(false);
    }

    if (root.size() == 0) // proof failed
    {
        return set_error(&error, SCRIPT_ERR_INVALID_PARAMETER);
    }

    // adjacency... (num elements 8-bit bitmaps pushed)
    if ((opt & MerkleRootFlags::RETURN_ADJACENCY) > 0)
    {
        for (uint64_t i = 0; i < num_elements; i++)
        {
            PushStack(StackItem(IntStack, returnAdjacent[i]));
        }
    }
    // depth... (num_elements scriptnums pushed)
    if ((opt & MerkleRootFlags::RETURN_DEPTH) > 0)
    {
        for (uint64_t i = 0; i < num_elements; i++)
        {
            PushStack(StackItem(IntStack, returnDepth[i]));
        }
    }
    // index... (num_elements scriptnums pushed)
    if ((opt & MerkleRootFlags::RETURN_INDEX) > 0)
    {
        for (uint64_t i = 0; i < num_elements; i++)
        {
            PushStack(StackItem(IntStack, returnIndex[i]));
        }
    }
    // merkle root
    PushStack(root);

    return true;
}
