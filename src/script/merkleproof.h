#include "script/stackitem.h"
#include <stack>

typedef enum
{
    RAW_VALUES = 0,
} MerkleProofOptions;

typedef enum
{
    MULTIPROOF_LEFT_SIBLING = 0,
    MULTIPROOF_RIGHT_SIBLING = 1,
    MULTIPROOF_LEFT_IS_EMPTY = 2,
    MULTIPROOF_RIGHT_IS_EMPTY = 3,
    MULTIPROOF_POP = 4,
    MULTIPROOF_PUSH = 5,

} MerkleProofStep;

enum MerkleRootAlg
{
    // 8 bits of hash algorithm
    SHA256 = 0,
    RIPEMD160 = 1,
    HASH160 = 2, // sha256 then RIPEMD160
    HASH256 = 3, // Double sha256
                 // Future:
                 // BLAKE3 = 4,
                 // CUSTOM = 5  // also provide a scriptlet to be executed
};

// OP_MERKLEROOT algorithm options
enum class MerkleRootFlags : uint64_t
{
    // LSB
    // 8 bits of node alg
    // 8 bits of leaf alg

    // Output (bitmap):
    // Root hash is always output
    MR_NONE = 0,
    HASH_ELEMENTS = 1 << 16, // raw elements are provided which will be hashed first
    RETURN_INDEX = 1 << 17,
    RETURN_DEPTH = 1 << 18,
    RETURN_ADJACENCY = 1 << 19,

    // These are the bits that are currently defined in this protocol
    // all other option bits MUST be 0
    USED_BITS = HASH_ELEMENTS | RETURN_INDEX | RETURN_ADJACENCY | RETURN_DEPTH | 0x0F0F,
    ALG_BITS = 0xFF // bottom 4 bits of alg are defined
};

constexpr MerkleRootFlags operator|(MerkleRootFlags a, MerkleRootFlags b)
{
    return static_cast<MerkleRootFlags>(static_cast<uint64_t>(a) | static_cast<uint64_t>(b));
}

constexpr MerkleRootFlags operator&(MerkleRootFlags lhs, MerkleRootFlags rhs)
{
    return static_cast<MerkleRootFlags>(static_cast<uint64_t>(lhs) & static_cast<uint64_t>(rhs));
}

constexpr uint64_t operator&(uint64_t lhs, MerkleRootFlags rhs) { return lhs & static_cast<uint64_t>(rhs); }


/** Helper function to build the option field for OP_MERKLEROOT */
inline uint64_t merkleRootOption(MerkleRootAlg nodes_hash, MerkleRootAlg leaves_hash, MerkleRootFlags flags)
{
    return ((uint64_t)nodes_hash) | (((uint64_t)leaves_hash) << 8) | ((uint64_t)flags);
}

/** Helper function to build the option field for OP_MERKLEROOT
    Same hash for nodes and leaves (or maybe flags specify no hashing of the leaves)
*/
inline uint64_t merkleRootOption(MerkleRootAlg hash, MerkleRootFlags flags)
{
    return ((uint64_t)hash) | (((uint64_t)hash) << 8) | ((uint64_t)flags);
}


static const VchType empty = {0};

// Hashers is a class like CHash256 in hashwrapper.h
template <typename Hasher, int HashSize>
class MerkleProof
{
public:
    Hasher h;

    MerkleProof() {}
    MerkleProof(Hasher hashFn) : h(hashFn) {}

    inline VchType Hash(const VchType &a, const VchType &b)
    {
        // We define an empty hash as the single character 0.  This is impossible for a normal hash to create because
        // its too short.  However, if an empty hash was size 0, then the hash of a single left child would be the
        // same as the hash of a single right child.  So a sparse merkle tree could not prove an element index.
        VchType result(HashSize);
        // Percolate empty upwards so we can see them easily: two empty hashes hash to an empty hash
        bool aIsEmpty = (a.size() == 0) || ((a.size() == 1) && (a[0] == 0));
        bool bIsEmpty = (b.size() == 0) || ((b.size() == 1) && (b[0] == 0));
        if (aIsEmpty && bIsEmpty)
            return empty;
        h.Reset();
        if (a.size() == 0)
            h.Write(&empty[0], 1);
        else
            h.Write(&a[0], a.size());
        if (b.size() == 0)
            h.Write(&empty[0], 1);
        else
            h.Write(&b[0], b.size());

        h.Finalize((unsigned char *)&result[0]);
        // DbgAssert(result.size() == HashSize, );
        return result;
    }

    inline VchType Hash(const VchType &a, const unsigned char *b)
    {
        // We define an empty hash as the single character 0.  This is impossible for a normal hash to create because
        // its too short.  However, if an empty hash was size 0, then the hash of a single left child would be the
        // same as the hash of a single right child.  So a sparse merkle tree could not prove an element index.
        VchType result(HashSize);
        h.Reset();
        h.Write(&a[0], a.size());
        h.Write(b, HashSize);
        h.Finalize((unsigned char *)&result[0]);
        return result;
    }
    inline VchType Hash(const unsigned char *a, const VchType &b)
    {
        // We define an empty hash as the single character 0.  This is impossible for a normal hash to create because
        // its too short.  However, if an empty hash was size 0, then the hash of a single left child would be the
        // same as the hash of a single right child.  So a sparse merkle tree could not prove an element index.
        VchType result(HashSize);
        h.Reset();
        h.Write(a, HashSize);
        h.Write(&b[0], b.size());
        h.Finalize((unsigned char *)&result[0]);
        return result;
    }

    VchType computeMultiproofRoot(const std::vector<VchType> &elements,
        const VchType &proof,
        std::vector<uint64_t> *returnIndexes = nullptr,
        std::vector<uint64_t> *returnDepth = nullptr,
        std::vector<uint8_t> *returnAdjacent = nullptr);

protected:
    void indexInit(uint64_t numElements,
        std::vector<uint64_t> *ei,
        std::vector<uint64_t> *eid,
        std::vector<uint8_t> *returnAdjacent)
    {
        if (ei != nullptr)
        {
            ei->resize(numElements);
            eid->resize(numElements);
            std::fill(ei->begin(), ei->end(), 0);
            std::fill(eid->begin(), eid->end(), 0);
        }
        if (returnAdjacent != nullptr)
        {
            returnAdjacent->resize(numElements);
            // Assume adjacency on both sides (and then remove the bit when an intermediary element is seen)
            std::fill(returnAdjacent->begin(), returnAdjacent->end(), 3);
        }
    }

    // Helper function to build the index of an element.
    // This updates the depth-th bit in the ei vector if it has not already been set.
    void updateIndex(std::vector<uint64_t> *ei,
        std::vector<uint64_t> *eid,
        std::vector<uint8_t> *ra,
        uint64_t elementPos,
        uint64_t depth,
        uint64_t bit,
        uint8_t adjacencyMask)
    {
        bool leftAdjacencySet = false;
        if (eid != nullptr)
        {
            bit = bit << depth;
            for (uint64_t i = 0; i <= elementPos; i++)
            {
                if ((*eid)[i] <= depth)
                {
                    if (ei != nullptr)
                        (*ei)[i] |= bit;
                    (*eid)[i] = depth + 1;
                    if (ra != nullptr)
                    {
                        // is adjacent to the left?
                        // If we are clearing the left adjacency, this only applies to the first (leftmost)
                        // element in the stack.  As soon as we move to the next element, it MUST be right of the
                        // first one, so it can't be left-adjacent to another element via a higher up parent.
                        if ((adjacencyMask & 1) == 0)
                        {
                            if (leftAdjacencySet == false)
                            {
                                (*ra)[i] &= adjacencyMask;
                                leftAdjacencySet = true;
                            }
                        }
                        // Right adjacency can only apply to the last (rightmost) element
                        // (we've already traversed from the a left element to this one and determined if its adjacent)
                        if ((adjacencyMask & 2) == 0)
                        {
                            if (i == elementPos)
                                (*ra)[i] &= adjacencyMask;
                        }
                    }
                }
            }
        }
    }
};

template <typename Hasher, int HashSize>
VchType MerkleProof<Hasher, HashSize>::computeMultiproofRoot(const std::vector<VchType> &elements,
    const VchType &proof,
    std::vector<uint64_t> *returnIndexes,
    std::vector<uint64_t> *returnDepth,
    std::vector<uint8_t> *returnAdjacent)
{
    uint64_t proofPos = 0;
    uint64_t elementPos = 0;
    if (elementPos >= elements.size())
        return VchType();
    VchType cur = elements[elementPos];

    // We will extract the position of each element from the proof
    // The index depth is how many bits of the index we've already set
    std::vector<uint64_t> elementIndexDepthStorage;
    // If we are returning the depth, then we need it; we also need it as a temporary if we are returning the index.
    std::vector<uint64_t> *elementIndexDepth =
        returnDepth ? returnDepth : (returnIndexes ? &elementIndexDepthStorage : nullptr);
    indexInit(elements.size(), returnIndexes, elementIndexDepth, returnAdjacent);
    uint64_t depth = 0;

    std::stack<VchType> evalStack;

    while (proofPos < proof.size())
    {
        if (elementPos >= elements.size())
            return VchType(); // Error not enough data
        char option = proof[proofPos];
        proofPos++;
        switch (option)
        {
        case MULTIPROOF_RIGHT_SIBLING:
            cur = Hash(cur, &proof[proofPos]);
            proofPos += HashSize;
            updateIndex(returnIndexes, elementIndexDepth, returnAdjacent, elementPos, depth, 0, 0xFD);
            // If this element is adjacent to the next one, the right sibling will ALWAYS be empty
            // if (returnAdjacent) (*returnAdjacent)[elementPos] &= 1;  // mask off the bit 1 << 1
            depth++;
            break;
        case MULTIPROOF_LEFT_SIBLING:
            cur = Hash(&proof[proofPos], cur);
            proofPos += HashSize;
            updateIndex(returnIndexes, elementIndexDepth, returnAdjacent, elementPos, depth, 1, 0xFE);
            // If this element is adjacent to the prior one, the left sibling will ALWAYS be empty
            // if (returnAdjacent) (*returnAdjacent)[elementPos] &= 2;  // mask off the lowest bit
            depth++;
            break;
        case MULTIPROOF_RIGHT_IS_EMPTY:
            cur = Hash(cur, VchType());
            updateIndex(returnIndexes, elementIndexDepth, returnAdjacent, elementPos, depth, 0, 0xFF);
            depth++;
            break;
        case MULTIPROOF_LEFT_IS_EMPTY:
            cur = Hash(VchType(), cur);
            updateIndex(returnIndexes, elementIndexDepth, returnAdjacent, elementPos, depth, 1, 0xFF);
            depth++;
            break;
        case MULTIPROOF_POP:
            if (evalStack.size() == 0)
                return VchType(); // Error too many pops
            // Since the elements must be sorted in leaf order, if the proof does a pop, we know that what we have
            // been working on is on the right side, and that the left was updated when the push happened so
            // it will be skipped over now.
            updateIndex(returnIndexes, elementIndexDepth, returnAdjacent, elementPos, depth, 1, 0xFF);

            // Since the proven elements must be provided in tree order, the pushed subtree is always the left one
            cur = Hash(evalStack.top(), cur);
            evalStack.pop();
            depth++;
            break;
        case MULTIPROOF_PUSH:
            // Since the elements must be sorted in leaf order, if the proof does a push, we know that what we have
            // been working on is on the left side.
            updateIndex(returnIndexes, elementIndexDepth, returnAdjacent, elementPos, depth, 0, 0xFF);

            evalStack.push(cur);
            elementPos++;
            if (elementPos >= elements.size())
                return VchType(); // Error not enough data
            cur = elements[elementPos];
            // not needed, all inited
            //(*returnIndexes)[elementPos] = 0;
            // elementIndexDepth[elementPos] = -1;
            depth = 0; // Back down to a leaf
            break;
        }
    }

    if (evalStack.size() != 0) // The proof didn't pop all the way to a single value! -- its bad
        return VchType();
    if (elementPos != elements.size() - 1) // All elements were not used in the proof! -- its bad
        return VchType();
    return cur;
}
