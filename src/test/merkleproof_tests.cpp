#include "core_io.h"
#include "key.h"
#include "keystore.h"
#include "policy/policy.h"
#include "rpc/server.h"
#include "script/script.h"
#include "script/script_error.h"
#include "script/scripttemplate.h"
#include "script/sighashtype.h"
#include "script/sign.h"
#include "test/scriptflags.h"
#include "test/test_nexa.h"
#include "unlimited.h"
#include "util.h"
#include "utilstrencodings.h"

#include <boost/test/unit_test.hpp>
#include <fstream>
#include <stdint.h>
#include <string>
#include <univalue.h>
#include <vector>

#include "script/merkleproof.h"
#include "tinyformat.h"

template <typename T>
std::vector<T> operator+(const std::vector<T> &a, const std::vector<T> &b)
{
    std::vector<T> result = a;
    result.insert(result.end(), b.begin(), b.end());
    return result;
}

template <typename T>
std::vector<T> operator<<(const std::vector<T> &a, const std::vector<T> &b)
{
    std::vector<T> result = a;
    result.insert(result.end(), b.begin(), b.end());
    return result;
}
template <typename T>
std::vector<T> operator<<(const std::vector<T> &a, const int b)
{
    std::vector<T> result = a;
    result.push_back((T)b);
    return result;
}


VchType v(MerkleProofStep mps)
{
    VchType ret(1);
    ret[0] = mps;
    return ret;
}

VchType sha256(VchType a, VchType b)
{
    CSHA256 sha;
    sha.Write(&a[0], a.size());
    sha.Write(&b[0], b.size());
    VchType result(32);
    sha.Finalize((unsigned char *)&result[0]);
    return result;
}

VchType hash256(VchType a, VchType b)
{
    CHash256 sha;
    sha.Write(&a[0], a.size());
    sha.Write(&b[0], b.size());
    VchType result(32);
    sha.Finalize((unsigned char *)&result[0]);
    return result;
}

VchType hash160(VchType a, VchType b)
{
    CHash160 sha;
    sha.Write(&a[0], a.size());
    sha.Write(&b[0], b.size());
    VchType result(32);
    sha.Finalize((unsigned char *)&result[0]);
    return result;
}


BOOST_FIXTURE_TEST_SUITE(merkleproof, BasicTestingSetup)

template <typename Hasher, int HashSize>
void treeExpansionTest()
{
    MerkleProof<Hasher, HashSize> mp;
    VchType one(HashSize);
    one[0] = 1;
    VchType two(HashSize);
    two[0] = 2;
    VchType three(HashSize);
    three[0] = 3;
    VchType four(HashSize);
    four[0] = 4;
    VchType five(HashSize);
    five[0] = 5;
    VchType six(HashSize);
    six[0] = 6;

    // Let's start with an empty database
    VchType oldroot = empty;
    VchType root = empty;

    // Let's add an element
    root = one;
    // Degenerate merkle proof
    VchType merkleRoot = mp.computeMultiproofRoot({one}, VchType());
    BOOST_CHECK(merkleRoot == root);
    // Expansion: Let's add space for another element
    oldroot = root;
    root = mp.Hash(root, empty);
    BOOST_CHECK(oldroot != root); // Root should have changed.

    // Prove the empty (the oldroot is now the left side of the tree)
    VchType proof = VchType() << MULTIPROOF_LEFT_SIBLING << oldroot;
    std::vector<uint64_t> indexes;
    merkleRoot = mp.computeMultiproofRoot({empty}, proof, &indexes);
    BOOST_CHECK(indexes[0] == 1);
    BOOST_CHECK(merkleRoot == root);
    // add an element
    oldroot = root;
    root = mp.computeMultiproofRoot({two}, proof, &indexes);
    BOOST_CHECK(oldroot != root);
    BOOST_CHECK(indexes[0] == 1);
    BOOST_CHECK(root == mp.Hash(one, two));

    // We have a 2 level, 2 element tree

    // Expansion: Let's add space for another element
    oldroot = root;
    root = mp.Hash(root, empty);

    // We have a 3 level, 4 slot: 2 element, 2 empty tree

    // Prove the empty (the oldroot is now the left side of the tree)
    proof = VchType() << MULTIPROOF_RIGHT_IS_EMPTY << MULTIPROOF_LEFT_SIBLING << oldroot;
    indexes.resize(0); // just to break things
    merkleRoot = mp.computeMultiproofRoot({empty}, proof, &indexes);
    BOOST_CHECK(indexes[0] == 2);
    BOOST_CHECK(merkleRoot == root);

    // add an element
    oldroot = root;
    root = mp.computeMultiproofRoot({three}, proof, &indexes);
    BOOST_CHECK(indexes[0] == 2);
    BOOST_CHECK(oldroot != root);

    BOOST_CHECK(root == mp.Hash(mp.Hash(one, two), mp.Hash(three, empty)));

    // Unbalanced tree:

    // Push a new level where the right side is empty
    oldroot = root;
    root = mp.Hash(root, empty);
    // We have a 4 level, 8 slot: 3 element, 5 empty tree

    // on the right side though, lets just have 2 elements by doing a dual insertion
    proof = VchType() << MULTIPROOF_PUSH << MULTIPROOF_POP << MULTIPROOF_LEFT_SIBLING << oldroot;
    merkleRoot = mp.computeMultiproofRoot({empty, empty}, proof, &indexes);
    BOOST_CHECK(root == merkleRoot);
    // Insert the 2 elements
    root = mp.computeMultiproofRoot({five, six}, proof, &indexes);

    BOOST_CHECK(root == mp.Hash(mp.Hash(mp.Hash(one, two), mp.Hash(three, empty)), mp.Hash(five, six)));
    /*
                                  R
                      c                   d
                a          b           5     6
             1    2      3   e


     */

    // Multilevel proof.  Prove elements three and five
    std::vector<uint64_t> depth;
    std::vector<uint8_t> adjacency;

    // partial proof:  forgot a pop
    proof = VchType() << MULTIPROOF_RIGHT_IS_EMPTY << MULTIPROOF_LEFT_SIBLING << mp.Hash(one, two) << MULTIPROOF_PUSH
                      << MULTIPROOF_RIGHT_SIBLING << six;
    merkleRoot = mp.computeMultiproofRoot({three, five}, proof, &indexes, &depth, &adjacency);
    BOOST_CHECK(merkleRoot == VchType());
    // ok the correct proof
    proof = VchType() << MULTIPROOF_RIGHT_IS_EMPTY << MULTIPROOF_LEFT_SIBLING << mp.Hash(one, two) << MULTIPROOF_PUSH
                      << MULTIPROOF_RIGHT_SIBLING << six << MULTIPROOF_POP;
    merkleRoot = mp.computeMultiproofRoot({three, five}, proof, &indexes, &depth, &adjacency);
    BOOST_CHECK(root == merkleRoot);
    BOOST_CHECK(indexes[0] == 2);
    BOOST_CHECK(depth[0] == 3);
    BOOST_CHECK(adjacency[0] == 2); // adjacent to our other element, but not to the beginning of the tree

    BOOST_CHECK(indexes[1] == 2); // Its element 2 on level 2 (which is a,b,5, see above)
    BOOST_CHECK(depth[1] == 2);
    BOOST_CHECK(adjacency[1] == 1); // adjacent to our other element, but not to the end of the tree
}

BOOST_AUTO_TEST_CASE(treeExpansion)
{
    treeExpansionTest<CSHA256, 32>(); // REQ3
    treeExpansionTest<CRIPEMD160, 20>(); // REQ4
    treeExpansionTest<CHash160, 20>(); // REQ5
    treeExpansionTest<CHash256, 32>(); // REQ6
}


/* This test case demonstrates how to add a new element into a subtree that is empty */
BOOST_AUTO_TEST_CASE(emptyExpansion)
{
    MerkleProof<CSHA256, 32> mp;
    VchType zero(32);
    VchType one(32);
    one[0] = 1;
    VchType two(32);
    two[0] = 2;
    VchType three(32);
    three[0] = 3;
    VchType four(32);
    four[0] = 4;
    VchType five(32);
    five[0] = 5;

    /* Tree diagram
              R
          /       \
         g          h
       /   \      /   \
l1:   c    d      e   f
      /\   /\    /\   /\
     1 2  3 4   b  b b  b
idx: 0 1  2 3   4  5 6  7

(the whole right subtree starts as empty, so e,f,h == empty)
    */

    VchType l1c = sha256(one, two);
    VchType l1d = sha256(three, four);
    VchType g = sha256(l1c, l1d);
    VchType root = sha256(g, empty);

    std::vector<uint64_t> indexes;
    std::vector<uint64_t> depth;
    std::vector<uint8_t> adjacency;
    // Warm up: prove element 3 (index 2)
    if (1)
    {
        VchType proof = VchType() << MULTIPROOF_RIGHT_SIBLING << four << MULTIPROOF_LEFT_SIBLING << l1c
                                  << MULTIPROOF_RIGHT_IS_EMPTY;
        std::vector<VchType> elems = {three};
        VchType merkleRoot = mp.computeMultiproofRoot(elems, proof, &indexes);
        // tfm::printf("root %s manual %s\n", HexStr(root), HexStr(merkleRoot));
        BOOST_CHECK(merkleRoot == root);
        BOOST_CHECK(indexes[0] == 2);
    }

    // let's fill empty index 4
    if (1)
    {
        // Create a proof for index 4 as empty:
        VchType proof = VchType() << MULTIPROOF_RIGHT_IS_EMPTY << MULTIPROOF_RIGHT_IS_EMPTY << MULTIPROOF_LEFT_SIBLING
                                  << g;
        std::vector<VchType> elems = {empty};
        VchType merkleRoot = mp.computeMultiproofRoot(elems, proof, &indexes, &depth, &adjacency);
        // tfm::printf("Fill first empty: root %s manual %s\n", HexStr(root), HexStr(merkleRoot));
        BOOST_CHECK(merkleRoot == root);
        BOOST_CHECK(indexes[0] == 4);
        // Although its unnecessary, let's also verify the depth and that its the last element (adjacent to the end)
        // and NOT the first element
        BOOST_CHECK(depth[0] == 3);
        BOOST_CHECK(adjacency[0] == 2);

        // Insert element five into this spot
        elems[0] = five;
        merkleRoot = mp.computeMultiproofRoot(elems, proof, &indexes);
        // tfm::printf("new root %s\n", HexStr(merkleRoot));
        BOOST_CHECK("1a63577c95d74ac51740dc693fe54c7bf3709b5e389ffb3b932705386a04d8cf" == HexStr(merkleRoot));
    }

    // Fill an index in the middle (say 5)
    if (1)
    {
        // Create a proof for index 5 as empty:
        VchType proof = VchType() << MULTIPROOF_LEFT_IS_EMPTY << MULTIPROOF_RIGHT_IS_EMPTY << MULTIPROOF_LEFT_SIBLING
                                  << g;
        std::vector<VchType> elems = {empty};
        VchType merkleRoot = mp.computeMultiproofRoot(elems, proof, &indexes);
        // tfm::printf("Fill an index in the middle: root %s manual %s\n", HexStr(root), HexStr(merkleRoot));
        BOOST_CHECK(merkleRoot == root);
        BOOST_CHECK(indexes[0] == 5);
        // Insert element five into this spot
        elems[0] = five;
        merkleRoot = mp.computeMultiproofRoot(elems, proof, &indexes);
        // Is it the same as if we calced the whole thing
        VchType newroot = sha256(g, sha256(sha256(empty, five), empty));
        BOOST_CHECK(newroot == merkleRoot);

        // since this is a fully defined test vector, check it against what we know is correct
        BOOST_CHECK("822dd345b0bd9db77ba5e4c0084b116bfb3bb7ae75ad6bbe1870ef10f10c595e" == HexStr(merkleRoot));
    }
}


BOOST_AUTO_TEST_CASE(indexedMerkleMultiProof)
{
    MerkleProof<CSHA256, 32> mp;
    VchType zero(32);
    VchType one(32);
    one[0] = 1;
    VchType two(32);
    two[0] = 2;
    VchType three(32);
    three[0] = 3;
    VchType four(32);
    four[0] = 4;
    VchType root;

    std::vector<VchType> elems = {one, two};
    std::vector<uint64_t> depth;
    std::vector<uint8_t> adjacent;
    std::vector<uint64_t> indexes;

    if (1) // prove both sides of a 2 element tree
    {
        VchType proof = VchType() << MULTIPROOF_PUSH << MULTIPROOF_POP;
        root = mp.computeMultiproofRoot(elems, proof, &indexes, &depth, &adjacent);
        VchType calced = sha256(one, two);
        // tfm::printf("root %s manual %s\n", HexStr(root), HexStr(calced));
        BOOST_CHECK(calced == root);
        BOOST_CHECK(indexes[0] == 0);
        BOOST_CHECK(indexes[1] == 1);
        BOOST_CHECK(depth[0] == 1);
        BOOST_CHECK(depth[1] == 1);
        BOOST_CHECK(adjacent[0] == 3);
        BOOST_CHECK(adjacent[1] == 3);
    }

    /* prove adjacent different parent:
            R
         /     \
        _       _
       / \     / \
      3   1   2   4
    */
    if (1)
    {
        VchType proof = VchType() << MULTIPROOF_LEFT_SIBLING << three << MULTIPROOF_PUSH << MULTIPROOF_RIGHT_SIBLING
                                  << four << MULTIPROOF_POP;
        root = mp.computeMultiproofRoot(elems, proof, &indexes, &depth, &adjacent);
        VchType calced = sha256(sha256(three, one), sha256(two, four));
        // tfm::printf("root %s manual %s\n", HexStr(root), HexStr(calced));
        BOOST_CHECK(calced == root);
        BOOST_CHECK(indexes[0] == 1);
        BOOST_CHECK(indexes[1] == 2);
        BOOST_CHECK(depth[0] == 2);
        BOOST_CHECK(depth[1] == 2);
        BOOST_CHECK(adjacent[0] == 2); // 1 is adjacent to the right
        BOOST_CHECK(adjacent[1] == 1); // 2 is adjacent to the left
    }

    /* prove adjacent same parent:
            R
         /     \
        _       _
       / \     / \
      1   2   3   4
    */
    if (1)
    {
        VchType proof = VchType() << MULTIPROOF_PUSH << MULTIPROOF_POP << MULTIPROOF_RIGHT_SIBLING
                                  << sha256(three, four);
        root = mp.computeMultiproofRoot(elems, proof, &indexes, &depth, &adjacent);
        VchType calced = sha256(sha256(one, two), sha256(three, four));
        // tfm::printf("root %s manual %s\n", HexStr(root), HexStr(calced));
        BOOST_CHECK(calced == root);
        BOOST_CHECK(indexes[0] == 0);
        BOOST_CHECK(indexes[1] == 1);
        BOOST_CHECK(depth[0] == 2);
        BOOST_CHECK(depth[1] == 2);
        BOOST_CHECK(adjacent[0] == 3); // 1 is adjacent to the left (with the edge) and the right
        BOOST_CHECK(adjacent[1] == 1); // 2 is adjacent to the left
    }

    /* prove adjacent same parent:
            R
         /     \
        _       _
       / \     / \
      3   4   1   2
    */
    if (1)
    {
        VchType proof = VchType() << MULTIPROOF_PUSH << MULTIPROOF_POP << MULTIPROOF_LEFT_SIBLING
                                  << sha256(three, four);
        root = mp.computeMultiproofRoot(elems, proof, &indexes, &depth, &adjacent);
        VchType calced = sha256(sha256(three, four), sha256(one, two));
        // tfm::printf("root %s manual %s\n", HexStr(root), HexStr(calced));
        BOOST_CHECK(calced == root);
        BOOST_CHECK(indexes[0] == 2);
        BOOST_CHECK(indexes[1] == 3);
        BOOST_CHECK(depth[0] == 2);
        BOOST_CHECK(depth[1] == 2);
        BOOST_CHECK(adjacent[0] == 2); // 1 is adjacent to the right
        BOOST_CHECK(adjacent[1] == 3); // 2 is adjacent to the left end the edge
    }

    /* prove gapped adjacent:
            R
         /     \
        _       _
       / \     / \
      1   e   2   3
    */
    if (1)
    {
        VchType proof = VchType() << MULTIPROOF_RIGHT_IS_EMPTY << MULTIPROOF_PUSH << MULTIPROOF_RIGHT_SIBLING << three
                                  << MULTIPROOF_POP;
        root = mp.computeMultiproofRoot(elems, proof, &indexes, &depth, &adjacent);
        VchType calced = sha256(sha256(one, empty), sha256(two, three));
        // tfm::printf("root %s manual %s\n", HexStr(root), HexStr(calced));
        BOOST_CHECK(calced == root);
        BOOST_CHECK(indexes[0] == 0);
        BOOST_CHECK(indexes[1] == 2);
        BOOST_CHECK(depth[0] == 2);
        BOOST_CHECK(depth[1] == 2);
        BOOST_CHECK(adjacent[0] == 3); // 1 is adjacent to the right and beginning
        BOOST_CHECK(adjacent[1] == 1); // 2 is adjacent to the left
    }

    // Test a bunch of permutations of 2 proved elements and 2 empties to verify that they all are dual adjacent
    if (1)
    {
        VchType proofs[] = {
            VchType() << MULTIPROOF_RIGHT_IS_EMPTY << MULTIPROOF_PUSH << MULTIPROOF_RIGHT_IS_EMPTY << MULTIPROOF_POP,
            VchType() << MULTIPROOF_LEFT_IS_EMPTY << MULTIPROOF_PUSH << MULTIPROOF_RIGHT_IS_EMPTY << MULTIPROOF_POP,
            VchType() << MULTIPROOF_LEFT_IS_EMPTY << MULTIPROOF_PUSH << MULTIPROOF_LEFT_IS_EMPTY << MULTIPROOF_POP,
            VchType() << MULTIPROOF_RIGHT_IS_EMPTY << MULTIPROOF_PUSH << MULTIPROOF_LEFT_IS_EMPTY << MULTIPROOF_POP,
            VchType() << MULTIPROOF_PUSH << MULTIPROOF_POP << MULTIPROOF_LEFT_IS_EMPTY,
            VchType() << MULTIPROOF_PUSH << MULTIPROOF_POP << MULTIPROOF_RIGHT_IS_EMPTY,
            VchType() // terminator
        };

        for (auto &p : proofs)
        {
            if (p.size() == 0)
                break;
            root = mp.computeMultiproofRoot(elems, p, &indexes, &depth, &adjacent);
            BOOST_CHECK(depth[0] == 2);
            BOOST_CHECK(depth[1] == 2);
            BOOST_CHECK(adjacent[0] == 3);
            BOOST_CHECK(adjacent[1] == 3);
        }
    }

    // Prove an 2 empty indexes
    // If you prove empty indexes, you could then populate one of them in one step in a script
    if (1)
    {
        std::vector<VchType> el = {empty, empty};
        VchType proof = VchType() << MULTIPROOF_PUSH << MULTIPROOF_POP << MULTIPROOF_LEFT_SIBLING << two;
        root = mp.computeMultiproofRoot(el, proof, &indexes);
        VchType calced = sha256(two, empty);
        // tfm::printf("2 empty indexes: root %s manual %s\n", HexStr(root), HexStr(calced));
        BOOST_CHECK(calced == root);
        BOOST_CHECK(indexes[0] == 2);
        BOOST_CHECK(indexes[1] == 3);
    }
}


BOOST_AUTO_TEST_CASE(indexedmerkleproof)
{
    MerkleProof<CSHA256, 32> mp;
    VchType zero(32);
    VchType one(32);
    one[0] = 1;
    VchType two(32);
    two[0] = 2;
    VchType three(32);
    three[0] = 3;
    VchType four(32);
    four[0] = 4;
    VchType root;

    std::vector<VchType> elems = {one};
    if (1)
    {
        VchType proof = VchType() << MULTIPROOF_LEFT_IS_EMPTY;
        std::vector<uint64_t> indexes;
        root = mp.computeMultiproofRoot(elems, proof, &indexes);
        VchType calced = sha256(empty, one);
        // tfm::printf("root %s manual %s\n", HexStr(root), HexStr(calced));
        BOOST_CHECK(calced == root);
        BOOST_CHECK(indexes[0] == 1);
    }
    if (1)
    {
        VchType proof = VchType() << MULTIPROOF_RIGHT_IS_EMPTY;
        std::vector<uint64_t> indexes;
        root = mp.computeMultiproofRoot(elems, proof, &indexes);
        VchType calced = sha256(one, empty);
        // tfm::printf("root %s manual %s\n", HexStr(root), HexStr(calced));
        BOOST_CHECK(calced == root);
        BOOST_CHECK(indexes[0] == 0);
    }

    if (1)
    {
        VchType proof = VchType() << MULTIPROOF_LEFT_SIBLING << two << MULTIPROOF_LEFT_SIBLING << three;
        std::vector<uint64_t> indexes;
        root = mp.computeMultiproofRoot(elems, proof, &indexes);
        VchType calced = sha256(three, sha256(two, one));
        // tfm::printf("root %s manual %s\n", HexStr(root), HexStr(calced));
        BOOST_CHECK(calced == root);
        BOOST_CHECK(indexes[0] == 3);
    }

    // Prove an empty index
    // If you prove empty indexes, you could then populate one of them in one step in a script
    if (1)
    {
        std::vector<VchType> el = {empty};
        VchType proof = VchType() << MULTIPROOF_LEFT_SIBLING << two << MULTIPROOF_LEFT_SIBLING << three;
        std::vector<uint64_t> indexes;
        root = mp.computeMultiproofRoot(el, proof, &indexes);
        VchType calced = sha256(three, sha256(two, empty));
        // tfm::printf("Empty index: root %s manual %s\n", HexStr(root), HexStr(calced));
        BOOST_CHECK(calced == root);
        BOOST_CHECK(indexes[0] == 3);
    }
}

BOOST_AUTO_TEST_CASE(merkleproof)
{
    MerkleProof<CSHA256, 32> mp;
    VchType one(32);
    one[0] = 1;
    VchType two(32);
    two[0] = 2;
    VchType three(32);
    three[0] = 3;
    VchType four(32);
    four[0] = 4;
    VchType root;
    VchType root2;

    std::vector<uint64_t> indexes;
    std::vector<uint64_t> depth;
    std::vector<uint8_t> adjacent;

    std::vector<VchType> elems = {one};
    if (1)
    {
        VchType proof;
        proof.push_back(MULTIPROOF_LEFT_IS_EMPTY);
        root = mp.computeMultiproofRoot(elems, proof);
        root2 = mp.computeMultiproofRoot(elems, proof, &indexes, &depth, &adjacent);
        CSHA256 sha;
        sha.Write(&empty[0], 1);
        sha.Write(&one[0], 32);
        VchType calced(32);
        sha.Finalize((unsigned char *)&calced[0]);
        // tfm::printf("root %s manual %s\n", HexStr(root), HexStr(calced));
        BOOST_CHECK(calced == root);
        BOOST_CHECK(root2 == root);
        BOOST_CHECK(indexes[0] == 1);
        BOOST_CHECK(depth[0] == 1);
        BOOST_CHECK(adjacent[0] == 3); // 1 element so its the 1st and last
    }
    if (1)
    {
        VchType proof;
        proof.push_back(MULTIPROOF_RIGHT_IS_EMPTY);
        root = mp.computeMultiproofRoot(elems, proof);
        root2 = mp.computeMultiproofRoot(elems, proof, &indexes, &depth, &adjacent);
        CSHA256 sha;
        sha.Write(&one[0], 32);
        sha.Write(&empty[0], 1);
        VchType calced(32);
        sha.Finalize((unsigned char *)&calced[0]);
        // tfm::printf("root %s manual %s\n", HexStr(root), HexStr(calced));
        BOOST_CHECK(calced == root);
        BOOST_CHECK(root2 == root);
        BOOST_CHECK(indexes[0] == 0);
        BOOST_CHECK(depth[0] == 1);
        BOOST_CHECK(adjacent[0] == 3); // 1 element so its the 1st and last
    }


    // 2 level tests.  In this test the hashes one, two and three are not necessarily elements.
    // As a shortcut, one of them is always the hash of 2 fictional elements on the other side of the root node
    if (1)
    {
        VchType proof = VchType() << MULTIPROOF_LEFT_SIBLING << two << MULTIPROOF_LEFT_SIBLING << three;
        root = mp.computeMultiproofRoot(elems, proof);
        root2 = mp.computeMultiproofRoot(elems, proof, &indexes, &depth, &adjacent);
        VchType calced = sha256(three, sha256(two, one));
        // tfm::printf("root %s manual %s\n", HexStr(root), HexStr(calced));
        BOOST_CHECK(calced == root);
        BOOST_CHECK(root2 == root);
        BOOST_CHECK(indexes[0] == 3);
        BOOST_CHECK(depth[0] == 2);
        BOOST_CHECK(adjacent[0] == 2); // rightmost element so adjacent to the end
    }

    if (1)
    {
        VchType proof = VchType() << MULTIPROOF_RIGHT_SIBLING << two << MULTIPROOF_RIGHT_SIBLING << three;
        root = mp.computeMultiproofRoot(elems, proof);
        root2 = mp.computeMultiproofRoot(elems, proof, &indexes, &depth, &adjacent);
        VchType calced = sha256(sha256(one, two), three);
        // tfm::printf("root %s manual %s\n", HexStr(root), HexStr(calced));
        BOOST_CHECK(calced == root);
        BOOST_CHECK(root2 == root);
        BOOST_CHECK(indexes[0] == 0);
        BOOST_CHECK(depth[0] == 2);
        BOOST_CHECK(adjacent[0] == 1); // leftmost element
    }

    if (1)
    {
        VchType proof = VchType() << MULTIPROOF_LEFT_SIBLING << two << MULTIPROOF_RIGHT_SIBLING << three;
        root = mp.computeMultiproofRoot(elems, proof);
        root2 = mp.computeMultiproofRoot(elems, proof, &indexes, &depth, &adjacent);
        VchType calced = sha256(sha256(two, one), three);
        // tfm::printf("root %s manual %s\n", HexStr(root), HexStr(calced));
        BOOST_CHECK(calced == root);
        BOOST_CHECK(root2 == root);
        BOOST_CHECK(indexes[0] == 1);
        BOOST_CHECK(depth[0] == 2);
        BOOST_CHECK(adjacent[0] == 0); // middle element
    }
    if (1)
    {
        VchType proof = VchType() << MULTIPROOF_RIGHT_SIBLING << two << MULTIPROOF_LEFT_SIBLING << three;
        root = mp.computeMultiproofRoot(elems, proof);
        root2 = mp.computeMultiproofRoot(elems, proof, &indexes, &depth, &adjacent);
        VchType calced = sha256(three, sha256(one, two));
        // tfm::printf("root %s manual %s\n", HexStr(root), HexStr(calced));
        BOOST_CHECK(calced == root);
        BOOST_CHECK(indexes[0] == 2);
        BOOST_CHECK(depth[0] == 2);
        BOOST_CHECK(adjacent[0] == 0); // middle element
    }
}


// Merkle proof script tests

static void CheckError(uint32_t flags, const Stack &original_stack, const CScript &script, ScriptError expected)
{
    ScriptError err = SCRIPT_ERR_OK;
    Stack stack{original_stack};
    // Note that this returns false for CHECKSIG, whereas an empty ScriptImportedState() errors out with missing data
    BaseSignatureChecker checker;
    ScriptImportedState sis(&checker);
    bool r = EvalScript(stack, script, flags, MAX_OPS_PER_SCRIPT, sis, &err);
    BOOST_CHECK(!r);
    BOOST_CHECK_EQUAL(err, expected);
}

static void CheckPass(uint32_t flags, const Stack &original_stack, const CScript &script, const Stack &expected)
{
    ScriptError err = SCRIPT_ERR_OK;
    Stack stack{original_stack};
    // Note that this returns false for CHECKSIG, whereas an empty ScriptImportedState() errors out with missing data
    BaseSignatureChecker checker;
    ScriptImportedState sis(&checker);
    bool r = EvalScript(stack, script, flags, MAX_OPS_PER_SCRIPT, sis, &err);
    BOOST_CHECK(r);
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
    BOOST_CHECK(stack == expected);
}

BOOST_AUTO_TEST_CASE(merkleProofScripts)
{
    auto flags = POST_UPGRADE_MANDATORY_SCRIPT_VERIFY_FLAGS;
    VchType one(32);
    one[0] = 1;
    VchType two(32);
    two[0] = 2;
    VchType three(32);
    three[0] = 3;
    VchType four(32);
    four[0] = 4;
    VchType root;
    VchType root2;

    std::vector<uint64_t> indexes;
    std::vector<uint64_t> depth;
    std::vector<uint8_t> adjacent;

    // Try a single element proof
    std::vector<VchType> elems = {one};
    VchType proof = VchType() << MULTIPROOF_RIGHT_SIBLING << two << MULTIPROOF_RIGHT_SIBLING << three;
    VchType calced = sha256(sha256(one, two), three);
    VchType eHashCalced = sha256(sha256(sha256(one, VchType()), two), three);
    // just the hash
    CScript s = CScript() << proof << one << 1 << merkleRootOption(MerkleRootAlg::SHA256, MerkleRootFlags::MR_NONE)
                          << OP_MERKLEROOT;
    CheckPass(flags, Stack(), s, {calced});

    if (true) // everything
    {
        s = CScript() << proof << one << 1
                      << merkleRootOption(MerkleRootAlg::SHA256, MerkleRootFlags::RETURN_INDEX |
                                                                     MerkleRootFlags::RETURN_DEPTH |
                                                                     MerkleRootFlags::RETURN_ADJACENCY)
                      << OP_MERKLEROOT;
        Stack expected = {{IntStack, 1}, // adjacency is left
            {IntStack, 2}, // depth is 2
            {IntStack, 0}, // Index is 2
            calced};
        CheckPass(flags, Stack(), s, expected);
    }

    if (true) // every output REQ7,REQ8,REQ9,REQ10
    {
        s = CScript() << proof << one << 1
                      << merkleRootOption(MerkleRootAlg::SHA256,
                             MerkleRootFlags::HASH_ELEMENTS | MerkleRootFlags::RETURN_INDEX |
                                 MerkleRootFlags::RETURN_DEPTH | MerkleRootFlags::RETURN_ADJACENCY)
                      << OP_MERKLEROOT;
        Stack expected = {{IntStack, 1}, // adjacency is left
            {IntStack, 2}, // depth is 2
            {IntStack, 0}, // Index is 2
            eHashCalced};
        CheckPass(flags, Stack(), s, expected);
    }

    // Try asking for different combinations of results
    // Test combinations of REQ8,REQ9,REQ10
    std::vector<std::pair<uint64_t, Stack> > tv = {
        {merkleRootOption(MerkleRootAlg::SHA256, MerkleRootFlags::RETURN_INDEX), {{IntStack, 0}, calced}},
        {merkleRootOption(MerkleRootAlg::SHA256, MerkleRootFlags::RETURN_DEPTH), {{IntStack, 2}, calced}},
        {merkleRootOption(MerkleRootAlg::SHA256, MerkleRootFlags::RETURN_ADJACENCY), {{IntStack, 1}, calced}},

        {merkleRootOption(MerkleRootAlg::SHA256, MerkleRootFlags::RETURN_ADJACENCY | MerkleRootFlags::RETURN_INDEX),
            {{IntStack, 1}, {IntStack, 0}, calced}},
        {merkleRootOption(MerkleRootAlg::SHA256, MerkleRootFlags::RETURN_ADJACENCY | MerkleRootFlags::RETURN_DEPTH),
            {{IntStack, 2}, {IntStack, 1}, calced}},

        {merkleRootOption(MerkleRootAlg::SHA256, MerkleRootFlags::RETURN_DEPTH | MerkleRootFlags::RETURN_INDEX),
            {{IntStack, 2}, {IntStack, 0}, calced}},
    };

    for (const auto &[option, expected] : tv)
    {
        s = CScript() << proof << one << 1 << option << OP_MERKLEROOT;
        CheckPass(flags, Stack(), s, expected);
    }
}

// Negative tests for bad proofs
BOOST_AUTO_TEST_CASE(merkleProofNegative)
{
    auto flags = POST_UPGRADE_MANDATORY_SCRIPT_VERIFY_FLAGS;
    VchType one(32);
    one[0] = 1;
    VchType two(32);
    two[0] = 2;
    VchType three(32);
    three[0] = 3;
    VchType four(32);
    four[0] = 4;

    // Try a multiproof
    /*
           R
        a     b
       1 2   3 4
     */
    std::vector<VchType> elems = {two, three};

    std::vector<std::pair<VchType, ScriptError_t> > tv = {
        // pops an empty stack
        {VchType() << MULTIPROOF_POP, SCRIPT_ERR_INVALID_PARAMETER},
        // proves 1 element, two provided (REQ11)
        {VchType() << MULTIPROOF_RIGHT_SIBLING << two << MULTIPROOF_RIGHT_SIBLING << three,
            SCRIPT_ERR_INVALID_PARAMETER},
        // proves 3 elements, two provided (REQ11)
        {VchType() << MULTIPROOF_PUSH << MULTIPROOF_POP << MULTIPROOF_PUSH, SCRIPT_ERR_INVALID_PARAMETER},
        // Leaves something on the stack (REQ12)
        {VchType() << MULTIPROOF_PUSH << MULTIPROOF_RIGHT_SIBLING << two, SCRIPT_ERR_INVALID_PARAMETER},
        // data is too small
        {VchType() << MULTIPROOF_LEFT_SIBLING << one << MULTIPROOF_PUSH << MULTIPROOF_RIGHT_SIBLING << VchType(1)
                   << MULTIPROOF_POP,
            SCRIPT_ERR_INVALID_PARAMETER},
        // garbage command (REQ13)
        {VchType() << 35 << one << MULTIPROOF_PUSH << MULTIPROOF_RIGHT_SIBLING << four << MULTIPROOF_POP,
            SCRIPT_ERR_INVALID_PARAMETER},
        {VchType() << MULTIPROOF_LEFT_SIBLING << one << 27 << MULTIPROOF_RIGHT_SIBLING << four << MULTIPROOF_POP,
            SCRIPT_ERR_INVALID_PARAMETER},
    };

    int count = 0;
    for (const auto &[proof, error] : tv)
    {
        // printf("negative test #%d\n", count);
        CScript s = CScript() << proof << two << one << 2
                              << merkleRootOption(MerkleRootAlg::SHA256, MerkleRootFlags::MR_NONE) << OP_MERKLEROOT;
        CheckError(flags, Stack(), s, error);
        count++;
    }
}

// Negative tests for bad opcode args
BOOST_AUTO_TEST_CASE(merkleOpcodeNegative)
{
    auto flags = POST_UPGRADE_MANDATORY_SCRIPT_VERIFY_FLAGS;
    VchType one(32);
    one[0] = 1;
    VchType two(32);
    two[0] = 2;
    VchType three(32);
    three[0] = 3;
    VchType four(32);
    four[0] = 4;

    VchType shortone(10);
    shortone[0] = 1;
    VchType shortfour(10);
    shortfour[0] = 4;

    // Try a multiproof
    /*
           R
        a     b
       1 2   3 4
     */
    // std::vector<VchType> elems = {one, four};

    VchType goodProof = VchType() << MULTIPROOF_RIGHT_SIBLING << two << MULTIPROOF_PUSH << MULTIPROOF_LEFT_SIBLING
                                  << three << MULTIPROOF_POP;
    auto mrOpt = merkleRootOption(MerkleRootAlg::SHA256, MerkleRootFlags::MR_NONE);
    CScript goodScript = CScript() << goodProof << one << four << 2 << mrOpt << OP_MERKLEROOT;

    std::vector<std::pair<CScript, ScriptError_t> > tv = {
        // pops an empty stack
        {CScript() << goodProof << shortone << four << 2
                   << merkleRootOption(MerkleRootAlg::SHA256, MerkleRootFlags::MR_NONE) << OP_MERKLEROOT,
            SCRIPT_ERR_INVALID_PARAMETER},
        // bad option
        {CScript() << goodProof << one << four << 2 << merkleRootOption((MerkleRootAlg)235, MerkleRootFlags::MR_NONE)
                   << OP_MERKLEROOT,
            SCRIPT_ERR_INVALID_BIT_RANGE},
        // REQ14: bad option
        {CScript() << goodProof << one << four << 2
                   << merkleRootOption(MerkleRootAlg::SHA256, (MerkleRootFlags)(1 << 22)) << OP_MERKLEROOT,
            SCRIPT_ERR_INVALID_BIT_RANGE},
        // bad # of args
        {CScript() << goodProof << one << four << 4 << mrOpt << OP_MERKLEROOT, SCRIPT_ERR_INVALID_STACK_OPERATION},
        {CScript() << OP_MERKLEROOT, SCRIPT_ERR_INVALID_STACK_OPERATION},
        {CScript() << goodProof << mrOpt << OP_MERKLEROOT, SCRIPT_ERR_INVALID_STACK_OPERATION},
        // REQ2: you can't prove 0 elements (push some junk on the stack to have enough to avoid invalid stack op)
        {CScript() << 1 << 1 << 1 << goodProof << 0 << mrOpt << OP_MERKLEROOT, SCRIPT_ERR_INVALID_PARAMETER},
        // REQ1: Proving too many elements
        {CScript() << goodProof << one << 257 << mrOpt << OP_MERKLEROOT, SCRIPT_ERR_INVALID_PARAMETER},
    };

    int count = 0;
    for (const auto &[script, error] : tv)
    {
        // printf("script negative test #%d\n", count);
        CheckError(flags, Stack(), script, error);
        count++;
    }
}


BOOST_AUTO_TEST_CASE(merkleMultiProofScripts)
{
    auto flags = POST_UPGRADE_MANDATORY_SCRIPT_VERIFY_FLAGS;
    VchType one(32);
    one[0] = 1;
    VchType two(32);
    two[0] = 2;
    VchType three(32);
    three[0] = 3;
    VchType four(32);
    four[0] = 4;
    VchType root;
    VchType root2;

    std::vector<uint64_t> indexes;
    std::vector<uint64_t> depth;
    std::vector<uint8_t> adjacent;

    // Try a multiproof
    /*
           R
        a     b
       1 2   3 4
     */
    std::vector<VchType> elems = {two, three};

    VchType proof = VchType() << MULTIPROOF_LEFT_SIBLING << one << MULTIPROOF_PUSH << MULTIPROOF_RIGHT_SIBLING << four
                              << MULTIPROOF_POP;
    VchType sha256calced = sha256(sha256(one, two), sha256(three, four));
    VchType hash256calced = hash256(hash256(one, two), hash256(three, four));
    // just the hash
    CScript s = CScript() << proof << two << one << 2
                          << merkleRootOption(MerkleRootAlg::SHA256, MerkleRootFlags::MR_NONE) << OP_MERKLEROOT;
    CheckPass(flags, Stack(), s, {sha256calced});

    s = CScript() << proof << two << one << 2 << merkleRootOption(MerkleRootAlg::HASH256, MerkleRootFlags::MR_NONE)
                  << OP_MERKLEROOT;
    CheckPass(flags, Stack(), s, {hash256calced});

    if (true) // everything
    {
        s = CScript() << proof << two << one << 2
                      << merkleRootOption(MerkleRootAlg::HASH256, MerkleRootFlags::RETURN_INDEX |
                                                                      MerkleRootFlags::RETURN_DEPTH |
                                                                      MerkleRootFlags::RETURN_ADJACENCY)
                      << OP_MERKLEROOT;
        Stack expected = {{IntStack, 2}, {IntStack, 1}, // adjacency is left
            {IntStack, 2}, // depth is 2
            {IntStack, 2}, // depth is 2
            {IntStack, 1}, // Index is 1
            {IntStack, 2}, // Index is 2
            hash256calced};
        CheckPass(flags, Stack(), s, expected);
    }


    std::vector<std::pair<uint64_t, Stack> > tv = {
        {merkleRootOption(MerkleRootAlg::SHA256, MerkleRootFlags::RETURN_INDEX),
            {{IntStack, 1}, {IntStack, 2}, sha256calced}},
        {merkleRootOption(MerkleRootAlg::SHA256, MerkleRootFlags::RETURN_DEPTH),
            {{IntStack, 2}, {IntStack, 2}, sha256calced}},
        {merkleRootOption(MerkleRootAlg::SHA256, MerkleRootFlags::RETURN_ADJACENCY),
            {{IntStack, 2}, {IntStack, 1}, sha256calced}},
    };

    for (const auto &[option, expected] : tv)
    {
        s = CScript() << proof << two << one << 2 << option << OP_MERKLEROOT;
        CheckPass(flags, Stack(), s, expected);
    }
}


VchType buildProofSubTree(int depth)
{
    if (depth == 1)
    {
        return VchType() << MULTIPROOF_PUSH << MULTIPROOF_POP;
    }
    else // Build the 2 subtrees and combined them
    {
        return VchType() << buildProofSubTree(depth - 1) << MULTIPROOF_PUSH << buildProofSubTree(depth - 1)
                         << MULTIPROOF_POP;
    }
}

BOOST_AUTO_TEST_CASE(merkleProofLimits)
{
    auto flags = POST_UPGRADE_MANDATORY_SCRIPT_VERIFY_FLAGS;
    VchType one(32);
    one[0] = 1;
    VchType two(32);
    two[0] = 2;

    VchType proof;

    // Proves all elements in a tree of 256 elements that looks like this:
    /*  R
       / \
       0 /\
        1 /\
         2 ...
     */
    // Its one less because the first element is implicitly loaded
    for (auto i = 0; i < 255; i++)
        proof = proof << MULTIPROOF_PUSH;
    for (auto i = 0; i < 255; i++)
        proof = proof << MULTIPROOF_POP;

    CScript pushpop = CScript() << proof;

    CScript s = pushpop;
    for (auto i = 0; i < 256; i++)
        s << one;

    s << 256 << merkleRootOption(MerkleRootAlg::SHA256, MerkleRootFlags::MR_NONE) << OP_MERKLEROOT;

    ScriptError err = SCRIPT_ERR_OK;
    BaseSignatureChecker checker;
    ScriptImportedState sis(&checker);
    Stack stk;
    bool r = EvalScript(stk, s, flags, MAX_OPS_PER_SCRIPT, sis, &err);
    BOOST_CHECK(r);
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
    BOOST_CHECK(HexStr(stk[0].asVch()) == "045c564fd25cbe1586ae23cc9721ef7847657a3c173328494a709f01b0eefb23");
    // tfm::printf("root %s\n", HexStr(stk[0].asVch()));

    // Let's add 1 more leaf (breaks it)
    s = pushpop;
    s = s << MULTIPROOF_PUSH << MULTIPROOF_POP;

    for (auto i = 0; i < 257; i++)
        s << one;
    s << 257 << merkleRootOption(MerkleRootAlg::SHA256, MerkleRootFlags::MR_NONE) << OP_MERKLEROOT;
    r = EvalScript(stk, s, flags, MAX_OPS_PER_SCRIPT, sis, &err);
    BOOST_CHECK(!r);

    // Proves all elements in a fully balanced tree with 256 leaves
    proof = buildProofSubTree(8);
    err = SCRIPT_ERR_OK;
    stk = Stack();
    s = CScript() << proof;
    for (auto i = 0; i < 256; i++)
        s << one;
    s << 256 << merkleRootOption(MerkleRootAlg::SHA256, MerkleRootFlags::MR_NONE) << OP_MERKLEROOT;
    r = EvalScript(stk, s, flags, MAX_OPS_PER_SCRIPT, sis, &err);
    BOOST_CHECK(r);
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
    // tfm::printf("root %s\n", HexStr(stk[0].asVch()));
    BOOST_CHECK("1520280e8ea9485728aea1efc33585271b70707980a652e6bcb8f7872efe1e7c" == HexStr(stk[0]));

    // Fully balanced tree, that's too big
    proof = buildProofSubTree(9);
    err = SCRIPT_ERR_OK;
    stk = Stack();
    s = CScript() << proof;
    for (auto i = 0; i < 256; i++)
        s << one;
    s << 256 << merkleRootOption(MerkleRootAlg::SHA256, MerkleRootFlags::MR_NONE) << OP_MERKLEROOT;
    r = EvalScript(stk, s, flags, MAX_OPS_PER_SCRIPT, sis, &err);
    BOOST_CHECK(!r);

    s = CScript() << proof;
    for (auto i = 0; i < 512; i++)
        s << one;
    s << 512 << merkleRootOption(MerkleRootAlg::SHA256, MerkleRootFlags::MR_NONE) << OP_MERKLEROOT;
    r = EvalScript(stk, s, flags, MAX_OPS_PER_SCRIPT, sis, &err);
    BOOST_CHECK(!r);
}

BOOST_AUTO_TEST_SUITE_END()
