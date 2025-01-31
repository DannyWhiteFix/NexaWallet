# OP_MERKLEROOT Script Instruction

## Definition

OP_MERKLEROOT calculates a merkle root given a list of elements and a merkle proof.  This instruction can be used to efficiently verify a variety of operations in Nexa script on verifiable databases.

proof elementsArray N option OP_MERKLEROOT -> [N adjacency] [N depth] [N index] merkleRoot

*Parameters:*
- *proof*: A bytearray merkle proof as defined in the "Merkle Proof Definition" below
- *elementsArray*: N bytearrays individually pushed onto the stack, where each push corresponds to either the raw element or the element hash depending on the selected options. Must be <= 256. (REQ1)
- *N*: Integer number of elements to be proven.  Must be > 0 (REQ 2)
- option: Merkle root algorithm selection (defined below)

The proof size is not explicitly limited since it is limited by the machine stack.  The number of elements proven is limited to <= 256 to control the size of the proof stack.

*Returns:*
- *N adjacency*: If the adjacency option flag is set, N numbers are pushed onto the stack.  For each pushed item, if the corresponding element is adjacent to the prior element, bit 0 is set, if the element is adjacent to the next element, bit 1 is set.
- *N depth*: If the depth option flag is set, N numbers are pushed onto the stack.  Each pushed item is the depth of this element in the merkle tree, where the root element is depth 0.
- *N index*: If the index option flags is set, N numbers are pushed onto the stack. Each pushed item is the zero-based from-the-left index of this element in the merkle tree.  Note, this is the element index *at the element's depth*.  Therefore it is possible for two elements to have the same depth.
- *merkleRoot*: a byte array corresponding to the merkle root calculated from the provided elements and merkle proof.

### Option Field

The option field is a 64 bit unsigned integer with the following format:

- The hash algorithm is one of the following numbers:
```
SHA256 = 0,     // REQ3
RIPEMD160 = 1,  // REQ4
HASH160 = 2,    // REQ5: sha256 then RIPEMD160
HASH256 = 3,    // REQ6: Double sha256
```

- the least significant byte defines the inner node hash algorithm.
- the next byte defines the leaf element hash algorithm.

- *HASH_ELEMENTS* = (1 << 16): (REQ7) Raw elements are provided so the algorithm should hash them to produce the tree leaves.
- *RETURN_INDEX* = (1 << 17): (REQ8) Element indexes should be returned on the stack.
- *RETURN_DEPTH* = (1 << 17): (REQ9) Element depths should be returned on the stack
- *RETURN_ADJACENCY* = (1 << 19): (REQ10) Element adjacency flags should be returned on the stack. 

### Errors

If the proof does not consume exactly the provided number of elements, the script fails (REQ11).
If the proof operation does not culminate in an empty proof stack, the script fails (REQ12).
These two restrictions are important for security when a spender is challenged to provide a proof of existence of an element.  If a proof could skip elements or somehow not incorporate them into the final hash, it could appear to prove an element but not actually use it in the proof.

If the proof contains invalid commands, the script fails (REQ13).
All undefined option bits MUST be 0, or the script fails (REQ14).


## External Verifiable Databases

The OP_MERKLEROOT script instruction enables the blockchain to interact with external verifiable databases.  An external verifiable database is a database that is not part of the current system (the Nexa blockchain), yet memory and time efficient methods exist to verify the correct behavior of many database operations, such as insertion/removal and proof of existence/non-existence.

An external verifiable database publishes a succinct probabilistically unique fingerprint (AKA cryptographic hash) of the data in the database and transactions can verify database operations, each operation producing a new fingerprint reflecting the changed database state.

### Related Work

A merkle tree is verifiable but operations like insert or delete are not defined on merkle trees.  This document extends merkle trees with efficient, verifiable operations as part of the description of the OP_MERKLEROOT opcode.

Systems like Namecoin work with "internal" databases -- the database is simply part of consensus.  But this approach is limited by both scalability and the need to "hard fork" consensus-specific code into the blockchain for every database.


### Definition of the "Empty" element

We propose a special hash value named "empty" that is distinguishable from real elements and can appear either as a leaf hash or an inner node hash.  In this work, "empty" is the single byte 0.  Since cryptographically strong hashes cannot be that short, "empty" cannot be the preimage of actual data; it is unique.

We define
```
Hash(X) = Y, where X != empty, is a cryptographically strong hash function.
Hash(X) != empty, if X != empty (you could probably get away with it just being computationally infeasible to find an X, but we can easily implement this stronger requirement)

Hash(empty) == empty
Hash(empty, empty) == empty

if X != Y and X,Y != empty, it is computationally infeasible to find an X and Y such that:
Hash(X, empty) != Hash(empty, X) != Hash(empty, Y) != Hash(X)
```

In other words, if you hash something real with empty, you must get a cryptographically strong non-empty result.

This gives our merkle tree interesting properties.
We can tell if a subtree is entirely empty by looking at its hash.
Every empty subtree is equivalent.  That is, you can't distinguish an empty subtree containing 8 empty leaves from one containing 2 empty leaves.  We will use this property to extend trees.

However, if a subtree has one or more elements, it is distinguishable from another subtree with the same elements but in different positions (even if it's just 1 element).

Note that empty element handling is a superset of proofs without empty elements -- this code will also work for standard merkle trees.

### Element restrictions

To avoid merkle proof leaf extension attacks (where a leaf can masquerade as an inner node and so an extended proof can be created for fake elements below this leaf), it's very important that elements are provided and then hashed.  In other words, the data provider must prove that they know the preimage of the leaf, allowing **leaves to be distinguished from inner nodes by being the hash of one item while inner nodes are the hash of two items**.  This also means that leaves cannot be exactly the size of 2 hashes or a single leaf can masquerade as the "hash of two things", since in inner node calculation, two items are concatenated to form the hash (note there is no separator we can place between items that an element cannot also include if an element can be arbitrary data).

Therefore, to handle variable size elements, double-hash every leaf by hashing it once outside of this system and providing that hash to this system.  Then hash it again as a leaf of this merkle tree.  This double-hashing technique can also be used if an element is large and so it's inefficient to provide the entire element in these proofs.

However, the API allows elements to be provided as hashes.  This is for efficiency; if an algorithm does multiple tree operations, it only needs to prove that leaf hashes are hashes of single elements once.

### Merkle Calculation Operation

Let us propose a function that calculates a merkle root from a set of provided elements and a proof.  As part of the operation of this function, the position (0-based index) of the provided elements will be determined.

```
(root, [index], [depth], [adjacency]) = computeMerkleRoot([elements], proof)
```

 * root is the database fingerprint (cryptographic hash)

Index, depth, and adjacency are arrays whose values provide information about the elements in the passed list [elements]

 * index is an array of the 0-based index of the element provided starting from the left, at the provided depth
 * depth is an array of the distance in nodes from this element to the root.  The root is depth 0.
 * adjacency is an array of that specifies whether the element is adjacent (next to) the previous (left adjacency) or the next (right adjacency) element in the list, ignoring empty elements.  Left adjacency of the first element specifies its relationship with the left side of the tree; and right adjacency of the last element specifies the same for the right side of the tree.


### Merkle Proof Definition

A merkle proof is a byte array describing how to calculate the merkle root of a tree, given a list of elements.
A merkle tree (and proof) has the concept of a "left" and a "right" element, like this:
```
    node
   /    \
 left  right
```
Formally, the node's hash is formed via the expression Hash(left, right), where the comma operator means "append".  Essentially the left/right designation specifies the order that the provided data should be hashed.

A merkle proof requires a stack to be evaluated, and comprises a set of instructions on how to proceed in the calculation, as follows:
```
MULTIPROOF_LEFT_SIBLING = 0,     // The current node has a sibling to its left.  That sibling (hash) must follow in the proof as raw data. That is, Hash(data, current).
MULTIPROOF_RIGHT_SIBLING = 1,    // The current node has a sibling to its right.  That sibling (hash) must follow in the proof as raw data.  That is, Hash(current, data).
MULTIPROOF_LEFT_IS_EMPTY = 2,    // The current node has an empty sibling to its left.  That is, Hash(empty, current).
MULTIPROOF_RIGHT_IS_EMPTY = 3,   // The current node has an empty sibling to its right.  That is, Hash(current, empty).
MULTIPROOF_POP = 4,              // Pop the top of the stack and calculate Hash(popped, current).  The popped item is ALWAYS the left one.
MULTIPROOF_PUSH = 5,             // Push the current node onto the stack, and load the next element into the current node.
```

The proof is going to be of the form \<command\>\[data\]...


#### Calculating Proofs
To form a merkle proof of one or multiple elements, first sort the elements in index order, where the "index" refers to the position in the tree that the element was in when the merkle root was created.


In the case of SIBLING LEFT and RIGHT, the sibling hash is always also added to the proof as data.

1. Start with the first element, call it the current node.

2. Loop:
3. Take the current node and examine its sibling.  If the next element is a within the sibling subtree, add PUSH to the proof, set current element = next element, and recurse.  When the recursion is done, add POP to the proof.
4: If the sibling is empty, add SIBLING LEFT IS EMPTY, or SIBLING RIGHT IS EMPTY to the proof, set current node = tree parent, and continue.  Note that combining the command with "empty" is just an optimization.
5: Otherwise add SIBLING LEFT or RIGHT to the proof and add the sibling itself, set current node = tree parent, and continue.

6: Stop when current element == root element.

#### Example Proofs

Here is an example tree:
```
           R
        A     B
       1 2   e 4
```

If << is the concatenation operator, and e is the empty element, let us create a proof for element 2:
```
MULTIPROOF_LEFT_SIBLING << 1 << MULTIPROOF_RIGHT_SIBLING << B
```

Let us prove element 1 and 4:

```
MULTIPROOF_RIGHT_SIBLING << 2 << MULTIPROOF_PUSH << MULTIPROOF_LEFT_IS_EMPTY << MULTIPROOF_POP
```

Let us prove elements e and 4:

MULTIPROOF_PUSH << MULTIPROOF_POP << MULTIPROOF_LEFT_SIBLING << A


### Implementing computeMerkleRoot

Executing the provided proof requires a stack of hashes.  This simplified description covers computing the hash only; refer to the implementation for details on extracting the index, depth and adjacency information.

Start with the first element, call it the current node.
Execute the proof from the beginning to the end, handling each command as follows:

PUSH:
Push the current node to the stack.
Set the current node to the next element.
POP:
if stack is empty then FAIL
current node = Hash(pop the stack, current node)
SIBLING LEFT IS EMPTY:
current node = Hash(empty, current node)
SIBLING RIGHT IS EMPTY:
current node = Hash(current node, empty)

SIBLING LEFT:
current node = Hash(data from proof, current node)
SIBLING RIGHT:
current node = Hash(current node, data from proof)

When the proof is fully executed, if the stack is not empty then FAIL
return "current node" as the merkle root.

### Unbalanced Binary Trees

Unbalanced binary trees are trees whose leaves occur at different depths.

In that situation, the calculated element indexes will be the position of the element **at its depth**.
Let us examine this unbalanced tree, where elements are named alphabetically and inner nodes are named reverse alphabetically:
```
    z
   / \
   y  c
  / \ 
 a   b
```

In this tree the returned index of both b and c is 1, because they are both element 1 at their own level (a, b) and (y,c).


### Verifiable Database Operations


### Overwrite/modify multiple entries

Given: root, multiproof, oldEntries, newEntries
Result: failure or a new database root that corresponds to the changed merkle root of the changed database

Check logN: root == merkleRoot([oldEntries], proof)
Compute logN: newRoot =  merkleRoot([newEntries], proof)

### Delete an entry
Given: root, multiproof, oldEntries
Result: failure or a new database root that corresponds to the changed merkle root of the changed database

Conceptually we will replace all deleted entries with a special symbol "empty".  Since Hash(empty,empty) -> empty, any subtree with all empty children is detectable at the root.  This effectively trims the tree.

Check logN: root == merkleRoot([oldEntries], proof)
Compute logN: newRoot =  merkleRoot([emptys], proof)

### Insert an entry
An entry cannot be inserted into the middle of the sequence of element leaves.


### Append an entry
The entity proposing the append must know the index of the leaf it is adding.  If the tree is not full, an append is an overwrite operation of a empty leaf.
If the tree is full it is necessary combine this tree and a new subtree into a single tree with a new root.

If the proposer can append arbitrary entities, it may provide the new subtree root hash.

However, it's much more likely that the proposer's entry must be validated.

But the new subtree's merkle proof must follow a very simple format if it defines a single left-most leaf.  It is simply the "MULTIPROOF_RIGHT_IS_EMPTY" command repeated (logN) times, where N is the number of elements in the current tree, or Hash(Hash(Hash...Hash(new element, empty), empty), empty) in expression form.

### Doubling the size of the tree

This operation takes a merkle tree and produces another merkle tree with twice as many elements, with all the new elements marked "empty".

Given: root hash
Result new root hash

new root hash = Hash(root hash, empty)

This works because, the "empty" hash is the hash for any fully empty subtree.

### Expanding an empty subtree

Certain operations (see Doubling the size of the tree) add an empty subtree to the merkle tree.

To expand an empty entry, a merkle proof should be provided to the empty entry to be overwritten, even if that involves descending a subtree of empty entries.
Since Hash(empty,empty) == empty, this merkle proof will compute exactly the same root as one that just trims the subtree at the first empty.

Once that merkle proof is verified, the same merkle proof can be used to compute a new root with a non-empty entry as the element.  Because the same proof was used, it is not possible for other other hidden insertions to be part of the proof.

### Proving adjacency (proof of non-existence)

It is possible to provide a multiproof of two adjacent elements


## References

* Original commit for merkle multiproofs in blocks: https://github.com/bitcoin/bitcoin/commit/4bedfa9223d38bbc322d19e28ca03417c216700b

* A breadth-first multiproof technique: https://arxiv.org/pdf/2002.07648
**It requires that an index be provided with every leaf.  Instead, we embed that information in the proof (which allows it to be optionally handled at the script level).**