# Tailstorm Implementation

This Tailstorm implemention moves from a Satoshi style blockchain to a Tailstorm style DAG in a careful and succinct manner, with respect to source code changes.

This document is a conceptual map as to how this is accomplished.


## Blocks

The Tailstorm and Bobtail papers contain the concepts of subblocks and summary blocks.  Although these two block types are conceptually extremely important, they are syntatically almost identical.

In the documentation, when enough subblocks have been discovered, a PoW-free summary block is created.  This implementation requires that the creator of the final subblock must know beforehand that a solution implies the summary block, and the final subblock *IS* the summary block.  In Bobtail, this is not strictly true because the last few subblocks could be discovered at the same time (within network propagation time), and then both be used within the summary block (if they do not conflict).  This is a small but necessary difference so that the summary block has PoW commitment (energy) behind its creation.  This energy means that we do not have to define a single unambiguous algorithm to convert an arbitrary set of subblock to a summary block.  If any ambiguity was possible, and attacker could spam the network with multiple valid competing summary blocks.

This code does not use separate data structures for the two block types.  A subblock simply does not contain sufficient proof-of-work to be a summary block.

Since the chain of summary blocks IS a traditional blockchain, the code and documentation uses "block" to refer to the summary blockchain block, and always uses subblock to refer to any DAG block. When its important to be absolutely clear, the code may use "summary block" as a synonym to "block".  However, as stated above, the final subblock *IS* the (summary) block (the summary blocks are a subset of the subblocks).  Therefore when a topic describes ALL blocks, the term "subblock" is often used (see Proof of Work just below for an example).

Subblocks are not stored on disk.  They only need to be stored in RAM.  We accomplish this by relaxing the requirement that subblocks be "consistent" (see below) once the block is away from the chain tip.

A block that is more than "Params().tailstormEnforceCorrectSubblocks" deep from the chain tip does NOT need to have consistent subblocks.  It merely needs those subblock references to solve the PoW puzzle.  This allows the full node to forget about subblocks that are not summary blocks, after a depth of tailstormEnforceCorrectSubblocks.

### Subblock Consistency

A subblock has the concept of "consistency" defined in the context of a subblock that references it.  To be "consistent" a subblock first must be valid in "standard" block field checks (prevBlockHash, merkle root, nBits, etc all correct).

And its transactions must be consistent (no conflicts) with those defined in the referencing subblock.


Let us define a "tip subblock" to be a subblock whose parent is the current chain tip.  Let us suppose an attacker creates a competing fork with some inconsistent subblocks.

First, it is important that doing so is no easier than the production of consistent subblocks (see "A Discussion of Subblock PoW Choices" below).  Second, note that if the inconsistencies are not "deep" (>tailstormEnforceCorrectSubblocks) depth, all honest nodes will ignore the fork.

Third, observe that the transactions in a non-tip subblock are completely ignored in favor of the transactions defined in the referencing (summary) block.  So these (deep) illegal transactions can have no effect on blockchain correctness.

Fourth, let us show that the chain converges.

A block that is more than "tailstormEnforceCorrectSubblocks" deep from the chain tip does NOT need to have consistent subblocks.  It merely needs those subblock references to solve the PoW puzzle.
The full node ignores forks that have inconsistent subblocks to a depth of tailstormEnforceCorrectSubblocks, but does NOT ignore them after that.  In other words, let us say we are at block A.  A block X appears with inconsistent subblocks.  We remain mining off of A, so X is the first block in a fork.  We mine our fork and the fork containing X is also mined, but let us say that fork X remains ahead.  Once the X has "tailstormEnforceCorrectSubblocks" children, we switch to it.  Inconsistent subblocks do not permanently mark a fork invalid.

This is important because an attacker could time the release of block headers to make some nodes evaluate a block's consistency but others skip that evaluation, causing a fork.  But if the consistent fork ever pulls ahead, the inconsistent one will be abandoned.  And if the inconsistent one pulls ahead then the consistent one is abandoned after tailstormEnforceCorrectSubblocks blocks.  So 

One effect of this is that any node that is missing subblocks (perhaps it just came online), and for some reason cannot acquire them over the network, might (for a time) mine the attacker's fork with "illegal" inconsistent subblocks.  However, the effect of this is just as if the attacker got a bit more hash power.


If the inconsistency is closer to the tip than tailstormEnforceCorrectSubblocks, the fork is rejected.

The attacker could provide different nodes different tips (on their fork) by withholding more recent blocks from honest nodes.  Without an eclipse attack, those honest nodes would exchange blocks defeating this attack.  But if we assume an eclipse attack, some nodes may
reject the attacker's fork and others accept it.  However, this simply reduces the 


### Proof of Work

#### nBits
The "nBits" PoW target field in a block refers to the actual work needed to solve this subblock.  This target is specified by the blockchain (chain of summary blocks) using the ASERT algorithm / neededSubblocks.  In a traditional blockchain the "neededSubblocks" is 1 (as in just the summary block), so the nBits target is just ASERT(...).  But in this implementation, it is ASERT(x)/neededSubblocks.

Since ASERT(...) is not a function of subblocks, ALL subblock children of a particular parent have the same nBits value.

By defining it like this, the mining infrastructure does not need to change AT ALL!!!  Miners are just trying to solve easier blocks.

#### chainWork

The total work in the block is therefore the number of referenced subblocks + 1 (itself).  The chainWork field must sum all of this work.


#### Block Proof of Work

A block must meet its own proof of work as a subblock.  It must also reference enough subblocks to meet the summary block proof of work.

Before Tailstorm, the minerData field was defined as 0.  It is now used to provide PoW puzzle solutions (which are also subblocks references).

A block meets the proof of work requirement *if "K" - 1 distinct PoW puzzle solutions are provided* (where K is the targeted number of subblocks per summary block as per the Bobtail/Tailstorm papers, and -1 because this block has PoW as well).

To compartmentalize the code, these PoW puzzle solutions do not have to be legal subblocks.  They could be arbitrary bytes.  However, the PoW puzzle includes the known hash of the previous (summary) block, so it is not possible to reuse old or forked solutions.  






## A Discussion of Subblock PoW Choices


Subblocks are not stored persistently.  They are just stored in RAM.

If a block not being added to the tip, its transactions no longer need to be consistent with its subblocks' transactions (by definition).  This makes it unnecessary to save old subblocks to verify blockchain correctness.

   Subblocks still need to have valid PoW, but this can be verified solely by the data in minerData.

   This works because subblocks have 2 purposes: Bobtail (low-variance mining) and Storm (announcing partial PoW
   blocks to indicate tx inclusion probability).  Bobtail is proven by the data in minerData; from this data
   we know that it took on average X work to find the block.  But the Storm data is not relevant once the
   (summary) block has been discovered (the tx either got into the block or not, all Storm-based probabilistic
   assessments of that collapse into the boolean fact).

   It does not matter if old subblocks contain complete lies about pending transactions (that are left out of
   the block); the (summary) blockchain upholds all chain properties, just like it would if subblocks did not
   exist.  An attacker can create a competing chain with invalid (old) subblocks.  But they cannot use those old
   subblocks to their advantage because the tx inclusion probability has already collapsed into true or false in
   the block.

   The only issue would be whether using illegal subblocks somehow makes it easier for an attacker to mine the
   block (defeating the Bobtail part of Tailstorm).  Changing the content to make computation simpler makes no sense
   because the mining algorithm functions over arbitrary bytes and uses a cryptographic hash.  It is impossible to
   predict the output from any input.

   But reusing prior subblock solutions, or intermediate work, is a concern.

   To prevent subblock reuse, the PoW algorithm must be verified using the cryptographic hash of the parent
   (summary) block.  This unique data must be injected at the beginning of the PoW computation and be part of the
   majority of the effort to prevent an intermediate work attack.  However, this statement says nothing about the
   quantity of the data.  Let us propose 2 work and cryptographically strong functions F(x) and S(x), where F runs
   several orders of magnitude faster than S (and let us use "><" as byte array interleave*, and "." as concatenation).
   A space efficient secure algorithm would be S(F(subblock) . parent hash).  Since F(subblock) also contains the
   (entropy inserting) parent hash it could be used as the block identifier.

   To recast this as a search, S(x) could be "find an x such that F(x) < target", and we could introduce some nonce
   data into x (as is traditional in blockchain PoW).

   Let us attempt to avoid providing the bare nonce for subblock PoW validation purposes, because this would mean
   that every block must provide the nonce of every subblock.

   Consider packing it into the first part of the final hash:
   Pack = F0(nonce >< subblock)
   PoW = F1(parent hash >< Pack) < target
   The block provides Pack for each subblock (the parent hash is the same as the block's parent hash so is known).
   
   In this case, an attacker could simply choose random values for Pack (skipping the F(subblock >< nonce) computation).
   This reduces their PoW work to F(D >< parent hash) < target.

   To ensure that an attacker fork must compute approximately the same work as the main chain, it is therefore
   important the the effort to compute Pack is << that of PoW, if the nonce is placed into Pack().

   Ok the above has some caveats so let's flesh out the option where we provide the nonce:
   Pack = F0(subblock)
   PoW = F1((nonce >< parent hash) . Pack)
   The block provides the nonce and pack for each subblock.
   
   It is expected that Pack is precomputed by honest nodes, so there is little benefit to an attacker to use
   random numbers (we interleave the nonce with the parent hash to reduce the attacker's ability to precompute
   an F(nonce) intermediate state for many nonces.  We do NOT interleave Pack, so that choosing a random number
   does not provide an attacker "free bits" to match F(nonce >< random number) against precomputed states.

   Note that in the above cases, if Pack contains a cryptographically secure hash function, it is a good candidate
   for the identifier -- this allows the PoW function (which is F1(...F0(...)...) to be complex without impacting the
   use of cryptographic hash functions as data pointers.

   TODO: For maximum compatibility with the old PoW algorithm, we will store both the sublblock
   MiningHeaderCommitment (basically Pack above) and the nonce in the block.  However when the PoW is changed,
   we should consider packing the nonce and the MiningHeaderCommitment into a single hash.

   * Why interleave:  Byte interleaving (F("ABC", "DEF") -> F("ADBECF")) ensures that if one of the two parameters
     are held constant or precomputed, the intermediate state of this computation of cannot be used.


### Allowing a variable number of subblocks in a block

If we do not make this a chain constant, we could adjust the # of subblocks without a subsequent hard fork.  We would do this by ensuring that the subblock work sums to the needed work rather than checking that N subblocks exist.

However, we don't want to store each nBits in the minerData.  We'd assume the nBits of the summary block.  But this would allow lucky subblocks to matter.  To fix that, nBits needs to be a hashed parameter in the PoW like prevBlockHash.

