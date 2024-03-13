# Nexa Header Paths

Header paths are a technique that allows light clients to rapidly and efficiently discover the Nexa blockchain tip, with the ability to discover dishonesty to some chosen probability.  Additionally, dishonesty would require significant hash power and is expensive, regardless of whether the dishonest attempt succeeds or fails.    Specifically it offers the following functionality:
* Determine that block header of height N is part of the Nexa blockchain, by looking at log N headers. 
* Determine the total chain work at height N by looking at log N headers.
* Determine the chain tip by choosing the header with the greatest work.

It relies on two fields in the Nexa block header: the total chain work and the ancestor hash (these two fields are not part of the standard Satoshi header).  Two new peer-to-peer protocol messages are defined: request headers path (actually "reqhdrpath") and "headers path" ("hdrpath").

# Definitions
* *chain work*:  The chain work is defined at a particular block header.  It is the expected number of hashes needed to recreate the entire blockchain from the genesis block to this header.  This is different than difficulty which is a measure of the work required to create a single block.  Chain work is the sum of the work in every block from the genesis block to the current.
*  *Ancestor hash*:  An ancestor hash is a commitment to the hash of some preceding block in the blockchain.  This preceding block must be older than the parent block.  The algorithm to determine which block to use as an ancestor is not that important (see the ancestor block definition in the Nexa block header) however, it should allow non-linear paths.
* *Header path*: A list of blocks that begins at a later block and ends at an earlier one.  Each block in the path must reference the next via either its ancestor hash or its parent hash.  The gap between block N<sub>i</sub> and N<sub>i+1</sub> may be different for different i, however it must be >= 0 (a header path never moves forwards in the blockchain only backwards).
# Theory of operation

Nexa includes the total chain work and an ancestor hash inside the block header.  This "commitment" to these fields means that there is work (energy and therefore cost) required to lie about these values.  If these fields are incorrect, the block will be rejected by full nodes so cannot be part of the valid blockchain.

A light client may request a header path from block N to the genesis block.  Using ancestor hashes this path can be provided with O(log N) headers.

However, "Mallory" (a minority-hash-power miner that wishes to trick a light client into using an incorrect blockchain fork) can produce a block header that claims the greatest chain work.  Mallory can then compute exactly and only the O(log N) headers required to provide a header path, and provide that path to the light client.

The light client receives this path (P<sub>0</sub>).  It then chooses a random block height that is *NOT* on the provided path, between the blockchain tip and the point where it imagines "Mallory" may have started producing a fake header path (possibly the light client's checkpoint, or possibly a relatively recent block).  The light client requests the path from P<sub>0</sub>[0] (the tip of the original path) to the chosen height (call this P<sub>1</sub>).  The light client can repeat this path request as many times as desired (or until every block header has been provided), receiving P<sub>n</sub> paths.  

Due to the properties of cryptographic hashes, it is computationally infeasible for Mallory to compute P<sub>x</sub> at the time it is requested because it comprises a hash chain (e.g. H(H(H(x)) from the chosen header to P<sub>0</sub>[0].  If Mallory is able to provide this path, he must have computed it prior to providing P<sub>0</sub>.  The likelihood that Mallory guesses the block correctly is 1/N.

Note if the light client chooses a block height before Mallory's fake fork, then Mallory could provide a valid path that connects to P<sub>0</sub> prior to his invalid headers.  This is easily detectable.  However, Mallory could also compute several fake paths through his fork and provide one of those paths.

# Practical Considerations

It is recommended that light clients request all headers within N blocks of the tip, and then paths to both recent and random heights.  For example, since full nodes provide up to 2000 headers in a single "getheaders" reply, it would make sense to request no more than 2000 headers behind the claimed tip.  Then the light client requests a headers path to a random height up to a few 2 months old, and then a few random heights within the header interval that comprises the greatest chain work growth per header within all provided paths.  By looking at the greatest chain work growth per header, the light client can focus on the potential blockchain discontinuity.

In the case where an invalid fork is being presented, the coinbase reward and fees in these block headers represent the minimum value that this miner would have gained by behaving honestly, so there is significant financial risk involved and organizational effort required to create a chain with (say) thousands of valid blocks before the invalid section.

Additionally, there is no reason to request these paths from the same node.  By requesting header paths from different nodes, "Mallory" must also implement an eclipse attack on the light client.  With this strategy, it becomes extremely expensive to calculate and present a fake chain, and that chain is unlikely to be accepted. 

# Message Definitions

The following messages are defined within the standard Nexa p2p message envelope and object serialization format.  These lower level standards will not be presented in this document.

## Request Header Path

* Message Id: "gethdrpath"

* Serialization:

| name | size in bytes | endian | description
|------|------|---------|---|
| fromHeight | 4 | little | Height of header that begins the path, or 0xFFFFFFFF to indicate the chain tip, or 0 to use the fromHash field. |
| fromHash | 32 | | Hash of header that begins the path (if fromHeight is 0.  If fromHash is 0, use the genesis block. |
| toHeight | 4 | little | Height of header that ends the path, or 0xFFFFFFFF to indicate the chain tip, or 0 to use the toHash field. |
| toHash | 32 | | Hash of header that ends the path (if fromHeight is 0.  If fromHash is 0, use the genesis block. |

### Description
This message requests the headers path from the specified beginning block to the specified end block, inclusive.  
Note that the "xxxHash" fields are ignored unless the "xxxHeight" fields are 0.  
If the path is successfully built, a reply "hdrpath" message is generated.

#### Error Responses
If the beginning block height is less than the end block height, a "reject" message is generated with the REJECT_MALFORMED (0x1) error.
If the beginning and end blocks are not on the main chain, are not found, or are beyond the tip, a "reject" message is generated with the REJECT_FORK (0x43) error.

## Header Path Response

* Message Id: "hdrpath"
  
* Serialization:

Vector of block headers that form the headers path.  This response is serialized in the exact format as the "headers" message.  The only difference is the content of the headers -- in the "headers" message, header heights increment.  In this message, header heights are strictly decreasing and the prevBlockHash or ancestorHash of header i must equal the hash of header i+1 (where i is an index into this vector).

