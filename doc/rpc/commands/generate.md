```
generate numblocks ( maxtries )

Mine up to numblocks blocks immediately (before the RPC call returns)

Arguments:
1. numblocks    (numeric, required) How many blocks are generated immediately.
2. maxtries     (numeric, optional) How many iterations to try (default = 1000000).

Result
[ blockhashes ]     (array) hashes of blocks generated

Examples:

Generate 11 blocks
> nexa-cli generate 11

```
