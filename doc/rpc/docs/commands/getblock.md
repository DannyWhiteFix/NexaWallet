```
getblock hash_or_height ( verbosity ) ( tx_count )

If verbosity is 0, returns a string that is serialized, hex-encoded data for block 'hash'.
If verbosity is 1, returns the block header with a list of transaction hashes in the block
If verbosity is 2, returns the block header with a list of all decoded transaction details in the block
If tx_count is true, returns a block header with a count of all transactions in the block.

Arguments:
1. "hash_or_height"      (string|numeric, required) The block hash or height.
2. "verbosity"           (numeric, optional, default=1) 0 for hex-encoded data, 1 
                          for a block header with list of txn hashes, and 2 for a block header with 
                          detailed transaction data.
3. "tx_count"            (boolean, optional, default=false true to get a block header with a count of 
                          of transactions in the block.

Result (for verbosity = 1, tx_count = false):
{
  "hash" : "hash",     (string) the block hash (same as provided)
  "confirmations" : n,   (numeric) The number of confirmations, or -1 if the block is not on the main chain
  "size" : n,            (numeric) The block size
  "height" : n,          (numeric) The block height or index
  "txcount" : n,         (numeric) The number of transactions in the block
  "feePoolAmt" : n,      (numeric) The fee pool amount
  "version" : n,         (numeric) The block version
  "versionHex" : "00000000", (string) The block version formatted in hexadecimal
  "merkleroot" : "xxxx", (string) The merkle root
  "tx" : [               (array of string) The transaction ids
     "transactionid"     (string) The transaction id
     ,...
  ],
  "time" : ttt,          (numeric) The block time in seconds since epoch (Jan 1 1970 GMT)
  "mediantime" : ttt,    (numeric) The median block time in seconds since epoch (Jan 1 1970 GMT)
  "nonce" : n,           (numeric) The nonce
  "bits" : "1d00ffff", (string) The bits
  "difficulty" : x.xxx,  (numeric) The difficulty
  "chainwork" : "xxxx",  (string) Expected number of hashes required to produce the chain up to this block (in hex)
  "utxoCommitment" : n,  (hash)    The utxo commitment
  "minerdata" : "xxxx",        (string) A hex string identifier that the miner provides
  "previousblockhash" : "hash",  (string) The hash of the previous block
  "ancestorblockhash" : "hash",  (string) The hash of the ancestor block
  "nextblockhash" : "hash"       (string) The hash of the next block
  "status": status,      (string) Block status
}

Result (for verbosity = 2, tx_count = false):
{
Same as for verbosity = 1 but with all the un-encoded details of each transaction
}

Result (for verbosity=0):
"data"             (string) A string that is serialized, hex-encoded data for block 'hash'.

Examples:
> nexa-cli getblock "00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09"
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "getblock", "params": ["00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09"] }' -H 'content-type: text/plain;' http://127.0.0.1:7227/

```
