```
getblockheader hash_or_height ( verbose )

If verbose is false, returns a string that is serialized, hex-encoded data for blockheader 'hash'.
If verbose is true, returns an Object with information about blockheader <hash>.

Arguments:
1. "hash_or_height"          (string|numeric, required) The block hash
2. verbose           (boolean, optional, default=true) true for a json object, false for the hex encoded data

Result (for verbose = true):
{
  "hash" : "hash",     (string) the block hash (same as provided)
  "confirmations" : n,   (numeric) The number of confirmations, or -1 if the block is not on the main chain
  "height" : n,          (numeric) The block height or index
  "size" : n,            (numeric) The size of the block
  "txcount" : n,         (numeric) The number of transactions in the block
  "feePoolAmt" : n,      (numeric) The fee pool amount
  "merkleroot" : "xxxx", (string) The merkle root
  "time" : ttt,          (numeric) The block time in seconds since epoch (Jan 1 1970 GMT)
  "mediantime" : ttt,    (numeric) The median block time in seconds since epoch (Jan 1 1970 GMT)
  "nonce" : n,           (numeric) The nonce
  "bits" : "1d00ffff", (string)  The bits
  "difficulty" : x.xxx,  (numeric) The difficulty
  "chainwork" : "0000...1f3"     (string) Expected number of hashes required to produce the current chain (in hex)
  "utxoCommitment" : n,  (hash)    The utxo commitment
  "minerdata" : "xxxx",        (string) A hex string identifier that the miner provides
  "previousblockhash" : "hash",  (string) The hash of the previous block
  "ancestorblockhash" : "hash",  (string) The hash of the ancestor block
  "nextblockhash" : "hash",      (string) The hash of the next block
}

Result (for verbose=false):
"data"             (string) A string that is serialized, hex-encoded data for block 'hash'.

Examples:
> nexa-cli getblockheader "00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09"
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "getblockheader", "params": ["00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09"] }' -H 'content-type: text/plain;' http://127.0.0.1:7227/

```
