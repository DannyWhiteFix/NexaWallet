```
getrawtransactionssince

Return the raw transaction data for <count> blocks starting with blockhash and moving towards the tip.

If verbose=0, each tx is a string that is serialized, hex-encoded data.
If verbose is non-zero, returns an array of Objects with information about each tx in the block.

Arguments:
1. "-v" or "--verbose" (string, optional, default=false) return an array of txid:hexstring, other return an array of tx json object
2. "hashblock" (string, required) The block hash
3. count    (numeric, optional, default=1) Fetch information for <count> blocks starting with <hashblock> and moving towards the chain tip
4. "protocol_id" (string, optional) The protocol id to search OP_RETURN for. Use * as a wildcard for any id. If this param is entered we will not return any transactions that do not meet the protocol id criteria

Result (if verbose is not set or set to 0):
{
  "hash" : {    (string) the block hash
  "txidem" : "data",      (string) 'txidem': the idem of a transaction in the block,
                              (string) 'data': The serialized, hex-encoded transaction contents
        ...
  },
  ...
}

Result (if verbose > 0):
{
  "in_active_chain": b,            (bool) Whether specified block is in the active chain or not (only present with explicit "blockhash" argument)
  "hex" : "data",                  (string) The serialized, hex-encoded data for 'txid'
  "txid" : "id",                   (string) The transaction id (identifier for this exact transaction)
  "txidem" : "idem",               (string) The transaction idem (malleability resistant identifier)
  "size" : n,                      (numeric) The transaction size
  "version" : n,                   (numeric) The version
  "locktime" : ttt,                (numeric) The lock time
  "spends" : n,                    (numeric) The total quantity of NEX input into this transaction
  "sends" : n,                     (numeric) The total quantity of NEX in this transaction's outputs
  "fee" : n,                       (numeric) The fee paid to miners (fee = spends - sends)
  "vin" : [                        (array of json objects)
     {
       "outpoint": "id",           (string) The outpoint hash
       "amount": n,                (numeric) 
       "scriptSig": {              (json object) The script
         "asm": "asm",             (string) asm
         "hex": "hex"              (string) hex
       },
       "sequence": n               (numeric) The script sequence number
     }
     ,...
  ],
  "vout" : [                       (array of json objects)
     {
       "outpoint": "id",           (string) The outpoint hash
       "value" : x.xxx,            (numeric) The value in 
       "n" : n,                    (numeric) index
       "scriptPubKey" : {          (json object)
         "asm" : "asm",            (string) the asm
         "hex" : "hex",            (string) the hex
         "reqSigs" : n,            (numeric) The required sigs
         "type" : "pubkeyhash",    (string) The type, eg 'pubkeyhash'
         "group" : "groupID",      (string, optional) If grouped, the group identity
         "groupQuantity": n,       (numeric, optional) If grouped, the amount of tokens
         "groupAuthority": n,      (numeric, optional) If an authority, the authority flags
         "addresses" : [           (json array of string)
           "nexaaddress"           (string) nexa address
           ,...
         ]
       }
     }
     ,...
  ],
  "blockhash" : "hash",            (string) the block hash
  "confirmations" : n,             (numeric) The confirmations
  "time" : ttt,                    (numeric) The transaction time in seconds since epoch (Jan 1 1970 GMT)
  "blocktime" : ttt                (numeric) The block time in seconds since epoch (Jan 1 1970 GMT)
}

Examples:
> nexa-cli getrawtransactionssince "hashblock"
> nexa-cli getrawtransactionssince -v "hashblock"
> nexa-cli getrawtransactionssince -v "hashblock" 10
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "getrawtransactionssince", "params": [-v "hashblock", 10] }' -H 'content-type: text/plain;' http://127.0.0.1:7227/

```
