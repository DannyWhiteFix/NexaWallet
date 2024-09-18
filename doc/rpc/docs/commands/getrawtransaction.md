```
getrawtransaction "tx id, idem or outpoint" ( verbose "blockhash" )

NOTE: By default this function only works for txpool or orphanpool transactions. If the -txindex option is enabled, it also works for blockchain transactions. If the block which contains the transaction is known, its hash can be provided even for nodes without -txindex. Note that if a blockhash is provided, only that block will be searched and if the transaction is in the txpool or other
blocks, or if this node does not have the given block available, the transaction will not be found.
DEPRECATED: for now, it also works for transactions with unspent outputs.

Return the raw transaction data.

If verbose=0, returns a string that is serialized, hex-encoded data for 'txid'.
If verbose is non-zero, returns an Object with information about 'txid'.

Arguments:
1. "tx"      (string, required) The transaction id or idem
2. verbose     (bool, optional, default=false) If false, return a string, otherwise return a json object
3. "blockhash" (string, optional) The block in which to look for the transaction

Result (if verbose is not set or set to 0):
"data"      (string) The serialized, hex-encoded data for 'txid'

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
> nexa-cli getrawtransaction "mytxid"
> nexa-cli getrawtransaction "mytxid" true
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "getrawtransaction", "params": ["mytxid", true] }' -H 'content-type: text/plain;' http://127.0.0.1:7227/
> nexa-cli getrawtransaction "mytxid" false "myblockhash"
> nexa-cli getrawtransaction "mytxid" true "myblockhash"

```
