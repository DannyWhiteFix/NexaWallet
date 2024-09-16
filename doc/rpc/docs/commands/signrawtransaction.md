```
signrawtransaction "hexstring" ( [{"outpoint":"hash","amount":n,"scriptPubKey":"hex","redeemScript":"hex"},...] ["privatekey1",...] sighashtype sigtype )

Sign inputs for raw transaction (serialized, hex-encoded).
The second optional argument (may be null) is an array of previous transaction outputs that
this transaction depends on but may not yet be in the block chain.
The third optional argument (may be null) is an array of base58-encoded private
keys that, if given, will be the only keys used to sign the transaction.


Arguments:
1. "hexstring"     (string, required) The transaction hex string
2. "prevtxs"       (string, optional) An json array of previous dependent transaction outputs
     [               (json array of json objects, or 'null' if none provided)
       {
         "outpoint":"id",             (string, required) The outpoint hash
         "amount":n,                  (numeric, required) The amount of coins in this outpoint
         "scriptPubKey": "hex",   (string, required) script key
         "redeemScript": "hex"    (string, required for P2SH) redeem script
         "amount": value            (numeric, required) The amount spent
       }
       ,...
    ]
3. "privatekeys"     (string, optional) A json array of base58-encoded private keys for signing
    [                  (json array of strings, or 'null' if none provided)
      "privatekey"   (string) private key in base58-encoding
      ,...
    ]
4. "sighashtype"     (string, optional, default=ALL) The signature hash type. Must be one of
       "ALL"
       "NONE"
       "SINGLE"
       followed by ANYONECANPAY and/or FORKID/NOFORKID flags separated with |, for example
       "ALL|ANYONECANPAY|FORKID"
       "NONE|FORKID"
       "SINGLE|ANYONECANPAY"
5. "sigtype"     (string, optional, default="0") The signature type. Must be one of
       "0" or "ECDSA" to select ECDSA, 
       "1" or "Schnorr" to select Schnorr 

Result:
{
  "hex" : "value",           (string) The hex-encoded raw transaction with signature(s)
  "txid" : "id",             (string) The transaction id (identifier for this exact transaction)
  "txidem" : "idem",         (string) The transaction idem (malleability resistant identifier)
  "complete" : true|false,   (boolean) If the transaction has a complete set of signatures
  "errors" : [                 (json array of objects) Script verification errors (if there are any)
    {
      "outpoint" : "hash",           (string) The hash of the referenced, previous outpoint
      "amount" : n,                (numeric) The quantity of coins being spent
      "scriptSig" : "hex",       (string) The hex-encoded signature script
      "sequence" : n,            (numeric) Script sequence number
      "error" : "text"           (string) Verification or signing error related to the input
    }
    ,...
  ]
}

Examples:
> nexa-cli signrawtransaction "myhex"
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "signrawtransaction", "params": ["myhex"] }' -H 'content-type: text/plain;' http://127.0.0.1:7227/

```
