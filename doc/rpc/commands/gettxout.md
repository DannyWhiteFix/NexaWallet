```
gettxout "txidem" n ( includetxpool )

Returns details about an unspent transaction output.

Arguments:
1. "txidem or outpoint"       (string, required) The transaction idem or outpoint hash
2. n              (numeric, optional) vout value if idem provided, pass -1 or nothing if outpoint
3. includetxpool  (boolean, optional) Whether to included the mem pool

Result:
{
  "bestblock" : "hash",    (string) the block hash
  "confirmations" : n,       (numeric) The number of confirmations
  "value" : x.xxx,           (numeric) The transaction value in NEX
  "scriptPubKey" : {         (json object)
     "asm" : "code",       (string) 
     "hex" : "hex",        (string) 
     "reqSigs" : n,          (numeric) Number of required signatures
     "type" : "pubkeyhash", (string) The type, eg pubkeyhash
     "addresses" : [          (array of string) array of nexa addresses
        "nexaaddress"     (string) nexa address
        ,...
     ]
  },
  "version" : n,            (numeric) The version
  "coinbase" : true|false   (boolean) Coinbase or not
}

Examples:

Get unspent transactions
> nexa-cli listunspent 

View the details
> nexa-cli gettxout "txidem" 1

As a json rpc call
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "gettxout", "params": ["txidem", 1] }' -H 'content-type: text/plain;' http://127.0.0.1:7227/

```
