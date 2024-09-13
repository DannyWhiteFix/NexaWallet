```
getrawtxpool ( verbose ) (id or idem)

Returns all transaction ids in memory pool as a json array of string transaction ids.

Arguments:
1. verbose           (boolean, optional, default=false) true for a json object, false for array of 2. id or idem        (string, optional, default=idem) return transaction idem or id

Result: (for verbose = false):
[                     (json array of string)
  "transactionid"     (string) The transaction id
  ,...
]

Result: (for verbose = true):
{                           (json object)
  "transactionid" : {       (json object)
    "size" : n,             (numeric) transaction size in bytes
    "fee" : n,              (numeric) transaction fee in NEX
    "modifiedfee" : n,      (numeric) transaction fee with fee deltas used for mining priority
    "time" : n,             (numeric) local time transaction entered pool in seconds since 1 Jan 1970 GMT
    "height" : n,           (numeric) block height when transaction entered pool
    "doublespent" : true|false   (boolean) has the transaction been double spent
    "startingpriority" : n, (numeric) priority when transaction entered pool
    "currentpriority" : n,  (numeric) transaction priority now (including manual adjustments)
    "ancestorcount" : n,    (numeric) number of in-txpool ancestor transactions (including this one)
    "ancestorsize" : n,     (numeric) size of in-txpool ancestors (including this one)
    "ancestorfees" : n,     (numeric) modified fees (see above) of in-txpool ancestors (including this one)
    "depends" : [           (array) unconfirmed transactions used as inputs for this transaction
        "transactionid",    (string) parent transaction idem
       ... ]
    "spentby" : [           (array) unconfirmed transactions spending outputs from this transaction
        "transactionidem",    (string) child transaction idem
       ... ]
  }, ...
}

Examples
> nexa-cli getrawtxpool true
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "getrawtxpool", "params": [true] }' -H 'content-type: text/plain;' http://127.0.0.1:7227/

```
