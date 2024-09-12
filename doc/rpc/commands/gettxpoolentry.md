```
gettxpoolentry txid

Returns txpool data for given transaction

Arguments:
1. "txid"                   (string, required) The transaction id (must be in txpool)

Result:
{                           (json object)
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
}

Examples
> nexa-cli gettxpoolentry "mytxid"
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "gettxpoolentry", "params": ["mytxid"] }' -H 'content-type: text/plain;' http://127.0.0.1:7227/

```
