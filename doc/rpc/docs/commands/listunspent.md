```
listunspent ( minconf maxconf  ["address",...] )

Returns array of unspent transaction outputs
with between minconf and maxconf (inclusive) confirmations.
Optionally filter to only include txouts paid to specified addresses.
Results are an array of Objects, each of which has:
{txid, vout, scriptPubKey, amount, confirmations}

Arguments:
1. minconf          (numeric, optional, default=1) The minimum confirmations to filter
2. maxconf          (numeric, optional, default=9999999) The maximum confirmations to filter
3. "addresses"    (string) A json array of addresses to filter
    [
      "address"   (string) address
      ,...
    ]

Result
[                   (array of json object)
  {
    "outpoint" : "hash"     (string) prevout identifier 
    "txid" : "txid",        (string) the transaction id 
    "txidem" : "txidem",    (string) the transaction idem 
    "vout" : n,               (numeric) the vout value
    "address" : "address",  (string) the address
    "account" : "account",  (string) DEPRECATED. The associated account, or "" for the default account
    "scriptPubKey" : "key", (string) the script key
    "amount" : x.xxx,         (numeric) the transaction amount in NEX
    "confirmations" : n       (numeric) The number of confirmations
  }
  ,...
]

Examples
> nexa-cli listunspent 
> nexa-cli listunspent 6 9999999 "[\"nexa:qqqdf524crwrn659hattd40jn5ykz32xey7z6n5z28\",\"1LtvqCaApEdUGFkpKMM4MstjcaL4dKg8SP\"]"
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "listunspent", "params": [6, 9999999 "[\"nexa:qqqdf524crwrn659hattd40jn5ykz32xey7z6n5z28\",\"1LtvqCaApEdUGFkpKMM4MstjcaL4dKg8SP\"]"] }' -H 'content-type: text/plain;' http://127.0.0.1:7227/

```
