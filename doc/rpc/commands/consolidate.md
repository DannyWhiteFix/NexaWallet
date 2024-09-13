```
consolidate ("num" "toleave")

Consolidates spendable utxos in the wallet. (-spendzeroconfchange or -wallet.instant
must be enabled)

Arguments:
1. "num"       (number, required) number of coins to select for consolidation)
2. "toleave"   (number, required) minimum number of coins to leave)
3. "verbosity" (boolean, optional, default: false) show also the outpoint of every consolidated utxos (default: false)
4. "address"   (string, optional, default: freshly generated addr from your wallet) address destination where to send coins to

Result:
{
  "amount"       :     (numeric) Amount on NEX consolidated into the destination address
  "destination"  :     "xxxxx" Address used as consolidation destinations
  "txids"        : [   (array of string) The transaction ids
     "transactionid"   (string) The transaction id
     ,...
  ],
  "txidems"      : [    (array of string) The transaction idems
     "transactionidem"  (string) The transaction idem
     ,...
  ],
"outpoints"  : [ (array od string) the outpoints of all consolidated utxos (showed only if verbosity is true)
  "outpoint"     (string) outpoint
     ,...
  ],

Examples:
> nexa-cli consolidate 500 50
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "consolidate", "params": [500, 50] }' -H 'content-type: text/plain;' http://127.0.0.1:7227/

```
