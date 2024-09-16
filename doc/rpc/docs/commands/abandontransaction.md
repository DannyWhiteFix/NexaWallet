```
abandontransaction "txid" or "txidem"

Mark in-wallet transaction as abandoned
This will mark this transaction and all its in-wallet descendants as abandoned which will allow
for their inputs to be respent.  It can be used to replace "stuck" or evicted transactions.
It only works on transactions which are not included in a block.  It removes transactions currently
in the txpool.  It has no effect on transactions which are already conflicted or abandoned.

Arguments:
1. "txid or txidem"    (string, required) The transaction id or idem

Result:

Examples:
> nexa-cli abandontransaction "1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d"
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "abandontransaction", "params": ["1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d"] }' -H 'content-type: text/plain;' http://127.0.0.1:7227/

```
