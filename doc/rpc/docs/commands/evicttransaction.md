```
evicttransaction "txid"

Remove transaction from txpool.  Note that it could be re-added quickly if relayed by another node

Arguments:
1. "txid"       (string, required) The transaction id

Result:
The number of transactions removed (children must also be removed)

Examples:
> nexa-cli evicttransaction "txid"
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "evicttransaction", "params": ["txid"] }' -H 'content-type: text/plain;' http://127.0.0.1:7227/

```
