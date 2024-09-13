```
removeprunedfunds "txidem"

Deletes the specified transaction from the wallet. Meant for use with pruned wallets and as a companion to importprunedfunds. This will effect wallet balances.

Arguments:
1. "txidem"           (string, required) The hex-encoded idem of the transaction you are deleting

Examples:
> nexa-cli removeprunedfunds "a8d0c0184dde994a09ec054286f1ce581bebf46446a512166eae7628734ea0a5"

As a JSON-RPC call
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "removprunedfunds", "params": ["a8d0c0184dde994a09ec054286f1ce581bebf46446a512166eae7628734ea0a5"] }' -H 'content-type: text/plain;' http://127.0.0.1:7227/

```
