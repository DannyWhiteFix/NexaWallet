```
getraworphanpool

Returns all transaction ids in orphan pool as a json array of string transaction ids.

Result:
[                     (json array of string)
  "transactionid"     (string) The transaction id
  ,...
]

Examples
> nexa-cli getraworphanpool 
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "getraworphanpool", "params": [] }' -H 'content-type: text/plain;' http://127.0.0.1:7227/

```
