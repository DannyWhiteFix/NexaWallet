```
getblockcount

Returns the number of blocks in the longest block chain.

Result:
n    (numeric) The current block count

Examples:
> nexa-cli getblockcount 
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "getblockcount", "params": [] }' -H 'content-type: text/plain;' http://127.0.0.1:7227/

```
