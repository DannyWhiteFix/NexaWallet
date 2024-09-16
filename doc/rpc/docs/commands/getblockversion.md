```
getblockversion

Return the block version used when mining.
Result
      (integer) block version number

Examples:
> nexa-cli getblockversion 
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "getblockversion", "params": [] }' -H 'content-type: text/plain;' http://127.0.0.1:7227/

```
