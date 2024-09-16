```
getminercomment

Return the comment that will be put into each mined block's coinbase
 transaction after the standard parameters.
Result
  minerComment (string) miner comment

Examples:
> nexa-cli getminercomment 
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "getminercomment", "params": [] }' -H 'content-type: text/plain;' http://127.0.0.1:7227/

```
