```
setminercomment

Set the comment that will be put into each mined block's coinbase
 transaction after the standard parameters.
 Comments that are too long will be truncated.
Examples:
> nexa-cli setminercomment "nakamoto consensus is emergent"
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "setminercomment", "params": ["nakamoto consensus is emergent"] }' -H 'content-type: text/plain;' http://127.0.0.1:7227/

```
