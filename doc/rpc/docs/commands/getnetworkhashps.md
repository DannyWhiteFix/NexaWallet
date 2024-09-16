```
getnetworkhashps ( blocks height )

Returns the estimated network hashes per second based on the last n blocks.
Pass in [blocks] to override # of blocks.
Pass in [height] to estimate the network speed at the time when a certain block was found.

Arguments:
1. blocks     (numeric, optional, default=600) The number of blocks (20 hours).
2. height     (numeric, optional, default=-1) To estimate at the time of the given height.

Result:
x             (numeric) Hashes per second estimated

Examples:
> nexa-cli getnetworkhashps 
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "getnetworkhashps", "params": [] }' -H 'content-type: text/plain;' http://127.0.0.1:7227/

```
