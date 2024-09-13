```
validateblocktemplate "hexdata"

Returns whether this block template will be accepted if a hash solution is found.
The 'jsonparametersobject' parameter is currently ignored.
See https://en.bitcoin.it/wiki/BIP_0022 for full specification.

Arguments
1. "hexdata"    (string, required) the hex-encoded block to validate (same format as submitblock)

Result:
true (boolean) submitted block template is valid
JSONRPCException if submitted block template is invalid

Examples:
> nexa-cli validateblocktemplate "mydata"
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "validateblocktemplate", "params": ["mydata"] }' -H 'content-type: text/plain;' http://127.0.0.1:7227/

```
