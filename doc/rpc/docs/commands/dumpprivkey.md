```
dumpprivkey "nexaaddress"

Reveals the private key corresponding to 'nexaaddress'.
Then the importprivkey can be used with this output

Arguments:
1. "nexaaddress"   (string, required) The nexa address for the private key

Result:
"key"                (string) The private key

Examples:
> nexa-cli dumpprivkey "myaddress"
> nexa-cli importprivkey "mykey"
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "dumpprivkey", "params": ["myaddress"] }' -H 'content-type: text/plain;' http://127.0.0.1:7227/

```
