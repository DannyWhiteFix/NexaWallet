```
importprivatekeys [rescan | no-rescan] "nexaprivatekey"...

Adds private keys (as returned by dumpprivkey) to your wallet.

Arguments:
1. "rescan | no-rescan" (string, optional default rescan) If "no-rescan", skip wallet rescan
2. "nexaprivatekey"   (string, at least 1 required) The private keys (see dumpprivkey)

Note: This command will return before the rescan (may take hours) is complete.

Examples:

Dump a private key
> nexa-cli dumpprivkey "myaddress"

Import the private key with rescan
> nexa-cli importprivatekey "mykey"

Import using a label and without rescan
> nexa-cli importprivatekeys no-rescan "mykey"

As a JSON-RPC call
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "importprivatekeys", "params": ["mykey"] }' -H 'content-type: text/plain;' http://127.0.0.1:7227/

```
