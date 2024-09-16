```
importprivkey "nexaprivkey" ( "label" rescan )

Adds a private key (as returned by dumpprivkey) to your wallet.

Arguments:
1. "nexaprivkey"   (string, required) The private key (see dumpprivkey)
2. "label"            (string, optional, default="") An optional label
3. rescan               (boolean, optional, default=true) Scan the blockchain for transactions

Note: This call can take hours to complete if rescan is true.  To import multiple private keys

use the importprivatekeys RPC call.

Examples:

Dump a private key
> nexa-cli dumpprivkey "myaddress"

Import the private key with rescan
> nexa-cli importprivkey "mykey"

Import using rescan and label
> nexa-cli importprivkey "mykey" "mylabel"

Import without rescan (must use a label)
> nexa-cli importprivkey "mykey" "mylabel" false

As a JSON-RPC call
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "importprivkey", "params": ["mykey", "mylabel", false] }' -H 'content-type: text/plain;' http://127.0.0.1:7227/

```
