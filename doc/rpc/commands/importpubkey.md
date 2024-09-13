```
importpubkey "pubkey" ( "label" rescan )

Adds a public key (in hex) that can be watched as if it were in your wallet but cannot be used to spend.

Arguments:
1. "pubkey"           (string, required) The hex-encoded public key
2. "label"            (string, optional, default="") An optional label
3. rescan               (boolean, optional, default=true) Rescan the wallet for transactions

Note: This call can take minutes to complete if rescan is true.

Examples:

Import a public key with rescan
> nexa-cli importpubkey "mypubkey"

Import using a label without rescan
> nexa-cli importpubkey "mypubkey" "testing" false

As a JSON-RPC call
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "importpubkey", "params": ["mypubkey", "testing", false] }' -H 'content-type: text/plain;' http://127.0.0.1:7227/

```
