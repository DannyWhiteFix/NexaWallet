```
signdata "address" "msgFormat" "message"

Sign message for use with the CHECKDATASIG instruction.
As per the CHECKDATASIG operation, this RPC normally signs the SHA256 of
the provided message unless the 'hash' message format is specified.
If using the 'hash' message format, provide the hex encoded SHA256 hash
of the message intended to be passed to CHECKDATASIG.


Arguments:
1. "address"  (string, required) The address to use for the private key.
2. "msgFormat"       (string, required) Use "string", "hex", or "hash" to specify the message encoding.
3. "message"         (string, required) The message to create a signature of.
4. "verbose"         (string, optional) pass 'verbose' to return additional info.

Result:
"signature"          (string) The signature of the message encoded in hex

if 'verbose', return a dictionary containing the signature, pubkey and pubkey hash in hex format.

Examples:

Unlock the wallet for 30 seconds
> nexa-cli walletpassphrase "mypassphrase" 30

Create the signature
> nexa-cli signdata "nexa:qq5lslagrktm5qtxfw4ltpd5krehhrh595fc04hv0k" "string" "my message"
> nexa-cli signdata "nexa:qq5lslagrktm5qtxfw4ltpd5krehhrh595fc04hv0k" "hex" "01020304"

As json rpc
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "signdata", "params": ["nexa:qq5lslagrktm5qtxfw4ltpd5krehhrh595fc04hv0k", "string", "my message"] }' -H 'content-type: text/plain;' http://127.0.0.1:7227/

```
