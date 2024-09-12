```
signmessage "address" "message"

Sign a message with the private key of an address.  This is NOT compatible with CHECKDATASIG
 (use signdata instead).

Arguments:
1. "address"  (string, required) The coin address to use for the private key.
2. "message"         (string, required) The message to create a signature of.

Result:
"signature"          (string) The signature of the message encoded in base 64

Examples:

Unlock the wallet for 30 seconds
> nexa-cli walletpassphrase "mypassphrase" 30

Create the signature
> nexa-cli signmessage "nexa:qpnfq7r98lkm2h7jksy0h5mqpwvttxlc3q6zkwmcha" "my message"

Verify the signature
> nexa-cli verifymessage "nexa:qpnfq7r98lkm2h7jksy0h5mqpwvttxlc3q6zkwmcha" "signature" "my message"

As json rpc
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "signmessage", "params": ["nexa:qpnfq7r98lkm2h7jksy0h5mqpwvttxlc3q6zkwmcha", "my message"] }' -H 'content-type: text/plain;' http://127.0.0.1:7227/

```
