```
enqueuerawtransaction "hexstring" ( options )

Submits raw transaction (serialized, hex-encoded) to local node and network.
This RPC by default does not wait for transaction validation and so is very fast.

Also see sendrawtransaction, createrawtransaction and signrawtransaction calls.

Arguments:
1. "hexstring"    (string, required) The hex string of the raw transaction)
2. "options"      (string, optional) "flush" to wait for every enqueued transaction to be handled

Result:
"hex"             (string) The transaction hash in hex

Examples:

Create a transaction
> nexa-cli createrawtransaction "[{\"txid\" : \"mytxid\",\"vout\":0}]" "{\"myaddress\":0.01}"
Sign the transaction, and get back the hex
> nexa-cli signrawtransaction "myhex"

Send the transaction (signed hex)
> nexa-cli enqueuerawtransaction "signedhex"

As a json rpc call
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "enqueuerawtransaction", "params": ["signedhex"] }' -H 'content-type: text/plain;' http://127.0.0.1:7227/

```
