```
sendrawtransaction "hexstring" ( allowhighfees, allownonstandard, verbose )

Submits raw transaction (serialized, hex-encoded) to local node and network.
This API does not return until the transaction has been fully validated, and raises
an exception if submission was unsuccessful.

Also see enqueuerawtransaction, createrawtransaction and signrawtransaction calls.

Arguments:
1. "hexstring"    (string, required) The hex string of the raw transaction)
2. allowhighfees    (boolean, optional, default=false) Allow high fees
3. allownonstandard (string 'standard', 'nonstandard', 'default', optional, default='default')
                    Force standard or nonstandard transaction check
4. alloworphans    (boolean, optional, default=false) Allow orphans and store them in the orphan pool
5. verbose         (boolean, optional, default=false) Return dictionary with additional information

Result:
"hex"             (string) The transaction hash in hex

Examples:

Send a transaction
> nexa-cli sendrawtransaction "signedhex"

Send the transaction (signed hex)
> nexa-cli sendrawtransaction "signedhex"

As a json rpc call
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "sendrawtransaction", "params": ["signedhex"] }' -H 'content-type: text/plain;' http://127.0.0.1:7227/

```
