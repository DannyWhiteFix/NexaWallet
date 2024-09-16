```
validaterawtransaction "hexstring" ( allowhighfees, allownonstandard )

Validates raw transaction (serialized, hex-encoded) to local node without broadcasting it.

Also see createrawtransaction and signrawtransaction calls.

Arguments:
1. "hexstring"    (string, required) The hex string of the raw transaction)
2. allowhighfees    (boolean, optional, default=false) Allow high fees
3. allownonstandard (string 'standard', 'nonstandard', 'default', optional, default='default')
                    Force standard or nonstandard transaction check

Result:
{
  "txid" : "value",           (string) The transaction hash
  "isValid" : true|false,   (boolean) Will the transaction be accepted into the memory pool
  "isMineable" : true|false,   (boolean) If the transaction is mineable now
  "isFutureMineable" : true|false,   (boolean) If the transaction is mineable in the future
  "isStandard" : true|false,   (boolean) If the transaction is standard
  "metadata" : {
       "size" : value,        (numeric) The size of the transaction in bytes
       "fee" : value,         (numeric) The amount of fee included in the transaction in satoshi
       "feeneeded" : value,   (numeric) The amount of fee needed for the transactio in satoshi
    },  "errors" : [                 (json array) Script verification errors (if there are any)
      "reason",           (string) A reason the tx would be rejected by the txpool
        ...
    ],
  "input_flags" : {
       "isValid" : true|false,        (boolean) Are all of the tx inputs valid with standard flags
       "inputs" : [
           "isValid" : true|false,        (boolean) is this input valid with standard flags
           "metadata" : {
               "outpoint" : value,        (string) The hash of the referenced outpoint
               "scriptPubKey" : value,   (string) The hex-encoded signature pubkey
               "scriptSig" : value,   (string) The hex-encoded signature script
               "amount" : value,   (numeric) The value of the output spent
             },
           "errors" : [                 (json array) standard flag errors with the input (if there are any)
               "reason",           (string) A reason the input would be rejected with standard flags
                ...
             ]
       ]
    },
  "inputs_mandatoryFlags" : {
       "isValid" : true|false,        (boolean) Are all of the tx inputs valid with mandatory flags
       "inputs" : [
           "isValid" : true|false,        (boolean) is this input valid with mandatory flags
           "metadata" : {
               "outpoint" : value,        (string) The hash of the referenced, previous transaction
               "scriptPubKey" : value,   (string) The hex-encoded signature pubkey
               "scriptSig" : value,   (string) The hex-encoded signature script
               "amount" : value,   (numeric) The value of the output spent
             },
           "errors" : [                 (json array) mandatory flag errors with the input (if there are any)
               "reason",           (string) A reason the input would be rejected with mandatory flags
                ...
             ]
       ]
    }
}

Examples:

Create a transaction
> nexa-cli createrawtransaction "[{\"txid\" : \"mytxid\",\"vout\":0}]" "{\"myaddress\":0.01}"
Sign the transaction, and get back the hex
> nexa-cli signrawtransaction "myhex"

Send the transaction (signed hex)
> nexa-cli sendrawtransaction "signedhex"

As a json rpc call
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "validaterawtransaction", "params": ["signedhex"] }' -H 'content-type: text/plain;' http://127.0.0.1:7227/

```
