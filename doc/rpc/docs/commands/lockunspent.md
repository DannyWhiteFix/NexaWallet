```
lockunspent unlock [{"txidem":"txidem","vout":n},...]
lockunspent unlock ["outpointhash",...]

Updates list of temporarily unspendable outputs.
Temporarily lock (unlock=false) or unlock (unlock=true) specified transaction outputs.
A locked transaction output will not be chosen by automatic coin selection, when spending coins.
Locks are stored in memory only. Nodes start with zero locked outputs, and the locked output list
is always cleared (by virtue of process exit) when a node stops or fails.
Also see the listunspent call

Arguments:
1. unlock            (boolean, required) Whether to unlock (true) or lock (false) the specified transactions
2. "transactions"  (string, required) A json array of objects. Each object the txidem (string) vout (numeric)
     [           (json array of json objects)
       {
         "txidem":"id",    (string) The transaction id
         "vout": n         (numeric) The output number
       }
       ,...
     ]

Result:
true|false    (boolean) Whether the command was successful or not

Examples:

List the unspent transactions
> nexa-cli listunspent 

Lock an unspent transaction
> nexa-cli lockunspent false "[{\"txidem\":\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\",\"vout\":1}]"

List the locked transactions
> nexa-cli listlockunspent 

Unlock the transaction again
> nexa-cli lockunspent true "[{\"txidem\":\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\",\"vout\":1}]"

As a json rpc call
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "lockunspent", "params": [false, "[{\"txidem\":\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\",\"vout\":1}]"] }' -H 'content-type: text/plain;' http://127.0.0.1:7227/

```
