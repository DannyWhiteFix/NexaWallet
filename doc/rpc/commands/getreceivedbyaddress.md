```
getreceivedbyaddress "address" ( minconf )

Returns the total amount received by the given address in transactions with at least minconf confirmations.

Arguments:
1. "address"           (string, required) The address for transactions.
2. minconf             (numeric, optional, default=1) Only include transactions confirmed at least this many times.

Result:
amount   (numeric) The total amount in NEX received at this address.

Examples:

The amount from transactions with at least 1 confirmation
> nexa-cli getreceivedbyaddress "nexa:qpnfq7r98lkm2h7jksy0h5mqpwvttxlc3q6zkwmcha"

The amount including unconfirmed transactions, zero confirmations
> nexa-cli getreceivedbyaddress "nexa:qpnfq7r98lkm2h7jksy0h5mqpwvttxlc3q6zkwmcha" 0

The amount with at least 6 confirmation, very safe
> nexa-cli getreceivedbyaddress "nexa:qpnfq7r98lkm2h7jksy0h5mqpwvttxlc3q6zkwmcha" 6

As a json rpc call
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "getreceivedbyaddress", "params": ["nexa:qpnfq7r98lkm2h7jksy0h5mqpwvttxlc3q6zkwmcha", 6] }' -H 'content-type: text/plain;' http://127.0.0.1:7227/

```
