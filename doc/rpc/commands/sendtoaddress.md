```
sendtoaddress "address" amount ( "comment" "comment-to" subtractfeefromamount )

Send an amount to a given address.

Arguments:
1. "address"  (string, required) The address to send to.
2. "amount"      (numeric or string, required) The amount in NEX to send. eg 10.81
3. "comment"     (string, optional) A comment used to store what the transaction is for. 
                             This is not part of the transaction, just kept in your wallet.
4. "comment-to"  (string, optional) A comment to store the name of the person or organization 
                             to which you're sending the transaction. This is not part of the 
                             transaction, just kept in your wallet.
5. subtractfeefromamount  (boolean, optional, default=false) The fee will be deducted from the amount being sent.
                             The recipient will receive less coins than you enter in the amount field.

Result:
"txidem"  (string) The txidem.

Examples:
> nexa-cli sendtoaddress "nexa:qpnfq7r98lkm2h7jksy0h5mqpwvttxlc3q6zkwmcha" 10.81
> nexa-cli sendtoaddress "nexa:qpnfq7r98lkm2h7jksy0h5mqpwvttxlc3q6zkwmcha" 10.81 "donation" "seans outpost"
> nexa-cli sendtoaddress "nexa:qpnfq7r98lkm2h7jksy0h5mqpwvttxlc3q6zkwmcha" 10.81 "" "" true
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "sendtoaddress", "params": ["nexa:qpnfq7r98lkm2h7jksy0h5mqpwvttxlc3q6zkwmcha", 10.81, "donation", "seans outpost"] }' -H 'content-type: text/plain;' http://127.0.0.1:7227/

```
