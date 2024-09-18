```
sendfrom "fromaccount" "toaddress" amount ( minconf "comment" "comment-to" )

DEPRECATED (use sendtoaddress). Sent an amount from an account to an address.

Arguments:
1. "fromaccount"       (string, required) The name of the account to send funds from. May be the default account using "".
2. "toaddress"  (string, required) The address to send funds to.
3. amount                (numeric or string, required) The amount in NEX (transaction fee is added on top).
4. minconf               (numeric, optional, default=1) Only use funds with at least this many confirmations.
5. "comment"           (string, optional) A comment used to store what the transaction is for. 
                                     This is not part of the transaction, just kept in your wallet.
6. "comment-to"        (string, optional) An optional comment to store the name of the person or organization 
                                     to which you're sending the transaction. This is not part of the transaction, 
                                     it is just kept in your wallet.

Result:
"transactionid"        (string) The transaction id.

Examples:

Send 0.01 NEX from the default account to the address, must have at least 1 confirmation
> nexa-cli sendfrom "" "nexa:qpnfq7r98lkm2h7jksy0h5mqpwvttxlc3q6zkwmcha" 10.01

Send 10.01 from the tabby account to the given address, funds must have at least 6 confirmations
> nexa-cli sendfrom "tabby" "nexa:qpnfq7r98lkm2h7jksy0h5mqpwvttxlc3q6zkwmcha" 10.01 6 "donation" "seans outpost"

As a json rpc call
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "sendfrom", "params": ["tabby", "nexa:qpnfq7r98lkm2h7jksy0h5mqpwvttxlc3q6zkwmcha", 10.01, 6, "donation", "seans outpost"] }' -H 'content-type: text/plain;' http://127.0.0.1:7227/

```
