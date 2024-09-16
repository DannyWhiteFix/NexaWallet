```
move "fromaccount" "toaccount" amount ( minconf "comment" )

DEPRECATED. Move a specified amount from one account in your wallet to another.

Arguments:
1. "fromaccount"   (string, required) The name of the account to move funds from. May be the default account using "".
2. "toaccount"     (string, required) The name of the account to move funds to. May be the default account using "".
3. amount            (numeric) Quantity of NEX to move between accounts.
4. minconf           (numeric, optional, default=1) Only use funds with at least this many confirmations.
5. "comment"       (string, optional) An optional comment, stored in the wallet only.

Result:
true|false           (boolean) true if successful.

Examples:

Move 10.01 NEX from the default account to the account named tabby
> nexa-cli move "" "tabby" 10.01

Move 0.01 NEX timotei to akiko with a comment and funds have 6 confirmations
> nexa-cli move "timotei" "akiko" 10.01 6 "happy birthday!"

As a json rpc call
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "move", "params": ["timotei", "akiko", 10.01, 6, "happy birthday!"] }' -H 'content-type: text/plain;' http://127.0.0.1:7227/

```
