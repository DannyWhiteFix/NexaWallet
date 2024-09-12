```
setaccount "address" "account"

DEPRECATED. Sets the account associated with the given address.

Arguments:
1. "address"  (string, required) The address to be associated with an account.
2. "account"         (string, required) The account to assign the address to.

Examples:
> nexa-cli setaccount "nexa:qpnfq7r98lkm2h7jksy0h5mqpwvttxlc3q6zkwmcha" "tabby"
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "setaccount", "params": ["nexa:qpnfq7r98lkm2h7jksy0h5mqpwvttxlc3q6zkwmcha", "tabby"] }' -H 'content-type: text/plain;' http://127.0.0.1:7227/

```
