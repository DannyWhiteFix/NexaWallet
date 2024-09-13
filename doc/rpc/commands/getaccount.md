```
getaccount "address"

DEPRECATED. Returns the account associated with the given address.

Arguments:
1. "address"  (string, required) The address for account lookup.

Result:
"accountname"        (string) the account address

Examples:
> nexa-cli getaccount "nexa:qpnfq7r98lkm2h7jksy0h5mqpwvttxlc3q6zkwmcha"
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "getaccount", "params": ["nexa:qpnfq7r98lkm2h7jksy0h5mqpwvttxlc3q6zkwmcha"] }' -H 'content-type: text/plain;' http://127.0.0.1:7227/

```
