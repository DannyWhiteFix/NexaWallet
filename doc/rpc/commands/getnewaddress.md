```
getnewaddress ("type" "account" )

Returns a new address for receiving payments.
If 'account' is specified (DEPRECATED), it is added to the address book 
so payments received with the address will be credited to 'account'.

Arguments:
1. "type" (string, optional) 'p2pkt' for pay to public key template or 'p2pkh' (legacy)2. "account"        (string, optional) DEPRECATED. The account name for the address to be linked to. If not provided, the default account "" is used. It can also be set to the empty string "" to represent the default account. The account does not need to exist, it will be created if there is no account by the given name.

Result:
"address"    (string) The new address

Examples:
> nexa-cli getnewaddress 
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "getnewaddress", "params": [] }' -H 'content-type: text/plain;' http://127.0.0.1:7227/

```
