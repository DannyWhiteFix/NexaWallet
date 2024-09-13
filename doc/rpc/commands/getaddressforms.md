```
getaddressforms "address"

Returns all ways of displaying this address.

Arguments
1. "address"    (string, required) the address

Result:
{
"legacy": "base58 encoding (OBSOLETE DO NOT USE)",
"nexa": "nexa prefixed address",

If this wallet is unlocked and owns this address additional information is supplied:
"pubkey": "public key corresponding to this address"
"p2pkh": "The pay-to-pub-key-hash address corresponding to this pubkey"
"p2pkt": "The pay-to-pub-key-template address corresponding to this pubkey"

If this address is a wrapped output script, the script is provided:
"outScript": "The disassembly of the output script specified by this address"
"outScriptHex": "The hex of the output script specified by this address"
}

Examples:
> nexa-cli getaddressforms "address"
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "getaddressforms", "params": ["address"] }' -H 'content-type: text/plain;' http://127.0.0.1:7227/

```
