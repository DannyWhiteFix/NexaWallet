```
addmultisigaddress nrequired ["key",...] ( "account" )

Add a nrequired-to-sign multisignature address to the wallet.
Each key is an address or hex-encoded public key.
If 'account' is specified (DEPRECATED), assign address to that account.

Arguments:
1. nrequired      (numeric, required) The number of required signatures out of the n keys or addresses.
2. "keysobject"   (string, required) A json array of addresses or hex-encoded public keys
     [
       "address"  (string) address or hex-encoded public key
       ...,
     ]
3. "account"      (string, optional) DEPRECATED. An account to assign the addresses to.

Result:
"address"  (string) A address associated with the keys.

Examples:

Add a multisig address from 2 addresses
> nexa-cli addmultisigaddress 2 "[\"nexa:qpnfq7r98lkm2h7jksy0h5mqpwvttxlc3q6zkwmcha\",\"nexa:qqqdf524crwrn659hattd40jn5ykz32xey7z6n5z28\"]"

As json rpc call
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "addmultisigaddress", "params": [2, "[\"nexa:qpnfq7r98lkm2h7jksy0h5mqpwvttxlc3q6zkwmcha\",\"nexa:qqqdf524crwrn659hattd40jn5ykz32xey7z6n5z28\"]"] }' -H 'content-type: text/plain;' http://127.0.0.1:7227/

```
