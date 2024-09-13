```
fundrawtransaction "hexstring" includeWatching

Add inputs to a transaction until it has enough in value to meet its out value.
This will not modify existing inputs, and will add one change output to the outputs.
Note that inputs which were signed may need to be resigned after completion since in/outputs have been added.
The inputs added will not be signed, use signrawtransaction for that.
Note that all existing inputs must have their previous output transaction be in the wallet.
Note that all inputs selected must be of standard form and P2SH scripts must bein the wallet using importaddress or addmultisigaddress (to calculate fees).
Only pay-to-pubkey, multisig, and P2SH versions thereof are currently supported for watch-only

Arguments:
1. "hexstring"     (string, required) The hex string of the raw transaction
2. includeWatching (boolean, optional, default false) Also select inputs which are watch only

Result:
{
  "hex":       "value", (string)  The resulting raw transaction (hex-encoded string)
  "fee":       n,         (numeric) Fee the resulting transaction pays
  "changepos": n          (numeric) The position of the added change output, or -1
}
"hex"             

Examples:

Create a transaction with no inputs
> nexa-cli createrawtransaction "[]" "{\"myaddress\":10.01}"

Add sufficient unsigned inputs to meet the output value
> nexa-cli fundrawtransaction "rawtransactionhex"

Sign the transaction
> nexa-cli signrawtransaction "fundedtransactionhex"

Send the transaction
> nexa-cli sendrawtransaction "signedtransactionhex"

```
