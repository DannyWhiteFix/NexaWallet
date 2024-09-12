```
estimatesmartfee nblocks

WARNING: This interface is unstable and may disappear or change!

This rpc call now does the same thing as estimatefee, It has not been removed for
compatibility reasons

Estimates the approximate fee per kilobyte needed for a transaction to begin
confirmation within nblocks blocks.

Arguments:
1. nblocks     (numeric)

Result:
{
  "feerate" : x.x,     (numeric) estimate fee-per-kilobyte (in Nexa)
  "blocks" : 1         (numeric) hardcoded to 1 for backwards compatibility reasons
}

A negative value is returned if not enough transactions and blocks
have been observed to make an estimate.

Example:
> nexa-cli estimatesmartfee 6

```
