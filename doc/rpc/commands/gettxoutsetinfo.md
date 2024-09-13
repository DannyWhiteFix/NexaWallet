```
gettxoutsetinfo

Returns statistics about the unspent transaction output set.
Note this call may take some time.

Result:
{
  "height":n,     (numeric) The current block height (index)
  "bestblock": "hex",   (string) the best block hash hex
  "txouts": n,            (numeric) The number of output transactions
  "hash_serialized": "hash",   (string) The hash of the serialized UTXO (commitment)
  "disk_size": n,         (numeric) The estimated size of the chainstate on disk
  "total_amount": x.xxx          (numeric) The total amount
}

Examples:
> nexa-cli gettxoutsetinfo 
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "gettxoutsetinfo", "params": [] }' -H 'content-type: text/plain;' http://127.0.0.1:7227/

```
