```
gettxpoolinfo

Returns details on the active state of the TX memory pool.

Result:
{
  "size": xxxxx,               (numeric) Current tx count
  "bytes": xxxxx,              (numeric) Sum of all tx sizes
  "usage": xxxxx,              (numeric) Total memory usage for the transaction pool
  "maxtxpool": xxxxx,          (numeric) Maximum memory usage for the transaction pool
  "txpoolminfee": xxxxx        (numeric) Minimum fee for tx to be accepted
  "tps": xxxxx                 (numeric) Transactions per second accepted
  "peak_tps": xxxxx            (numeric) Peak Transactions per second accepted
}

Examples:
> nexa-cli gettxpoolinfo 
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "gettxpoolinfo", "params": [] }' -H 'content-type: text/plain;' http://127.0.0.1:7227/

```
