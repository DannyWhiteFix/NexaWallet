```
getorphanpoolinfo

Returns details on the active state of the TX orphan pool.

Result:
{
  "size": xxxxx,               (numeric) Current tx count
  "bytes": xxxxx,              (numeric) Sum of all tx sizes
}

Examples:
> nexa-cli getorphanpoolinfo 
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "getorphanoolinfo", "params": [] }' -H 'content-type: text/plain;' http://127.0.0.1:7227/

```
