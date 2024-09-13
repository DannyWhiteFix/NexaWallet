```
getelectruminfo
Returns the status of the integrated electrum server.

Result:
{ (json object)
    "status" (string) status description
    "index_height" (numeric) block height of last indexed block
    "index_progress" (numeric) index progress as percentage
    "debug" (json object)
    {
      ... debug information, subject to change    }
}
> nexa-cli getelectruminfo 
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "getelectruminfo", "params": [] }' -H 'content-type: text/plain;' http://127.0.0.1:7227/

```
