```
getstatlist
Returns a list of all statistics available on this node.

Arguments: None

Result:
  {
    "name" : (string) name of the statistic
    ...
  }

Examples:
> nexa-cli getstatlist 
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "getstatlist", "params": [] }' -H 'content-type: text/plain;' http://127.0.0.1:7227/

```
