```
get
Returns the value of a configuration setting

Arguments: configuration setting name

Result:
  {
    "setting name" : value of the setting
    ...
  }

Examples:
> nexa-cli get a b 
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "get a b", "params": [] }' -H 'content-type: text/plain;' http://127.0.0.1:7227/

```
