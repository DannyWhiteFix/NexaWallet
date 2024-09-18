```
set
Sets the value of a configuration option.  Parameters must be of the format name=value (use name="the value" for strings)

Arguments: <configuration setting name>=<value> <configuration setting name2>=<value2>...

Result:
the new settings or error string

Examples:
> nexa-cli set mining.blockSize=50000 
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "set mining.blockSize=50000 set mining.coinbaseReserve=2000", "params": [] }' -H 'content-type: text/plain;' http://127.0.0.1:7227/

```
