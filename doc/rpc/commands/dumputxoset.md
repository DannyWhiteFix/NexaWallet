```
dumputxoset "filename"
Dumps all utxoset destination address and amount, one per line using a comma separetad format, overwriting existing files is not permitted.

Arguments:
1. "filename"    (string, required) The filename with path (either absolute or relative to nexad)

Result:
{                           (json object)
  "filename" : {        (string) The filename with full absolute path
}

Examples:
> nexa-cli dumputxoset "test"
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "dumputxset", "params": ["test"] }' -H 'content-type: text/plain;' http://127.0.0.1:7227/

```
