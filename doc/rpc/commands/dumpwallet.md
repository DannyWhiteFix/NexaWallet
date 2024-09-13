```
dumpwallet "filename"

Dumps all wallet keys in a human-readable format to a server-side file. This does not allow overwriting existing files.

Arguments:
1. "filename"    (string, required) The filename with path (either absolute or relative to nexad)

Result:
{                           (json object)
  "filename" : {        (string) The filename with full absolute path
}

Examples:
> nexa-cli dumpwallet "test"
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "dumpwallet", "params": ["test"] }' -H 'content-type: text/plain;' http://127.0.0.1:7227/

```
