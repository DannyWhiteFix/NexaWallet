```
importaddresses [rescan | no-rescan] "address"...

Adds a script (in hex) or address that can be watched as if it were in your wallet but cannot be used to spend.

Arguments:
1. "rescan | no-rescan" (string, optional, default=rescan) If "no-rescan", skip wallet rescan
2. "address"           (string, 0 or more) The address(es) or hex-encoded P2SH script(s)

Note, this command will return before the rescan (may take hours) is complete.
If you have the full public key, you should call importpublickey instead of this.
This command assumes all scripts are P2SH, so you should call importaddress to
import a nonstandard non-P2SH script.

Examples:

Import 2 scripts with rescan
> nexa-cli importaddresses "myscript1" "myscript2"

Import 2 scripts without rescan
> nexa-cli importaddresses no-rescan "myscript1" "myscript2"

Rescan without import
> nexa-cli importaddresses rescan

As a JSON-RPC call
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "importaddresses", "params": ["myscript1", "myscript2"] }' -H 'content-type: text/plain;' http://127.0.0.1:7227/

```
