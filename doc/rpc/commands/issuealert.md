```
issuealert "alert"

trigger an alert (executes configured -alertnotify string).

Arguments
1. "alert"    (string, required) the alert text (in quotes if in a shell)

Examples:
> nexa-cli issuealert "this is an alert"
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "issuealert", "params": ["this is an alert"] }' -H 'content-type: text/plain;' http://127.0.0.1:7227/

```
