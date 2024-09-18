```
dumptokenset
Dumps all generated group ids in the token description database, one per line using a comma separated format (json array)

Result:
[
group id 1,
...,
group id N
]

Examples:
> nexa-cli dumptokenset 
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "dumptokenset", "params": [] }' -H 'content-type: text/plain;' http://127.0.0.1:7227/

```
