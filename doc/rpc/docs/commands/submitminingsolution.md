```
submitminingsolution "Mining-Candidate data" ( "jsonparametersobject" )

Attempts to submit a new block to the network.

Arguments
1. "submitminingsolutiondata"    (string, required) the mining solution (JSON encoded) data to submit

Result:

dictionary of 'hash', 'height' and 'result' which is empty if accepted
and an error string if block was rejected.
Identical to "submitblock".

Examples:
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "submitminingsolution", "params": ["mydata"] }' -H 'content-type: text/plain;' http://127.0.0.1:7227/

```
