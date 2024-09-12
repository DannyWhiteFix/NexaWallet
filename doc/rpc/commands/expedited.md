```
expedited block|tx "node IP addr" on|off

Request expedited forwarding of blocks and/or transactions from a node.
Expedited forwarding sends blocks or transactions to a node before the node requests them.  This reduces latency, potentially at the expense of bandwidth.

Arguments:
1. "block | tx"        (string, required) choose block to send expedited blocks, tx to send expedited transactions
2. "node ip addr"     (string, required) The node's IP address or IP and port (see getpeerinfo for nodes)
3. "on | off"     (string, required) Turn expedited service on or off

Examples:
> nexa-cli expedited block "192.168.0.6:7228" on
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "expedited", "params": ["block", "192.168.0.6:7228", "on"] }' -H 'content-type: text/plain;' http://127.0.0.1:7227/

```
