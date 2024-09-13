```
getinfo
Returns an object containing various state info.

Result:
{
  "version": xxxxx,           (numeric) the server version
  "protocolversion": xxxxx,   (numeric) the protocol version
  "walletversion": xxxxx,     (numeric) the wallet version
  "balance": xxxxxxx,         (numeric) the total  balance of the wallet
  "blocks": xxxxxx,           (numeric) the current number of blocks processed in the server
  "headers": xxxxxx,          (numeric) the current number of headers processed in the server
  "timeoffset": xxxxx,        (numeric) the time offset
  "connections": xxxxx,       (numeric) the number of connections
  "peers_graphene": xxxxx     (numeric) the number of grapheneblock peers
  "peers_xthinblock": xxxxx,  (numeric) the number of xthinblock peers
  "peers_cmpctblock": xxxxx,  (numeric) the number of compactblock peers
  "proxy": "host:port",     (string, optional) the proxy used by the server
  "difficulty": xxxxxx,       (numeric) the current difficulty
  "testnet": true|false,      (boolean) if the server is using testnet or not
  "keypoololdest": xxxxxx,    (numeric) the timestamp (seconds since GMT epoch) of the oldest pre-generated key in the key pool
  "keypoolsize": xxxx,        (numeric) how many new keys are pre-generated
  "unlocked_until": ttt,      (numeric) the timestamp in seconds since epoch (midnight Jan 1 1970 GMT) that the wallet is unlocked for transfers, or 0 if the wallet is locked
  "paytxfee": xxxx,           (numeric) the transaction fee set in sat/KB
  "relayfee": xxxx,           (numeric) minimum relay fee for non-free transactions in sat/KB
  "status":"..."            (string) long running operations are indicated here (rescan).
  "txindex":"synced|trailing|not ready" (string) indicate the current state of the txindex.
  "errors": "..."           (string) any error messages
}

Examples:
> nexa-cli getinfo 
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "getinfo", "params": [] }' -H 'content-type: text/plain;' http://127.0.0.1:7227/

```
