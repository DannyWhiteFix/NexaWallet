```
listbanned

List all banned IPs/Subnets.

Result:
[
  {
    "address" : "192.168.0.201/32",    (string) The banned IP/Subnet with netmask (/32 = single ip)
    "banned_until" : ttt,              (numeric) The ban expiration time in seconds since epoch (Jan 1 1970 GMT)
    "ban_created" : ttt                (numeric) The ban creation time in seconds since epoch (Jan 1 1970 GMT)
    "ban_reason" : "node misbehaving"  (string) The reason the ban was created
  }
  ,...
]

Examples:
> nexa-cli listbanned 
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "listbanned", "params": [] }' -H 'content-type: text/plain;' http://127.0.0.1:7227/

```
