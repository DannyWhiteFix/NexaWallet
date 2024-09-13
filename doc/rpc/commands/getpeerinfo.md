```
getpeerinfo [peer IP address]

Returns data about each connected network node as a json array of objects.

Result:
[
  {
    "id": n,                       (numeric) Peer index
    "addr":"host:port",            (string) The ip address and port of the peer
    "addrlocal":"ip:port",         (string) local address
    "services":"xxxxxxxxxxxxxxxx", (string) The services offered
    "services":"xxxxxxxxxxxxxxxx", (string) The services offered
    "servicesnames":[              (array) the services offered, in human-readable form
        "SERVICE_NAME",         (string) the service name if it is recognised
         ...
     ],
    "relaytxes":true|false,        (boolean) Whether peer has asked us to relay transactions to it
    "lastsend": ttt,               (numeric) The time in seconds since epoch (Jan 1 1970 GMT) of the last send
    "lastrecv": ttt,               (numeric) The time in seconds since epoch (Jan 1 1970 GMT) of the last receive
    "bytessent": n,                (numeric) The total bytes sent
    "bytesrecv": n,                (numeric) The total bytes received
    "conntime": ttt,               (numeric) The connection time in seconds since epoch (Jan 1 1970 GMT)
    "timeoffset": ttt,             (numeric) The time offset in seconds
    "pingtime": n,                 (numeric) ping time
    "minping": n,                  (numeric) minimum observed ping time
    "pingwait": n,                 (numeric) ping wait
    "version": v,                  (numeric) The peer version, such as 7001
    "subver": "/Nexa:x.x.x/",    (string) The string version
    "inbound": true|false,         (boolean) Inbound (true) or Outbound (false)
    "startingheight": n,           (numeric) The starting height (block) of the peer
    "banscore": n,                 (numeric) The ban score
    "synced_headers": n,           (numeric) The last header we have in common with this peer
    "synced_blocks": n,            (numeric) The last block we have in common with this peer
    "inflight": [
       n,                            (numeric) The heights of blocks we're currently asking from this peer
       ...
    ]
    "whitelisted": true|false,     (boolean) Whether we have whitelisted this peer, preventing us from banning the node due to misbehavior, though we may still disconnect it
  }
  ,...
]

Examples:
> nexa-cli getpeerinfo 
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "getpeerinfo", "params": [] }' -H 'content-type: text/plain;' http://127.0.0.1:7227/

```
