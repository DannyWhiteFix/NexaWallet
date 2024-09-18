```
getnetworkinfo
Returns an object containing various state info regarding P2P networking.

Result:
{
  "version": xxxxx,                    (numeric) the server version
  "subversion": "/Nexa:x.x.x/",      (string) the server subversion string
  "protocolversion": xxxxx,            (numeric) the protocol version
  "localservices": "xxxxxxxxxxxxxxxx", (string) the services we offer to the network
  "localservicesnames": [                (array) the services we offer to the network, in human-readable form
      "SERVICE_NAME",                    (string) the service name
       ...
   ],
  "timeoffset": xxxxx,                 (numeric) the time offset
  "connections": xxxxx,                (numeric) the number of connections
  "networks": [                        (array) information per network
    {
      "name": "xxx",                   (string) network (ipv4, ipv6 or onion)
      "limited": true|false,           (boolean) is the network limited using -onlynet?
      "reachable": true|false,         (boolean) is the network reachable?
      "proxy": "host:port"             (string) the proxy that is used for this network, or empty if none
      "proxy_randomize_credentials": true|false,  (string) Whether randomized credentials are used
    }
  ,...
  ],
  "relayfee": xxxx,              (numeric) minimum relay fee for non-free transactions in sat/kB
  "limitfreerelay": x.xxxx,            (numeric) The maximum number of free transactions (in KB) that can enter the txpool per minute
  "maxallowednetmsg" xxxx              (numeric) The maximum message size in bytes that will be accepted by our node
  "localaddresses": [                  (array) list of local addresses
    {
      "address": "xxxx",               (string) network address
      "port": xxx,                     (numeric) network port
      "score": xxx                     (numeric) relative score
    }
  ,...
  ]
  "thinblockstats": "..."              (string) thin block related statistics 
  "compactblockstats": "..."           (string) compact block related statistics 
  "grapheneblockstats": "..."          (string) graphene block related statistics 
  "warnings": "..."                    (string) any network warnings (such as alert messages) 
}

Examples:
> nexa-cli getnetworkinfo 
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "getnetworkinfo", "params": [] }' -H 'content-type: text/plain;' http://127.0.0.1:7227/

```
