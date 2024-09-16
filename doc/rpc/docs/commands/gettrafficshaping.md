```
gettrafficshaping
Returns the current settings for the network send and receive bandwidth and burst in kilobytes per second.

Arguments: None

Result:
  {
    "sendBurst" : 40,   (string) The maximum send bandwidth in Kbytes/sec
    "sendAve" : 30,   (string) The average send bandwidth in Kbytes/sec
    "recvBurst" : 20,   (string) The maximum receive bandwidth in Kbytes/sec
    "recvAve" : 10,   (string) The average receive bandwidth in Kbytes/sec
  }

 NOTE: if the send and/or recv parameters do not exist, shaping in that direction is disabled.

Examples:
> nexa-cli gettrafficshaping 
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "gettrafficshaping", "params": [] }' -H 'content-type: text/plain;' http://127.0.0.1:7227/

```
