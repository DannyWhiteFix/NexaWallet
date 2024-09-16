```
settrafficshaping "send|receive" "burstKB" "averageKB"
Sets the network send or receive bandwidth and burst in kilobytes per second.

Arguments:
1. "send|receive"     (string, required) Are you setting the transmit or receive bandwidth
2. "burst"  (integer, required) Specify the maximum burst size in Kbytes/sec (actual max will be 1 packet larger than this number)
2. "average"  (integer, required) Specify the average throughput in Kbytes/sec

Examples:
> nexa-cli settrafficshaping "receive" 10000 1024
> nexa-cli settrafficshaping "receive" disable
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "settrafficshaping", "params": ["receive" 10000 1024] }' -H 'content-type: text/plain;' http://127.0.0.1:7227/

```
