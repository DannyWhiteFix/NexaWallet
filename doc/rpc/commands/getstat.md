```
getstat
Returns the current settings for the network send and receive bandwidth and burst in kilobytes per second.
To get a list of available statistics use "getstatlist".

Arguments: 
1. "-v" or "--verbose" (string, optional) full details
2. "statistic"     (string, required) Specify what statistic you want
3. "series"  (string, optional) Specify what data series you want.  Options are "total", "now","all", "sec10", "min5", "hourly", "daily","monthly".  Default is all.
4. "count"  (string, optional) Specify the number of samples you want.

Result:
  {
    "<statistic name>"
    {
    "<series meta>"
 (Only with --verbose|-v)       [
        "Series": Requested series.
        "SampleSize": Requested sample group size."
      ],
    "<series name>"
      [
      <data>, (any type) The data points in the series
      ],
    "timestamp"
      [
      <time> (time only with --verbose|-v)
      ],
    ...
    },
  ...
  }

Examples:
> nexa-cli getstat 
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "getstat", "params": [] }' -H 'content-type: text/plain;' http://127.0.0.1:7227/


```
