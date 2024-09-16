```
getmininginfo

Returns a json object containing mining-related information.
Result:
{
  "blocks": nnn,              (numeric) The number of blocks in the chain
  "currentblocksize": nnn,    (numeric) The current block template reserved size
  "currentblocktx": nnn,      (numeric) The current block template transaction count
  "currentmaxblocksize": nnn, (numeric) The current maximum block size possible
  "difficulty": xxx.xxxxx     (numeric) The current difficulty
  "errors": "..."           (string) Current errors
  "pooledtx": n               (numeric) The size of the transaction pool
  "chain": "xxxx",          (string) Current network name as defined in BIP70 (main, test, regtest)
  "miners": {                 (object) Miner information
    "name" : {                (object) Name reported by the miner
      "lastrequest" : nnn,    (numeric) Epoch time in seconds of this miner's last request
      }
      ...
  }
}

Examples:
> nexa-cli getmininginfo 
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "getmininginfo", "params": [] }' -H 'content-type: text/plain;' http://127.0.0.1:7227/

```
