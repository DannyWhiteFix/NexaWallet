```
genesis

create a genesis block  chainName (string) what chain parameters
  minerComment (string) miner comment
  difficulty (int) genesis difficulty in nBits format

Examples:
> nexa-cli genesis 
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "genesis", "params": [] }' -H 'content-type: text/plain;' http://127.0.0.1:7227/

```
