# Unauthenticated REST Interface

The REST API can be enabled with the `-rest` option on the command line, or `rest=1` in the nexa.conf configuration file.  REST access occurs via the same port as JSON-RPC requests.  For example, to access the chain information on Nexa mainnet, use:
`curl http://localhost:7227/rest/chaininfo.json`

Note that the REST API uses the same access rules as RPC.  To enable external access to these interfaces, you must use the `rpcallowip` option.  For example, add `rpcallowip=192.168.0.0/16` to nexa.conf to allow the REST API to be accessed from 192.168.* private networks.

## Supported API

#### Transactions
`GET /rest/tx/<TX-HASH>.<bin|hex|json>`

Given a transaction hash: returns a transaction in binary, hex-encoded binary, or JSON formats.

For full TX query capability, one must enable the transaction index via "txindex=1" command line / configuration option. TX-HASH could be either `txid` or `txidem`.

#### Blocks
`GET /rest/block/<BLOCK-HASH>.<bin|hex|json>`
`GET /rest/block/notxdetails/<BLOCK-HASH>.<bin|hex|json>`

Given a block hash: returns a block, in binary, hex-encoded binary or JSON formats.

The HTTP request and response are both handled entirely in-memory, thus making maximum memory usage at least 2.66 times max block size (need to take into account hex encoding) per request.

With the /notxdetails/ option JSON response will only contain the transaction hash instead of the complete transaction details. The option only affects the JSON response.

#### Blockheaders
`GET /rest/headers/<COUNT>/<BLOCK-HASH>.<bin|hex|json>`

Given a block hash: returns <COUNT> amount of blockheaders in upward direction.

#### Chaininfos
`GET /rest/chaininfo.json`

Returns various state info regarding block chain processing.
Only supports JSON as output format.
* chain : (string) current network name as defined in BIP70 (nexa, test, regtest)
* blocks : (numeric) the current number of blocks processed in the server
* headers : (numeric) the current number of headers we have validated
* bestblockhash : (string) the hash of the currently best block
* difficulty : (numeric) the current difficulty
* verificationprogress : (numeric) estimate of verification progress [0..1]
* chainwork : (string) total amount of work in active chain, in hexadecimal
* coinsupply: (numeric) total amount of satoshis minted so far in the active chain
* pruned : (boolean) if the blocks are subject to pruning
* softforks : (array) status of softforks in progress
* bip9_softforks": (object) status of BIP9 softforks in progress
* bip135_forks": (object) status of BIP135 forks in progress

#### Query UTXO set
`GET /rest/getutxos/<checktxpool>/<txidem>-<n>/<txidem>-<n>/.../<txidem>-<n>.<bin|hex|json>`

The getutxo command allows querying of the UTXO set given a set of outpoints. This works only by using `txidem`, same as the `gettxout` RPC command.

See BIP64 for input and output serialisation:
https://github.com/bitcoin/bips/blob/master/bip-0064.mediawiki

Example:
```
$> curl localhost:7227/rest/getutxos/checktxpool/c786590b62b926129c4c09d61e25e489f7d0454cafbc5a1eccca4a44968c0ca1-0.json 2>/dev/null | json_pp
{
  "chainHeight": 258220,
  "chaintipHash": "160fd6194d88908d61e3ccf63d51c9514313a51545db485b430a867298e8c4ce",
  "bitmap": "1",
  "utxos": [
    {
      "height": 2147483647,
      "value": 2689.03,
      "scriptPubKey": {
        "asm": "0 1 3850434eed2037e3313ec48199adab5fea4fc984",
        "hex": "0051143850434eed2037e3313ec48199adab5fea4fc984",
        "type": "scripttemplate",
        "scriptHash": "pay2pubkeytemplate",
        "argsHash": "3850434EED2037E3313EC48199ADAB5FEA4FC984",
        "addresses": [
          "nexa:nqtsq5g58pgyxnhdyqm7xvf7cjqentdttl4yljvyg3y6kzld"
        ]
      }
    }
  ]
}
```

#### Transactions pool
`GET /rest/txpool/info.json`

Returns various information about the TX mempool.
Only supports JSON as output format.
* size : (numeric) the number of transactions in the TX mempool
* bytes : (numeric) size of the TX mempool in bytes
* usage : (numeric) total TX mempool memory usage
* maxtxpool": (numeric) Maximum memory usage for the transaction pool
* txpoolminfee": (numeric) Minimum fee for tx to be accepted
* tps": (numeric) Transactions per second accepted
* peak_tps": (numeric) Peak Transactions per second accepted

`GET /rest/txpool/contents.json`

Returns transactions in the TX mempool.
Only supports JSON as output format.

## Risks

Running a web browser on the same node with a REST enabled bitcoind can be a risk. Accessing prepared XSS websites could read out tx/block data of your node by placing links like `<script src="http://127.0.0.1:7227/rest/tx/1234567890.json">` which might break the nodes privacy.
