[Website](https://www.nexa.org)  | [Download](https://gitlab.com/nexa/nexa/-/releases) | [Setup](../README.md)   |   [Miner](miner.md)  |  [Rostrum](electrum-integration.md)  |  [UnconfirmedChains](unconfirmedTxChainLimits.md)

# Using Nexa for Mining

Nexa has an ASIC resistant mining algorithm and has specific features to facilitate CPU mining.

## ***getminingcandidate*** and ***submitminingsolution***

*efficient protocol to access block candidates and submit block solutions*

Nexa provides 2 mining RPC functions that can be used instead of the traditional "getblocktemplate" and "submitblock".  These RPCs do not pass the entire block to mining pools.  Instead, the candidate block header, proposed coinbase transaction, and coinbase merkle proof are passed.  This is the approximately the same data that is passed to hashing hardware via the Stratum protocol, so if you are familiar with Stratum, you are familiar with how this is possible.

A mining pool uses ***getminingcandidate*** to receive the previously described block information and a tracking identifier.  It then may modify or completely replace the coinbase transaction and many block header fields, to create different candidates for hashing hardware.  It then forwards these candidates to the hashing hardware via Stratum.  When a solution is found, the mining pool can submit the solution back to nexad via ***submitminingsolution***.

A few of the benefits when using RPC getminingcandidate and RPC submitminingsolution are:
* Massively reduced bandwidth and latency, especially for large blocks.  This RPC requires log2(blocksize) data. 
* Faster JSON parsing and creation
* Concise JSON

### nexa-miner

An example CPU-miner program is provided that shows a proof-of-concept use of these functions.
The source code is located in src/nexa-miner.cpp. 

A typical way to launch nexa-miner on the main chain is the following. (If no -cpu value is given the default is *1*)

```sh
./nexa-miner -rpcuser=<your-nodes-login> -rpcpassword=<your-nodes-password> -cpus=4
```

Rather than supplying the rpc username/password you can supply the path to the config file where the username/password is defined and which your nexa node will also use.

```sh
./nexa-miner -config=nexa.conf -cpus=4
```

If running on tesnet then add *-testnet*

```sh
./nexa-miner -rpcuser=<your-nodes-login> -rpcpassword=<your-nodes-password> -cpus=4 -testnet
```

 To get a full list of additional options run
```sh
./nexa-miner --help
```

#### Setting the mining candidate interval

By default your node will generate a new mining candidate every 30 seconds.  Also, by default, the nexa-miner will update the mining candidate it is mining with every 30 seconds.If a new block is received by your node the nexa-miner will almost immediately get the new mining candidate and begin mining with it.

If you want then nexa-miner to update the block mining candidate more frequently than the default of 30 seconds then you can modify *-duration*, but you should only do this if you also make your node update its mining candidate interval by setting *-mining.minCandidateInterval* to match the new *-duration* you have set in your nexa-miner. So you could launch the nexa-miner and nexad with the following settings.

```sh
./nexa-miner -rpcuser=<your-nodes-login> -rpcpassword=<your-nodes-password> -cpus=4 -testnet -duration=15

./nexad -mining.minCandidateInterval=15
```


### miningtest.py

A python based test of these interfaces is located at qa/rpc-tests/miningtest.py.  This example may be of more use for people accessing these RPCs in higher level languages.

### Function documentation:

#### RPC getminingcandidate

##### Arguments: -none
##### Returns:
```
{
  # candidate identifier for submitminingsolution (integer):
  "id": 14,
  
  # Hash of the previous block (hex string):
  "prevhash": "0000316517e048ab283a41df3c0ba125345a5c56ef3f76db901b0ede65e2f0e5",
  
  # Coinbase transaction (hex string encoded binary transaction)
  "coinbase": "...00ffffffff10028122000b2f454233322f414431322ffff..."

  # Block version (integer):
  "version": 536870912,
  
  # Difficulty (hex string):
  "nBits": "207fffff",
  
  # Block time (integer):
  "time": 1528925409,
  
  # Merkle branch for the block, proving that this coinbase is part of the block (list of hex strings):
  "merkleProof": [
   "ff12771afd8b7c5f11b499897c27454a869a01c2863567e0fc92308f01fd2552",
   "d7fa501d5bc94d9ae9fdab9984fd955c08fedbfe02637ac2384844eb52688f45"
  ]
 }
```


#### RPC submitminingsolution

##### Arguments:
```
{
  # ID from getminingcandidate RPC (integer):
  "id": 14,

  # Miner generated nonce (integer):
  "nonce": 1804358173,

  # Modified Coinbase transaction (hex string encoded binary transaction, optional): 
  "coinbase": "...00ffffffff10028122000b2fc7237b322f414431322ffff...",
  
  # Block time (integer, optional):
  "time": 1528925410,
  
  # Block version (integer, optional):
  "version": 536870912
}
```

##### Returns:

Exactly the same as ***submitblock***.  None means successful, error string or JSONRPCException if there is a problem.


## BIP135-based feature voting

BIP135 is an enhancement of BIP9, allowing miners to vote for features by setting certain bits in the version field of solved blocks.
The definition of the meaning of the bits in the version field changes and is found in config/forks.csv.  You may define your own bits, however
such a definition is not valuable unless the vast majority of miners agree to honor those bit definitions.
Detailed information is available in doc/bip135-genvoting.md.

Miners may enable voting for certain features via the "mining.vote" configuration parameter.  Provide a comma separate list of feature names.
For example, if forks.csv defines three features "f0", "f1" and "f2", you might vote for "f1" and "f2" via the following configuration setting:

```
mining.vote=f0,f1
```

This parameter can be accessed or changed at any time via the "get" and "set" RPC calls.


## Setting your subversion string (spoofing the user agent)

To hide that this is a Nexa node, set the "net.subversionOverride" to a string of your choice, in the nexa.conf file or using ./nexa-cli:

```sh
 nexa-cli set net.subversionOverride="Your Choice Here"
```

To show the current string:

```sh
nexa-cli get net.subversionOverride
```

To change this field in nexa.conf or on the command line, use:
 > net.subversionOverride=<YourChoiceHere>


## Setting your maximum mined block

By default Nexa uses an adaptive block size algorithm. (see adaptive-blocksize.md)

You may want to lower the largest blocksize you're willing to create by the following settings.

```sh
nexa-cli setminingmaxblock blocksize
```
For example, to set 2MB blocks, use:
```sh
nexa-cli setminingmaxblock 2000000
```
To change this field in nexa.conf or on the command line, use:
 > `blockmaxsize=<NNN>`
 
for example, to set 3MB blocks use:
 > blockmaxsize=3000000

You can discover the maximum block size by running:
```sh
nexa-cli getminingmaxblock
```
 - WARNING: Setting this max block size parameter means that Nexa may mine blocks of that size on the NEXT block.
 

## Setting your block version

Miners can set the block version flag via CLI/RPC or config file:

From the CLI/RPC, 
```sh
nexa-cli setblockversion (version number or string)
```
For example:

The following all choose to vote for 2MB blocks:
```sh
nexa-cli setblockversion 0x30000000
nexa-cli setblockversion 805306368
nexa-cli setblockversion BIP109
```

The following does not vote for 2MB blocks:
```sh
nexa-cli setblockversion 0x20000000
nexa-cli setblockversion 536870912
nexa-cli setblockversion BASE
```

You can discover the current block version using:
```sh
nexa-cli getblockversion
```
From nexa.conf:
 > blockversion=805306368

Note you must specify the version in decimal format in the nexa.conf file.
Here is an easy conversion in Linux: python -c "print '%d' % 0x30000000"

 - WARNING: If you use nonsense numbers when calling setblockversion, you'll end up generating blocks with nonsense versions!

## Setting your block retry intervals

Nexa tracks multiple sources for data an can rapidly request blocks or transactions from other sources if one source does not deliver the requested data.
To change the retry rate, set it in microseconds in your nexa.conf:

Transaction retry interval:
 > txretryinterval=2000000
 
 Block retry interval:
 > blkretryinterval=2000000

## Setting your transaction pool size

A larger transaction tx pool allows your node to receive expedited blocks successfully (it increases the chance that you will have a transaction referenced in the expedited block) and to pick from a larger set of available transactions.  To change the tx pool size, configure it in nexa.conf:

 > `cache.maxTxPool=<megabytes>`

So a 4GB mempool would be configured like:
 > cache.maxTxPool=4096

## Setting your Coinbase string

To change the string that appears in the coinbase message of a mined block, run:

```sh
nexa-cli setminercomment "your mining comment"
```

To show the current string:

```sh
nexa-cli getminercomment
```

 - WARNING: some mining software and pools also add to the coinbase string and do not validate the total string length (it must be < 100 bytes).  This can cause the mining pool to generate invalid blocks.  Please ensure that your mining pool software validates total string length, or keep the string you add to Nexa short.


## Filling a new node's transaction pool

When you restart nexad, the tx pool starts empty.  If a block is found quickly, this could result in a block with few transactions.  It is possible to "prime" a new instance of nexad with the tx pool of a different node.  To do so, go to the CLI on the node that has a full txpool, connect to your new node, and push the transactions to it.

```sh
nexa-cli addnode <new node's IP:port> onetry
nexa-cli pushtx <new node's IP:port>
```

## Validating unsolved blocks

Nexa can be used to validate block templates received from other Nexa releases or other nexa clients.  This ensures that Nexa will accept the block once it is mined, allowing miners to deploy multiple clients in their mining networks.  Note that this API will return an error if the block is not built off of the chain tip seen by this client.  So it is important that the client be fully synchronized with the client that creates the block template.  You can do this by explicitly connecting them via "addnode".

The block validation RPC uses the same call syntax as the "submitblock" RPC, and returns a JSONRPCException if the block validation fails.  See "qa/rpc-tests/validateblocktemplate.py" for detailed python examples.

```sh
nexa-cli validateblocktemplate <hex encoded block>
```

