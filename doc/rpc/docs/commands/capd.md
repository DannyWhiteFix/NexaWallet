```
capd

CAPD RPC calls, including info, send, get, list, remove and clear.
capd clear: removes all messages from the pool.
capd remove <message hash>: removes a particular message from the pool.
capd get <message hash>: returns a particular message.
capd info: returns information about the message pool.
capd list: returns the hash of every message in the pool.
capd send <message data>: sends hex (preferred) or ascii encoded message.
    To force ascii encoding use a non-hex character.

Result: 
capd info
{                           (json object)
  "size" : Integer current message pool size in bytes
  "count" : Integer current number of messages in pool
  "minPriority" : The minimum priority to enter the pool
  "maxPriority" : The highest priority in the pool
  "relayPriority" : The minimum priority message that will be relayed
}

capd get
{                           (json object)
  "hash" : Message identifier
  "created" : Message creation time in seconds since epoch
  "expiration" : Message expiration time in seconds since epoch
  "difficultyBits" : Message difficulty in 'nBits' format
  "difficulty" : Message difficulty as a 256 bit number
  "priority" : 
  "initialPriority" : 
  "nonce" : Hex string to solve the POW
  "size" : Integer message size in ram bytes
  "data" : Hex string of message payload
}

capd list
[ "message id as hex string", ... ] (json list)

Examples:
> nexa-cli capd info
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "capd", "params": [info] }' -H 'content-type: text/plain;' http://127.0.0.1:7227/

```
