```
getblockchaininfo
Returns an object containing various state info regarding block chain processing.

Result:
{
  "chain": "xxxx",        (string) current network name as defined in BIP70 (main, test, regtest)
  "blocks": xxxxxx,         (numeric) the current number of blocks processed in the server
  "headers": xxxxxx,        (numeric) the current number of headers we have validated
  "bestblockhash": "...", (string) the hash of the currently best block
  "difficulty": xxxxxx,     (numeric) the current difficulty
  "mediantime": xxxxxx,     (numeric) median time for the current best block
  "forktime": xxxxxx,       (numeric)  time when the fork becomes active on the next block
  "forkactive": xxxxxx,     (bool) is the fork active, true for all blocks following the new rules
   "forkenforcednextblock": xx,(bool) will the new fork rules be enforced on the next block mined, true only for the first block following the new rules
  "verificationprogress": xx, (numeric) estimate of verification progress [0..1]
  "initialblockdownload": xx, (bool) (debug information) estimate of whether this node is in Initial Block Download mode.
  "chainwork": "xxxx"     (string) total amount of work in active chain, in hexadecimal
  "coinsupply": xxxxxxx     (numeric) total amount of satoshis minted so far in the active chain
  "size_on_disk": xxxxxx,   (numeric) the estimated size of the block and undo files on disk
  "pruned": xx,             (boolean) if the blocks are subject to pruning
  "pruneheight": xxxxxx,    (numeric) lowest-height complete block stored (only present if pruning is enabled)
  "prune_target_size": xxxxxx,  (numeric) the target size used by pruning (only present if automatic pruning is enabled)
  "softforks": [            (array) status of softforks in progress
     {
        "id": "xxxx",        (string) name of softfork
        "version": xx,         (numeric) block version
        "reject": {            (object) progress toward rejecting pre-softfork blocks
           "status": xx,       (boolean) true if threshold reached
        },
     }, ...
  ],
  "bip9_softforks": {          (object) status of BIP9 softforks in progress
     "xxxx" : {                (string) name of the softfork
        "status": "xxxx",    (string) one of "defined", "started", "lockedin", "active", "failed"
        "bit": xx,             (numeric) the bit, 0-28, in the block version field used to signal this soft fork
        "startTime": xx,       (numeric) the minimum median time past of a block at which the bit gains its meaning
        "timeout": xx          (numeric) the median time past of a block at which the deployment is considered failed if not yet locked in
     }
  }
  "bip135_forks": {            (object) status of BIP135 forks in progress
     "xxxx" : {                (string) name of the fork
        "status": "xxxx",      (string) one of "defined", "started", "locked_in", "active", "failed"
        "bit": xx,             (numeric) the bit (0-28) in the block version field used to signal this fork (only for "started" status)
        "startTime": xx,       (numeric) the minimum median time past of a block at which the bit gains its meaning
        "windowsize": xx,      (numeric) the number of blocks over which the fork status is tallied
        "threshold": xx,       (numeric) the number of blocks in a window that must signal for fork to lock in
        "minlockedblocks": xx, (numeric) the minimum number of blocks to elapse after lock-in and before activation
        "minlockedtime": xx,   (numeric) the minimum number of seconds to elapse after median time past of lock-in until activation
     }
  }
}

Examples:
> nexa-cli getblockchaininfo 
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "getblockchaininfo", "params": [] }' -H 'content-type: text/plain;' http://127.0.0.1:7227/

```
