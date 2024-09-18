```
getminingcandidate
Returns Mining-Candidate protocol data.

Arguments:
1. "coinbasesize" (int, optional) Get a fixed size coinbase transaction.
                                  Default: null (null indicates unspecified / use daemon defaults)
2. "address"      (string, optional) The address to send the newly generated coins to.
                                     Default: an address in daemon's wallet.
3. "name"      (string, optional) The identity of the mining node (for statistics).
                                     Default: all unnamed nodes are counted as 1 node
> nexa-cli getminingcandidate 
> nexa-cli getminingcandidate 1000
> nexa-cli getminingcandidate 1000 nexa:qq9rw090p2eu9drv6ptztwx4ghpftwfa0gyqvlvx2q
> nexa-cli getminingcandidate null nexa:qq9rw090p2eu9drv6ptztwx4ghpftwfa0gyqvlvx2q
> nexa-cli getminingcandidate null null miner1

```
