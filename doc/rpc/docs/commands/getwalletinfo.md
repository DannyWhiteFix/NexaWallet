```
getwalletinfo
Returns an object containing various wallet state info.

Result:
{
  "walletversion": xxxxx,     (numeric) the wallet version
  "syncblock": string,         (hex hash) the wallet is synced to this block
  "syncheight": xxxx,         (numeric) the wallet is synced to this height
  "balance": xxxxxxx,         (numeric) the total confirmed balance of the wallet in NEX
  "unconfirmed_balance": xxx, (numeric) the total unconfirmed balance of the wallet in NEX
  "immature_balance": xxxxxx, (numeric) the total immature balance of the wallet in NEX
  "watchonly_balance": xxxxxxx,         (numeric) the total watchonly confirmed balance of the wallet in NEX
  "unconfirmed_watchonly_balance": xxx, (numeric) the total watchonly unconfirmed balance of the wallet in NEX
  "immature_watchonly_balance": xxxxxx, (numeric) the total watchonly immature balance of the wallet in NEX
  "txcount": xxxxxxx,         (numeric) the total number of transactions in the wallet
  "unspentcount": xxxxxxx,    (numeric) the total number of unspent coins in wallet
  "keypoololdest": xxxxxx,    (numeric) the timestamp (seconds since GMT epoch) of the oldest pre-generated key in the key pool
  "keypoolsize": xxxx,        (numeric) how many new keys are pre-generated
  "unlocked_until": ttt,      (numeric) the timestamp in seconds since epoch (midnight Jan 1 1970 GMT) that the wallet is unlocked for transfers, or 0 if the wallet is locked
  "paytxfee": xxxx,           (numeric) the transaction fee configuration, set in sat/KB
  "hdmasterkeyid": "<hash160>", (hex string) the Hash160 of the hd master pubkey
}

Examples:
> nexa-cli getwalletinfo 
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "getwalletinfo", "params": [] }' -H 'content-type: text/plain;' http://127.0.0.1:7227/

```
