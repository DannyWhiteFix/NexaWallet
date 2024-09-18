```
gettransaction "txid or txidem" ( includeWatchonly )

Get detailed information about in-wallet transaction <txid/txidem>

Arguments:
1. "txid or txidem"    (string, required) The transaction id or transaction idem
2. "includeWatchonly"    (bool, optional, default=false) Whether to include watchonly addresses in balance calculation and details[]

Result:
{
  "amount" : x.xxx,        (numeric) The transaction amount in NEX
  "confirmations" : n,     (numeric) The number of confirmations
  "blockhash" : "hash",    (string) The block hash
  "blockindex" : xx,       (numeric) The index of the transaction in the block that includes it
  "blocktime" : ttt,       (numeric) The time in seconds since epoch (1 Jan 1970 GMT)
  "txid" : "transaction id",   (string) The transaction id.
  "txidem" : "transaction idem",   (string) The transaction idem.
  "time" : ttt,            (numeric) The transaction time in seconds since epoch (1 Jan 1970 GMT)
  "timereceived" : ttt,    (numeric) The time received in seconds since epoch (1 Jan 1970 GMT)
  "bip125-replaceable": "yes|no|unknown"  (string) Whether this transaction could be replaced due to BIP125 (replace-by-fee);
                                                   may be unknown for unconfirmed transactions not in the txpool
  "details" : [
    {
      "account" : "accountname",  (string) DEPRECATED. The account name involved in the transaction, can be "" for the default account.
      "address" : "address",   (string) The address involved in the transaction
      "category" : "send|receive",    (string) The category, either 'send' or 'receive'
      "group": "groupidentifier",     (string) The token identifier (appears only if applicable)
      "groupAmount": n,               (numeric) The token quantity (appears only if applicable)
      "amount" : x.xxx,               (numeric) The amount in NEX
      "label" : "label",              (string) A comment for the address/transaction, if any
      "vout" : n,                     (numeric) the vout value
    }
    ,...
  ],
  "hex" : "data"         (string) Raw data for transaction
}

Examples:
> nexa-cli gettransaction "1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d"
> nexa-cli gettransaction "1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d" true
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "gettransaction", "params": ["1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d"] }' -H 'content-type: text/plain;' http://127.0.0.1:7227/

```
