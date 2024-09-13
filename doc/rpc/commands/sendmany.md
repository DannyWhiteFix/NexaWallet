```
sendmany "fromaccount" {"address":amount,...} ( minconf "comment" ["address",...] )

Send multiple times. Amounts are double-precision floating point numbers.

Arguments:
1. "fromaccount"         (string, required) DEPRECATED. The account to send the funds from. Should be "" for the default account
2. "amounts"             (string, required) A json object with addresses and amounts
    {
      "address":amount   (numeric or string) The address is the key, the numeric amount (can be string) in NEX is the value
      ,...
    }
3. minconf                 (numeric, optional, default=1) Only use the balance confirmed at least this many times.
4. "comment"             (string, optional) A comment
5. subtractfeefromamount   (string, optional) A json array with addresses.
                           The fee will be equally deducted from the amount of each selected address.
                           Those recipients will receive less coins than you enter in their corresponding amount field.
                           If no addresses are specified here, the sender pays the fee.
    [
      "address"            (string) Subtract fee from this address
      ,...
    ]

Result:
"transactionid"          (string) The transaction id for the send. Only 1 transaction is created regardless of 
                                    the number of addresses.

Examples:

Send two amounts to two different addresses:
> nexa-cli sendmany "" "{\"nexa:qpnfq7r98lkm2h7jksy0h5mqpwvttxlc3q6zkwmcha\":10.01,\"nexa:qqqdf524crwrn659hattd40jn5ykz32xey7z6n5z28\":10.02}"

Send two amounts to two different addresses setting the confirmation and comment:
> nexa-cli sendmany "" "{\"nexa:qpnfq7r98lkm2h7jksy0h5mqpwvttxlc3q6zkwmcha\":10.01,\"nexa:qqqdf524crwrn659hattd40jn5ykz32xey7z6n5z28\":10.02}" 6 "testing"

Send two amounts to two different addresses, subtract fee from amount:
> nexa-cli sendmany "" "{\"nexa:qpnfq7r98lkm2h7jksy0h5mqpwvttxlc3q6zkwmcha\":10.01,\"nexa:qqqdf524crwrn659hattd40jn5ykz32xey7z6n5z28\":10.02}" 1 "" "[\"nexa:qpnfq7r98lkm2h7jksy0h5mqpwvttxlc3q6zkwmcha\",\"nexa:qqqdf524crwrn659hattd40jn5ykz32xey7z6n5z28\"]"

As a json rpc call
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "sendmany", "params": ["", "{\"nexa:qpnfq7r98lkm2h7jksy0h5mqpwvttxlc3q6zkwmcha\":10.01,\"nexa:qqqdf524crwrn659hattd40jn5ykz32xey7z6n5z28\":10.02}", 6, "testing"] }' -H 'content-type: text/plain;' http://127.0.0.1:7227/

```
