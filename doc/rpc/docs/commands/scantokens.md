```
scantokens <action> ( <scanobjects> )

Scans the unspent transaction output set for possible entries that belong to a specified token group.

Arguments:
1. "action"                     (string, required) The action to execute
                                      "start" for starting a scan
                                      "abort" for aborting the current scan (returns true when abort was successful)
                                      "status" for progress report (in %) of the current scan
2. "tokenGroupID"               (string, optional) Token group identifier


Result:
{
  "unspents": [
    {
    "txid" : "transactionid",   (string) The transaction id
    "vout" : n,                 (numeric) the vout value
    "address" : "address",      (string) the address that received the tokens
    "scriptPubKey" : "script",  (string) the script key
    "tokenAmount" : xxx,       (numeric) The total token amount of the unspent output
    "height" : n,               (numeric) Height of the unspent transaction output
   }
   ,...], 
 "totalAmount" : xxx,          (numeric) The total token amount of all found unspent outputs
]

```
