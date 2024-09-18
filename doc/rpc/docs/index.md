## Nexa Remote Procedure Call (RPC) commands documentation

### Blockchain

- [dumputxoset](commands/dumputxoset.md) "filename"
- [evicttransaction](commands/evicttransaction.md) "txid"
- [getbestblockhash](commands/getbestblockhash.md)
- [getblock](commands/getblock.md) hash_or_height ( verbosity ) ( tx_count )
- [getblockchaininfo](commands/getblockchaininfo.md)
- [getblockcount](commands/getblockcount.md)
- [getblockhash](commands/getblockhash.md) index
- [getblockheader](commands/getblockheader.md) hash_or_height ( verbose )
- [getblockstats](commands/getblockstats.md) hash_or_height ( stats )
- [getchaintips](commands/getchaintips.md)
- [getchaintxstats](commands/getchaintxstats.md) ( nblocks blockhash )
- [getdifficulty](commands/getdifficulty.md)
- [getorphanpoolinfo](commands/getorphanpoolinfo.md)
- [getraworphanpool](commands/getraworphanpool.md)
- [getrawtxpool](commands/getrawtxpool.md) ( verbose ) (id or idem)
- [getrawtxpool](commands/getrawtxpool.md) ( verbose ) ( id or idem)
- [gettxout](commands/gettxout.md) "txidem" n ( includetxpool )
- [gettxoutproof](commands/gettxoutproof.md) ["txid",...](commands/ blockhash )
- [gettxoutproofs](commands/gettxoutproofs.md) ["txid",...](commands/ blockhash )
- [gettxoutsetinfo](commands/gettxoutsetinfo.md)
- [gettxpoolancestors](commands/gettxpoolancestors.md) txid (verbose)
- [gettxpooldescendants](commands/gettxpooldescendants.md) txid (verbose)
- [gettxpoolentry](commands/gettxpoolentry.md) txid
- [gettxpoolinfo](commands/gettxpoolinfo.md)
- [saveorphanpool](commands/saveorphanpool.md)
- [savetxpool](commands/savetxpool.md)
- [scantokens](commands/scantokens.md) <action> ( <scanobjects> )
- [verifychain](commands/verifychain.md) ( checklevel numblocks )
- [verifytxoutproof](commands/verifytxoutproof.md) "proof"

### Control

- [getinfo](commands/getinfo.md)
- [help](commands/help.md) ( "command" )
- [stop](commands/stop.md)
- [uptime](commands/uptime.md)

### Electrum

- [getelectruminfo](commands/getelectruminfo.md)

### Generating

- [generate](commands/generate.md) numblocks ( maxtries )
- [generatetoaddress](commands/generatetoaddress.md) numblocks address ( maxtries )

### Mining

- [genesis](commands/genesis.md)
- [getblocktemplate](commands/getblocktemplate.md) ( "jsonrequestobject" )
- [getblockversion](commands/getblockversion.md)
- [getminercomment](commands/getminercomment.md)
- [getminingcandidate](commands/getminingcandidate.md)
- [getmininginfo](commands/getmininginfo.md)
- [getminingmaxblock](commands/getminingmaxblock.md)
- [getnetworkhashps](commands/getnetworkhashps.md) ( blocks height )
- [prioritisetransaction](commands/prioritisetransaction.md) <tx id or idem> <priority delta> <fee delta>
- [setblockversion](commands/setblockversion.md) blockVersionNumber
- [setminercomment](commands/setminercomment.md)
- [setminingmaxblock](commands/setminingmaxblock.md) blocksize
- [submitblock](commands/submitblock.md) "hexdata" ( "jsonparametersobject" )
- [submitminingsolution](commands/submitminingsolution.md) "Mining-Candidate data" ( "jsonparametersobject" )
- [validateblocktemplate](commands/validateblocktemplate.md) "hexdata"

### Network

- [addnode](commands/addnode.md) "node" "add|remove|onetry"
- [capd](commands/capd.md)
- [clearbanned](commands/clearbanned.md)
- [clearblockstats](commands/clearblockstats.md)
- [disconnectnode](commands/disconnectnode.md) "node"
- [expedited](commands/expedited.md) block|tx "node IP addr" on|off
- [getaddednodeinfo](commands/getaddednodeinfo.md) dns ( "node" )
- [getconnectioncount](commands/getconnectioncount.md)
- [getnettotals](commands/getnettotals.md)
- [getnetworkinfo](commands/getnetworkinfo.md)
- [getpeerinfo](commands/getpeerinfo.md) [peer IP address]
- [gettrafficshaping](commands/gettrafficshaping.md)
- [listbanned](commands/listbanned.md)
- [ping](commands/ping.md)
- [pushtx](commands/pushtx.md) "node"
- [savemsgpool](commands/savemsgpool.md)
- [setban](commands/setban.md) "ip(/netmask)" "add|remove" (bantime) (absolute)
- [settrafficshaping](commands/settrafficshaping.md) "send|receive" "burstKB" "averageKB"

### Rawtransactions

- [createrawtransaction](commands/createrawtransaction.md) [{"outpoint":"id","amount":n},...] {"address":amount,"data":"hex",...} ( locktime )
- [decoderawtransaction](commands/decoderawtransaction.md) "hexstring"
- [decodescript](commands/decodescript.md) "hex"
- [enqueuerawtransaction](commands/enqueuerawtransaction.md) "hexstring" ( options )
- [fundrawtransaction](commands/fundrawtransaction.md) "hexstring" includeWatching
- [getrawblocktransactions](commands/getrawblocktransactions.md)
- [getrawtransaction](commands/getrawtransaction.md) "tx id, idem or outpoint" ( verbose "blockhash" )
- [getrawtransactionssince](commands/getrawtransactionssince.md)
- [sendrawtransaction](commands/sendrawtransaction.md) "hexstring" ( allowhighfees, allownonstandard, verbose )
- [signrawtransaction](commands/signrawtransaction.md) "hexstring" ( [{"outpoint":"hash","amount":n,"scriptPubKey":"hex","redeemScript":"hex"},...] ["privatekey1",...] sighashtype sigtype )
- [validaterawtransaction](commands/validaterawtransaction.md) "hexstring" ( allowhighfees, allownonstandard )

### Token

- [dumptokenset](commands/dumptokenset.md)

### Util

- [createmultisig](commands/createmultisig.md) nrequired ["key",...]
- [estimatefee](commands/estimatefee.md) nblocks
- [estimatesmartfee](commands/estimatesmartfee.md) nblocks
- [get](commands/get.md)
- [getaddressforms](commands/getaddressforms.md) "address"
- [getstat](commands/getstat.md)
- [getstatlist](commands/getstatlist.md)
- [issuealert](commands/issuealert.md) "alert"
- [log](commands/log.md) "category|all" "on|off"
- [logline](commands/logline.md) 'string'
- [set](commands/set.md)
- [validateaddress](commands/validateaddress.md) "address"
- [validatechainhistory](commands/validatechainhistory.md) [hash]
- [verifymessage](commands/verifymessage.md) "address" "signature" "message"

### Wallet

- [abandontransaction](commands/abandontransaction.md) "txid" or "txidem"
- [addmultisigaddress](commands/addmultisigaddress.md) nrequired ["key",...] ( "account" )
- [backupwallet](commands/backupwallet.md) "destination"
- [consolidate](commands/consolidate.md) ("num" "toleave")
- [dumpprivkey](commands/dumpprivkey.md) "nexaaddress"
- [dumpwallet](commands/dumpwallet.md) "filename"
- [encryptwallet](commands/encryptwallet.md) "passphrase"
- [getaccount](commands/getaccount.md) "address"
- [getaccountaddress](commands/getaccountaddress.md) "account"
- [getaddressesbyaccount](commands/getaddressesbyaccount.md) "account"
- [getbalance](commands/getbalance.md) ( "account" minconf includeWatchonly )
- [getnewaddress](commands/getnewaddress.md) ("type" "account" )
- [getrawchangeaddress](commands/getrawchangeaddress.md)
- [getreceivedbyaccount](commands/getreceivedbyaccount.md) "account" ( minconf )
- [getreceivedbyaddress](commands/getreceivedbyaddress.md) "address" ( minconf )
- [gettransaction](commands/gettransaction.md) "txid or txidem" ( includeWatchonly )
- [getunconfirmedbalance](commands/getunconfirmedbalance.md)
- [getwalletinfo](commands/getwalletinfo.md)
- [importaddress](commands/importaddress.md) "address" ( "label" rescan p2sh )
- [importaddresses](commands/importaddresses.md) [rescan | no-rescan] "address"...
- [importprivatekeys](commands/importprivatekeys.md) [rescan | no-rescan] "nexaprivatekey"...
- [importprivkey](commands/importprivkey.md) "nexaprivkey" ( "label" rescan )
- [importprunedfunds](commands/importprunedfunds.md)
- [importpubkey](commands/importpubkey.md) "pubkey" ( "label" rescan )
- [importwallet](commands/importwallet.md) "filename"
- [keypoolrefill](commands/keypoolrefill.md) ( newsize )
- [listaccounts](commands/listaccounts.md) ( minconf includeWatchonly)
- [listactiveaddresses](commands/listactiveaddresses.md)
- [listaddressgroupings](commands/listaddressgroupings.md)
- [listlockunspent](commands/listlockunspent.md)
- [listreceivedbyaccount](commands/listreceivedbyaccount.md) ( minconf includeempty includeWatchonly)
- [listreceivedbyaddress](commands/listreceivedbyaddress.md) ( minconf includeempty includeWatchonly)
- [listsinceblock](commands/listsinceblock.md) ( "blockhash" target-confirmations includeWatchonly)
- [listtransactions](commands/listtransactions.md) ( "account" count from includeWatchonly)
- [listtransactionsfrom](commands/listtransactionsfrom.md) ( "account" count from includeWatchonly)
- [listunspent](commands/listunspent.md) ( minconf maxconf  ["address",...] )
- [lockunspent](commands/lockunspent.md) unlock [{"txidem":"txidem","vout":n},...]
- [move](commands/move.md) "fromaccount" "toaccount" amount ( minconf "comment" )
- [removeprunedfunds](commands/removeprunedfunds.md) "txidem"
- [sendfrom](commands/sendfrom.md) "fromaccount" "toaddress" amount ( minconf "comment" "comment-to" )
- [sendmany](commands/sendmany.md) "fromaccount" {"address":amount,...} ( minconf "comment" ["address",...] )
- [sendtoaddress](commands/sendtoaddress.md) "address" amount ( "comment" "comment-to" subtractfeefromamount )
- [setaccount](commands/setaccount.md) "address" "account"
- [signdata](commands/signdata.md) "address" "msgFormat" "message"
- [signmessage](commands/signmessage.md) "address" "message"
- [token](commands/token.md) [info, new, mint, melt, balance, send, authority, tracker, subgroup, mintage]

### Zmq

- [getzmqnotifications](commands/getzmqnotifications.md)
