```
token [info, new, mint, melt, balance, send, authority, tracker, subgroup, mintage] 

Token functions.
'info' returns a list of all tokens with their groupId and associated token-name, token-ticker descUrl, descHash, decimals, genesis_address, the number of mint/melt/renew/rescript/subgroup authorities, and also the finest balance (in satoshis) and finest mintage numbers (in satoshis) for all tokens created in this wallet, or if a group id is specific, it will return the info just for that group regardless of whether it was created in this wallet
'new' creates a new token type. args: [address] [token-ticker token-name [descUrl descHash decimals]]
'mint' creates new tokens. args: groupId address quantity
'melt' removes tokens from circulation. args: groupId quantity
'balance' reports quantity of this token, in the finest unit (satoshis). args: groupId [address]
'send' sends tokens to a new address. args: groupId address quantity [address quantity...]
'authority create' creates a new authority args: groupId address [mint melt nochild rescript]
'authority count' returns a list of all authorities and their current counts. args: groupId
'authority list'  returns a list of all authorities controlled by this wallet along with each
                  associated outpoint and the current authorities defined. args: [groupId]
'authority destroy'  Destroys all authorties associated with this outpoint. args: outpoint
'subgroup' translates a group and additional data into a subgroup identifier. args: groupId data
'mintage' returns the current mintage of a token. args: groupId
'tracker add' adds a token to the tracking whitelist which allows for that token to be shown in the QT gui and returned by rpc commands. args: groupId, token-ticker(optional)
'tracker remove' removes a token from the tracking whitelist, args: groupId
'tracker list' lists all token trackers, args: none
Note: As this interface is often used for scripting, all balances are accepted and reported as integers
      specified in the token's finest unit (the 'decimals' field in the token information is ignored).

Arguments:
1. "groupId"           (string, required) the group identifier
2. "address"           (string, required) the destination address
3. "quantity"          (numeric, required) the quantity desired
4. "data"              (number, 0xhex, or string) binary data
5. "token-ticker"      (string, optional) the token's preferred ticker symbol
6. "token-name"        (string, optional) the name of the token
7. "descUrl"           (string, optional) the url of the token description json document
8. "descHash"          (string, optional) the hash of the token description json document
9. "decimals"          (numeric, optional) suggest number of decimal places to display
10. "nochild"          (string, optional) do not allow this authority to create child authorities
11. "rescript"         (string, optional) for covenanted groups, this authority can change the
                         constraint script hash
12. "mint"             (string, optional) allow this authority to mint (create) new tokens
13. "melt"             (string, optional) allow this authority to melt (destroy) new tokens

Result:


Examples:

Get token info
> nexa-cli token info
> nexa-cli token info nexa:nqtsq5g59472zwd85c2esgslh6wh025r0x43ttlv2xy98jd0

Create a new token
> nexa-cli token new APPL apple
> nexa-cli token new nexa:nqtsq5g59472zwd85c2esgslh6wh025r0x43ttlv2xy98jd0 ORNGE orange
> nexa-cli token new nexa:nqtsq5g5ltvwgj6ga6vlyxcay22uh2m8zy0rxzp8sf884gp9 GRP grape http://nexa.org 1296fdd732e34fa750256095bb68dcd78091c49ab9382a35dce89ea15e055a63

Mint tokens
> nexa-cli token mint nexa:tpyte9hwr6ew0agt67a0y2fnnccc0d8r62lwryq44rfhzmv7ngqqqza82qdum nexa:nqtsq5g553andqv5p33ylx7xyr76vu0mh56x5nlylhfzcyj2 30000

Melt tokens
> nexa-cli token mint nexa:tpyte9hwr6ew0agt67a0y2fnnccc0d8r62lwryq44rfhzmv7ngqqqza82qdum 500

Get wallet token balances
> nexa-cli token balance
> nexa-cli token balance nexa:tpyte9hwr6ew0agt67a0y2fnnccc0d8r62lwryq44rfhzmv7ngqqqza82qdum
> nexa-cli token balance nexa:tpyte9hwr6ew0agt67a0y2fnnccc0d8r62lwryq44rfhzmv7ngqqqza82qdum nexa:nqtsq5g553andqv5p33ylx7xyr76vu0mh56x5nlylhfzcyj2

Send tokens
> nexa-cli token send nexa:tpyte9hwr6ew0agt67a0y2fnnccc0d8r62lwryq44rfhzmv7ngqqqza82qdum nexa:nqtsq5g5swutfrulf565c6v42rk36gk9w9r8lwymly8ju76c 150
> nexa-cli token send nexa:tpyte9hwr6ew0agt67a0y2fnnccc0d8r62lwryq44rfhzmv7ngqqqza82qdum nexa:nqtsq5g5swutfrulf565c6v42rk36gk9w9r8lwymly8ju76c 100 nexa:nqtsq5g563td29kuumldxk0u6lsfrjyapxth5jqwmyepjmlw 300

Make new authority
> nexa-cli token authority create nexa:tpyte9hwr6ew0agt67a0y2fnnccc0d8r62lwryq44rfhzmv7ngqqqza82qdu0 nexa:nqtsq5g5t8hqv7gflfp3gshvck0srh2a0ktd53kzc97c26w0 mint melt nochild rescript

Make new authority
> nexa-cli token authority count nexa:tpyte9hwr6ew0agt67a0y2fnnccc0d8r62lwryq44rfhzmv7ngqqqza82qdu0

Make subgroups
 > nexa-cli token subgroup nexa:tpyte9hwr6ew0agt67a0y2fnnccc0d8r62lwryq44rfhzmv7ngqqqza82qdum data1

Add token tracker
 > nexa-cli token tracker add nexa:tpyte9hwr6ew0agt67a0y2fnnccc0d8r62lwryq44rfhzmv7ngqqqza82qdum

Remove token tracker
 > nexa-cli token tracker remove nexa:tpyte9hwr6ew0agt67a0y2fnnccc0d8r62lwryq44rfhzmv7ngqqqza82qdum

list all token trackers
 > nexa-cli token tracker list

Get token mintage
 > nexa-cli token mintage nexa:tpyte9hwr6ew0agt67a0y2fnnccc0d8r62lwryq44rfhzmv7ngqqqza82qdum

```
