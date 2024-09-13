```
setblockversion blockVersionNumber

Set the block version number.

Arguments:
1. blockVersionNumber         (integer, hex integer, 'BIP109', 'BASE' or 'default'.  Required) The block version number.

Examples:

Vote for 2MB blocks
> nexa-cli setblockversion BIP109

Check the setting
> nexa-cli getblockversion 

```
