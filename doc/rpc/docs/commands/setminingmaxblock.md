```
setminingmaxblock blocksize

Set the maximum number of bytes to include in a generated (mined) block.  This command does not turn generation on/off.

Arguments:
1. blocksize         (integer, required) the maximum number of bytes to include in a block.

Examples:

Set the generated block size limit to 8 MB
> nexa-cli setminingmaxblock 8000000

Check the setting
> nexa-cli getminingmaxblock 

```
