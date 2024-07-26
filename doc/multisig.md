<div class="cwikmeta">
{
"title": "Transaction Changes",
"related":["/transaction.md"]
} </div>

# Multisig Changes

This document assumes a familiarity with Bitcoin Cash Schnorr Multisig

## ECDSA Removed

ECDSA signatures have been removed.

## "Soft" Fail

Scripts that want CHECKMULTISIG to push FALSE on the stack *MUST* set the signature bitmap (previously the "dummy" parameter) to OP_0 (a stack item with 0 length).  The signature fields are unused, and *SHOULD* be set to OP_0, but may be anything.  This means that no signatures will actually be checked.

If the signature bitmap is non-zero, and any actual signature checks fail, the script immediately fails in the same manner as CHECKMULTISIGVERIFY.

This behavior does not reduce generality since the spender knows that the signature will fail so can replace the signature bitmap and all signatures as described above when creating the satisfier script.

## m of N Multisig

Using the 'addmultisigaddress' rpc command, any combination of multisig address can be created with as many as 16 pubkeys. So anywhere from a '1 of 16' to a '16 of 16' multisig address can be created and and then subsequently used as a wallet address.

## 0 of N Multisig

There is no reason to make a 0 of N multisig.

In Nexa, 0 of N scripts are unspendable because the "MINIMAL_DATA" requirement reduces any pushed 0 to a stack item with 0 length, resulting in the soft fail semantics described above.  At some point "MINIMAL_DATA" may be relaxed so DO NOT RELY ON 0 of N to be unspendable... if MINIMAL_DATA is relaxed 0 of N may become anyone-can-spend.  At this point we can explicitly make 0 of N unspendable, if desired.  Anyone-can-spend semantics is the BCH behavior in the 0 of N case (and it follows the meaning of "0 of N") so this is not considered an issue for other blockchains.



