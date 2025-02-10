Nexa Hard Fork 1
===========================

# Activation

Fork 1 has a 2 phase activation.  When the MTP (median time past) of a block is greater than or equal to the the activation time, the fork "activates" (phase 1).  The transactions in this "activation" block MUST still follow the old ruleset.  Activation flushes the txpool and re-admits all pending transactions under the new rules.  The next block (and all subsequent), regardless of its time, are "enabled" blocks.  They are evaluated using the new fork rules.

This 2 phase activation allows us to cleanly apply the new rule set to pending transactions, by giving advance warning of a "locked in" upgrade.

# New script functionality/opcodes

* OP_STORE / OP_LOAD

  see (Script Registers)[script_registers.md]

* OP_PARSE

  see (OP_PARSE)[op_parse.md]

* Introspection (OP_INPUTTYPE, OP_OUTPUTTYPE, OP_INPUTVALUE)

| Word            | Value  | Hex  | Input               | Output                 | Description                           |
| --------------- | ------ | ---- | ------------------- | ---------------------- | ------------------------------------- |
| OP_INPUTTYPE    | 107    | 0x6b | N                   | T                      | Puts the Nth input's type field onto the main stack |
| OP_OUTPUTTYPE   | 107    | 0x6b | N                   | T                      | Puts the Nth output's type field onto the main stack |
| OP_INPUTVALUE   | 107    | 0x6b | N                   | T                      | Puts the Nth inputs's amount field onto the main stack.  This is 0 for read-only inputs. |

# New transaction functionality

* Read-only inputs

  see (read only inputs)[read-only-inputs.md].

* Data in inputs and outputs

  Append an OP_RETURN and arbitrary additional data to unlocking or locking scripts to associate that data with an input or an output.  Anything after the OP_RETURN
  is not executed in the script.  It is recommended that you use serialize the additional data using script serialization so analysis programs can parse it without knowing its contents.  This extra data is accessible via transaction introspection, although it is recommended that the normal push operations be used to provide data to scripts.

# Constraints

* Minimum block size is raised to 2MB to allow more volatility in transaction generation rates.

* Script Machine limits changed.

See (Nexa Script Machine)[nexa-script-machine.md]

* Template script args hash is limited to 0, 20 or 32 bytes.  Previously this was allowed onchain, but is unspendable.

This change prevents accidental creating of unspendable templates, and leaves other sizes open for future use.

* Legacy (non-script template) outputs formats are tightly constrained.

By constraining arbitrary scripts in the outputs, we minimize the size of the UTXO and prevent a variety of DoS/scalability attacks that historically caused Bitcoin to adopt the "IsStandard" design idea.

  * All non-standard outputs are now disallowed by consensus.  Pay-to-script-template MUST be used for arbitrary contracts.

  * TX_PUBKEY, and TX_SCRIPTHASH "standard" scripts are disallowed.

  * Multisig script are allowed if they are "standard".  This means that they must be M of N where N is 1,2, or 3, and M > 0 and M <= n.

  * For legacy compatibility TX_PUBKEYHASH are allowed, but it is recommended to not use it.  Instead use pay-to-public-key-template.

TX_PUBKEYHASH remains available so legacy libraries can be used with Nexa with minimal work.

  * TX_NULL_DATA (OP_RETURN) is fully supported and is the expected way to include data (that is not meant for the UTXO) in a transaction

