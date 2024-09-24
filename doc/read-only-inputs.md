# Read-only transaction inputs in NEXA

Nexa transactions can contain inputs that are not spent when the transaction is processed.

## Constraints
The Type of the transaction input must be set to 1 (READONLY) rather than the normal 0 (UTXO) to mark a tx input as read-only. Read-only inputs must have their nValue and nSequence fields set to 0. Read-only inputs may have an empty scriptSig, or a valid scriptSig.

## Validation rules

### Transaction Validation

A transaction MUST NOT be comprised solely of read-only inputs.  It MUST have either 0 inputs (coinbase) or at least 1 non-read-only input.
A transaction MUST NOT duplicate inputs, including 2 of the same read-only inputs, or the same read-only and consumed input.  Note that since duplicated inputs are currently not allowed, this restriction is essentially saying to not skip read-only inputs during duplicate detection.

The nValue (amount) of a read-only input MUST be 0.

Additionally, the nValue of a read-only input MUST be explicitly excluded from the input total during transaction validation even though they are required to be 0. This is a redundant check meant to catch any mistakes where a read-only tx input somehow has a non 0 value for nValue. Read-only inputs are not processed when updating spent inputs in the utxo set because they do not spend the input.

A zero length signature (of a read-only input) is valid.

If the signature is non-zero it MUST be validated in the normal fashion, even though it will not spend the input.

Read-only inputs must be excluded from undo data because they did not create a change in the utxo set.

Grouped assets in read-only inputs MUST not be spent or counted as part of introspection.
Group authorities in read-only inputs are available to the transaction IF and ONLY IF the BATON flag is set and the scriptSig is non-zero and valid.

### Block Validation Rules

Recall that blocks are validated according to the OTI (all outputs added then inputs deleted) algorithm.  Within a block, all read only inputs of every transaction MUST be conceptually evaluated before OTI.  In other words the full algorithm is now ROTOTI "Read Only Then Outputs Then Inputs".  Note that since read only inputs do not affect the UTXO set, the order of evaluation of read-only inputs does not matter.  See section "Appendix 1: Read-only sequencing" for the rationale behind this decision.

The effect of this is that a block can include transactions that "read" a UTXO and transactions that consume the same UTXO in any order.  However, the new UTXOs created by transactions in the block CANNOT be used as read only within that same block.  Users must wait until the transaction is confirmed in a block before using its outputs as read-only UTXOs. 


## Use cases
Read-only inputs are useful for bringing in transaction data from inputs that do not belong to the user creating the transaction because they are not signed. Data from these inputs can be accessed via transaction introspection and is useful for covenants and templates that want to consistently pull in data from a specific utxo to be used in the transaction.  Read-only inputs allows multiple transactions to access this data in parallel (as compared to the "import and rewrite" approach) because the UTXO is not destroyed and recreated.

A nonzero length signature can be used to prove ownership of a UTXO, because any nonzero length signature MUST be valid to for the transaction to be valid (irrespective of the read-only flag).  This makes certain asset operations easier, specifically where owners are asked to prove ownership of an asset.  Dividend and token reward distributions are classic examples of this use case.  Note that a contract that uses this feature MUST use introspection to check that the read-only input's scriptSig length is non-zero.  Also note that a contract that needs the quantity of the owned asset can access it via the prevout nValue (amount) field, even though the quantity (amount field in CTxIn) being imported into THIS transaction is 0.

The powers provided by a token authority UTXO can be reused by importing the authority UTXO as read only and signing it, provided that the authority has the BATON flag set.  This makes token operations more efficient and easier to develop since the "import and rewrite" design pattern is no longer needed.

A BATON group authority can be offered to the general public in a non-destructive manner by making a spend clause that verifies the input is read-only (and presumably a different clause to actually spend the UTXO to stop offering this authority to the general public).  However since a nonzero scriptSig will not enable the authority powers, the constraint must be written to require at least a trivial scriptSig.  For example, "OP_DROP"/"OP_1" would work.  However, in practice the group owner will likely want to prevent non-read-only spends so a slightly larger script with introspection is necessary.

Note that is not possible to prove one has signatory ability over a BATON group authority without also activating the group authority's powers within that transaction.  It is therefore recommended that any use of read only inputs to prove signatory abilities over BATON authorities sign the input with an xxx/ALL sighash type to strictly control how those authorities are used.


# Appendix

## Appendix 1: Read-only Validation Sequencing

The sequencing of read-only validation has subtle ramifications on how read-only inputs could be used, especially in the "state update" architecture.  This architecture has a "baton UTXO" that contains service state, call it S{n}.  Any client can access this state for read by using read-only inputs.  When the state needs to be updated, a transaction (call it T{n->n+1}) is created that inputs (and destroys) the UTXO and produces a new UTXO (call it S{n+1}), with the new state.  Consider two services: in a "data-oriented" service, there is no advantage to be gained by knowing S{n+1} but being able to use S{n}.  However in a "front-runnable service", there is an advantage. 

We will use this design pattern to describe the ramifications of read-only validation sequencing within block validation.

There are three possibilities given our existing outputs then inputs (OTI) algorithm: before OTI, between O and I, and after.

If read-only input checking happens between O and I, transactions could be included in the block that input both the old and new states: S{n} and S{n+1}.  This would offer the least impediment to clients; they do not need to monitor the txpool and can use whatever state they have cached.  However, it would allow a single transaction to input BOTH S{n} and S{n+1}, and therefore potentially pick data between the old and new states to satisfy a particular spending clause.  The state transformation is no longer atomic at transaction boundaries.  This would place a significant burden on application developers to ensure that the same input is used for ALL state.  Note that simple solutions do not work, like application developers implementing some kind of internal state "lock", where the application smart contract fails in the "locked" state.  The problem is that this would require at least two transactions: "lock and update", then "unlock", which must be issued in separate blocks.  But there is no way to guarantee separate block inclusion.  Even if the service waits for the first transaction to confirm before issuing the second, an attacker could attempt a chain reorganization attack to issue both within a forked block.  In summary, "in the middle" is front-runnable in a very immediate way (one could execute the front-run against S{n} and then the resolution against S{n+1} repeatedly within a single block).  The ability to issue the setup against S{n} and the resolution against S{n+1} in the same block would allow reuse of the same coins to execute the front-run attack (if some coins are needed).

If read-only input checking happens afterwards, this would mean that transactions in the block can only use S{n+1}.  This allows applications to use the new state right away, which is typically desirable.  However, it would mean that a miner may be fee-incentivized to place transactions using S{n} in the block, bumping S{n+1} forward to another block (perhaps indefinitely).  But in the same manner, the T{n->n+1} can be issued with a high fee, incentivizing miners to kick out S{n} using transactions (it would have to out-spend ALL S{n} though).  So this sequencing may create a fee war between state users and the state updater -- ultimately resulting in all value being extracted from the transformation knowledge before it is allowed to proceed.  In summary "after" this is front-runnable using fee competition, the effect is to delay the state transition indefinitely, and it is likely to be onerous for contract developers to anticipate and counteract this.

If read-only input checking happens first, this would mean that transactions in the block can only use S{n} (because S{n+1} hasn't been included in the UTXO set yet).  The effect of this is that read-only transactions cannot use fees to push the state update transaction out-of-the block, because the transactions do not conflict.  Note though that an attacker could attempt a chain reorganization attack to drop T{n->n+1} from the block, delaying the transformation.  However, why bother?  Any transaction that wants to use the old state may do so by simply issuing a transaction into the current block.  But this means that the new state cannot be used until the block is mined, which may delay "data-oriented" applications (but only those that need the new state).  This is "naturally" front-runnable -- the S{n+1} state is announced before it takes effect, allowing a block's worth of transactions to attempt value extraction.  However, the resolution transaction using S{n+1} cannot be issued until the next block so coins cannot be reused.

For completeness, we must consider not allowing any transactions that use S{n} or S{n+1} in the same block as T{n->n+1}.  This would allow S{n} and T{n->n+1} fee competition, as with the "after" possibilitiy.  But it would also cause what is in-effect a service outage for "data-oriented" services until T is confirmed, yet still allows "front running" by fee competition and indefinite postponement of T{n->n+1}.

From this analysis, it appears that ROTOTI "Read Only Then Outputs Then Inputs" makes the most sense, even though the use of the new state is delayed until the block after confirmation.  For clarity, note that use of the new state is ONLY delayed for read-only use -- deep unconfirmed chains of transactions that spend other transactions is unchanged.

This choice has an implementation advantage in the txpool; read-only inputs cannot cause a txpool dependency.  This means that we do not need to evict read-only children when the parent is evicted (since no read-only children exist).  In the current txpool dependency is a 1-to-1 relationship; but allowing unconfirmed read-only inputs into the txpool changes this to a 1-to-many relationship, so would necessitate a structural change.


In an aside, note that this analysis suggests that services with a significant front-running benefit will need a more sophisticated contract regardless of the chosen read-only ordering.  All cases except "no read only if modifying" allow front running naturally or by fee competition, and the "no read only if modifying" case allows it by a single-block reorganization attack.  So these contracts may need to implement a 2 phase state update where the old state is first "locked" for a sufficient blockchain depth to discourage chain reorganization attacks, then the new state is written and "unlocked".  This lock/unlock function can be implemented at the smart contract level -- it can simply be a bit in the application state that fails the read-only-using-contract if 0.

