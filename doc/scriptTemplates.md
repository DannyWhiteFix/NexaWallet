# Script Templates
*Allows 3 agent (covenant, owner, and spender) trustless interaction*

## Introduction
A script template is a generalization of the P2SH (pay-to-script-hash) format, that allows for the implementation of covenants.  It is perhaps conceptually difficult to understand at first, but is both easy to implement over the existing Nexa scripting system and is powerful.

A script template factors all data in a traditional script out into arguments that are furnished by the owner and spender.  For example, a traditional pay-to-pubkey-hash script looks like this:

DUP 
HASH160
PUSH **pubkeyhash**
EQUALVERIFY
CHECKSIG

Since the pubkeyhash changes for each address, a slightly different script is created for each address.  A script template factors this data out of the script, expecting it as arguments (i.e. on the stack) before the script is executed.  This means that every pay-to-pubkey-hash script is the exact same bytes.

This confers several advantages:

* easy script identification
* parameter extraction is unnecessary
* The hash of the script template does not change when parameters change
* 3 participant interaction

Note that the arguments may themselves be scripts, executed via the EXEC opcode.

## 3 Participant Interaction

A smart contract or covenant system contains 3 agents (an "agent" is defined by lack of trust) whereas traditional bitcoin contains two.  The 3 agents are:

* The contract/covenant author (often the group creator)
* The current holder
* The spender

These three agents are now captured in 3 scripts: the "template", the "constraint scriptlets", and the "satisfier" scripts.

The "satisfier" script is analogous to the traditional "scriptSig".  It is provided by the spender and pushes data onto the stack that "satisfies" the constraints enforced by other scripts. 

The "constraint" script is analogous to the traditional "scriptPubKey".  It is provided by current "owner" of a UTXO to constrain future spending in manners allowed by the template.  It typically consists of data pushes or "scriptlets" (small scripts which are also pushed as data) .  These "scriptlets" are executed at various times as controlled by the template.  The constraint script is optional (its possible that the template script allows no additional constraints).

The "template" script defines the overall structure in which the other scripts execute.  It may be conserved from input to output so implements covenants.  It implements any constraints (or spending permissions) defined by the Group, and decides when to delegate constraints/permissions to constraint scriptlets.

These scripts are positioned very differently in the blockchain as compared to traditional locations.

### Relationship to P2SH

Note that if the holder's modifications are not factored out of a script, the system reduces to P2SH with 2 parties.  But the underlying implementation of script templates is much cleaner since P2SH was deployed as a soft fork.  This meant that it had to be partly compatible with, but also patch the standard script execution model.  

In contrast, script templates specifies a separate execution model (described below).

## Script Template Structure Within a Transaction

### Locking
To indicate a template, a transaction output's type is set to TEMPLATE(1).  A template's "scriptPubKey" field does not contain a script.  It contains the following, serialized as a "push-only" script:

GroupId or empty stack item, 
Group amount if GroupId, 
H(script template) or well-known script template, 
H(args script) or empty stack item,
any additional args (as multiple pushes)

### Unlocking (spending)
This template is spent with a "push-only" script located in the transaction "vin" inputs.  It consists of:

script template (as a single data "push"), if the template is not well-known, otherwise do not push,
args script (as a single data "push"), if H(args script) is not empty, otherwise do not push
satisfier script data pushes

Note that the script template and args script are **not actually pushed** onto the script machine stack so can exceed script stack limits.

### Hash Functions
H() is either the Hash256 or Hash160 "standard" hash functions (creator's choice).  The choice is clear based on the size of the pushed item.  Hash160 is recommended unless the creation of the preimage is multi-party and potentially susceptible to Wagner's Birthday Attack.

### Well-known script templates
Certain well-known script templates are specified with hard-coded numbers.  From time to time new well-known script templates may be added via a hard fork.  

Additionally, software may choose to compress commonly used script templates by using >2 byte (and <9 byte) numbers.  In such a case, the software MUST provide an interface to query the mapping from number to script template (which is beyond the scope of this document).  The difference between a "well-known" and "commonly used" script template is that the "commonly used" number must be replaced with the actual hash, and its script with the actual script, when the transaction is included in the blockchain or hashed.

### Argument Script Commitment
To minimize space in the UTXO, and manage data visibility, a creator can choose to add a commitment to a push-only script of arguments, and directly push any additional arguments.

### Example

The equivalent of "pay-to-pubkeyhash" (p2pkh) is encoded as follows (italics denote data):

Template =
FROMALTSTACK    *# We will discuss this later*
CHECKSIGVERIFY  *# Could be CHECKSIG*

Constraint argument script =
PUSH *pubkey*

Satisfier =
PUSH *signature*

The locking output is:
FALSE  # No group
PUSH *Hash160(Template)*
PUSH *Hash160(Constraint argument script)*

The unlocking input is:
PUSH *Template*
PUSH *Constraint argument script*
PUSH *signature*           *# that is, the satisfier script is appended.*

Note that since the hash of the constraint argument script is pushed as the locking output the pubkey is hidden until spend.  So there is no need to explicitly code this like in the standard P2PKH script.

### Well-known Example
The script described above is actually "well-known" script number 1, so it could be rewritten as:

The locking output is:  
FALSE  # No group  
OP_1  
PUSH *Hash160(Constraint argument script)*

The unlocking input is:
PUSH *AsData(PUSH pubkey)*
PUSH *signature*

On detail to note is that the constraint arguments are pushed *as a script even if it is just one argument*.  This is emphasized above with the "AsData(...script...)" notation.


## Script Template Execution Model

The unlocking input and locking output data are analyzed and the satisfier, constraint (potentially in 2 parts, the hashed and visible), and template scripts are extracted as described above.

The satisfier and constraint scripts are executed in separate "script virtual machine" environments with "push-only" restrictions. When executing the constraint script, The hashed portion is executed first, and then the visible portion is executed.

The main stacks from these two executions are saved.

 A third "template" script virtual machine  is created.
The "main" stack from the satisfier execution is copied to the "main" template stack.  The "main" stack from the constraint execution is copied to the "alt" template stack.  The template script is then executed.

In other words, the template script can access the result of the satisfier script on its main stack, and the result of the constraint script on its alt stack.

Execution is successful if the main stack is empty (and no "VERIFY" operations failed during execution).

## Address Formats

Well known templates are identified by address prefix bytes, similar to Bitcoin/Bitcoin Cash, resulting in an address similar to what we use today.

A complete address is possible, specifying group, template hash, and constraint args is possible in around 72 raw bytes (or 40 bytes without the group).  This turns into a long ascii-encoded address, but not an unusable one.

## Advantages

- Allows interaction between 3 agents (who do not trust eachother).

- Combined with OP_EXEC, this system allows 2 agents (the covenant author, and the output "owner") to specify constraints/permissions via scripts and data, rather than data only.

- All scripts are provided to the blockchain when they are executed.  This minimizes data storage in the UTXO database which is an important feature to support nontrivial scripts.

- This also means that transaction size more accurately reflects execution time.

- While trivial scripts (< 20 bytes) would be more efficiently encoded as raw bytes, it is expected that any such popular scripts will be assigned well-known numbers

- The most common (pay someone) format is encoded slightly more efficiently than p2pkh.

- Addresses remain reasonable for arbitrary scripts & templates, although this is larger than the addresses we currently have.  In the worst case, an address must contain 2 SHA160 or SHA256 numbers (the template and the constraint scripts) and a Group.  However, if the template is a group covenant, its value is enforced so does not need to be specified in the address.  If no constraint script is used it does not need to be specified.
- Allows P2SH and OP_GROUP to be removed from old-style scripts (templates should be used).
