# OP_PARSE Script Instruction

This opcode automatically parses common types of script data (notably bytecode), extracting portions of that data and placing them on the stack.
This extracts data from buffers of data that is serialized in a specific format, as compared to OP_SPLIT which extracts data from buffers of any format by offset.

One the the primary tasks of UTXO-family scripts is to constrain and verify properties of locking scripts.  This is the only way to constrain the effects of a transaction.  For example, let us suppose an author wants a spend clause that constrains an input to be only spent to a particular output.  This example was chosen since it is simple yet an essential requirement of "vault" functionality and reversible payments.  The author must write a script that accesses the output script and checks that its template hash and its args hash are equal to expected values.  Today, to do so the author must use introspection to access the output script, and then write a small bytecode parser within bytecode itself to extract the template hash and args hash.  While possible, this bytecode parser is a non-trivial piece of code.  And without loops, the size of this code is proportional to the number of opcodes needed to be parsed to access the needed data.  However, with OP_PARSE, accessing these two fields can be done in a single instruction.

Similarly any state baton pattern will benefit from OP_PARSE.  In the state baton pattern, a service provider is periodically updating a piece of state held within a UTXO, while users are accessing this state.  But updating this state must follow a set of rules agreed upon by the service provider and the users of the service.  These rules must therefore be enforced in the constraint script.  OP_PARSE is used to load the prior (incoming) state from the prevout of one of the inputs in the transaction.  The script then applies its rules producing the expected output state.  OP_PARSE is then used to get the next state from one of the outputs of the transaction, and OP_EQUALVERIFY compares and verifies that the expected output state equals the actual state specified in the transaction.


## Definition

<args> <parse operation> OP_PARSE

- *parse operation*: a minimally encoded (single byte) number defining the parsing algorithm and parsing input data

Currently defined parse operations are: OUTPUT_DATA (OP_0), PREVOUT_DATA (OP_1), INPUT_DATA (OP_2), and BYTECODE_DATA (OP_3).  Any other values MUST fail the script (REQ1.0)

The specific behavior of this opcode depends on the parse operation.

### Error conditions

If start, count, whichInput or whichOutput fields are less than 0, the script **MUST** fail (REQ1.1).
if whichInput or whichOutput exceeds the # of inputs or outputs available, the script **MUST** fail (REQ1.2).
If the requested number of fields exceeds what is left in the input data, starting from the indicated start position, the script  **MUST** fail (REQ1.3).
If the requested number of fields is 0, the operation  **MUST** succeed without any parsing (REQ1.4).  This means that it succeeds even if the starting field is beyond the end of the parsed data, or even if the parsed data would have a parsing error.  Also note that no results would be pushed onto the stack -- so this mode has almost no purpose.
Otherwise, if the start field exceeds what is available in the data, the script **MUST** fail (REQ1.5).
The data to be parsed **MUST** be valid for that parse operation *up to the point where op_parse has gathered all requested data*.  OP_PARSE **MUST NOT** parse beyond the minimum needed to access the requested data (this allows scripts to truncate large input buffers using OP_SPLIT OP_DROP if the author can determine a maximum location of the requested data) (REQ1.6).

### Parse Operations

The xxx_DATA operations parse scripts to retrieve constant data (e.g. OP_PUSHDATA{n} or OP_{NUMBER}).  Operations may request N contiguous data items.  These items are pushed onto the stack in the order they are encountered.  This means that the top of the stack will contain the last item encountered.

#### OUTPUT_DATA

Parses transaction locking scripts.

##### Syntax and Stack
*whichOutput* *start* *count* **OUTPUT_DATA** **OP_PARSE** => *item*<sup>*[?](../opcodesyntax.md)*</sup>

- *whichOutput*: 0-based index into the transaction's output array
- *start*: 0-based "canonical" push to access
- *count*: How many items to retrieve
- *OUTPUT_DATA*: constant defined as OP_0

If the output is not a script template, it is parsed as BYTECODE_DATA (see below).  Otherwise it is parsed in "Canonical" form as follows:

##### Canonical Output Form

The "canonical push" normalizes the script template as beginning with the following data items.  In other words, even if the particular output being parsed does not contain all of the following fields, OP_PARSE parses it as if it does.  This simplifies output field selection, while still retaining the efficiency of allowing transactions to drop unused fields.

- 0: Group id.  If this output is ungrouped (just Nexa) the result will be OP_0
- 1: Group amount.  If this output is ungrouped (just Nexa) or fenced nexa, the result will be the amount of nexa in the output.  This will make handling nexa like any other token easier (but that mode can be distinguished, if needed, because the nexa "group id" is OP_0).  If the output is a grouped authority (so no amount defined), the result will be OP_0.
- 2: Group authority flags. If this output claims no authority or is ungrouped the result will be OP_0.
- 3: Template hash.  Note that value in the output (either well-known number or hash) is provided.  It is not converted, with the expectation that the transaction author has provided this number in the way constraint scripts expect (see appendix 1).
- 4: Args hash.
- 5,6,7: produces OP_0 (reserved for future use).
- 8...: The subsequent pushes in this output script (visible args and non-arg data)

Note that for numeric pushes the actual result of the push will be provided.  For example OP_TRUE and OP_FALSE provides the numbers 1 and 0, while OP_2 provides the number 2 (not its opcode value of 0x52). OP_PUSHDATA{n} provides the actual data pushed (so not the pushdata opcode and length).

The canonical form **MUST** be fully parsable or op_parse fails.  Note that the transaction would fail anyway in this case, because the referenced output would be invalid.

#### PREVOUT_DATA

Parses prevout locking scripts.

*whichInput* *start* *count* **PREVOUT_DATA** **OP_PARSE** => *item*<sup>*[?](../opcodesyntax.md)*</sup>

- *whichInput*: 0-based index into the transaction's input array
- *start*: 0-based "canonical" push to begin with
- *count*: How many items to retrieve
- *PREVOUT_DATA*: the constant 1

This parser follows the same algorithm as the OUTPUT_DATA parser, except that it parses the prevout of input *whichInput*.

#### INPUT_DATA

Parses unlocking scripts.

*whichInput* *start* *count* **INPUT_DATA** **OP_PARSE** => *item*<sup>*[?](../opcodesyntax.md)*</sup>

- *whichInput*: 0-based index into the transaction's input array
- *start*: 0-based "canonical" push to begin with
- *count*: How many items to retrieve
- *INPUT_DATA*: the constant 2

If the input is not a script template unlocking script, it is parsed as BYTECODE_DATA (see below).  Otherwise it is parsed in "Canonical Input" form as follows:

##### Canonical Input Form

The canonical input form normalizes the script template as the following data items.  In other words, even if the particular input being parsed does not contain all of the following fields, the code should index it as if it does.

- 0: Template script bytecode.  The actual bytecode is ALWAYS provided even though prevouts using well-known scripts will not actually contain the bytecode.
- 1: args bytecode.
- 2...: satisfier pushes.

#### BYTECODE_DATA

Parses arbitrary scripts.

*bytecode* *start* *count* **INPUT_DATA** **OP_PARSE** => *item*<sup>*[?](../opcodesyntax.md)*</sup>

- *bytecode*: vector of chars that represent a serialized script or script fraction (e.g. bytecode)
- *start*: 0-based "canonical" push to begin with
- *count*: How many items to retrieve
- *BYTECODE_DATA*: the constant 3


#### Examples

##### Access the groupId and amount from the prevout locking script of input N (e.g. how much of what token does the prevout N pull into this transaction)

Minimally annotated code is provided, followed by a detailed step-through.
```
PUSH n
0 # group id
2 # get 2 items
PUSH PREVOUT_DATA
OP_PARSE
```
| Instruction  | Description     | Stack after execution (end is top[^1]) |
|:-------------|:---------------:| :--------------------------------------|
| ```PUSH {n}``` | push the input index | {n} |
|```0``` | access the first data pushed: the group id | {n} 0 |
|```2``` | get 2 items | {n} 0 2 |
|```PUSH PREVOUT_DATA```| select the op_parse variant | {n} 0 2 PREVOUT_DATA |
|```OP_PARSE``` | execute the instruction | {amount} {groupId} |


##### Access the groupId and amount from the prevout locking script of output N (e.g. how much of what token does the prevout N pull into this transaction)

Minimally annotated code is provided, followed by a detailed step-through.
```
PUSH n
0
2
PUSH OUTPUT_DATA
OP_PARSE
```
| Instruction  | Description     | Stack after execution (end is top[^1]) |
|:-------------|:---------------:| :--------------------------------------|
| ```PUSH {n}``` | push the output index | {n} |
|```0``` | access the first data pushed: the group id | {n} 0 |
|```2``` | get 2 items | {n} 0 2 |
|```PUSH OUTPUT_DATA```| select the op_parse variant | {n} 0 2 OUTPUT_DATA |
|```OP_PARSE``` | execute the instruction | {amount} {groupId} |

##### Access the first pushed data from the template script of Input n.

This seems to be an unlikely use, yet is included to demonstrate 2 levels of data parsing.
The template script is the first item in the input script, pushed as a data blob.  So we get that and then parse it.
Minimally annotated code is provided, followed by a detailed step-through.
```
PUSH n
0
1
PUSH INPUT_DATA
OP_PARSE
# the above got me the template script on the stack
0
1
PUSH BYTECODE_DATA
OP_PARSE
```
| Instruction  | Description     | Stack after execution (end is top[^1]) |
|:-------------|:---------------:| :--------------------------------------|
| ```PUSH {n}``` | push the input index | {n} |
|``` 0 ``` | Get data item 0 (template script bytecode) | {n} 0 |
|``` 1 ``` | Get 1 item | {n} 0 1 |
|``` PUSH INPUT_DATA ``` | select the op_parse variant| {n} 0 1 INPUT_DATA |
|``` OP_PARSE ``` |  execute the instruction | {bytecode} |
|``` 0 ``` | Get data item 0 from the script bytecode  | {bytecode} 0 |
|``` 1 ``` | Get just one item  | {bytecode} 0 1 |
|``` PUSH BYTECODE_DATA ``` | select the op_parse variant | {bytecode} 0 1 BYTECODE_DATA |
|``` OP_PARSE ``` | execute the instruction | {first data item} |

## Appendix 1: Design rationale

### Why have a Parse Operation field rather than separate opcodes?
To save instruction space, OP_PARSE implements a variety of algorithms and allows the specific algorithm to be chosen.  It is therefore effectively a multi-byte opcode.  This is accomplished by pushing a parse operation constant to the stack first, and then pushing OP_PARSE (and this is the reference behavior).  However, note that in the serialized form this will consist of 2 bytes, for example 0x51d0 that could be interpreted as a multibyte opcode (with the caveat that there must be available space on the stack for a phantom push of 1 byte), but it is also OP_1 OP_PARSE (PREVOUT_DATA parsing).

### Why convert well known template scripts to their bytecodes?
The intention is to future-proof scripts in the situation where popular templates are assigned "well known" numbers.  In this case, the scripts still want to parse some data out of the bytecode and need the whole script to do it.

### Why not convert well known templates to their script hashes?
Well known script hashes are provided as their well-known numbers for comparison efficiency.  Authors of transactions must know whether the script is looking for a well-known number because a transaction cannot spend a transaction without knowing the execution details of the locking scripts.

There is limited downside as well-known numbers are added for popular scripts because the author of a future transaction that uses an old script can provide the actual hash, not the new well-known number.  This means that old scripts function just as they used to, but new scripts can take advantage of the efficiency of well-known script numbers.  However, a transaction will not be able to bring in 2 different inputs, one that expects the well-known number and another that expects the full hash.  This situation is expected to be so rare it will likely only be theoretical.


[^1]: Note: Stacks are shown with the TOP at the END, either in left to right or top to bottom order.  For example in a stack of "0 1", "1" is on the top of the stack.  This aligns the visual display of the stack with the code order; In other words: "PUSH 0; PUSH 1" is shown as "0 1".  You will find that this visual ordering is much easier to follow because you do not need to mentally reverse lists.  You just need to remember the top is at the end.
