Title: Script Machine Registers
Maintainer: Griffith
Status: Draft
Initial Publication Date: 2024-07-13
Latest Revision Date: 2024-07-13
Version: 0.1

# Script Machine Registers
Script machine registers provide random access data into the script machine instead of always using sequential access.

## How would they work

By using two opcodes LOAD and STORE we can save up to X variables into script machine registers for easier use later in the script as a more performant alternative to ROLL and PICK. Initially allow for up to 32 (arbitrary value) registers to be used.

Inside an OP_EXEC, the script registers are reset to empty and can be used by the called script.  Upon return, they are reset to their original values.  In other words, the operation behaves as if the OP_EXEC executed inside a completely different script machine.

Script registers are cleared after execution of each script in the traditional and script template execution models.  It is not meaningful in push-only scripts to load script registers.  Attempting to do so will fail the script.

Scripts SHOULD NOT rely on the initial value of a register to be zero.  Scripts SHOULD always load an initial value.

Script machine registers implemented as `std::array<StackItem, 32> arrRegisters; `in the script machine.


### OP_STORE

#### Syntax and Stack

*REG_VAL* *REG_NUM* **OP_STORE** =>

- *REG_VAL*: The stack item to be stored in the register
- *REG_NUM*: The register number that the REG_VAL is stored in. Values outside of the range 0-31 will fail the script.  REG_NUM must be a Script Num (not a big number).

#### Implementation
```
// get the top two stack items, the top is the register number, the 2nd from the top is to be the register value
int register_number = top stack item
StackItem register_value = 2nd to top stack item

// in the script machine there are only 32 registers (0-31)
// a register number higher than this a failure
if register_number > 31:
    script failure

// store the value in the register
arrRegisters.at(register_num) = register_value
// remove the top two stack items we just used from the stack
pop_the_stack()
pop_the_stack()
```

Script Example:
```
push 10
push 5
OP_STORE # stores the value 10 into register #5
```


### OP_LOAD

#### Syntax and Stack

*REG_NUM* **OP_STORE** => *REG_VAL*

- *REG_NUM*: The register number that the REG_VAL is loaded from. Values outside of the range 0-31 will fail the script.  REG_NUM must be a Script Num (not a big number).
- *REG_VAL*: The stack item from the register. Note: All registers start script execution with a StackElementType::VCH(0) in them.

#### Implementation

```
// get the top stack item, this is the register number we want to load the value from
int register_num  = top stack item;
// in the script machine there are only 32 registers (0-31)
// a register number higher than this a failure
if register_num > 31:
    script failure

// load the value in the register
StackItem register_value = arrRegisters.at(register_num);
PopStack(); // pop the register number off the stack
PushStack(value) // push the loaded value on to the stack
```
Script Example:
```
push 5
OP_LOAD # pops the top stack item (5) and replaces it with the contents of that register
```


### Final Script State
It is not required that all registers be empty for the script to complete successfully. If values remain when the script is finished, they are cleared/ignored.


