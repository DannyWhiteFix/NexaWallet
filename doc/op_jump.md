# OP_JUMP Script Instruction


## Definition

This opcode jumps to a location defined by the current location minus the argument to this script (counted in bytes).  However, False or a bignum/scriptnum of 0 continues to the next instruction, not re-executing the current one.

(REQ1.0) Jumping to exactly the location after the last instruction (that is, to the end of the script code, but not beyond) is a valid way to end the script (all other validation checks, such as clean stack, are still checked for the script to be valid).

Note that since the offset is specified in bytes, it is possible to jump into an area of the script that is also pushed bytes.  For example:  "PUSH 010000000000h, JUMP", jumps backwards 1 byte, executing the last byte of the push as code (which pushes 0 to the stack), then executes JUMP again, passing thru because the stack top is false.  Script authors might also use "0 IF **code** ENDIF" to create isolated code sections that can only be JUMPED into.

### Error conditions

If the relative location is outside the bounds of the current script code, the script **MUST** fail. (REQ1.1)

If the maximum ops or sig ops are exceeded, the script **MUST** abort and fail at that moment (that is, abort out of infinite loops) (REQ1.2)

If the relative location is a byte buffer of length greater than 8 (an out-of-range scriptnum), the script **MUST** fail. (REQ1.3)

### Syntax and Stack
**relative location** **OP_JUMP** => *item*<sup>*[?](../opcodesyntax.md)*</sup>

- *relative location*: a backwards offset specified as a number of bytes, relative to the beginning of this instruction.  If the relative location field is False (the empty stack item) or a form of 0 (a scriptnum or bignum of 0) then continue with the next instruction (do not jump).  A positive relative jump moves towards the beginning of the script.  A negative one moves towards the end.

#### Example Uses

Note that locations in these scripts are denoted by "<some string>:", for example "jumpat:".  Given these locations, computing and pushing the relative jump argument looks awkward in these scripts.  However, the higher level language (even if its an assembly language) would handle this for you as part of higher level looping or function call constructs.

##### Basic countdown loop

PUSH count
top:
  do some code
  1SUB
  DUP
  IF
    PUSH top - jumpat # this is evaled at compile time
else
    PUSH FALSE
endif
jumpat:
IFJUMP

##### Loop 4 times
PUSH FALSE  # when ifjump pops this we'll stop looping
PUSH top - jumpat  # this is evaled at compile time
DUP                # Make 4 copies of the jump target
DUP2
top:               # since the stack is false, top, top, top, top, we'll execute the loop 4 times.
    do some code
jumpat:
IFJUMP

##### Function call

0 IF  # skip executing this code right now, so we can define functions

funcDefinition:
  <do some code>
  DROP   # This function took 2 args
  DROP
funcEnd:
  IFJUMP

ELSE

# call that function
push continue - funcEnd  # first push where we want to resume execution
push arg1  # Push the function args
push arg2
push funcDefinition - jumpat  # Push the function's address
jumpat:
IFJUMP   # call the function
continue:

ENDIF


##### Use stack data to define the loop contents using OP_EXEC

top:
  PUSH <script data>  # suppose that this script takes 2 args and returns 1 arg where you loop if 0 (some kind of search maybe?)
  PUSH <script arg 1>
  PUSH <script arg 2>
  2 1 OP_EXEC
  IF
    PUSH FALSE
  ELSE
    PUSH top - jumpat
  ENDIF
jumpat:
  IFJUMP

##### Branch table

The idea of a branch table is to abstract destinations into an integer from 0 to N.  Assume that this integer is the top stack item.  We will space out jump code so each entry takes 4 bytes.  Since the IFJUMP takes 1 byte, and pushing 2 bytes is 1 byte of code + 2 bytes of data, this gives us 2 bytes of relative offset for jump destinations (note that for this particular script to work your "compiler" must not optimize PUSHes into their most space efficient form).  Of course you could space it out more if needed:

2
LSHIFT   # Multiply the index by 4
1ADD     # because the 1st jump starts at offset 1 not 0.
NEGATE   # jump downwards relative to the jump instruction
IFJUMP   # jump into the table just below
PUSH <destination 0 location>
IfJUMP
PUSH <destination 1 location>
IfJUMP
PUSH <destination 2 location>
IfJUMP
PUSH <destination 3 location>
IfJUMP
...
PUSH <destination N location>
IfJUMP



#### Interaction with OP_EXEC

Data executed by an OP_EXEC is isolated from the rest of the program.  OP_JUMP cannot jump outside of the bounds defined by this data.  Attempting to do so fails the script as specified in "Error conditions".


### Appendix 1 - Design rationale

It is generally assumed beneficial for blockchain scripting languages to be Turing incomplete, to preserve features like simultaneous evalution, out-of-block-processing evaluation, and "blind-signing" protection.  This idea is not strictly correct though.  The property we want to preserve is a script's Turing-incompleteness *with the blockchain ledger taking the role of the Turing tape (storage)*.  In other words, we want a program to be able to efficiently determine exactly which UTXOs will be destroyed and which will be created without running the scripts within the transaction.  Since there is no mechanism in Nexa's scripting language to make modifications to the blockchain ledger, it is irrelevant whether the execution of a script is Turing complete with its internal stack in the role of the "tape".

We realistically do not need to worry about long running scripts.  A single signature validation is on the order of 10^6 normal instructions.  The Nexa script machine already limits sigops and instructions, and aborts if the limits are exceeded.

So there is no need to construct a limited, Turing-incomplete looping mechanism.

Instead, it is desirable to implement a simple, succinct control flow that is similar to other assembly languages (for the purpose of leveraging existing compilation technologies).  And a rule of thumb, we want to trend towards "standard" ASM languages because they were designed to be easy to implement in hardware.

So a "goto" makes the most sense.

However, our if statements are currently scoped (they require if/endif pairs).  Jumping out of such a scope would be very awkward to write and generate code for, because you would have to cheat the scoping with extraneous endif statements.

For these reasons, it was decided to implement a conditional goto (IFJUMP) to a relative location retrieved from the top of the stack.

The precise format of this instruction has been optimized for short upwards jumps.  By choosing to subtract the argument from the current location, a short upward jump can be specified as a single byte constant.  A short downward jump can be specified as 2 bytes -- a single byte constant and OP_NEGATE.

Many assembly languages have both relative and absolute jumps.  But since, aside from OP_EXEC, the Nexa VM follows the "Harvard architecture" (data and code are separate), code cannot be dynamically moved or created.  Therefore locations of code are ALWAYS known at compile time.  This means that absolute jumps (to a "subroutine" for example) can be converted into *relative locations* at compile time by computing desired location - current code location.  And by having only relative jumps, the compiled code is inherently position-independent, which will be convenient if our compilers ever become sophisticated enough to have libraries linked into a single big script (recall that "dynamically-linked libraries" -- that is libraries located in read-only UTXOs -- are effectively in a different address space, accessed via OP_EXEC)

Zero or "false" values do not jump, they move to the next instruction.  This is slightly inconsistent with the behavior of the relative jump as it moves from positive to negative values.  However, I think that jumping to the same IFJUMP instruction will almost always be a bug (the only conceivable use would be to pop an unknown number of zero or false values from the stack).  Therefore, 0 IFJUMP (meaning do not jump), is equivalent to -1 IFJUMP (jump to the instruction after this one).


### Appendix 2 - Rationale to not use bch-loops

I examined the "Forth" style as proposed here: https://github.com/bitjson/bch-loops
In thinking and looking at how it would be implemented, I've realised that it needs a jump stack (of unspecified length).  Every time BEGIN is executed, the CPU pushes the current IP (instruction pointer) to this stack.  Then when UNTIL is executed it pops a value from the jump stack and if a condition evaluates to false, it jumps to the popped value.  The bch-loops spec proposes this structure because there is already an if/else stack.  But while there is conceptually an if/else stack there is no need for an ACTUAL stack.  Instead in Nexa it has been implemented as a counter of how "deep" you are.  We do not want to create a whole new jump stack if we can avoid it, especially since we are planning to implement this in hardware.

It certainly makes sense to have looping constructs at the language level, but why reflect that in the assembly code?  The bch-loops spec suggests that the reason is for covenants because "modeling execution" of a goto is more difficult without delving deeply into why.   Presumably this is the Turing-completeness problem affecting covenant enforcement code.  The covenant enforcement code in BCH needs to verify that the output script that coins are being sent to maintains certain constraints (the covenant).  But Nexa does not need to do that at the script analysis level due to Nexa's script templates.  Templates factor everything that changes based on the "holder's" requirements out of the template script, leaving JUST the covenant constraints.  This means that we can enforce the covenant by just comparing template script hashes, as is done automatically if the covenant bit is set in a group.  This is technique works better because for turing complete machines, one cannot write a program that determines whether another arbitrary program enforces some covenant constraints anyway, and even for non-turing complete programs, it can be very difficult (which is likely the inspiration behind this Forth-style loop construct).

But this means that the more functional the scripting language, the more difficult is to implement BCH style of covenant enforcement.

