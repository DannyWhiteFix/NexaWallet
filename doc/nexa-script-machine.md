# Nexa Script Machine

## Resource Limits and Use Tracking

After fork 1, scripts may use a total of 1MB (1024*1024 bytes) stack memory.  They may use a total of 8*1024 individual stack elements.  The length of a stack element is no longer constrained (except it must be smaller than the total stack of course).  These two limits are assessed by summing max use in both the stack and altstack, including the current use of any parent scripts recursively (see `OP_EXEC`).

Stack elements are treated as if they contain no metadata.  That is, pushing 0x1234 onto the stack is counted as 2 bytes and 1 element.
Any bignums are treated as if they are stored in sign-magnitude format, regardless of actual internal format.  Round both sign and magnitude independently up to the nearest byte.  For example, the number 0 is charged 2 bytes to store, even though technically it only needs 1 bit.

Opcodes, unless otherwise noted, should be treated as if they first popped all arguments that get popped and then pushed all results.  In other words, use the most optimistic stack counting.  For example if `OP_CAT`, `OP_TOALTSTACK`, or `OP_FROMALTSTACK` is called, the max stack use is unchanged, *even if your internal implementation of FROMALTSTACK (say) actually first copies memory from the altstack buffer to the main stack buffer, and then removes it from the altstack buffer (resulting in a momentary, internal use of increased memory as that stack item is located in 2 places*.

Certain opcodes combine an operation and a verify, for example, CHECKSIGVERIFY.  Although these instructions are effectively a compound instruction, their stack use MUST NOT include the intermediate value that is then verified.

### `OP_EXEC`

`OP_EXEC` requires detailed instructions.  With respect to limits, executed subroutines should be offered a total stack space which is the current stack size limit minus the space currently used on the main and alt stacks, at the moment of launch (this is called the "parent's current use"), rather then the beginning of `OP_EXEC` execution.

In other words, pop all `OP_EXEC` arguments (including the code to be executed) off of the parent's stack before calculating the "parent's current use".  The code to be executed and the quantity of returned parameters
are therefore not "counted" as part of used space during the child's execution, and the parameters to the child are counted only once (since they are moved from the parent's stack to the childs).  Recursive `OP_EXEC`s are limited by all parents' current use.

After execution, the parent's maximum use MUST be updated with the parent's current use plus the child's max use, recursively.
