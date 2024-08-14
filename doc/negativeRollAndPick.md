# Negative OP_ROLL and OP_PICK

There is a need to insert items into the middle of the stack (as opposed to overwriting the item via OP_PLACE).  It was observed that OP_ROLL can be thought of as rotating a number of stack items.  Insertion is effectively rotation in the opposite direction.  Capturing this opposite direction idea with negative numbers efficiently uses the available operation space.

## Original Definition

OP_ROLL and OP_PICK were previously defined as follows:

| Word            | Value | Hex  | Input               | Output                 | Description                           |
| --------------- | ----- | ---- | ------------------- | ---------------------- | ------------------------------------- |
| OP_PICK         | 121   | 0x79 | xn ... x2 x1 x0 n | xn ... x2 x1 x0 xn     | The item *n* back in the stack is copied to the top. |
| OP_ROLL         | 122   | 0x7a | xn ... x2 x1 x0 n | x(n-1) ... x2 x1 x0 xn | The item *n* back in the stack is moved to the top. |

n was limited to 0 or positive numbers.

## New Definition


| Word            | Value | Hex  | Input               | Output                 | Description                           |
| --------------- | ----- | ---- | ------------------- | ---------------------- | ------------------------------------- |
| OP_PICK         | 121   | 0x79 | xn ... x2 x1 x0 n | xn ... x2 x1 x0 xn     | *n* is popped. If *n* is positive, the item *n* back in the stack is copied to the top.  If *n* is negative, the top item is inserted to the position *n* back in the stack.  |
| OP_ROLL         | 122   | 0x7a | xn ... x2 x1 x0 n | x(n-1) ... x2 x1 x0 xn | *n* is popped. If *n* is positive, the item *n* back in the stack is moved to the top.  If *n* is negative, the top item is moved to the position *n* back in the stack.  Note that since the top item is itself *on the stack* -1 OP_ROLL is a no-op  |

### Examples to clarify behavior

* Moving/copying to last index for both OP_ROLL and OP_PICK would be OP_DEPTH OP_NEGATE OP_ROLL.
* x -1 OP_PICK is equivalent to x OP_DUP.  It produces a stack of x x.


