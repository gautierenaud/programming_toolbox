package def

type Opcode uint32

const (
	// Load a value from the arguments array at index `arg'.
	ARG Opcode = iota + 1
	// Add stack[-2] + stack[-1].
	ADD
	// Pop the top of the stack and print it.
	PRINT
	// Halt the machine.
	HALT
)

// Example of opcode:
// 		byte bytecode[] = {	/*0:*/ ARG,   0,
// 							/*2:*/ ARG,   1,
// 							/*4:*/ ADD,   0,
// 							/*6:*/ PRINT, 0,
// 							/*8:*/ HALT,  0};
//
// This program takes its two arguments, adds them together, prints the result, and then halts the interpreter.

type CachedValue struct {
	Key ObjectType
	// Value Method
}

type Code struct {
	// Array of `num_opcodes' (op, arg) pairs (total size `num_opcodes' * 2).
	Bytecode   []byte
	NumOpcodes uint32
	Caches     []CachedValue
}
