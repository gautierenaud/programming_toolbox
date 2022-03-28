package def

import "fmt"

type Opcode uint32

const (
	// Load a value from the arguments array at index `arg'.
	ARG Opcode = iota + 1
	// Add stack[-2] + stack[-1].
	ADD
	// same as ADD, but specific to integer
	ADD_INT
	// same as ADD, but first tries to use cached value
	ADD_CACHED
	// Pop the top of the stack and print it.
	PRINT
	// Halt the machine.
	HALT
)

func OpToStr(op Opcode) string {
	return map[Opcode]string{
		ARG:        "arg",
		ADD:        "add",
		ADD_INT:    "add_int",
		ADD_CACHED: "add_cached",
		PRINT:      "print",
		HALT:       "halt",
	}[op]
}

// Example of opcode:
// 		byte bytecode[] = {	/*0:*/ ARG,   0,
// 							/*2:*/ ARG,   1,
// 							/*4:*/ ADD,   0,
// 							/*6:*/ PRINT, 0,
// 							/*8:*/ HALT,  0};
//
// This program takes its two arguments, adds them together, prints the result, and then halts the interpreter.

type CachedValue struct {
	Type  ObjectType
	Value any
}

type Code struct {
	// Array of `num_opcodes' (op, arg) pairs (total size `num_opcodes' * 2).
	Bytecode   []CodeChunk
	NumOpcodes uint32
	Caches     []*CachedValue
}

type CodeChunk struct {
	Op  Opcode
	Arg uint32
}

func (c CodeChunk) String() string {
	return fmt.Sprintf("{Op: %s, Arg: %d}", OpToStr(c.Op), c.Arg)
}
