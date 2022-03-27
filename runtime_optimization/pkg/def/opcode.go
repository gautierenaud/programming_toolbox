package def

import "fmt"

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

func opToStr(op Opcode) string {
	return map[Opcode]string{
		ARG:   "arg",
		ADD:   "add",
		PRINT: "print",
		HALT:  "halt",
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
	Arg int
}

func (c CodeChunk) String() string {
	return fmt.Sprintf("{Op: %s, Arg: %d}", opToStr(c.Op), c.Arg)
}
