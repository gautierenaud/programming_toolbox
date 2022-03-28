package pkg

import (
	"fmt"

	log "github.com/sirupsen/logrus"

	"github.com/gautierenaud/programming_toolbox/rtopt/pkg/def"
)

type Frame struct {
	stack    []def.Object
	stackLen uint32
	code     def.Code
	pc       uint32
	args     []def.Object
	nArgs    uint32
}

func NewFrame(stackLen uint32, bytecode []def.CodeChunk, args []def.Object) Frame {
	return Frame{
		stack:    make([]def.Object, 0, stackLen),
		stackLen: stackLen,

		code: def.Code{
			Bytecode:   bytecode,
			NumOpcodes: uint32(len(bytecode)),
			Caches:     make([]*def.CachedValue, len(bytecode)),
		},
		args:  args,
		nArgs: uint32(len(args)),
	}
}

func (f *Frame) SetArgs(args []def.Object) {
	f.args = args
	f.nArgs = uint32(len(args))
}

func (f *Frame) push(val def.Object) {
	if len(f.stack) == int(f.stackLen) {
		log.Fatal("stack overflow")
	}

	f.stack = append(f.stack, val)

	log.Debugf("Add %+v to stack", val)
}

func (f *Frame) pop() def.Object {
	n := len(f.stack)
	if n < 1 {
		log.Fatal("stack underflow")
	}

	var val def.Object
	f.stack, val = f.stack[:n-1], f.stack[n-1]

	return val
}

func (f Frame) cachedAt() *def.CachedValue {
	return f.code.Caches[f.pc]
}

func (f *Frame) putCachedAt(val *def.CachedValue) {
	f.code.Caches[f.pc] = val
}

func (f Frame) String() string {
	return fmt.Sprintf("PC: %d, Args: %v, Current Code: %v, Cached: %v, Stack: %v", f.pc, f.args, f.code.Bytecode[f.pc], f.code.Caches, f.stack)
}
