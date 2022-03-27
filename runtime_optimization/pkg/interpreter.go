package pkg

import (
	"errors"
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

func EvalCodeUncached(frame *Frame) {
	frame.pc = 0
	code := frame.code

	for frame.pc < frame.code.NumOpcodes {
		// instantiate a log object in loop since the frame will change
		dbgLog := log.WithField("frame", frame)

		op := code.Bytecode[frame.pc].Op
		arg := uint32(code.Bytecode[frame.pc].Arg)

		switch op {
		case def.ARG:
			dbgLog.Debugf("Processing ARG with arg: %v", arg)

			if arg < frame.nArgs {
				err := frame.push(frame.args[arg])
				if err != nil {
					dbgLog.Fatal("could not process ARG:", err)
				}
			}
		case def.ADD:
			dbgLog.Debugf("Processing ADD with arg: %v", arg)

			right, err := frame.pop()
			if err != nil {
				dbgLog.Fatalln("could not process ADD:", err)
			}

			left, err := frame.pop()
			if err != nil {
				dbgLog.WithError(err).Fatal("Could not pop left value")
			}

			var method any
			cached := frame.cachedAt()
			if cached == nil || cached.Type != right.Type {
				log.WithField("cached", cached).Infof("Could not find cached value for type: %s", right.Type)

				method, err = def.LookupMethod(right.Type, def.SymAdd)
				if err != nil {
					dbgLog.WithError(err).
						WithField("type", right.Type).
						WithField("symbol", def.SymAdd).
						Fatalf("Could not retrieve appropriate method")
				}

				frame.putCachedAt(def.CachedValue{Type: right.Type, Value: method})
			} else {
				log.WithField("cached", cached).Infof("Using cached method for type: %s", right.Type)

				method = cached.Value
			}

			adder, ok := method.(def.Adder)
			if !ok {
				dbgLog.Fatal("Could not use method as an Adder")
			}

			result, err := adder.Add(right, left)
			if err != nil {
				dbgLog.WithError(err).
					Fatalf("Could not add %v and %v", right, left)
			}
			dbgLog.Debugf("Added: %v", result)

			err = frame.push(result)
			if err != nil {
				dbgLog.WithError(err).
					Fatalf("Could not push %v to stask", result)
			}
		case def.PRINT:
			dbgLog.Debugf("Processing PRINT with arg: %v", arg)

			obj, err := frame.pop()
			if err != nil {
				dbgLog.Fatalln("Could not process PRINT:", err)
			}

			method, err := def.LookupMethod(obj.Type, def.SymPrint)
			if err != nil {
				dbgLog.WithError(err).
					WithField("type", obj.Type).
					WithField("symbol", def.SymPrint).
					Fatalf("Could not retrieve appropriate method")
			}

			printer, ok := method.(def.Printer)
			if !ok {
				dbgLog.Fatal("Could not use method as a Printer")
			}

			err = printer.Print(obj)
			if err != nil {
				dbgLog.WithError(err).
					Fatalf("Could not print %v", obj)
			}
		case def.HALT:
			dbgLog.Debugf("HALTing with arg: %v", arg)
			return
		default:
			dbgLog.Fatalf("Unkown operation: %v", op)
		}

		frame.pc += 1
	}
}

func (f *Frame) push(val def.Object) error {
	if len(f.stack) == int(f.stackLen) {
		return errors.New("stack overflow")
	}

	f.stack = append(f.stack, val)

	log.Debugf("Add %+v to stack", val)

	return nil
}

func (f *Frame) pop() (def.Object, error) {
	n := len(f.stack)
	if n < 1 {
		return def.Object{}, errors.New("stack underflow")
	}

	var val def.Object
	f.stack, val = f.stack[:n-1], f.stack[n-1]

	return val, nil
}

func (f Frame) cachedAt() *def.CachedValue {
	return f.code.Caches[f.pc]
}

func (f *Frame) putCachedAt(val def.CachedValue) {
	f.code.Caches[f.pc] = &val

	log.WithField("cached", f.code.Caches[f.pc]).Infof("%v cached at PC: %d", val.Value, f.pc)
}

func (f Frame) String() string {
	return fmt.Sprintf("PC: %d, Args: %v, Current Code: %v, Cached: %v, Stack: %v", f.pc, f.args, f.code.Bytecode[f.pc], f.code.Caches, f.stack)
}
