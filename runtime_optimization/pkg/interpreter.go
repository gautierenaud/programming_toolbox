package pkg

import (
	"errors"

	log "github.com/sirupsen/logrus"

	"github.com/gautierenaud/programming_toolbox/rtopt/pkg/def"
)

type Word uint64

type Frame struct {
	StackArray []def.Object
	StackLen   uint64
	Stack      [][]def.Object
	Code       def.Code
	PC         Word
	Args       []def.Object
	NArgs      Word
}

func NewFrame(stackLen uint64, bytecode []byte, args []def.Object) Frame {
	return Frame{
		StackArray: make([]def.Object, 0, stackLen),
		StackLen:   stackLen,

		Code: def.Code{
			Bytecode:   bytecode,
			NumOpcodes: uint32(len(bytecode) / 2),
		},
		Args:  args,
		NArgs: Word(len(args)),
	}
}

func (f *Frame) push(val def.Object) error {
	if len(f.StackArray) == int(f.StackLen) {
		return errors.New("stack overflow")
	}

	f.StackArray = append(f.StackArray, val)

	log.Debugf("Add %+v to stack", val)

	return nil
}

func (f *Frame) pop() (def.Object, error) {
	n := len(f.StackArray)
	if n < 1 {
		return def.Object{}, errors.New("stack underflow")
	}

	var val def.Object
	f.StackArray, val = f.StackArray[:n-1], f.StackArray[n-1]

	return val, nil
}

func EvalCodeUncached(frame Frame) {
	code := frame.Code

	for frame.PC <= Word(frame.Code.NumOpcodes) {
		// instantiate log in loop since the frame will change
		log := log.WithField("frame", frame)

		op := def.Opcode(code.Bytecode[frame.PC])
		arg := code.Bytecode[frame.PC+1]

		switch op {
		case def.ARG:
			log.Debugf("Processing ARG with arg: %v", arg)

			if Word(arg) < frame.NArgs {
				err := frame.push(frame.Args[arg])
				if err != nil {
					log.Fatal("could not process ARG:", err)
				}
			}
		case def.ADD:
			log.Debugf("Processing ADD with arg: %v", arg)

			right, err := frame.pop()
			if err != nil {
				log.Fatalln("could not process ADD:", err)
			}

			left, err := frame.pop()
			if err != nil {
				log.WithError(err).Fatal("Could not pop left value")
			}

			method, err := def.LookupMethod(right.Type, def.SymAdd)
			if err != nil {
				log.WithError(err).
					WithField("type", right.Type).
					WithField("symbol", def.SymAdd).
					Fatalf("Could not retrieve appropriate method")
			}

			adder, ok := method.(def.Adder)
			if !ok {
				log.Fatal("Could not use method as an Adder")
			}

			result, err := adder.Add(right, left)
			if err != nil {
				log.WithError(err).
					Fatalf("Could not add %v and %v", right, left)
			}

			err = frame.push(result)
			if err != nil {
				log.WithError(err).
					Fatalf("Could not push %v to stask", result)
			}
		case def.PRINT:
			log.Debugf("Processing PRINT with arg: %v", arg)

			obj, err := frame.pop()
			if err != nil {
				log.Fatalln("Could not process PRINT:", err)
			}

			method, err := def.LookupMethod(obj.Type, def.SymPrint)
			if err != nil {
				log.WithError(err).
					WithField("type", obj.Type).
					WithField("symbol", def.SymPrint).
					Fatalf("Could not retrieve appropriate method")
			}

			printer, ok := method.(def.Printer)
			if !ok {
				log.Fatal("Could not use method as a Printer")
			}

			err = printer.Print(obj)
			if err != nil {
				log.WithError(err).
					Fatalf("Could not print %v", obj)
			}
		case def.HALT:
			return
		default:
			log.Fatalf("Unkown operation: %v", op)
		}

		frame.PC += 2
	}
}
