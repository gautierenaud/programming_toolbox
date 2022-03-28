package pkg

import (
	"github.com/gautierenaud/programming_toolbox/rtopt/pkg/def"
	log "github.com/sirupsen/logrus"
)

func EvalCodeCached(frame *Frame) {
	frame.pc = 0
	code := frame.code

	for frame.pc < frame.code.NumOpcodes {
		// instantiate a log object in loop since the frame will change
		dbgLog := log.WithField("frame", frame)

		op := code.Bytecode[frame.pc].Op
		arg := code.Bytecode[frame.pc].Arg

		switch op {
		case def.ARG:
			dbgLog.Debugf("Processing ARG with arg: %v", arg)

			if arg >= frame.nArgs {
				log.Fatalf("Invalid arg index: %d", arg)
			}
			frame.push(frame.args[arg])
		case def.ADD:
			dbgLog.Debugf("Processing ADD with arg: %v", arg)

			right := frame.pop()
			left := frame.pop()

			cached := frame.cachedAt()
			if cached == nil || cached.Type != right.Type {
				log.WithField("cached", cached).Infof("Could not find cached value for type: %s", right.Type)

				method, err := def.LookupMethod(right.Type, def.SymAdd)
				if err != nil {
					dbgLog.WithError(err).
						WithField("type", right.Type).
						WithField("symbol", def.SymAdd).
						Fatalf("Could not retrieve appropriate method")
				}

				cached = &def.CachedValue{Type: right.Type, Value: method}
				frame.putCachedAt(cached)
			} else {
				log.WithField("cached", cached).Infof("Using cached method for type: %s", right.Type)
			}

			adder, ok := cached.Value.(def.Adder)
			if !ok {
				dbgLog.Fatal("Could not use method as an Adder")
			}

			result, err := adder.Add(right, left)
			if err != nil {
				dbgLog.WithError(err).
					Fatalf("Could not add %v and %v", right, left)
			}
			dbgLog.Debugf("Added: %v", result)

			frame.push(result)
		case def.PRINT:
			dbgLog.Debugf("Processing PRINT with arg: %v", arg)

			obj := frame.pop()

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
