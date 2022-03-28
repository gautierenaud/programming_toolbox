package pkg

import (
	"github.com/gautierenaud/programming_toolbox/rtopt/pkg/def"
	log "github.com/sirupsen/logrus"
)

func EvalCodeCachedQuick(frame *Frame) {
	frame.pc = 0
	code := frame.code

	for frame.pc < frame.code.NumOpcodes {
		op := code.Bytecode[frame.pc].Op
		arg := code.Bytecode[frame.pc].Arg

		// instantiate a log object in loop since the frame will change
		dbgLog := log.WithField("frame", frame)

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

			log.Infof("ADD: By default, there is no cache (type: %s)", right.Type)

			method, err := def.LookupMethod(right.Type, def.SymAdd)
			if err != nil {
				dbgLog.WithError(err).
					WithField("type", right.Type).
					WithField("symbol", def.SymAdd).
					Fatalf("Could not retrieve appropriate method")
			}

			frame.putCachedAt(&def.CachedValue{Type: right.Type, Value: method})

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

			frame.push(result)

			if right.Type == def.TypeInt {
				frame.code.Bytecode[frame.pc] = def.CodeChunk{Op: def.ADD_INT, Arg: arg}
			} else {
				frame.code.Bytecode[frame.pc] = def.CodeChunk{Op: def.ADD_CACHED, Arg: arg}
			}

			log.WithField("instruction", frame.code.Bytecode[frame.pc]).Infof("ADD: Bytecode have been replaced at PC: %d", frame.pc)
		case def.ADD_INT:
			dbgLog.Debugf("Processing ADD_INT with arg: %v", arg)

			right := frame.pop()
			left := frame.pop()

			if right.Type != def.TypeInt {
				log.Infof("ADD_INT: type %s not corresponding to int, looking for right method", right.Type)

				method, err := def.LookupMethod(right.Type, def.SymAdd)
				if err != nil {
					dbgLog.WithError(err).
						WithField("type", right.Type).
						WithField("symbol", def.SymAdd).
						Fatalf("Could not retrieve appropriate method")
				}

				frame.putCachedAt(&def.CachedValue{Type: right.Type, Value: method})

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

				frame.push(result)

				frame.code.Bytecode[frame.pc] = def.CodeChunk{Op: def.ADD_CACHED, Arg: arg}
				log.WithField("instruction", frame.code.Bytecode[frame.pc]).Infof("ADD_INT: Bytecode have been replaced at PC: %d", frame.pc)
				break
			}

			log.Info("ADD_INT: Using cached value")

			cached := frame.cachedAt() // no need to check type, since we know it must be for integer
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
		case def.ADD_CACHED:
			dbgLog.Debugf("Processing ADD_CACHED with arg: %v", arg)

			right := frame.pop()
			left := frame.pop()

			cached := frame.cachedAt()
			if cached.Type != right.Type {
				log.WithField("cached", cached).Infof("ADD_CACHED: Could not find cached value for type: %s", right.Type)

				method, err := def.LookupMethod(right.Type, def.SymAdd)
				if err != nil {
					dbgLog.WithError(err).
						WithField("type", right.Type).
						WithField("symbol", def.SymAdd).
						Fatalf("Could not retrieve appropriate method")
				}

				cached = &def.CachedValue{Type: right.Type, Value: method}
				frame.putCachedAt(cached)
			}

			log.Info("ADD_CACHED: Using cached value")

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
			dbgLog.Fatalf("Unkown operation: %s", def.OpToStr(op))
		}

		frame.pc += 1
	}
}
