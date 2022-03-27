package def

import (
	"errors"
	"fmt"

	log "github.com/sirupsen/logrus"
)

var ErrObjectNotInt = errors.New("Object is not an integer type")

func kIntMethods() map[Symbol]any {
	return map[Symbol]any{
		SymAdd:     IntAdder{},
		SymPrint:   IntPrinter{},
		SymUnknown: nil,
	}
}

type IntAdder struct{}

func (_ IntAdder) Add(right, left Object) (Object, error) {
	if !objectIsInt(right) || !objectIsInt(left) {
		return Object{}, ErrObjectNotInt
	}

	log.Debugf("right val: %d, left val: %d", intVal(right), intVal(left))

	return Object{
		Type:  TypeInt,
		Value: intVal(right) + intVal(left),
	}, nil
}

func (_ IntAdder) String() string {
	return "IntAdder"
}

type IntPrinter struct{}

func (_ IntPrinter) Print(obj Object) error {
	if !objectIsInt(obj) {
		return ErrObjectNotInt
	}

	fmt.Println(obj.Value)

	return nil
}

func (_ IntPrinter) String() string {
	return "IntPrinter"
}

func objectIsInt(obj Object) bool {
	return obj.Type == TypeInt
}

func intVal(obj Object) int {
	o, _ := obj.Value.(int)
	return o
}
