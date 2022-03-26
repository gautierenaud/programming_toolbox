package def

import (
	"errors"
	"fmt"
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

	return Object{
		Type:  TypeInt,
		Value: intVal(right) + intVal(left),
	}, nil
}

type IntPrinter struct{}

func (_ IntPrinter) Print(obj Object) error {
	if !objectIsInt(obj) {
		return ErrObjectNotInt
	}

	fmt.Println(obj.Value)

	return nil
}

func objectIsInt(obj Object) bool {
	return obj.Type == TypeInt
}

func intVal(obj Object) int {
	o, _ := obj.Value.(int)
	return o
}
