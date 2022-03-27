package def

import (
	"errors"
	"fmt"
)

var ErrObjectNotStr = errors.New("Object is not a string type")

func kStrMethods() map[Symbol]any {
	return map[Symbol]any{
		SymAdd:     StrAdder{},
		SymPrint:   StrPrinter{},
		SymUnknown: nil,
	}
}

type StrAdder struct{}

func (_ StrAdder) Add(right, left Object) (Object, error) {
	if !objectIsStr(right) || !objectIsStr(left) {
		return Object{}, ErrObjectNotStr
	}

	return Object{Type: TypeStr, Value: strVal(right) + strVal(left)}, nil
}

func (_ StrAdder) String() string {
	return "StrAdder"
}

type StrPrinter struct{}

func (_ StrPrinter) Print(obj Object) error {
	if !objectIsStr(obj) {
		return ErrObjectNotStr
	}

	fmt.Println(strVal(obj))

	return nil
}

func (_ StrPrinter) String() string {
	return "StrPrinter"
}

func objectIsStr(obj Object) bool {
	return obj.Type == TypeStr
}

func strVal(obj Object) string {
	o, _ := obj.Value.(string)
	return o
}
