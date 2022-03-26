package def

import "errors"

type Symbol uint32

const (
	SymAdd Symbol = iota + 1
	SymPrint
	SymUnknown
)

type Adder interface {
	Add(right, left Object) (Object, error)
}

type Printer interface {
	Print(obj Object) error
}

type MethodDefinitions map[Symbol]any

var ErrUnknownMethod = errors.New("no such known method")

func methodDefinitions() map[ObjectType]MethodDefinitions {
	return map[ObjectType]MethodDefinitions{
		TypeInt: kIntMethods(),
		TypeStr: kStrMethods(),
	}
}

func LookupMethod(t ObjectType, name Symbol) (any, error) {
	methods := methodDefinitions()[t]
	method, ok := methods[name]
	if !ok {
		return nil, ErrUnknownMethod
	}

	return method, nil
}
