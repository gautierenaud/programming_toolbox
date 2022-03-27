package def

import "fmt"

type ObjectType uint32

const (
	TypeInt ObjectType = iota + 1
	TypeStr
)

func (o ObjectType) String() string {
	return map[ObjectType]string{
		TypeInt: "int",
		TypeStr: "string",
	}[o]
}

type Object struct {
	Type  ObjectType
	Value any
}

func (o Object) String() string {
	return fmt.Sprintf("{type: %s, value: %v}", o.Type, o.Value)
}
