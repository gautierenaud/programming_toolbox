package def

type ObjectType uint32

const (
	TypeInt ObjectType = iota + 1
	TypeStr
)

type Object struct {
	Type  ObjectType
	Value any
}
