package main

import (
	log "github.com/sirupsen/logrus"

	"github.com/gautierenaud/programming_toolbox/rtopt/pkg"
	"github.com/gautierenaud/programming_toolbox/rtopt/pkg/def"
)

func main() {
	log.SetLevel(log.DebugLevel)

	bytecode := []byte{
		byte(def.ARG), 0,
		byte(def.PRINT), 0,
	}
	args := []def.Object{{Type: def.TypeStr, Value: "42"}}
	frame := pkg.NewFrame(10, bytecode, args)

	pkg.EvalCodeUncached(frame)
}
