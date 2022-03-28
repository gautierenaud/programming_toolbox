package main

import (
	"flag"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/gautierenaud/programming_toolbox/rtopt/pkg"
	"github.com/gautierenaud/programming_toolbox/rtopt/pkg/def"
)

func main() {
	logLevel := flag.String("log", "warn", "Set level of log. Possible values: debug, info, warn and fatal")
	runtime := flag.String("runtime", "cached", "Select which runtime to use: cached, quickCached")
	flag.Parse()

	setLogLevel(*logLevel)

	var eval func(frame *pkg.Frame)
	switch *runtime {
	case "cached":
		eval = pkg.EvalCodeCached
	case "quickCached":
		eval = pkg.EvalCodeCachedQuick
	default:
		log.Infof("Could not find runtime for: %s, using \"cached\" as default", *runtime)
		eval = pkg.EvalCodeCached
	}

	// basic code that will add 2 arguments and print it
	bytecode := []def.CodeChunk{
		{Op: def.ARG, Arg: 0},
		{Op: def.ARG, Arg: 1},
		{Op: def.ADD, Arg: 0},
		{Op: def.PRINT, Arg: 0},
		{Op: def.HALT, Arg: 0},
	}

	// first case where each arg is an int
	args := []def.Object{
		{Type: def.TypeInt, Value: 42},
		{Type: def.TypeInt, Value: 42},
	}

	frame := pkg.NewFrame(10, bytecode, args)
	eval(&frame) // Should look for method
	eval(&frame) // Should use cached method

	// second case where each arg is a string
	frame.SetArgs([]def.Object{
		{Type: def.TypeStr, Value: "42"},
		{Type: def.TypeStr, Value: "42"},
	})
	eval(&frame) // Should look for method (entry in cache but with wrong type)
	eval(&frame) // Should use cached method
}

func setLogLevel(level string) {
	switch strings.ToLower(level) {
	case "debug":
		log.SetLevel(log.DebugLevel)
	case "info":
		log.SetLevel(log.InfoLevel)
	case "warn":
		log.SetLevel(log.WarnLevel)
	case "fatal":
		log.SetLevel(log.FatalLevel)
	default:
		log.SetLevel(log.WarnLevel)
	}
}
