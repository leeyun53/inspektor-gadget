package main

import (
	api "github.com/inspektor-gadget/inspektor-gadget/wasmapi/go"
)

//export gadgetInit
func gadgetInit() int {
	api.Info("init: hello from wasm")
	return 0
}

//export gadgetStart
func gadgetStart() int {
	api.Info("start: hello from wasm")
	return 0
}

//export gadgetStop
func gadgetStop() int {
	api.Info("stop: hello from wasm")
	return 0
}

// The main function is not used, but it's still required by the compiler
func main() {}