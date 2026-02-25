package main

import (
	"os"

	"github.com/dominikschlosser/ssi-debugger/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
