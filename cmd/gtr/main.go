package main

import (
	"fmt"
	"os"
)

// Version is set at build time.
var Version = "dev"

func main() {
	cmd := NewRootCmd()
	cmd.Version = Version

	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
