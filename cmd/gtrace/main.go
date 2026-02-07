package main

import (
	"fmt"
	"os"
)

// Version is set at build time.
var Version = "dev"

func main() {
	cmd := NewRootCmd(Version)
	cmd.Version = Version

	if Version != "dev" {
		cmd.AddCommand(NewUpgradeCmd(Version))
	}

	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
