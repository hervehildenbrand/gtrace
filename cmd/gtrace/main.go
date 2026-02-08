package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// Version is set at build time.
var Version = "dev"

// SetupCmd creates the root command with all subcommands registered.
func SetupCmd(version string) *cobra.Command {
	cmd := NewRootCmd(version)
	cmd.Version = version
	cmd.AddCommand(NewUpgradeCmd(version))
	return cmd
}

func main() {
	cmd := SetupCmd(Version)

	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
