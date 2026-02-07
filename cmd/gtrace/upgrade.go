package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/hervehildenbrand/gtrace/internal/update"
	"github.com/spf13/cobra"
)

// NewUpgradeCmd creates the `gtrace upgrade` subcommand.
func NewUpgradeCmd(currentVersion string) *cobra.Command {
	var force bool

	cmd := &cobra.Command{
		Use:   "upgrade",
		Short: "Upgrade gtrace to the latest version",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			fmt.Fprintln(cmd.OutOrStdout(), "Checking for updates...")

			checker := update.NewChecker()
			result := checker.Check(ctx, currentVersion)
			if result == nil {
				fmt.Fprintf(cmd.OutOrStdout(), "gtrace %s is already the latest version.\n", currentVersion)
				return nil
			}

			fmt.Fprintf(cmd.OutOrStdout(), "New version available: %s → %s\n", result.CurrentVersion, result.LatestVersion)

			if result.AssetURL == "" {
				fmt.Fprintf(cmd.OutOrStdout(), "No pre-built binary available for your platform.\nVisit %s to download manually.\n", result.ReleaseURL)
				return nil
			}

			if !force {
				fmt.Fprint(cmd.OutOrStdout(), "Upgrade? [y/N] ")
				reader := bufio.NewReader(cmd.InOrStdin())
				answer, _ := reader.ReadString('\n')
				answer = strings.TrimSpace(strings.ToLower(answer))
				if answer != "y" && answer != "yes" {
					fmt.Fprintln(cmd.OutOrStdout(), "Upgrade cancelled.")
					return nil
				}
			}

			binaryPath, err := os.Executable()
			if err != nil {
				return fmt.Errorf("cannot determine binary path: %w", err)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "Downloading %s...\n", result.AssetName)

			if err := update.SelfUpdate(ctx, result, binaryPath); err != nil {
				return fmt.Errorf("upgrade failed: %w", err)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "Successfully upgraded to gtrace %s\n", result.LatestVersion)
			return nil
		},
	}

	cmd.Flags().BoolVar(&force, "force", false, "Skip confirmation prompt")

	return cmd
}
