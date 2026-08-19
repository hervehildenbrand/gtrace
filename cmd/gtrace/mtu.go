package main

import (
	"fmt"

	"github.com/hervehildenbrand/gtrace/internal/trace"
	"github.com/spf13/cobra"
)

// NewMTUCmd creates the mtu subcommand: a trace with active Path MTU
// Discovery forced on, using simple output.
func NewMTUCmd() *cobra.Command {
	var cfg Config

	cmd := &cobra.Command{
		Use:   "mtu <target>",
		Short: "Discover per-hop path MTU to a target",
		Long: `Trace the path to a target with active Path MTU Discovery:
probes carry the Don't Fragment bit and vary in size to find each hop's MTU,
including PMTUD black holes (hops that silently drop oversized packets).

Equivalent to: gtrace <target> --mtu --simple`,
		Args: cobra.ExactArgs(1),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if cfg.Protocol == "tcp" || !validProtocols[cfg.Protocol] {
				return fmt.Errorf("invalid protocol %q: mtu discovery supports icmp or udp", cfg.Protocol)
			}
			if cfg.DryRun {
				return nil
			}
			return trace.CheckPrivileges()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg.Target = args[0]
			cfg.Targets = args
			if cfg.DryRun {
				return nil
			}
			return runTrace(cmd, &cfg)
		},
	}

	cfg.DiscoverMTU = true
	cfg.Simple = true
	cfg.Packets = 3
	cfg.Port = 33434
	cfg.ProbeSize = 64

	cmd.Flags().StringVar(&cfg.Protocol, "protocol", "icmp", "Protocol: icmp|udp")
	cmd.Flags().IntVar(&cfg.MaxHops, "max-hops", 30, "Maximum hops")
	cmd.Flags().StringVar(&cfg.Timeout, "timeout", "500ms", "Per-hop timeout")
	cmd.Flags().StringVarP(&cfg.Output, "output", "o", "", "Export to file (json/csv/txt)")
	cmd.Flags().BoolVar(&cfg.Offline, "offline", false, "Disable online enrichment lookups")
	cmd.Flags().BoolVar(&cfg.NoColor, "no-color", false, "Disable colors")
	cmd.Flags().BoolVar(&cfg.DryRun, "dry-run", false, "Validate arguments without tracing")
	_ = cmd.Flags().MarkHidden("dry-run")

	return cmd
}
