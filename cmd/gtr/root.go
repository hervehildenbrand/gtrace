package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/hervehildenbrand/gtr/internal/display"
	"github.com/hervehildenbrand/gtr/internal/trace"
	"github.com/hervehildenbrand/gtr/pkg/hop"
	"github.com/spf13/cobra"
)

// Config holds the parsed CLI configuration.
type Config struct {
	Target   string
	From     string
	Protocol string
	Port     int
	MaxHops  int
	Packets  int
	Timeout  string
	Compare  bool
	View     string
	Monitor  bool
	AlertLatency string
	AlertLoss    string
	Simple   bool
	NoColor  bool
	Output   string
	Format   string
	APIKey   string
	Offline  bool
	Verbose  bool
	DryRun   bool
}

var validProtocols = map[string]bool{
	"icmp": true,
	"udp":  true,
	"tcp":  true,
}

// NewRootCmd creates and returns the root cobra command.
func NewRootCmd() *cobra.Command {
	var cfg Config

	cmd := &cobra.Command{
		Use:   "gtr <target>",
		Short: "GlobalPing Traceroute CLI",
		Long: `gtr combines local traceroute with GlobalPing's global probe network,
featuring advanced diagnostics (MPLS, ECMP, MTU, NAT detection),
rich hop enrichment, and real-time TUI.`,
		Args: cobra.ExactArgs(1),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			// Validate protocol
			if !validProtocols[cfg.Protocol] {
				return fmt.Errorf("invalid protocol %q: must be icmp, udp, or tcp", cfg.Protocol)
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg.Target = args[0]

			if cfg.DryRun {
				// Just validate args and return
				return nil
			}

			return runTrace(cmd, &cfg)
		},
	}

	// Source location flags
	cmd.Flags().StringVar(&cfg.From, "from", "", "Run from GlobalPing location(s)")
	cmd.Flags().BoolVar(&cfg.Compare, "compare", false, "Compare local + remote traces")
	cmd.Flags().StringVar(&cfg.View, "view", "side", "Display mode: side|tabs|unified")

	// Protocol flags
	cmd.Flags().StringVar(&cfg.Protocol, "protocol", "icmp", "Protocol: icmp|udp|tcp")
	cmd.Flags().IntVar(&cfg.Port, "port", 33434, "Port for TCP/UDP")
	cmd.Flags().IntVar(&cfg.MaxHops, "max-hops", 30, "Maximum hops")
	cmd.Flags().IntVar(&cfg.Packets, "packets", 3, "Packets per hop")
	cmd.Flags().StringVar(&cfg.Timeout, "timeout", "3s", "Per-hop timeout")

	// Monitoring flags
	cmd.Flags().BoolVar(&cfg.Monitor, "monitor", false, "Continuous monitoring mode")
	cmd.Flags().StringVar(&cfg.AlertLatency, "alert-latency", "", "Alert on latency threshold (e.g., 100ms)")
	cmd.Flags().StringVar(&cfg.AlertLoss, "alert-loss", "", "Alert on packet loss threshold (e.g., 5%)")

	// Display flags
	cmd.Flags().BoolVar(&cfg.Simple, "simple", false, "Simple output (no TUI)")
	cmd.Flags().BoolVar(&cfg.NoColor, "no-color", false, "Disable colors")

	// Export flags
	cmd.Flags().StringVarP(&cfg.Output, "output", "o", "", "Export to file (json/csv/txt)")
	cmd.Flags().StringVar(&cfg.Format, "format", "", "Explicit export format")

	// Other flags
	cmd.Flags().StringVar(&cfg.APIKey, "api-key", "", "GlobalPing API key")
	cmd.Flags().BoolVar(&cfg.Offline, "offline", false, "Use only local enrichment DBs")
	cmd.Flags().BoolVarP(&cfg.Verbose, "verbose", "v", false, "Verbose output")
	cmd.Flags().BoolVar(&cfg.DryRun, "dry-run", false, "Validate args without running trace")

	return cmd
}

// runTrace executes the traceroute based on configuration.
func runTrace(cmd *cobra.Command, cfg *Config) error {
	// Parse timeout
	timeout, err := time.ParseDuration(cfg.Timeout)
	if err != nil {
		return fmt.Errorf("invalid timeout: %w", err)
	}

	// Resolve target
	targetIP, err := trace.ResolveTarget(cfg.Target)
	if err != nil {
		return fmt.Errorf("failed to resolve target: %w", err)
	}

	// Create trace config
	traceCfg := &trace.Config{
		Protocol:      trace.Protocol(cfg.Protocol),
		MaxHops:       cfg.MaxHops,
		PacketsPerHop: cfg.Packets,
		Timeout:       timeout,
		Port:          cfg.Port,
	}

	// Create tracer
	tracer, err := trace.NewLocalTracer(traceCfg)
	if err != nil {
		return fmt.Errorf("failed to create tracer: %w", err)
	}

	// Set up context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	// Create renderer
	renderer := display.NewSimpleRenderer()

	// Print header
	fmt.Fprintf(cmd.OutOrStdout(), "traceroute to %s (%s), %d hops max, %s protocol\n",
		cfg.Target, targetIP, cfg.MaxHops, cfg.Protocol)

	// Run trace with real-time output
	callback := func(h *hop.Hop) {
		fmt.Fprintln(cmd.OutOrStdout(), renderer.RenderHop(h))
	}

	result, err := tracer.Trace(ctx, targetIP, callback)
	if err != nil {
		if ctx.Err() != nil {
			fmt.Fprintln(cmd.OutOrStdout(), "\nTrace interrupted")
			return nil
		}
		return fmt.Errorf("trace failed: %w", err)
	}

	// Print summary
	if result.ReachedTarget {
		fmt.Fprintf(cmd.OutOrStdout(), "\nTrace complete: reached %s in %d hops\n",
			cfg.Target, result.TotalHops())
	} else {
		fmt.Fprintf(cmd.OutOrStdout(), "\nTrace complete: %d hops (target not reached)\n",
			result.TotalHops())
	}

	return nil
}
