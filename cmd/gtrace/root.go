package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hervehildenbrand/gtrace/internal/display"
	"github.com/hervehildenbrand/gtrace/internal/enrich"
	"github.com/hervehildenbrand/gtrace/internal/export"
	"github.com/hervehildenbrand/gtrace/internal/globalping"
	"github.com/hervehildenbrand/gtrace/internal/monitor"
	"github.com/hervehildenbrand/gtrace/internal/trace"
	"github.com/hervehildenbrand/gtrace/pkg/hop"
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
	Interval string // MTR mode: interval between trace cycles
	Cycles   int    // MTR mode: number of cycles (0 = infinite)
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
	DownloadDB bool
	DBStatus   bool
	IPv4Only bool // Force IPv4 only
	IPv6Only bool // Force IPv6 only
}

var validProtocols = map[string]bool{
	"icmp": true,
	"udp":  true,
	"tcp":  true,
}

// getAddressFamily returns the AddressFamily based on config flags.
func getAddressFamily(cfg *Config) trace.AddressFamily {
	if cfg.IPv4Only {
		return trace.AddressFamilyIPv4
	}
	if cfg.IPv6Only {
		return trace.AddressFamilyIPv6
	}
	return trace.AddressFamilyAuto
}

// NewRootCmd creates and returns the root cobra command.
func NewRootCmd() *cobra.Command {
	var cfg Config

	cmd := &cobra.Command{
		Use:   "gtrace <target>",
		Short: "Advanced network path analysis tool",
		Long: `gtrace combines local traceroute with GlobalPing's distributed probe network,
featuring advanced diagnostics (MPLS, ECMP, MTU, NAT detection),
rich hop enrichment (ASN, geo, hostnames), and real-time MTR-style TUI.`,
		Args: cobra.MaximumNArgs(1),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			// Skip validation for special commands
			if cfg.DBStatus || cfg.DownloadDB {
				return nil
			}

			// Require target for normal operation
			if len(args) == 0 {
				return fmt.Errorf("requires a target argument")
			}

			// Validate protocol
			if !validProtocols[cfg.Protocol] {
				return fmt.Errorf("invalid protocol %q: must be icmp, udp, or tcp", cfg.Protocol)
			}

			// --compare requires --from
			if cfg.Compare && cfg.From == "" {
				return fmt.Errorf("--compare requires --from to specify remote location")
			}

			// -4 and -6 are mutually exclusive
			if cfg.IPv4Only && cfg.IPv6Only {
				return fmt.Errorf("-4/--ipv4 and -6/--ipv6 are mutually exclusive")
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			// Handle --db-status
			if cfg.DBStatus {
				fmt.Fprint(cmd.OutOrStdout(), enrich.PrintDBStatus())
				return nil
			}

			// Handle --download-db
			if cfg.DownloadDB {
				fmt.Fprintln(cmd.OutOrStdout(), "Database Download")
				fmt.Fprintln(cmd.OutOrStdout(), "")
				fmt.Fprintln(cmd.OutOrStdout(), "MaxMind GeoLite2 databases require a free license key.")
				fmt.Fprintln(cmd.OutOrStdout(), "")
				fmt.Fprintln(cmd.OutOrStdout(), "To set up GeoIP databases:")
				fmt.Fprintln(cmd.OutOrStdout(), "  1. Register at https://www.maxmind.com/en/geolite2/signup")
				fmt.Fprintln(cmd.OutOrStdout(), "  2. Download GeoLite2-City.mmdb from your account")
				fmt.Fprintln(cmd.OutOrStdout(), "  3. Place it at: "+enrich.DefaultGeoDBPath())
				fmt.Fprintln(cmd.OutOrStdout(), "")
				fmt.Fprintln(cmd.OutOrStdout(), "Current status:")
				fmt.Fprint(cmd.OutOrStdout(), enrich.PrintDBStatus())
				return nil
			}

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
	cmd.Flags().StringVar(&cfg.Timeout, "timeout", "500ms", "Per-hop timeout (MTR default: 500ms)")

	// MTR mode flags
	cmd.Flags().StringVar(&cfg.Interval, "interval", "1s", "Interval between trace cycles (MTR mode)")
	cmd.Flags().IntVar(&cfg.Cycles, "cycles", 0, "Number of cycles (0 = infinite, MTR mode)")

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

	// Database management flags
	cmd.Flags().BoolVar(&cfg.DownloadDB, "download-db", false, "Show instructions to download GeoIP databases")
	cmd.Flags().BoolVar(&cfg.DBStatus, "db-status", false, "Show GeoIP database status")

	// IP version flags
	cmd.Flags().BoolVarP(&cfg.IPv4Only, "ipv4", "4", false, "Use IPv4 only")
	cmd.Flags().BoolVarP(&cfg.IPv6Only, "ipv6", "6", false, "Use IPv6 only")

	return cmd
}

// newGlobalPingClient creates a GlobalPing client with retry notification.
func newGlobalPingClient(w io.Writer, apiKey string) *globalping.Client {
	client := globalping.NewClient(apiKey)
	client.SetRetryCallback(func(attempt int, delay time.Duration) {
		fmt.Fprintf(w, "Rate limited by GlobalPing API. Retrying in %v (attempt %d/3)...\n", delay, attempt)
	})
	return client
}

// runTrace executes the traceroute based on configuration.
func runTrace(cmd *cobra.Command, cfg *Config) error {
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

	// Use monitoring mode if --monitor is set
	if cfg.Monitor {
		err := runMonitor(ctx, cmd, cfg)
		if err != nil && ctx.Err() != nil {
			fmt.Fprintln(cmd.OutOrStdout(), "\nMonitoring stopped")
			return nil
		}
		return err
	}

	// Compare mode: run local and remote traces concurrently
	if cfg.Compare && cfg.From != "" {
		return runCompareMode(ctx, cmd, cfg)
	}

	var result *hop.TraceResult
	var err error

	// Use GlobalPing if --from is specified
	if cfg.From != "" {
		result, err = runGlobalPingTrace(ctx, cmd, cfg)
	} else {
		result, err = runLocalTrace(ctx, cmd, cfg)
	}

	if err != nil {
		if ctx.Err() != nil {
			fmt.Fprintln(cmd.OutOrStdout(), "\nTrace interrupted")
			return nil
		}
		return err
	}

	// Export if output file specified
	if cfg.Output != "" {
		format := export.Format(cfg.Format)
		if err := export.ExportToFile(cfg.Output, format, result); err != nil {
			return fmt.Errorf("failed to export: %w", err)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Results exported to %s\n", cfg.Output)
	}

	return nil
}

// runLocalTrace runs a local traceroute.
func runLocalTrace(ctx context.Context, cmd *cobra.Command, cfg *Config) (*hop.TraceResult, error) {
	// Parse timeout
	timeout, err := time.ParseDuration(cfg.Timeout)
	if err != nil {
		return nil, fmt.Errorf("invalid timeout: %w", err)
	}

	// Resolve target
	targetIP, err := trace.ResolveTarget(cfg.Target, getAddressFamily(cfg))
	if err != nil {
		return nil, fmt.Errorf("failed to resolve target: %w", err)
	}

	// Create enricher (unless offline mode)
	var enricher *enrich.Enricher
	if !cfg.Offline {
		enricher = enrich.NewEnricher()
	}

	// Use single-shot mode for --simple or when exporting
	if cfg.Simple || cfg.Output != "" {
		// Create trace config for single-shot mode
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
			return nil, fmt.Errorf("failed to create tracer: %w", err)
		}

		return runLocalTraceSimple(ctx, cmd, cfg, tracer, enricher, targetIP)
	}

	// MTR mode is the default for TUI
	return runLocalTraceMTR(ctx, cmd, cfg, enricher, targetIP, timeout)
}

// runLocalTraceMTR runs a continuous MTR-style trace with the TUI.
func runLocalTraceMTR(ctx context.Context, cmd *cobra.Command, cfg *Config, enricher *enrich.Enricher, targetIP net.IP, timeout time.Duration) (*hop.TraceResult, error) {
	// Parse interval
	interval, err := time.ParseDuration(cfg.Interval)
	if err != nil {
		return nil, fmt.Errorf("invalid interval: %w", err)
	}

	// Create trace config for MTR mode (1 packet per hop for faster cycles)
	traceCfg := &trace.Config{
		Protocol:      trace.Protocol(cfg.Protocol),
		MaxHops:       cfg.MaxHops,
		PacketsPerHop: 1, // MTR-style: 1 probe per hop per cycle
		Timeout:       timeout,
		Port:          cfg.Port,
	}

	// Create tracer
	tracer, err := trace.NewLocalTracer(traceCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create tracer: %w", err)
	}

	// Create continuous tracer
	ct := trace.NewContinuousTracer(traceCfg, tracer, interval)

	// Create channels for TUI communication
	resultChan := make(chan display.ProbeResultMsg, 100)
	cycleChan := make(chan display.CycleCompleteMsg, 10)
	doneChan := make(chan struct{})

	// Track enriched IPs to avoid re-enriching
	enrichedIPs := make(map[string]bool)
	var enrichMu sync.Mutex

	// Run continuous tracer in background
	go func() {
		defer close(resultChan)
		defer close(cycleChan)

		probeCallback := func(pr trace.ProbeResult) {
			msg := display.ProbeResultMsg{
				TTL:     pr.TTL,
				IP:      pr.IP,
				RTT:     pr.RTT,
				Timeout: pr.Timeout,
				MPLS:    pr.MPLS,
			}

			// Enrich first occurrence of each IP
			if pr.IP != nil && enricher != nil {
				ipStr := pr.IP.String()
				enrichMu.Lock()
				needsEnrich := !enrichedIPs[ipStr]
				if needsEnrich {
					enrichedIPs[ipStr] = true
				}
				enrichMu.Unlock()

				if needsEnrich {
					// Create a temporary hop to get enrichment
					h := hop.NewHop(pr.TTL)
					h.AddProbe(pr.IP, pr.RTT)
					enricher.EnrichHop(ctx, h)
					msg.Enrichment = h.Enrichment
				}
			}

			select {
			case resultChan <- msg:
			case <-ctx.Done():
			}
		}

		cycleCallback := func(cycle int, reached bool) {
			select {
			case cycleChan <- display.CycleCompleteMsg{Cycle: cycle, Reached: reached}:
			case <-ctx.Done():
			}

			// Check if we've reached the cycle limit
			if cfg.Cycles > 0 && cycle >= cfg.Cycles {
				// Signal done via context cancellation
				return
			}
		}

		ct.Run(ctx, targetIP, probeCallback, cycleCallback)
	}()

	// Run MTR TUI (blocks until user quits)
	if err := display.RunMTR(cfg.Target, targetIP.String(), resultChan, cycleChan, doneChan); err != nil {
		return nil, fmt.Errorf("TUI error: %w", err)
	}

	// Return nil result for MTR mode (no single trace result)
	return nil, nil
}

// runLocalTraceWithTUI runs a trace with the interactive TUI display (legacy single-shot).
func runLocalTraceWithTUI(ctx context.Context, cmd *cobra.Command, cfg *Config, tracer trace.Tracer, enricher *enrich.Enricher, targetIP net.IP) (*hop.TraceResult, error) {
	hopChan := make(chan *hop.Hop, 100)
	doneChan := make(chan bool, 1)

	// Run trace in background
	var result *hop.TraceResult
	var traceErr error

	go func() {
		defer close(hopChan)

		callback := func(h *hop.Hop) {
			// Enrich the hop before sending to TUI
			if enricher != nil {
				enricher.EnrichHop(ctx, h)
			}
			hopChan <- h
		}

		result, traceErr = tracer.Trace(ctx, targetIP, callback)

		if result != nil {
			doneChan <- result.ReachedTarget
		} else {
			doneChan <- false
		}
		close(doneChan)
	}()

	// Run TUI (blocks until user quits)
	if err := display.RunTUI(cfg.Target, targetIP.String(), hopChan, doneChan); err != nil {
		return nil, fmt.Errorf("TUI error: %w", err)
	}

	if traceErr != nil {
		return nil, fmt.Errorf("trace failed: %w", traceErr)
	}

	return result, nil
}

// runLocalTraceSimple runs a trace with simple text output.
func runLocalTraceSimple(ctx context.Context, cmd *cobra.Command, cfg *Config, tracer trace.Tracer, enricher *enrich.Enricher, targetIP net.IP) (*hop.TraceResult, error) {
	// Create renderer
	renderer := display.NewSimpleRenderer()

	// Print header
	fmt.Fprintf(cmd.OutOrStdout(), "traceroute to %s (%s), %d hops max, %s protocol\n",
		cfg.Target, targetIP, cfg.MaxHops, cfg.Protocol)

	// Run trace with real-time output
	callback := func(h *hop.Hop) {
		// Enrich the hop before displaying
		if enricher != nil {
			enricher.EnrichHop(ctx, h)
		}
		fmt.Fprintln(cmd.OutOrStdout(), renderer.RenderHop(h))
	}

	result, err := tracer.Trace(ctx, targetIP, callback)
	if err != nil {
		return nil, fmt.Errorf("trace failed: %w", err)
	}

	// Print summary
	if result.ReachedTarget {
		fmt.Fprintf(cmd.OutOrStdout(), "\nTrace complete: reached %s in %d hops\n",
			cfg.Target, result.TotalHops())
	} else {
		fmt.Fprintf(cmd.OutOrStdout(), "\nTrace complete: %d hops (target not reached)\n",
			result.TotalHops())
	}

	return result, nil
}

// runGlobalPingTrace runs a traceroute via GlobalPing API.
// Uses MTR when not in simple mode for richer statistics.
func runGlobalPingTrace(ctx context.Context, cmd *cobra.Command, cfg *Config) (*hop.TraceResult, error) {
	// Use MTR for richer output when not in simple mode
	if !cfg.Simple {
		return runGlobalPingMTR(ctx, cmd, cfg)
	}

	return runGlobalPingTraceroute(ctx, cmd, cfg)
}

// runGlobalPingTraceroute runs a simple traceroute via GlobalPing API.
func runGlobalPingTraceroute(ctx context.Context, cmd *cobra.Command, cfg *Config) (*hop.TraceResult, error) {
	// Create client with retry notification
	client := newGlobalPingClient(cmd.OutOrStdout(), cfg.APIKey)

	// Parse locations
	locations := globalping.ParseLocationStrings(cfg.From)

	// Create measurement request
	req := &globalping.MeasurementRequest{
		Type:      globalping.MeasurementTypeTraceroute,
		Target:    cfg.Target,
		Locations: locations,
		Options: globalping.MeasurementOptions{
			Protocol: strings.ToUpper(cfg.Protocol),
		},
		InProgressUpdates: true,
	}

	fmt.Fprintf(cmd.OutOrStdout(), "traceroute to %s from %s via GlobalPing\n",
		cfg.Target, cfg.From)
	fmt.Fprintln(cmd.OutOrStdout(), "Creating measurement...")

	// Create measurement
	resp, err := client.CreateMeasurement(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to create measurement: %w", err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Measurement ID: %s (%d probes)\n", resp.ID, resp.ProbesCount)
	fmt.Fprintln(cmd.OutOrStdout(), "Waiting for results...")

	// Wait for completion
	measurement, err := client.WaitForMeasurement(ctx, resp.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get results: %w", err)
	}

	// Create renderer
	renderer := display.NewSimpleRenderer()

	// Display results from each probe
	var lastResult *hop.TraceResult
	for _, pr := range measurement.Results {
		result := pr.ToTraceResult(cfg.Target)
		lastResult = result

		fmt.Fprintf(cmd.OutOrStdout(), "\n=== From %s ===\n", result.Source)
		fmt.Fprintf(cmd.OutOrStdout(), "Target: %s (%s)\n\n", cfg.Target, result.TargetIP)

		for _, h := range result.Hops {
			fmt.Fprintln(cmd.OutOrStdout(), renderer.RenderHop(h))
		}

		if result.ReachedTarget {
			fmt.Fprintf(cmd.OutOrStdout(), "\nTarget reached in %d hops\n", result.TotalHops())
		} else {
			fmt.Fprintf(cmd.OutOrStdout(), "\nTarget not reached (%d hops)\n", result.TotalHops())
		}
	}

	return lastResult, nil
}

// runGlobalPingMTR runs an MTR measurement via GlobalPing API.
func runGlobalPingMTR(ctx context.Context, cmd *cobra.Command, cfg *Config) (*hop.TraceResult, error) {
	// Create client with retry notification
	client := newGlobalPingClient(cmd.OutOrStdout(), cfg.APIKey)

	// Parse locations
	locations := globalping.ParseLocationStrings(cfg.From)

	// Create MTR measurement request
	req := &globalping.MeasurementRequest{
		Type:      globalping.MeasurementTypeMTR,
		Target:    cfg.Target,
		Locations: locations,
		Options: globalping.MeasurementOptions{
			Protocol: strings.ToUpper(cfg.Protocol),
		},
		InProgressUpdates: true,
	}

	fmt.Fprintf(cmd.OutOrStdout(), "MTR to %s from %s via GlobalPing\n",
		cfg.Target, cfg.From)
	fmt.Fprintln(cmd.OutOrStdout(), "Creating measurement...")

	// Create measurement
	resp, err := client.CreateMeasurement(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to create measurement: %w", err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Measurement ID: %s (%d probes)\n", resp.ID, resp.ProbesCount)
	fmt.Fprintln(cmd.OutOrStdout(), "Waiting for results (MTR takes longer)...")

	// Wait for MTR completion
	measurement, err := client.WaitForMTRMeasurement(ctx, resp.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get results: %w", err)
	}

	// Display MTR results from each probe
	var lastResult *hop.TraceResult
	for _, pr := range measurement.Results {
		result := pr.ToTraceResult(cfg.Target)
		lastResult = result

		fmt.Fprintf(cmd.OutOrStdout(), "\n=== MTR from %s ===\n", result.Source)
		fmt.Fprintf(cmd.OutOrStdout(), "Target: %s (%s)\n\n", cfg.Target, result.TargetIP)

		// Display MTR-style header
		fmt.Fprintf(cmd.OutOrStdout(), "%-3s  %-20s  %6s  %5s  %5s  %8s  %8s  %8s\n",
			"Hop", "Host", "Loss%", "Sent", "Recv", "Best", "Avg", "Worst")

		// Display each hop with MTR stats
		for i, mh := range pr.Result.Hops {
			displayMTRHop(cmd.OutOrStdout(), i+1, &mh)
		}

		if result.ReachedTarget {
			fmt.Fprintf(cmd.OutOrStdout(), "\nTarget reached in %d hops\n", result.TotalHops())
		} else {
			fmt.Fprintf(cmd.OutOrStdout(), "\nTarget not reached (%d hops)\n", result.TotalHops())
		}
	}

	return lastResult, nil
}

// displayMTRHop displays a single MTR hop with statistics.
func displayMTRHop(w io.Writer, ttl int, mh *globalping.MTRHop) {
	// Handle direct format (actual GlobalPing API response)
	if mh.ResolvedAddress != "" {
		host := mh.ResolvedAddress
		if mh.ResolvedHostname != "" && mh.ResolvedHostname != mh.ResolvedAddress {
			host = mh.ResolvedHostname
		}
		// Truncate long hostnames
		if len(host) > 20 {
			host = host[:17] + "..."
		}

		fmt.Fprintf(w, "%3d  %-20s  %5.1f%%  %5d  %5d  %7.1fms  %7.1fms  %7.1fms\n",
			ttl, host,
			mh.Stats.Loss,
			mh.Stats.Total,
			mh.Stats.Rcv,
			mh.Stats.Min,
			mh.Stats.Avg,
			mh.Stats.Max)
		return
	}

	// Handle legacy format with resolvers array
	if len(mh.Resolvers) == 0 {
		fmt.Fprintf(w, "%3d  %-20s  %6s  %5s  %5s  %8s  %8s  %8s\n",
			ttl, "???", "-", "-", "-", "-", "-", "-")
		return
	}

	for _, r := range mh.Resolvers {
		host := r.Address
		if r.Hostname != "" && r.Hostname != r.Address {
			host = r.Hostname
		}
		if len(host) > 20 {
			host = host[:17] + "..."
		}

		fmt.Fprintf(w, "%3d  %-20s  %5.1f%%  %5d  %5d  %7.1fms  %7.1fms  %7.1fms\n",
			ttl, host,
			r.Stats.Loss,
			r.Stats.Total,
			r.Stats.Rcv,
			r.Stats.Min,
			r.Stats.Avg,
			r.Stats.Max)
	}
}

// runCompareMode runs local and remote traces concurrently and displays side-by-side.
func runCompareMode(ctx context.Context, cmd *cobra.Command, cfg *Config) error {
	fmt.Fprintf(cmd.OutOrStdout(), "Comparing traces to %s (local vs %s)\n", cfg.Target, cfg.From)
	fmt.Fprintln(cmd.OutOrStdout(), "Running traces concurrently...")

	var localResult, remoteResult *hop.TraceResult
	var localErr, remoteErr error
	var wg sync.WaitGroup

	// Run both traces concurrently
	wg.Add(2)

	go func() {
		defer wg.Done()
		// Force simple mode for local trace in compare mode
		localCfg := *cfg
		localCfg.Simple = true
		localCfg.From = "" // Clear to run local
		localResult, localErr = runLocalTraceForCompare(ctx, &localCfg)
	}()

	go func() {
		defer wg.Done()
		remoteResult, remoteErr = runGlobalPingTraceForCompare(ctx, cmd.OutOrStdout(), cfg)
	}()

	wg.Wait()

	// Check for errors
	if localErr != nil && remoteErr != nil {
		return fmt.Errorf("both traces failed: local=%v, remote=%v", localErr, remoteErr)
	}

	// Display comparison if we have at least one result
	if localResult == nil && remoteResult == nil {
		return fmt.Errorf("no trace results available")
	}

	// Handle partial results
	if localResult == nil {
		fmt.Fprintf(cmd.OutOrStdout(), "\nLocal trace failed: %v\n", localErr)
		localResult = hop.NewTraceResult(cfg.Target, "")
		localResult.Source = "Local"
	}
	if remoteResult == nil {
		fmt.Fprintf(cmd.OutOrStdout(), "\nRemote trace failed: %v\n", remoteErr)
		remoteResult = hop.NewTraceResult(cfg.Target, "")
		remoteResult.Source = cfg.From
	}

	// Set source labels
	localResult.Source = "Local"

	fmt.Fprintln(cmd.OutOrStdout())

	// Render comparison
	renderer := display.NewCompareRenderer(cmd.OutOrStdout(), cfg.NoColor)
	return renderer.Render(localResult, remoteResult, cfg.From)
}

// runLocalTraceForCompare runs a local trace for compare mode (simple output, no TUI).
func runLocalTraceForCompare(ctx context.Context, cfg *Config) (*hop.TraceResult, error) {
	// Parse timeout
	timeout, err := time.ParseDuration(cfg.Timeout)
	if err != nil {
		return nil, fmt.Errorf("invalid timeout: %w", err)
	}

	// Resolve target
	targetIP, err := trace.ResolveTarget(cfg.Target, getAddressFamily(cfg))
	if err != nil {
		return nil, fmt.Errorf("failed to resolve target: %w", err)
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
		return nil, fmt.Errorf("failed to create tracer: %w", err)
	}

	// Create enricher (unless offline mode)
	var enricher *enrich.Enricher
	if !cfg.Offline {
		enricher = enrich.NewEnricher()
	}

	// Run trace silently (no output during trace)
	result, err := tracer.Trace(ctx, targetIP, func(h *hop.Hop) {
		if enricher != nil {
			enricher.EnrichHop(ctx, h)
		}
	})
	if err != nil {
		return nil, fmt.Errorf("trace failed: %w", err)
	}

	result.TargetIP = targetIP.String()
	return result, nil
}

// runGlobalPingTraceForCompare runs a GlobalPing trace for compare mode (returns result only).
// Uses MTR instead of traceroute to get ASN data for richer output.
func runGlobalPingTraceForCompare(ctx context.Context, w io.Writer, cfg *Config) (*hop.TraceResult, error) {
	// Create client with retry notification
	client := newGlobalPingClient(w, cfg.APIKey)

	// Parse locations
	locations := globalping.ParseLocationStrings(cfg.From)

	// Use MTR to get ASN data (traceroute doesn't include ASN)
	req := &globalping.MeasurementRequest{
		Type:      globalping.MeasurementTypeMTR,
		Target:    cfg.Target,
		Locations: locations,
		Options: globalping.MeasurementOptions{
			Protocol: strings.ToUpper(cfg.Protocol),
		},
		InProgressUpdates: true,
	}

	// Create measurement
	resp, err := client.CreateMeasurement(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to create measurement: %w", err)
	}

	// Wait for MTR completion (takes longer than traceroute)
	measurement, err := client.WaitForMTRMeasurement(ctx, resp.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get results: %w", err)
	}

	// Return first probe result
	if len(measurement.Results) == 0 {
		return nil, fmt.Errorf("no probe results")
	}

	result := measurement.Results[0].ToTraceResult(cfg.Target)
	return result, nil
}

// parseLatencyThreshold parses a latency threshold string (e.g., "100ms", "1s").
func parseLatencyThreshold(s string) (time.Duration, error) {
	if s == "" {
		return 0, nil
	}
	return time.ParseDuration(s)
}

// parseLossThreshold parses a loss threshold string (e.g., "5%", "10").
func parseLossThreshold(s string) (float64, error) {
	if s == "" {
		return 0, nil
	}
	// Remove percent sign if present
	s = strings.TrimSuffix(s, "%")
	return strconv.ParseFloat(s, 64)
}

// runMonitor runs continuous monitoring mode.
func runMonitor(ctx context.Context, cmd *cobra.Command, cfg *Config) error {
	// Parse thresholds
	latencyThreshold, err := parseLatencyThreshold(cfg.AlertLatency)
	if err != nil {
		return fmt.Errorf("invalid latency threshold: %w", err)
	}

	lossThreshold, err := parseLossThreshold(cfg.AlertLoss)
	if err != nil {
		return fmt.Errorf("invalid loss threshold: %w", err)
	}

	// Parse trace timeout
	timeout, err := time.ParseDuration(cfg.Timeout)
	if err != nil {
		return fmt.Errorf("invalid timeout: %w", err)
	}

	// Resolve target
	targetIP, err := trace.ResolveTarget(cfg.Target, getAddressFamily(cfg))
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

	// Create enricher (unless offline mode)
	var enricher *enrich.Enricher
	if !cfg.Offline {
		enricher = enrich.NewEnricher()
	}

	// Create monitor config
	monCfg := monitor.DefaultConfig()
	monCfg.LatencyThreshold = latencyThreshold
	monCfg.LossThreshold = lossThreshold

	// Create monitor
	mon := monitor.NewMonitor(monCfg)

	// Set up change callback
	mon.SetCallback(func(changes []monitor.Change) {
		for _, c := range changes {
			fmt.Fprintf(cmd.OutOrStdout(), "ALERT: %s\n", c.String())
		}
	})

	fmt.Fprintf(cmd.OutOrStdout(), "Monitoring %s (%s), interval %v\n",
		cfg.Target, targetIP, monCfg.Interval)
	if latencyThreshold > 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "  Latency alert threshold: %v\n", latencyThreshold)
	}
	if lossThreshold > 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "  Loss alert threshold: %.1f%%\n", lossThreshold)
	}
	fmt.Fprintln(cmd.OutOrStdout(), "Press Ctrl+C to stop")
	fmt.Fprintln(cmd.OutOrStdout())

	// Create trace function for monitor
	traceFn := func(ctx context.Context) (*hop.TraceResult, error) {
		result, err := tracer.Trace(ctx, targetIP, func(h *hop.Hop) {
			// Enrich each hop
			if enricher != nil {
				enricher.EnrichHop(ctx, h)
			}
		})
		if err != nil {
			return nil, err
		}

		// Print current trace summary
		fmt.Fprintf(cmd.OutOrStdout(), "[%s] Trace: %d hops, reached=%v\n",
			time.Now().Format("15:04:05"), result.TotalHops(), result.ReachedTarget)

		return result, nil
	}

	// Run monitoring loop
	return mon.Run(ctx, traceFn)
}
