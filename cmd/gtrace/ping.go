package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/hervehildenbrand/gtrace/internal/globalping"
	"github.com/spf13/cobra"
)

// NewPingCmd creates the ping subcommand for distributed ping via GlobalPing.
func NewPingCmd() *cobra.Command {
	var (
		from     string
		packets  int
		protocol string
		port     int
		ipv4     bool
		ipv6     bool
		jsonOut  bool
		apiKey   string
	)

	cmd := &cobra.Command{
		Use:   "ping <target>",
		Short: "Distributed ping via GlobalPing probes",
		Long: `Run a distributed ping from remote GlobalPing probe locations worldwide.
Supports ICMP (default) and TCP ping.

Does not require root privileges. Works without an API key (rate-limited).

Examples:
  gtrace ping 8.8.8.8 --from Paris
  gtrace ping example.com --from "Tokyo; London" --packets 5
  gtrace ping example.com --from "city:Tokyo,asn:2497" --protocol tcp --port 443
  gtrace ping 1.1.1.1 --from "country:US@3" -4 --json`,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			target := args[0]

			if from == "" {
				return fmt.Errorf("--from is required (specify probe locations)")
			}

			if ipv4 && ipv6 {
				return fmt.Errorf("-4/--ipv4 and -6/--ipv6 are mutually exclusive")
			}

			if packets < 1 || packets > 16 {
				return fmt.Errorf("--packets must be between 1 and 16")
			}

			protocol = strings.ToLower(protocol)
			if protocol != "icmp" && protocol != "tcp" {
				return fmt.Errorf("--protocol must be icmp or tcp")
			}

			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()

			locations := globalping.ParseLocationStrings(from)
			if len(locations) > globalping.MaxLocations {
				return fmt.Errorf("too many locations: %d (maximum %d)", len(locations), globalping.MaxLocations)
			}

			opts := globalping.MeasurementOptions{
				Protocol: strings.ToUpper(protocol),
				Packets:  packets,
			}
			if protocol == "tcp" && port > 0 {
				opts.Port = port
			}
			// Only set IPVersion for hostnames — GlobalPing rejects it for IP targets
			if net.ParseIP(target) == nil {
				if ipv4 {
					opts.IPVersion = 4
				} else if ipv6 {
					opts.IPVersion = 6
				}
			}

			req := &globalping.MeasurementRequest{
				Type:      globalping.MeasurementTypePing,
				Target:    target,
				Locations: locations,
				Options:   opts,
			}

			client := globalping.NewClient(apiKey)
			client.SetRetryCallback(func(attempt int, delay time.Duration) {
				fmt.Fprintf(cmd.ErrOrStderr(), "Rate limited. Retrying in %v (attempt %d/3)...\n", delay, attempt)
			})

			if !jsonOut {
				fmt.Fprintf(cmd.ErrOrStderr(), "Ping %s from %s via GlobalPing\n", target, from)
				fmt.Fprintln(cmd.ErrOrStderr(), "Creating measurement...")
			}

			resp, err := client.CreateMeasurement(ctx, req)
			if err != nil {
				return fmt.Errorf("failed to create measurement: %w", err)
			}

			if !jsonOut {
				fmt.Fprintf(cmd.ErrOrStderr(), "Measurement ID: %s (%d probe%s)\n",
					resp.ID, resp.ProbesCount, pluralS(resp.ProbesCount))
				fmt.Fprintln(cmd.ErrOrStderr(), "Waiting for results...")
			}

			result, err := client.WaitForPingMeasurement(ctx, resp.ID)
			if err != nil {
				return fmt.Errorf("failed to get results: %w", err)
			}

			if jsonOut {
				data, err := json.MarshalIndent(result, "", "  ")
				if err != nil {
					return fmt.Errorf("failed to marshal JSON: %w", err)
				}
				fmt.Fprintln(cmd.OutOrStdout(), string(data))
				return nil
			}

			for _, pr := range result.Results {
				displayPingResult(cmd, &pr, target)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&from, "from", "", "Probe locations (required). Simple: 'Paris; Tokyo'. Structured: 'city:Tokyo,asn:2497'")
	cmd.Flags().IntVar(&packets, "packets", 3, "Number of packets (1-16)")
	cmd.Flags().StringVar(&protocol, "protocol", "icmp", "Protocol: icmp or tcp")
	cmd.Flags().IntVar(&port, "port", 80, "Destination port (TCP only)")
	cmd.Flags().BoolVarP(&ipv4, "ipv4", "4", false, "Force IPv4 only")
	cmd.Flags().BoolVarP(&ipv6, "ipv6", "6", false, "Force IPv6 only")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output in JSON format")
	cmd.Flags().StringVar(&apiKey, "api-key", "", "GlobalPing API key for higher rate limits")

	return cmd
}

func displayPingResult(cmd *cobra.Command, pr *globalping.PingProbeResult, target string) {
	w := cmd.OutOrStdout()

	// Probe location header
	loc := formatPingProbeLocation(&pr.Probe)
	fmt.Fprintf(w, "\n=== From %s ===\n", loc)

	// Target info
	r := pr.Result
	if r.ResolvedHostname != "" && r.ResolvedHostname != r.ResolvedAddress {
		fmt.Fprintf(w, "Target: %s (%s)\n", r.ResolvedAddress, r.ResolvedHostname)
	} else if r.ResolvedAddress != "" {
		fmt.Fprintf(w, "Target: %s\n", r.ResolvedAddress)
	}

	fmt.Fprintln(w)

	// Stats
	fmt.Fprintf(w, "  %d packets sent, %d received, %.1f%% loss\n",
		r.Stats.Total, r.Stats.Rcv, r.Stats.Loss)

	if r.Stats.Min != nil && r.Stats.Avg != nil && r.Stats.Max != nil {
		fmt.Fprintf(w, "  rtt min/avg/max = %.2f/%.2f/%.2f ms\n",
			*r.Stats.Min, *r.Stats.Avg, *r.Stats.Max)
	}

	// Individual timings
	if len(r.Timings) > 0 {
		var parts []string
		for _, t := range r.Timings {
			parts = append(parts, fmt.Sprintf("%.2fms", t.RTT))
		}
		fmt.Fprintf(w, "  Timings: %s\n", strings.Join(parts, " "))
	}
}

func formatPingProbeLocation(p *globalping.ProbeInfo) string {
	parts := []string{}
	if p.City != "" {
		parts = append(parts, p.City)
	}
	if p.Country != "" {
		parts = append(parts, p.Country)
	}
	loc := strings.Join(parts, ", ")
	if p.Network != "" {
		loc += fmt.Sprintf(" (%s, AS%d)", p.Network, p.ASN)
	}
	return loc
}

func pluralS(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
