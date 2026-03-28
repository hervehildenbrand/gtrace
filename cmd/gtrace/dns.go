package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/hervehildenbrand/gtrace/internal/globalping"
	"github.com/spf13/cobra"
)

// NewDNSCmd creates the dns subcommand for distributed DNS lookup via GlobalPing.
func NewDNSCmd() *cobra.Command {
	var (
		from      string
		queryType string
		resolver  string
		protocol  string
		port      int
		trace     bool
		ipv4      bool
		ipv6      bool
		jsonOut   bool
		apiKey    string
	)

	cmd := &cobra.Command{
		Use:   "dns <domain>",
		Short: "Distributed DNS lookup via GlobalPing probes",
		Long: `Query DNS records from remote GlobalPing probe locations worldwide.
Supports all common DNS record types and custom resolvers.
Use --trace to see the full delegation path from root servers.

Examples:
  gtrace dns example.com --from Paris
  gtrace dns example.com --from "Tokyo; London" --type MX
  gtrace dns gmail.com --from "country:US" --type MX
  gtrace dns example.com --from Paris --resolver 1.1.1.1
  gtrace dns example.com --from Paris --trace
  gtrace dns example.com --from Paris --protocol tcp --json`,
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

			validTypes := map[string]bool{
				"A": true, "AAAA": true, "MX": true, "NS": true,
				"TXT": true, "CNAME": true, "SOA": true, "PTR": true,
				"SRV": true, "CAA": true,
			}
			queryType = strings.ToUpper(queryType)
			if !validTypes[queryType] {
				return fmt.Errorf("invalid record type %q: must be A, AAAA, MX, NS, TXT, CNAME, SOA, PTR, SRV, or CAA", queryType)
			}

			protocol = strings.ToLower(protocol)
			if protocol != "udp" && protocol != "tcp" {
				return fmt.Errorf("invalid protocol %q: must be udp or tcp", protocol)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()

			locations := globalping.ParseLocationStrings(from)
			if len(locations) > globalping.MaxLocations {
				return fmt.Errorf("too many locations: %d (maximum %d)", len(locations), globalping.MaxLocations)
			}

			opts := globalping.MeasurementOptions{
				Protocol: strings.ToUpper(protocol),
				Port:     port,
				Query:    &globalping.DNSQuery{Type: queryType},
				Trace:    trace,
			}
			if resolver != "" {
				opts.Resolver = resolver
			}
			if ipv4 {
				opts.IPVersion = 4
			} else if ipv6 {
				opts.IPVersion = 6
			}

			req := &globalping.MeasurementRequest{
				Type:      globalping.MeasurementTypeDNS,
				Target:    target,
				Locations: locations,
				Options:   opts,
			}

			client := globalping.NewClient(apiKey)
			client.SetRetryCallback(func(attempt int, delay time.Duration) {
				fmt.Fprintf(cmd.ErrOrStderr(), "Rate limited. Retrying in %v (attempt %d/3)...\n", delay, attempt)
			})

			if !jsonOut {
				fmt.Fprintf(cmd.ErrOrStderr(), "DNS lookup %s (%s) from %s via GlobalPing\n",
					target, queryType, from)
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

			result, err := client.WaitForDNSMeasurement(ctx, resp.ID)
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
				displayDNSResult(cmd, &pr, trace)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&from, "from", "", "Probe locations (required). Simple: 'Paris;Tokyo'. Structured: 'city:Tokyo,asn:2497'")
	cmd.Flags().StringVar(&queryType, "type", "A", "DNS record type: A, AAAA, MX, NS, TXT, CNAME, SOA, PTR, SRV, CAA")
	cmd.Flags().StringVar(&resolver, "resolver", "", "Custom DNS resolver IP or FQDN")
	cmd.Flags().StringVar(&protocol, "protocol", "udp", "Protocol: udp or tcp")
	cmd.Flags().IntVar(&port, "port", 53, "DNS server port")
	cmd.Flags().BoolVar(&trace, "trace", false, "Enable delegation path tracing")
	cmd.Flags().BoolVarP(&ipv4, "ipv4", "4", false, "Force IPv4 only")
	cmd.Flags().BoolVarP(&ipv6, "ipv6", "6", false, "Force IPv6 only")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output in JSON format")
	cmd.Flags().StringVar(&apiKey, "api-key", "", "GlobalPing API key for higher rate limits")

	return cmd
}

func displayDNSResult(cmd *cobra.Command, pr *globalping.DNSProbeResult, traceMode bool) {
	w := cmd.OutOrStdout()

	loc := formatPingProbeLocation(&pr.Probe)
	fmt.Fprintf(w, "\n=== From %s ===\n", loc)

	r := pr.Result

	// For trace mode, show raw output
	if traceMode && r.RawOutput != "" {
		fmt.Fprintln(w, r.RawOutput)
		return
	}

	if r.Resolver != "" {
		fmt.Fprintf(w, "Resolver: %s\n", r.Resolver)
	}

	fmt.Fprintf(w, "Status: %s (%d)\n", r.StatusCodeName, r.StatusCode)

	if r.Timings.Total > 0 {
		fmt.Fprintf(w, "Query time: %.1f ms\n", r.Timings.Total)
	}

	if len(r.Answers) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "ANSWER SECTION:")
		for _, a := range r.Answers {
			fmt.Fprintf(w, "  %-30s %5d  %s  %-5s %s\n",
				a.Name, a.TTL, a.Class, a.Type, a.Value)
		}
	} else {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "(No answer records)")
	}
}
