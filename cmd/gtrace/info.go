package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/hervehildenbrand/gtrace/internal/enrich"
	"github.com/hervehildenbrand/gtrace/internal/trace"
	"github.com/spf13/cobra"
)

// InfoResult contains the result of an IP info lookup.
type InfoResult struct {
	IP        string `json:"ip"`
	Hostname  string `json:"hostname,omitempty"`
	ASN       uint32 `json:"asn,omitempty"`
	ASName    string `json:"as_name,omitempty"`
	Prefix    string `json:"prefix,omitempty"`
	Country   string `json:"country,omitempty"`
	Registry  string `json:"registry,omitempty"`
	Allocated string `json:"allocated,omitempty"`
}

// NewInfoCmd creates the info subcommand.
func NewInfoCmd() *cobra.Command {
	var jsonOutput bool
	var ipv4Only bool
	var ipv6Only bool

	cmd := &cobra.Command{
		Use:   "info <ip-or-hostname>",
		Short: "Look up IP address information (ASN, prefix, rDNS)",
		Long: `Look up detailed information about an IP address or hostname.

Displays ASN, organization, prefix, country, registry, allocation date,
and reverse DNS hostname. Uses Team Cymru DNS, ip-api.com, and RIPE REST
as data sources.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if ipv4Only && ipv6Only {
				return fmt.Errorf("-4/--ipv4 and -6/--ipv6 are mutually exclusive")
			}

			af := trace.AddressFamilyAuto
			if ipv4Only {
				af = trace.AddressFamilyIPv4
			} else if ipv6Only {
				af = trace.AddressFamilyIPv6
			}

			ip, err := trace.ResolveTarget(args[0], af)
			if err != nil {
				return fmt.Errorf("failed to resolve %q: %w", args[0], err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			result := InfoResult{IP: ip.String()}

			var asnResult *enrich.ASNResult
			var asnErr error
			var hostname string

			var wg sync.WaitGroup
			wg.Add(2)

			go func() {
				defer wg.Done()
				asnLookup := enrich.NewASNLookup()
				asnResult, asnErr = asnLookup.Lookup(ctx, ip)
			}()

			go func() {
				defer wg.Done()
				rdnsLookup := enrich.NewRDNSLookup()
				hostname, _ = rdnsLookup.Lookup(ctx, ip)
			}()

			wg.Wait()

			if hostname != "" {
				result.Hostname = hostname
			}

			if asnErr == nil && asnResult != nil {
				result.ASN = asnResult.ASN
				result.ASName = asnResult.Name
				result.Prefix = asnResult.Prefix
				result.Country = asnResult.Country
				result.Registry = asnResult.Registry
				result.Allocated = asnResult.Date
			}

			if jsonOutput {
				data, err := json.Marshal(result)
				if err != nil {
					return fmt.Errorf("failed to marshal JSON: %w", err)
				}
				fmt.Fprintln(cmd.OutOrStdout(), string(data))
			} else {
				fmt.Fprint(cmd.OutOrStdout(), formatInfoText(result))
			}

			return nil
		},
	}

	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output in JSON format")
	cmd.Flags().BoolVarP(&ipv4Only, "ipv4", "4", false, "Use IPv4 only")
	cmd.Flags().BoolVarP(&ipv6Only, "ipv6", "6", false, "Use IPv6 only")

	return cmd
}

// formatInfoText formats an InfoResult as aligned human-readable text.
func formatInfoText(r InfoResult) string {
	type field struct {
		label string
		value string
	}

	var fields []field

	fields = append(fields, field{"IP Address", r.IP})

	if r.Hostname != "" {
		fields = append(fields, field{"Hostname", r.Hostname})
	}
	if r.ASN > 0 {
		fields = append(fields, field{"AS Number", fmt.Sprintf("AS%d", r.ASN)})
	}
	if r.ASName != "" {
		fields = append(fields, field{"AS Name", r.ASName})
	}
	if r.Prefix != "" {
		fields = append(fields, field{"Prefix", r.Prefix})
	}
	if r.Country != "" {
		fields = append(fields, field{"Country", r.Country})
	}
	if r.Registry != "" {
		fields = append(fields, field{"Registry", r.Registry})
	}
	if r.Allocated != "" {
		fields = append(fields, field{"Allocated", r.Allocated})
	}

	// Find max label width for alignment
	maxWidth := 0
	for _, f := range fields {
		if len(f.label) > maxWidth {
			maxWidth = len(f.label)
		}
	}

	var sb strings.Builder
	sb.WriteString("\n")
	for _, f := range fields {
		fmt.Fprintf(&sb, "  %-*s : %s\n", maxWidth, f.label, f.value)
	}
	sb.WriteString("\n")

	return sb.String()
}
