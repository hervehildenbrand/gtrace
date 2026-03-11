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

// NewProbesCmd creates the probes subcommand for discovering GlobalPing probes.
func NewProbesCmd() *cobra.Command {
	var (
		country    string
		city       string
		asn        int
		network    string
		tag        string
		jsonOutput bool
		limit      int
	)

	cmd := &cobra.Command{
		Use:   "probes [keyword]",
		Short: "Discover available GlobalPing probe locations",
		Long: `List available GlobalPing probes worldwide with optional filtering.

Filter by country (ISO code), city, ASN, network name, or tag.
Provide a positional keyword to search across all fields.

Examples:
  gtrace probes                    # List probes (default limit 50)
  gtrace probes --country JP       # Filter by country
  gtrace probes --asn 13335        # Filter by ASN (Cloudflare)
  gtrace probes --city London      # Filter by city
  gtrace probes --network OVH      # Filter by network name
  gtrace probes --json             # JSON output
  gtrace probes LINX               # Keyword search`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			apiKey, _ := cmd.Flags().GetString("api-key")
			client := globalping.NewClient(apiKey)

			filter := &globalping.ProbeFilter{
				Country: country,
				City:    city,
				ASN:     asn,
				Network: network,
				Tag:     tag,
			}

			// If a positional keyword is given, use it as a broad search
			keyword := ""
			if len(args) > 0 {
				keyword = args[0]
			}

			probes, err := client.ListProbes(ctx, filter)
			if err != nil {
				return fmt.Errorf("failed to list probes: %w", err)
			}

			// Apply keyword filter across all text fields
			if keyword != "" {
				probes = filterByKeyword(probes, keyword)
			}

			// Apply limit
			if limit > 0 && len(probes) > limit {
				probes = probes[:limit]
			}

			if jsonOutput {
				data, err := json.MarshalIndent(probes, "", "  ")
				if err != nil {
					return fmt.Errorf("failed to marshal JSON: %w", err)
				}
				fmt.Fprintln(cmd.OutOrStdout(), string(data))
				return nil
			}

			if len(probes) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "No probes found matching the criteria.")
				return nil
			}

			fmt.Fprintf(cmd.OutOrStdout(), "Found %d probes:\n\n", len(probes))
			fmt.Fprintf(cmd.OutOrStdout(), "%-20s  %-4s  %8s  %-25s  %s\n",
				"City", "CC", "ASN", "Network", "Tags")
			fmt.Fprintln(cmd.OutOrStdout(), strings.Repeat("-", 85))

			for _, p := range probes {
				tags := ""
				if len(p.Tags) > 0 {
					tags = strings.Join(p.Tags, ", ")
				}
				cityStr := p.Location.City
				if len(cityStr) > 20 {
					cityStr = cityStr[:17] + "..."
				}
				networkStr := p.Location.Network
				if len(networkStr) > 25 {
					networkStr = networkStr[:22] + "..."
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%-20s  %-4s  %8d  %-25s  %s\n",
					cityStr,
					p.Location.Country,
					p.Location.ASN,
					networkStr,
					tags)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&country, "country", "", "Filter by country code (e.g., JP, US, DE)")
	cmd.Flags().StringVar(&city, "city", "", "Filter by city name (substring match)")
	cmd.Flags().IntVar(&asn, "asn", 0, "Filter by ASN number")
	cmd.Flags().StringVar(&network, "network", "", "Filter by network name (substring match)")
	cmd.Flags().StringVar(&tag, "tag", "", "Filter by tag (e.g., datacenter)")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output in JSON format")
	cmd.Flags().IntVar(&limit, "limit", 50, "Maximum number of probes to display")

	return cmd
}

// filterByKeyword filters probes where the keyword matches any text field.
func filterByKeyword(probes []globalping.Probe, keyword string) []globalping.Probe {
	kw := strings.ToLower(keyword)
	var result []globalping.Probe
	for _, p := range probes {
		if strings.Contains(strings.ToLower(p.Location.City), kw) ||
			strings.Contains(strings.ToLower(p.Location.Country), kw) ||
			strings.Contains(strings.ToLower(p.Location.Network), kw) ||
			strings.Contains(strings.ToLower(p.Location.Region), kw) ||
			strings.Contains(strings.ToLower(p.Location.Continent), kw) ||
			containsAnyTag(p.Tags, kw) {
			result = append(result, p)
		}
	}
	return result
}

func containsAnyTag(tags []string, kw string) bool {
	for _, t := range tags {
		if strings.Contains(strings.ToLower(t), kw) {
			return true
		}
	}
	return false
}
