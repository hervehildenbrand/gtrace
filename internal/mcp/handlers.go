package mcp

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/hervehildenbrand/gtrace/internal/display"
	"github.com/hervehildenbrand/gtrace/internal/enrich"
	"github.com/hervehildenbrand/gtrace/internal/globalping"
	"github.com/hervehildenbrand/gtrace/internal/trace"
	"github.com/mark3labs/mcp-go/mcp"
)

// handlers holds shared state for MCP tool handlers.
type handlers struct {
	apiKey string
}

func (h *handlers) handleTraceroute(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	target, err := req.RequireString("target")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	if err := trace.CheckPrivileges(); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("traceroute requires root privileges: %v", err)), nil
	}

	cfg := trace.DefaultConfig()

	if v := req.GetString("protocol", ""); v != "" {
		cfg.Protocol = trace.Protocol(strings.ToLower(v))
	}
	if v := req.GetInt("port", 0); v > 0 {
		cfg.Port = v
	}
	if v := req.GetInt("max_hops", 0); v > 0 {
		cfg.MaxHops = v
	}
	if v := req.GetString("timeout", ""); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("invalid timeout: %v", err)), nil
		}
		cfg.Timeout = d
	}
	if v := req.GetInt("packets", 0); v > 0 {
		cfg.PacketsPerHop = v
	}
	cfg.DetectNAT = req.GetBool("detect_nat", false)
	if v := req.GetInt("ecmp_flows", 0); v > 0 {
		cfg.ECMPFlows = v
	}
	cfg.DiscoverMTU = req.GetBool("discover_mtu", false)
	if v := req.GetInt("probe_size", 0); v > 0 {
		cfg.ProbeSize = v
	}

	if err := cfg.Validate(); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("invalid configuration: %v", err)), nil
	}

	af := getAddressFamily(req)
	targetIP, err := trace.ResolveTarget(target, af)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to resolve target: %v", err)), nil
	}

	tracer, err := trace.NewLocalTracer(cfg)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to create tracer: %v", err)), nil
	}

	result, err := tracer.Trace(ctx, targetIP, nil)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("traceroute failed: %v", err)), nil
	}

	result.Target = target
	result.TargetIP = targetIP.String()
	result.Protocol = string(cfg.Protocol)

	enricher := enrich.NewEnricher()
	enricher.EnrichTrace(ctx, result)

	return mcp.NewToolResultText(formatTraceResult(result)), nil
}

func (h *handlers) handleMTR(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	target, err := req.RequireString("target")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	if err := trace.CheckPrivileges(); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("MTR requires root privileges: %v", err)), nil
	}

	cfg := trace.DefaultConfig()
	cfg.PacketsPerHop = 1 // MTR-style single probe per cycle

	if v := req.GetString("protocol", ""); v != "" {
		cfg.Protocol = trace.Protocol(strings.ToLower(v))
	}
	if v := req.GetInt("port", 0); v > 0 {
		cfg.Port = v
	}
	if v := req.GetInt("max_hops", 0); v > 0 {
		cfg.MaxHops = v
	}
	if v := req.GetString("timeout", ""); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("invalid timeout: %v", err)), nil
		}
		cfg.Timeout = d
	}
	if v := req.GetInt("ecmp_flows", 0); v > 0 {
		cfg.ECMPFlows = v
	}

	cycles := req.GetInt("cycles", 10)
	if cycles < 1 {
		cycles = 10
	}

	interval := 1 * time.Second
	if v := req.GetString("interval", ""); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("invalid interval: %v", err)), nil
		}
		interval = d
	}

	if err := cfg.Validate(); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("invalid configuration: %v", err)), nil
	}

	targetIP, err := trace.ResolveTarget(target, trace.AddressFamilyAuto)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to resolve target: %v", err)), nil
	}

	tracer, err := trace.NewLocalTracer(cfg)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to create tracer: %v", err)), nil
	}

	ct := trace.NewContinuousTracer(cfg, tracer, interval)
	stats := make(map[int]*display.HopStats)
	completedCycles := 0

	mtrCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	probeCallback := func(pr trace.ProbeResult) {
		s, ok := stats[pr.TTL]
		if !ok {
			s = display.NewHopStats(pr.TTL)
			stats[pr.TTL] = s
		}
		if pr.Timeout {
			s.AddTimeout()
		} else {
			s.AddProbe(pr.IP, pr.RTT)
		}
		if len(pr.MPLS) > 0 {
			s.SetMPLS(pr.MPLS)
		}
	}

	cycleCallback := func(cycle int, reached bool) {
		completedCycles = cycle
		if cycle >= cycles {
			cancel()
		}
	}

	err = ct.Run(mtrCtx, targetIP, probeCallback, cycleCallback)
	if err != nil && mtrCtx.Err() == nil {
		return mcp.NewToolResultError(fmt.Sprintf("MTR failed: %v", err)), nil
	}

	// Enrich each hop's primary IP
	enricher := enrich.NewEnricher()
	for _, s := range stats {
		ip := s.PrimaryIP()
		if ip != nil {
			e, enrichErr := enricher.EnrichIP(ctx, ip)
			if enrichErr == nil && e != nil {
				s.SetEnrichment(*e)
			}
			// Enrich ECMP IPs
			if s.HasECMP() {
				for _, ipInfo := range s.SortedIPs() {
					ie, ieErr := enricher.EnrichIP(ctx, ipInfo.IP)
					if ieErr == nil && ie != nil {
						s.SetIPEnrichment(ipInfo.IP, *ie)
					}
				}
			}
		}
	}

	return mcp.NewToolResultText(formatMTRStats(stats, completedCycles, target)), nil
}

func (h *handlers) handleGlobalPing(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	target, err := req.RequireString("target")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	from, err := req.RequireString("from")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	locations := globalping.ParseLocationStrings(from)
	if len(locations) == 0 {
		return mcp.NewToolResultError("no valid locations provided"), nil
	}

	opts := globalping.MeasurementOptions{}
	if v := req.GetString("protocol", ""); v != "" {
		opts.Protocol = strings.ToUpper(v)
	}
	if v := req.GetInt("port", 0); v > 0 {
		opts.Port = v
	}
	ipv4 := req.GetBool("ipv4", false)
	ipv6 := req.GetBool("ipv6", false)
	if ipv4 {
		opts.IPVersion = 4
	} else if ipv6 {
		opts.IPVersion = 6
	}

	measReq := &globalping.MeasurementRequest{
		Type:      globalping.MeasurementTypeMTR,
		Target:    target,
		Locations: locations,
		Options:   opts,
	}

	if err := measReq.Validate(); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("invalid request: %v", err)), nil
	}

	client := globalping.NewClient(h.apiKey)
	result, err := client.RunMTRMeasurement(ctx, measReq)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("GlobalPing measurement failed: %v", err)), nil
	}

	var probeResults []*globalPingProbeResult
	for _, pr := range result.Results {
		tr := pr.ToTraceResult(target)
		probeResults = append(probeResults, &globalPingProbeResult{
			probe: probeInfo{
				City:    pr.Probe.City,
				Country: pr.Probe.Country,
				ASN:     pr.Probe.ASN,
				Network: pr.Probe.Network,
			},
			trace: tr,
		})
	}

	return mcp.NewToolResultText(formatGlobalPingResults(probeResults)), nil
}

func (h *handlers) handleASNLookup(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	ipStr, err := req.RequireString("ip")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return mcp.NewToolResultError(fmt.Sprintf("invalid IP address: %s", ipStr)), nil
	}

	lookup := enrich.NewASNLookup()
	result, err := lookup.Lookup(ctx, ip)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("ASN lookup failed: %v", err)), nil
	}

	return mcp.NewToolResultText(formatASNResult(result)), nil
}

func (h *handlers) handleGeoLookup(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	ipStr, err := req.RequireString("ip")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return mcp.NewToolResultError(fmt.Sprintf("invalid IP address: %s", ipStr)), nil
	}

	lookup := enrich.NewGeoLookup()
	result, err := lookup.Lookup(ctx, ip)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("geo lookup failed: %v", err)), nil
	}

	return mcp.NewToolResultText(formatGeoResult(result)), nil
}

func (h *handlers) handleReverseDNS(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	ipStr, err := req.RequireString("ip")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return mcp.NewToolResultError(fmt.Sprintf("invalid IP address: %s", ipStr)), nil
	}

	lookup := enrich.NewRDNSLookup()
	hostname, err := lookup.Lookup(ctx, ip)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("reverse DNS lookup failed: %v", err)), nil
	}

	return mcp.NewToolResultText(formatRDNSResult(ipStr, hostname)), nil
}

// getAddressFamily determines the address family from ipv4/ipv6 flags.
func getAddressFamily(req mcp.CallToolRequest) trace.AddressFamily {
	if req.GetBool("ipv4", false) {
		return trace.AddressFamilyIPv4
	}
	if req.GetBool("ipv6", false) {
		return trace.AddressFamilyIPv6
	}
	return trace.AddressFamilyAuto
}
