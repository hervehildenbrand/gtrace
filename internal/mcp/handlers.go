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

func (h *handlers) handleListProbes(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	filter := &globalping.ProbeFilter{}

	if v := req.GetString("country", ""); v != "" {
		filter.Country = v
	}
	if v := req.GetString("city", ""); v != "" {
		filter.City = v
	}
	if v := req.GetInt("asn", 0); v > 0 {
		filter.ASN = v
	}
	if v := req.GetString("network", ""); v != "" {
		filter.Network = v
	}
	if v := req.GetString("tag", ""); v != "" {
		filter.Tag = v
	}

	limit := req.GetInt("limit", 20)
	if limit < 1 {
		limit = 20
	}

	client := globalping.NewClient(h.apiKey)
	probes, err := client.ListProbes(ctx, filter)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to list probes: %v", err)), nil
	}

	if limit > 0 && len(probes) > limit {
		probes = probes[:limit]
	}

	return mcp.NewToolResultText(formatProbeList(probes)), nil
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
	cfg.Decode = req.GetBool("decode", false)

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
	cfg.Decode = req.GetBool("decode", false)

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
			// Track ICMP type/code for code reporting
			if pr.ICMPType != 0 {
				s.LastICMPType = pr.ICMPType
				s.LastICMPCode = pr.ICMPCode
			}
			// Track TTL manipulation
			if pr.OriginalTTL >= 0 && pr.OriginalTTL != 0 && pr.OriginalTTL != 1 {
				s.TTLManipulated = true
			}
			// Track ECMP flow paths
			if pr.FlowID > 0 && pr.IP != nil {
				ipStr := pr.IP.String()
				if s.FlowPaths[pr.FlowID] == nil {
					s.FlowPaths[pr.FlowID] = make(map[string]int)
				}
				s.FlowPaths[pr.FlowID][ipStr]++
			}
		}
		if len(pr.MPLS) > 0 {
			s.SetMPLS(pr.MPLS)
		}
		// Track TransportInfo for decode mode
		if pr.TransportInfo != nil {
			s.LastTransportInfo = pr.TransportInfo
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

	// Post-process: rate-limit detection and ECMP classification
	updateMCPRateLimitFlags(stats)
	updateMCPECMPClassification(stats)

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

	protocol := opts.Protocol
	if protocol == "" {
		protocol = "ICMP"
	}

	var probeResults []*globalPingProbeResult
	for _, pr := range result.Results {
		tr := pr.ToTraceResult(target)
		tr.Protocol = protocol
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

func (h *handlers) handlePing(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
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
	if v := req.GetInt("packets", 0); v > 0 {
		opts.Packets = v
	}
	if req.GetBool("ipv4", false) {
		opts.IPVersion = 4
	} else if req.GetBool("ipv6", false) {
		opts.IPVersion = 6
	}

	measReq := &globalping.MeasurementRequest{
		Type:      globalping.MeasurementTypePing,
		Target:    target,
		Locations: locations,
		Options:   opts,
	}

	if err := measReq.Validate(); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("invalid request: %v", err)), nil
	}

	client := globalping.NewClient(h.apiKey)
	result, err := client.RunPingMeasurement(ctx, measReq)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("ping measurement failed: %v", err)), nil
	}

	return mcp.NewToolResultText(formatPingResults(result.Results, target)), nil
}

func (h *handlers) handleDNS(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
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
	if v := req.GetString("query_type", ""); v != "" {
		opts.Query = &globalping.DNSQuery{Type: strings.ToUpper(v)}
	}
	if v := req.GetString("resolver", ""); v != "" {
		opts.Resolver = v
	}
	if v := req.GetString("protocol", ""); v != "" {
		opts.Protocol = strings.ToUpper(v)
	}
	if v := req.GetInt("port", 0); v > 0 {
		opts.Port = v
	}
	opts.Trace = req.GetBool("trace", false)
	if req.GetBool("ipv4", false) {
		opts.IPVersion = 4
	} else if req.GetBool("ipv6", false) {
		opts.IPVersion = 6
	}

	measReq := &globalping.MeasurementRequest{
		Type:      globalping.MeasurementTypeDNS,
		Target:    target,
		Locations: locations,
		Options:   opts,
	}

	if err := measReq.Validate(); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("invalid request: %v", err)), nil
	}

	client := globalping.NewClient(h.apiKey)
	result, err := client.RunDNSMeasurement(ctx, measReq)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("DNS measurement failed: %v", err)), nil
	}

	return mcp.NewToolResultText(formatDNSResults(result.Results, target, opts.Trace)), nil
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

// updateMCPRateLimitFlags detects ICMP rate-limiting in MTR stats.
// A hop is rate-limited if its loss is >10% but downstream hops have
// significantly lower loss (difference >15%).
func updateMCPRateLimitFlags(stats map[int]*display.HopStats) {
	maxTTL := 0
	for ttl, s := range stats {
		if s.Recv > 0 && ttl > maxTTL {
			maxTTL = ttl
		}
	}

	for ttl, s := range stats {
		loss := s.LossPercent()
		if loss <= 10 {
			s.RateLimited = false
			continue
		}

		var downstreamLoss float64
		var count int
		for t := ttl + 1; t <= maxTTL; t++ {
			ds, ok := stats[t]
			if !ok || ds.Recv == 0 {
				continue
			}
			downstreamLoss += ds.LossPercent()
			count++
		}

		if count == 0 {
			s.RateLimited = false
			continue
		}

		avgDownstream := downstreamLoss / float64(count)
		s.RateLimited = (loss - avgDownstream) > 15
	}
}

// updateMCPECMPClassification classifies ECMP type for all hops.
func updateMCPECMPClassification(stats map[int]*display.HopStats) {
	for _, s := range stats {
		if s.HasECMP() && len(s.FlowPaths) > 0 {
			s.ECMPClassified = classifyMCPECMP(s.FlowPaths)
		}
	}
}

// classifyMCPECMP determines if ECMP is per-flow or per-packet.
func classifyMCPECMP(flowPaths map[int]map[string]int) string {
	if len(flowPaths) == 0 {
		return ""
	}

	// If any single flow hits multiple IPs, it's per-packet
	for _, ipCounts := range flowPaths {
		if len(ipCounts) > 1 {
			return "per_packet"
		}
	}

	// If different flows hit different IPs, it's per-flow
	allIPs := make(map[string]bool)
	for _, ipCounts := range flowPaths {
		for ip := range ipCounts {
			allIPs[ip] = true
		}
	}

	if len(allIPs) > 1 && len(flowPaths) > 1 {
		return "per_flow"
	}

	return ""
}
