// Package hop defines the unified hop data model for traceroute results.
package hop

import (
	"fmt"
	"net"
	"time"
)

// Probe represents a single traceroute probe result.
type Probe struct {
	IP      net.IP
	RTT     time.Duration
	Timeout bool
}

// MPLSLabel represents an MPLS label from ICMP extensions (RFC 4950).
type MPLSLabel struct {
	Label uint32 // 20-bit label value
	Exp   uint8  // 3-bit experimental/traffic class
	S     bool   // Bottom of stack
	TTL   uint8  // MPLS TTL
}

// String formats the MPLS label for display.
func (m MPLSLabel) String() string {
	s := 0
	if m.S {
		s = 1
	}
	return fmt.Sprintf("L=%d E=%d S=%d TTL=%d", m.Label, m.Exp, s, m.TTL)
}

// Enrichment contains additional data about a hop (ASN, geo, rDNS).
type Enrichment struct {
	ASN      uint32
	ASOrg    string
	Country  string
	City     string
	Hostname string
	IX       string // Internet Exchange name if applicable
}

// Hop represents a single hop in a traceroute.
type Hop struct {
	TTL        int
	Probes     []Probe
	MPLS       []MPLSLabel
	Enrichment Enrichment
	MTU        int  // Discovered MTU at this hop
	NAT        bool // NAT detected at this hop
}

// NewHop creates a new Hop with the given TTL.
func NewHop(ttl int) *Hop {
	return &Hop{
		TTL:    ttl,
		Probes: make([]Probe, 0),
	}
}

// AddProbe records a successful probe response.
func (h *Hop) AddProbe(ip net.IP, rtt time.Duration) {
	h.Probes = append(h.Probes, Probe{
		IP:  ip,
		RTT: rtt,
	})
}

// AddTimeout records a probe that timed out.
func (h *Hop) AddTimeout() {
	h.Probes = append(h.Probes, Probe{
		Timeout: true,
	})
}

// AvgRTT calculates the average RTT excluding timeouts.
func (h *Hop) AvgRTT() time.Duration {
	var total time.Duration
	var count int

	for _, p := range h.Probes {
		if !p.Timeout {
			total += p.RTT
			count++
		}
	}

	if count == 0 {
		return 0
	}
	return total / time.Duration(count)
}

// LossPercent calculates the packet loss percentage.
func (h *Hop) LossPercent() float64 {
	if len(h.Probes) == 0 {
		return 0
	}

	var timeouts int
	for _, p := range h.Probes {
		if p.Timeout {
			timeouts++
		}
	}

	return float64(timeouts) / float64(len(h.Probes)) * 100
}

// PrimaryIP returns the first non-nil IP from probes.
func (h *Hop) PrimaryIP() net.IP {
	for _, p := range h.Probes {
		if p.IP != nil {
			return p.IP
		}
	}
	return nil
}

// HasMultipleIPs returns true if different IPs were seen (ECMP indication).
func (h *Hop) HasMultipleIPs() bool {
	ips := make(map[string]bool)
	for _, p := range h.Probes {
		if p.IP != nil {
			ips[p.IP.String()] = true
		}
	}
	return len(ips) > 1
}

// SetMPLS sets the MPLS labels for this hop.
func (h *Hop) SetMPLS(labels []MPLSLabel) {
	h.MPLS = labels
}

// SetEnrichment sets the enrichment data for this hop.
func (h *Hop) SetEnrichment(e Enrichment) {
	h.Enrichment = e
}

// TraceResult contains the complete result of a traceroute.
type TraceResult struct {
	Target        string    // Target hostname
	TargetIP      string    // Resolved target IP
	Hops          []*Hop    // Ordered list of hops
	ReachedTarget bool      // Whether the target was reached
	Protocol      string    // Protocol used (icmp, udp, tcp)
	Source        string    // Source location (empty for local)
	StartTime     time.Time // When the trace started
	EndTime       time.Time // When the trace completed
}

// NewTraceResult creates a new TraceResult for the given target.
func NewTraceResult(target, targetIP string) *TraceResult {
	return &TraceResult{
		Target:   target,
		TargetIP: targetIP,
		Hops:     make([]*Hop, 0),
	}
}

// AddHop appends a hop to the trace result.
func (tr *TraceResult) AddHop(h *Hop) {
	tr.Hops = append(tr.Hops, h)
}

// GetHop returns the hop at the given TTL, or nil if not found.
func (tr *TraceResult) GetHop(ttl int) *Hop {
	for _, h := range tr.Hops {
		if h.TTL == ttl {
			return h
		}
	}
	return nil
}

// IsComplete returns true if the trace has finished.
func (tr *TraceResult) IsComplete() bool {
	return tr.ReachedTarget
}

// TotalHops returns the number of hops in the trace.
func (tr *TraceResult) TotalHops() int {
	return len(tr.Hops)
}
