// Package export provides functionality to export trace results to various formats.
package export

import (
	"encoding/json"
	"io"
	"time"

	"github.com/hervehildenbrand/gtrace/pkg/hop"
)

// ExportedTrace is the JSON representation of a trace result.
type ExportedTrace struct {
	Target        string        `json:"target"`
	TargetIP      string        `json:"targetIP"`
	Protocol      string        `json:"protocol,omitempty"`
	Source        string        `json:"source,omitempty"`
	ReachedTarget bool          `json:"reachedTarget"`
	StartTime     time.Time     `json:"startTime,omitempty"`
	EndTime       time.Time     `json:"endTime,omitempty"`
	Hops          []ExportedHop `json:"hops"`
}

// ExportedHop is the JSON representation of a single hop.
type ExportedHop struct {
	TTL        int              `json:"ttl"`
	IP         string           `json:"ip,omitempty"`
	Hostname   string           `json:"hostname,omitempty"`
	ASN        uint32           `json:"asn,omitempty"`
	ASOrg      string           `json:"asOrg,omitempty"`
	Country    string           `json:"country,omitempty"`
	City       string           `json:"city,omitempty"`
	Probes     []ExportedProbe  `json:"probes"`
	MPLS       []ExportedMPLS   `json:"mpls,omitempty"`
	AvgRTT     float64          `json:"avgRtt"`     // in ms
	LossPercent float64         `json:"lossPercent"`
}

// ExportedProbe is the JSON representation of a single probe.
type ExportedProbe struct {
	IP      string  `json:"ip,omitempty"`
	RTT     float64 `json:"rtt,omitempty"` // in ms
	Timeout bool    `json:"timeout,omitempty"`
}

// ExportedMPLS is the JSON representation of an MPLS label.
type ExportedMPLS struct {
	Label uint32 `json:"label"`
	Exp   uint8  `json:"exp"`
	S     bool   `json:"s"`
	TTL   uint8  `json:"ttl"`
}

// JSONExporter exports trace results to JSON format.
type JSONExporter struct {
	Pretty bool // Whether to pretty-print the JSON
}

// NewJSONExporter creates a new JSON exporter.
func NewJSONExporter() *JSONExporter {
	return &JSONExporter{
		Pretty: false,
	}
}

// Export writes the trace result as JSON to the writer.
func (e *JSONExporter) Export(w io.Writer, tr *hop.TraceResult) error {
	exported := e.convert(tr)

	encoder := json.NewEncoder(w)
	if e.Pretty {
		encoder.SetIndent("", "  ")
	}

	return encoder.Encode(exported)
}

// convert transforms a TraceResult to an ExportedTrace.
func (e *JSONExporter) convert(tr *hop.TraceResult) *ExportedTrace {
	exported := &ExportedTrace{
		Target:        tr.Target,
		TargetIP:      tr.TargetIP,
		Protocol:      tr.Protocol,
		Source:        tr.Source,
		ReachedTarget: tr.ReachedTarget,
		StartTime:     tr.StartTime,
		EndTime:       tr.EndTime,
		Hops:          make([]ExportedHop, 0, len(tr.Hops)),
	}

	for _, h := range tr.Hops {
		exported.Hops = append(exported.Hops, e.convertHop(h))
	}

	return exported
}

// convertHop transforms a Hop to an ExportedHop.
func (e *JSONExporter) convertHop(h *hop.Hop) ExportedHop {
	primaryIP := ""
	if ip := h.PrimaryIP(); ip != nil {
		primaryIP = ip.String()
	}

	exported := ExportedHop{
		TTL:         h.TTL,
		IP:          primaryIP,
		Hostname:    h.Enrichment.Hostname,
		ASN:         h.Enrichment.ASN,
		ASOrg:       h.Enrichment.ASOrg,
		Country:     h.Enrichment.Country,
		City:        h.Enrichment.City,
		Probes:      make([]ExportedProbe, 0, len(h.Probes)),
		AvgRTT:      float64(h.AvgRTT()) / float64(time.Millisecond),
		LossPercent: h.LossPercent(),
	}

	for _, p := range h.Probes {
		exported.Probes = append(exported.Probes, e.convertProbe(p))
	}

	for _, m := range h.MPLS {
		exported.MPLS = append(exported.MPLS, ExportedMPLS{
			Label: m.Label,
			Exp:   m.Exp,
			S:     m.S,
			TTL:   m.TTL,
		})
	}

	return exported
}

// convertProbe transforms a Probe to an ExportedProbe.
func (e *JSONExporter) convertProbe(p hop.Probe) ExportedProbe {
	ip := ""
	if p.IP != nil {
		ip = p.IP.String()
	}

	return ExportedProbe{
		IP:      ip,
		RTT:     float64(p.RTT) / float64(time.Millisecond),
		Timeout: p.Timeout,
	}
}
