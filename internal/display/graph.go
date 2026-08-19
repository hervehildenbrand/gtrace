package display

import (
	"fmt"
	"time"

	"github.com/hervehildenbrand/gtrace/pkg/hop"
)

// graphNode is one router (or synthetic source / timeout placeholder) in the
// merged path DAG. Nodes are keyed by bare IP so the same router reached from
// several sources becomes a single node — a convergence point.
type graphNode struct {
	key       string
	label     string // IP string, source label, or "*" for timeouts
	enrich    hop.Enrichment
	rtt       time.Duration
	loss      float64
	hasMPLS   bool
	nat       bool
	sources   map[int]bool // source indices whose path crosses this node
	depth     int          // max TTL across sources (0 for source nodes)
	isSource  bool
	isTarget  bool
	isTimeout bool
}

type graphEdge struct {
	sources map[int]bool
}

// pathGraph is the merged DAG built from one or more trace results.
type pathGraph struct {
	nodes        map[string]*graphNode
	edges        map[[2]string]*graphEdge
	sourceLabels []string
}

func (g *pathGraph) touchNode(n *graphNode, source int) *graphNode {
	existing := g.nodes[n.key]
	if existing == nil {
		n.sources = map[int]bool{source: true}
		g.nodes[n.key] = n
		return n
	}
	existing.sources[source] = true
	if n.depth > existing.depth {
		existing.depth = n.depth
	}
	return existing
}

func (g *pathGraph) addEdge(from, to string, source int) {
	key := [2]string{from, to}
	e := g.edges[key]
	if e == nil {
		e = &graphEdge{sources: map[int]bool{}}
		g.edges[key] = e
	}
	e.sources[source] = true
}

func allTimeout(h *hop.Hop) bool {
	for _, p := range h.Probes {
		if !p.Timeout {
			return false
		}
	}
	return true
}

// ipAvgRTT averages the RTTs of the probes answering from ip.
func ipAvgRTT(h *hop.Hop, ip string) time.Duration {
	var total time.Duration
	var count int
	for _, p := range h.Probes {
		if !p.Timeout && p.IP != nil && p.IP.String() == ip {
			total += p.RTT
			count++
		}
	}
	if count == 0 {
		return 0
	}
	return total / time.Duration(count)
}

// distinctIPs returns the distinct responding IPs of a hop in probe order.
func distinctIPs(h *hop.Hop) []string {
	var ips []string
	seen := map[string]bool{}
	for _, p := range h.Probes {
		if p.Timeout || p.IP == nil {
			continue
		}
		s := p.IP.String()
		if !seen[s] {
			seen[s] = true
			ips = append(ips, s)
		}
	}
	return ips
}

// buildGraph merges trace results into a path DAG. Within a source,
// consecutive hop node sets are fully connected.
// ponytail: mesh edges overstate what ICMP tells us; FlowID-based per-flow
// path reconstruction is the upgrade path if exact ECMP wiring matters.
func buildGraph(results []*hop.TraceResult) *pathGraph {
	g := &pathGraph{
		nodes:        map[string]*graphNode{},
		edges:        map[[2]string]*graphEdge{},
		sourceLabels: make([]string, len(results)),
	}

	for i, tr := range results {
		label := tr.Source
		if label == "" {
			label = "Local"
		}
		g.sourceLabels[i] = label

		srcKey := fmt.Sprintf("src:%d", i)
		g.touchNode(&graphNode{key: srcKey, label: label, isSource: true}, i)

		// Trim trailing all-timeout hops (same convention as MTR display).
		hops := tr.Hops
		for len(hops) > 0 && allTimeout(hops[len(hops)-1]) {
			hops = hops[:len(hops)-1]
		}

		visits := map[string]int{} // per-source IP revisit counter (loop guard)
		prev := []string{srcKey}
		for _, h := range hops {
			var cur []string
			if allTimeout(h) {
				key := fmt.Sprintf("t:%d:%d", i, h.TTL)
				g.touchNode(&graphNode{key: key, label: "*", depth: h.TTL, isTimeout: true}, i)
				cur = []string{key}
			} else {
				ips := distinctIPs(h)
				ecmp := len(ips) > 1
				for _, ip := range ips {
					key := ip
					if n := visits[ip]; n > 0 {
						key = fmt.Sprintf("%s#%d", ip, n)
					}
					node := &graphNode{
						key:     key,
						label:   ip,
						enrich:  h.Enrichment,
						rtt:     ipAvgRTT(h, ip),
						depth:   h.TTL,
						hasMPLS: len(h.MPLS) > 0,
						nat:     h.NAT,
					}
					if !ecmp {
						// Loss is per-hop; with ECMP siblings it cannot be
						// attributed to a single IP.
						node.loss = h.LossPercent()
					}
					g.touchNode(node, i)
					cur = append(cur, key)
				}
				for _, ip := range ips {
					visits[ip]++
				}
			}
			for _, p := range prev {
				for _, c := range cur {
					g.addEdge(p, c, i)
				}
			}
			prev = cur
		}

		if tr.ReachedTarget {
			if n := g.nodes[tr.TargetIP]; n != nil {
				n.isTarget = true
			}
		}
	}

	return g
}
