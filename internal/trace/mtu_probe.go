package trace

import (
	"net"

	"github.com/hervehildenbrand/gtrace/pkg/hop"
)

// Active per-hop Path MTU Discovery state machine (tracepath-style).
//
// The engine sends one probe at a time with the DF bit set and feeds the
// outcome back as an MTUProbeEvent; Next returns either the next probe size
// or a final per-TTL verdict. The candidate size persists across TTLs
// because path MTU is monotonically non-increasing along the path.

// Probing bounds.
const (
	// MTUMaxProbesPerTTL caps the probes spent discovering one hop's MTU
	// (sized to fit a full black-hole search plus its confirmation probe).
	MTUMaxProbesPerTTL = 12

	// MTUConvergence is the binary-search window below which we stop.
	MTUConvergence = 8
)

// MTUEventType classifies the outcome of a single DF probe.
type MTUEventType int

const (
	// MTUEventFragNeeded is ICMP Fragmentation Needed (v4 type 3 code 4)
	// or ICMPv6 Packet Too Big; ReportedMTU carries the next-hop MTU (0 if absent).
	MTUEventFragNeeded MTUEventType = iota
	// MTUEventHopReply is any hop response at the probed size
	// (time exceeded, echo reply, or port unreachable).
	MTUEventHopReply
	// MTUEventTimeout means no response arrived.
	MTUEventTimeout
	// MTUEventEMSGSIZE means the local kernel refused the send;
	// ReportedMTU carries the kernel's cached path MTU (0 if unknown).
	MTUEventEMSGSIZE
)

// MTUProbeEvent is the outcome of one probe, fed back into the state machine.
type MTUProbeEvent struct {
	Type        MTUEventType
	ReportedMTU int
}

// MTUAction tells the engine what to do next.
type MTUAction int

const (
	// MTUActionProbe: send another probe at Decision.Size.
	MTUActionProbe MTUAction = iota
	// MTUActionDone: this TTL is finished; MTU/Blackhole are the verdict
	// (MTU 0 = hop unresponsive, nothing discovered).
	MTUActionDone
)

// MTUProbeDecision is the state machine's instruction to the engine.
type MTUProbeDecision struct {
	Action    MTUAction
	Size      int // next probe size when Action == MTUActionProbe
	MTU       int // discovered MTU when Action == MTUActionDone (0 = none)
	Blackhole bool
}

type mtuPhase int

const (
	mtuPhaseNormal mtuPhase = iota
	mtuPhaseRetry
	mtuPhaseSmallProbe
	mtuPhaseSearch
	mtuPhaseConfirm
)

// MTUProbeState tracks per-hop MTU discovery. Create once per trace with
// NewMTUProbeState and call NextTTL between hops; Candidate carries over.
type MTUProbeState struct {
	Candidate int // current path MTU estimate = next probe size
	MinSize   int // 68 for IPv4, 1280 for IPv6

	lastSize  int
	low, high int
	probes    int
	phase     mtuPhase
	blackhole bool
}

// NewMTUProbeState creates discovery state starting at startSize (typically
// the egress interface MTU) with the given protocol minimum.
func NewMTUProbeState(startSize, minSize int) *MTUProbeState {
	return &MTUProbeState{Candidate: startSize, MinSize: minSize, lastSize: startSize}
}

// NextTTL resets per-hop state while keeping the path MTU candidate.
func (s *MTUProbeState) NextTTL() {
	s.lastSize = s.Candidate
	s.probes = 0
	s.phase = mtuPhaseNormal
	s.blackhole = false
}

// Next consumes the outcome of the last probe and decides what to do.
func (s *MTUProbeState) Next(ev MTUProbeEvent) MTUProbeDecision {
	s.probes++
	switch s.phase {
	case mtuPhaseNormal, mtuPhaseRetry:
		switch ev.Type {
		case MTUEventHopReply:
			return s.done(s.Candidate)
		case MTUEventFragNeeded, MTUEventEMSGSIZE:
			return s.handleFragNeeded(ev.ReportedMTU)
		default: // timeout
			if s.phase == mtuPhaseNormal {
				s.phase = mtuPhaseRetry
				return s.probe(s.Candidate)
			}
			s.phase = mtuPhaseSmallProbe
			return s.probe(s.MinSize)
		}
	case mtuPhaseSmallProbe:
		if ev.Type == MTUEventHopReply {
			// Small probe passed where full-size silently vanished: black hole.
			s.blackhole = true
			return s.startSearch(s.MinSize, s.Candidate)
		}
		// Hop is simply unresponsive.
		return s.done(0)
	case mtuPhaseConfirm:
		// One probe back at the pre-search candidate decides whether the
		// silent drops were size-related or just a lossy/rate-limited hop.
		switch ev.Type {
		case MTUEventHopReply:
			s.blackhole = false
			return s.done(s.Candidate)
		case MTUEventFragNeeded, MTUEventEMSGSIZE:
			// ICMP is arriving after all: not a black hole.
			s.blackhole = false
			if m := ev.ReportedMTU; m >= s.MinSize && m < s.Candidate {
				return s.done(m)
			}
			return s.done(s.low)
		default: // timeout again: the black-hole verdict stands
			return s.done(s.low)
		}
	default: // mtuPhaseSearch
		switch ev.Type {
		case MTUEventHopReply:
			s.low = s.lastSize
		case MTUEventFragNeeded, MTUEventEMSGSIZE:
			if m := ev.ReportedMTU; m >= s.low && m < s.lastSize {
				// A trustworthy report mid-search pins the answer exactly.
				s.low, s.high = m, m
			} else {
				s.high = s.lastSize
			}
		default: // timeout
			s.high = s.lastSize
		}
		return s.searchStep()
	}
}

// handleFragNeeded processes a frag-needed/EMSGSIZE report in the fast path.
func (s *MTUProbeState) handleFragNeeded(reported int) MTUProbeDecision {
	if reported >= s.MinSize && reported < s.Candidate {
		s.Candidate = reported
		return s.probe(reported)
	}
	// Missing or garbage MTU value (RFC 1191 pre-dating routers): search.
	return s.startSearch(s.MinSize, s.lastSize)
}

func (s *MTUProbeState) startSearch(low, high int) MTUProbeDecision {
	s.low, s.high = low, high
	s.phase = mtuPhaseSearch
	return s.searchStep()
}

func (s *MTUProbeState) searchStep() MTUProbeDecision {
	if s.high-s.low < MTUConvergence {
		if s.blackhole {
			// Converged without any ICMP: verify the drops are really
			// size-related before condemning the hop (rate limiters
			// otherwise produce bogus black-hole verdicts).
			s.phase = mtuPhaseConfirm
			return s.probe(s.Candidate)
		}
		return s.done(s.low)
	}
	return s.probe(MTUSearchMidpoint(s.low, s.high))
}

// probe requests another probe unless the per-TTL budget is exhausted.
func (s *MTUProbeState) probe(size int) MTUProbeDecision {
	if s.probes >= MTUMaxProbesPerTTL {
		if s.phase == mtuPhaseSearch && !s.blackhole {
			return s.done(s.low) // low is the best confirmed size
		}
		// Unconfirmed black-hole search (or nothing confirmed at all):
		// report no MTU and keep the pre-search candidate intact so one
		// lossy hop cannot poison the rest of the path.
		s.blackhole = false
		return s.done(0)
	}
	s.lastSize = size
	return MTUProbeDecision{Action: MTUActionProbe, Size: size}
}

func (s *MTUProbeState) done(mtu int) MTUProbeDecision {
	if mtu > 0 {
		s.Candidate = mtu
	}
	return MTUProbeDecision{Action: MTUActionDone, MTU: mtu, Blackhole: s.blackhole && mtu > 0}
}

// classifyMTUProbe maps a probe outcome onto a state-machine event.
func classifyMTUProbe(pr *probeResult, err error) MTUProbeEvent {
	if err != nil {
		if isEMSGSIZE(err) {
			// ponytail: ReportedMTU left 0 (binary search recovers); query
			// IP_MTU getsockopt here if EMSGSIZE turns out common in practice.
			return MTUProbeEvent{Type: MTUEventEMSGSIZE}
		}
		return MTUProbeEvent{Type: MTUEventTimeout}
	}
	if pr == nil {
		return MTUProbeEvent{Type: MTUEventTimeout}
	}
	switch {
	case pr.ICMPType == 3 && pr.ICMPCode == 4: // IPv4 Fragmentation Needed
		return MTUProbeEvent{Type: MTUEventFragNeeded, ReportedMTU: pr.MTU}
	case pr.ICMPType == 2: // ICMPv6 Packet Too Big
		return MTUProbeEvent{Type: MTUEventFragNeeded, ReportedMTU: pr.MTU}
	default:
		return MTUProbeEvent{Type: MTUEventHopReply}
	}
}

// runMTUDiscovery drives the state machine for one TTL. send transmits a DF
// probe of the given total IP-layer size and returns the outcome. The
// returned probeResult is the last hop reply (nil if the hop never replied),
// so callers record the hop's identity rather than a frag-needed reporter's.
func runMTUDiscovery(state *MTUProbeState, send func(size int) (MTUProbeEvent, *probeResult)) (MTUProbeDecision, *probeResult) {
	size := state.Candidate
	var lastReply *probeResult
	for {
		ev, pr := send(size)
		if ev.Type == MTUEventHopReply && pr != nil {
			lastReply = pr
		}
		d := state.Next(ev)
		if d.Action == MTUActionDone {
			return d, lastReply
		}
		size = d.Size
	}
}

// newMTUStateForTarget seeds discovery state from the egress interface MTU.
func newMTUStateForTarget(target net.IP) *MTUProbeState {
	minSize := MinMTU
	if IsIPv6(target) {
		minSize = MinMTUv6
	}
	start := GetEgressMTU(target)
	if start < minSize {
		start = minSize
	}
	return NewMTUProbeState(start, minSize)
}

// recordMTUOutcome applies a per-TTL discovery verdict to the hop and
// reports whether the replying hop is the target.
func recordMTUOutcome(h *hop.Hop, d MTUProbeDecision, pr *probeResult, target net.IP) bool {
	reached := false
	if pr != nil && pr.IP != nil {
		h.Probes = append(h.Probes, hop.Probe{IP: pr.IP, RTT: pr.RTT, ResponseTTL: pr.ResponseTTL, IPID: pr.IPID, ICMPType: pr.ICMPType, ICMPCode: pr.ICMPCode, OriginalTTL: pr.OriginalTTL, TransportInfo: pr.TransportInfo})
		if len(pr.MPLS) > 0 {
			h.SetMPLS(pr.MPLS)
		}
		if pr.InterfaceInfo != nil {
			h.InterfaceInfo = pr.InterfaceInfo
		}
		reached = pr.IP.Equal(target)
	} else {
		h.AddTimeout()
	}
	if d.MTU > 0 {
		h.MTU = d.MTU
		h.MTUBlackhole = d.Blackhole
	}
	return reached
}
