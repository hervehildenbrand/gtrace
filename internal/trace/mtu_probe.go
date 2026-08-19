package trace

// Active per-hop Path MTU Discovery state machine (tracepath-style).
//
// The engine sends one probe at a time with the DF bit set and feeds the
// outcome back as an MTUProbeEvent; Next returns either the next probe size
// or a final per-TTL verdict. The candidate size persists across TTLs
// because path MTU is monotonically non-increasing along the path.

// Probing bounds.
const (
	// MTUMaxProbesPerTTL caps the probes spent discovering one hop's MTU.
	MTUMaxProbesPerTTL = 10

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
		return s.done(s.low)
	}
	return s.probe(MTUSearchMidpoint(s.low, s.high))
}

// probe requests another probe unless the per-TTL budget is exhausted.
func (s *MTUProbeState) probe(size int) MTUProbeDecision {
	if s.probes >= MTUMaxProbesPerTTL {
		if s.phase == mtuPhaseSearch {
			return s.done(s.low) // low is the best confirmed size
		}
		return s.done(0) // nothing confirmed; lowered Candidate is retained
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
