package trace

import (
	"testing"
)

// driveTTL runs the state machine for one TTL against a simulated path.
// respond maps a probe size to the event the path would produce.
// Returns the final decision and the number of probes sent.
func driveTTL(t *testing.T, s *MTUProbeState, respond func(size int) MTUProbeEvent) (MTUProbeDecision, int) {
	t.Helper()
	size := s.Candidate
	probes := 0
	for probes < 50 { // runaway guard well above MTUMaxProbesPerTTL
		probes++
		d := s.Next(respond(size))
		if d.Action == MTUActionDone {
			return d, probes
		}
		size = d.Size
	}
	t.Fatal("state machine did not terminate within 50 probes")
	return MTUProbeDecision{}, probes
}

// pathWithMTU simulates a path segment with the given true MTU.
// over is the event produced when the probe exceeds the MTU.
func pathWithMTU(trueMTU int, over func(size int) MTUProbeEvent) func(size int) MTUProbeEvent {
	return func(size int) MTUProbeEvent {
		if size > trueMTU {
			return over(size)
		}
		return MTUProbeEvent{Type: MTUEventHopReply}
	}
}

func TestMTUProbeState_CleanPath_ConfirmsCandidateInOneProbe(t *testing.T) {
	s := NewMTUProbeState(1500, MinMTU)
	d, probes := driveTTL(t, s, pathWithMTU(1500, nil))
	if d.MTU != 1500 || d.Blackhole {
		t.Errorf("Done = {MTU:%d Blackhole:%v}, want {MTU:1500 Blackhole:false}", d.MTU, d.Blackhole)
	}
	if probes != 1 {
		t.Errorf("probes = %d, want 1", probes)
	}
}

func TestMTUProbeState_FragNeededWithMTU_LowersCandidate(t *testing.T) {
	s := NewMTUProbeState(1500, MinMTU)
	respond := pathWithMTU(1400, func(size int) MTUProbeEvent {
		return MTUProbeEvent{Type: MTUEventFragNeeded, ReportedMTU: 1400}
	})
	d, probes := driveTTL(t, s, respond)
	if d.MTU != 1400 || d.Blackhole {
		t.Errorf("Done = {MTU:%d Blackhole:%v}, want {MTU:1400 Blackhole:false}", d.MTU, d.Blackhole)
	}
	if probes != 2 {
		t.Errorf("probes = %d, want 2 (oversized then confirm)", probes)
	}
}

func TestMTUProbeState_FragNeededZeroMTU_BinarySearches(t *testing.T) {
	s := NewMTUProbeState(1500, MinMTU)
	respond := pathWithMTU(1400, func(size int) MTUProbeEvent {
		return MTUProbeEvent{Type: MTUEventFragNeeded, ReportedMTU: 0}
	})
	d, probes := driveTTL(t, s, respond)
	if d.MTU < 1400-MTUConvergence || d.MTU > 1400 {
		t.Errorf("MTU = %d, want within %d of 1400", d.MTU, MTUConvergence)
	}
	if d.Blackhole {
		t.Error("Blackhole = true, want false (ICMP was received, just without MTU)")
	}
	if probes > MTUMaxProbesPerTTL {
		t.Errorf("probes = %d, want <= %d", probes, MTUMaxProbesPerTTL)
	}
}

func TestMTUProbeState_SilentDrop_DetectsBlackhole(t *testing.T) {
	s := NewMTUProbeState(1500, MinMTU)
	respond := pathWithMTU(1400, func(size int) MTUProbeEvent {
		return MTUProbeEvent{Type: MTUEventTimeout}
	})
	d, probes := driveTTL(t, s, respond)
	if !d.Blackhole {
		t.Error("Blackhole = false, want true (oversized dropped silently, small passed)")
	}
	if d.MTU < 1400-MTUConvergence || d.MTU > 1400 {
		t.Errorf("MTU = %d, want within %d of 1400", d.MTU, MTUConvergence)
	}
	if probes > MTUMaxProbesPerTTL {
		t.Errorf("probes = %d, want <= %d", probes, MTUMaxProbesPerTTL)
	}
}

func TestMTUProbeState_AllTimeouts_ReportsNoMTU(t *testing.T) {
	s := NewMTUProbeState(1500, MinMTU)
	respond := func(size int) MTUProbeEvent {
		return MTUProbeEvent{Type: MTUEventTimeout}
	}
	d, probes := driveTTL(t, s, respond)
	if d.MTU != 0 || d.Blackhole {
		t.Errorf("Done = {MTU:%d Blackhole:%v}, want {MTU:0 Blackhole:false} for unresponsive hop", d.MTU, d.Blackhole)
	}
	if probes != 3 {
		t.Errorf("probes = %d, want 3 (candidate, retry, min-size)", probes)
	}
}

func TestMTUProbeState_LocalEMSGSIZE_TreatedAsFragNeeded(t *testing.T) {
	s := NewMTUProbeState(1500, MinMTU)
	respond := pathWithMTU(1450, func(size int) MTUProbeEvent {
		return MTUProbeEvent{Type: MTUEventEMSGSIZE, ReportedMTU: 1450}
	})
	d, probes := driveTTL(t, s, respond)
	if d.MTU != 1450 || d.Blackhole {
		t.Errorf("Done = {MTU:%d Blackhole:%v}, want {MTU:1450 Blackhole:false}", d.MTU, d.Blackhole)
	}
	if probes != 2 {
		t.Errorf("probes = %d, want 2", probes)
	}
}

func TestMTUProbeState_InvalidReportedMTU_FallsBackToSearch(t *testing.T) {
	// Router reports garbage MTU below the minimum: distrust it, search instead.
	s := NewMTUProbeState(1500, MinMTU)
	respond := pathWithMTU(1400, func(size int) MTUProbeEvent {
		return MTUProbeEvent{Type: MTUEventFragNeeded, ReportedMTU: 40}
	})
	d, probes := driveTTL(t, s, respond)
	if d.MTU < 1400-MTUConvergence || d.MTU > 1400 {
		t.Errorf("MTU = %d, want within %d of 1400", d.MTU, MTUConvergence)
	}
	if probes > MTUMaxProbesPerTTL {
		t.Errorf("probes = %d, want <= %d", probes, MTUMaxProbesPerTTL)
	}
}

func TestMTUProbeState_CandidatePersistsAcrossTTLs(t *testing.T) {
	s := NewMTUProbeState(1500, MinMTU)
	respond := pathWithMTU(1400, func(size int) MTUProbeEvent {
		return MTUProbeEvent{Type: MTUEventFragNeeded, ReportedMTU: 1400}
	})
	d, _ := driveTTL(t, s, respond)
	if d.MTU != 1400 {
		t.Fatalf("first TTL MTU = %d, want 1400", d.MTU)
	}

	s.NextTTL()
	if s.Candidate != 1400 {
		t.Errorf("Candidate after NextTTL = %d, want 1400 (PMTU is monotonic along the path)", s.Candidate)
	}
	// Next hop passes at the lowered candidate in a single probe.
	d, probes := driveTTL(t, s, pathWithMTU(1400, nil))
	if d.MTU != 1400 || probes != 1 {
		t.Errorf("next TTL = {MTU:%d probes:%d}, want {MTU:1400 probes:1}", d.MTU, probes)
	}
}

func TestMTUProbeState_AdversarialFragNeeded_BoundedProbes(t *testing.T) {
	// A router that frag-needs every size with size-1 must not cause
	// unbounded probing; the TTL gives up but keeps the lowered estimate.
	s := NewMTUProbeState(1500, MinMTU)
	respond := func(size int) MTUProbeEvent {
		return MTUProbeEvent{Type: MTUEventFragNeeded, ReportedMTU: size - 1}
	}
	d, probes := driveTTL(t, s, respond)
	if d.Action != MTUActionDone {
		t.Error("expected termination via Done")
	}
	if probes > MTUMaxProbesPerTTL {
		t.Errorf("probes = %d, want <= %d", probes, MTUMaxProbesPerTTL)
	}
	if s.Candidate >= 1500 {
		t.Errorf("Candidate = %d, want lowered below 1500 (frag-needed evidence retained)", s.Candidate)
	}
}
