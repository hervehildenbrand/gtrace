package trace

import (
	"net"
	"syscall"
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

func TestClassifyMTUProbe(t *testing.T) {
	tests := []struct {
		name     string
		pr       *probeResult
		err      error
		wantType MTUEventType
		wantMTU  int
	}{
		{"timeout error", nil, &timeoutError{}, MTUEventTimeout, 0},
		{"local EMSGSIZE", nil, syscall.EMSGSIZE, MTUEventEMSGSIZE, 0},
		{"v4 frag needed with MTU", &probeResult{ICMPType: 3, ICMPCode: 4, MTU: 1400}, nil, MTUEventFragNeeded, 1400},
		{"v4 frag needed without MTU", &probeResult{ICMPType: 3, ICMPCode: 4}, nil, MTUEventFragNeeded, 0},
		{"v6 packet too big", &probeResult{ICMPType: 2, MTU: 1300}, nil, MTUEventFragNeeded, 1300},
		{"time exceeded is hop reply", &probeResult{ICMPType: 11}, nil, MTUEventHopReply, 0},
		{"port unreachable is hop reply", &probeResult{ICMPType: 3, ICMPCode: 3}, nil, MTUEventHopReply, 0},
		{"echo reply is hop reply", &probeResult{}, nil, MTUEventHopReply, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := classifyMTUProbe(tt.pr, tt.err)
			if ev.Type != tt.wantType || ev.ReportedMTU != tt.wantMTU {
				t.Errorf("classifyMTUProbe() = {%v %d}, want {%v %d}", ev.Type, ev.ReportedMTU, tt.wantType, tt.wantMTU)
			}
		})
	}
}

func TestRunMTUDiscovery_ReturnsVerdictAndLastHopReply(t *testing.T) {
	s := NewMTUProbeState(1500, MinMTU)
	hopIP := net.ParseIP("10.0.0.1")
	send := func(size int) (MTUProbeEvent, *probeResult) {
		if size > 1400 {
			return MTUProbeEvent{Type: MTUEventFragNeeded, ReportedMTU: 1400},
				&probeResult{IP: net.ParseIP("10.0.0.9"), ICMPType: 3, ICMPCode: 4, MTU: 1400}
		}
		return MTUProbeEvent{Type: MTUEventHopReply}, &probeResult{IP: hopIP, ICMPType: 11}
	}
	d, pr := runMTUDiscovery(s, send)
	if d.MTU != 1400 {
		t.Errorf("MTU = %d, want 1400", d.MTU)
	}
	if pr == nil || !pr.IP.Equal(hopIP) {
		t.Errorf("last reply = %+v, want hop reply from %s (not the frag-needed reporter)", pr, hopIP)
	}
}

func TestRunMTUDiscovery_AllTimeouts_NilProbeResult(t *testing.T) {
	s := NewMTUProbeState(1500, MinMTU)
	send := func(size int) (MTUProbeEvent, *probeResult) {
		return MTUProbeEvent{Type: MTUEventTimeout}, nil
	}
	d, pr := runMTUDiscovery(s, send)
	if d.MTU != 0 || pr != nil {
		t.Errorf("got (MTU:%d, pr:%v), want (0, nil)", d.MTU, pr)
	}
}

func TestBuildEchoRequestForIP_MTUSizePadsToIPLayerSize(t *testing.T) {
	tracer := NewICMPTracer(&Config{})

	msg := tracer.buildEchoRequestForIP(1, 0, net.ParseIP("8.8.8.8"), 0, 600)
	b, err := msg.Marshal(nil)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if want := 600 - 20; len(b) != want { // IPv4 header is 20 bytes
		t.Errorf("v4 ICMP message = %d bytes, want %d (600 total - IP header)", len(b), want)
	}

	msg6 := tracer.buildEchoRequestForIP(1, 0, net.ParseIP("2001:db8::1"), 0, 1280)
	b6, err := msg6.Marshal(nil)
	if err != nil {
		t.Fatalf("marshal v6: %v", err)
	}
	if want := 1280 - 40; len(b6) != want { // IPv6 header is 40 bytes
		t.Errorf("v6 ICMP message = %d bytes, want %d (1280 total - IP header)", len(b6), want)
	}
}

func TestMTUProbeState_FragNeededEchoingProbeSize_FallsBackToSearch(t *testing.T) {
	// A broken router reports the probe size itself as the next-hop MTU,
	// which is no information at all: distrust it and binary search.
	s := NewMTUProbeState(1500, MinMTU)
	respond := pathWithMTU(1400, func(size int) MTUProbeEvent {
		return MTUProbeEvent{Type: MTUEventFragNeeded, ReportedMTU: size}
	})
	d, probes := driveTTL(t, s, respond)
	if d.MTU < 1400-MTUConvergence || d.MTU > 1400 {
		t.Errorf("MTU = %d, want within %d of 1400", d.MTU, MTUConvergence)
	}
	if d.Blackhole {
		t.Error("Blackhole = true, want false")
	}
	if probes > MTUMaxProbesPerTTL {
		t.Errorf("probes = %d, want <= %d", probes, MTUMaxProbesPerTTL)
	}
}

func TestMTUProbeState_RateLimitedHop_ConfirmationClearsBlackhole(t *testing.T) {
	// An ICMP-rate-limited hop: drops the first full-size probes and every
	// binary-search probe, but the final confirmation probe at the original
	// candidate gets through. Real-world case: 193.251.133.3 (Orange) gave
	// bogus "blackhole 112/828" verdicts without confirmation.
	s := NewMTUProbeState(1500, MinMTU)
	calls := 0
	respond := func(size int) MTUProbeEvent {
		calls++
		if size == MinMTU || (size == 1500 && calls > 3) {
			return MTUProbeEvent{Type: MTUEventHopReply}
		}
		return MTUProbeEvent{Type: MTUEventTimeout}
	}
	d, probes := driveTTL(t, s, respond)
	if d.MTU != 1500 || d.Blackhole {
		t.Errorf("Done = {MTU:%d Blackhole:%v}, want {MTU:1500 Blackhole:false} (confirmation passed => not size-related)", d.MTU, d.Blackhole)
	}
	if s.Candidate != 1500 {
		t.Errorf("Candidate = %d, want 1500 (lossy hop must not poison the path estimate)", s.Candidate)
	}
	if probes > MTUMaxProbesPerTTL {
		t.Errorf("probes = %d, want <= %d", probes, MTUMaxProbesPerTTL)
	}
}

func TestMTUProbeState_GenuineBlackhole_ConfirmationFails(t *testing.T) {
	// Size-dependent silent drop: the confirmation probe at the original
	// candidate times out too, so the blackhole verdict stands.
	s := NewMTUProbeState(1500, MinMTU)
	respond := pathWithMTU(1400, func(size int) MTUProbeEvent {
		return MTUProbeEvent{Type: MTUEventTimeout}
	})
	d, probes := driveTTL(t, s, respond)
	if !d.Blackhole || d.MTU < 1400-MTUConvergence || d.MTU > 1400 {
		t.Errorf("Done = {MTU:%d Blackhole:%v}, want blackhole with MTU within %d of 1400", d.MTU, d.Blackhole, MTUConvergence)
	}
	if probes > MTUMaxProbesPerTTL {
		t.Errorf("probes = %d, want <= %d", probes, MTUMaxProbesPerTTL)
	}
}

func TestMTUProbeState_UnconfirmedSearchBail_DoesNotPoisonPath(t *testing.T) {
	// Search range too large to converge within the probe budget: without a
	// failed confirmation there is no verdict - report nothing and keep the
	// pre-search candidate for later hops.
	s := NewMTUProbeState(65536, MinMTU)
	respond := func(size int) MTUProbeEvent {
		if size == MinMTU {
			return MTUProbeEvent{Type: MTUEventHopReply}
		}
		return MTUProbeEvent{Type: MTUEventTimeout}
	}
	d, probes := driveTTL(t, s, respond)
	if d.MTU != 0 || d.Blackhole {
		t.Errorf("Done = {MTU:%d Blackhole:%v}, want {MTU:0 Blackhole:false} (nothing confirmed)", d.MTU, d.Blackhole)
	}
	if s.Candidate != 65536 {
		t.Errorf("Candidate = %d, want 65536 (unconfirmed search must not lower the path estimate)", s.Candidate)
	}
	if probes > MTUMaxProbesPerTTL {
		t.Errorf("probes = %d, want <= %d", probes, MTUMaxProbesPerTTL)
	}
}
