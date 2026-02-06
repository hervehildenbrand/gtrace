package trace

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/hervehildenbrand/gtrace/pkg/hop"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// ICMPTracer implements traceroute using ICMP Echo Request.
type ICMPTracer struct {
	config *Config
	id     int
}

// NewICMPTracer creates a new ICMP tracer with the given configuration.
func NewICMPTracer(cfg *Config) *ICMPTracer {
	return &ICMPTracer{
		config: cfg,
		id:     os.Getpid() & 0xffff,
	}
}

// Trace performs an ICMP traceroute to the target IP.
// Supports both IPv4 and IPv6 targets.
func (t *ICMPTracer) Trace(ctx context.Context, target net.IP, callback HopCallback) (*hop.TraceResult, error) {
	result := hop.NewTraceResult(target.String(), target.String())
	result.Protocol = string(ProtocolICMP)
	result.StartTime = time.Now()

	// Open ICMP connection based on IP version
	proto := ICMPProtocol(target)
	listenAddr := ListenAddress(target)
	conn, err := icmp.ListenPacket(proto, listenAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to open ICMP socket: %w (try running with sudo)", err)
	}
	defer conn.Close()

	for ttl := 1; ttl <= t.config.MaxHops; ttl++ {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		h := hop.NewHop(ttl)
		reached := false

		for i := 0; i < t.config.PacketsPerHop; i++ {
			pr, err := t.sendProbe(conn, target, ttl, i)
			if err != nil {
				if errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
					h.AddTimeout()
				} else {
					// Other errors - still record as timeout for display
					h.AddTimeout()
				}
				continue
			}

			if t.config.DetectNAT && pr.ResponseTTL > 0 {
				h.AddProbeWithTTL(pr.IP, pr.RTT, pr.ResponseTTL)
			} else {
				h.AddProbe(pr.IP, pr.RTT)
			}

			// Set MPLS labels if discovered (first probe with labels wins)
			if len(pr.MPLS) > 0 && len(h.MPLS) == 0 {
				h.SetMPLS(pr.MPLS)
			}

			if pr.IP.Equal(target) {
				reached = true
			}
		}

		// NAT detection via TTL analysis
		if t.config.DetectNAT {
			for _, p := range h.Probes {
				if !p.Timeout && p.ResponseTTL > 0 {
					expectedTTL := 64 - ttl // Assume common Linux/macOS default
					if DetectNATFromTTL(expectedTTL, p.ResponseTTL) {
						h.NAT = true
						break
					}
				}
			}
		}

		result.AddHop(h)
		if callback != nil {
			callback(h)
		}

		if reached {
			result.ReachedTarget = true
			break
		}
	}

	result.EndTime = time.Now()
	return result, nil
}

// probeResult holds the result of a single probe including MPLS labels.
type probeResult struct {
	IP          net.IP
	RTT         time.Duration
	MPLS        []hop.MPLSLabel
	ResponseTTL int // TTL from response packet (for NAT detection)
	MTU         int // Discovered MTU from Fragmentation Needed
}

// sendProbe sends a single ICMP probe and waits for response.
// Supports both IPv4 and IPv6 targets.
func (t *ICMPTracer) sendProbe(conn *icmp.PacketConn, target net.IP, ttl, seq int) (*probeResult, error) {
	isV6 := IsIPv6(target)

	// Set TTL/Hop Limit for this probe
	if isV6 {
		if err := conn.IPv6PacketConn().SetHopLimit(ttl); err != nil {
			return nil, fmt.Errorf("failed to set hop limit: %w", err)
		}
	} else {
		if err := conn.IPv4PacketConn().SetTTL(ttl); err != nil {
			return nil, fmt.Errorf("failed to set TTL: %w", err)
		}
	}

	// Build and send ICMP Echo Request
	msg := t.buildEchoRequestForIP(ttl, seq, target)
	msgBytes, err := msg.Marshal(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ICMP message: %w", err)
	}

	start := time.Now()

	_, err = conn.WriteTo(msgBytes, &net.IPAddr{IP: target})
	if err != nil {
		return nil, fmt.Errorf("failed to send ICMP: %w", err)
	}

	// Set read deadline
	deadline := start.Add(t.config.Timeout)
	if err := conn.SetReadDeadline(deadline); err != nil {
		return nil, fmt.Errorf("failed to set deadline: %w", err)
	}

	// Protocol number for parsing ICMP messages
	protoNum := ICMPProtocolNum(target)
	// IP header size for extracting original packet info
	ipHdrSize := IPHeaderSize(target)

	// Enable TTL control messages for NAT detection (IPv4 only)
	if !isV6 && t.config.DetectNAT {
		_ = conn.IPv4PacketConn().SetControlMessage(ipv4.FlagTTL, true)
	}

	// Wait for response
	reply := make([]byte, 1500)
	for {
		var n int
		var peer net.Addr
		var responseTTL int

		if !isV6 && t.config.DetectNAT {
			var cm *ipv4.ControlMessage
			n, cm, peer, err = conn.IPv4PacketConn().ReadFrom(reply)
			if cm != nil {
				responseTTL = cm.TTL
			}
		} else {
			n, peer, err = conn.ReadFrom(reply)
		}
		if err != nil {
			return nil, err
		}

		end := time.Now()
		rtt := t.calculateRTT(start, end)

		// Parse the response
		rm, err := icmp.ParseMessage(protoNum, reply[:n])
		if err != nil {
			continue // Ignore malformed packets
		}

		peerIP := peer.(*net.IPAddr).IP

		// Check for Echo Reply (target reached)
		if isEchoReply(rm.Type, target) {
			if body, ok := rm.Body.(*icmp.Echo); ok {
				if body.ID == t.id {
					return &probeResult{IP: peerIP, RTT: rtt, ResponseTTL: responseTTL}, nil
				}
			}
		}

		// Check for Time Exceeded (intermediate hop)
		if isTimeExceeded(rm.Type, target) {
			if body, ok := rm.Body.(*icmp.TimeExceeded); ok {
				// The Data field contains the original IP header + first 8 bytes of payload
				// For IPv4: 20 byte header + 8 bytes = 28 minimum
				// For IPv6: 40 byte header + 8 bytes = 48 minimum
				minLen := ipHdrSize + 8
				if len(body.Data) >= minLen {
					// Original ICMP ID is at offset ipHdrSize+4 and ipHdrSize+5
					origID := int(body.Data[ipHdrSize+4])<<8 | int(body.Data[ipHdrSize+5])
					if origID == t.id {
						// Extract MPLS labels from the raw ICMP data
						var mplsLabels []hop.MPLSLabel
						if n > 8 {
							mplsLabels = ExtractMPLSFromICMP(reply[8:n])
						}
						return &probeResult{IP: peerIP, RTT: rtt, MPLS: mplsLabels, ResponseTTL: responseTTL}, nil
					}
				}
			}
		}

		// Check for Destination Unreachable
		if isDestUnreachable(rm.Type, target) {
			if body, ok := rm.Body.(*icmp.DstUnreach); ok {
				minLen := ipHdrSize + 8
				if len(body.Data) >= minLen {
					origID := int(body.Data[ipHdrSize+4])<<8 | int(body.Data[ipHdrSize+5])
					if origID == t.id {
						return &probeResult{IP: peerIP, RTT: rtt, ResponseTTL: responseTTL}, nil
					}
				}
			}
		}

		// Check if we've exceeded deadline
		if time.Now().After(deadline) {
			return nil, context.DeadlineExceeded
		}
	}
}

// buildEchoRequest creates an ICMP Echo Request message (IPv4 only, for backward compatibility).
func (t *ICMPTracer) buildEchoRequest(ttl, seq int) *icmp.Message {
	return &icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   t.id,
			Seq:  seq,
			Data: []byte(fmt.Sprintf("gtr-%d-%d-%d", time.Now().UnixNano(), ttl, seq)),
		},
	}
}

// buildEchoRequestForIP creates an ICMP Echo Request message for the given IP version.
func (t *ICMPTracer) buildEchoRequestForIP(ttl, seq int, target net.IP) *icmp.Message {
	var msgType icmp.Type
	if IsIPv6(target) {
		msgType = ipv6.ICMPTypeEchoRequest
	} else {
		msgType = ipv4.ICMPTypeEcho
	}

	return &icmp.Message{
		Type: msgType,
		Code: 0,
		Body: &icmp.Echo{
			ID:   t.id,
			Seq:  seq,
			Data: []byte(fmt.Sprintf("gtr-%d-%d-%d", time.Now().UnixNano(), ttl, seq)),
		},
	}
}

// calculateRTT computes the round-trip time.
func (t *ICMPTracer) calculateRTT(start, end time.Time) time.Duration {
	return end.Sub(start)
}

// isTargetReached checks if the ICMP type indicates target reached (IPv4 only, for backward compatibility).
func (t *ICMPTracer) isTargetReached(msgType icmp.Type) bool {
	return msgType == ipv4.ICMPTypeEchoReply
}

// isTargetReachedForIP checks if the ICMP type indicates target reached for the given IP version.
func (t *ICMPTracer) isTargetReachedForIP(msgType icmp.Type, target net.IP) bool {
	return isEchoReply(msgType, target)
}

// getICMPID returns the ICMP identifier for this tracer.
func (t *ICMPTracer) getICMPID() int {
	return t.id
}

// isTimeout checks if an error is a timeout error.
func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	netErr, ok := err.(net.Error)
	return ok && netErr.Timeout()
}

// isTimeExceeded checks if the ICMP type is Time Exceeded for the given IP version.
func isTimeExceeded(msgType icmp.Type, target net.IP) bool {
	if IsIPv6(target) {
		return msgType == ipv6.ICMPTypeTimeExceeded
	}
	return msgType == ipv4.ICMPTypeTimeExceeded
}

// isEchoReply checks if the ICMP type is Echo Reply for the given IP version.
func isEchoReply(msgType icmp.Type, target net.IP) bool {
	if IsIPv6(target) {
		return msgType == ipv6.ICMPTypeEchoReply
	}
	return msgType == ipv4.ICMPTypeEchoReply
}

// isDestUnreachable checks if the ICMP type is Destination Unreachable for the given IP version.
func isDestUnreachable(msgType icmp.Type, target net.IP) bool {
	if IsIPv6(target) {
		return msgType == ipv6.ICMPTypeDestinationUnreachable
	}
	return msgType == ipv4.ICMPTypeDestinationUnreachable
}
