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

	// Open ICMP connection based on IP version. net.ListenPacket (rather
	// than icmp.ListenPacket) exposes the fd so the DF bit can be set.
	proto := ICMPProtocol(target)
	listenAddr := ListenAddress(target)
	pc, err := net.ListenPacket(proto, listenAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to open ICMP socket: %w (try running with sudo)", err)
	}
	defer pc.Close()

	conn := &icmpConn{pc: pc}
	if IsIPv6(target) {
		conn.p6 = ipv6.NewPacketConn(pc)
	} else {
		conn.p4 = ipv4.NewPacketConn(pc)
	}

	var mtuState *MTUProbeState
	if t.config.DiscoverMTU {
		if err := applyDontFragment(pc, IsIPv6(target)); err != nil {
			return nil, fmt.Errorf("failed to set DF bit: %w", err)
		}
		mtuState = newMTUStateForTarget(target)
	}

	for ttl := 1; ttl <= t.config.MaxHops; ttl++ {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		h := hop.NewHop(ttl)
		reached := false

		// When ECMP flows are enabled, use them as probe count with flow IDs
		probeCount := t.config.PacketsPerHop
		if t.config.ECMPFlows > 0 {
			probeCount = t.config.ECMPFlows
		}

		if mtuState != nil {
			// Active MTU discovery drives its own probe loop for this TTL.
			mtuState.NextTTL()
			d, pr := runMTUDiscovery(mtuState, func(size int) (MTUProbeEvent, *probeResult) {
				pr, err := t.sendProbe(conn, target, ttl, 0, 0, size)
				return classifyMTUProbe(pr, err), pr
			})
			if recordMTUOutcome(h, d, pr, target) {
				reached = true
			}
		}

		for i := 0; mtuState == nil && i < probeCount; i++ {
			flowID := 0
			if t.config.ECMPFlows > 0 {
				flowID = i + 1
			}
			pr, err := t.sendProbe(conn, target, ttl, i, flowID, 0)
			if err != nil {
				if errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
					h.AddTimeout()
				} else {
					// Other errors - still record as timeout for display
					h.AddTimeout()
				}
				continue
			}

			probe := hop.Probe{IP: pr.IP, RTT: pr.RTT, ResponseTTL: pr.ResponseTTL, IPID: pr.IPID, ICMPType: pr.ICMPType, ICMPCode: pr.ICMPCode, OriginalTTL: pr.OriginalTTL, FlowID: flowID, TransportInfo: pr.TransportInfo}
			h.Probes = append(h.Probes, probe)

			// Set MPLS labels if discovered (first probe with labels wins)
			if len(pr.MPLS) > 0 && len(h.MPLS) == 0 {
				h.SetMPLS(pr.MPLS)
			}

			// Set MTU if discovered
			if pr.MTU > 0 && h.MTU == 0 {
				h.MTU = pr.MTU
			}

			// Set interface info if discovered (first probe with info wins)
			if pr.InterfaceInfo != nil && h.InterfaceInfo == nil {
				h.InterfaceInfo = pr.InterfaceInfo
			}

			if pr.IP.Equal(target) {
				reached = true
			}
		}

		// NAT detection: IP-based (Tier 1) and TTL-based (Tier 2) only.
		// IP ID analysis (Tier 3) is not used because ICMP sockets don't expose
		// the response packet's IP ID — we can only see our own probe's IP ID
		// reflected in the ICMP error, which is meaningless for NAT detection.
		if t.config.DetectNAT {
			for _, p := range h.Probes {
				if p.Timeout || p.IP == nil {
					continue
				}
				if DetectNATFromIP(p.IP, ttl) {
					h.NAT = true
					break
				}
				if p.ResponseTTL > 0 && DetectNATFromTTL(ttl, p.ResponseTTL) {
					h.NAT = true
					break
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

	if mtuState != nil && result.ReachedTarget {
		result.PathMTU = mtuState.Candidate
	}

	result.EndTime = time.Now()
	return result, nil
}

// probeResult holds the result of a single probe including MPLS labels.
type probeResult struct {
	IP            net.IP
	RTT           time.Duration
	MPLS          []hop.MPLSLabel
	ResponseTTL   int                // TTL from response packet (for NAT detection)
	MTU           int                // Discovered MTU from Fragmentation Needed
	IPID          uint16             // IP ID from original datagram in ICMP error
	ICMPType      int                // ICMP response message type
	ICMPCode      int                // ICMP response message code
	OriginalTTL   int                // TTL from original datagram in ICMP error (-1 = not set)
	InterfaceInfo *hop.InterfaceInfo // RFC 5837 interface info (nil if not available)
	TransportInfo *hop.TransportInfo // Decoded transport header info (nil if --decode not used)
}

// ExtractIPID extracts the IP Identification field from an original IP header
// contained in an ICMP error response's body.Data. Bytes 4-5 of the IPv4 header.
func ExtractIPID(data []byte) uint16 {
	if len(data) < 6 {
		return 0
	}
	return uint16(data[4])<<8 | uint16(data[5])
}

// icmpConn wraps the raw ICMP socket with version-specific control access.
type icmpConn struct {
	pc net.PacketConn
	p4 *ipv4.PacketConn // non-nil for IPv4 targets
	p6 *ipv6.PacketConn // non-nil for IPv6 targets
}

// sendProbe sends a single ICMP probe and waits for response.
// Supports both IPv4 and IPv6 targets. flowID > 0 varies the payload for ECMP
// diversity. mtuSize > 0 pads the probe to that total IP-layer size.
func (t *ICMPTracer) sendProbe(conn *icmpConn, target net.IP, ttl, seq, flowID, mtuSize int) (*probeResult, error) {
	isV6 := IsIPv6(target)

	// Set TTL/Hop Limit for this probe
	if isV6 {
		if err := conn.p6.SetHopLimit(ttl); err != nil {
			return nil, fmt.Errorf("failed to set hop limit: %w", err)
		}
	} else {
		if err := conn.p4.SetTTL(ttl); err != nil {
			return nil, fmt.Errorf("failed to set TTL: %w", err)
		}
	}

	// Build and send ICMP Echo Request
	msg := t.buildEchoRequestForIP(ttl, seq, target, flowID, mtuSize)
	msgBytes, err := msg.Marshal(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ICMP message: %w", err)
	}

	start := time.Now()

	_, err = conn.pc.WriteTo(msgBytes, &net.IPAddr{IP: target})
	if err != nil {
		return nil, fmt.Errorf("failed to send ICMP: %w", err)
	}

	// Set read deadline
	deadline := start.Add(t.config.Timeout)
	if err := conn.pc.SetReadDeadline(deadline); err != nil {
		return nil, fmt.Errorf("failed to set deadline: %w", err)
	}

	// Protocol number for parsing ICMP messages
	protoNum := ICMPProtocolNum(target)
	// IP header size for extracting original packet info
	ipHdrSize := IPHeaderSize(target)

	// Enable TTL control messages for NAT detection (IPv4 only)
	if !isV6 && t.config.DetectNAT {
		_ = conn.p4.SetControlMessage(ipv4.FlagTTL, true)
	}

	// Wait for response. Echo replies mirror the probe size, which in MTU
	// mode can exceed 1500, so size for any IP packet.
	reply := make([]byte, 65535)
	for {
		var n int
		var peer net.Addr
		var responseTTL int

		if !isV6 && t.config.DetectNAT {
			var cm *ipv4.ControlMessage
			n, cm, peer, err = conn.p4.ReadFrom(reply)
			if cm != nil {
				responseTTL = cm.TTL
			}
		} else {
			n, peer, err = conn.pc.ReadFrom(reply)
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
						// Extract ICMP extensions (MPLS + Interface Info)
						var mplsLabels []hop.MPLSLabel
						var ifInfo *hop.InterfaceInfo
						if n > 8 {
							if ext := ExtractICMPExtensionsFromData(reply[8:n]); ext != nil {
								mplsLabels = ext.MPLS
								ifInfo = ext.InterfaceInfo
							}
						}
						ipid := ExtractIPID(body.Data)
						origTTL := ExtractOriginalTTL(body.Data)
						var transportInfo *hop.TransportInfo
						if t.config.Decode {
							transportInfo = ExtractTransportInfo(body.Data, ipHdrSize, string(t.config.Protocol))
						}
						return &probeResult{IP: peerIP, RTT: rtt, MPLS: mplsLabels, ResponseTTL: responseTTL, IPID: ipid, ICMPType: 11, ICMPCode: rm.Code, OriginalTTL: origTTL, InterfaceInfo: ifInfo, TransportInfo: transportInfo}, nil
					}
				}
			}
		}

		// Check for Packet Too Big (IPv6 path MTU discovery)
		if isPacketTooBig(rm.Type, target) {
			if body, ok := rm.Body.(*icmp.PacketTooBig); ok {
				minLen := ipHdrSize + 8
				if len(body.Data) >= minLen {
					origID := int(body.Data[ipHdrSize+4])<<8 | int(body.Data[ipHdrSize+5])
					if origID == t.id {
						mtu, _ := ParseMTUFromICMPv6PacketTooBig(reply[:n])
						return &probeResult{IP: peerIP, RTT: rtt, ResponseTTL: responseTTL, MTU: mtu, ICMPType: 2, ICMPCode: rm.Code}, nil
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
						// Check for Fragmentation Needed (Code 4) with MTU discovery
						var mtu int
						if rm.Code == 4 && t.config.DiscoverMTU && n >= 8 {
							// Next-Hop MTU is in bytes 6-7 of raw ICMP message
							mtu = int(reply[6])<<8 | int(reply[7])
							if mtu < MinMTU {
								mtu = 0
							}
						}
						ipid := ExtractIPID(body.Data)
						origTTL := ExtractOriginalTTL(body.Data)
						var transportInfo *hop.TransportInfo
						if t.config.Decode {
							transportInfo = ExtractTransportInfo(body.Data, ipHdrSize, string(t.config.Protocol))
						}
						return &probeResult{IP: peerIP, RTT: rtt, ResponseTTL: responseTTL, MTU: mtu, IPID: ipid, ICMPType: 3, ICMPCode: rm.Code, OriginalTTL: origTTL, TransportInfo: transportInfo}, nil
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
// When flowID > 0, extra bytes are appended to vary the ICMP checksum for ECMP path
// diversity. When mtuSize > 0, the payload is padded so the packet's total IP-layer
// size (IP header + ICMP header + payload) equals mtuSize.
func (t *ICMPTracer) buildEchoRequestForIP(ttl, seq int, target net.IP, flowID, mtuSize int) *icmp.Message {
	var msgType icmp.Type
	if IsIPv6(target) {
		msgType = ipv6.ICMPTypeEchoRequest
	} else {
		msgType = ipv4.ICMPTypeEcho
	}

	payload := []byte(fmt.Sprintf("gtr-%d-%d-%d", time.Now().UnixNano(), ttl, seq))
	if flowID > 0 {
		// Append flow-specific bytes to vary ICMP checksum for ECMP
		flowBytes := make([]byte, 4)
		flowBytes[0] = byte(flowID >> 24)
		flowBytes[1] = byte(flowID >> 16)
		flowBytes[2] = byte(flowID >> 8)
		flowBytes[3] = byte(flowID)
		payload = append(payload, flowBytes...)
	}

	// Pad payload to reach desired probe size
	if mtuSize > 0 {
		targetPayload := mtuSize - IPHeaderSize(target) - 8 // ICMP header is 8 bytes
		if targetPayload > len(payload) {
			payload = append(payload, make([]byte, targetPayload-len(payload))...)
		}
	} else if t.config.ProbeSize > 0 {
		currentSize := len(payload) + 8 // ICMP header is 8 bytes
		if t.config.ProbeSize > currentSize {
			padding := make([]byte, t.config.ProbeSize-currentSize)
			payload = append(payload, padding...)
		}
	}

	return &icmp.Message{
		Type: msgType,
		Code: 0,
		Body: &icmp.Echo{
			ID:   t.id,
			Seq:  seq,
			Data: payload,
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

// isPacketTooBig checks if the ICMP type is Packet Too Big (IPv6 only;
// IPv4 signals the same condition via Destination Unreachable code 4).
func isPacketTooBig(msgType icmp.Type, target net.IP) bool {
	return IsIPv6(target) && msgType == ipv6.ICMPTypePacketTooBig
}
