package trace

import (
	"context"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/hervehildenbrand/gtrace/pkg/hop"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// UDPTracer implements traceroute using UDP probes.
type UDPTracer struct {
	config *Config
	id     int
}

// NewUDPTracer creates a new UDP tracer with the given configuration.
func NewUDPTracer(cfg *Config) *UDPTracer {
	return &UDPTracer{
		config: cfg,
		id:     os.Getpid() & 0xffff,
	}
}

// Trace performs a UDP traceroute to the target IP.
// Supports both IPv4 and IPv6 targets.
func (t *UDPTracer) Trace(ctx context.Context, target net.IP, callback HopCallback) (*hop.TraceResult, error) {
	result := hop.NewTraceResult(target.String(), target.String())
	result.Protocol = string(ProtocolUDP)
	result.StartTime = time.Now()

	// Open raw socket for receiving ICMP responses based on IP version
	proto := ICMPProtocol(target)
	listenAddr := ListenAddress(target)
	icmpConn, err := icmp.ListenPacket(proto, listenAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to open ICMP socket: %w (try running with sudo)", err)
	}
	defer icmpConn.Close()

	probeNum := 0
	for ttl := 1; ttl <= t.config.MaxHops; ttl++ {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		h := hop.NewHop(ttl)
		reached := false

		probeCount := t.config.PacketsPerHop
		if t.config.ECMPFlows > 0 {
			probeCount = t.config.ECMPFlows
		}

		for i := 0; i < probeCount; i++ {
			probeNum++
			pr, err := t.sendProbe(icmpConn, target, ttl, probeNum)
			if err != nil {
				if isTimeout(err) {
					h.AddTimeout()
				} else {
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

			// Set MTU if discovered
			if pr.MTU > 0 && h.MTU == 0 {
				h.MTU = pr.MTU
			}

			if pr.IP.Equal(target) {
				reached = true
			}
		}

		// NAT detection via TTL analysis
		if t.config.DetectNAT {
			for _, p := range h.Probes {
				if !p.Timeout && p.ResponseTTL > 0 {
					expectedTTL := 64 - ttl
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

// sendProbe sends a single UDP probe and waits for ICMP response.
// Supports both IPv4 and IPv6 targets.
func (t *UDPTracer) sendProbe(icmpConn *icmp.PacketConn, target net.IP, ttl, seq int) (*probeResult, error) {
	port := t.getPort(seq)

	// Create UDP socket with specific TTL/Hop Limit
	domain := SocketDomain(target)
	fd, err := createRawSocket(domain, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
	if err != nil {
		return nil, fmt.Errorf("failed to create UDP socket: %w", err)
	}
	defer closeSocket(fd)

	// Set TTL/Hop Limit
	level := ProtocolLevel(target)
	opt := TTLSocketOption(target)
	if err := setSocketTTL(fd, level, opt, ttl); err != nil {
		return nil, fmt.Errorf("failed to set TTL/hop limit: %w", err)
	}

	// Build destination address
	sa := buildSockaddr(target, port)

	// Build payload
	payload := t.buildPayload(ttl, seq)

	start := time.Now()

	// Send UDP packet
	if err := sendToSocket(fd, payload, 0, sa); err != nil {
		return nil, fmt.Errorf("failed to send UDP: %w", err)
	}

	// Set read deadline on ICMP socket
	deadline := start.Add(t.config.Timeout)
	if err := icmpConn.SetReadDeadline(deadline); err != nil {
		return nil, fmt.Errorf("failed to set deadline: %w", err)
	}

	// Protocol number for parsing ICMP messages
	protoNum := ICMPProtocolNum(target)

	// Enable TTL control messages for NAT detection (IPv4 only)
	isV6 := IsIPv6(target)
	if !isV6 && t.config.DetectNAT {
		_ = icmpConn.IPv4PacketConn().SetControlMessage(ipv4.FlagTTL, true)
	}

	// Wait for ICMP response
	reply := make([]byte, 1500)
	for {
		var n int
		var peer net.Addr
		var responseTTL int

		if !isV6 && t.config.DetectNAT {
			var cm *ipv4.ControlMessage
			n, cm, peer, err = icmpConn.IPv4PacketConn().ReadFrom(reply)
			if cm != nil {
				responseTTL = cm.TTL
			}
		} else {
			n, peer, err = icmpConn.ReadFrom(reply)
		}
		if err != nil {
			return nil, err
		}

		end := time.Now()
		rtt := end.Sub(start)

		// Parse the ICMP response
		rm, err := icmp.ParseMessage(protoNum, reply[:n])
		if err != nil {
			continue
		}

		peerIP := peer.(*net.IPAddr).IP

		// Check for Time Exceeded (intermediate hop)
		if isTimeExceeded(rm.Type, target) {
			if body, ok := rm.Body.(*icmp.TimeExceeded); ok {
				if t.isOurProbeForIP(body.Data, port, target) {
					// Extract MPLS labels from the raw ICMP data
					var mplsLabels []hop.MPLSLabel
					if n > 8 {
						mplsLabels = ExtractMPLSFromICMP(reply[8:n])
					}
					return &probeResult{IP: peerIP, RTT: rtt, MPLS: mplsLabels, ResponseTTL: responseTTL}, nil
				}
			}
		}

		// Check for Destination Unreachable (target reached, port unreachable)
		if isDestUnreachable(rm.Type, target) {
			if body, ok := rm.Body.(*icmp.DstUnreach); ok {
				if t.isOurProbeForIP(body.Data, port, target) {
					// Check for Fragmentation Needed (Code 4) with MTU discovery
					var mtu int
					if rm.Code == 4 && t.config.DiscoverMTU && n >= 8 {
						mtu = int(reply[6])<<8 | int(reply[7])
						if mtu < MinMTU {
							mtu = 0
						}
					}
					return &probeResult{IP: peerIP, RTT: rtt, ResponseTTL: responseTTL, MTU: mtu}, nil
				}
			}
		}

		// Check deadline
		if time.Now().After(deadline) {
			return nil, &net.OpError{Op: "read", Err: &timeoutError{}}
		}
	}
}

// getPort returns the UDP destination port for a given sequence number.
// When ECMP flows are enabled, uses GenerateFlowID for port diversity.
func (t *UDPTracer) getPort(seq int) int {
	if t.config.ECMPFlows > 0 {
		return int(GenerateFlowID(seq))
	}
	return t.config.Port + seq - 1
}

// buildPayload creates the UDP payload.
func (t *UDPTracer) buildPayload(ttl, seq int) []byte {
	// Standard traceroute payload size
	return []byte(fmt.Sprintf("gtr-%d-%d-%d", time.Now().UnixNano(), ttl, seq))
}

// getUDPID returns the identifier for this tracer.
func (t *UDPTracer) getUDPID() int {
	return t.id
}

// isOurProbe checks if the ICMP response contains our original UDP packet (IPv4 only, for backward compatibility).
func (t *UDPTracer) isOurProbe(data []byte, expectedPort int) bool {
	// Data contains original IP header (20 bytes) + UDP header (8 bytes)
	if len(data) < 28 {
		return false
	}

	// Extract destination port from UDP header (offset 22-23 in the returned data)
	// IP header is 20 bytes, UDP dest port is at offset 2 in UDP header
	dstPort := int(data[22])<<8 | int(data[23])
	return dstPort == expectedPort
}

// isOurProbeForIP checks if the ICMP response contains our original UDP packet.
// Handles both IPv4 (20 byte header) and IPv6 (40 byte header).
func (t *UDPTracer) isOurProbeForIP(data []byte, expectedPort int, target net.IP) bool {
	ipHdrSize := IPHeaderSize(target)
	minLen := ipHdrSize + 4 // Need IP header + at least 4 bytes of UDP header (for dest port)
	if len(data) < minLen {
		return false
	}

	// Extract destination port from UDP header
	// UDP dest port is at offset 2 in UDP header
	portOffset := ipHdrSize + 2
	dstPort := int(data[portOffset])<<8 | int(data[portOffset+1])
	return dstPort == expectedPort
}

// buildSockaddr creates the appropriate sockaddr structure for the target IP.
func buildSockaddr(target net.IP, port int) syscall.Sockaddr {
	if IsIPv6(target) {
		var addr [16]byte
		copy(addr[:], target.To16())
		return &syscall.SockaddrInet6{
			Port: port,
			Addr: addr,
		}
	}
	var addr [4]byte
	copy(addr[:], target.To4())
	return &syscall.SockaddrInet4{
		Port: port,
		Addr: addr,
	}
}

// timeoutError implements net.Error for timeout handling.
type timeoutError struct{}

func (e *timeoutError) Error() string   { return "timeout" }
func (e *timeoutError) Timeout() bool   { return true }
func (e *timeoutError) Temporary() bool { return true }
