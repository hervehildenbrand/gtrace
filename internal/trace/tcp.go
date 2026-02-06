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

// TCPTracer implements traceroute using TCP SYN probes.
type TCPTracer struct {
	config *Config
	id     int
}

// NewTCPTracer creates a new TCP tracer with the given configuration.
func NewTCPTracer(cfg *Config) *TCPTracer {
	return &TCPTracer{
		config: cfg,
		id:     os.Getpid() & 0xffff,
	}
}

// Trace performs a TCP traceroute to the target IP.
// Supports both IPv4 and IPv6 targets.
func (t *TCPTracer) Trace(ctx context.Context, target net.IP, callback HopCallback) (*hop.TraceResult, error) {
	result := hop.NewTraceResult(target.String(), target.String())
	result.Protocol = string(ProtocolTCP)
	result.StartTime = time.Now()

	// Open raw socket for receiving ICMP responses based on IP version
	proto := ICMPProtocol(target)
	listenAddr := ListenAddress(target)
	icmpConn, err := icmp.ListenPacket(proto, listenAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to open ICMP socket: %w (try running with sudo)", err)
	}
	defer icmpConn.Close()

	for ttl := 1; ttl <= t.config.MaxHops; ttl++ {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		h := hop.NewHop(ttl)
		reached := false

		for i := 0; i < t.config.PacketsPerHop; i++ {
			pr, err := t.sendProbe(icmpConn, target, ttl, i)
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

// sendProbe sends a single TCP SYN probe and waits for response.
// Supports both IPv4 and IPv6 targets.
func (t *TCPTracer) sendProbe(icmpConn *icmp.PacketConn, target net.IP, ttl, seq int) (*probeResult, error) {
	port := t.getPort()

	// Create TCP socket
	domain := SocketDomain(target)
	fd, err := createRawSocket(domain, syscall.SOCK_STREAM, syscall.IPPROTO_TCP)
	if err != nil {
		return nil, fmt.Errorf("failed to create TCP socket: %w", err)
	}
	defer closeSocket(fd)

	// Set TTL/Hop Limit
	level := ProtocolLevel(target)
	opt := TTLSocketOption(target)
	if err := setSocketTTL(fd, level, opt, ttl); err != nil {
		return nil, fmt.Errorf("failed to set TTL/hop limit: %w", err)
	}

	// Set non-blocking
	if err := setSocketNonBlocking(fd); err != nil {
		return nil, fmt.Errorf("failed to set non-blocking: %w", err)
	}

	// Build destination address
	sa := buildSockaddr(target, port)

	start := time.Now()

	// Initiate TCP connection (will send SYN)
	err = connectSocket(fd, sa)
	// Connect will return EINPROGRESS (Unix) or WSAEWOULDBLOCK (Windows) for non-blocking socket
	if err != nil && !isErrInProgress(err) {
		// Check if we got a connection refused (RST) - means target reached
		if isErrConnRefused(err) {
			return &probeResult{IP: target, RTT: time.Since(start)}, nil
		}
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

	// Wait for ICMP response or TCP connection
	reply := make([]byte, 1500)
	for {
		// Check if TCP connection completed (SYN-ACK received)
		if t.checkTCPConnection(fd) {
			return &probeResult{IP: target, RTT: time.Since(start)}, nil
		}

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
			if isTimeout(err) {
				return nil, err
			}
			// Keep trying until deadline
			if time.Now().After(deadline) {
				return nil, &timeoutError{}
			}
			continue
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

		// Check for Destination Unreachable (target reached but filtered)
		if isDestUnreachable(rm.Type, target) {
			if body, ok := rm.Body.(*icmp.DstUnreach); ok {
				if t.isOurProbeForIP(body.Data, port, target) {
					return &probeResult{IP: peerIP, RTT: rtt, ResponseTTL: responseTTL}, nil
				}
			}
		}

		// Check deadline
		if time.Now().After(deadline) {
			return nil, &timeoutError{}
		}
	}
}

// getPort returns the TCP destination port.
func (t *TCPTracer) getPort() int {
	return t.config.Port
}

// getTCPID returns the identifier for this tracer.
func (t *TCPTracer) getTCPID() int {
	return t.id
}

// checkTCPConnection checks if the TCP connection has completed.
func (t *TCPTracer) checkTCPConnection(fd socketFD) bool {
	// Use select with zero timeout to check if socket is writable
	// A non-blocking socket becomes writable when connection completes (or fails)
	ready, err := selectWrite(socketFDInt(fd))
	if err != nil || !ready {
		return false
	}

	// Socket is writable - check SO_ERROR to see if connection succeeded or failed
	val, err := getSocketError(fd)
	if err != nil {
		return false
	}
	// val == 0 means connected, ECONNREFUSED means RST received (target reached)
	return val == 0 || val == int(errConnRefused)
}

// isOurProbe checks if the ICMP response contains our original TCP packet (IPv4 only, for backward compatibility).
func (t *TCPTracer) isOurProbe(data []byte, expectedPort int) bool {
	// Data contains original IP header (20 bytes) + TCP header
	if len(data) < 24 {
		return false
	}

	// Extract destination port from TCP header (offset 22-23 in the returned data)
	// IP header is 20 bytes, TCP dest port is at offset 2 in TCP header
	dstPort := int(data[22])<<8 | int(data[23])
	return dstPort == expectedPort
}

// isOurProbeForIP checks if the ICMP response contains our original TCP packet.
// Handles both IPv4 (20 byte header) and IPv6 (40 byte header).
func (t *TCPTracer) isOurProbeForIP(data []byte, expectedPort int, target net.IP) bool {
	ipHdrSize := IPHeaderSize(target)
	minLen := ipHdrSize + 4 // Need IP header + at least 4 bytes of TCP header (for dest port)
	if len(data) < minLen {
		return false
	}

	// Extract destination port from TCP header
	// TCP dest port is at offset 2 in TCP header
	portOffset := ipHdrSize + 2
	dstPort := int(data[portOffset])<<8 | int(data[portOffset+1])
	return dstPort == expectedPort
}
