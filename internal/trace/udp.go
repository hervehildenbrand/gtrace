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
func (t *UDPTracer) Trace(ctx context.Context, target net.IP, callback HopCallback) (*hop.TraceResult, error) {
	result := hop.NewTraceResult(target.String(), target.String())
	result.Protocol = string(ProtocolUDP)
	result.StartTime = time.Now()

	// Open raw socket for receiving ICMP responses
	icmpConn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
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

		for i := 0; i < t.config.PacketsPerHop; i++ {
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

			h.AddProbe(pr.IP, pr.RTT)

			// Set MPLS labels if discovered (first probe with labels wins)
			if len(pr.MPLS) > 0 && len(h.MPLS) == 0 {
				h.SetMPLS(pr.MPLS)
			}

			if pr.IP.Equal(target) {
				reached = true
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
func (t *UDPTracer) sendProbe(icmpConn *icmp.PacketConn, target net.IP, ttl, seq int) (*probeResult, error) {
	port := t.getPort(seq)

	// Create UDP socket with specific TTL
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
	if err != nil {
		return nil, fmt.Errorf("failed to create UDP socket: %w", err)
	}
	defer syscall.Close(fd)

	// Set TTL
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_TTL, ttl); err != nil {
		return nil, fmt.Errorf("failed to set TTL: %w", err)
	}

	// Build destination address
	var addr [4]byte
	copy(addr[:], target.To4())
	sa := &syscall.SockaddrInet4{
		Port: port,
		Addr: addr,
	}

	// Build payload
	payload := t.buildPayload(ttl, seq)

	start := time.Now()

	// Send UDP packet
	if err := syscall.Sendto(fd, payload, 0, sa); err != nil {
		return nil, fmt.Errorf("failed to send UDP: %w", err)
	}

	// Set read deadline on ICMP socket
	deadline := start.Add(t.config.Timeout)
	if err := icmpConn.SetReadDeadline(deadline); err != nil {
		return nil, fmt.Errorf("failed to set deadline: %w", err)
	}

	// Wait for ICMP response
	reply := make([]byte, 1500)
	for {
		n, peer, err := icmpConn.ReadFrom(reply)
		if err != nil {
			return nil, err
		}

		end := time.Now()
		rtt := end.Sub(start)

		// Parse the ICMP response
		rm, err := icmp.ParseMessage(1, reply[:n])
		if err != nil {
			continue
		}

		peerIP := peer.(*net.IPAddr).IP

		switch rm.Type {
		case ipv4.ICMPTypeTimeExceeded:
			// Intermediate hop
			if body, ok := rm.Body.(*icmp.TimeExceeded); ok {
				if t.isOurProbe(body.Data, port) {
					// Extract MPLS labels from the raw ICMP data
					var mplsLabels []hop.MPLSLabel
					if n > 8 {
						mplsLabels = ExtractMPLSFromICMP(reply[8:n])
					}
					return &probeResult{IP: peerIP, RTT: rtt, MPLS: mplsLabels}, nil
				}
			}

		case ipv4.ICMPTypeDestinationUnreachable:
			// Target reached (port unreachable)
			if body, ok := rm.Body.(*icmp.DstUnreach); ok {
				if t.isOurProbe(body.Data, port) {
					return &probeResult{IP: peerIP, RTT: rtt}, nil
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
func (t *UDPTracer) getPort(seq int) int {
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

// isOurProbe checks if the ICMP response contains our original UDP packet.
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

// timeoutError implements net.Error for timeout handling.
type timeoutError struct{}

func (e *timeoutError) Error() string   { return "timeout" }
func (e *timeoutError) Timeout() bool   { return true }
func (e *timeoutError) Temporary() bool { return true }
