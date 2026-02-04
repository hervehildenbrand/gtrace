package trace

import (
	"context"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/hervehildenbrand/gtr/pkg/hop"
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
func (t *TCPTracer) Trace(ctx context.Context, target net.IP, callback HopCallback) (*hop.TraceResult, error) {
	result := hop.NewTraceResult(target.String(), target.String())
	result.Protocol = string(ProtocolTCP)
	result.StartTime = time.Now()

	// Open raw socket for receiving ICMP responses
	icmpConn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
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
			ip, rtt, err := t.sendProbe(icmpConn, target, ttl, i)
			if err != nil {
				if isTimeout(err) {
					h.AddTimeout()
				} else {
					h.AddTimeout()
				}
				continue
			}

			h.AddProbe(ip, rtt)
			if ip.Equal(target) {
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

// sendProbe sends a single TCP SYN probe and waits for response.
func (t *TCPTracer) sendProbe(icmpConn *icmp.PacketConn, target net.IP, ttl, seq int) (net.IP, time.Duration, error) {
	port := t.getPort()

	// Create TCP socket
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, syscall.IPPROTO_TCP)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create TCP socket: %w", err)
	}
	defer syscall.Close(fd)

	// Set TTL
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_TTL, ttl); err != nil {
		return nil, 0, fmt.Errorf("failed to set TTL: %w", err)
	}

	// Set non-blocking
	if err := syscall.SetNonblock(fd, true); err != nil {
		return nil, 0, fmt.Errorf("failed to set non-blocking: %w", err)
	}

	// Build destination address
	var addr [4]byte
	copy(addr[:], target.To4())
	sa := &syscall.SockaddrInet4{
		Port: port,
		Addr: addr,
	}

	start := time.Now()

	// Initiate TCP connection (will send SYN)
	err = syscall.Connect(fd, sa)
	// Connect will return EINPROGRESS for non-blocking socket
	if err != nil && err != syscall.EINPROGRESS {
		// Check if we got a connection refused (RST) - means target reached
		if err == syscall.ECONNREFUSED {
			return target, time.Since(start), nil
		}
	}

	// Set read deadline on ICMP socket
	deadline := start.Add(t.config.Timeout)
	if err := icmpConn.SetReadDeadline(deadline); err != nil {
		return nil, 0, fmt.Errorf("failed to set deadline: %w", err)
	}

	// Wait for ICMP response or TCP connection
	reply := make([]byte, 1500)
	for {
		// Check if TCP connection completed (SYN-ACK received)
		if t.checkTCPConnection(fd) {
			return target, time.Since(start), nil
		}

		n, peer, err := icmpConn.ReadFrom(reply)
		if err != nil {
			if isTimeout(err) {
				return nil, 0, err
			}
			// Keep trying until deadline
			if time.Now().After(deadline) {
				return nil, 0, &timeoutError{}
			}
			continue
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
					return peerIP, rtt, nil
				}
			}

		case ipv4.ICMPTypeDestinationUnreachable:
			// Target reached but filtered
			if body, ok := rm.Body.(*icmp.DstUnreach); ok {
				if t.isOurProbe(body.Data, port) {
					return peerIP, rtt, nil
				}
			}
		}

		// Check deadline
		if time.Now().After(deadline) {
			return nil, 0, &timeoutError{}
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
func (t *TCPTracer) checkTCPConnection(fd int) bool {
	// Use getsockopt to check connection status
	val, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_ERROR)
	if err != nil {
		return false
	}
	// val == 0 means connected, ECONNREFUSED means RST received (target reached)
	return val == 0 || val == int(syscall.ECONNREFUSED)
}

// isOurProbe checks if the ICMP response contains our original TCP packet.
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
