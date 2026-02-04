package trace

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/hervehildenbrand/gtr/pkg/hop"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
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
func (t *ICMPTracer) Trace(ctx context.Context, target net.IP, callback HopCallback) (*hop.TraceResult, error) {
	result := hop.NewTraceResult(target.String(), target.String())
	result.Protocol = string(ProtocolICMP)
	result.StartTime = time.Now()

	// Open ICMP connection
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
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
			ip, rtt, err := t.sendProbe(conn, target, ttl, i)
			if err != nil {
				if errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
					h.AddTimeout()
				} else {
					// Other errors - still record as timeout for display
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

// sendProbe sends a single ICMP probe and waits for response.
func (t *ICMPTracer) sendProbe(conn *icmp.PacketConn, target net.IP, ttl, seq int) (net.IP, time.Duration, error) {
	// Set TTL for this probe
	if err := conn.IPv4PacketConn().SetTTL(ttl); err != nil {
		return nil, 0, fmt.Errorf("failed to set TTL: %w", err)
	}

	// Build and send ICMP Echo Request
	msg := t.buildEchoRequest(ttl, seq)
	msgBytes, err := msg.Marshal(nil)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to marshal ICMP message: %w", err)
	}

	start := time.Now()

	_, err = conn.WriteTo(msgBytes, &net.IPAddr{IP: target})
	if err != nil {
		return nil, 0, fmt.Errorf("failed to send ICMP: %w", err)
	}

	// Set read deadline
	deadline := start.Add(t.config.Timeout)
	if err := conn.SetReadDeadline(deadline); err != nil {
		return nil, 0, fmt.Errorf("failed to set deadline: %w", err)
	}

	// Wait for response
	reply := make([]byte, 1500)
	for {
		n, peer, err := conn.ReadFrom(reply)
		if err != nil {
			return nil, 0, err
		}

		end := time.Now()
		rtt := t.calculateRTT(start, end)

		// Parse the response
		rm, err := icmp.ParseMessage(1, reply[:n]) // 1 = ICMP for IPv4
		if err != nil {
			continue // Ignore malformed packets
		}

		peerIP := peer.(*net.IPAddr).IP

		switch rm.Type {
		case ipv4.ICMPTypeEchoReply:
			// Check if this is our reply
			if body, ok := rm.Body.(*icmp.Echo); ok {
				if body.ID == t.id {
					return peerIP, rtt, nil
				}
			}

		case ipv4.ICMPTypeTimeExceeded:
			// Extract original packet from Time Exceeded message
			if body, ok := rm.Body.(*icmp.TimeExceeded); ok {
				// The Data field contains the original IP header + first 8 bytes of payload
				if len(body.Data) >= 28 {
					// Check if this response is for our probe
					// Original ICMP header starts at offset 20 (after IP header)
					origID := int(body.Data[24])<<8 | int(body.Data[25])
					if origID == t.id {
						return peerIP, rtt, nil
					}
				}
			}

		case ipv4.ICMPTypeDestinationUnreachable:
			// Destination unreachable - target reached but port/protocol unreachable
			return peerIP, rtt, nil
		}

		// Check if we've exceeded deadline
		if time.Now().After(deadline) {
			return nil, 0, context.DeadlineExceeded
		}
	}
}

// buildEchoRequest creates an ICMP Echo Request message.
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

// calculateRTT computes the round-trip time.
func (t *ICMPTracer) calculateRTT(start, end time.Time) time.Duration {
	return end.Sub(start)
}

// isTargetReached checks if the ICMP type indicates target reached.
func (t *ICMPTracer) isTargetReached(msgType icmp.Type) bool {
	return msgType == ipv4.ICMPTypeEchoReply
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
