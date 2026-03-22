package trace

import (
	"strings"

	"github.com/hervehildenbrand/gtrace/pkg/hop"
)

// ExtractTransportInfo extracts IP and transport header fields from the
// original datagram embedded in an ICMP error response body.
// Returns nil if data is too short for the IP header.
func ExtractTransportInfo(data []byte, ipHdrSize int, protocol string) *hop.TransportInfo {
	if len(data) < ipHdrSize {
		return nil
	}

	info := &hop.TransportInfo{}

	// IPv4 IP header fields
	if ipHdrSize == 20 && len(data) >= 7 {
		tos := data[1]
		info.DSCP = int(tos >> 2)
		info.ECN = int(tos & 0x03)
		info.DF = (data[6] & 0x40) != 0
	}

	// Transport header
	transport := data[ipHdrSize:]
	switch protocol {
	case "tcp":
		extractTCP(info, transport)
	case "udp":
		extractUDP(info, transport)
	}

	return info
}

func extractTCP(info *hop.TransportInfo, data []byte) {
	if len(data) < 4 {
		return
	}
	info.TCPSrcPort = uint16(data[0])<<8 | uint16(data[1])
	info.TCPDstPort = uint16(data[2])<<8 | uint16(data[3])
	if len(data) >= 8 {
		info.TCPSeqNum = uint32(data[4])<<24 | uint32(data[5])<<16 |
			uint32(data[6])<<8 | uint32(data[7])
	}
	if len(data) >= 14 {
		info.TCPFlags = data[13]
		info.TCPFlagsStr = formatTCPFlags(data[13])
	}
}

func extractUDP(info *hop.TransportInfo, data []byte) {
	if len(data) < 4 {
		return
	}
	info.UDPSrcPort = uint16(data[0])<<8 | uint16(data[1])
	info.UDPDstPort = uint16(data[2])<<8 | uint16(data[3])
	if len(data) >= 6 {
		info.UDPLength = uint16(data[4])<<8 | uint16(data[5])
	}
	if len(data) >= 8 {
		info.UDPChecksum = uint16(data[6])<<8 | uint16(data[7])
	}
}

func formatTCPFlags(flags uint8) string {
	masked := flags & 0x3F
	switch masked {
	case 0x02:
		return "SYN"
	case 0x12:
		return "SYN-ACK"
	case 0x10:
		return "ACK"
	case 0x04:
		return "RST"
	case 0x14:
		return "RST-ACK"
	case 0x01:
		return "FIN"
	case 0x11:
		return "FIN-ACK"
	case 0x18:
		return "PSH-ACK"
	}
	var parts []string
	if flags&0x20 != 0 {
		parts = append(parts, "URG")
	}
	if flags&0x10 != 0 {
		parts = append(parts, "ACK")
	}
	if flags&0x08 != 0 {
		parts = append(parts, "PSH")
	}
	if flags&0x04 != 0 {
		parts = append(parts, "RST")
	}
	if flags&0x02 != 0 {
		parts = append(parts, "SYN")
	}
	if flags&0x01 != 0 {
		parts = append(parts, "FIN")
	}
	return strings.Join(parts, "-")
}
