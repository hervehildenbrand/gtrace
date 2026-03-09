package trace

import (
	"net"

	"github.com/hervehildenbrand/gtrace/pkg/hop"
)

// ICMP extension class numbers
const (
	classNumMPLS          = 1 // RFC 4950: MPLS Label Stack
	classNumInterfaceInfo = 2 // RFC 5837: Interface Information
)

// ICMPExtensionResult holds parsed ICMP extension objects.
type ICMPExtensionResult struct {
	MPLS          []hop.MPLSLabel
	InterfaceInfo *hop.InterfaceInfo
}

// ParseICMPExtensions parses ICMP extension data (RFC 4884) and returns
// both MPLS labels (class 1, RFC 4950) and interface info (class 2, RFC 5837).
func ParseICMPExtensions(data []byte) *ICMPExtensionResult {
	if len(data) < minExtensionSize {
		return nil
	}

	// Verify extension version (first nibble should be 2)
	if data[0]&0xF0 != icmpExtVersion {
		return nil
	}

	result := &ICMPExtensionResult{}
	pos := extensionHeaderSize

	for pos+objectHeaderSize <= len(data) {
		objLen := int(data[pos])<<8 | int(data[pos+1])
		classNum := data[pos+2]
		cType := data[pos+3]

		pos += objectHeaderSize

		dataLen := objLen - objectHeaderSize
		if dataLen < 0 || pos+dataLen > len(data) {
			break
		}

		switch classNum {
		case classNumMPLS:
			result.MPLS = parseMPLSObject(data[pos:pos+dataLen])
		case classNumInterfaceInfo:
			result.InterfaceInfo = parseInterfaceInfoObject(data[pos:pos+dataLen], cType)
		}

		pos += dataLen
	}

	// Return nil if nothing was found
	if len(result.MPLS) == 0 && result.InterfaceInfo == nil {
		return nil
	}

	return result
}

// parseMPLSObject parses MPLS label entries from object data.
func parseMPLSObject(data []byte) []hop.MPLSLabel {
	var labels []hop.MPLSLabel
	for i := 0; i+mplsLabelEntrySize <= len(data); i += mplsLabelEntrySize {
		label := ParseMPLSLabelEntry(data[i : i+mplsLabelEntrySize])
		labels = append(labels, label)
		if label.S {
			break
		}
	}
	return labels
}

// parseInterfaceInfoObject parses an RFC 5837 Interface Information object.
// C-Type bits:
//   - Bit 0: Interface IP Address sub-object present
//   - Bit 1: Interface Name sub-object present
//   - Bit 2: Role (0=incoming, 1=outgoing) — this bit encodes the role directly
func parseInterfaceInfoObject(data []byte, cType byte) *hop.InterfaceInfo {
	info := &hop.InterfaceInfo{}

	hasAddress := cType&0x01 != 0
	hasName := cType&0x02 != 0
	isOutgoing := cType&0x04 != 0

	if isOutgoing {
		info.Role = "outgoing"
	} else {
		info.Role = "incoming"
	}

	pos := 0

	// Parse ifAddress if present (AFI + padding + IP)
	if hasAddress && pos+4 <= len(data) {
		afi := int(data[pos])<<8 | int(data[pos+1])
		pos += 2 // AFI
		pos += 2 // reserved

		switch afi {
		case 1: // IPv4
			if pos+4 <= len(data) {
				info.IP = net.IP(make([]byte, 4))
				copy(info.IP, data[pos:pos+4])
				pos += 4
			}
		case 2: // IPv6
			if pos+16 <= len(data) {
				info.IP = net.IP(make([]byte, 16))
				copy(info.IP, data[pos:pos+16])
				pos += 16
			}
		}
	}

	// Parse ifName if present (length byte + name, padded to 4 bytes)
	if hasName && pos < len(data) {
		nameLen := int(data[pos])
		pos++
		if nameLen > 0 && pos+nameLen <= len(data) {
			info.Name = string(data[pos : pos+nameLen])
		}
	}

	if info.Name == "" && info.IP == nil {
		return nil
	}

	return info
}
