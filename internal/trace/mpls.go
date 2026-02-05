package trace

import (
	"github.com/hervehildenbrand/gtrace/pkg/hop"
)

// MPLS extension constants per RFC 4950
const (
	// ICMP Extension version (should be 2)
	icmpExtVersion = 0x20

	// MPLS Label Stack Entry class number
	mplsClassNum = 1

	// Minimum sizes
	minExtensionSize      = 8  // Extension header + object header
	mplsLabelEntrySize    = 4  // Size of one label stack entry
	extensionHeaderSize   = 4  // ICMP extension header
	objectHeaderSize      = 4  // Object header
)

// ParseMPLSExtensions parses MPLS label stack from ICMP extension data.
// The extension data format follows RFC 4884 (ICMP Extensions) and RFC 4950 (MPLS Extensions).
func ParseMPLSExtensions(data []byte) []hop.MPLSLabel {
	if len(data) < minExtensionSize {
		return nil
	}

	// Verify extension version (first nibble should be 2)
	if data[0]&0xF0 != icmpExtVersion {
		return nil
	}

	// Skip extension header (4 bytes: version/reserved, checksum)
	pos := extensionHeaderSize

	var labels []hop.MPLSLabel

	// Parse objects until we run out of data
	for pos+objectHeaderSize <= len(data) {
		// Object header: length (2 bytes), class-num (1 byte), c-type (1 byte)
		objLen := int(data[pos])<<8 | int(data[pos+1])
		classNum := data[pos+2]
		// cType := data[pos+3] // unused for now

		// Move past object header
		pos += objectHeaderSize

		// Check if this is an MPLS object
		if classNum != mplsClassNum {
			// Skip this object
			if objLen > objectHeaderSize {
				pos += objLen - objectHeaderSize
			}
			continue
		}

		// Parse MPLS label stack entries
		// Object length includes the header, so subtract header size
		dataLen := objLen - objectHeaderSize
		if dataLen < 0 {
			break
		}

		// Parse each 4-byte label entry
		for i := 0; i < dataLen && pos+mplsLabelEntrySize <= len(data); i += mplsLabelEntrySize {
			label := ParseMPLSLabelEntry(data[pos : pos+mplsLabelEntrySize])
			labels = append(labels, label)
			pos += mplsLabelEntrySize

			// Stop if this was bottom of stack
			if label.S {
				break
			}
		}

		break // Only process first MPLS object
	}

	return labels
}

// ParseMPLSLabelEntry parses a single 4-byte MPLS label stack entry.
// Format: Label (20 bits) | Exp (3 bits) | S (1 bit) | TTL (8 bits)
func ParseMPLSLabelEntry(data []byte) hop.MPLSLabel {
	if len(data) < 4 {
		return hop.MPLSLabel{}
	}

	// Combine bytes into 32-bit value
	val := uint32(data[0])<<24 | uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])

	return hop.MPLSLabel{
		Label: val >> 12,            // Top 20 bits
		Exp:   uint8((val >> 9) & 7), // Next 3 bits
		S:     (val>>8)&1 == 1,       // Next 1 bit
		TTL:   uint8(val & 0xFF),     // Bottom 8 bits
	}
}

// ExtractMPLSFromICMP extracts MPLS labels from an ICMP Time Exceeded message.
// The ICMP message body contains the original IP header (20 bytes minimum)
// followed by at least 8 bytes of the original datagram.
// RFC 4884 extensions appear after the original datagram portion.
func ExtractMPLSFromICMP(icmpData []byte) []hop.MPLSLabel {
	// Need at least original IP header (20 bytes) + 8 bytes of original payload
	// + some extension data
	if len(icmpData) < 128 {
		// RFC 4884 requires at least 128 bytes for extensions
		return nil
	}

	// The extension header starts at a 4-byte boundary after the original packet
	// Original packet is typically at offset 4 in the ICMP data (after unused field)
	// Look for extension header starting around byte 128

	// Try to find extension header by looking for version byte
	for offset := 128; offset < len(icmpData)-minExtensionSize; offset += 4 {
		if icmpData[offset]&0xF0 == icmpExtVersion {
			return ParseMPLSExtensions(icmpData[offset:])
		}
	}

	return nil
}
