package trace

// ICMPCodeIndicator returns a short display indicator for an ICMP Destination
// Unreachable code (type 3). Returns empty string for non-Dest-Unreachable
// types or codes without a specific indicator.
func ICMPCodeIndicator(icmpType, code int) string {
	if icmpType != 3 {
		return ""
	}
	switch code {
	case 0:
		return "[!N]"
	case 1:
		return "[!H]"
	case 3:
		return "[!P]"
	case 4:
		return "[!F]"
	case 9, 10, 13:
		return "[!X]"
	default:
		return ""
	}
}

// ICMPCodeText returns a human-readable description of an ICMP Destination
// Unreachable code (type 3).
func ICMPCodeText(icmpType, code int) string {
	if icmpType != 3 {
		return ""
	}
	switch code {
	case 0:
		return "network unreachable"
	case 1:
		return "host unreachable"
	case 2:
		return "protocol unreachable"
	case 3:
		return "port unreachable"
	case 4:
		return "fragmentation needed"
	case 9, 10, 13:
		return "admin prohibited"
	default:
		return ""
	}
}
