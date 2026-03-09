package trace

// ExtractOriginalTTL extracts the TTL field from an original IPv4 header
// contained in an ICMP error response's body.Data. TTL is byte 8 of the
// IPv4 header. Returns -1 if data is too short.
func ExtractOriginalTTL(data []byte) int {
	if len(data) < 9 {
		return -1
	}
	return int(data[8])
}

// IsTTLManipulated compares the TTL we sent with the TTL returned in the
// ICMP error's original datagram. For Time Exceeded responses, routers
// typically return TTL=1 or TTL=0 (they decremented it to 0 before
// sending the error). A value significantly different suggests a middlebox
// modified the TTL.
func IsTTLManipulated(sentTTL, originalTTL int) bool {
	if sentTTL <= 0 || originalTTL < 0 {
		return false
	}
	// Normal: original TTL should be 0 or 1 (router decremented our sent TTL to 0)
	// Some routers return the value before decrement (1), some after (0)
	return originalTTL != 0 && originalTTL != 1
}
