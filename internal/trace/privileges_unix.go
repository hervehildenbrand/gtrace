//go:build !windows

package trace

import (
	"fmt"
	"os"
	"strings"
)

// CheckPrivileges verifies that the current process has the necessary privileges
// to perform raw socket operations (required for traceroute).
// Returns nil if privileged, error otherwise with a helpful message.
func CheckPrivileges() error {
	// Root always has privileges
	if os.Geteuid() == 0 {
		return nil
	}

	// On Linux, also check for CAP_NET_RAW capability
	if HasNetRawCapability() {
		return nil
	}

	return fmt.Errorf("gtrace requires elevated privileges for raw socket access.\n\nRun with: sudo %s", strings.Join(os.Args, " "))
}

// HasNetRawCapability checks if the current process has CAP_NET_RAW capability (Linux only).
// On non-Linux Unix systems (macOS, BSD), this always returns false since capabilities aren't supported.
func HasNetRawCapability() bool {
	// Read the effective capabilities from /proc/self/status
	// This is Linux-specific; on other Unix systems this file doesn't exist
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}

	// Look for CapEff line (effective capabilities)
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "CapEff:") {
			// Parse the hex capability mask
			fields := strings.Fields(line)
			if len(fields) < 2 {
				return false
			}

			// CAP_NET_RAW is capability bit 13
			// Check if bit 13 is set in the capability mask
			var capMask uint64
			_, err := fmt.Sscanf(fields[1], "%x", &capMask)
			if err != nil {
				return false
			}

			// CAP_NET_RAW = 13, so we check bit 13
			const capNetRaw = 1 << 13
			return (capMask & capNetRaw) != 0
		}
	}

	return false
}
