//go:build windows

package trace

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

// CheckPrivileges verifies that the current process has the necessary privileges
// to perform raw socket operations (required for traceroute).
// On Windows, this checks if the process is running with Administrator privileges.
// Returns nil if privileged, error otherwise with a helpful message.
func CheckPrivileges() error {
	if isAdmin() {
		return nil
	}

	return fmt.Errorf("gtrace requires Administrator privileges for raw socket access.\n\nRun as Administrator or use: runas /user:Administrator %s", strings.Join(os.Args, " "))
}

// HasNetRawCapability is a no-op on Windows (capabilities are a Linux concept).
// Returns false since Windows doesn't have Linux-style capabilities.
func HasNetRawCapability() bool {
	return false
}

// isAdmin checks if the current process is running with Administrator privileges.
func isAdmin() bool {
	var sid *windows.SID

	// Create a SID for the Administrators group
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid,
	)
	if err != nil {
		return false
	}
	defer windows.FreeSid(sid)

	// Check if the current process token is a member of the Administrators group
	token := windows.Token(0) // Current process token
	member, err := token.IsMember(sid)
	if err != nil {
		return false
	}

	return member
}
