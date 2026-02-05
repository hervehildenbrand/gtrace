//go:build windows

package trace

import "golang.org/x/sys/windows"

// Platform-specific error codes for Windows systems.
var (
	// errInProgress indicates a non-blocking connect is in progress.
	// On Windows, WSAEWOULDBLOCK is returned for non-blocking connect.
	errInProgress = windows.WSAEWOULDBLOCK

	// errConnRefused indicates the connection was refused (RST received).
	errConnRefused = windows.WSAECONNREFUSED
)

// isErrInProgress checks if the error indicates a connection in progress.
// On Windows, both WSAEWOULDBLOCK and WSAEINPROGRESS can indicate this.
func isErrInProgress(err error) bool {
	return err == windows.WSAEWOULDBLOCK || err == windows.WSAEINPROGRESS
}

// isErrConnRefused checks if the error indicates connection refused.
func isErrConnRefused(err error) bool {
	return err == windows.WSAECONNREFUSED
}
