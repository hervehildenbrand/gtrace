//go:build !windows

package trace

import "syscall"

// Platform-specific error codes for Unix systems.
var (
	// errInProgress indicates a non-blocking connect is in progress.
	errInProgress = syscall.EINPROGRESS

	// errConnRefused indicates the connection was refused (RST received).
	errConnRefused = syscall.ECONNREFUSED
)

// isErrInProgress checks if the error indicates a connection in progress.
func isErrInProgress(err error) bool {
	return err == syscall.EINPROGRESS
}

// isErrConnRefused checks if the error indicates connection refused.
func isErrConnRefused(err error) bool {
	return err == syscall.ECONNREFUSED
}
