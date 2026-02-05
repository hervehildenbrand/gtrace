//go:build windows

package trace

import (
	"syscall"
	"unsafe"
)

// wsaPollFD is the Windows POLLFD structure for WSAPoll.
type wsaPollFD struct {
	fd      syscall.Handle
	events  int16
	revents int16
}

// Poll event flags
const (
	pollOut = 0x0010 // POLLOUT - ready for writing
)

// selectWrite checks if a file descriptor is writable using WSAPoll.
// On Windows, we use WSAPoll with a zero timeout for non-blocking check.
func selectWrite(fd int) (ready bool, err error) {
	pfd := wsaPollFD{
		fd:     syscall.Handle(fd),
		events: pollOut,
	}

	// WSAPoll with 0 timeout for immediate check
	ret, err := wsaPoll(&pfd, 1, 0)
	if err != nil {
		return false, err
	}

	if ret <= 0 {
		return false, nil
	}

	// Check if POLLOUT is set in revents
	return (pfd.revents & pollOut) != 0, nil
}

// wsaPoll wraps the Windows WSAPoll function.
func wsaPoll(fds *wsaPollFD, nfds int, timeout int) (int, error) {
	r1, _, e1 := syscall.Syscall(
		procWSAPoll.Addr(),
		3,
		uintptr(unsafe.Pointer(fds)),
		uintptr(nfds),
		uintptr(timeout),
	)

	if r1 == socketError {
		if e1 != 0 {
			return -1, e1
		}
		return -1, syscall.EINVAL
	}

	return int(r1), nil
}

var procWSAPoll = modws2_32.NewProc("WSAPoll")
