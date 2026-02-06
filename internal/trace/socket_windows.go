//go:build windows

package trace

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// socketFD represents a socket file descriptor on Windows systems.
type socketFD syscall.Handle

// invalidSocket represents an invalid socket value on Windows.
const invalidSocket socketFD = socketFD(syscall.InvalidHandle)

// Windows socket constants
const (
	fionbio     = 0x8004667e    // FIONBIO for ioctlsocket
	soError     = 0x1007        // SO_ERROR
	socketError = uintptr(^uint(0)) // SOCKET_ERROR (-1)
)

// createRawSocket creates a raw socket with the given parameters.
func createRawSocket(domain, sockType, proto int) (socketFD, error) {
	fd, err := syscall.Socket(domain, sockType, proto)
	if err != nil {
		return invalidSocket, err
	}
	return socketFD(fd), nil
}

// closeSocket closes the socket.
func closeSocket(fd socketFD) error {
	return syscall.Closesocket(syscall.Handle(fd))
}

// setSocketTTL sets the TTL/hop limit on a socket.
func setSocketTTL(fd socketFD, level, opt, ttl int) error {
	return syscall.SetsockoptInt(syscall.Handle(fd), level, opt, ttl)
}

// setSocketNonBlocking sets the socket to non-blocking mode using ioctlsocket.
func setSocketNonBlocking(fd socketFD) error {
	var mode uint32 = 1 // Non-blocking
	return ioctlSocket(syscall.Handle(fd), fionbio, &mode)
}

// ioctlSocket calls ioctlsocket on Windows.
func ioctlSocket(fd syscall.Handle, cmd uint32, argp *uint32) error {
	r1, _, e1 := syscall.Syscall(
		procIoctlSocket.Addr(),
		3,
		uintptr(fd),
		uintptr(cmd),
		uintptr(unsafe.Pointer(argp)),
	)
	if r1 == socketError {
		if e1 != 0 {
			return e1
		}
		return syscall.EINVAL
	}
	return nil
}

// connectSocket initiates a connection on the socket.
func connectSocket(fd socketFD, sa syscall.Sockaddr) error {
	return syscall.Connect(syscall.Handle(fd), sa)
}

// sendToSocket sends data to the specified address.
func sendToSocket(fd socketFD, data []byte, flags int, sa syscall.Sockaddr) error {
	return syscall.Sendto(syscall.Handle(fd), data, flags, sa)
}

// getSocketError retrieves the socket error status (SO_ERROR).
func getSocketError(fd socketFD) (int, error) {
	val, err := syscall.GetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, soError)
	if err != nil {
		return 0, err
	}
	return val, nil
}

// setDontFragment sets the Don't Fragment (DF) bit on an IPv4 socket.
// On Windows this uses IP_DONTFRAGMENT (14).
func setDontFragment(fd socketFD) error {
	return syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, 14, 1)
}

// socketFDInt returns the underlying integer file descriptor (for WSAPoll).
// On Windows, this returns the handle as an int for compatibility.
func socketFDInt(fd socketFD) int {
	return int(fd)
}

var (
	modws2_32        = windows.NewLazySystemDLL("ws2_32.dll")
	procIoctlSocket  = modws2_32.NewProc("ioctlsocket")
)
