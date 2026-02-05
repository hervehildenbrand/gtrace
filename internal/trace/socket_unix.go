//go:build !windows

package trace

import (
	"syscall"
)

// socketFD represents a socket file descriptor on Unix systems.
type socketFD int

// invalidSocket represents an invalid socket value.
const invalidSocket socketFD = -1

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
	return syscall.Close(int(fd))
}

// setSocketTTL sets the TTL/hop limit on a socket.
func setSocketTTL(fd socketFD, level, opt, ttl int) error {
	return syscall.SetsockoptInt(int(fd), level, opt, ttl)
}

// setSocketNonBlocking sets the socket to non-blocking mode.
func setSocketNonBlocking(fd socketFD) error {
	return syscall.SetNonblock(int(fd), true)
}

// connectSocket initiates a connection on the socket.
func connectSocket(fd socketFD, sa syscall.Sockaddr) error {
	return syscall.Connect(int(fd), sa)
}

// sendToSocket sends data to the specified address.
func sendToSocket(fd socketFD, data []byte, flags int, sa syscall.Sockaddr) error {
	return syscall.Sendto(int(fd), data, flags, sa)
}

// getSocketError retrieves the socket error status (SO_ERROR).
func getSocketError(fd socketFD) (int, error) {
	return syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_ERROR)
}

// socketFDInt returns the underlying integer file descriptor (for select).
func socketFDInt(fd socketFD) int {
	return int(fd)
}
