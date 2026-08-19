//go:build !windows

package trace

import (
	"errors"
	"fmt"
	"net"
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

// isEMSGSIZE checks if an error is EMSGSIZE (message too long), including
// errno wrapped by the net package (OpError/SyscallError chains).
// This indicates the packet exceeds a local size limit when DF bit is set.
func isEMSGSIZE(err error) bool {
	return errors.Is(err, syscall.EMSGSIZE)
}

// socketFDInt returns the underlying integer file descriptor (for select).
func socketFDInt(fd socketFD) int {
	return int(fd)
}

// applyDontFragment sets the probing DF option on a net.PacketConn whose
// concrete type exposes its file descriptor (net.IPConn, net.UDPConn).
func applyDontFragment(pc net.PacketConn, ipv6 bool) error {
	sc, ok := pc.(syscall.Conn)
	if !ok {
		return fmt.Errorf("connection type %T does not expose a file descriptor", pc)
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return err
	}
	var optErr error
	err = raw.Control(func(fd uintptr) {
		if ipv6 {
			optErr = setDontFragmentV6(socketFD(fd))
		} else {
			optErr = setDontFragmentProbe(socketFD(fd))
		}
	})
	if err != nil {
		return err
	}
	return optErr
}
