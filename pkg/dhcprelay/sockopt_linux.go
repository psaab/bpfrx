package dhcprelay

import "golang.org/x/sys/unix"

// setBindToDevice sets SO_BINDTODEVICE on the given file descriptor.
func setBindToDevice(fd uintptr, ifaceName string) error {
	return unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, ifaceName)
}

// setReusePort sets SO_REUSEADDR and SO_REUSEPORT on the given file
// descriptor. Both are required so that multiple per-interface relay
// listeners can coexist on the wildcard 0.0.0.0:67 bind address without
// EADDRINUSE. Per-interface isolation is preserved because the kernel
// discards SO_BINDTODEVICE-mismatched sockets before the REUSEPORT fanout,
// so each listener only receives its own interface's ingress traffic.
func setReusePort(fd uintptr) error {
	if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
		return err
	}
	return unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
}

// setBroadcast sets SO_BROADCAST on the given file descriptor. Without it,
// Linux returns EACCES when sending to the limited broadcast address
// 255.255.255.255. The client-facing relay socket needs this to deliver
// broadcast OFFER/ACK replies to clients that set the broadcast flag.
func setBroadcast(fd uintptr) error {
	return unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_BROADCAST, 1)
}
