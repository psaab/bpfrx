// Package daemon implements the bpfrx daemon lifecycle.
package daemon

import (
	"log/slog"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

func isInteractive() bool {
	_, err := unix.IoctlGetTermios(int(os.Stdin.Fd()), unix.TCGETS)
	return err == nil
}

// resolveInterfaceAddr returns the first IPv4 address on the named interface.
// If the interface is not found or has no IPv4 addresses, it returns fallback.
func resolveInterfaceAddr(ifname, fallback string) string {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		slog.Warn("web-management interface not found, using fallback", "interface", ifname, "fallback", fallback)
		return fallback
	}
	addrs, err := iface.Addrs()
	if err != nil || len(addrs) == 0 {
		slog.Warn("web-management interface has no addresses, using fallback", "interface", ifname, "fallback", fallback)
		return fallback
	}
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if ip4 := ipNet.IP.To4(); ip4 != nil {
			return ip4.String()
		}
	}
	// No IPv4, try IPv6
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if ipNet.IP.To4() == nil {
			return ipNet.IP.String()
		}
	}
	slog.Warn("web-management interface has no usable addresses, using fallback", "interface", ifname, "fallback", fallback)
	return fallback
}

func parseLiteralIP(addr string) net.IP {
	if addr == "" {
		return nil
	}
	if ip := net.ParseIP(addr); ip != nil {
		return ip
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil
	}
	return net.ParseIP(host)
}

func selectClusterBindAddr(addrs []net.Addr, peerAddr, fallback string) string {
	var ipv4Candidates []string
	var globalIPv6Candidates []string
	peerIP := parseLiteralIP(peerAddr)
	peerWantsIPv4 := peerIP != nil && peerIP.To4() != nil
	peerWantsIPv6 := peerIP != nil && peerIP.To4() == nil

	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if ip4 := ipNet.IP.To4(); ip4 != nil {
			ipv4Candidates = append(ipv4Candidates, ip4.String())
			continue
		}
		// Cluster control/fabric transports do not support binding to bare
		// link-local IPv6 addresses because the resulting listen address lacks
		// an interface zone. Treat them as unusable so startup waits for the
		// configured control/fabric address family instead of racing on fe80::.
		if ipNet.IP.IsLinkLocalUnicast() {
			continue
		}
		globalIPv6Candidates = append(globalIPv6Candidates, ipNet.IP.String())
	}

	switch {
	case peerWantsIPv4:
		if len(ipv4Candidates) > 0 {
			return ipv4Candidates[0]
		}
	case peerWantsIPv6:
		if len(globalIPv6Candidates) > 0 {
			return globalIPv6Candidates[0]
		}
	default:
		if len(ipv4Candidates) > 0 {
			return ipv4Candidates[0]
		}
		if len(globalIPv6Candidates) > 0 {
			return globalIPv6Candidates[0]
		}
	}

	return fallback
}

// resolveClusterInterfaceAddr returns a usable control/fabric bind address for
// the named interface. It prefers the same address family as the configured
// peer and skips unscoped link-local IPv6 addresses.
func resolveClusterInterfaceAddr(ifname, peerAddr, fallback string) string {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		slog.Warn("cluster interface not found, using fallback", "interface", ifname, "fallback", fallback)
		return fallback
	}
	addrs, err := iface.Addrs()
	if err != nil || len(addrs) == 0 {
		slog.Warn("cluster interface has no addresses, using fallback", "interface", ifname, "fallback", fallback)
		return fallback
	}
	addr := selectClusterBindAddr(addrs, peerAddr, fallback)
	if addr == "" {
		slog.Info("cluster interface has no usable bind address yet", "interface", ifname, "peer", peerAddr)
	}
	return addr
}
