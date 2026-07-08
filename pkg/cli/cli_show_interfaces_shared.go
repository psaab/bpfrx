package cli

import (
	"net"
	"os"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dhcp"
	"github.com/vishvananda/netlink"
)

// dhcpLease returns the current DHCP lease for a managed interface, if any.
// Consumed by `show interfaces` presenters when rendering DHCP-assigned
// addresses; returns nil when no DHCP client is wired or no lease exists.
func (c *CLI) dhcpLease(ifaceName string, af dhcp.AddressFamily) *dhcp.Lease {
	if c.dhcp == nil {
		return nil
	}
	return c.dhcp.LeaseFor(ifaceName, af)
}

// rethMemberLinkState returns the admin/link ("up"/"down") state for a reth's
// physical member, best-effort from the kernel. When the device is absent (a
// peer-owned member, or a test host with no such netdev) admin stays "up" and
// only link is reported "down" — matching the terse handler (#4328).
func rethMemberLinkState(member string) (admin, link string) {
	admin, link = "up", "up"
	kernelIf := config.LinuxIfName(member)
	iface, err := net.InterfaceByName(kernelIf)
	if err != nil {
		return "up", "down"
	}
	if iface.Flags&net.FlagUp == 0 {
		admin = "down"
	}
	if data, err := os.ReadFile("/sys/class/net/" + kernelIf + "/operstate"); err == nil {
		if strings.TrimSpace(string(data)) != "up" {
			link = "down"
		}
	}
	return admin, link
}

// baseIfName strips a dotted unit suffix ("reth0.50" -> "reth0").
func baseIfName(name string) string {
	if i := strings.IndexByte(name, '.'); i >= 0 {
		return name[:i]
	}
	return name
}

// rethMemberAttrs returns the netlink attributes of a reth's physical member,
// best-effort. ok is false when the member device is absent (peer-owned or a
// test host) so callers render from config alone (#4328).
func rethMemberAttrs(member string) (attrs *netlink.LinkAttrs, ok bool) {
	link, err := netlink.LinkByName(config.LinuxIfName(member))
	if err != nil {
		return nil, false
	}
	return link.Attrs(), true
}
