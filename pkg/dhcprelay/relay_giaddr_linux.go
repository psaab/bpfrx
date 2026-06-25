package dhcprelay

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// init replaces the portable IPv4 lister with a netlink-backed one so the
// giaddr resolver can honor the kernel's IFA_F_SECONDARY flag. On Linux an
// interface may carry a primary address plus secondary subnet aliases; the
// kernel returns them in maintenance order, NOT guaranteed primary-first.
// net.Interface.Addrs() discards the secondary flag, so selecting the first
// address can stamp a secondary alias as giaddr and lease from the wrong
// subnet pool (#2849). netlink.AddrList preserves the flag.
//
// netlinkIPv4Lister is a package var (not assigned inline) so a test can drive
// the selection logic through this Linux path with a fake address list without
// requiring root or a real interface.
func init() {
	primaryIPv4Lister = netlinkIPv4Lister
}

// netlinkAddrLister is the seam over netlink.LinkByName + netlink.AddrList so
// tests can inject a fake address set. Production uses listLinkAddrs.
var netlinkAddrLister = listLinkAddrs

// listLinkAddrs returns the IPv4 addresses of ifaceName via netlink, including
// the per-address flags (which carry IFA_F_SECONDARY).
func listLinkAddrs(ifaceName string) ([]netlink.Addr, error) {
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("interface lookup: %w", err)
	}
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return nil, fmt.Errorf("list addresses: %w", err)
	}
	return addrs, nil
}

// netlinkIPv4Lister enumerates non-loopback IPv4 addresses on ifaceName via
// netlink, recording each address's secondary flag so selectPrimaryIPv4 can
// prefer the primary. If netlink enumeration fails it falls back to the
// portable lister rather than failing closed — a transient netlink hiccup must
// not strand a relay that the standard library can still address.
func netlinkIPv4Lister(ifaceName string) ([]ipv4Candidate, error) {
	addrs, err := netlinkAddrLister(ifaceName)
	if err != nil {
		return portableIPv4Lister(ifaceName)
	}
	var cands []ipv4Candidate
	for _, a := range addrs {
		if a.IPNet == nil {
			continue
		}
		ip4 := a.IP.To4()
		if ip4 == nil || ip4.IsLoopback() {
			continue
		}
		cands = append(cands, ipv4Candidate{
			ip:        append(net.IP(nil), ip4...),
			secondary: a.Flags&unix.IFA_F_SECONDARY != 0,
		})
	}
	// If netlink returned no usable IPv4 (e.g. address churn mid-rename), fall
	// back to the portable path before declaring the interface unaddressed.
	if len(cands) == 0 {
		return portableIPv4Lister(ifaceName)
	}
	return cands, nil
}
