package dhcp

import (
	"context"
	"net"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv4/nclient4"
	"github.com/insomniacslk/dhcp/dhcpv6"
)

// This file holds the RFC-correct renewal path (#2994). Before #2994 the
// run loops ran a full DORA (v4) / Rapid-Solicit (v6) at every T1/T2,
// which is wire-level re-acquisition, not renewal: it broadcasts a fresh
// server-selection, can move the lease to a different server, and churns
// the address (and therefore interface-DDNS, FRR routes, ip-monitoring).
// RFC 2131 §4.4.5 / RFC 8415 §18.2.4-5 require a unicast RENEW to the
// granting server at T1, a broadcast/multicast REBIND at T2, and only a
// fresh DISCOVER/SOLICIT once the lease has expired.
//
// The wire exchange and the renewal wait are reached through the small
// seam helpers below so the run-loop state machine — the
// acquire→renew→rebind→re-acquire transitions and lease preservation —
// is unit-testable without real sockets or the 30 s T1 clamp.

// v4Exchange dispatches one DHCPv4 exchange through the test seam when
// set, else the real wire path.
func (m *Manager) v4Exchange(ctx context.Context, ifaceName string, mode dhcpExchangeMode, prev *Lease) (*Lease, error) {
	if m.doV4ExchangeForTest != nil {
		return m.doV4ExchangeForTest(ctx, ifaceName, mode, prev)
	}
	return m.doDHCPv4(ctx, ifaceName, mode, prev)
}

// v6Exchange dispatches one DHCPv6 exchange through the test seam when
// set, else the real wire path.
func (m *Manager) v6Exchange(ctx context.Context, ifaceName string, mode dhcpExchangeMode, prev *Lease, prevPDs []DelegatedPrefix) (*dhcpv6Result, error) {
	if m.doV6ExchangeForTest != nil {
		return m.doV6ExchangeForTest(ctx, ifaceName, mode, prev, prevPDs)
	}
	return m.doDHCPv6(ctx, ifaceName, mode, prev, prevPDs)
}

// after returns the renewal-wait channel, routed through the test seam
// when set so tests can fire T1/T2 instantly (the real clamps are 30 s
// T1 / 1 s T2, see renewalTimers).
func (m *Manager) after(d time.Duration) <-chan time.Time {
	if m.afterForTest != nil {
		return m.afterForTest(d)
	}
	return time.After(d)
}

// waitLinkLocal dispatches the DHCPv6 link-local wait through the test
// seam when set, else the real netlink poll.
func (m *Manager) waitLinkLocal(ctx context.Context, ifaceName string, timeout time.Duration) error {
	if m.waitLinkLocalForTest != nil {
		return m.waitLinkLocalForTest(ctx, ifaceName, timeout)
	}
	return m.waitForLinkLocal(ctx, ifaceName, timeout)
}

// buildV4RenewRequest builds an RFC 2131 §4.3.6 RENEWING/REBINDING
// DHCPREQUEST from the currently held lease: a DHCPREQUEST with ciaddr
// set to the held address, NO Requested-IP-Address option and NO
// Server-Identifier option (both MUST be absent in BOUND/RENEW/REBIND
// per RFC 2131 Table 5). The renew-vs-rebind distinction is the
// destination (see v4RenewDest), not the message contents, so a single
// builder serves both. mods carries per-interface options (e.g. the
// requested lease time).
func buildV4RenewRequest(hwaddr net.HardwareAddr, prev *Lease, mods []dhcpv4.Modifier) (*dhcpv4.DHCPv4, error) {
	ciaddr := net.IP(prev.Address.Addr().AsSlice())
	base := []dhcpv4.Modifier{
		dhcpv4.WithMessageType(dhcpv4.MessageTypeRequest),
		dhcpv4.WithHwAddr(hwaddr),
		dhcpv4.WithClientIP(ciaddr),
		// Client owns the address and can receive a unicast reply.
		dhcpv4.WithBroadcast(false),
		dhcpv4.WithRequestedOptions(
			dhcpv4.OptionSubnetMask,
			dhcpv4.OptionRouter,
			dhcpv4.OptionDomainName,
			dhcpv4.OptionDomainNameServer,
		),
	}
	base = append(base, mods...)
	return dhcpv4.New(base...)
}

// v4RenewDest returns the unicast/broadcast destination for a renewal
// DHCPREQUEST: RENEW (T1) unicasts to the granting server's
// server-identifier; REBIND (T2) — or a renew with no recorded
// server-identifier — broadcasts.
func v4RenewDest(prev *Lease, rebind bool) *net.UDPAddr {
	if rebind || !prev.serverID.IsValid() {
		return &net.UDPAddr{IP: net.IPv4bcast, Port: nclient4.ServerPort}
	}
	return &net.UDPAddr{IP: net.IP(prev.serverID.AsSlice()), Port: nclient4.ServerPort}
}

// buildV6RenewMessage builds an RFC 8415 §18.2.4 RENEW (rebind=false) or
// §18.2.5 REBIND (rebind=true) echoing the IA_NA address and IA_PD
// prefixes the client currently holds. RENEW includes the granting
// server's DUID (Server-Identifier) so only that server answers; REBIND
// omits it. Both are sent to All_DHCP_Relay_Agents_and_Servers (the
// client does not track the server's unicast address). IAIDs match the
// acquisition path: IA_NA uses the last 4 bytes of the MAC (as
// dhcpv6.NewSolicit does) and IA_PD uses {0,0,0,1} (as
// buildDHCPv6Modifiers does), so the server matches the existing binding.
func buildV6RenewMessage(hwaddr net.HardwareAddr, prev *Lease, prevPDs []DelegatedPrefix, rebind bool, mods []dhcpv6.Modifier) (*dhcpv6.Message, error) {
	msg, err := dhcpv6.NewMessage()
	if err != nil {
		return nil, err
	}
	if rebind {
		msg.MessageType = dhcpv6.MessageTypeRebind
	} else {
		msg.MessageType = dhcpv6.MessageTypeRenew
	}

	// Client identifier + ORO come from the per-interface modifiers.
	for _, mod := range mods {
		mod(msg)
	}
	msg.AddOption(dhcpv6.OptElapsedTime(0))

	// RENEW targets the original server; REBIND omits the server DUID.
	if !rebind && prev != nil && prev.v6ServerDUID != nil {
		dhcpv6.WithServerID(prev.v6ServerDUID)(msg)
	}

	// Echo the held IA_NA address.
	if prev != nil && prev.Address.IsValid() {
		var iaid [4]byte
		if l := len(hwaddr); l >= 4 {
			copy(iaid[:], hwaddr[l-4:l])
		}
		dhcpv6.WithIANA(dhcpv6.OptIAAddress{
			IPv6Addr:      net.IP(prev.Address.Addr().AsSlice()),
			ValidLifetime: prev.LeaseTime,
		})(msg)
		dhcpv6.WithIAID(iaid)(msg)
	}

	// Echo the held delegated prefixes (IA_PD).
	if len(prevPDs) > 0 {
		prefixes := make([]*dhcpv6.OptIAPrefix, 0, len(prevPDs))
		for _, pd := range prevPDs {
			prefixes = append(prefixes, &dhcpv6.OptIAPrefix{
				PreferredLifetime: pd.PreferredLifetime,
				ValidLifetime:     pd.ValidLifetime,
				Prefix: &net.IPNet{
					IP:   net.IP(pd.Prefix.Addr().AsSlice()),
					Mask: net.CIDRMask(pd.Prefix.Bits(), 128),
				},
			})
		}
		dhcpv6.WithIAPD([4]byte{0, 0, 0, 1}, prefixes...)(msg)
	}

	return msg, nil
}
