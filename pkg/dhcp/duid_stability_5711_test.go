package dhcp

import (
	"bytes"
	"net"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv6"
)

// firstHWIface returns a local interface whose hardware address is at least 4
// bytes long — dhcpv6.NewSolicit derives the IA_NA IAID from the last 4 MAC
// bytes and errors on a shorter address, so loopback (empty MAC) will not do.
// Skips the test when no such interface exists.
func firstHWIface(t *testing.T) net.Interface {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Skipf("enumerate interfaces: %v", err)
	}
	for _, ifc := range ifaces {
		if len(ifc.HardwareAddr) >= 4 {
			return ifc
		}
	}
	t.Skip("no interface with a >=4-byte hardware address available")
	return net.Interface{}
}

// clientIDBytes rebuilds the SOLICIT the acquisition path actually sends
// (dhcpv6.NewSolicit + WithRapidCommit, mirroring nclient6.RapidSolicit) and
// the RENEW the renewal path sends (buildV6RenewMessage), then returns the
// Client-ID DUID bytes each presents on the wire.
func acquisitionDUID(t *testing.T, m *Manager, ifc net.Interface) []byte {
	t.Helper()
	mods := m.buildDHCPv6Modifiers(ifc.Name, nil)
	sol, err := dhcpv6.NewSolicit(ifc.HardwareAddr, append(mods, dhcpv6.WithRapidCommit)...)
	if err != nil {
		t.Fatalf("build acquisition SOLICIT: %v", err)
	}
	duid := sol.Options.ClientID()
	if duid == nil {
		t.Fatal("acquisition SOLICIT carries no Client-ID")
	}
	return duid.ToBytes()
}

func renewalDUID(t *testing.T, m *Manager, ifc net.Interface) []byte {
	t.Helper()
	renewMods := m.buildDHCPv6RenewModifiers(ifc.Name, nil)
	msg, err := buildV6RenewMessage(ifc.HardwareAddr, nil, nil, false, renewMods)
	if err != nil {
		t.Fatalf("build RENEW: %v", err)
	}
	duid := msg.Options.ClientID()
	if duid == nil {
		t.Fatal("RENEW carries no Client-ID")
	}
	return duid.ToBytes()
}

// TestDHCPv6DUIDStableAcrossAcquisitionAndRenew pins #5711: the DUID a bare
// DHCPv6 client presents at initial acquisition (SOLICIT) MUST be byte-identical
// to the DUID it presents at RENEW/REBIND. RFC 8415 §11 requires a stable
// client DUID for the client's lifetime; the server binds the lease to it, so a
// renewal sent under a different DUID is a new client and the original lease is
// not renewed.
//
// RED on revert: before the fix, buildDHCPv6Modifiers returned nil when
// opts == nil, so RapidSolicit/NewSolicit fell back to its default DUID-LLT
// (Time = GetTime() at send) while the renew path always used the persistent
// getDUID (default DUID-LL). Acquisition presented a DUID-LLT and renewal a
// DUID-LL — different type and different bytes — and this assertion fails.
func TestDHCPv6DUIDStableAcrossAcquisitionAndRenew(t *testing.T) {
	ifc := firstHWIface(t)

	// Default DUID type (empty -> DUID-LL). Both paths must read the same
	// persistent identity.
	m := &Manager{
		duids:     map[string]dhcpv6.DUID{},
		duidTypes: map[string]string{},
		stateDir:  t.TempDir(),
	}

	acq := acquisitionDUID(t, m, ifc)
	renew := renewalDUID(t, m, ifc)
	if !bytes.Equal(acq, renew) {
		t.Fatalf("DUID diverges between acquisition and renewal:\n  acquisition=%x\n  renewal    =%x", acq, renew)
	}
}

// TestDHCPv6DUIDLLTStableAcrossAcquisitionAndRenew is the DUID-LLT companion to
// the above. A DUID-LLT embeds a generation timestamp; the stable identity must
// come from the once-generated, persisted DUID-LLT — the same Time on every
// message — NOT a per-message GetTime(). If acquisition recomputed the LLT Time
// while renewal used the persisted one, their bytes would differ even though
// both are DUID-LLT.
//
// RED on revert: acquisition (opts == nil -> nil mods) let NewSolicit stamp a
// fresh DUID-LLT with GetTime() at send, so the Time field (and thus the bytes)
// would not match the persisted DUID-LLT the renew path presents.
func TestDHCPv6DUIDLLTStableAcrossAcquisitionAndRenew(t *testing.T) {
	ifc := firstHWIface(t)

	m := &Manager{
		duids:     map[string]dhcpv6.DUID{},
		duidTypes: map[string]string{ifc.Name: "duid-llt"},
		stateDir:  t.TempDir(),
	}

	acq := acquisitionDUID(t, m, ifc)
	renew := renewalDUID(t, m, ifc)
	if !bytes.Equal(acq, renew) {
		t.Fatalf("DUID-LLT diverges between acquisition and renewal (timestamp recomputed per-message?):\n  acquisition=%x\n  renewal    =%x", acq, renew)
	}

	// Sanity: the stable identity must actually be a DUID-LLT (type 1), not a
	// silently substituted default.
	if got := m.duids[ifc.Name]; got == nil || got.DUIDType() != dhcpv6.DUID_LLT {
		t.Fatalf("expected a persisted DUID-LLT, got %v", got)
	}
}
