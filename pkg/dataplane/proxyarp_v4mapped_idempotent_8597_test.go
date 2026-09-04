package dataplane

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// #8597 (muse-spark-review-004 K21): a `::ffff:a.b.c.d` proxy-ARP literal must
// CONVERGE — the second reconcile pass must install nothing.
//
// The desired key was built from `prefix.Addr()`, which for a v4-mapped literal
// is a 4-in-6 `netip.Addr` (16 bytes). The existing key is built from
// `n.IP.To4()` on the kernel's v4 NeighList pass (4 bytes). `netip.Addr`
// equality distinguishes the two forms, so `desired` never matched `existing`
// and the add loop fired on every pass — a NeighSet and an error log every 30
// seconds, forever, with the entry never recognised as installed.
//
// WHY THE EXISTING TESTS DID NOT SEE IT, which is the part worth keeping.
// `TestReconcileProxyARP_V4MappedClassifiesAsV4` pins the FIRST install's
// family and stops there; `TestReconcileProxyARP_V6Idempotent` pins the
// second-pass property but only for a genuine v6 address. The 4-in-6 form had a
// first-pass test and an idempotency test, and no cell where those two axes
// crossed — which is exactly where it lived.
//
// The rationale in `proxyarp.go` reads as though the case is handled, and it is
// — on the FAMILY axis. Both that comment and `keyFamily`'s are correct about
// what family a 4-in-6 literal installs under, and silent about what form its
// KEY takes. A rationale is scoped to the axis it was written against.

func TestReconcileProxyARP_V4MappedIdempotent_8597(t *testing.T) {
	const idx = 7
	// The kernel's v4 pass reports the address in 4-form — this is what
	// `NeighList(AF_INET)` yields for an entry installed from a `::ffff:`
	// literal, and it is the seam value that makes the two key forms meet.
	existing := []netlink.Neigh{{
		LinkIndex: idx,
		IP:        net.ParseIP("10.0.0.1").To4(),
		Flags:     unix.NTF_PROXY,
		Family:    unix.AF_INET,
	}}
	sets, dels := captureNeigh(t, existing)
	captureProxySysctl(t, false)

	cfg := &config.Config{}
	cfg.Security.NAT.ProxyARP = []*config.ProxyARPEntry{
		{Interface: "ge-0-0-2", Addresses: []string{"::ffff:10.0.0.1/128"}},
	}
	ifaceMap := map[string]int{"ge-0-0-2": idx}

	if _, _, err := ReconcileProxyARP(cfg, ifaceMap, nil, nil); err != nil {
		t.Fatalf("ReconcileProxyARP: %v", err)
	}
	if len(*sets) != 0 {
		t.Fatalf("#8597: a v4-mapped proxy-ARP entry already present in the kernel was "+
			"RE-INSTALLED, so the reconcile never converges: it re-adds and logs every pass "+
			"forever. desired keys the 4-in-6 form, existing keys the 4-form, and netip.Addr "+
			"equality separates them. NeighSet calls: %+v", *sets)
	}
	if len(*dels) != 0 {
		t.Fatalf("#8597: the desired v4-mapped entry was swept as stale: %+v", *dels)
	}
}

// TestReconcileProxyARP_V4MappedStillInstallsFirst_8597 is the control that
// fails on the over-broad fix. Unmapping must not stop the entry being
// installed when the kernel does NOT already have it — a change that made
// desired and existing agree by dropping the entry entirely would satisfy the
// idempotency cell above and install nothing at all.
func TestReconcileProxyARP_V4MappedStillInstallsFirst_8597(t *testing.T) {
	sets, _ := captureNeigh(t, nil)
	captureProxySysctl(t, false)

	cfg := &config.Config{}
	cfg.Security.NAT.ProxyARP = []*config.ProxyARPEntry{
		{Interface: "ge-0-0-2", Addresses: []string{"::ffff:10.0.0.1/128"}},
	}
	if _, _, err := ReconcileProxyARP(cfg, map[string]int{"ge-0-0-2": 7}, nil, nil); err != nil {
		t.Fatalf("ReconcileProxyARP: %v", err)
	}
	if len(*sets) != 1 {
		t.Fatalf("#8597 control: the first pass must still install exactly one entry; got %+v", *sets)
	}
	// And still as v4, which is the property the pre-existing
	// ..._V4MappedClassifiesAsV4 cell pins — asserted here too so this file
	// cannot pass while silently changing the family.
	if (*sets)[0].Family != unix.AF_INET {
		t.Fatalf("#8597 control: v4-mapped literal must install as AF_INET; got family %d",
			(*sets)[0].Family)
	}
	// The installed IP must be the v4 form, which is what makes the second pass
	// recognise it. Asserting the family alone would not catch a key that is
	// still 4-in-6.
	if ip := (*sets)[0].IP; ip.To4() == nil {
		t.Fatalf("#8597 control: the installed address must be in v4 form; got %v", ip)
	}
}
