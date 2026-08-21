package daemon

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"

	"github.com/vishvananda/netlink"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #6554 — the fabric peer-MAC IPv6-NDP fallback must not accept an arbitrary
// link-local neighbour.
//
// probeFabricNeighbor deliberately seeds the fabric parent's NDP table by
// pinging ff02::1, so every IPv6-speaking host on the segment answers. The
// pre-fix fallback then took the FIRST non-self link-local entry it found. On a
// shared fabric segment that is an unrelated adjacent host: the refresh
// programs a stranger's MAC as the cross-chassis peer, reports success, and
// latches fabricPopulated (which feeds the RG takeover-readiness gate).
//
// These tests drive the real refreshFabricFwd end-to-end against a synthetic
// link + neighbour table and assert on the MAC actually handed to
// SetFabricForwarding — the value that is programmed — not on an intermediate.

// fabricProgramRecorder captures every SetFabricForwarding call so a test can
// assert on the FabricFwdInfo that was actually programmed.
type fabricProgramRecorder struct {
	mu     sync.Mutex
	writes []dataplane.FabricFwdInfo
	ids    []dataplane.FabricID
	syncs  int
}

func (h *fabricProgramRecorder) SetRGActive(_ context.Context, _ int, _ bool) error { return nil }
func (h *fabricProgramRecorder) SetHAWatchdog(_ context.Context, _ int, _ uint64) error {
	return nil
}

func (h *fabricProgramRecorder) SetFabricForwarding(_ context.Context, id dataplane.FabricID, info dataplane.FabricFwdInfo) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.ids = append(h.ids, id)
	h.writes = append(h.writes, info)
	return nil
}

func (h *fabricProgramRecorder) SyncFabricState(_ context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.syncs++
	return nil
}

// programmedPeerMACs returns the peer MACs of every NON-ZERO fabric write, in
// order. A zeroed write is a clear (clearFabricFwd0), not a programmed peer.
func (h *fabricProgramRecorder) programmedPeerMACs() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []string
	for _, w := range h.writes {
		if w.Ifindex == 0 {
			continue
		}
		out = append(out, net.HardwareAddr(w.PeerMAC[:]).String())
	}
	return out
}

type fabricProgramDP struct {
	dataplane.RuntimeDataPlane
	ha *fabricProgramRecorder
}

func (d *fabricProgramDP) HA() dataplane.HAController { return d.ha }

const (
	fabPeerTestLocalMAC = "02:00:00:00:00:0a" // this node's fabric parent MAC
	fabPeerTestPeerMAC  = "02:00:00:00:00:0b" // the real peer chassis
	fabPeerTestDecoyMAC = "02:00:00:00:00:99" // an unrelated host on the segment
)

func mustMAC(t *testing.T, s string) net.HardwareAddr {
	t.Helper()
	mac, err := net.ParseMAC(s)
	if err != nil {
		t.Fatalf("ParseMAC(%q): %v", s, err)
	}
	return mac
}

// fabPeerNeigh builds a valid (REACHABLE) neighbour entry.
func fabPeerNeigh(t *testing.T, ip, mac string) netlink.Neigh {
	t.Helper()
	parsed := net.ParseIP(ip)
	if parsed == nil {
		t.Fatalf("ParseIP(%q) failed", ip)
	}
	return netlink.Neigh{
		IP:           parsed,
		HardwareAddr: mustMAC(t, mac),
		State:        netlink.NUD_REACHABLE,
	}
}

// fabPeerTestDaemon wires a Daemon whose fabric parent resolves to a synthetic
// link and whose neighbour dumps come from parentV6 (the fabric parent's IPv6
// NDP table, seeded by the ff02::1 probe). The overlay's own neighbour table is
// deliberately EMPTY and no parent IPv4 entry exists for the peer address, so
// resolution falls through to the link-local NDP fallback under test.
//
// TxQLen is pre-set at the 10000 threshold so refreshFabricFwd never issues a
// real netlink LinkSetTxQLen against the fake link.
func fabPeerTestDaemon(t *testing.T, parentV6 []netlink.Neigh) (*Daemon, *fabricProgramRecorder) {
	t.Helper()
	const (
		parentIdx  = 11
		overlayIdx = 12
	)
	parent := &testLink{attrs: netlink.LinkAttrs{
		Name:         "ge-0-0-0",
		Index:        parentIdx,
		OperState:    netlink.OperUp,
		TxQLen:       10000,
		HardwareAddr: mustMAC(t, fabPeerTestLocalMAC),
	}}
	overlay := &testLink{attrs: netlink.LinkAttrs{
		Name:         "fab0",
		Index:        overlayIdx,
		ParentIndex:  parentIdx,
		OperState:    netlink.OperUp,
		TxQLen:       10000,
		HardwareAddr: mustMAC(t, fabPeerTestLocalMAC),
	}}

	rec := &fabricProgramRecorder{}
	d := &Daemon{
		linkByNameFn: mockLinkByName(map[string]*testLink{
			"ge-0-0-0": parent,
			"fab0":     overlay,
		}),
		neighListFn: func(ifindex, family int) ([]netlink.Neigh, error) {
			if ifindex == parentIdx && family == netlink.FAMILY_V6 {
				return parentV6, nil
			}
			// Overlay ARP and parent IPv4 both miss — the state this
			// fallback exists to recover from.
			return nil, nil
		},
	}
	d.setDataplane(&fabricProgramDP{ha: rec}) // #2114: publish through the cell
	return d, rec
}

func fabPeerRefresh(t *testing.T, d *Daemon) bool {
	t.Helper()
	return d.refreshFabricFwd(context.Background(), "ge-0-0-0", "fab0",
		net.ParseIP("10.99.13.2"), false)
}

// TestFabricPeerNDPFallbackRejectsDecoyWithKnownPeerMAC is the primary
// fail-on-revert gate. A decoy link-local neighbour is listed FIRST, ahead of
// the real peer, and the peer's MAC is already known from an earlier
// address-matched resolution. The permissive pre-#6554 loop took the first
// non-self link-local entry and would program the decoy's MAC.
func TestFabricPeerNDPFallbackRejectsDecoyWithKnownPeerMAC(t *testing.T) {
	d, rec := fabPeerTestDaemon(t, []netlink.Neigh{
		// Decoy first — a permissive first-match selection picks this.
		fabPeerNeigh(t, "fe80::dec0", fabPeerTestDecoyMAC),
		fabPeerNeigh(t, "fe80::b", fabPeerTestPeerMAC),
	})
	// An earlier address-matched resolution established the peer's identity.
	d.rememberFabricPeerMAC(0, mustMAC(t, fabPeerTestPeerMAC))

	if !fabPeerRefresh(t, d) {
		t.Fatal("refreshFabricFwd returned false; expected the real peer to resolve")
	}

	got := rec.programmedPeerMACs()
	if len(got) != 1 {
		t.Fatalf("expected exactly one programmed fabric entry, got %d (%v)", len(got), got)
	}
	if got[0] == fabPeerTestDecoyMAC {
		// Scope note: the MAC this path programs goes into the retired-eBPF
		// `fabric_fwd` map (pkg/dataplane/maps_fabric.go). The LIVE Rust
		// redirect re-derives FabricSnapshot.PeerMAC with its own
		// address-matched neighbour lookup (buildFabricPeerMAC,
		// pkg/dataplane/userspace/fabric.go), so a decoy accepted here never
		// becomes an L2 destination. The damage is false readiness, not
		// misdelivery — assert on that, not on a forwarding claim.
		t.Fatalf("DECOY MAC %s was programmed as the fabric peer — the node would "+
			"latch fabricPopulated, end the fast-retry probe loop early, and log an "+
			"unrelated host's MAC as the fabric peer during an HA incident (#6554)",
			fabPeerTestDecoyMAC)
	}
	if got[0] != fabPeerTestPeerMAC {
		t.Fatalf("programmed peer MAC = %s, want the real peer %s", got[0], fabPeerTestPeerMAC)
	}
}

// TestFabricPeerNDPFallbackRefusesAmbiguousSegment covers the cold-start case:
// a decoy is present alongside the real peer but NO address-matched resolution
// has ever identified the peer. With no identity to check against, the segment
// is ambiguous and the fallback must refuse rather than guess. The permissive
// form programmed the decoy.
func TestFabricPeerNDPFallbackRefusesAmbiguousSegment(t *testing.T) {
	d, rec := fabPeerTestDaemon(t, []netlink.Neigh{
		fabPeerNeigh(t, "fe80::dec0", fabPeerTestDecoyMAC),
		fabPeerNeigh(t, "fe80::b", fabPeerTestPeerMAC),
	})
	// No rememberFabricPeerMAC — the peer address has never resolved.

	if fabPeerRefresh(t, d) {
		t.Fatal("refreshFabricFwd reported success on an ambiguous fabric segment; " +
			"expected a fail-closed refusal (#6554)")
	}
	if got := rec.programmedPeerMACs(); len(got) != 0 {
		t.Fatalf("a peer MAC was programmed from an unidentifiable segment: %v "+
			"(decoy=%s, peer=%s) (#6554)", got, fabPeerTestDecoyMAC, fabPeerTestPeerMAC)
	}
	if d.fabricEntryPopulated(0) {
		t.Fatal("fabricPopulated latched on a refused resolution — the RG " +
			"takeover-readiness gate would read a fabric that never resolved")
	}
}

// TestFabricPeerNDPFallbackResolvesSolePeer is the over-reach guard: the normal
// point-to-point fabric — only the real peer on the segment, no cached identity
// — must still resolve, and to the peer's MAC. This test must stay GREEN when
// the fix is reverted.
func TestFabricPeerNDPFallbackResolvesSolePeer(t *testing.T) {
	d, rec := fabPeerTestDaemon(t, []netlink.Neigh{
		fabPeerNeigh(t, "fe80::b", fabPeerTestPeerMAC),
	})

	if !fabPeerRefresh(t, d) {
		t.Fatal("refreshFabricFwd returned false on a healthy point-to-point fabric")
	}
	got := rec.programmedPeerMACs()
	if len(got) != 1 || got[0] != fabPeerTestPeerMAC {
		t.Fatalf("programmed peer MACs = %v, want exactly [%s]", got, fabPeerTestPeerMAC)
	}
	if !d.fabricEntryPopulated(0) {
		t.Fatal("fabricPopulated not set after a successful sole-peer resolution")
	}
}

// TestFabricPeerNDPFallbackSolePeerMatchesKnownIdentity is the second half of
// the over-reach guard: a healthy fabric that HAS resolved before must keep
// resolving to the same MAC once the identity constraint is armed.
func TestFabricPeerNDPFallbackSolePeerMatchesKnownIdentity(t *testing.T) {
	d, rec := fabPeerTestDaemon(t, []netlink.Neigh{
		fabPeerNeigh(t, "fe80::b", fabPeerTestPeerMAC),
	})
	d.rememberFabricPeerMAC(0, mustMAC(t, fabPeerTestPeerMAC))

	if !fabPeerRefresh(t, d) {
		t.Fatal("refreshFabricFwd returned false for the known peer")
	}
	got := rec.programmedPeerMACs()
	if len(got) != 1 || got[0] != fabPeerTestPeerMAC {
		t.Fatalf("programmed peer MACs = %v, want exactly [%s]", got, fabPeerTestPeerMAC)
	}
}

// TestFabricPeerNDPFallbackRefusesLoneDecoyWhenPeerKnown covers the peer-down
// case on a shared segment: the real peer is gone, only the decoy answers. With
// the peer's identity known, the sole remaining neighbour must still be
// refused — "the only host left" is not "the peer".
func TestFabricPeerNDPFallbackRefusesLoneDecoyWhenPeerKnown(t *testing.T) {
	d, rec := fabPeerTestDaemon(t, []netlink.Neigh{
		fabPeerNeigh(t, "fe80::dec0", fabPeerTestDecoyMAC),
	})
	d.rememberFabricPeerMAC(0, mustMAC(t, fabPeerTestPeerMAC))

	if fabPeerRefresh(t, d) {
		t.Fatal("refreshFabricFwd accepted a lone non-peer neighbour")
	}
	if got := rec.programmedPeerMACs(); len(got) != 0 {
		t.Fatalf("programmed peer MACs = %v, want none", got)
	}
}

// TestFabricPeerAddressMatchRecordsIdentity proves the identity the fallback
// checks against comes from an ADDRESS-MATCHED resolution — the MAC that
// actually answered for the configured fabric peer address — and that the
// fallback's own result never promotes itself into that identity.
func TestFabricPeerAddressMatchRecordsIdentity(t *testing.T) {
	t.Run("address match records", func(t *testing.T) {
		d, _ := fabPeerTestDaemon(t, nil)
		peerIP := net.ParseIP("10.99.13.2")
		d.neighListFn = func(ifindex, family int) ([]netlink.Neigh, error) {
			if ifindex == 12 && family == netlink.FAMILY_V4 {
				return []netlink.Neigh{
					fabPeerNeigh(t, peerIP.String(), fabPeerTestPeerMAC),
				}, nil
			}
			return nil, nil
		}
		if !fabPeerRefresh(t, d) {
			t.Fatal("refreshFabricFwd returned false on an address-matched resolution")
		}
		hint := d.fabricPeerMACHint(0)
		if hint.String() != fabPeerTestPeerMAC {
			t.Fatalf("peer identity hint = %v, want %s", hint, fabPeerTestPeerMAC)
		}
	})

	t.Run("fallback result is not promoted to identity", func(t *testing.T) {
		d, _ := fabPeerTestDaemon(t, []netlink.Neigh{
			fabPeerNeigh(t, "fe80::b", fabPeerTestPeerMAC),
		})
		if !fabPeerRefresh(t, d) {
			t.Fatal("refreshFabricFwd returned false on a sole-peer segment")
		}
		if hint := d.fabricPeerMACHint(0); hint != nil {
			t.Fatalf("link-local fallback promoted its own result to the peer "+
				"identity (%v); a single bad selection would then pin every "+
				"later refresh", hint)
		}
	})
}

// TestFabricPeerIdentityClearedOnPeerChange proves a re-pointed fabric drops
// the cached identity: the new peer chassis has a different MAC, and pinning
// the old one would refuse the new peer forever.
func TestFabricPeerIdentityClearedOnPeerChange(t *testing.T) {
	d := &Daemon{}
	// Hermetic by construction (#6595). populateFabricFwd now checks ctx before
	// the first probe, so a cancelled context returns without touching netlink —
	// but do not let this test's SAFETY depend on that check surviving. Pin the
	// netlink seams to hard errors so a regression in the cancellation guard
	// fails as an assertion here rather than dumping the kernel neighbour table
	// and transmitting an ICMP / ff02::1 probe on whatever real interface
	// happens to be named ge-0-0-0 on the machine running the suite.
	d.linkByNameFn = func(string) (netlink.Link, error) {
		return nil, errors.New("hermetic test: netlink disabled")
	}
	d.neighListFn = func(int, int) ([]netlink.Neigh, error) {
		return nil, errors.New("hermetic test: netlink disabled")
	}
	d.fabricPeerIP = net.ParseIP("10.99.13.2")
	d.rememberFabricPeerMAC(0, mustMAC(t, fabPeerTestPeerMAC))
	d.fabricPeerIP1 = net.ParseIP("10.99.14.2")
	d.rememberFabricPeerMAC(1, mustMAC(t, fabPeerTestPeerMAC))

	// Same peer — identity survives.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	d.populateFabricFwd(ctx, "ge-0-0-0", "fab0", "10.99.13.2", nil)
	if d.fabricPeerMACHint(0) == nil {
		t.Fatal("peer identity cleared even though the peer address is unchanged")
	}

	// Different peer — identity must be dropped.
	d.populateFabricFwd(ctx, "ge-0-0-0", "fab0", "10.99.13.3", nil)
	if hint := d.fabricPeerMACHint(0); hint != nil {
		t.Fatalf("stale peer identity %v retained across a fabric peer change", hint)
	}

	d.populateFabricFwd1(ctx, "ge-0-0-0", "fab1", "10.99.14.3", nil)
	if hint := d.fabricPeerMACHint(1); hint != nil {
		t.Fatalf("stale fab1 peer identity %v retained across a peer change", hint)
	}
}

// TestPopulateFabricFwdHonoursCancelledContextBeforeFirstProbe pins the #6595
// cancellation guard. The retry loop used to check ctx.Done() only inside its
// `i > 0` sleep arm, so iteration 0 ran unconditionally: an already-cancelled
// caller still reached probeFabricNeighbor, which dumps the kernel neighbour
// table and — on a miss — transmits a raw ICMP probe plus an ff02::1
// solicitation on a live interface. A cancelled context must put nothing on the
// wire and read nothing from netlink.
//
// The assertion is a netlink-touch count rather than a packet capture: both
// populateFabricFwd's probe and its refreshFabricFwd call reach the kernel
// through fabricLinkByName, so ZERO calls is the only state in which neither
// can have run. Reverting the guard makes this count non-zero.
func TestPopulateFabricFwdHonoursCancelledContextBeforeFirstProbe(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(d *Daemon, ctx context.Context)
	}{
		{"fab0", func(d *Daemon, ctx context.Context) {
			d.populateFabricFwd(ctx, "ge-0-0-0", "fab0", "10.99.13.2", nil)
		}},
		{"fab1", func(d *Daemon, ctx context.Context) {
			d.populateFabricFwd1(ctx, "ge-0-0-0", "fab1", "10.99.14.2", nil)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			netlinkTouches := 0
			d := &Daemon{}
			d.linkByNameFn = func(string) (netlink.Link, error) {
				mu.Lock()
				netlinkTouches++
				mu.Unlock()
				return nil, errors.New("hermetic test: netlink disabled")
			}
			d.neighListFn = func(int, int) ([]netlink.Neigh, error) {
				mu.Lock()
				netlinkTouches++
				mu.Unlock()
				return nil, errors.New("hermetic test: netlink disabled")
			}

			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			tc.run(d, ctx)

			mu.Lock()
			got := netlinkTouches
			mu.Unlock()
			if got != 0 {
				t.Fatalf("cancelled context still performed %d netlink read(s) — "+
					"the pre-probe ctx.Err() guard is not holding, so a cancelled "+
					"caller can still transmit an ICMP/ff02::1 probe on a live NIC "+
					"(#6595)", got)
			}
		})
	}
}

// TestSelectFabricPeerLinkLocalMAC exercises the candidate filter directly:
// which neighbour entries are eligible at all, and how ambiguity is resolved.
func TestSelectFabricPeerLinkLocalMAC(t *testing.T) {
	local := mustMAC(t, fabPeerTestLocalMAC)
	peer := mustMAC(t, fabPeerTestPeerMAC)

	withState := func(n netlink.Neigh, state int) netlink.Neigh {
		n.State = state
		return n
	}

	tests := []struct {
		name     string
		neighs   []netlink.Neigh
		expected net.HardwareAddr
		want     string // "" means refusal
	}{
		{
			name:   "sole peer accepted",
			neighs: []netlink.Neigh{fabPeerNeigh(t, "fe80::b", fabPeerTestPeerMAC)},
			want:   fabPeerTestPeerMAC,
		},
		{
			name: "self entry ignored",
			neighs: []netlink.Neigh{
				fabPeerNeigh(t, "fe80::a", fabPeerTestLocalMAC),
				fabPeerNeigh(t, "fe80::b", fabPeerTestPeerMAC),
			},
			want: fabPeerTestPeerMAC,
		},
		{
			name: "global unicast ignored",
			neighs: []netlink.Neigh{
				fabPeerNeigh(t, "2001:db8::99", fabPeerTestDecoyMAC),
				fabPeerNeigh(t, "fe80::b", fabPeerTestPeerMAC),
			},
			want: fabPeerTestPeerMAC,
		},
		{
			name: "unusable NUD state ignored",
			neighs: []netlink.Neigh{
				withState(fabPeerNeigh(t, "fe80::dec0", fabPeerTestDecoyMAC), netlink.NUD_FAILED),
				fabPeerNeigh(t, "fe80::b", fabPeerTestPeerMAC),
			},
			want: fabPeerTestPeerMAC,
		},
		{
			name: "group-bit MAC ignored",
			neighs: []netlink.Neigh{
				fabPeerNeigh(t, "fe80::dec0", "33:33:00:00:00:01"),
				fabPeerNeigh(t, "fe80::b", fabPeerTestPeerMAC),
			},
			want: fabPeerTestPeerMAC,
		},
		{
			name: "multiple link-locals on one peer NIC are one candidate",
			neighs: []netlink.Neigh{
				fabPeerNeigh(t, "fe80::b", fabPeerTestPeerMAC),
				fabPeerNeigh(t, "fe80::bbbb", fabPeerTestPeerMAC),
			},
			want: fabPeerTestPeerMAC,
		},
		{
			name: "two distinct hosts refused without identity",
			neighs: []netlink.Neigh{
				fabPeerNeigh(t, "fe80::dec0", fabPeerTestDecoyMAC),
				fabPeerNeigh(t, "fe80::b", fabPeerTestPeerMAC),
			},
			want: "",
		},
		{
			name: "two distinct hosts resolved by identity",
			neighs: []netlink.Neigh{
				fabPeerNeigh(t, "fe80::dec0", fabPeerTestDecoyMAC),
				fabPeerNeigh(t, "fe80::b", fabPeerTestPeerMAC),
			},
			expected: peer,
			want:     fabPeerTestPeerMAC,
		},
		{
			name:     "lone decoy refused against identity",
			neighs:   []netlink.Neigh{fabPeerNeigh(t, "fe80::dec0", fabPeerTestDecoyMAC)},
			expected: peer,
			want:     "",
		},
		{
			name:   "empty table refused",
			neighs: nil,
			want:   "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mac, peerLL, n, reason := selectFabricPeerLinkLocalMAC(tc.neighs, local, tc.expected)
			if tc.want == "" {
				if mac != nil {
					t.Fatalf("selected %v (ll=%v), want refusal", mac, peerLL)
				}
				if reason == "" {
					t.Fatal("refusal carried no operator-facing reason")
				}
				return
			}
			if mac == nil {
				t.Fatalf("refused (%s, candidates=%d), want %s", reason, n, tc.want)
			}
			if mac.String() != tc.want {
				t.Fatalf("selected %s, want %s", mac, tc.want)
			}
			if reason != "" {
				t.Fatalf("success carried a refusal reason: %s", reason)
			}
			if peerLL == nil {
				t.Fatal("success carried no link-local address for logging")
			}
		})
	}
}
