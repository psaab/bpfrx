package frr

import (
	"regexp"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #5518: the BGP declaration loop skips a remote-as-0 neighbor (the #2963
// fail-closed guard, RFC 7607 reserved AS 0), but the address-family
// ACTIVATION loop, the per-neighbor route-map emission, and the BFD peer
// accumulator historically iterated bgp.Neighbors with NO PeerAS==0 guard. A
// leniently-loaded / peer-synced neighbor with `remote-as 0` was therefore kept
// OUT of the `neighbor <ip> remote-as ...` declaration yet STILL emitted
// `neighbor <ip> activate` / `route-map ... out` / `neighbor <ip> bfd` / a
// `bfd` `peer <ip>` for a neighbor that was never declared. vtysh/frr-reload
// rejects a config that activates or attaches BFD to an undeclared neighbor, so
// a single remote-as-0 neighbor bricked the managed frr-reload for EVERY valid
// BGP peer on the box.
//
// The fix unifies all neighbor-referencing render loops on ONE validNeighbors
// slice (PeerAS != 0). This test renders a mixed config (valid + remote-as-0,
// both carrying family/BFD/export so an unguarded loop WOULD emit for the bad
// neighbor) and asserts the remote-as-0 neighbor is completely absent while the
// valid neighbor renders fully.
//
// RED-on-revert: revert the validNeighbors guard on the AF-activation loop
// and/or the BFD accumulator and the rendered config gains
// `neighbor 10.0.3.1 activate` and ` peer 10.0.3.1` for the undeclared
// neighbor — the brick — turning both the blanket-absence assertion and the
// self-consistency (no activate/bfd-without-declare) assertion RED.
func TestBuildManagedSection_BGPRemoteAS0NotActivatedOrBFD(t *testing.T) {
	fc := &FullConfig{
		PolicyOptions: &config.PolicyOptionsConfig{
			PolicyStatements: map[string]*config.PolicyStatement{
				"ALLOW-ALL": {Name: "ALLOW-ALL", Terms: []*config.PolicyTerm{
					{Name: "t1", Action: "accept"},
				}},
			},
		},
		BGP: &config.BGPConfig{
			LocalAS:  65001,
			RouterID: "1.1.1.1",
			Neighbors: []*config.BGPNeighbor{
				// Valid neighbor: fully renderable.
				{Address: "10.0.2.1", PeerAS: 65002, FamilyInet: true, BFD: true, Export: []string{"ALLOW-ALL"}},
				// remote-as-0 neighbor: peer-as omitted. Carries family/BFD/export
				// so an UNGUARDED activation/BFD loop would emit for it.
				{Address: "10.0.3.1", PeerAS: 0, FamilyInet: true, BFD: true, Export: []string{"ALLOW-ALL"}},
			},
		},
	}
	got := New().buildManagedSection(fc)

	// The valid neighbor renders end-to-end: declaration, activation, per-neighbor
	// BFD attach, route-map out, and a `bfd` peer entry.
	for _, want := range []string{
		"neighbor 10.0.2.1 remote-as 65002\n",
		"neighbor 10.0.2.1 activate\n",
		"neighbor 10.0.2.1 bfd\n",
		"neighbor 10.0.2.1 route-map ALLOW-ALL out\n",
		" peer 10.0.2.1\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("valid neighbor dropped: missing %q in:\n%s", want, got)
		}
	}

	// The remote-as-0 neighbor is completely invisible — no line anywhere
	// references its IP (declaration, activate, route-map, or bfd peer).
	if strings.Contains(got, "10.0.3.1") {
		t.Errorf("remote-as-0 neighbor 10.0.3.1 must not appear in ANY rendered line; output:\n%s", got)
	}
	// Belt-and-suspenders: the specific brick lines must be absent.
	for _, banned := range []string{
		"neighbor 10.0.3.1 activate",
		"neighbor 10.0.3.1 bfd",
		"neighbor 10.0.3.1 route-map",
		" peer 10.0.3.1",
	} {
		if strings.Contains(got, banned) {
			t.Errorf("undeclared remote-as-0 neighbor emitted %q (bricks frr-reload); output:\n%s", banned, got)
		}
	}
	// Never emit the reserved remote-as 0 (RFC 7607).
	if strings.Contains(got, "remote-as 0") {
		t.Errorf("renderer emitted reserved 'remote-as 0'; output:\n%s", got)
	}

	// Self-consistency: every activated or BFD-attached neighbor MUST also be
	// declared. This is exactly the invariant vtysh/frr-reload enforces — an
	// `activate` / `bfd` / `peer` for an undeclared neighbor fails the whole
	// managed-section reload.
	assertNoActivateOrBFDWithoutDeclare5518(t, got)
}

var (
	reDeclare5518  = regexp.MustCompile(`(?m)^ neighbor (\S+) remote-as \d+$`)
	reActivate5518 = regexp.MustCompile(`(?m)^  neighbor (\S+) activate$`)
	reNbrBFD5518   = regexp.MustCompile(`(?m)^ neighbor (\S+) bfd$`)
	rePeer5518     = regexp.MustCompile(`(?m)^ peer (\S+)( vrf \S+)?$`)
)

// assertNoActivateOrBFDWithoutDeclare5518 verifies the rendered frr.conf never
// activates, BFD-attaches, or emits a `bfd` peer for a BGP neighbor that was not
// declared with `remote-as`. This mirrors the vtysh/frr-reload validity rule the
// #5518 brick violated.
func assertNoActivateOrBFDWithoutDeclare5518(t *testing.T, cfg string) {
	t.Helper()
	declared := map[string]bool{}
	for _, m := range reDeclare5518.FindAllStringSubmatch(cfg, -1) {
		declared[m[1]] = true
	}
	for _, m := range reActivate5518.FindAllStringSubmatch(cfg, -1) {
		if !declared[m[1]] {
			t.Errorf("neighbor %s is activated but never declared (frr-reload would reject)", m[1])
		}
	}
	for _, m := range reNbrBFD5518.FindAllStringSubmatch(cfg, -1) {
		if !declared[m[1]] {
			t.Errorf("neighbor %s has `bfd` attached but never declared (frr-reload would reject)", m[1])
		}
	}
	for _, m := range rePeer5518.FindAllStringSubmatch(cfg, -1) {
		if !declared[m[1]] {
			t.Errorf("bfd peer %s emitted but the neighbor was never declared (frr-reload would reject)", m[1])
		}
	}
}
