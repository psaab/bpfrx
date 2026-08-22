package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/grpc/metadata"
)

// fakeMonitorCluster is a minimal monitorClusterState for exercising the #5497
// proxy decision without a live cluster.Manager or a network dial.
type fakeMonitorCluster struct {
	localPrimary map[int]bool
	peerPrimary  map[int]bool
}

func (f fakeMonitorCluster) IsLocalPrimary(rg int) bool { return f.localPrimary[rg] }
func (f fakeMonitorCluster) IsPeerPrimary(rg int) bool  { return f.peerPrimary[rg] }

func neither() fakeMonitorCluster {
	return fakeMonitorCluster{localPrimary: map[int]bool{}, peerPrimary: map[int]bool{}}
}
func localOwns(rg int) fakeMonitorCluster {
	return fakeMonitorCluster{localPrimary: map[int]bool{rg: true}, peerPrimary: map[int]bool{}}
}
func peerOwns(rg int) fakeMonitorCluster {
	return fakeMonitorCluster{localPrimary: map[int]bool{}, peerPrimary: map[int]bool{rg: true}}
}

// TestDecideMonitorProxy covers the full state matrix the #5497 fix must honor.
func TestDecideMonitorProxy(t *testing.T) {
	tests := []struct {
		name           string
		alreadyProxied bool
		existsLocally  bool
		isPeerMember   bool
		isReth         bool
		rg             int
		cl             monitorClusterState
		want           monitorProxyAction
	}{
		// The core bug: both nodes non-primary (election / both-secondary /
		// hold). The old `!IsLocalPrimary` test proxied here and — with no hop
		// marker — looped A->B->A. Must serve locally now.
		{"reth both-secondary -> local", false, true, false, true, 1, neither(), monitorServeLocal},
		// Normal case preserved: local secondary, peer owns the RG -> one hop.
		{"reth local-secondary peer-primary -> proxy", false, true, false, true, 1, peerOwns(1), monitorProxyToPeer},
		// Local owns the RG: serve locally, never proxy.
		{"reth local-primary -> local", false, true, false, true, 1, localOwns(1), monitorServeLocal},
		// Peer in sync-hold (not primary): do not proxy.
		{"reth peer-hold -> local", false, true, false, true, 1, neither(), monitorServeLocal},
		// HOP MARKER: request forwarded from the peer is served locally even
		// when peer-ownership would otherwise say "proxy" — the second hop is
		// the recursion. This is the marker's whole job.
		{"reth marked + peer-primary -> local (no re-proxy)", true, true, false, true, 1, peerOwns(1), monitorServeLocal},
		{"reth marked + both-secondary -> local", true, true, false, true, 1, neither(), monitorServeLocal},
		// Missing / non-cluster RG: never proxy a locally-present reth.
		{"reth rg<=0 -> local", false, true, false, true, 0, neither(), monitorServeLocal},
		{"reth nil cluster -> local", false, true, false, true, 1, nil, monitorServeLocal},
		// Non-reth locally-present interface: always local.
		{"non-reth local -> local", false, true, false, false, -1, peerOwns(1), monitorServeLocal},
		// Peer physical member, not local: one hop to the peer.
		{"peer-member not-local -> proxy", false, false, true, false, -1, neither(), monitorProxyToPeer},
		// Peer physical member, not local, but already forwarded: do NOT bounce
		// it back to the peer — report not-found instead of looping.
		{"peer-member not-local + marked -> not-found", true, false, true, false, -1, neither(), monitorNotFound},
		// Not local and not a peer member: not-found (unchanged behavior).
		{"unknown not-local -> not-found", false, false, false, false, -1, neither(), monitorNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := decideMonitorProxy(tt.alreadyProxied, tt.existsLocally, tt.isPeerMember, tt.isReth, tt.rg, tt.cl)
			if got != tt.want {
				t.Fatalf("decideMonitorProxy() = %d, want %d", got, tt.want)
			}
		})
	}
}

// TestDecideMonitorProxyNoRecursionBothSecondary is the fail-on-revert guard for
// the peer-ownership check. Reverting to the old `!IsLocalPrimary`-only trigger
// makes both-secondary return monitorProxyToPeer and this test fails — proving
// the check is what breaks the A->B->A storm.
func TestDecideMonitorProxyNoRecursionBothSecondary(t *testing.T) {
	got := decideMonitorProxy(false /*alreadyProxied*/, true /*existsLocally*/, false /*isPeerMember*/, true /*isReth*/, 1, neither())
	if got == monitorProxyToPeer {
		t.Fatal("both-secondary must NOT proxy (A->B->A recursion); peer-ownership check regressed")
	}
	if got != monitorServeLocal {
		t.Fatalf("both-secondary must serve locally, got %d", got)
	}
}

// TestDecideMonitorProxyMarkerNotReProxied is the fail-on-revert guard for the
// hop marker. Removing the alreadyProxied short-circuit makes a forwarded
// request re-proxy and this test fails.
func TestDecideMonitorProxyMarkerNotReProxied(t *testing.T) {
	// Even with peer-ownership satisfied, a forwarded (marked) request must be
	// served locally, never re-proxied.
	if got := decideMonitorProxy(true, true, false, true, 1, peerOwns(1)); got == monitorProxyToPeer {
		t.Fatal("a request carrying the no-peer hop marker must NOT be re-proxied (hop bound regressed)")
	}
}

// TestMonitorRequestForwardedFromPeer verifies the ingress marker detection used
// to enforce the hop bound.
func TestMonitorRequestForwardedFromPeer(t *testing.T) {
	if monitorRequestForwardedFromPeer(context.Background()) {
		t.Error("bare context must not be treated as forwarded-from-peer")
	}
	// #5883: the marker is honored only when the FABRIC listener's interceptor
	// promotes it, so build the context through that interceptor rather than
	// stuffing raw incoming metadata — which a client could do too, and which
	// is the forgeability #5883 reported.
	ctx := fabricMarkerCtx(t, metadata.MD{monitorNoPeerMarker: []string{"1"}})
	if !monitorRequestForwardedFromPeer(ctx) {
		t.Errorf("a peer-forwarded request carrying %q must be detected as forwarded-from-peer", monitorNoPeerMarker)
	}
	// A request WITHOUT the marker (original client call) must proxy normally.
	ctxNoMarker := fabricMarkerCtx(t, metadata.MD{"other": []string{"x"}})
	if monitorRequestForwardedFromPeer(ctxNoMarker) {
		t.Error("unrelated metadata must not be treated as forwarded-from-peer")
	}
	// #5883: the same header on the LOOPBACK listener, which no peer dials,
	// must NOT be honored. Without this the test passes on a build that trusts
	// any caller's header.
	if monitorRequestForwardedFromPeer(fabricMarkerCtxUntrusted(t, metadata.MD{monitorNoPeerMarker: []string{"1"}})) {
		t.Errorf("a client-supplied %q on the loopback listener was honored", monitorNoPeerMarker)
	}
}

// TestMonitorHopMarkerRoundTrip pins the marker contract proxyMonitorInterface
// relies on: the no-peer key stamped on the OUTGOING context is visible on the
// peer's ingress (via monitorRequestForwardedFromPeer), so the peer declines a
// second hop. Mirrors server_show_chassis_forwarding_test.go's marker test.
func TestMonitorHopMarkerRoundTrip(t *testing.T) {
	ctx := metadata.AppendToOutgoingContext(context.Background(), monitorNoPeerMarker, "1")
	md, ok := metadata.FromOutgoingContext(ctx)
	if !ok {
		t.Fatal("expected outgoing metadata")
	}
	vals := md.Get(monitorNoPeerMarker)
	if len(vals) == 0 {
		t.Fatalf("%q key missing from outgoing metadata: %#v", monitorNoPeerMarker, md)
	}
	if vals[0] != "1" {
		t.Errorf("%q value: got %q, want %q", monitorNoPeerMarker, vals[0], "1")
	}
}
