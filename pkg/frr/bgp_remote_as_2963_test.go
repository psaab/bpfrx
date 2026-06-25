package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #2963 defense-in-depth: the FRR renderer must never emit
// `neighbor <addr> remote-as 0`. peer-as is optional in the parser/compiler,
// so a leniently-loaded (already-persisted / peer-synced) neighbor may carry a
// zero PeerAS. AS 0 is reserved (RFC 7607) and FRR/vtysh rejects
// `remote-as 0`, which fails the whole frr-reload for every other peer. The
// commit-time gate (pkg/config validateBGPNeighborPeerASStrict) hard-rejects
// on commit; this render guard keeps the leniently-loaded bad neighbor out of
// frr.conf entirely.
//
// FAIL-ON-REVERT: without the `if n.PeerAS == 0 { continue }` guard the
// rendered output contains `remote-as 0`, turning this test RED.
func TestGenerateProtocols_BGPRemoteAS0Skipped(t *testing.T) {
	m := New()
	bgp := &config.BGPConfig{
		LocalAS:  65001,
		RouterID: "1.1.1.1",
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.2.1", PeerAS: 0, Description: "no-peer-as"}, // peer-as omitted
			{Address: "10.0.3.1", PeerAS: 65003},                        // valid
		},
	}
	got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 0, nil)
	if strings.Contains(got, "remote-as 0") {
		t.Errorf("renderer emitted reserved 'remote-as 0' (RFC 7607); output:\n%s", got)
	}
	// The peer-as-less neighbor is skipped entirely, so none of its lines render.
	if strings.Contains(got, "neighbor 10.0.2.1") {
		t.Errorf("renderer emitted lines for a peer-as-less neighbor; output:\n%s", got)
	}
	// The valid neighbor still renders.
	if !strings.Contains(got, "neighbor 10.0.3.1 remote-as 65003\n") {
		t.Errorf("renderer dropped a valid neighbor; output:\n%s", got)
	}
}
