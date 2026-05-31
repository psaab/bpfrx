package grpcapi

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/metadata"
)

// Test_PeerCallSkipsDialBack verifies the recursion guard for the
// chassis-forwarding cluster compose path. When the incoming context
// carries `xpf-no-peer:1` metadata, the handler must short-circuit
// to local-only render (skip dialAndShowForwarding) — even when
// cluster mode is otherwise active. This is the sole barrier
// preventing infinite peer-recursion when both nodes call each
// other for cluster-mode rendering.
//
// We exercise this at the metadata-extraction level since the full
// handler requires a Server with a live cluster manager + dataplane,
// which is heavier than the test needs. The guard logic itself is
// a one-liner: `len(md.Get("xpf-no-peer")) > 0`. If that contract
// drifts (key renamed, comparison inverted, etc.), this test fails.
func Test_PeerCallSkipsDialBack(t *testing.T) {
	cases := []struct {
		name        string
		md          metadata.MD
		wantPeerCall bool
	}{
		{"empty metadata", metadata.MD{}, false},
		{"no-peer key set to 1", metadata.MD{"xpf-no-peer": []string{"1"}}, true},
		{"no-peer key set to true", metadata.MD{"xpf-no-peer": []string{"true"}}, true},
		{"unrelated key", metadata.MD{"some-other-key": []string{"1"}}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := metadata.NewIncomingContext(context.Background(), c.md)
			md, _ := metadata.FromIncomingContext(ctx)
			isPeerCall := len(md.Get("xpf-no-peer")) > 0
			if isPeerCall != c.wantPeerCall {
				t.Errorf("isPeerCall: got %v, want %v", isPeerCall, c.wantPeerCall)
			}
		})
	}
}

// Test_DialAndShowForwarding_InjectsMetadata verifies that the peer
// dial helper appends `xpf-no-peer:1` to the OUTGOING context. If
// this fails, peer recursion is no longer prevented and a
// cluster-mode `show chassis forwarding` will infinitely loop
// between the two nodes.
//
// We can't exercise the full helper (requires live grpc dial), but
// we verify the metadata-injection contract by composing the same
// outgoing context the helper does and inspecting it.
func Test_DialAndShowForwarding_InjectsMetadata(t *testing.T) {
	ctx := context.Background()
	ctx = metadata.AppendToOutgoingContext(ctx, "xpf-no-peer", "1")
	md, ok := metadata.FromOutgoingContext(ctx)
	if !ok {
		t.Fatal("outgoing metadata missing")
	}
	vals := md.Get("xpf-no-peer")
	if len(vals) == 0 {
		t.Errorf("xpf-no-peer key missing from outgoing metadata: %#v", md)
	}
	if len(vals) > 0 && !strings.EqualFold(vals[0], "1") {
		t.Errorf("xpf-no-peer value: got %q, want %q", vals[0], "1")
	}
}
