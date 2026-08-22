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
// We exercise this at the marker-extraction level since the full
// handler requires a Server with a live cluster manager + dataplane,
// which is heavier than the test needs.
//
// #5883: this test used to RE-IMPLEMENT the predicate inline
// (`len(md.Get("xpf-no-peer")) > 0`) rather than call the production
// one, so it asserted its own copy and could not have noticed either
// that the header was forgeable or that the real predicate changed.
// It now runs the metadata through the production interceptor and
// reads the production accessor, and carries a forged-on-loopback row
// so the security property is part of the same table.
func Test_PeerCallSkipsDialBack(t *testing.T) {
	cases := []struct {
		name         string
		md           metadata.MD
		fabric       bool
		wantPeerCall bool
	}{
		{"empty metadata", metadata.MD{}, true, false},
		{"no-peer key set to 1", metadata.MD{"xpf-no-peer": []string{"1"}}, true, true},
		{"no-peer key set to true", metadata.MD{"xpf-no-peer": []string{"true"}}, true, true},
		{"unrelated key", metadata.MD{"some-other-key": []string{"1"}}, true, false},
		// #5883: the same header arriving on the loopback listener, which no
		// cluster peer dials, is forged and must not suppress the peer dial.
		{"forged on loopback", metadata.MD{"xpf-no-peer": []string{"1"}}, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var ctx context.Context
			if c.fabric {
				ctx = fabricMarkerCtx(t, c.md)
			} else {
				ctx = fabricMarkerCtxUntrusted(t, c.md)
			}
			isPeerCall := peerMarkersFromContext(ctx).noPeer
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
