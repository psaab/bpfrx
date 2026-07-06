package userspace

import (
	"encoding/json"
	"strings"
	"testing"
)

// #4082: the fabric parent up-state must ride the snapshot wire so the Rust
// dataplane can prefer an UP fabric for the cross-chassis redirect. The `up`
// field MUST serialize unconditionally (no omitempty): a genuinely-down fabric
// has to emit "up":false, because the Rust decoder defaults an ABSENT field to
// true (fail-open back-compat). If omitempty dropped a false value the down
// fabric would decode back to up and the failover would be defeated.
func TestFabricSnapshotUpWireField4082(t *testing.T) {
	for _, tc := range []struct {
		name string
		up   bool
		want string
	}{
		{name: "down", up: false, want: `"up":false`},
		{name: "up", up: true, want: `"up":true`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := json.Marshal(FabricSnapshot{Name: "fab0", ParentIfindex: 21, Up: tc.up})
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			got := string(b)
			if !strings.Contains(got, tc.want) {
				t.Fatalf("FabricSnapshot JSON %q missing %q (up must not be omitempty)", got, tc.want)
			}

			var back FabricSnapshot
			if err := json.Unmarshal(b, &back); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if back.Up != tc.up {
				t.Fatalf("round-trip Up = %v, want %v", back.Up, tc.up)
			}
		})
	}

	// A snapshot without the field (a stale peer, or a producer that omitted
	// it) unmarshals to the Go zero value false — the fail-open-to-true
	// default lives on the RUST decoder, not here, so the Go producer must
	// always set Up explicitly (which buildFabricSnapshots does).
	var absent FabricSnapshot
	if err := json.Unmarshal([]byte(`{"name":"fab0","parent_ifindex":21}`), &absent); err != nil {
		t.Fatalf("unmarshal absent: %v", err)
	}
	if absent.Up {
		t.Fatalf("absent up decodes to Go zero value false, got true")
	}
}

// fabricParentUp must fail safe on inputs that cannot resolve a link: an empty
// name and a nonexistent interface both return false (the fabric is skipped in
// Rust on ifindex<=0 anyway, and the Rust selection fails open when no fabric
// reports up).
func TestFabricParentUpUnresolvable4082(t *testing.T) {
	if fabricParentUp("") {
		t.Fatalf("empty parent name must report not-up")
	}
	if fabricParentUp("xpf-nonexistent-fab-4082") {
		t.Fatalf("nonexistent parent link must report not-up")
	}
}
