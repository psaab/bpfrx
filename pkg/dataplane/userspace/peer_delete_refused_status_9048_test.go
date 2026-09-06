package userspace

import (
	"encoding/json"
	"reflect"
	"testing"
)

// #9048: the helper refuses a peer DeleteSynced that would tear down a LIVE
// LOCAL session it is actively forwarding for. The refusal is SILENT by design
// — the condition that produces it (a dual-primary split) produces one per
// closing flow, so a log line would be a storm exactly when the cluster is
// already in trouble — which makes this counter the ONLY surface that reports
// it. A json-tag drift would therefore not degrade the signal, it would delete
// it, and silently: the field would decode to 0 forever and read as "no
// split-brain".
func TestPeerDeleteRefusedLocalOwnedDecodes9048(t *testing.T) {
	// A Rust-style helper payload, keyed exactly as protocol/status.rs emits.
	const payload = `{"peer_delete_refused_local_owned":7,` +
		`"session_delete_replica_dropped":3}`
	var st ProcessStatus
	if err := json.Unmarshal([]byte(payload), &st); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if st.PeerDeleteRefusedLocalOwned != 7 {
		t.Errorf("PeerDeleteRefusedLocalOwned = %d, want 7 — the Go json tag no "+
			"longer matches the helper's `peer_delete_refused_local_owned`, so the "+
			"only surface reporting a dual-primary split now reads a constant 0 "+
			"(#9048)", st.PeerDeleteRefusedLocalOwned)
	}
	// The sibling in the same payload is the control: if BOTH decoded as 0 the
	// failure would be the payload or the decoder, not this field's tag.
	if st.SessionDeleteReplicaDropped != 3 {
		t.Fatalf("control: SessionDeleteReplicaDropped = %d, want 3 — the decode "+
			"itself is broken, so the assertion above says nothing about the #9048 tag",
			st.SessionDeleteReplicaDropped)
	}

	// An OLDER helper omits the key entirely (rolling upgrade, mixed base).
	// It must decode to 0 rather than erroring: the field is purely additive
	// on the wire in both directions.
	var old ProcessStatus
	if err := json.Unmarshal([]byte(`{"session_delete_replica_dropped":3}`), &old); err != nil {
		t.Fatalf("#9048: a pre-#9048 helper payload failed to decode: %v. The "+
			"field must be additive — a mixed-base cluster is the normal state "+
			"during a rolling upgrade.", err)
	}
	if old.PeerDeleteRefusedLocalOwned != 0 {
		t.Errorf("absent key decoded as %d, want 0", old.PeerDeleteRefusedLocalOwned)
	}

	f, ok := reflect.TypeOf(ProcessStatus{}).FieldByName("PeerDeleteRefusedLocalOwned")
	if !ok {
		t.Fatal("field not found")
	}
	if got := f.Tag.Get("json"); got != "peer_delete_refused_local_owned,omitempty" {
		t.Errorf("json tag = %q, want %q", got, "peer_delete_refused_local_owned,omitempty")
	}
}
