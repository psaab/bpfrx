package userspace

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6846: the two forms #4228 Gap 2 left inert are resolved in the Rust builder
// (forwarding_build::cos), which can only resolve what the Go side HANDS it.
//
// The Rust cells pin the resolver. They cannot see this: a correct resolver
// that is never given the values behaves exactly like a broken one — the queue
// gets default sizing and no explicit rate either way, which is precisely the
// pre-fix behaviour this change removes. Found by the mutation matrix, where
// zeroing each field at the snapshot boundary escaped GREEN against the whole
// Go suite.
func TestCoSSnapshotCarriesRemainderAndTemporal6846(t *testing.T) {
	cfg := &config.Config{}
	cfg.ClassOfService = &config.ClassOfServiceConfig{
		ForwardingClasses: map[string]*config.CoSForwardingClass{
			"real": {Name: "real", Queue: 3},
		},
		Schedulers: map[string]*config.CoSScheduler{
			"s1": {
				Name:                  "s1",
				TransmitRateRemainder: true,
				BufferSizeTemporalUS:  50000,
			},
		},
		SchedulerMaps: map[string]*config.CoSSchedulerMap{
			"sm": {Name: "sm", Entries: map[string]*config.CoSSchedulerMapEntry{
				"real": {ForwardingClass: "real", Scheduler: "s1"},
			}},
		},
	}

	// Guard the fixture before asserting on the snapshot: if the compiled
	// scheduler ever stopped carrying these, every assertion below would pass
	// over zero values and prove nothing.
	src := cfg.ClassOfService.Schedulers["s1"]
	if !src.TransmitRateRemainder || src.BufferSizeTemporalUS != 50000 {
		t.Fatalf("fixture broken: the source scheduler must carry both forms "+
			"(remainder=%t temporal=%d)", src.TransmitRateRemainder, src.BufferSizeTemporalUS)
	}

	snap := buildClassOfServiceSnapshot(cfg)
	if snap == nil {
		t.Fatal("buildClassOfServiceSnapshot returned nil for a populated CoS config")
	}
	var got *CoSSchedulerSnapshot
	for i := range snap.Schedulers {
		if snap.Schedulers[i].Name == "s1" {
			got = &snap.Schedulers[i]
		}
	}
	if got == nil {
		t.Fatal("scheduler s1 is missing from the snapshot")
	}
	if !got.TransmitRateRemainder {
		t.Error("#6846: TransmitRateRemainder must reach the wire — without it the " +
			"Rust resolver never sees a remainder queue, and the queue falls back to " +
			"exactly the pre-fix no-explicit-rate behaviour")
	}
	if got.BufferSizeTemporalUS != 50000 {
		t.Errorf("#6846: BufferSizeTemporalUS must reach the wire verbatim, got %d — "+
			"without it the queue falls back to default sizing, which is the pre-fix "+
			"behaviour this change removes", got.BufferSizeTemporalUS)
	}
}

// TestCoSRemainderTemporalWireKeysAgreeWithRust6846 binds the two SPELLINGS to
// each other.
//
// The cell above proves the Go builder carries both values; it cannot see that
// the Rust decoder reads them under the same names. A rename on either side is
// not a decode failure — `#[serde(default)]` leaves the field at false/0, which
// is exactly the accepted-but-inert behaviour #6846 removes. Silent, and
// indistinguishable from a correct build that was simply never given a
// remainder queue.
//
// The assertion is the AGREEMENT, not a literal on one side: the expected key
// set is read from `userspace-dp/tests/fixtures/protocol_wire_v1.json`, which
// the RUST suite generates by serializing `CoSSchedulerSnapshot::default()`
// (protocol/tests.rs, wire_invariant_default_specimens). Pinning the Go tags to
// hand-typed strings would encode which side I trust; comparing against the
// Rust-generated specimen makes a rename on EITHER side red this.
func TestCoSRemainderTemporalWireKeysAgreeWithRust6846(t *testing.T) {
	fixture := filepath.Join("..", "..", "..", "userspace-dp", "tests", "fixtures", "protocol_wire_v1.json")
	blob, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatalf("read the Rust wire specimen %s: %v", fixture, err)
	}
	var specimens map[string]map[string]json.RawMessage
	if err := json.Unmarshal(blob, &specimens); err != nil {
		t.Fatalf("decode the Rust wire specimen: %v", err)
	}
	rustKeys, ok := specimens["cos_scheduler_snapshot"]
	if !ok {
		t.Fatalf("the Rust wire specimen has no cos_scheduler_snapshot object; "+
			"available: %v", len(specimens))
	}
	// Vacuity guard: an empty or truncated specimen would make every
	// membership check below trivially fail-or-pass depending on direction.
	if _, ok := rustKeys["transmit_rate_bytes"]; !ok {
		t.Fatal("the Rust cos_scheduler_snapshot specimen is missing a long-standing " +
			"key (transmit_rate_bytes) — the fixture is not what this test thinks it is")
	}

	// Populate both fields so `omitempty` cannot hide them.
	raw, err := json.Marshal(CoSSchedulerSnapshot{
		Name:                  "s1",
		TransmitRateRemainder: true,
		BufferSizeTemporalUS:  50000,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var goKeys map[string]json.RawMessage
	if err := json.Unmarshal(raw, &goKeys); err != nil {
		t.Fatalf("decode the Go snapshot: %v", err)
	}

	for _, field := range []struct{ goTag, why string }{
		{"transmit_rate_remainder", "the Rust resolver never sees a remainder queue"},
		{"buffer_size_temporal_us", "the queue falls back to default buffer sizing"},
	} {
		if _, ok := goKeys[field.goTag]; !ok {
			t.Errorf("#6846: the Go snapshot does not emit %q — %s", field.goTag, field.why)
			continue
		}
		if _, ok := rustKeys[field.goTag]; !ok {
			t.Errorf("#6846: the Go snapshot emits %q but the Rust decoder does not read "+
				"a key of that name (its serde rename disagrees), so %s. The two spellings "+
				"must agree; serde(default) makes the disagreement SILENT",
				field.goTag, field.why)
		}
	}
}
