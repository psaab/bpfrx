package userspace

import (
	"encoding/json"
	"strings"
	"testing"
)

// #1620: cold_path_sample_mask wire-protocol shape test. The field is
// *uint64 with omitempty so:
//   - nil pointer → field absent on the wire → Rust deserializes to
//     Option::None → unwrap_or(0xff)
//   - non-nil pointer to 0 → field present with value 0 → Rust
//     deserializes to Some(0) → 1-in-1 sampling (only allowed when
//     --enable-cold-path-1-in-1-sampling is also set, per cmd/xpfd
//     validator).
//   - non-nil pointer to 0xff → field present with value 255 → Rust
//     deserializes to Some(255) → 1-in-256 sampling (default).
//
// These three cases form the truth table from #1620 plan v4 §4.3.
// The Rust receiver's behavior is verified by the Rust-side cargo
// tests (cold_path_hist::tests::*); this Go-side test pins the JSON
// wire format on the sender side.

func TestColdPathSampleMask_NilPointerOmitsField(t *testing.T) {
	snap := ConfigSnapshot{
		Version:    3,
		Generation: 1,
		// ColdPathSampleMask: nil (default).
	}
	payload, err := json.Marshal(&snap)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	body := string(payload)
	if strings.Contains(body, "cold_path_sample_mask") {
		t.Fatalf("nil ColdPathSampleMask must be omitted from wire; got: %s", body)
	}
}

func TestColdPathSampleMask_DefaultMaskFFSerializesAs255(t *testing.T) {
	mask := uint64(0xff)
	snap := ConfigSnapshot{
		Version:            3,
		Generation:         1,
		ColdPathSampleMask: &mask,
	}
	payload, err := json.Marshal(&snap)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	body := string(payload)
	if !strings.Contains(body, `"cold_path_sample_mask":255`) {
		t.Fatalf(`expected "cold_path_sample_mask":255 in wire body; got: %s`, body)
	}
}

func TestColdPathSampleMask_ZeroValueSerializesAs0(t *testing.T) {
	// Explicit 0 mask (1-in-1 sampling) must round-trip as `:0`, NOT
	// omitted. omitempty on a *uint64 only omits when the pointer
	// itself is nil — a non-nil pointer to 0 stays.
	mask := uint64(0)
	snap := ConfigSnapshot{
		Version:            3,
		Generation:         1,
		ColdPathSampleMask: &mask,
	}
	payload, err := json.Marshal(&snap)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	body := string(payload)
	if !strings.Contains(body, `"cold_path_sample_mask":0`) {
		t.Fatalf(`expected "cold_path_sample_mask":0 in wire body for non-nil ptr-to-0; got: %s`, body)
	}
}

func TestColdPathSampleMask_RoundTripPreservesValues(t *testing.T) {
	cases := []struct {
		name string
		mask *uint64
	}{
		{name: "nil", mask: nil},
		{name: "0", mask: u64ptr(0)},
		{name: "0x1", mask: u64ptr(0x1)},
		{name: "0xff", mask: u64ptr(0xff)},
		{name: "0x3ff", mask: u64ptr(0x3ff)},
		{name: "u64_max", mask: u64ptr(^uint64(0))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			snap := ConfigSnapshot{
				Version:            3,
				Generation:         1,
				ColdPathSampleMask: tc.mask,
			}
			payload, err := json.Marshal(&snap)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var got ConfigSnapshot
			if err := json.Unmarshal(payload, &got); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if (tc.mask == nil) != (got.ColdPathSampleMask == nil) {
				t.Fatalf("nil-ness changed: src=%v got=%v", tc.mask, got.ColdPathSampleMask)
			}
			if tc.mask != nil && *tc.mask != *got.ColdPathSampleMask {
				t.Fatalf("value changed: src=%d got=%d", *tc.mask, *got.ColdPathSampleMask)
			}
		})
	}
}

func u64ptr(v uint64) *uint64 { return &v }
