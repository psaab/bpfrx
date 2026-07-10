package configstore

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// #4891: an unbounded commit description marshals into a single oversized JSONL
// journal line that the bounded reverse-tail scanner later treats as a poisoned
// line and discards — the legitimate commit record vanishes from bounded audit
// views after allocating memory/disk proportional to its size. The operator
// commit path must reject an over-cap description strictly (#1960) BEFORE
// anything is persisted or promoted, and the journal boundary must bound any
// Detail defensively.

// TestCommitWithDescription_RejectsOversized is the RED-on-revert guard for the
// strict cap. Revert the length check and the commit succeeds (nil error) with
// the oversized comment persisted — failing both assertions below.
func TestCommitWithDescription_RejectsOversized(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := s.SetFromInput("interfaces eth0 unit 0 family inet address 10.0.0.1/24"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}

	huge := strings.Repeat("A", maxCommitDescriptionBytes+1)
	cfg, err := s.CommitWithDescription(huge)
	if err == nil {
		t.Fatal("CommitWithDescription accepted an over-cap description — must reject (#4891)")
	}
	if cfg != nil {
		t.Errorf("rejected commit returned a non-nil config: %v", cfg)
	}
	if !strings.Contains(err.Error(), "too long") {
		t.Errorf("error = %q, want it to mention the description is too long", err)
	}

	// The rejected commit must have mutated nothing: no history entry, no
	// journal record. A leaked entry is exactly the audit bloat #4891 avoids.
	if h := s.ListHistory(); len(h) != 0 {
		t.Errorf("rejected commit pushed %d history entries, want 0", len(h))
	}
	entries, err := s.ListCommitHistory(10)
	if err != nil {
		t.Fatalf("ListCommitHistory: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("rejected commit wrote %d journal entries, want 0", len(entries))
	}

	// A commit with a description exactly at the cap still succeeds — the
	// bound must not regress the normal path.
	atCap := strings.Repeat("B", maxCommitDescriptionBytes)
	if _, err := s.CommitWithDescription(atCap); err != nil {
		t.Fatalf("CommitWithDescription(at cap) = %v, want success", err)
	}
}

// TestTruncateDetail_BoundsAndMarks guards the journal-boundary belt: a Detail
// past the cap is truncated to a bounded, UTF-8-valid, explicitly-marked
// string. Revert the truncation in journalLog / truncateDetail and an oversized
// Detail passes through unbounded.
func TestTruncateDetail_BoundsAndMarks(t *testing.T) {
	// Under the cap: returned verbatim.
	small := "rotated the vpn psk"
	if got := truncateDetail(small, maxCommitDescriptionBytes); got != small {
		t.Errorf("truncateDetail(small) = %q, want verbatim", got)
	}

	// Over the cap: bounded and marked.
	over := strings.Repeat("x", maxCommitDescriptionBytes*3)
	got := truncateDetail(over, maxCommitDescriptionBytes)
	if len(got) >= len(over) {
		t.Fatalf("truncateDetail did not shrink an over-cap Detail: len=%d, orig=%d", len(got), len(over))
	}
	if !strings.Contains(got, "truncated") {
		t.Errorf("truncated Detail lacks the explicit marker: %q", got[len(got)-40:])
	}
	if !utf8.ValidString(got) {
		t.Errorf("truncated Detail is not valid UTF-8")
	}

	// A multibyte rune straddling the cut boundary must not leave a partial
	// rune. Build content whose byte cap lands mid-rune ('世' is 3 bytes).
	multibyte := strings.Repeat("世", maxCommitDescriptionBytes) // 3 bytes each
	m := truncateDetail(multibyte, maxCommitDescriptionBytes)
	if !utf8.ValidString(m) {
		t.Errorf("truncateDetail split a multibyte rune")
	}
}
