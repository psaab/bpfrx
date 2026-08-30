package configstore

import (
	"os"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// TestReadConfirmRejectsDegenerateRecord_5637 pins the #5637 / codex-review-181
// M29 fail-open fix at the DB read layer. ReadConfirm decoded confirm.json
// straight into a *confirmRecord without validating its shape or fields, the
// way the #5474 fix hardened readTreeMeta. Go's json.Unmarshal of a top-level
// `null` (or `{}`) into *confirmRecord returns NO error and yields a ZERO-VALUE
// record — Deadline is the zero time, PrevTree is nil. recoverPendingConfirmLocked
// then reads time.Now().After(zeroTime) as TRUE (an "expired" window) and
// synthesizes a rollback to an EMPTY prev tree, silently WIPING the just-loaded
// active config to policy-absent (fail-open) on boot. A record that is present
// but structurally/semantically degenerate must now be REJECTED (non-nil
// error); a genuinely absent record stays the no-confirm-pending path (tested
// elsewhere) and a valid record still round-trips (regression guard below).
//
// Each degenerate body is exercised in BOTH framings: plaintext (the previous
// tree carried no master-password, so confirm.json is written unencrypted) and
// AES-GCM encrypted (the previous tree declared a master-password). The
// encrypted framing decrypts to the same degenerate plaintext, so both reach
// the same decode+validate path.
//
// RED-on-revert: the load-bearing gate is the Deadline/PrevTree field check.
// `null`, `{}`, deadline-only, and prev-tree-only all decode into a zero- or
// partial-value confirmRecord with NO json.Unmarshal error, so reverting the
// field checks makes those subtests return (rec, nil) → RED. The
// requireJSONObject gate is redundant belt-and-suspenders here (array/scalar
// bodies already error in json.Unmarshal, and null/`{}` are already caught by
// the field checks); it only produces a clearer parse error and mirrors the
// #5474 readTreeMeta hardening, so reverting requireJSONObject alone stays
// GREEN.
func TestReadConfirmRejectsDegenerateRecord_5637(t *testing.T) {
	reject := []struct {
		name string
		body string
	}{
		{"null literal", "null"},
		{"null with whitespace", "  \n null \n"},
		{"empty object", "{}"},
		{"top-level array", "[]"},
		{"top-level scalar number", "5"},
		{"top-level scalar string", `"nope"`},
		{"top-level bool", "true"},
		// Structurally an object, but semantically impossible: a deadline with
		// no rollback target...
		{"deadline without prev_tree", `{"deadline":"2999-01-01T00:00:00Z"}`},
		// ...and a rollback target with no (zero) deadline.
		{"prev_tree without deadline", `{"prev_tree":{"Children":[{"Keys":["system"]}]}}`},
		{"explicit zero deadline", `{"deadline":"0001-01-01T00:00:00Z","prev_tree":{"Children":[]}}`},
	}

	// mpTree declares a master-password so maybeEncryptTreeJSON produces an
	// AES-GCM envelope; a plaintext tree encrypts to a pass-through (no
	// envelope), matching how WriteConfirm frames a record whose prev tree has
	// no master-password.
	mpTree := testConfigTree("hmac-sha2-256", "confirm-fw")

	// writeConfirm writes body to a fresh DB's confirm.json, optionally
	// AES-GCM encrypted (keyed off mpTree's master-password), and returns the DB.
	writeConfirm := func(t *testing.T, encrypted bool, body string) *DB {
		t.Helper()
		db, err := NewDB(t.TempDir())
		if err != nil {
			t.Fatalf("NewDB: %v", err)
		}
		raw := []byte(body)
		if encrypted {
			raw, err = db.maybeEncryptTreeJSON(raw, mpTree, nil)
			if err != nil {
				t.Fatalf("maybeEncryptTreeJSON: %v", err)
			}
		}
		if err := os.WriteFile(db.confirmPath(), raw, 0600); err != nil {
			t.Fatalf("write confirm.json: %v", err)
		}
		return db
	}

	for _, encrypted := range []bool{false, true} {
		framing := "plaintext"
		if encrypted {
			framing = "encrypted"
		}
		for _, tc := range reject {
			t.Run("reject/"+framing+"/"+tc.name, func(t *testing.T) {
				db := writeConfirm(t, encrypted, tc.body)
				rec, err := db.ReadConfirm()
				if err == nil {
					t.Fatalf("ReadConfirm(%q) returned nil error; want fail-closed rejection (rec=%+v)", tc.body, rec)
				}
				if rec != nil {
					t.Fatalf("ReadConfirm(%q) returned non-nil rec %+v with error %v; want nil rec", tc.body, rec, err)
				}
			})
		}
	}
}

// TestReadConfirmValidRecordRoundTrips_5637 is the regression guard: a
// legitimately-written pending-confirm record — real future deadline + non-nil
// rollback target — must still round-trip through WriteConfirm/ReadConfirm
// unchanged, in BOTH the plaintext and the encrypted (prev tree declares a
// master-password) framings, and for the first-commit variant whose PrevTree is
// a non-nil empty bootstrap tree. This proves the #5637 validation only rejects
// degenerate shapes and does not widen behavior for valid records.
func TestReadConfirmValidRecordRoundTrips_5637(t *testing.T) {
	deadline := time.Now().Add(37 * time.Minute).Round(0)

	cases := []struct {
		name        string
		prev        *config.ConfigTree
		firstCommit bool
	}{
		{
			name: "plaintext populated prev tree",
			prev: testConfigTree("", "prev-fw"),
		},
		{
			name: "encrypted prev tree with master-password",
			prev: testConfigTree("hmac-sha2-256", "prev-fw"),
		},
		{
			// First-commit rollback target: the empty bootstrap tree. It is
			// non-nil (confirmPrevTree = s.active.Clone()); FirstCommit records
			// that it is the empty bootstrap, not an operator-committed-empty.
			name:        "first-commit empty bootstrap prev tree",
			prev:        &config.ConfigTree{},
			firstCommit: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db, err := NewDB(t.TempDir())
			if err != nil {
				t.Fatalf("NewDB: %v", err)
			}
			want := &confirmRecord{Deadline: deadline, PrevTree: tc.prev, FirstCommit: tc.firstCommit}
			if err := db.WriteConfirm(want); err != nil {
				t.Fatalf("WriteConfirm: %v", err)
			}
			got, err := db.ReadConfirm()
			if err != nil {
				t.Fatalf("ReadConfirm errored on a valid record: %v", err)
			}
			if got == nil {
				t.Fatalf("ReadConfirm returned nil rec for a valid record")
			}
			if !got.Deadline.Equal(want.Deadline) {
				t.Fatalf("Deadline round-trip mismatch: got %v want %v", got.Deadline, want.Deadline)
			}
			if got.PrevTree == nil {
				t.Fatalf("PrevTree round-trip lost the rollback target (got nil)")
			}
			if got.FirstCommit != want.FirstCommit {
				t.Fatalf("FirstCommit round-trip mismatch: got %v want %v", got.FirstCommit, want.FirstCommit)
			}
		})
	}
}
