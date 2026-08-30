package configstore

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestReadTreeMetaRejectsNonObjectBody_5474 pins the #5474 fail-open fix at the
// DB read layer. Go's json.Unmarshal([]byte("null"), &ConfigTree{}) returns NO
// error and leaves the tree at its zero value, so a persisted active body of
// literal `null` used to decode to a semantically EMPTY config and boot as if
// no policy were configured (fail-open). A body whose top-level JSON is `null`,
// an array, or a scalar must now be REJECTED (non-nil error); the valid empty
// config `{}` and a populated object still read back cleanly.
//
// Both a legacy/plaintext body (no #1917 envelope) and an
// enveloped-but-unencrypted body reach the same decode path, so every case is
// exercised in both framings. (`null` is the specific gap the issue targets;
// arrays/scalars already error against the struct target — they are covered
// here for completeness and to lock the behavior.)
func TestReadTreeMetaRejectsNonObjectBody_5474(t *testing.T) {
	reject := []struct {
		name string
		body string
	}{
		{"null literal", "null"},
		{"null with whitespace", "  \n null \n"},
		{"top-level array", "[]"},
		{"top-level scalar number", "5"},
		{"top-level scalar string", `"nope"`},
		{"top-level bool", "true"},
	}
	accept := []struct {
		name string
		body string
	}{
		{"empty object", "{}"},
		{"empty object with whitespace", "\n  {}\n"},
		{"populated object", `{"Children":[{"Keys":["system"]}]}`},
	}

	// frame writes body to a fresh DB's active.json, optionally wrapped in the
	// #1917 compatibility envelope (unencrypted), and returns the DB.
	frame := func(t *testing.T, enveloped bool, body string) *DB {
		t.Helper()
		dbDir := filepath.Join(t.TempDir(), ".configdb")
		db, err := NewDB(dbDir)
		if err != nil {
			t.Fatalf("NewDB: %v", err)
		}
		raw := []byte(body)
		if enveloped {
			raw = wrapEnvelope(raw, "9.9.9", true, EnvelopeMinReaderVersion)
		}
		if err := os.WriteFile(db.activePath(), raw, 0600); err != nil {
			t.Fatalf("write active.json: %v", err)
		}
		return db
	}

	for _, enveloped := range []bool{false, true} {
		framing := "plaintext"
		if enveloped {
			framing = "enveloped"
		}
		for _, tc := range reject {
			t.Run("reject/"+framing+"/"+tc.name, func(t *testing.T) {
				db := frame(t, enveloped, tc.body)
				tree, _, err := db.ReadActiveMeta()
				if err == nil {
					t.Fatalf("ReadActiveMeta(%q) returned nil error; want fail-closed (tree=%+v)", tc.body, tree)
				}
			})
		}
		for _, tc := range accept {
			t.Run("accept/"+framing+"/"+tc.name, func(t *testing.T) {
				db := frame(t, enveloped, tc.body)
				tree, _, err := db.ReadActiveMeta()
				if err != nil {
					t.Fatalf("ReadActiveMeta(%q) errored: %v; want success", tc.body, err)
				}
				if tree == nil {
					t.Fatalf("ReadActiveMeta(%q) returned nil tree; want non-nil valid tree", tc.body)
				}
			})
		}
	}
}

// TestStoreLoadNullBodyFailsClosed_5474 proves the end-to-end fail-closed
// property: a PRESENT plaintext active.json of literal `null` is rejected with
// ErrConfigDBUnreadable, so the daemon can make boot fatal instead of silently
// coming up with policy absent. A `{}` body is the valid empty config and Load
// succeeds (and boots to a non-nil tree).
//
// This is the RED-on-revert regression: without the requireJSONObject gate the
// `null` subtest passes Load with no error (the boot-empty fail-open bug).
func TestStoreLoadNullBodyFailsClosed_5474(t *testing.T) {
	load := func(t *testing.T, body string) error {
		t.Helper()
		dir := t.TempDir()
		path := filepath.Join(dir, "config")
		dbDir := filepath.Join(dir, ".configdb")
		if err := os.MkdirAll(dbDir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dbDir, "active.json"), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		return newTestStoreAt(t, path).Load()
	}

	t.Run("null fails closed", func(t *testing.T) {
		err := load(t, "null")
		if err == nil {
			t.Fatal("Load accepted a `null` active.json; must fail closed (policy would be absent)")
		}
		if !errors.Is(err, ErrConfigDBUnreadable) {
			t.Fatalf("Load error not tagged ErrConfigDBUnreadable: %v", err)
		}
	})
	t.Run("array fails closed", func(t *testing.T) {
		err := load(t, "[]")
		if err == nil {
			t.Fatal("Load accepted a `[]` active.json; must fail closed")
		}
		if !errors.Is(err, ErrConfigDBUnreadable) {
			t.Fatalf("Load error not tagged ErrConfigDBUnreadable: %v", err)
		}
	})
	t.Run("scalar fails closed", func(t *testing.T) {
		err := load(t, "5")
		if err == nil {
			t.Fatal("Load accepted a `5` active.json; must fail closed")
		}
		if !errors.Is(err, ErrConfigDBUnreadable) {
			t.Fatalf("Load error not tagged ErrConfigDBUnreadable: %v", err)
		}
	})
	t.Run("empty object boots", func(t *testing.T) {
		if err := load(t, "{}"); err != nil {
			t.Fatalf("Load rejected `{}` (valid empty config): %v", err)
		}
	})
}
