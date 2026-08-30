package configstore

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestEnvelopeRoundTrip verifies a tree written through the DB is read
// back identically via the envelope-stripping path.
func TestEnvelopeRoundTrip(t *testing.T) {
	dir := t.TempDir()
	db, err := NewDB(dir)
	if err != nil {
		t.Fatal(err)
	}
	db.SetWriterVersion("test-1.2.3")

	tree := &config.ConfigTree{Children: []*config.Node{{Keys: []string{"system"}}}}
	if err := db.WriteActive(tree); err != nil {
		t.Fatalf("WriteActive: %v", err)
	}

	got, err := db.ReadActive()
	if err != nil {
		t.Fatalf("ReadActive: %v", err)
	}
	if got == nil || len(got.Children) != 1 || got.Children[0].Keys[0] != "system" {
		t.Fatalf("round trip mismatch: %+v", got)
	}
}

// TestEnvelopeOnDiskHasMagicHeader proves the persisted bytes begin with
// the magic header line — the encoding that makes an old reader fail closed.
func TestEnvelopeOnDiskHasMagicHeader(t *testing.T) {
	dir := t.TempDir()
	db, err := NewDB(dir)
	if err != nil {
		t.Fatal(err)
	}
	db.SetWriterVersion("9.9.9")
	if err := db.WriteActive(&config.ConfigTree{}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "active.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(raw, []byte(envelopeMagic)) {
		t.Fatalf("on-disk active.json does not start with envelope magic: %q", raw[:min(40, len(raw))])
	}
	firstLine := string(raw[:bytes.IndexByte(raw, '\n')])
	// #7176: assert against the CONSTANTS, not literals. Pinning "v=1" encoded
	// which side of the agreement was trusted, and it broke the moment the
	// writer legitimately moved to v2 — reporting a version bump as a header
	// defect. The property worth holding is that the header states what this
	// build actually writes.
	for _, want := range []string{
		fmt.Sprintf("v=%d", EnvelopeFormatVersion),
		"writer=9.9.9",
		fmt.Sprintf("min-reader=%d", EnvelopeMinReaderVersion),
	} {
		if !strings.Contains(firstLine, want) {
			t.Errorf("header line %q missing %q", firstLine, want)
		}
	}
}

// TestOldReaderRejectsEnvelope proves the PRE-ENVELOPE reader semantics
// (a bare json.Unmarshal of the on-disk bytes into ConfigTree) ERROR on an
// enveloped DB — i.e. the floor's fail-closed property holds. This is the
// silent-wipe defect the floor closes: an old reader must reject, not
// empty-load.
func TestOldReaderRejectsEnvelope(t *testing.T) {
	body := wrapEnvelope([]byte(`{"Children":null}`), "1.0", true, EnvelopeMinReaderVersion)
	var tree config.ConfigTree
	if err := json.Unmarshal(body, &tree); err == nil {
		t.Fatal("old reader (bare json.Unmarshal) accepted the envelope; floor is broken — it must reject")
	}
}

// TestEnvelopeTooNewFailsClosed proves a DB stamped min-reader greater than
// this build's support is rejected with ErrConfigDBUnreadable-class failure
// rather than misread.
func TestEnvelopeTooNewFailsClosed(t *testing.T) {
	// Craft a header with an artificially high min-reader.
	header := "#xpf-config-envelope v=1 writer=future ast=1 min-reader=99 rollback-fmt=1\n"
	data := append([]byte(header), []byte(`{"Children":null}`)...)
	if !hasEnvelope(data) {
		t.Fatal("hasEnvelope false on crafted header")
	}
	_, _, err := stripEnvelope(data)
	if err == nil {
		t.Fatal("stripEnvelope accepted a too-new min-reader; must fail closed")
	}
	if !strings.Contains(err.Error(), "NEWER xpf") && !strings.Contains(err.Error(), "reader format") {
		t.Errorf("unexpected error text: %v", err)
	}
}

// TestStoreLoadTooNewDBTaggedUnreadable proves Store.Load tags a too-new
// DB with ErrConfigDBUnreadable so the daemon can fail closed.
func TestStoreLoadTooNewDBTaggedUnreadable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	dbDir := filepath.Join(dir, ".configdb")
	if err := os.MkdirAll(dbDir, 0755); err != nil {
		t.Fatal(err)
	}
	header := "#xpf-config-envelope v=1 writer=future ast=1 min-reader=99 rollback-fmt=1\n"
	data := append([]byte(header), []byte(`{"Children":null}`)...)
	if err := os.WriteFile(filepath.Join(dbDir, "active.json"), data, 0644); err != nil {
		t.Fatal(err)
	}

	s := newTestStoreAt(t, path)
	err := s.Load()
	if err == nil {
		t.Fatal("Load accepted a too-new DB; must fail closed")
	}
	if !errors.Is(err, ErrConfigDBUnreadable) {
		t.Fatalf("Load error not tagged ErrConfigDBUnreadable: %v", err)
	}
}

// TestStoreLoadCorruptDBTaggedUnreadable proves a corrupt (unparseable)
// active.json is tagged ErrConfigDBUnreadable rather than silently
// start-fresh.
func TestStoreLoadCorruptDBTaggedUnreadable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	dbDir := filepath.Join(dir, ".configdb")
	if err := os.MkdirAll(dbDir, 0755); err != nil {
		t.Fatal(err)
	}
	// Garbage with no envelope: the legacy-read path runs json.Unmarshal
	// and errors -> tagged unreadable.
	if err := os.WriteFile(filepath.Join(dbDir, "active.json"), []byte("{not json"), 0644); err != nil {
		t.Fatal(err)
	}
	s := newTestStoreAt(t, path)
	err := s.Load()
	if err == nil {
		t.Fatal("Load accepted corrupt DB; must fail closed")
	}
	if !errors.Is(err, ErrConfigDBUnreadable) {
		t.Fatalf("Load error not tagged ErrConfigDBUnreadable: %v", err)
	}
}

// TestLegacyNoEnvelopeStillReads proves upgrading TO the floor release is
// non-destructive: a pre-envelope (plain-JSON) active.json still loads.
func TestLegacyNoEnvelopeStillReads(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	dbDir := filepath.Join(dir, ".configdb")
	if err := os.MkdirAll(dbDir, 0755); err != nil {
		t.Fatal(err)
	}
	// A plain-JSON active.json with no envelope (as written by a pre-floor
	// xpf).
	plain := `{"Children":[{"Keys":["system"]}]}`
	if err := os.WriteFile(filepath.Join(dbDir, "active.json"), []byte(plain), 0644); err != nil {
		t.Fatal(err)
	}
	s := newTestStoreAt(t, path)
	if err := s.Load(); err != nil {
		t.Fatalf("Load of legacy no-envelope DB failed: %v", err)
	}
	if s.ActiveConfig() == nil {
		t.Fatal("legacy DB loaded as nil active config")
	}
}
