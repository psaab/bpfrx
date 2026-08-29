package configstore

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/fsatomic"
)

// syncBuffer is a bytes.Buffer whose Write and String share a mutex so a
// leaked background goroutine still logging through slog.Default() cannot
// race the test's read (#6446). captureWarnLogs installs the buffer as the
// process-global slog default; a persistRetryLoop goroutine leaked from an
// earlier test (store_persist.go — intentionally no close signal) keeps
// calling slog.Warn() and writes through the newly-installed handler. slog's
// handler mutex only serializes writers among themselves; the test reads the
// raw buffer, so the read needs the same lock as the write to be safe.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// masterPwTree builds the minimal config tree that declares a
// master-password pseudorandom-function — the leaf masterPasswordPRF
// (crypto.go) reads to decide whether a stored config must be encrypted.
func masterPwTree() *config.ConfigTree {
	return &config.ConfigTree{
		Children: []*config.Node{{
			Keys: []string{"system"},
			Children: []*config.Node{{
				Keys: []string{"master-password"},
				Children: []*config.Node{{
					Keys:   []string{"pseudorandom-function", "sha256"},
					IsLeaf: true,
				}},
			}},
		}},
	}
}

// captureWarnLogs redirects slog to a buffer at Warn level for the test's
// lifetime and returns the buffer. The buffer is mutex-guarded (syncBuffer)
// because slog.SetDefault installs it process-globally: a leaked
// persistRetryLoop goroutine from an earlier test writes through the handler
// concurrently with the test's read (#6446).
func captureWarnLogs(t *testing.T) *syncBuffer {
	t.Helper()
	buf := &syncBuffer{}
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(old) })
	return buf
}

// TestPlaintextDowngradeWarn_4579 pins the #4579 A4-06 hardening: reading a
// config that DECLARES a master-password but is stored as UNENCRYPTED
// plaintext emits an operator warning. Every write path encrypts the body
// when master-password is set (maybeEncryptTreeJSON keyed off the tree's
// master-password leaf), so plaintext-with-master-password can only arise
// from a downgrade to an older build, a restore from an unencrypted backup,
// or tampering — surfacing it beats loading the cleartext secrets silently.
//
// RED on revert: readTreeMeta drops the warn, so no record is logged and the
// substring assertion fails.
func TestPlaintextDowngradeWarn_4579(t *testing.T) {
	buf := captureWarnLogs(t)
	s := newTestStore(t)

	// Write active.json as PLAINTEXT (no AES-GCM envelope) even though the
	// tree declares a master-password — the exact downgrade case. Wrap the
	// body in the #1917 compatibility envelope like a real committed DB so
	// readTreeMeta reaches the decrypt/parse path.
	tree := masterPwTree()
	if masterPasswordPRF(tree) != "sha256" {
		t.Fatalf("test tree does not declare a master-password: %+v", tree)
	}
	body, err := json.MarshalIndent(tree, "", "  ")
	if err != nil {
		t.Fatalf("marshal tree: %v", err)
	}
	framed := wrapEnvelope(body, "", true, EnvelopeMinReaderVersion)
	if err := fsatomic.WriteFileDurable(s.db.activePath(), framed, 0600); err != nil {
		t.Fatalf("write plaintext active.json: %v", err)
	}

	got, err := s.db.ReadActive()
	if err != nil {
		t.Fatalf("ReadActive: %v", err)
	}
	if got == nil || masterPasswordPRF(got) != "sha256" {
		t.Fatalf("read-back tree lost the master-password declaration: %+v", got)
	}

	logged := buf.String()
	if !strings.Contains(logged, "#4579") || !strings.Contains(logged, "UNENCRYPTED plaintext") {
		t.Fatalf("expected an unexpected-plaintext warning (#4579 A4-06); got log:\n%s", logged)
	}
}

// TestEncryptedRoundTripNoWarn_4579 is the negative control: a config with a
// master-password written through the normal (encrypting) path reads back
// WITHOUT the downgrade warning — so the A4-06 warn does not cry wolf on the
// legitimate encrypted DB.
func TestEncryptedRoundTripNoWarn_4579(t *testing.T) {
	buf := captureWarnLogs(t)
	s := newTestStore(t)

	// WriteActive encrypts because the tree declares a master-password, so
	// ReadActive decrypts (decrypted=true) and the warn must stay silent.
	tree := masterPwTree()
	if err := s.db.WriteActive(tree); err != nil {
		t.Fatalf("WriteActive: %v", err)
	}
	if _, err := s.db.ReadActive(); err != nil {
		t.Fatalf("ReadActive: %v", err)
	}
	if strings.Contains(buf.String(), "#4579") {
		t.Fatalf("encrypted round-trip must not warn; got log:\n%s", buf.String())
	}
}

// TestPlaintextNoMasterPasswordNoWarn_4579 is the other negative control: a
// plaintext config that does NOT declare a master-password (the common case,
// no encryption configured) must not warn — the warn is specific to the
// declared-but-unencrypted downgrade.
func TestPlaintextNoMasterPasswordNoWarn_4579(t *testing.T) {
	buf := captureWarnLogs(t)
	s := newTestStore(t)

	tree := &config.ConfigTree{Children: []*config.Node{{
		Keys:     []string{"system"},
		Children: []*config.Node{{Keys: []string{"host-name", "plainbox"}, IsLeaf: true}},
	}}}
	if masterPasswordPRF(tree) != "" {
		t.Fatalf("control tree unexpectedly declares a master-password: %+v", tree)
	}
	if err := s.db.WriteActive(tree); err != nil { // no PRF => plaintext write
		t.Fatalf("WriteActive: %v", err)
	}
	if _, err := s.db.ReadActive(); err != nil {
		t.Fatalf("ReadActive: %v", err)
	}
	if strings.Contains(buf.String(), "#4579") {
		t.Fatalf("plaintext config without master-password must not warn; got log:\n%s", buf.String())
	}
}
