package configstore

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #4060 — symmetric commit-ingest guard for the #4051 raw-AST secret redaction.
//
// RedactedClone masks every secret leaf with config.SecretDataPlaceholder
// ("##SECRET-DATA##") for the REST config show / export + gRPC ShowConfig
// surfaces. Those renders are display-only and NOT restorable. An operator who
// re-applies a redacted export (a load/commit of that text) must be REJECTED at
// commit-ingest — otherwise the placeholder is silently committed as the LITERAL
// secret for every secret leaf, breaking IPsec/auth with a nonsense key.
//
// The IKE pre-shared-key is deliberately used as the probe: it is opaque free
// text to the #1319 typed-leaf validators (no per-leaf validator would reject
// "##SECRET-DATA##"), so ONLY the #4060 placeholder guard catches it — proving
// the guard is load-bearing rather than a coincidental typed-leaf rejection.

// redactedPSKLine is the config-mode `set` input (no `set` prefix, for
// SetFromInput) that a REST `export` of a configured IKE PSK renders after
// redaction: the ascii-text qualifier is kept, the key material is the masked
// placeholder (quoted by FormatSet because '#' is a non-identifier char).
const redactedPSKLine = `security ike policy pol1 pre-shared-key ascii-text "` + config.SecretDataPlaceholder + `"`

// TestCommitCheck_RejectsRedactionPlaceholder is the strict-path e2e: an
// operator committing a re-applied redacted export is rejected at both
// CommitCheck and Commit with the #4060 placeholder error.
func TestCommitCheck_RejectsRedactionPlaceholder(t *testing.T) {
	s := newTestStoreAt(t, filepath.Join(t.TempDir(), "config"))
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := s.SetFromInput(redactedPSKLine); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	_, err := s.CommitCheck()
	if err == nil {
		t.Fatal("expected CommitCheck to reject the ##SECRET-DATA## placeholder, got nil")
	}
	if !strings.Contains(err.Error(), config.SecretDataPlaceholder) {
		t.Fatalf("CommitCheck error should name the redaction placeholder: %v", err)
	}
	if !strings.Contains(err.Error(), "pre-shared-key") {
		t.Fatalf("CommitCheck error should name the offending config path: %v", err)
	}
	if _, err := s.Commit(); err == nil {
		t.Fatal("expected Commit to reject the ##SECRET-DATA## placeholder, got nil")
	}
}

// TestCheckText_RejectsRedactionPlaceholder proves the same rejection through
// the CheckText gate (the #1879 `xpfd check-config` day-0 path), which parses
// full config text — the shape a REST `load`/`import` of an exported file takes.
func TestCheckText_RejectsRedactionPlaceholder(t *testing.T) {
	redactedText := `security {
    ike {
        policy pol1 {
            pre-shared-key ascii-text "` + config.SecretDataPlaceholder + `";
        }
    }
}`
	_, err := CheckText(redactedText, -1)
	if err == nil {
		t.Fatal("expected CheckText to reject the ##SECRET-DATA## placeholder, got nil")
	}
	if !strings.Contains(err.Error(), config.SecretDataPlaceholder) {
		t.Fatalf("CheckText error should name the redaction placeholder: %v", err)
	}
}

// TestCommitCheck_AcceptsRealSecret proves the guard rejects ONLY the exact
// placeholder: a normal cleartext IKE PSK still commits cleanly.
func TestCommitCheck_AcceptsRealSecret(t *testing.T) {
	s := newTestStoreAt(t, filepath.Join(t.TempDir(), "config"))
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := s.SetFromInput("security ike policy pol1 pre-shared-key ascii-text realsupersecret"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if _, err := s.CommitCheck(); err != nil {
		t.Fatalf("a real cleartext secret must pass CommitCheck, got: %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("a real cleartext secret must Commit, got: %v", err)
	}
}

// TestLoad_ToleratesStoredRedactionPlaceholder is the boot-safety half: a
// placeholder that somehow reached persisted state must WARN-boot (lenient
// path), not blackout the daemon — the same strict/lenient doctrine as the
// #1319 typed-leaf gate. RedactedClone is display-only so this should never
// happen in practice, but the tolerant path stays fail-open on ingest of a
// config the operator did not just author; the next strict commit rejects it.
func TestLoad_ToleratesStoredRedactionPlaceholder(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "config")
	writeStoredConfig(t, cfgPath,
		`set security ike policy pol1 pre-shared-key ascii-text "`+config.SecretDataPlaceholder+`"`)

	s := newTestStoreAt(t, cfgPath)
	if err := s.Load(); err != nil {
		t.Fatalf("Load() must tolerate a stored placeholder (warn, not blackout), got: %v", err)
	}
	if s.ActiveConfig() == nil {
		t.Fatal("ActiveConfig() is nil after tolerated Load")
	}

	// The next STRICT operator commit must still reject it.
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	_, err := s.CommitCheck()
	if err == nil {
		t.Fatal("CommitCheck must stay strict after a tolerated Load, got nil")
	}
	if !strings.Contains(err.Error(), config.SecretDataPlaceholder) {
		t.Fatalf("CommitCheck error should name the redaction placeholder: %v", err)
	}
}
