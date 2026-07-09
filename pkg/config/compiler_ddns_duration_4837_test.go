package config

import (
	"strings"
	"testing"
)

// #4837: `system services dynamic-dns forced-refresh <value>` and
// `... error-backoff-max <value>` accept a Go duration string ("24h") or a
// bare-seconds integer ("86400"), but a value that parses as NEITHER form
// was silently discarded — parseDurationSeconds returned 0, the `s > 0`
// guard skipped the assignment, and the field was left unset (falling back
// to its downstream default) with no commit-time error or warning. The
// operator believed their tuning applied when it silently did not.
//
// All tests use the production ParseSetCommand + SetPath path (buildTree),
// never NewParser (the flat-set gotcha in CLAUDE.md).

func hasDDNSDurationWarning(cfg *Config, leaf string) bool {
	for _, w := range cfg.Warnings {
		if strings.Contains(w, leaf) && strings.Contains(w, "not a valid duration") {
			return true
		}
	}
	return false
}

// A garbage forced-refresh value (typo: extra "h") is rejected at commit.
func TestDDNSForcedRefreshGarbageRejected(t *testing.T) {
	tree := buildTree(t, []string{
		"set system services dynamic-dns forced-refresh 24hh",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("garbage forced-refresh '24hh' compiled without error (#4837 regression)")
	}
	if !strings.Contains(err.Error(), "24hh") || !strings.Contains(err.Error(), "forced-refresh") {
		t.Fatalf("error should name the offending leaf and value, got: %v", err)
	}
}

// A negative error-backoff-max value parses via strconv.Atoi but is not a
// meaningful interval — the pre-fix code silently discarded it the same way
// as an unparseable string (parseDurationSeconds returns a value <= 0 in
// both cases). It must be rejected at commit too.
func TestDDNSErrorBackoffMaxNegativeRejected(t *testing.T) {
	tree := buildTree(t, []string{
		"set system services dynamic-dns error-backoff-max -5",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("negative error-backoff-max '-5' compiled without error (#4837 regression)")
	}
	if !strings.Contains(err.Error(), "-5") || !strings.Contains(err.Error(), "error-backoff-max") {
		t.Fatalf("error should name the offending leaf and value, got: %v", err)
	}
}

// The lenient (tolerant load / peer-sync) path WARNS instead of rejecting a
// garbage forced-refresh value, so an already-persisted config an older
// binary accepted still boots (#1960 fail-closed-on-load).
func TestDDNSForcedRefreshGarbageLenientWarns(t *testing.T) {
	tree := buildTree(t, []string{
		"set system services dynamic-dns forced-refresh 24hh",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient load of a garbage forced-refresh value must NOT fail (brick-on-restart), got: %v", err)
	}
	if !hasDDNSDurationWarning(cfg, "forced-refresh") {
		t.Fatalf("lenient load must emit a forced-refresh warning, warnings=%v", cfg.Warnings)
	}
	// Matches pre-#4837 runtime behavior: the field stays unset (falls back
	// to the downstream default) — only the warning is new.
	if cfg.System.Services != nil && cfg.System.Services.DynamicDNS != nil &&
		cfg.System.Services.DynamicDNS.ForcedRefreshSeconds != 0 {
		t.Fatalf("garbage forced-refresh must not set a value, got %d",
			cfg.System.Services.DynamicDNS.ForcedRefreshSeconds)
	}
}

// The lenient path also warns (not rejects) a garbage error-backoff-max.
func TestDDNSErrorBackoffMaxGarbageLenientWarns(t *testing.T) {
	tree := buildTree(t, []string{
		"set system services dynamic-dns error-backoff-max -5",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient load of a negative error-backoff-max must NOT fail (brick-on-restart), got: %v", err)
	}
	if !hasDDNSDurationWarning(cfg, "error-backoff-max") {
		t.Fatalf("lenient load must emit an error-backoff-max warning, warnings=%v", cfg.Warnings)
	}
}

// A well-formed duration string and a well-formed bare-seconds integer both
// still parse and apply — the fix must not over-reject valid values.
func TestDDNSDurationValidFormsAccepted(t *testing.T) {
	cases := []struct {
		name string
		line string
		want int
	}{
		{"duration-string", "set system services dynamic-dns forced-refresh 24h", 86400},
		{"bare-seconds", "set system services dynamic-dns forced-refresh 3600", 3600},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildTree(t, []string{tc.line})
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("valid forced-refresh should compile, got: %v", err)
			}
			if cfg.System.Services == nil || cfg.System.Services.DynamicDNS == nil {
				t.Fatal("system services dynamic-dns did not compile")
			}
			if got := cfg.System.Services.DynamicDNS.ForcedRefreshSeconds; got != tc.want {
				t.Fatalf("forced-refresh = %d, want %d", got, tc.want)
			}
			if hasDDNSDurationWarning(cfg, "forced-refresh") {
				t.Fatalf("valid forced-refresh must not warn, warnings=%v", cfg.Warnings)
			}
		})
	}
}
