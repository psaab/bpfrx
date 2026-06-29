package config_test

// #3350: `security log stream <s> transport tls-profile <name>` was parsed,
// validated, and stored but NEVER resolved into a *tls.Config at runtime
// (daemon_system.go always passes nil; there is no TLS profile definition
// stanza to resolve it to), so a TLS syslog stream silently fell back to the
// system CA roots instead of the named profile — a secure-syslog posture
// silently downgraded (fail-open). The compiler now REJECTS a named tls-profile
// at commit (validateSecurityLogStreamTLSProfileAST) while leaving a plain
// `transport protocol tls` (system-root TLS) intact. These tests are
// RED-on-revert: removing the gate makes the named profile pass silently.

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestLogStreamTLSProfile3350_StrictReject asserts a named tls-profile is a
// hard compile error on the strict (commit / commit-check) path.
func TestLogStreamTLSProfile3350_StrictReject(t *testing.T) {
	cases := map[string][]string{
		"flat-set": {
			"set security log stream s host 192.0.2.1",
			"set security log stream s transport protocol tls",
			"set security log stream s transport tls-profile mytls",
		},
		"profile-without-explicit-protocol": {
			"set security log stream s host 192.0.2.1",
			"set security log stream s transport tls-profile mytls",
		},
	}
	for name, cmds := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := config.CompileConfig(buildTree3349(t, cmds...))
			if err == nil {
				t.Fatalf("expected strict compile rejection for %v, got nil (tls-profile silently accepted)", cmds)
			}
			if !strings.Contains(err.Error(), "tls-profile") {
				t.Fatalf("error should mention tls-profile, got %v", err)
			}
		})
	}
}

// TestLogStreamTLSProfile3350_NestedReject covers the hierarchical AST shape
// (Junos-canonical nested transport block) parsed by the real parser.
func TestLogStreamTLSProfile3350_NestedReject(t *testing.T) {
	const cfg = `security {
		log {
			stream s {
				host 192.0.2.1;
				transport {
					protocol tls;
					tls-profile mytls;
				}
			}
		}
	}`
	p := config.NewParser(cfg)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	if _, err := config.CompileConfig(tree); err == nil {
		t.Fatalf("expected strict compile rejection for nested transport{tls-profile}, got nil")
	}
}

// TestLogStreamTLSProfile3350_AcceptPlainTLS asserts a TLS stream WITHOUT a
// named profile (system-root TLS) — and tcp/udp streams — still commit cleanly.
// The gate must reject only the named-but-unapplied profile, not TLS itself.
func TestLogStreamTLSProfile3350_AcceptPlainTLS(t *testing.T) {
	good := map[string][]string{
		"plain-tls": {
			"set security log stream s host 192.0.2.1",
			"set security log stream s transport protocol tls",
		},
		"tcp": {
			"set security log stream s host 192.0.2.1",
			"set security log stream s transport protocol tcp",
		},
		"udp-default": {
			"set security log stream s host 192.0.2.1",
		},
	}
	for name, cmds := range good {
		t.Run(name, func(t *testing.T) {
			if err := schemaCheck3349(t, cmds...); err != nil {
				t.Fatalf("valid config rejected by commit-check: %v", err)
			}
			if _, err := config.CompileConfig(buildTree3349(t, cmds...)); err != nil {
				t.Fatalf("valid config failed strict compile: %v", err)
			}
		})
	}
}

// TestLogStreamTLSProfile3350_LenientWarns proves the #1960/#3261 doctrine: an
// already-persisted / peer-synced config naming a tls-profile must NOT brick
// the load — it is downgraded to a warning and still compiles (the profile was
// never applied either way, so the leniently-loaded value is inert).
func TestLogStreamTLSProfile3350_LenientWarns(t *testing.T) {
	tree := buildTree3349(t,
		"set security log stream s host 192.0.2.1",
		"set security log stream s transport protocol tls",
		"set security log stream s transport tls-profile mytls",
	)
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must not fail on a named tls-profile, got %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "tls-profile") && strings.Contains(w, "mytls") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected a lenient warning about the tls-profile, warnings=%v", cfg.Warnings)
	}
}
