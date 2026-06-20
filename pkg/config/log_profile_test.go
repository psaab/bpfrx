package config

// Tests for #2008 H7: `security log profile <name>` compilation +
// stream-name cross-reference. Before H7 the whole profile stanza parsed
// but was silently discarded (no schema child, no compiler case), so a
// config such as vsrx-ha.conf's `profile default-syslog { stream-name ...;
// default-profile; }` committed with no validation and no effect.
//
// Each compile test drives the dual-AST flat-set path
// (ParseSetCommand + SetPath, NOT NewParser, per CLAUDE.md) and the
// reject tests are non-tautological: pre-fix the profile is dropped
// entirely so the Profiles map is empty and the dangling reference never
// errors, so the assertions below FAIL against the unfixed compiler.

import (
	"strings"
	"testing"
)

// buildTree assembles a ConfigTree from flat `set ...` commands using the
// dual-AST flat-set path (ParseSetCommand + SetPath).
func buildLogProfileTree(t *testing.T, cmds ...string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return tree
}

// TestLogProfile_FlatSet_Compiles verifies the profile object compiles to
// typed state from flat-set syntax, including the default-profile flag.
// Pre-fix this FAILS: the stanza is dropped, Profiles is nil.
func TestLogProfile_FlatSet_Compiles(t *testing.T) {
	tree := buildLogProfileTree(t,
		"set security log stream syslog-container host 192.168.99.3",
		"set security log stream syslog-container category all",
		"set security log profile default-syslog stream-name syslog-container",
		"set security log profile default-syslog default-profile",
	)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if cfg.Security.Log.Profiles == nil {
		t.Fatal("expected Log.Profiles populated, got nil (profile silently dropped?)")
	}
	p, ok := cfg.Security.Log.Profiles["default-syslog"]
	if !ok || p == nil {
		t.Fatalf("expected profile default-syslog, got %#v", cfg.Security.Log.Profiles)
	}
	if p.StreamName != "syslog-container" {
		t.Errorf("StreamName = %q, want syslog-container", p.StreamName)
	}
	if !p.DefaultProfile {
		t.Error("DefaultProfile = false, want true")
	}
}

// TestLogProfile_Hierarchical_Compiles verifies the same profile shape as
// authored in vsrx-ha.conf (hierarchical) compiles identically. Uses
// NewParser only because hierarchical AST is the input shape under test;
// the compiler must handle BOTH shapes.
func TestLogProfile_Hierarchical_Compiles(t *testing.T) {
	input := `security {
    log {
        stream syslog-container {
            host {
                192.168.99.3;
            }
            category all;
        }
        profile default-syslog {
            stream-name syslog-container;
            category {
                session {
                    field-extra-name hostname;
                }
            }
            default-profile;
        }
    }
}`
	p := NewParser(input)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	prof, ok := cfg.Security.Log.Profiles["default-syslog"]
	if !ok || prof == nil {
		t.Fatalf("expected profile default-syslog, got %#v", cfg.Security.Log.Profiles)
	}
	if prof.StreamName != "syslog-container" {
		t.Errorf("StreamName = %q, want syslog-container", prof.StreamName)
	}
	if !prof.DefaultProfile {
		t.Error("DefaultProfile = false, want true")
	}
}

// TestLogProfile_DanglingStream_Rejected verifies a profile naming a
// stream that is not configured is rejected at commit. Pre-fix this
// FAILS: the profile is dropped so no error is raised.
func TestLogProfile_DanglingStream_Rejected(t *testing.T) {
	tree := buildLogProfileTree(t,
		"set security log stream real-stream host 192.168.99.3",
		"set security log profile p1 stream-name does-not-exist",
	)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("expected error for profile referencing undefined stream, got nil")
	}
	if !strings.Contains(err.Error(), "does-not-exist") || !strings.Contains(err.Error(), "p1") {
		t.Fatalf("error should name the profile and the missing stream: %v", err)
	}
}

// TestLogProfile_ValidStream_Accepted verifies a profile naming a defined
// stream compiles without error.
func TestLogProfile_ValidStream_Accepted(t *testing.T) {
	tree := buildLogProfileTree(t,
		"set security log stream real-stream host 192.168.99.3",
		"set security log profile p1 stream-name real-stream",
	)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if p := cfg.Security.Log.Profiles["p1"]; p == nil || p.StreamName != "real-stream" {
		t.Fatalf("expected profile p1 -> real-stream, got %#v", cfg.Security.Log.Profiles["p1"])
	}
}

// TestLogProfile_NoStreamName_Accepted verifies a profile with only the
// default-profile flag (no stream-name) is accepted — there is nothing to
// dangle, and Junos permits a profile relying on global routing.
func TestLogProfile_NoStreamName_Accepted(t *testing.T) {
	tree := buildLogProfileTree(t,
		"set security log profile p1 default-profile",
	)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	p := cfg.Security.Log.Profiles["p1"]
	if p == nil || !p.DefaultProfile || p.StreamName != "" {
		t.Fatalf("expected profile p1 default-profile no stream-name, got %#v", p)
	}
}

// TestLogProfile_DanglingStream_LenientWarns verifies the tolerant load /
// peer-sync path downgrades the dangling reference to a warning rather
// than failing the compile (the #1960 fail-closed-on-load doctrine).
func TestLogProfile_DanglingStream_LenientWarns(t *testing.T) {
	tree := buildLogProfileTree(t,
		"set security log stream real-stream host 192.168.99.3",
		"set security log profile p1 stream-name does-not-exist",
	)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient should not error on dangling ref: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "security log profile stream reference") &&
			strings.Contains(w, "does-not-exist") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected a downgraded warning for the dangling stream ref, got %v", cfg.Warnings)
	}
}

// TestLogProfile_InactiveProfile_NotValidated verifies an inactive
// profile (#2042 inactive: marker) is pruned before compile, so a
// dangling stream-name inside it does NOT error — the profile never
// reaches compileLog or the cross-ref validator.
func TestLogProfile_InactiveProfile_NotValidated(t *testing.T) {
	input := `security {
    log {
        stream real-stream {
            host {
                192.168.99.3;
            }
        }
        inactive: profile p1 {
            stream-name does-not-exist;
            default-profile;
        }
    }
}`
	p := NewParser(input)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("inactive profile must not be validated/compiled: %v", err)
	}
	if _, ok := cfg.Security.Log.Profiles["p1"]; ok {
		t.Errorf("inactive profile p1 should be pruned, but it compiled: %#v", cfg.Security.Log.Profiles)
	}
}
