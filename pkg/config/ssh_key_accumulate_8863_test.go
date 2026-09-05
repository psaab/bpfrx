package config

import (
	"reflect"
	"testing"
)

// #8863: a second `set … ssh-ed25519` REVOKED the first key instead of adding
// to it. The commit succeeded with no warning, and `applyRootAuth` writes the
// surviving key as the whole of root's authorized_keys, so the first
// administrator lost root access at the next apply.
//
// It fails CLOSED — access lost, not granted — which is why it is a lockout
// rather than a permissive leak, and why the severity argument is about what
// the daemon does on the next apply rather than about the config diff.
//
// TWO SPELLINGS DISAGREED, and the hierarchical one was already right:
//
//	set … ssh-ed25519 "K1"; set … ssh-ed25519 "K2"   -> [K2]      WRONG
//	root-authentication { ssh-ed25519 "K1"; ssh-ed25519 "K2"; }   -> [K1 K2]  correct
//
// So the braced form is the ground truth this cell measures the flat form
// against, rather than an invented expectation.
//
// THE FIX IS TWO PARTS AND EITHER ALONE IS WRONG. `multi: true` on the leaf
// makes repeated `set` lines accumulate onto one node instead of replacing —
// but the compiler read `nodeVal`, which is Keys[1] only, so with the schema
// change alone the second key would be dropped instead of the first: the same
// #2419 multi-value defect pointed the other way. `sshKeyValues` reads the
// whole Keys tail AND the children, so both spellings and the bracketed list
// land the same set.
//
// EVERY EQUALITY BELOW IS PAIRED WITH A LIVENESS ASSERTION. An empty slice
// equals an empty slice: if compilation silently produced no keys at all, a
// bare DeepEqual against an expected-empty value would pass and would be
// indistinguishable from the defect. Nothing here expects empty, and the
// non-empty check says so out loud.
func compileFlat8863(t *testing.T, lines ...string) *Config {
	t.Helper()
	tree := &ConfigTree{}
	for _, l := range lines {
		path, err := ParseSetCommand(l)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", l, err)
		}
		tree.SetPath(path)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict compile: %v", err)
	}
	return cfg
}

func rootSSHKeys8863(t *testing.T, cfg *Config) []string {
	t.Helper()
	if cfg == nil || cfg.System.RootAuthentication == nil {
		t.Fatal("root-authentication absent from the compiled config")
	}
	return cfg.System.RootAuthentication.SSHKeys
}

func userSSHKeys8863(t *testing.T, cfg *Config, name string) []string {
	t.Helper()
	if cfg == nil || cfg.System.Login == nil {
		t.Fatal("system login absent from the compiled config")
	}
	for _, u := range cfg.System.Login.Users {
		if u != nil && u.Name == name {
			return u.SSHKeys
		}
	}
	t.Fatalf("user %q absent from the compiled config", name)
	return nil
}

// assertKeys compares CONTENTS and asserts the result is live. `want` must be
// non-empty: this cell has no case whose correct answer is "no keys", so an
// empty result is always the defect and must never satisfy an assertion here.
func assertKeys8863(t *testing.T, label string, got, want []string) {
	t.Helper()
	if len(want) == 0 {
		t.Fatalf("%s: the expectation is empty, which cannot distinguish a delivered "+
			"result from a config that compiled no keys at all", label)
	}
	if len(got) == 0 {
		t.Errorf("%s: NO keys compiled. An administrator's authorized_keys would be "+
			"written empty at the next apply (#8863)", label)
		return
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s: keys = %q, want %q. A key missing here is REVOKED at the next "+
			"apply — applyRootAuth writes the compiled set as the whole of the "+
			"authorized_keys file (#8863)", label, got, want)
	}
}

func TestRepeatedSSHKeySetLinesAccumulate8863(t *testing.T) {
	t.Run("root, same key type twice", func(t *testing.T) {
		cfg := compileFlat8863(t,
			`set system root-authentication ssh-ed25519 "K1"`,
			`set system root-authentication ssh-ed25519 "K2"`)
		assertKeys8863(t, "root ssh-ed25519 x2", rootSSHKeys8863(t, cfg), []string{"K1", "K2"})
	})

	t.Run("root, three keys", func(t *testing.T) {
		cfg := compileFlat8863(t,
			`set system root-authentication ssh-ed25519 "K1"`,
			`set system root-authentication ssh-ed25519 "K2"`,
			`set system root-authentication ssh-ed25519 "K3"`)
		assertKeys8863(t, "root ssh-ed25519 x3", rootSSHKeys8863(t, cfg), []string{"K1", "K2", "K3"})
	})

	t.Run("per-user, same key type twice", func(t *testing.T) {
		cfg := compileFlat8863(t,
			`set system login user u1 class super-user`,
			`set system login user u1 authentication ssh-rsa "R1"`,
			`set system login user u1 authentication ssh-rsa "R2"`)
		assertKeys8863(t, "user u1 ssh-rsa x2", userSSHKeys8863(t, cfg, "u1"), []string{"R1", "R2"})
	})

	t.Run("bracketed list, one statement", func(t *testing.T) {
		cfg := compileFlat8863(t, `set system root-authentication ssh-ed25519 [ "K1" "K2" ]`)
		assertKeys8863(t, "root ssh-ed25519 [ K1 K2 ]", rootSSHKeys8863(t, cfg), []string{"K1", "K2"})
	})

	// A real key contains spaces and arrives QUOTED. It must stay ONE key: the
	// leaf is now multi:true, and a reader that split on whitespace would turn
	// one key into three garbage entries.
	t.Run("a quoted key containing spaces stays one key", func(t *testing.T) {
		cfg := compileFlat8863(t,
			`set system root-authentication ssh-ed25519 "ssh-ed25519 AAAAC3NzaC1 admin@host"`)
		assertKeys8863(t, "quoted key with spaces", rootSSHKeys8863(t, cfg),
			[]string{"ssh-ed25519 AAAAC3NzaC1 admin@host"})
	})

	// Controls: things that were already correct and must stay correct.
	t.Run("CONTROL different key types were never affected", func(t *testing.T) {
		cfg := compileFlat8863(t,
			`set system root-authentication ssh-ed25519 "K1"`,
			`set system root-authentication ssh-rsa "R1"`)
		assertKeys8863(t, "root ed25519 + rsa", rootSSHKeys8863(t, cfg), []string{"K1", "R1"})
	})

	t.Run("CONTROL a single key is unchanged", func(t *testing.T) {
		cfg := compileFlat8863(t, `set system root-authentication ssh-ed25519 "K1"`)
		assertKeys8863(t, "root one key", rootSSHKeys8863(t, cfg), []string{"K1"})
	})
}

// The hierarchical spelling was ALREADY correct, and it is the reference the
// flat form is measured against. If it ever regresses, the flat cells above
// would still pass against a wrong expectation, so it is asserted separately
// rather than assumed.
func TestBothSpellingsAgreeOnTheKeySet8863(t *testing.T) {
	text := "system {\n root-authentication {\n  ssh-ed25519 \"K1\";\n  ssh-ed25519 \"K2\";\n }\n}\n"
	tree, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	hier, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("hierarchical compile: %v", err)
	}
	hierKeys := rootSSHKeys8863(t, hier)
	assertKeys8863(t, "hierarchical", hierKeys, []string{"K1", "K2"})

	flat := compileFlat8863(t,
		`set system root-authentication ssh-ed25519 "K1"`,
		`set system root-authentication ssh-ed25519 "K2"`)
	assertKeys8863(t, "flat set", rootSSHKeys8863(t, flat), hierKeys)
}

// #1319 / #1960: the tolerant path must keep accepting what it accepts today.
// A schema change is exactly the kind that can tighten it by accident.
func TestTolerantPathStillAcceptsRepeatedKeys8863(t *testing.T) {
	tree := &ConfigTree{}
	for _, l := range []string{
		`set system root-authentication ssh-ed25519 "K1"`,
		`set system root-authentication ssh-ed25519 "K2"`,
	} {
		path, err := ParseSetCommand(l)
		if err != nil {
			t.Fatalf("ParseSetCommand: %v", err)
		}
		tree.SetPath(path)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient REJECTED a config it must accept: %v (#1960)", err)
	}
	assertKeys8863(t, "lenient", rootSSHKeys8863(t, cfg), []string{"K1", "K2"})
}

// The duplicate-user-block fold (#6992) accumulates keys too, so the two
// spellings land the same set. This is asserted HERE as well as in #6992's own
// cell, because #6992 measures the fold and this measures the equivalence the
// fix is for — if the fold ever reverts to replacing, #6992 reds on the fold
// and this reds on the divergence, and the two failures say different things.
func TestDuplicateUserBlocksAccumulateKeysToo8863(t *testing.T) {
	hier := "system {\n login {\n  class ops { permissions [ view ]; }\n" +
		"  user alice {\n   uid 2001;\n   class ops;\n   authentication { ssh-rsa \"R1\"; }\n  }\n" +
		"  user alice {\n   uid 2002;\n   class ops;\n   authentication { ssh-rsa \"R2\"; }\n  }\n }\n}\n"
	tree, perrs := NewParser(hier).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}
	if cfg.System.Login == nil || len(cfg.System.Login.Users) != 1 {
		t.Fatalf("duplicate `user alice` did not fold to one entry")
	}
	u := cfg.System.Login.Users[0]
	assertKeys8863(t, "duplicate blocks, keys", u.SSHKeys, []string{"R1", "R2"})

	// The scalar half of #6992's decision is UNCHANGED and asserted here so a
	// future change cannot quietly make everything accumulate.
	if u.UID != 2002 {
		t.Errorf("uid = %d, want 2002 — uid is a SCALAR and still takes the LAST authored "+
			"value; only the key SET accumulates (#6992/#8863)", u.UID)
	}
}
