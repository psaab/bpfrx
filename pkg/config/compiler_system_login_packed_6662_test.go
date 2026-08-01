package config

import (
	"sort"
	"strings"
	"testing"
)

// gate6662Marker is the substring unique to the #6662 packed-body rejection.
// Several gates can reject a `system login` config (the schema keyValidator on
// the user name, validateLoginClassRef on an undefined class, the duplicate
// named-block gate), so every rejection assertion in this file is attributed:
// a bare `err != nil` would pass even if this gate never ran.
const gate6662Marker = "written on the instance line"

// gate6662StatementMarker is the sibling marker for the one-level-down packed
// BLOCK statement (`authentication ssh-rsa "..."` inside a nested user body).
const gate6662StatementMarker = "written on the statement line"

// gate6701ShadowMarker attributes the built-in-shadowing rejection found while
// sweeping the #6701 fail-open for siblings.
const gate6701ShadowMarker = "is a SYSTEM-DEFINED login class"

// compileHierarchical drives the REAL hierarchical parse -> compile path.
func compileLogin6662(t *testing.T, text string) (*Config, error) {
	t.Helper()
	p := NewParser(text)
	tree, perrs := p.Parse()
	if len(perrs) != 0 {
		t.Fatalf("parse %q: %v", text, perrs)
	}
	return CompileConfig(tree)
}

// compileLogin6662Lenient is compileHierarchical on the tolerant load /
// peer-sync path (#1960).
func compileLogin6662Lenient(t *testing.T, text string) (*Config, error) {
	t.Helper()
	p := NewParser(text)
	tree, perrs := p.Parse()
	if len(perrs) != 0 {
		t.Fatalf("parse %q: %v", text, perrs)
	}
	return CompileConfigLenient(tree)
}

// compileFlatSet drives the REAL flat-set path: ParseSetCommand + SetPath per
// line, never NewParser (which merges newline-separated `set` lines into one
// giant node and would silently test something else).
func compileLogin6662FlatSet(t *testing.T, lines ...string) (*Config, error) {
	t.Helper()
	tree := &ConfigTree{}
	for _, l := range lines {
		path, err := ParseSetCommand(l)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", l, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	return CompileConfig(tree)
}

func mustReject(t *testing.T, err error, marker, what string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: compiled with NO error — the gate did not fire and the operator's "+
			"configuration was silently altered", what)
	}
	if !strings.Contains(err.Error(), marker) {
		t.Fatalf("%s: rejected by a DIFFERENT gate (want a message containing %q):\n  %v",
			what, marker, err)
	}
}

// ---------------------------------------------------------------------------
// Outcome 1: the nested spelling compiles CORRECTLY (and its safety nets fire).
// ---------------------------------------------------------------------------

// TestLoginNestedCompilesCorrectly_6662 is the baseline: the block spelling
// carries every leaf through, INCLUDING the ones whose downstream warnings are
// guarded on non-emptiness. Asserting the deny-commands advisory fires is the
// point — that advisory (`if lc.DenyCommands != ""`, loginClassAdvisoryWarnings)
// is one of the safety nets the packed drop silently disabled, so a test that
// only checked struct fields would miss half of what the bug cost.
func TestLoginNestedCompilesCorrectly_6662(t *testing.T) {
	cfg, err := compileLogin6662(t, `system {
		login {
			class ops {
				permissions [ view configure ];
				idle-timeout 30;
				deny-commands "request system zeroize";
				deny-configuration "system login";
				allow-commands "show .*";
			}
			user alice {
				uid 2001;
				class ops;
				authentication {
					ssh-rsa "ssh-rsa AAAAB3NzaC1yc2E alice";
					encrypted-password "$6$rounds=5000$abc$def";
				}
			}
		}
	}`)
	if err != nil {
		t.Fatalf("nested spelling must compile: %v", err)
	}

	if cfg.System.Login == nil {
		t.Fatal("System.Login is nil")
	}
	if len(cfg.System.Login.Classes) != 1 {
		t.Fatalf("got %d classes, want 1", len(cfg.System.Login.Classes))
	}
	lc := cfg.System.Login.Classes[0]
	if lc.Name != "ops" {
		t.Errorf("class name = %q, want \"ops\"", lc.Name)
	}
	if got := strings.Join(lc.Permissions, ","); got != "view,configure" {
		t.Errorf("permissions = %q, want \"view,configure\"", got)
	}
	if len(lc.MappedPermissions) != 2 {
		t.Errorf("MappedPermissions = %v, want 2 entries", lc.MappedPermissions)
	}
	if lc.IdleTimeout != 30 {
		t.Errorf("IdleTimeout = %d, want 30", lc.IdleTimeout)
	}
	if lc.DenyCommands != "request system zeroize" {
		t.Errorf("DenyCommands = %q, want \"request system zeroize\"", lc.DenyCommands)
	}
	if lc.DenyConfiguration != "system login" {
		t.Errorf("DenyConfiguration = %q, want \"system login\"", lc.DenyConfiguration)
	}
	if lc.AllowCommands != "show .*" {
		t.Errorf("AllowCommands = %q, want \"show .*\"", lc.AllowCommands)
	}

	if len(cfg.System.Login.Users) != 1 {
		t.Fatalf("got %d users, want 1", len(cfg.System.Login.Users))
	}
	u := cfg.System.Login.Users[0]
	if u.Name != "alice" || u.Class != "ops" || u.UID != 2001 {
		t.Errorf("user = {Name:%q Class:%q UID:%d}, want {alice ops 2001}", u.Name, u.Class, u.UID)
	}
	if len(u.SSHKeys) != 1 || u.SSHKeys[0] != "ssh-rsa AAAAB3NzaC1yc2E alice" {
		t.Errorf("SSHKeys = %v, want one ssh-rsa key", u.SSHKeys)
	}
	if u.EncryptedPassword.Reveal() != "$6$rounds=5000$abc$def" {
		t.Errorf("EncryptedPassword = %q, want the configured hash", u.EncryptedPassword.Reveal())
	}

	// The safety net the packed drop disabled: deny-* is not enforced by xpf's
	// coarse RBAC, so the class is MORE PERMISSIVE than the Junos source and
	// the operator must be told. The warning is guarded on DenyCommands != "".
	var advisory string
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "MORE PERMISSIVE") {
			advisory = w
		}
	}
	if advisory == "" {
		t.Fatalf("the deny-commands MORE PERMISSIVE advisory did not fire; warnings: %v", cfg.Warnings)
	}
	if !strings.Contains(advisory, "deny-commands") || !strings.Contains(advisory, "deny-configuration") {
		t.Errorf("advisory does not name both deny leaves: %q", advisory)
	}
}

// ---------------------------------------------------------------------------
// Outcome 2: the packed spelling is REJECTED at commit, by THIS gate.
// ---------------------------------------------------------------------------

// TestLoginPackedRejectedAtCommit_6662 walks the whole `system login` body
// vocabulary in its packed spelling. Each row previously compiled an EMPTY
// object and returned no error.
func TestLoginPackedRejectedAtCommit_6662(t *testing.T) {
	tests := []struct {
		name   string
		text   string
		marker string
	}{
		// --- login user <name> ---
		{"user class", `system { login { user alice class ops; } }`, gate6662Marker},
		{"user uid", `system { login { user alice uid 2001; } }`, gate6662Marker},
		{"user authentication (fully packed)",
			`system { login { user alice authentication ssh-rsa "ssh-rsa AAAA k"; } }`, gate6662Marker},
		{"user multiple statements packed",
			`system { login { user alice class ops uid 2001; } }`, gate6662Marker},

		// --- login class <name> ---
		{"class permissions (bracketed)",
			`system { login { class ops permissions [ view configure ]; } }`, gate6662Marker},
		{"class permissions (single)",
			`system { login { class ops permissions view; } }`, gate6662Marker},
		{"class idle-timeout", `system { login { class ops idle-timeout 30; } }`, gate6662Marker},
		{"class deny-commands",
			`system { login { class ops deny-commands "request system zeroize"; } }`, gate6662Marker},
		{"class deny-configuration",
			`system { login { class ops deny-configuration "system login"; } }`, gate6662Marker},
		{"class allow-commands",
			`system { login { class ops allow-commands "show .*"; } }`, gate6662Marker},
		{"class allow-configuration",
			`system { login { class ops allow-configuration "interfaces"; } }`, gate6662Marker},
		{"class login-alarms", `system { login { class ops login-alarms; } }`, gate6662Marker},
		{"class login-tip", `system { login { class ops login-tip; } }`, gate6662Marker},

		// --- one level down: a BLOCK statement written inline inside a nested body ---
		{"authentication ssh-rsa inline in a nested user body",
			`system { login { user alice { authentication ssh-rsa "ssh-rsa AAAA k"; } } }`,
			gate6662StatementMarker},
		{"authentication ssh-ed25519 inline in a nested user body",
			`system { login { user alice { authentication ssh-ed25519 "ssh-ed25519 AAAA k"; } } }`,
			gate6662StatementMarker},
		{"authentication encrypted-password inline in a nested user body",
			`system { login { user alice { authentication encrypted-password "$6$abc$def"; } } }`,
			gate6662StatementMarker},

		// --- the bare-container AST shape (namedInstances' second branch) ---
		{"packed inside a bare `user { }` container",
			`system { login { user { alice class ops; } } }`, gate6662Marker},
		{"packed inside a bare `class { }` container",
			`system { login { class { ops permissions view; } } }`, gate6662Marker},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := compileLogin6662(t, tt.text)
			mustReject(t, err, tt.marker, tt.name)
			if !strings.Contains(err.Error(), "#6662") {
				t.Errorf("rejection does not cite the issue: %v", err)
			}
			if !strings.Contains(err.Error(), "Rewrite as") {
				t.Errorf("rejection is not actionable (no rewrite shown): %v", err)
			}
		})
	}
}

// TestLoginPackedRejectionNamesTheDroppedTokens_6662 pins the message CONTENT,
// not just the fact of rejection: an operator has to be able to see which
// statement was dropped and how to spell it. A gate that rejected with a
// generic message would satisfy the table above.
func TestLoginPackedRejectionNamesTheDroppedTokens_6662(t *testing.T) {
	_, err := compileLogin6662(t,
		`system { login { class ops deny-commands "request system zeroize"; } }`)
	if err == nil {
		t.Fatal("packed class body compiled with no error")
	}
	msg := err.Error()
	for _, want := range []string{
		"system login class ops",
		`deny-commands request system zeroize`,
		"SILENTLY DROPPED",
		"set system login class ops deny-commands",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("rejection does not contain %q:\n  %s", want, msg)
		}
	}
}

// TestLoginPackedUserRejectionExplainsTheRBACCost_6662 requires the `user`
// rejection to state the consequence that makes this a security defect rather
// than a typo: an empty class is the CLI's legacy allow-everything mode.
func TestLoginPackedUserRejectionExplainsTheRBACCost_6662(t *testing.T) {
	_, err := compileLogin6662(t, `system { login { user alice class ops; } }`)
	if err == nil {
		t.Fatal("packed user body compiled with no error")
	}
	msg := err.Error()
	for _, want := range []string{"NO login class", "allow-everything"} {
		if !strings.Contains(msg, want) {
			t.Errorf("rejection does not explain the RBAC cost (missing %q):\n  %s", want, msg)
		}
	}
}

// ---------------------------------------------------------------------------
// Outcome 3: flat-set still compiles CORRECTLY (regression guard).
// ---------------------------------------------------------------------------

// TestLoginFlatSetStillCompiles_6662 is the regression guard. Flat-set works
// today — the schema consumes exactly the instance name as the keyed arg and
// hangs the body off as children — and the new gate must not touch it. Without
// this, a gate keyed on "the instance node carries extra tokens" that got the
// identity-key count wrong would reject every `set system login ...` line and
// brick config authoring, while the reject-table above stayed green.
func TestLoginFlatSetStillCompiles_6662(t *testing.T) {
	cfg, err := compileLogin6662FlatSet(t,
		"set system login class ops permissions [ view configure ]",
		"set system login class ops idle-timeout 30",
		`set system login class ops deny-commands "request system zeroize"`,
		`set system login class ops allow-commands "show .*"`,
		"set system login class ops login-alarms",
		"set system login user alice uid 2001",
		"set system login user alice class ops",
		`set system login user alice authentication ssh-rsa "ssh-rsa AAAAB3NzaC1yc2E alice"`,
		`set system login user alice authentication encrypted-password "$6$rounds=5000$abc$def"`,
	)
	if err != nil {
		t.Fatalf("flat-set spelling must still compile: %v", err)
	}

	if len(cfg.System.Login.Classes) != 1 {
		t.Fatalf("got %d classes, want 1", len(cfg.System.Login.Classes))
	}
	lc := cfg.System.Login.Classes[0]
	if got := strings.Join(lc.Permissions, ","); got != "view,configure" {
		t.Errorf("permissions = %q, want \"view,configure\"", got)
	}
	if lc.IdleTimeout != 30 {
		t.Errorf("IdleTimeout = %d, want 30", lc.IdleTimeout)
	}
	if lc.DenyCommands != "request system zeroize" {
		t.Errorf("DenyCommands = %q, want the configured regex", lc.DenyCommands)
	}
	if lc.AllowCommands != "show .*" {
		t.Errorf("AllowCommands = %q, want the configured regex", lc.AllowCommands)
	}

	if len(cfg.System.Login.Users) != 1 {
		t.Fatalf("got %d users, want 1", len(cfg.System.Login.Users))
	}
	u := cfg.System.Login.Users[0]
	if u.Name != "alice" || u.Class != "ops" || u.UID != 2001 {
		t.Errorf("user = {Name:%q Class:%q UID:%d}, want {alice ops 2001}", u.Name, u.Class, u.UID)
	}
	if len(u.SSHKeys) != 1 {
		t.Errorf("SSHKeys = %v, want one key", u.SSHKeys)
	}
	if u.EncryptedPassword.Reveal() != "$6$rounds=5000$abc$def" {
		t.Errorf("EncryptedPassword = %q, want the configured hash", u.EncryptedPassword.Reveal())
	}
}

// TestLoginBareInstanceStillCompiles_6662 guards the other false-positive edge:
// an instance with NO body at all (`user alice;` / `class ops;`) carries exactly
// the identity keys and must pass the gate untouched.
func TestLoginBareInstanceStillCompiles_6662(t *testing.T) {
	for _, text := range []string{
		`system { login { user alice; } }`,
		`system { login { class ops; } }`,
		`system { login { user alice { } } }`,
	} {
		if _, err := compileLogin6662(t, text); err != nil {
			t.Errorf("%s: bare instance must compile, got: %v", text, err)
		}
	}
}

// TestLoginPackedInsideAppliedGroupRejected_6662 pins that the gate sees a
// packed body arriving through `apply-groups`.
//
// The gate walks TOP-LEVEL `system`, so its coverage depends on running AFTER
// apply-groups expansion — which runPreWalkGates does. If it ever moved ahead of
// expansion, a packed login body hidden in an applied group would compile empty
// again with the top-level cases still green, and `groups` is exactly how a
// migrated vSRX config carries shared login stanzas.
//
// The UNAPPLIED case is the false-positive half and must NOT reject: an
// unapplied group is inert (the compiler ignores its body too), so rejecting it
// would fail a config that does nothing.
//
// Scope note, so the binding is not overclaimed: only the APPLIED subtest is
// mutation-bound. Making the gate blind to `system` reds it (M16). The UNAPPLIED
// subtest holds STRUCTURALLY rather than by assertion — ExpandGroups DELETES the
// whole `groups` stanza before compileExpanded runs runPreWalkGates, so the gate
// cannot see an unapplied body no matter what it walks. An attempt to mutate the
// gate into rejecting one was a no-op for exactly that reason. It is kept as
// documentation of the ordering the applied case depends on, not as a guard that
// a plausible edit could trip.
func TestLoginPackedInsideAppliedGroupRejected_6662(t *testing.T) {
	const groupBody = `groups { g1 { system { login { user alice class ops; } } } }`
	const classDef = `system { login { class ops { permissions view; } } }`

	t.Run("applied group is rejected", func(t *testing.T) {
		_, err := compileLogin6662(t, groupBody+"\napply-groups g1;\n"+classDef)
		mustReject(t, err, gate6662Marker, "packed body inside an applied group")
	})

	t.Run("unapplied group is inert, not rejected", func(t *testing.T) {
		cfg, err := compileLogin6662(t, groupBody+"\n"+classDef)
		if err != nil {
			t.Fatalf("an UNAPPLIED group must not be rejected — its body never compiles: %v", err)
		}
		if len(cfg.System.Login.Users) != 0 {
			t.Fatalf("unapplied group contributed users %+v; the premise of not rejecting it is "+
				"that it contributes nothing", cfg.System.Login.Users)
		}
	})

	t.Run("nested body inside an applied group still compiles", func(t *testing.T) {
		cfg, err := compileLogin6662(t,
			`groups { g1 { system { login { user alice { class ops; } } } } }`+
				"\napply-groups g1;\n"+classDef)
		if err != nil {
			t.Fatalf("the NESTED spelling inside an applied group must compile: %v", err)
		}
		if len(cfg.System.Login.Users) != 1 || cfg.System.Login.Users[0].Class != "ops" {
			t.Fatalf("users = %+v, want alice with class ops", cfg.System.Login.Users)
		}
	})

	t.Run("shadowing class inside an applied group is rejected", func(t *testing.T) {
		_, err := compileLogin6662(t,
			`groups { g1 { system { login { class super-user { permissions view; } } } } }`+
				"\napply-groups g1;")
		mustReject(t, err, gate6701ShadowMarker, "shadowing class inside an applied group")
	})
}

// ---------------------------------------------------------------------------
// The tolerant path WARNS rather than rejecting (#1960 no-brick).
// ---------------------------------------------------------------------------

// TestLoginPackedLenientWarns_6662 covers the tolerant load / peer-sync path.
// It asserts the WARNING TEXT, not merely the absence of an error: a lenient
// path that dropped the finding entirely would satisfy `err == nil`.
func TestLoginPackedLenientWarns_6662(t *testing.T) {
	tests := []struct {
		name   string
		text   string
		marker string
	}{
		{"packed user body", `system { login { user alice class ops; } }`, gate6662Marker},
		{"packed class body", `system { login { class ops permissions view; } }`, gate6662Marker},
		{"inline authentication block",
			`system { login { user alice { authentication ssh-rsa "ssh-rsa AAAA k"; } } }`,
			gate6662StatementMarker},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := compileLogin6662Lenient(t, tt.text)
			if err != nil {
				t.Fatalf("tolerant path must NOT reject (#1960 no-brick): %v", err)
			}
			var found string
			for _, w := range cfg.Warnings {
				if strings.Contains(w, tt.marker) {
					found = w
				}
			}
			if found == "" {
				t.Fatalf("tolerant path emitted no warning containing %q; warnings: %v",
					tt.marker, cfg.Warnings)
			}
			if !strings.Contains(found, "#6662") {
				t.Errorf("warning does not cite the issue: %q", found)
			}
		})
	}
}

// TestLoginPackedLenientStillCompilesEmpty_6662 states the residual honestly and
// pins the belt that covers it: on the tolerant path the packed stanza STILL
// compiles to an empty class (that is what "warn, don't reject" means), so the
// commit gate alone does not close the RBAC hole there. What closes it is
// pkg/cli ResolveLoginClass mapping a matched user with an EMPTY class to the
// fail-closed class — asserted independently in
// pkg/daemon TestApplyCLILoginClassLenientEmptyClassFailsClosed_6701.
func TestLoginPackedLenientStillCompilesEmpty_6662(t *testing.T) {
	cfg, err := compileLogin6662Lenient(t, `system { login { user alice class ops; } }`)
	if err != nil {
		t.Fatalf("tolerant path must not reject: %v", err)
	}
	if len(cfg.System.Login.Users) != 1 {
		t.Fatalf("got %d users, want 1", len(cfg.System.Login.Users))
	}
	if got := cfg.System.Login.Users[0].Class; got != "" {
		t.Fatalf("leniently-loaded packed user Class = %q; this test documents the residual "+
			"(it compiles EMPTY) — if unpacking was added, update the pkg/cli belt rationale too", got)
	}
}

// ---------------------------------------------------------------------------
// #6701 sibling: a custom class shadowing a system-defined one.
// ---------------------------------------------------------------------------

// TestLoginClassShadowingBuiltinRejected_6701 covers the sibling found while
// sweeping the RBAC fail-open. `class super-user { permissions view; }` compiled
// cleanly, recorded MappedPermissions=[PermView], and the commit advisory
// reported the narrowing as applied — while pkg/cli resolveClassPerms resolved
// the BUILT-IN [PermAll] at runtime, so the user held every permission.
func TestLoginClassShadowingBuiltinRejected_6701(t *testing.T) {
	for _, name := range []string{"super-user", "operator", "read-only", "config-viewer", "unauthorized"} {
		t.Run(name, func(t *testing.T) {
			_, err := compileLogin6662(t,
				`system { login { class `+name+` { permissions view; } } }`)
			mustReject(t, err, gate6701ShadowMarker, "class "+name)
			if !strings.Contains(err.Error(), "INERT") {
				t.Errorf("rejection does not say the definition is inert: %v", err)
			}
		})
	}
}

// TestLoginClassShadowingBuiltinLenientWarns_6701 is the tolerant-path half.
func TestLoginClassShadowingBuiltinLenientWarns_6701(t *testing.T) {
	cfg, err := compileLogin6662Lenient(t,
		`system { login { class super-user { permissions view; } } }`)
	if err != nil {
		t.Fatalf("tolerant path must NOT reject (#1960 no-brick): %v", err)
	}
	var found bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, gate6701ShadowMarker) {
			found = true
		}
	}
	if !found {
		t.Fatalf("tolerant path emitted no shadowing warning; warnings: %v", cfg.Warnings)
	}
}

// TestLoginCustomClassStillCompiles_6701 is the false-positive guard for the
// shadow gate: a custom class whose name is NOT a built-in must keep compiling
// exactly as #4304 S-2 intends.
func TestLoginCustomClassStillCompiles_6701(t *testing.T) {
	cfg, err := compileLogin6662(t, `system {
		login {
			class noc-admin { permissions [ view configure ]; }
			user bob { class noc-admin; }
		}
	}`)
	if err != nil {
		t.Fatalf("a non-shadowing custom class must compile: %v", err)
	}
	if len(cfg.System.Login.Classes) != 1 || cfg.System.Login.Classes[0].Name != "noc-admin" {
		t.Fatalf("classes = %+v, want one named noc-admin", cfg.System.Login.Classes)
	}
	if len(cfg.System.Login.Users) != 1 || cfg.System.Login.Users[0].Class != "noc-admin" {
		t.Fatalf("users = %+v, want bob with class noc-admin", cfg.System.Login.Users)
	}
}

// ---------------------------------------------------------------------------
// Enumeration drift guards.
// ---------------------------------------------------------------------------

// TestLoginInstanceKeywordsMatchSchema_6662 pins the enumeration to the schema.
// `system login` has exactly two children (`class`, `user`); if a third named
// instance is added to setSchema without a row in loginInstanceKeywords, the new
// stanza's packed spelling silently compiles empty again — the exact regression
// this gate exists to prevent, reintroduced one stanza over.
func TestLoginInstanceKeywordsMatchSchema_6662(t *testing.T) {
	sys, ok := setSchema.children["system"]
	if !ok || sys == nil {
		t.Fatal("setSchema has no `system` node")
	}
	login, ok := sys.children["login"]
	if !ok || login == nil {
		t.Fatal("setSchema has no `system login` node")
	}

	var schemaKeys []string
	for name := range login.children {
		schemaKeys = append(schemaKeys, name)
	}
	sort.Strings(schemaKeys)

	gateKeys := append([]string(nil), loginInstanceKeywords...)
	sort.Strings(gateKeys)

	if strings.Join(schemaKeys, ",") != strings.Join(gateKeys, ",") {
		t.Fatalf("loginInstanceKeywords = %v but the `system login` schema children are %v — "+
			"a stanza missing from the gate compiles its packed spelling EMPTY with no error (#6662)",
			gateKeys, schemaKeys)
	}
}

// TestLoginBlockOnlyStatementsAreSchemaChildren_6662 guards the other
// enumeration: every `<keyword> <statement>` listed as block-only must be a real
// schema child of that instance, and must itself have children (which is what
// makes it a block rather than a leaf). A typo would silently disable the
// one-level-down half of the gate while the instance-line half stayed green.
func TestLoginBlockOnlyStatementsAreSchemaChildren_6662(t *testing.T) {
	login := setSchema.children["system"].children["login"]

	names := loginBlockOnlyStatementNames()
	if len(names) == 0 {
		t.Fatal("loginBlockOnlyStatements is empty — the one-level-down gate binds nothing")
	}

	for _, full := range names {
		parts := strings.SplitN(full, " ", 2)
		keyword, stmt := parts[0], parts[1]

		inst, ok := login.children[keyword]
		if !ok || inst == nil {
			t.Errorf("block-only entry %q: %q is not a `system login` schema child", full, keyword)
			continue
		}
		node, ok := inst.children[stmt]
		if !ok || node == nil {
			t.Errorf("block-only entry %q: %q is not a schema child of `login %s`", full, stmt, keyword)
			continue
		}
		if len(node.children) == 0 {
			t.Errorf("block-only entry %q: the schema node has no children, so it is a LEAF, "+
				"not a block — listing it here gates the wrong shape", full)
		}
		// The recorded ARITY must equal the schema's, because the gate skips
		// exactly that many key tokens before calling the rest a packed body.
		// Recording it too low rejects the correct nested spelling; too high
		// lets a packed body through (#6701 MINOR-4).
		gotArity, listed := loginBlockOnlyArity(keyword, stmt)
		if !listed {
			t.Errorf("block-only entry %q: not retrievable through loginBlockOnlyArity", full)
			continue
		}
		if gotArity != node.args {
			t.Errorf("block-only entry %q: gate records arity %d but the schema node takes %d "+
				"arg(s) — the gate would skip the wrong number of key tokens", full, gotArity, node.args)
		}
	}
}

// TestLoginBlockOnlyEnumerationIsComplete_6662 is the completeness half: it
// derives, from the SCHEMA, every `login <keyword> <statement>` that is a block
// (has children — at ANY arity) and requires each to be listed as block-only.
//
// Reading the compiler by hand is how the enumeration was built; this is what
// stops it rotting. If someone adds a second block-bodied login statement to
// the schema and forgets the gate row, its inline spelling starts dropping
// silently — and this test names it.
func TestLoginBlockOnlyEnumerationIsComplete_6662(t *testing.T) {
	login := setSchema.children["system"].children["login"]

	listed := map[string]bool{}
	for _, full := range loginBlockOnlyStatementNames() {
		listed[full] = true
	}

	var missing []string
	for _, keyword := range loginInstanceKeywords {
		inst := login.children[keyword]
		if inst == nil {
			continue
		}
		for stmt, node := range inst.children {
			// A BLOCK is any node with children, REGARDLESS of arity. The
			// previous version also skipped `node.args != 0`, which put an
			// args-bearing block statement (`foo <name> { ... }`) outside the
			// guard's scope entirely — guard scope narrower than the claim it
			// protects. Such a statement is exactly as droppable as a
			// zero-arity one; the arity only changes how many key tokens the
			// gate must skip, which loginBlockOnlyStatements now records
			// (#6701 MINOR-4).
			if node == nil || len(node.children) == 0 {
				continue // a leaf: not a block
			}
			if !listed[keyword+" "+stmt] {
				missing = append(missing, keyword+" "+stmt)
			}
		}
	}
	sort.Strings(missing)
	for _, m := range missing {
		t.Errorf("`login %s` is a BLOCK statement in setSchema but is not listed in "+
			"loginBlockOnlyStatements — its inline spelling drops silently (#6662)", m)
	}
}
