package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/osident"
)

// spoofedUSER is a sentinel that can never be a real passwd account name, so an
// assertion against it is never satisfied by coincidence on whatever uid runs
// the suite.
const spoofedUSER = "xpf-spoofed-6701"

// loginCfg builds a `system login` with the given name->class pairs, in order.
func loginCfg(pairs ...[2]string) *config.LoginConfig {
	lc := &config.LoginConfig{}
	for _, p := range pairs {
		lc.Users = append(lc.Users, &config.LoginUser{Name: p[0], Class: p[1]})
	}
	return lc
}

// TestResolveLoginClass_6701 is the decision table for the RBAC identity fix.
//
// Rows 3-6 are the four cases #6701's acceptance criteria name: a configured
// user, a configured user with a spoofed `$USER`, an unset `$USER`, and an OS
// account present on the box but absent from `system login`. `$USER` is set to
// the sentinel for the WHOLE table (and unset for the row that needs it) so the
// spoof is live on every row, not only the row named after it — the resolver
// takes an osident.Identity and must be a pure function of it.
func TestResolveLoginClass_6701(t *testing.T) {
	restricted := loginCfg(
		[2]string{"bob", "read-only"},
		[2]string{"carol", "operator"},
		[2]string{spoofedUSER, "super-user"}, // the account the spoof names
	)

	tests := []struct {
		name       string
		login      *config.LoginConfig
		id         osident.Identity
		wantClass  string
		reasonHas  string
		unsetUSER  bool
		wantNotSup bool // must NOT be super-user (the #6701 promote-on-no-match hole)
	}{
		{
			name:      "configured user gets its configured class",
			login:     restricted,
			id:        osident.Identity{UID: 1001, Name: "bob"},
			wantClass: "read-only",
			reasonHas: `login user "bob" class "read-only"`,
		},
		{
			name: "spoofed $USER cannot change the class: identity is the credential",
			// $USER says "xpf-spoofed-6701", which IS configured as super-user.
			// The kernel says bob. bob's class must win.
			login:      restricted,
			id:         osident.Identity{UID: 1001, Name: "bob"},
			wantClass:  "read-only",
			wantNotSup: true,
		},
		{
			name:       "unset $USER cannot change the class",
			login:      restricted,
			id:         osident.Identity{UID: 1001, Name: "bob"},
			unsetUSER:  true,
			wantClass:  "read-only",
			wantNotSup: true,
		},
		{
			name:       "OS account absent from `system login` is NOT promoted",
			login:      restricted,
			id:         osident.Identity{UID: 1500, Name: "mallory"},
			wantClass:  ClassUnidentified,
			reasonHas:  `OS account "mallory" (uid 1500) is not configured`,
			wantNotSup: true,
		},
		{
			name:       "unidentifiable caller (no passwd entry) is NOT promoted",
			login:      restricted,
			id:         osident.Identity{UID: 1500, Reason: osident.ReasonNoPasswdEntry},
			wantClass:  ClassUnidentified,
			reasonHas:  "has no passwd entry",
			wantNotSup: true,
		},
		{
			name:       "configured user with an EMPTY class fails closed, not to legacy mode",
			login:      loginCfg([2]string{"dave", ""}),
			id:         osident.Identity{UID: 1002, Name: "dave"},
			wantClass:  ClassUnidentified,
			reasonHas:  "configured with no class",
			wantNotSup: true,
		},
		{
			name:      "uid 0 with no matching stanza keeps the Junos root default",
			login:     restricted,
			id:        osident.Identity{UID: 0, Name: "root"},
			wantClass: ClassRootDefault,
			reasonHas: "applying the root default",
		},
		{
			// OVER-REACH GUARD. `set system login user root authentication
			// ssh-ed25519 "..."` is an ordinary additive stanza that leaves the
			// class empty and expresses no intent to restrict. The first draft
			// applied the non-root empty-class rule here and demoted the CONSOLE
			// root shell to `unauthorized` — a lockout of the lifeline caused by
			// a config that reads as purely additive.
			name:      "uid 0 LISTED WITH NO CLASS is not locked out of the console",
			login:     loginCfg([2]string{"root", ""}),
			id:        osident.Identity{UID: 0, Name: "root"},
			wantClass: ClassRootDefault,
			reasonHas: "listed under `system login` with no class",
		},
		{
			// The uid-0 passwd ALIAS (`toor` and friends). os/user.LookupId
			// returns whichever passwd row comes first, so without consulting
			// the literal "root" an explicit restriction on the account the
			// operator named would be silently skipped — a permissive-direction
			// miss, which is this change's whole thesis.
			name:      "uid 0 resolving under a passwd alias still honours `user root`",
			login:     loginCfg([2]string{"root", "read-only"}),
			id:        osident.Identity{UID: 0, Name: "toor"},
			wantClass: "read-only",
			reasonHas: `login user "root" class "read-only"`,
		},
		{
			// The alias lookup must not OVERRIDE a stanza written for the
			// resolved name: the resolved name is tried first.
			name: "a stanza for the resolved alias wins over the `root` fallback",
			login: loginCfg(
				[2]string{"root", "operator"},
				[2]string{"toor", "read-only"},
			),
			id:        osident.Identity{UID: 0, Name: "toor"},
			wantClass: "read-only",
		},
		{
			// A non-root account listed with no class still fails closed — the
			// uid-0 carve-out above must not widen into the general rule.
			name:       "a NON-root account listed with no class still fails closed",
			login:      loginCfg([2]string{"root", ""}, [2]string{"dave", ""}),
			id:         osident.Identity{UID: 1002, Name: "dave"},
			wantClass:  ClassUnidentified,
			reasonHas:  "configured with no class",
			wantNotSup: true,
		},
		{
			// An unresolved identity contributes no name, so an empty-named
			// config row must never match it.
			name:       "an unresolved identity does not match an empty-named config user",
			login:      &config.LoginConfig{Users: []*config.LoginUser{{Name: "", Class: "super-user"}}},
			id:         osident.Identity{UID: 1000, Reason: osident.ReasonNoPasswdEntry},
			wantClass:  ClassUnidentified,
			reasonHas:  "has no passwd entry",
			wantNotSup: true,
		},
		{
			name:      "a numeric-only account name is matched as a name, not a uid",
			login:     loginCfg([2]string{"1000", "read-only"}),
			id:        osident.Identity{UID: 1000, Name: "1000"},
			wantClass: "read-only",
		},
		{
			name:       "a numeric-only name absent from the config is not promoted",
			login:      loginCfg([2]string{"alice", "read-only"}),
			id:         osident.Identity{UID: 1000, Name: "1000"},
			wantClass:  ClassUnidentified,
			wantNotSup: true,
		},
		{
			name:      "uid 0 with an EXPLICIT stanza is restricted by it",
			login:     loginCfg([2]string{"root", "read-only"}),
			id:        osident.Identity{UID: 0, Name: "root"},
			wantClass: "read-only",
			reasonHas: `login user "root" class "read-only"`,
		},
		{
			name:      "uid 0 with no passwd entry still keeps the root default",
			login:     restricted,
			id:        osident.Identity{UID: 0},
			wantClass: ClassRootDefault,
		},
		{
			name:       "nil login config fails closed for a non-root caller",
			login:      nil,
			id:         osident.Identity{UID: 1001, Name: "bob"},
			wantClass:  ClassUnidentified,
			wantNotSup: true,
		},
		{
			name:      "empty user list does not promote a non-root caller",
			login:     &config.LoginConfig{},
			id:        osident.Identity{UID: 1001, Name: "bob"},
			wantClass: ClassUnidentified,
		},
		{
			name:      "a nil user entry is skipped, not matched",
			login:     &config.LoginConfig{Users: []*config.LoginUser{nil, {Name: "bob", Class: "operator"}}},
			id:        osident.Identity{UID: 1001, Name: "bob"},
			wantClass: "operator",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.unsetUSER {
				t.Setenv("USER", "") // t.Setenv restores after the subtest
			} else {
				t.Setenv("USER", spoofedUSER)
			}

			gotClass, gotReason := ResolveLoginClass(tt.login, tt.id)

			if gotClass != tt.wantClass {
				t.Fatalf("ResolveLoginClass(%+v) class = %q, want %q (reason: %s)",
					tt.id, gotClass, tt.wantClass, gotReason)
			}
			// The empty string is pkg/cli's legacy "no RBAC configured"
			// allow-everything shortcut. The resolver is only ever called when
			// RBAC IS configured, so it must never hand that back.
			if gotClass == "" {
				t.Fatalf("ResolveLoginClass(%+v) returned the EMPTY class, which checkPermission "+
					"treats as allow-everything and showConfigRedacted treats as cleartext-read", tt.id)
			}
			if tt.wantNotSup && gotClass == "super-user" {
				t.Fatalf("ResolveLoginClass(%+v) = %q: this is the #6701 promote-on-no-match hole",
					tt.id, gotClass)
			}
			if tt.reasonHas != "" && !strings.Contains(gotReason, tt.reasonHas) {
				t.Fatalf("reason = %q, want it to contain %q", gotReason, tt.reasonHas)
			}
		})
	}
}

// TestClassUnidentifiedIsDenyingNotLegacy_6701 pins the MECHANISM the
// fail-closed default relies on, rather than just its name. `unauthorized` has
// to behave as deny-everything through the real gates:
//
//   - it must not be the empty string (that is the legacy allow-everything mode);
//   - resolveClassPerms must RESOLVE it (present, with an empty permission set),
//     so checkPermission denies by name rather than falling through;
//   - checkPermission must deny an ordinary view-level command;
//   - showConfigRedacted must mask secrets.
//
// Picking any name that fails these — including "" or an undefined string —
// would still satisfy a test that only compared the returned class constant.
func TestClassUnidentifiedIsDenyingNotLegacy_6701(t *testing.T) {
	if ClassUnidentified == "" {
		t.Fatal("ClassUnidentified is the empty string, which IS the legacy allow-everything mode")
	}

	c := &CLI{userClass: ClassUnidentified}

	perms, ok := c.resolveClassPerms(ClassUnidentified)
	if !ok {
		t.Fatalf("resolveClassPerms(%q) did not resolve the class", ClassUnidentified)
	}
	if len(perms) != 0 {
		t.Fatalf("resolveClassPerms(%q) = %v, want an EMPTY permission set", ClassUnidentified, perms)
	}

	for _, cmd := range [][]string{
		{"show", "configuration"},
		{"configure"},
		{"request", "system", "reboot"},
		{"clear", "security", "flow", "session", "all"},
	} {
		if err := c.checkPermission(cmd); err == nil {
			t.Errorf("checkPermission(%v) = nil under class %q — the fail-closed default allows commands",
				cmd, ClassUnidentified)
		}
	}

	if !c.showConfigRedacted() {
		t.Errorf("showConfigRedacted() = false under class %q — secrets would render in cleartext",
			ClassUnidentified)
	}
}

// TestUnresolvedIdentityMatchesNoConfiguredUser_6701 binds the `id.Resolved()`
// test in candidateNames, which is the ONLY thing stopping an unidentifiable
// caller from matching a configured user (#6701 MINOR-1).
//
// The premise is measured, not assumed: `system login user "" { class
// super-user; }` reaches the ACTIVE config — not because the validator is
// missing, but despite it. `config.ValidateLoginUsername` rejects an empty
// name and STRICT commit-check enforces it (configstore.compileTreeStrict ->
// schemaValidateExpandedTreeForNode: `invalid value "": login user name must
// not be empty`). The TOLERANT ingress — Store.Load and Store.SyncApply, i.e.
// boot and peer-sync — runs the SAME gate via Store.compileTreeLenient but
// DOWNGRADES the violation to an slog.Warn and keeps the entry, deliberately
// (#1319), so that a legacy config cannot blackout-boot a node or alarm-loop
// HA sync. So such an entry really can be live, on a path the operator does
// not drive by hand. Do not check this against config.CompileConfigLenient —
// that is a different function with no schema gate at all. An
// unidentified caller carries Name == "". If candidateNames offered that name
// to the match loop, `u.Name == ""` would match the entry and hand the caller
// super-user, reopening #6701 without touching $USER.
//
// The subtests separate PROTECTION from MESSAGE, because the reviewer's
// citation pointed at the wrong one. Removing the `!id.Resolved()` branch in
// ResolveLoginClass changes only which denial string is produced — the class is
// ClassUnidentified either way, because `listed` is already false by then. The
// class assertion is therefore the real guard; the reason assertion is a
// message assertion and is labelled as such.
func TestUnresolvedIdentityMatchesNoConfiguredUser_6701(t *testing.T) {
	// A config that a real deployment can hold: an empty-named super-user entry.
	emptyNamed := &config.LoginConfig{Users: []*config.LoginUser{
		{Name: "", Class: "super-user"},
		{Name: "bob", Class: "read-only"},
	}}

	t.Run("PROTECTION: an unresolved identity is not handed the empty-named entry", func(t *testing.T) {
		for _, id := range []osident.Identity{
			{UID: 1000},  // no passwd entry
			{UID: 65534}, // nobody, unresolvable
			{UID: 1},     // low uid, unresolvable
		} {
			got, reason := ResolveLoginClass(emptyNamed, id)
			if got == "super-user" {
				t.Errorf("identity %+v matched the empty-named `system login user \"\"` entry and "+
					"was handed %q — an unidentifiable caller reached full power (reason: %s)",
					id, got, reason)
			}
			if got != ClassUnidentified {
				t.Errorf("identity %+v resolved to %q, want the fail-closed %q", id, got, ClassUnidentified)
			}
		}
	})

	t.Run("PROTECTION: an unresolved ROOT identity is not handed it either", func(t *testing.T) {
		// uid 0 unresolved must reach the root default via the "root" candidate
		// only — never by matching the empty-named entry.
		got, reason := ResolveLoginClass(emptyNamed, osident.Identity{UID: 0})
		if got != ClassRootDefault {
			t.Fatalf("unresolved uid 0 resolved to %q, want %q (reason: %s)", got, ClassRootDefault, reason)
		}
		if strings.Contains(reason, `login user ""`) {
			t.Fatalf("unresolved uid 0 was governed by the empty-named entry: %s", reason)
		}
	})

	t.Run("MESSAGE ONLY: the !Resolved branch selects the reason, not the class", func(t *testing.T) {
		// Documented explicitly so nobody mistakes this for a second guard: with
		// no empty-named entry present, an unresolved caller is denied by the
		// `listed == false` fall-through regardless, and the !Resolved branch
		// only chooses the wording.
		got, reason := ResolveLoginClass(loginCfg([2]string{"bob", "read-only"}),
			osident.Identity{UID: 1000, Reason: osident.ReasonNoPasswdEntry})
		if got != ClassUnidentified {
			t.Fatalf("class = %q, want %q", got, ClassUnidentified)
		}
		if !strings.Contains(reason, "has no passwd entry") {
			t.Errorf("reason = %q, want it to name the passwd failure", reason)
		}
	})
}

// TestUnauthorizedClassCannotBeWidened_6701 pins the COUPLING the whole
// fail-closed default rests on, which is easy to miss because it lives in a
// different function.
//
// ClassUnidentified is safe only because resolveClassPerms consults the
// system-defined table FIRST. If that precedence were ever inverted — or if a
// custom definition were allowed to win — then a config carrying
//
//	system login class unauthorized { permissions all; }
//
// would turn the fail-closed DEFAULT into a full-power one: every
// unidentifiable caller, and every OS account absent from `system login`, would
// land on PermAll. The strict commit gate rejects such a definition
// (validateLoginClassShadowsBuiltinAST), but the tolerant load / peer-sync path
// only WARNS (#1960), so a persisted or peer-synced config can still carry it
// at runtime. This asserts the runtime holds regardless, through the real gates
// rather than by inspecting precedence.
// It drives the REAL tolerant ingress (Store.SyncApply -> compileTreeLenient),
// not a hand-built Config, and resolves through a REAL store. The first version
// of this test built the struct by hand and left store nil, so
// resolveClassPerms never read the config at all — it passed for the wrong
// reason and stayed green when built-in precedence was inverted. Mutation
// caught that; reading it did not.
func TestUnauthorizedClassCannotBeWidened_6701(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))

	// The peer-sync / persisted-config scenario: a definition that STRICT
	// commit rejects (validateLoginClassShadowsBuiltinAST) but the tolerant path
	// accepts with a warning, so it really can be live at runtime.
	const peerConfig = `system {
    login {
        class unauthorized {
            permissions all;
        }
    }
}
`
	if _, err := store.SyncApply(peerConfig, nil); err != nil {
		t.Fatalf("SyncApply(): %v — the tolerant path must ACCEPT this (that is why the "+
			"runtime precedence has to hold)", err)
	}
	cfg := store.ActiveConfig()
	if cfg == nil || cfg.System.Login == nil || len(cfg.System.Login.Classes) != 1 {
		t.Fatalf("tolerant load did not produce the shadowing class: %+v", cfg)
	}
	// Premise check: the COMPILED struct really does carry the widened mapping.
	// Without this the test could pass because the class never compiled at all.
	if mapped := cfg.System.Login.Classes[0].MappedPermissions; len(mapped) != 1 || mapped[0] != config.PermAll {
		t.Fatalf("compiled MappedPermissions = %v, want [PermAll] — the fixture does not "+
			"actually express the widening it claims to test", mapped)
	}

	c := &CLI{userClass: ClassUnidentified, store: store}
	perms, ok := c.resolveClassPerms(ClassUnidentified)
	if !ok {
		t.Fatalf("resolveClassPerms(%q) did not resolve", ClassUnidentified)
	}
	if len(perms) != 0 {
		t.Fatalf("resolveClassPerms(%q) = %v — a custom definition widened the fail-closed "+
			"default; every unidentifiable caller now holds these permissions", ClassUnidentified, perms)
	}
	for _, p := range perms {
		if p == config.PermAll {
			t.Fatalf("the fail-closed default resolved to PermAll")
		}
	}
	if err := c.checkPermission([]string{"request", "system", "reboot"}); err == nil {
		t.Fatal("a widened `unauthorized` class authorized a destructive maintenance verb")
	}
	if !c.showConfigRedacted() {
		t.Fatal("a widened `unauthorized` class read secrets in cleartext")
	}
}

// TestClassRootDefaultIsSuperUser_6701 pins the one deliberate promotion left:
// uid 0 with nothing configured. It is a Junos-parity default for an identity
// that already owns the config database and the daemon process, and it is the
// console lifeline; the point of the assertion is that it stays scoped to uid 0
// and never becomes the default for anybody else (which the table above
// covers).
func TestClassRootDefaultIsSuperUser_6701(t *testing.T) {
	if ClassRootDefault != "super-user" {
		t.Fatalf("ClassRootDefault = %q, want \"super-user\"", ClassRootDefault)
	}
	if _, ok := config.LoginClassPermissions[ClassRootDefault]; !ok {
		t.Fatalf("ClassRootDefault %q is not a system-defined class", ClassRootDefault)
	}
	if _, ok := config.LoginClassPermissions[ClassUnidentified]; !ok {
		t.Fatalf("ClassUnidentified %q is not a system-defined class — resolveClassPerms would "+
			"not resolve it, and an UNKNOWN class is a weaker guarantee than an empty-but-present one",
			ClassUnidentified)
	}
}

// TestCLIPromptIdentityIgnoresUSEREnv_6701 covers the pkg/cli site
// (cli.go, formerly `username := os.Getenv("USER")`).
//
// The invariance assertion is the mutation-sensitive one: the pre-fix code
// returned `$USER` when set and "root" when unset, so it VARIED with the
// environment. A plain `!= spoofedUSER` alone would be satisfied by any
// hardcoded fallback, and a plain `== "root"` would be vacuous whenever the
// suite runs as root.
func TestCLIPromptIdentityIgnoresUSEREnv_6701(t *testing.T) {
	t.Setenv("USER", spoofedUSER)
	spoofed := New(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	t.Setenv("USER", "")
	unset := New(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	if spoofed.username == spoofedUSER {
		t.Fatalf("CLI.username = %q: the prompt identity came from $USER", spoofed.username)
	}
	if spoofed.username != unset.username {
		t.Fatalf("CLI.username varies with the environment: $USER set -> %q, $USER unset -> %q",
			spoofed.username, unset.username)
	}
	if want := osident.Current().String(); spoofed.username != want {
		t.Fatalf("CLI.username = %q, want the OS credential %q", spoofed.username, want)
	}
	if spoofed.username == "" {
		t.Fatal("CLI.username is empty — the prompt would render `@host>`")
	}
}

// TestCLIPromptDoesNotSetAClass_6701 pins the separation of the two halves:
// constructing the shell must NOT set an RBAC class. The class is applied
// separately by the daemon (pkg/daemon applyCLILoginClass) from the ACTIVE
// config, and a constructor that quietly seeded one would make the daemon's
// fail-closed default unreachable.
func TestCLIPromptDoesNotSetAClass_6701(t *testing.T) {
	c := New(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	if c.userClass != "" {
		t.Fatalf("New() seeded userClass = %q; the class must come from the daemon's "+
			"config-driven resolution, not the constructor", c.userClass)
	}
}

// TestAmbiguousUIDFailsClosed_6706 is the policy half of the #6706 MAJOR: a uid
// shared by two configured accounts must not lend one account's class to the
// other.
//
// The escalation is entirely between LEGITIMATE accounts, which is why "a
// duplicate-uid passwd file is already a broken host" does not dispose of it:
//
//	/etc/passwd:  admin:x:2001:...    bob:x:2001:...
//	system login user admin class super-user
//	system login user bob   class read-only
//
// bob's shell has kernel uid 2001 and nothing else. Resolving that to whichever
// passwd row comes first — os/user's behaviour — hands bob `super-user`.
// osident now reports the uid as unresolved with ReasonAmbiguousUID, and this
// pins that the resolver denies on it rather than matching either name.
//
// Provisioning mitigates but does not close it: pkg/daemon reconcileSystemUsers
// invokes `useradd` without `-o`, so xpf never MAKES a duplicate — but a
// pre-existing, hand-edited or directory-supplied alias is not xpf's to prevent,
// and an authorization decision may not depend on someone else's hygiene.
func TestAmbiguousUIDFailsClosed_6706(t *testing.T) {
	login := loginCfg(
		[2]string{"admin", "super-user"},
		[2]string{"bob", "read-only"},
	)

	t.Run("a non-root ambiguous uid gets neither account's class", func(t *testing.T) {
		got, reason := ResolveLoginClass(login,
			osident.Identity{UID: 2001, Reason: osident.ReasonAmbiguousUID})
		if got != ClassUnidentified {
			t.Fatalf("class = %q, want the fail-closed %q — a uid shared by two configured "+
				"accounts resolved to one of them (reason: %s)", got, ClassUnidentified, reason)
		}
		if !strings.Contains(reason, "shared by more than one passwd account") {
			t.Errorf("reason = %q, want it to name the ambiguity — reporting this as a missing "+
				"account sends the operator hunting for one that is present", reason)
		}
	})

	t.Run("the reason distinguishes ambiguity from absence and from a read failure", func(t *testing.T) {
		// All three deny identically; the operator fix differs in each case.
		for _, tc := range []struct {
			reason osident.Reason
			want   string
		}{
			{osident.ReasonNoPasswdEntry, "has no passwd entry"},
			{osident.ReasonAmbiguousUID, "shared by more than one passwd account"},
			{osident.ReasonLookupFailed, "could not be read"},
		} {
			got, reason := ResolveLoginClass(login, osident.Identity{UID: 2001, Reason: tc.reason})
			if got != ClassUnidentified {
				t.Errorf("reason %v: class = %q, want %q", tc.reason, got, ClassUnidentified)
			}
			if !strings.Contains(reason, tc.want) {
				t.Errorf("reason %v rendered %q, want it to contain %q", tc.reason, reason, tc.want)
			}
		}
	})

	t.Run("an ambiguous uid 0 still keeps the console lifeline", func(t *testing.T) {
		// `root` + `toor` both at uid 0 is a supported layout, and uid 0 is not
		// a boundary xpf can enforce anyway. Ambiguity must not brick the
		// console: the literal "root" candidate still applies, so an explicit
		// stanza wins and the omission case keeps the Junos root default.
		got, _ := ResolveLoginClass(loginCfg([2]string{"bob", "read-only"}),
			osident.Identity{UID: 0, Reason: osident.ReasonAmbiguousUID})
		if got != ClassRootDefault {
			t.Fatalf("ambiguous uid 0 resolved to %q, want %q — an aliased root must not be "+
				"locked out of the console", got, ClassRootDefault)
		}
		got, reason := ResolveLoginClass(loginCfg([2]string{"root", "read-only"}),
			osident.Identity{UID: 0, Reason: osident.ReasonAmbiguousUID})
		if got != "read-only" {
			t.Fatalf("ambiguous uid 0 with an EXPLICIT `user root class read-only` resolved to "+
				"%q, want it honoured (reason: %s)", got, reason)
		}
	})
}

// TestRootAliasClassMatrix_6706 pins the uid-0 decision matrix that decision 1
// of ResolveLoginClass's doc comment describes.
//
// READ THIS AS A DELIBERATE DECISION, NOT AN ACCIDENT AWAITING A FIX (#6706
// review r11). The alias rows below assert that a restrictively configured
// uid-0 alias — `system login user toor class read-only;` with a passwd row
// `toor:x:0:0:` — resolves to `read-only` on a SUCCESSFUL lookup and to
// `super-user` on every FAILED one. That is a promotion on failure, and it is
// the one place in this package where a lookup failure is not narrowing. A
// reviewer meeting it cold reasonably reads it as a fail-open to close; it was
// reviewed as exactly that and deliberately kept, because uid 0 already owns
// the config database, the daemon process and the on-disk secrets, so it is not
// a boundary xpf can enforce — and denying instead would risk locking the
// console out over an unreadable /etc/passwd, buying no real security for a
// real lockout mode. The reasoning lives at identity.go decision 1; this note
// exists so the test is not "corrected" into a denial by someone who finds the
// matrix before the argument.
//
// Changing it is a product decision, not a bug fix. If it is ever revisited,
// the non-root half must stay as it is: an unresolved NON-root identity matches
// no stanza and gets ClassUnidentified, which IS fail-closed.
//
// That paragraph has now been wrong twice, in opposite directions: first
// claiming an explicit class wins "for any uid including 0" (#6706 MINOR-5),
// then that it "cannot win when the caller has no name" and that this is "false
// in exactly one reachable case" (#6706 review r5 F7). Both halves of the real
// rule are asserted here, so the next revision has to agree with something
// executable rather than with a previous sentence:
//
//   - a stanza written for `root` DOES win at uid 0 with no resolved name,
//     because candidateNames injects the literal "root";
//   - a stanza written for an ALIAS does not — and that holds for EVERY
//     unresolved Reason, not for ReasonAmbiguousUID alone. Three reachable
//     Reasons, not one.
//   - an unnamed NON-ROOT caller matches no stanza AT ALL, `root` included,
//     because candidateNames returns an empty slice for it. That is the half
//     the r5 sentence's replacement still left uncovered — it read as a
//     characterization while being only a sufficient condition, and only uid 0
//     was driven here (#6706 review r7 F6). It fails closed, which is why it is
//     a comment finding and not a defect; the point of asserting it is that the
//     next revision of that paragraph has to agree with something executable.
func TestRootAliasClassMatrix_6706(t *testing.T) {
	unresolved := []struct {
		name   string
		reason osident.Reason
	}{
		{"ambiguous uid", osident.ReasonAmbiguousUID},
		{"no passwd entry", osident.ReasonNoPasswdEntry},
		{"lookup failed", osident.ReasonLookupFailed},
	}

	for _, tc := range unresolved {
		id := osident.Identity{UID: 0, Reason: tc.reason}

		t.Run(tc.name+": a `root` stanza still wins with no resolved name", func(t *testing.T) {
			got, reason := ResolveLoginClass(loginCfg([2]string{"root", "read-only"}), id)
			if got != "read-only" {
				t.Fatalf("class = %q, want %q — candidateNames offers the literal \"root\" for "+
					"uid 0 precisely so an explicit stanza can be honoured without a resolved "+
					"name (reason: %s)", got, "read-only", reason)
			}
		})

		t.Run(tc.name+": an ALIAS stanza is dropped", func(t *testing.T) {
			got, reason := ResolveLoginClass(loginCfg([2]string{"toor", "read-only"}), id)
			if got != ClassRootDefault {
				t.Fatalf("class = %q, want %q — with no resolved name there is nothing to match "+
					"`user toor` against, so the root default applies (reason: %s)",
					got, ClassRootDefault, reason)
			}
			if !strings.Contains(reason, "was NOT applied") {
				t.Errorf("reason = %q, want it to say the configured class was not applied — "+
					"silently dropping an operator's explicit restriction is the one thing that "+
					"must not go unreported here", reason)
			}
		})
	}

	// The half a uid-0-only matrix cannot see: an unnamed NON-root caller
	// matches nothing, so an explicit class cannot win for it under ANY stanza
	// name — including the literal "root", which candidateNames injects only for
	// uid 0. Driving `root` and the empty name is the point: those are the two
	// names a reader might expect to slip through.
	for _, tc := range unresolved {
		id := osident.Identity{UID: 1001, Reason: tc.reason}
		for _, stanza := range []string{"root", "", "alice"} {
			t.Run(tc.name+": uid 1001 unnamed matches no `"+stanza+"` stanza", func(t *testing.T) {
				got, reason := ResolveLoginClass(loginCfg([2]string{stanza, ClassRootDefault}), id)
				if got != ClassUnidentified {
					t.Fatalf("class = %q, want %q — candidateNames returns an EMPTY slice for a "+
						"caller that is neither resolved nor uid 0, so no stanza of any name may "+
						"match it (reason: %s)", got, ClassUnidentified, reason)
				}
			})
		}
	}

	// The contrast row: once the alias IS resolved, its stanza wins.
	t.Run("a resolved alias gets its own class", func(t *testing.T) {
		got, reason := ResolveLoginClass(loginCfg([2]string{"toor", "read-only"}),
			osident.Identity{UID: 0, Name: "toor"})
		if got != "read-only" {
			t.Fatalf("class = %q, want %q (reason: %s)", got, "read-only", reason)
		}
	})
}
