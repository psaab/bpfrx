package cli

import (
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
			id:         osident.Identity{UID: 1500},
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
			id:         osident.Identity{UID: 1000},
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
func TestUnauthorizedClassCannotBeWidened_6701(t *testing.T) {
	// The compiled shape a leniently-loaded `class unauthorized { permissions
	// all; }` produces: a custom class, mapped to PermAll.
	cfg := &config.Config{}
	cfg.System.Login = &config.LoginConfig{
		Classes: []*config.LoginClass{{
			Name:              ClassUnidentified,
			Permissions:       []string{"all"},
			MappedPermissions: []config.LoginClassPermission{config.PermAll},
		}},
	}

	c := &CLI{userClass: ClassUnidentified, store: nil}
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
