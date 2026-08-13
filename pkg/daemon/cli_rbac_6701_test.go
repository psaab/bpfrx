package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/cli"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/osident"
)

// classRecorder is the userClassSetter double: it records every SetUserClass
// call so the test can assert BOTH the value and whether the call happened at
// all (the "no `system login` stanza" row turns on the latter).
type classRecorder struct{ calls []string }

func (r *classRecorder) SetUserClass(class string) { r.calls = append(r.calls, class) }

func cfgWithLogin(pairs ...[2]string) *config.Config {
	c := &config.Config{}
	lc := &config.LoginConfig{}
	for _, p := range pairs {
		lc.Users = append(lc.Users, &config.LoginUser{Name: p[0], Class: p[1]})
	}
	c.System.Login = lc
	return c
}

// TestApplyCLILoginClass_6701 is the daemon-site decision table: given an
// active config and an OS identity, which class reaches the shell.
//
// It is the site the #6701 report names (`pkg/daemon/daemon_run.go:721`), now
// extracted to applyCLILoginClass so the wiring is assertable without standing
// up a daemon. Every row sets `$USER` to a sentinel that IS a configured
// super-user, so any row that reintroduced an environment read would resolve to
// super-user and fail loudly rather than silently agreeing.
func TestApplyCLILoginClass_6701(t *testing.T) {
	restricted := cfgWithLogin(
		[2]string{"bob", "read-only"},
		[2]string{spoofedUSERDaemon, "super-user"},
	)

	tests := []struct {
		name      string
		cfg       *config.Config
		id        osident.Identity
		wantCalls []string
	}{
		{
			name:      "configured user gets its configured class",
			cfg:       restricted,
			id:        osident.Identity{UID: 1001, Name: "bob"},
			wantCalls: []string{"read-only"},
		},
		{
			name:      "OS account absent from `system login` is NOT promoted to super-user",
			cfg:       restricted,
			id:        osident.Identity{UID: 1500, Name: "mallory"},
			wantCalls: []string{cli.ClassUnidentified},
		},
		{
			name:      "unidentifiable caller is NOT promoted to super-user",
			cfg:       restricted,
			id:        osident.Identity{UID: 1500},
			wantCalls: []string{cli.ClassUnidentified},
		},
		{
			name:      "user configured with no class fails closed",
			cfg:       cfgWithLogin([2]string{"dave", ""}),
			id:        osident.Identity{UID: 1002, Name: "dave"},
			wantCalls: []string{cli.ClassUnidentified},
		},
		{
			name:      "uid 0 keeps the Junos root default when unconfigured",
			cfg:       restricted,
			id:        osident.Identity{UID: 0, Name: "root"},
			wantCalls: []string{cli.ClassRootDefault},
		},
		{
			// The DELIBERATE legacy mode: with no `system login` stanza the
			// class is left UNSET, which pkg/cli treats as allow-everything for
			// a deployment that never configured RBAC. Asserting zero calls (not
			// `SetUserClass("")`) is the point — an explicit empty-string call
			// would look identical from the shell's side but would mean the
			// resolver ran and produced nothing, which must never happen.
			name:      "no `system login` stanza leaves the class unset (legacy mode preserved)",
			cfg:       &config.Config{},
			id:        osident.Identity{UID: 1500, Name: "mallory"},
			wantCalls: nil,
		},
		{
			name:      "nil config leaves the class unset",
			cfg:       nil,
			id:        osident.Identity{UID: 1500, Name: "mallory"},
			wantCalls: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("USER", spoofedUSERDaemon)
			rec := &classRecorder{}

			applyCLILoginClass(rec, tt.cfg, tt.id)

			if len(rec.calls) != len(tt.wantCalls) {
				t.Fatalf("SetUserClass called %d time(s) with %v, want %d with %v",
					len(rec.calls), rec.calls, len(tt.wantCalls), tt.wantCalls)
			}
			for i, want := range tt.wantCalls {
				if rec.calls[i] != want {
					t.Fatalf("SetUserClass call %d = %q, want %q", i, rec.calls[i], want)
				}
			}
			for _, got := range rec.calls {
				if got == "" {
					t.Fatalf("SetUserClass(\"\") — the empty class is the legacy "+
						"allow-everything mode and must never be set explicitly (identity %+v)", tt.id)
				}
			}
		})
	}
}

// spoofedUSERDaemon is a sentinel that is also a configured super-user in the
// table above, so a reintroduced `$USER` read resolves to super-user and the
// test fails rather than silently agreeing with the correct answer.
const spoofedUSERDaemon = "xpf-spoofed-6701"

// TestApplyCLILoginClassNeverPromotesOnNoMatch_6701 is the narrow fail-on-revert
// for the exact line the issue reports: `if !found { shell.SetUserClass("super-user") }`.
//
// It sweeps a range of non-root uids and names against a config that grants
// super-user to somebody else, and requires that NONE of them reaches
// super-user. Restoring the old default makes every row RED.
func TestApplyCLILoginClassNeverPromotesOnNoMatch_6701(t *testing.T) {
	cfg := cfgWithLogin([2]string{"admin", "super-user"}, [2]string{"bob", "read-only"})

	unmatched := []osident.Identity{
		{UID: 1000, Name: "mallory"},
		{UID: 1500, Name: "nobody"},
		{UID: 65534, Name: ""},
		{UID: 1, Name: "daemon"},
		{UID: 1001, Name: "ADMIN"}, // case must not fold onto the super-user row
	}

	for _, id := range unmatched {
		rec := &classRecorder{}
		applyCLILoginClass(rec, cfg, id)
		if len(rec.calls) != 1 {
			t.Fatalf("identity %+v: SetUserClass called %d time(s), want 1", id, len(rec.calls))
		}
		if rec.calls[0] == "super-user" {
			t.Errorf("identity %+v resolved to %q — the #6701 promote-on-no-match hole is back",
				id, rec.calls[0])
		}
		if rec.calls[0] != cli.ClassUnidentified {
			t.Errorf("identity %+v resolved to %q, want the fail-closed %q",
				id, rec.calls[0], cli.ClassUnidentified)
		}
	}
}

// TestApplyCLILoginClassLenientEmptyClassFailsClosed_6701 covers the sibling
// path that survives the #6662 commit gate.
//
// #6662 REJECTS a packed `user alice class ops;` at commit, but the tolerant
// load / peer-sync path only WARNS (#1960 no-brick), so a node that persisted
// such a config under an older binary still boots with `Class == ""`. That
// empty class is exactly pkg/cli's legacy allow-everything shortcut, so the
// commit gate alone does NOT close the RBAC hole on that path — the resolver's
// empty-class branch is what does. This asserts the belt independently of the
// gate: build the compiled shape a lenient load produces and require it to fail
// closed.
func TestApplyCLILoginClassLenientEmptyClassFailsClosed_6701(t *testing.T) {
	// The shape CompileConfigLenient yields for `user alice class ops;`.
	cfg := cfgWithLogin([2]string{"alice", ""})

	rec := &classRecorder{}
	applyCLILoginClass(rec, cfg, osident.Identity{UID: 1001, Name: "alice"})

	if len(rec.calls) != 1 {
		t.Fatalf("SetUserClass called %d time(s), want 1", len(rec.calls))
	}
	if rec.calls[0] == "" {
		t.Fatal("a leniently-loaded packed login stanza set the EMPTY class — the CLI would " +
			"allow every command and render secrets in cleartext for a user the operator restricted")
	}
	if rec.calls[0] != cli.ClassUnidentified {
		t.Fatalf("SetUserClass(%q), want the fail-closed %q", rec.calls[0], cli.ClassUnidentified)
	}
}
