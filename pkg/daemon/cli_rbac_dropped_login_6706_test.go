package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/osident"
)

// Round-11 guard: a `system login` stanza that was AUTHORED but compiled away
// must not land in pkg/cli's legacy allow-everything mode.
//
// THE DEFECT THIS BINDS. `applyCLILoginClass` early-returned on
// `cfg.System.Login == nil`, which conflates two states:
//
//   - nothing configured RBAC -> leave the class unset. That is pkg/cli's
//     documented legacy contract and must not change.
//   - RBAC was configured, packed onto an ancestor statement line, and DROPPED
//     by the compiler -> also nil. Strict commit rejects that config (#6662),
//     but the tolerant ingress (Store.Load at boot, Store.SyncApply from a
//     peer) downgrades the finding to a warning and KEEPS it (#1960 no-brick).
//     So a node boots — or a standby inherits — a config that reads as
//     restrictive and runs with NO RBAC at all: every command permitted, and
//     showConfigRedacted false, so IKE PSKs, SNMP communities and
//     authentication-keys render in CLEARTEXT.
//
// The second state is now carried structurally by
// config.SystemConfig.LoginDroppedByPacking rather than inferred, and this test
// drives the WHOLE path: real config text -> the real lenient compiler (which
// is what the tolerant ingress runs) -> applyCLILoginClass -> the class the
// shell would actually receive.
//
// WHY THE CONTROLS MATTER AS MUCH AS THE CASES. Two of the rows below must NOT
// change: a config with no `system login` at all keeps SetUserClass UNCALLED
// (severing the legacy contract would lock out every deployment that never
// configured RBAC), and a correctly-nested config still resolves to the class
// the operator wrote. A fix that simply denied on every nil login would pass
// the defect rows and fail both controls.
func TestApplyCLILoginClass6706DroppedLoginFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name string
		src  string
		// wantSet is whether SetUserClass must be called at all; wantClass is
		// the class it must receive when it is.
		wantSet      bool
		wantClass    string
		wantDropped  bool
		wantNilLogin bool
	}{
		{
			// THE HOLE: the whole stanza packed onto the `system` line.
			name:         "full stanza packed on the system line",
			src:          `system login user alice class ops;`,
			wantSet:      true,
			wantClass:    "unauthorized",
			wantDropped:  true,
			wantNilLogin: true,
		},
		{
			// The SHORT prefix the packed gate deliberately does not report.
			// Its nested twin `system { login; }` compiles a non-nil empty
			// LoginConfig and denies every non-root caller; packed it compiled
			// nil and permitted everyone. The two spellings must agree.
			name:         "bare `system login;` packed on the system line",
			src:          `system login;`,
			wantSet:      true,
			wantClass:    "unauthorized",
			wantDropped:  true,
			wantNilLogin: true,
		},
		{
			name:         "`system login user;` packed on the system line",
			src:          `system login user;`,
			wantSet:      true,
			wantClass:    "unauthorized",
			wantDropped:  true,
			wantNilLogin: true,
		},
		{
			// Packed one level lower: System.Login is non-nil but empty, so
			// this arm was ALREADY fail-closed. It must stay that way, and the
			// flag must still record that the stanza was dropped.
			name:         "packed on the login line (already fail-closed)",
			src:          `system { login user alice class ops; }`,
			wantSet:      true,
			wantClass:    "unauthorized",
			wantDropped:  true,
			wantNilLogin: false,
		},
		{
			// CONTROL 1: the correctly-nested config must resolve to the class
			// the operator wrote. A blanket "deny on anything suspicious" fix
			// fails here.
			name:         "CONTROL correctly nested resolves the authored class",
			src:          `system { login { user alice { class ops; } } }`,
			wantSet:      true,
			wantClass:    "ops",
			wantDropped:  false,
			wantNilLogin: false,
		},
		{
			// CONTROL 2: no `system login` anywhere. SetUserClass must NOT be
			// called — the legacy unset-class contract for a deployment that
			// never configured RBAC. This is the row that stops the fix from
			// becoming a lockout.
			name:         "CONTROL no system login at all keeps the legacy contract",
			src:          `system { host-name fw; }`,
			wantSet:      false,
			wantDropped:  false,
			wantNilLogin: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree, perrs := config.NewParser(tc.src).Parse()
			if len(perrs) != 0 {
				t.Fatalf("parse %q: %v", tc.src, perrs)
			}
			// The LENIENT compiler is what Store.Load and Store.SyncApply run;
			// the strict one rejects the packed rows before they can reach the
			// daemon at all, so driving strict here would test nothing.
			cfg, err := config.CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("lenient compile %q: %v", tc.src, err)
			}
			if got := cfg.System.Login == nil; got != tc.wantNilLogin {
				t.Fatalf("System.Login == nil is %v, want %v — the fixture no longer "+
					"reproduces the shape this row is about", got, tc.wantNilLogin)
			}
			if got := cfg.System.LoginDroppedByPacking; got != tc.wantDropped {
				t.Fatalf("LoginDroppedByPacking = %v, want %v for %q", got, tc.wantDropped, tc.src)
			}

			p := &recordingUserClassSetter6706{}
			applyCLILoginClass(p, cfg, osident.Identity{UID: 1000, Name: "alice"})
			if p.called != tc.wantSet {
				t.Fatalf("SetUserClass called = %v, want %v for %q — an unset class is "+
					"pkg/cli's ALLOW-EVERYTHING mode, so calling it or not IS the "+
					"authorization decision", p.called, tc.wantSet, tc.src)
			}
			if tc.wantSet && p.class != tc.wantClass {
				t.Fatalf("SetUserClass(%q), want %q for %q", p.class, tc.wantClass, tc.src)
			}
		})
	}
}

// TestApplyCLILoginClass6706DroppedLoginKeepsRootLifeline pins the other half of
// the posture: failing closed on a dropped login must not lock the console out.
// uid 0 takes the root default exactly as it does under the nested spelling of
// the same text, so the fix cannot brick a box whose config was mis-authored.
func TestApplyCLILoginClass6706DroppedLoginKeepsRootLifeline(t *testing.T) {
	tree, perrs := config.NewParser(`system login user alice class ops;`).Parse()
	if len(perrs) != 0 {
		t.Fatalf("parse: %v", perrs)
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	p := &recordingUserClassSetter6706{}
	applyCLILoginClass(p, cfg, osident.Identity{UID: 0, Name: "root"})
	if !p.called {
		t.Fatal("SetUserClass not called for uid 0 on a dropped login")
	}
	if p.class != "super-user" {
		t.Fatalf("uid 0 got class %q, want super-user — failing closed on a dropped "+
			"`system login` must not take the console lifeline with it", p.class)
	}
}

type recordingUserClassSetter6706 struct {
	called bool
	class  string
}

func (r *recordingUserClassSetter6706) SetUserClass(c string) { r.called = true; r.class = c }
