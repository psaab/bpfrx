package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #5831 — RUNTIME half of the repair-floor property.
//
// The compiler-side tests (pkg/config/login_class_deny_5831_test.go) pin the
// folded MappedPermissions. This file pins what actually matters to an
// operator standing at the console: that the folded class still passes the
// RBAC gate for `configure`, resolved through the real
// resolveClassPerms -> checkPermission path against a real store.

// syncedLoginConfig is the previously-accepted config that motivated the
// repair floor. Before #5831 the deny leaf was inert, so this committed
// cleanly and `noc-admin` held view + configure.
//
// pkg/daemon/daemon_run.go assigns the CONFIGURED class to any OS user whose
// name matches a `system login user` (`if u.Name == osUser {
// shell.SetUserClass(u.Class) }`). Account provisioning skips root; that
// assignment does not. So `user root class noc-admin` binds the CONSOLE
// operator to a custom class, and whatever the fold leaves that class holding
// is the total access available to repair the box.
const syncedLoginConfig = `
system {
    login {
        class noc-admin {
            permissions [ view configure ];
            deny-configuration "security policies";
        }
        user root {
            class noc-admin;
        }
    }
}
`

// TestFoldedLoginClassCanStillReachConfigure proves the tolerant fold leaves an
// in-band recovery path.
//
// Store.SyncApply is the HA peer-sync ingress — a config pushed by a primary
// running older code — and it compiles through compileTreeLenient, the same
// tolerant path Store.Load uses when booting from a persisted DB. Both are
// configs the local operator did NOT just author, which is exactly when the
// strict rejection is downgraded to the fold.
//
// Reverting the fold to a view-only collapse makes the `configure` subtest fail
// with "permission denied", i.e. the box can no longer delete the statement
// that is blocking every commit.
func TestFoldedLoginClassCanStillReachConfigure(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if _, err := store.SyncApply(syncedLoginConfig, nil); err != nil {
		t.Fatalf("tolerant peer-sync must not reject a previously-accepted config (#1960): %v", err)
	}

	// Guard the guard: without the class AND the root binding in the active
	// config this test would pass against a gate that never ran.
	cfg := store.ActiveConfig()
	if cfg == nil || cfg.System.Login == nil || len(cfg.System.Login.Classes) != 1 {
		t.Fatalf("precondition: synced config did not produce the custom class; cfg=%+v", cfg)
	}
	lc := cfg.System.Login.Classes[0]
	if len(lc.DenyLeavesPresent) == 0 {
		t.Fatalf("precondition: the deny leaf was not recorded, so the fold never ran; class=%+v", lc)
	}
	var rootClass string
	for _, u := range cfg.System.Login.Users {
		if u.Name == "root" {
			rootClass = u.Class
		}
	}
	if rootClass != "noc-admin" {
		t.Fatalf("precondition: root is not bound to the folded class (got %q) — "+
			"without that binding this is a downgrade, not a lockout", rootClass)
	}

	c := &CLI{store: store, userClass: "noc-admin"}

	// THE recovery path. `configure` is the only way to reach `delete system
	// login class noc-admin deny-configuration`, and config mode applies no
	// further per-statement permission gate, so PermConfig is the whole
	// self-repair channel in xpf's coarse model.
	if err := c.checkPermission([]string{"configure"}); err != nil {
		t.Fatalf("STRANDED: the console class lost `configure` to the fold (%v). "+
			"Every commit is rejected while the deny statement is present, and "+
			"`configure` is the only way to remove it — recovery would need an "+
			"out-of-band shell. perms=%v", err, lc.MappedPermissions)
	}
	// Reading the config to FIND the offending statement is part of recovery.
	if err := c.checkPermission([]string{"show", "configuration"}); err != nil {
		t.Errorf("folded class cannot read its own config: %v", err)
	}

	// The fold must still have teeth: everything above the repair floor goes,
	// including the buckets that carry the destructive verbs.
	for _, parts := range [][]string{
		{"clear", "security"},
		{"request", "session"},
		{"request", "system", "zeroize"},
	} {
		if err := c.checkPermission(parts); err == nil {
			t.Errorf("%q ALLOWED after the fold — the fold kept a bucket above the repair floor",
				strings.Join(parts, " "))
		}
	}

	// A class folded off PermAll must also lose cleartext secret rendering.
	if !c.showConfigRedacted() {
		t.Error("folded class still reads cleartext secrets (retained PermAll)")
	}
}

// TestFoldedLoginClassDenyOnRetainedBucketIsANoOp documents the fold's LIMIT as
// a tested property rather than a comment (#6838 review).
//
// The floor retains {view, configure}. Both are reachable deny targets:
// `deny-configuration` aims at PermConfig, and a `deny-commands` naming
// `show`/`ping`/`traceroute`/`monitor` aims at PermView. A deny aimed at either
// is a COMPLETE no-op — the fold drops nothing that would stop it, and the
// coarse gate never reads the regex.
//
// This test asserts that no-op deliberately. It is not endorsing the gap: it
// pins the honest statement the warning now makes, so that if someone later
// believes they have closed it, this test forces them to prove it here rather
// than in prose. The real enforcement is validateLoginClassDenyStrict refusing
// the commit; per-command RBAC stays on #5831.
func TestFoldedLoginClassDenyOnRetainedBucketIsANoOp(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	const synced = `
system {
    login {
        class noc-admin {
            permissions [ view configure ];
            deny-commands "show interfaces";
        }
        user root {
            class noc-admin;
        }
    }
}
`
	if _, err := store.SyncApply(synced, nil); err != nil {
		t.Fatalf("tolerant peer-sync must not reject a previously-accepted config: %v", err)
	}
	cfg := store.ActiveConfig()
	if cfg == nil || cfg.System.Login == nil || len(cfg.System.Login.Classes) != 1 ||
		len(cfg.System.Login.Classes[0].DenyLeavesPresent) == 0 {
		t.Fatalf("precondition: the fold never ran; cfg=%+v", cfg)
	}

	c := &CLI{store: store, userClass: "noc-admin"}

	// The denied command itself. PermView is retained, so it runs.
	if err := c.checkPermission([]string{"show", "interfaces"}); err != nil {
		t.Fatalf("`show interfaces` denied after the fold (%v) — if this now fails, the "+
			"fold has started enforcing view-level denies and the operator warning "+
			"(loginClassDenyFoldWarning) must stop saying those levels are unrestricted", err)
	}
	// And the rest of the retained view bucket, so the claim is about the
	// LEVEL, not one lucky command string.
	for _, parts := range [][]string{{"ping", "10.0.0.1"}, {"traceroute", "10.0.0.1"}, {"monitor", "interface"}} {
		if err := c.checkPermission(parts); err != nil {
			t.Errorf("%q denied after the fold: %v — the warning claims the whole view "+
				"level is unrestricted", strings.Join(parts, " "), err)
		}
	}
	// `configure` likewise — the other retained bucket, and the repair channel.
	if err := c.checkPermission([]string{"configure"}); err != nil {
		t.Errorf("`configure` denied after the fold: %v", err)
	}
	// The control: a bucket the fold DROPS really is gone, so this class is not
	// simply unfolded.
	if err := c.checkPermission([]string{"request", "system", "zeroize"}); err == nil {
		t.Error("`request system zeroize` ALLOWED — the fold dropped nothing at all")
	}
}

// TestFoldedLoginClassBelowFloorIsNotRaised is the negative control for the
// test above: the repair floor is an intersection, not a grant. A class that
// never held `configure` must not be handed it by the fold — otherwise the
// "keep the recovery path" rule would become a privilege escalation for every
// class carrying a deny leaf.
func TestFoldedLoginClassBelowFloorIsNotRaised(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	const synced = `
system {
    login {
        class watcher {
            permissions [ view clear ];
            deny-commands "clear security";
        }
        user root {
            class watcher;
        }
    }
}
`
	if _, err := store.SyncApply(synced, nil); err != nil {
		t.Fatalf("tolerant peer-sync must not reject a previously-accepted config: %v", err)
	}
	cfg := store.ActiveConfig()
	if cfg == nil || cfg.System.Login == nil || len(cfg.System.Login.Classes) != 1 ||
		len(cfg.System.Login.Classes[0].DenyLeavesPresent) == 0 {
		t.Fatalf("precondition: the fold never ran; cfg=%+v", cfg)
	}

	c := &CLI{store: store, userClass: "watcher"}
	if err := c.checkPermission([]string{"configure"}); err == nil {
		t.Fatalf("PRIV-ESC: the fold GRANTED `configure` to a class that never held it; perms=%v",
			cfg.System.Login.Classes[0].MappedPermissions)
	}
	// View is retained (the class held it), so this is a fold, not a lockout.
	if err := c.checkPermission([]string{"show", "version"}); err != nil {
		t.Errorf("view-holding class lost `show`: %v", err)
	}
	// And `clear` — the bucket the deny targeted — is gone.
	if err := c.checkPermission([]string{"clear", "security"}); err == nil {
		t.Error("`clear` survived the fold despite an unenforceable deny-commands")
	}
}

// TestFoldedLoginClassEmptyStaysEmpty pins the third arm: a class holding
// NEITHER floor bucket folds to the empty set and stays locked out of
// everything. It is included so the floor cannot be re-read as "every folded
// class gets view+configure" — the fold is an intersection with what the class
// already held, in all three directions.
func TestFoldedLoginClassEmptyStaysEmpty(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	const synced = `
system {
    login {
        class nobody {
            deny-commands "request system zeroize";
        }
    }
}
`
	if _, err := store.SyncApply(synced, nil); err != nil {
		t.Fatalf("tolerant peer-sync must not reject a previously-accepted config: %v", err)
	}
	cfg := store.ActiveConfig()
	if cfg == nil || cfg.System.Login == nil || len(cfg.System.Login.Classes) != 1 {
		t.Fatalf("precondition: synced config did not produce the class; cfg=%+v", cfg)
	}
	if got := cfg.System.Login.Classes[0].MappedPermissions; len(got) != 0 {
		t.Fatalf("fold GRANTED %v to a class with no `permissions` statement at all", got)
	}
	c := &CLI{store: store, userClass: "nobody"}
	for _, parts := range [][]string{{"configure"}, {"show", "version"}} {
		if err := c.checkPermission(parts); err == nil {
			t.Errorf("%q ALLOWED for a class that holds nothing", strings.Join(parts, " "))
		}
	}
}

// TestFoldedLoginClassDuplicateNameIsNotFailOpen pins the fold against a config
// that spells the SAME class name twice (#6838 review B1).
//
// A duplicate name splits the class into two *LoginClass blocks, and the two
// sides of the system disagree about which one is "the" class: the fold used to
// pick the LAST via a name-keyed map, while pkg/cli's resolveClassPerms returns
// the FIRST match. Every combination of that disagreement was a measured
// runtime fail-open on the peer-sync path — PermAll live at the console,
// `request system zeroize` allowed, secrets rendered in cleartext, and an
// operator warning asserting a reduction that had not happened to the block the
// runtime reads.
//
// The property is deliberately stated WITHOUT reference to the tie-break rule:
// whichever block resolveClassPerms picks, it must be folded. That is why the
// production fix folds the whole same-named cohort instead of matching
// first-match — matching the reader's pick would be a proxy for the property
// and would rot silently the day the reader's pick changed.
//
// TWO INDEPENDENT REVERTS RED THIS TEST, one per subtest:
//
//   - restoring the name-keyed last-wins map reds `deny-on-first` (the fold
//     lands on the innocent second block);
//   - keeping pointer identity but folding ONLY the offending block reds
//     `deny-on-second` (correct by identity, useless in effect — the runtime
//     reads the first block, which never carried a deny leaf).
func TestFoldedLoginClassDuplicateNameIsNotFailOpen(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  string
	}{
		{
			// The offender is FIRST, so it is also the block the runtime
			// resolves. A last-wins map folds the other one.
			name: "deny-on-first",
			cfg: `
system {
    login {
        class limited {
            permissions all;
            deny-commands "request system zeroize";
        }
        class limited {
            permissions [ view configure ];
        }
        user root {
            class limited;
        }
    }
}
`,
		},
		{
			// The offender is SECOND. A last-wins map folds exactly the right
			// object — and the box still fails open, because the block the
			// runtime reads is the first one and it carries `permissions all`.
			name: "deny-on-second",
			cfg: `
system {
    login {
        class limited {
            permissions all;
        }
        class limited {
            permissions [ view configure ];
            deny-commands "request system zeroize";
        }
        user root {
            class limited;
        }
    }
}
`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
			if _, err := store.SyncApply(tc.cfg, nil); err != nil {
				t.Fatalf("tolerant peer-sync must not reject a previously-accepted config (#1960): %v", err)
			}

			// Guard the guard: two blocks under ONE name is the whole premise.
			// If the compiler ever merges them this test silently stops
			// testing anything, so assert the shape rather than assume it.
			cfg := store.ActiveConfig()
			if cfg == nil || cfg.System.Login == nil || len(cfg.System.Login.Classes) != 2 {
				t.Fatalf("precondition: want 2 `limited` blocks (the duplicate-name shape); cfg=%+v", cfg)
			}
			var denyBlocks int
			for _, lc := range cfg.System.Login.Classes {
				if lc.Name != "limited" {
					t.Fatalf("precondition: block named %q, want both named `limited`", lc.Name)
				}
				if len(lc.DenyLeavesPresent) > 0 {
					denyBlocks++
				}
			}
			if denyBlocks != 1 {
				t.Fatalf("precondition: want exactly 1 block carrying the deny leaf, got %d — "+
					"the arm under test is not the arm configured", denyBlocks)
			}

			c := &CLI{store: store, userClass: "limited"}

			// THE fail-open. `request system zeroize` is the exact verb
			// deny-commands names, and PermAll answers every requirement in
			// checkPermission.
			if err := c.checkPermission([]string{"request", "system", "zeroize"}); err == nil {
				perms, _ := c.resolveClassPerms("limited")
				t.Errorf("FAIL-OPEN: `request system zeroize` ALLOWED — the block the runtime "+
					"resolves was never folded. resolveClassPerms=%v", perms)
			}
			// PermAll is also what turns off secret redaction, so a class that
			// kept it leaks IKE PSKs / SNMP communities / auth-keys to a login
			// the operator wrote a deny statement for.
			if !c.showConfigRedacted() {
				t.Error("FAIL-OPEN: secrets render in cleartext — the resolved block retained PermAll")
			}

			// The fold is a fold, not a lockout: the repair path survives on
			// whichever block answers.
			if err := c.checkPermission([]string{"configure"}); err != nil {
				t.Errorf("STRANDED: the folded class lost `configure` (%v) — every commit is "+
					"rejected while the deny statement is present and this is the only way "+
					"to remove it", err)
			}

			// And the warning must describe what actually happened. Before the
			// fix it named a reduction the resolved block never underwent.
			var foldWarn string
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "deny-commands is NOT enforced") {
					foldWarn = w
				}
			}
			if foldWarn == "" {
				t.Fatalf("no fold warning at all; warnings=%v", cfg.Warnings)
			}
			if !strings.Contains(foldWarn, "super-user") {
				t.Errorf("the fold warning does not mention losing super-user, but one of the "+
					"blocks under this name held `permissions all` — the operator is told less "+
					"than the fold did:\n  %s", foldWarn)
			}
		})
	}
}

// TestFoldedClassResolvesThroughCustomTableNotBuiltins guards the assumption
// the pre-fold code leaned on. resolveClassPerms consults the BUILT-IN table
// first, which was cited as proof the fold "cannot brick the box". It does not
// prove that: built-ins-first only decides which table answers for a class
// NAME. A user bound to a custom name is answered by the custom table, folded
// permissions and all, and never touches the built-ins.
func TestFoldedClassResolvesThroughCustomTableNotBuiltins(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if _, err := store.SyncApply(syncedLoginConfig, nil); err != nil {
		t.Fatalf("SyncApply: %v", err)
	}
	c := &CLI{store: store, userClass: "noc-admin"}

	perms, ok := c.resolveClassPerms("noc-admin")
	if !ok {
		t.Fatal("custom class did not resolve at all")
	}
	if _, isBuiltin := config.LoginClassPermissions["noc-admin"]; isBuiltin {
		t.Fatal("precondition: `noc-admin` must NOT be a built-in for this test to mean anything")
	}
	for _, p := range perms {
		if p == config.PermAll {
			t.Fatalf("custom class resolved to PermAll — it was answered by the "+
				"super-user built-in rather than the folded custom entry; perms=%v", perms)
		}
	}
}
