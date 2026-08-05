package config

import (
	"strings"
	"testing"
)

// #5831 — a custom `system login class` may carry deny-commands /
// deny-configuration, which xpf's coarse RBAC gate does not enforce. Before
// this gate such a config committed cleanly and enforced nothing: the operator
// held a config saying a verb was denied and a box on which it was allowed.
//
// These tests pin the fail-closed half: strict commit REJECTS; the tolerant
// load / peer-sync path folds the class down to the REPAIR FLOOR ({view,
// configure} intersected with what it already held — see
// TestLoginClassDenyFoldKeepsTheRepairPath for why it stops there and not at
// view-only); and neither over-reaches onto the additive allow-* half or onto
// ordinary classes.

// buildLoginTree5831 builds a ConfigTree from flat `set` lines. It uses
// ParseSetCommand + SetPath and NEVER NewParser: the parser treats newlines as
// whitespace and would merge every line into one node, silently invalidating
// the test.
func buildLoginTree5831(t *testing.T, cmds []string) *ConfigTree {
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

// TestLoginClassDenyRejectedAtCommit is the core RED-on-revert guard: every
// restrictive-regex spelling must be REFUSED by the strict commit path.
//
// The `quoted-empty` and `valueless` cases are the ones a value-based gate
// (`lc.DenyCommands != ""`) would wave through — both flatten to the empty
// string, indistinguishable from an absent leaf, yet an empty POSIX regex
// matches every command, i.e. denies EVERYTHING. They are the edge where a
// guard scoped to "non-empty deny regex" would be narrower than the claim
// "a restriction is never accepted as inert".
func TestLoginClassDenyRejectedAtCommit(t *testing.T) {
	for _, tc := range []struct {
		name string
		line string
		want string
	}{
		{"deny-commands", `set system login class limited deny-commands "request system zeroize"`, "deny-commands"},
		{"deny-configuration", `set system login class limited deny-configuration "security policies"`, "deny-configuration"},
		{"deny-commands quoted-empty", `set system login class limited deny-commands ""`, "deny-commands"},
		{"deny-configuration quoted-empty", `set system login class limited deny-configuration ""`, "deny-configuration"},
		{"deny-commands valueless", `set system login class limited deny-commands`, "deny-commands"},
		{"deny-configuration valueless", `set system login class limited deny-configuration`, "deny-configuration"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildLoginTree5831(t, []string{
				"set system login class limited permissions all",
				tc.line,
				"set system login user carol class limited",
			})
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("commit ACCEPTED a class carrying %s; xpf does not enforce it, "+
					"so the restriction would be inert and the class MORE permissive than the config states", tc.want)
			}
			if !strings.Contains(err.Error(), "limited") || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("rejection must name the class and the offending leaf; got %q", err)
			}
		})
	}
}

// TestLoginClassDenyRejectedHierarchicalShape pins the SECOND parser AST shape.
// The flat `set` form lands the regex on a child node; the hierarchical block
// form lands it on the leaf's own Keys. A gate that reads only one shape sees
// only one spelling — the defect class currently open as #6817/#6818 — so the
// hierarchical spelling must be rejected too.
func TestLoginClassDenyRejectedHierarchicalShape(t *testing.T) {
	src := `
system {
    login {
        class limited {
            permissions [ view ];
            deny-commands "request system zeroize";
        }
    }
}
`
	p := NewParser(src)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	// Guard the guard: if the hierarchical parse did not actually populate the
	// leaf, this test would "pass" against a gate that never ran.
	cfgLenient, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	if len(cfgLenient.System.Login.Classes) != 1 ||
		len(cfgLenient.System.Login.Classes[0].DenyLeavesPresent) != 1 {
		t.Fatalf("hierarchical shape did not record the deny leaf; classes=%+v",
			cfgLenient.System.Login.Classes)
	}

	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("hierarchical `deny-commands` inside a class block was ACCEPTED at commit")
	}
}

// TestLoginClassValidStillCommits is the POSITIVE CONTROL. Without it the
// rejection tests above cannot distinguish "rejects the bad config" from
// "rejects everything".
//
// It also pins the DIRECTIONALITY finding: allow-commands / allow-configuration
// are ADDITIVE in Junos (they grant access beyond the permission bits), so
// ignoring them yields a SUBSET of what the operator wrote — fail-closed. They
// must keep committing with the #4304 advisory. Rejecting them would break
// configs that are already safe.
func TestLoginClassValidStillCommits(t *testing.T) {
	for _, tc := range []struct {
		name  string
		lines []string
	}{
		{"plain class", []string{
			"set system login class limited permissions view",
		}},
		{"permissions all", []string{
			"set system login class limited permissions all",
		}},
		{"allow-commands (additive, fail-closed when ignored)", []string{
			"set system login class limited permissions view",
			`set system login class limited allow-commands "show interfaces"`,
		}},
		{"allow-configuration (additive, fail-closed when ignored)", []string{
			"set system login class limited permissions view",
			`set system login class limited allow-configuration "interfaces"`,
		}},
		{"both allow leaves plus idle-timeout", []string{
			"set system login class limited permissions clear",
			`set system login class limited allow-commands "show interfaces"`,
			`set system login class limited allow-configuration "interfaces"`,
			"set system login class limited idle-timeout 30",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lines := append([]string{}, tc.lines...)
			lines = append(lines, "set system login user carol class limited")
			cfg, err := CompileConfig(buildLoginTree5831(t, lines))
			if err != nil {
				t.Fatalf("a class with no restrictive regex must still commit; got %v", err)
			}
			if cfg.System.Login == nil || len(cfg.System.Login.Classes) != 1 {
				t.Fatalf("expected the class to survive the commit; got %+v", cfg.System.Login)
			}
		})
	}
}

// TestLoginClassDenyToleratedButFolded pins the tolerant load / peer-sync
// behavior. #1960 says an already-persisted or peer-synced config must still
// BOOT, so the strict rejection cannot simply be re-run here.
//
// But a bare warning would leave the runtime fail-open exactly where it
// started. So the tolerant path resolves the un-enforceable restriction in the
// RESTRICTIVE direction: `permissions all` + an unenforceable deny must NOT
// keep PermAll, and must lose every operational-verb bucket the deny could
// have targeted (clear / control / maintenance). What it keeps is the repair
// floor — see TestLoginClassDenyFoldKeepsTheRepairPath.
func TestLoginClassDenyToleratedButFolded(t *testing.T) {
	tree := buildLoginTree5831(t, []string{
		"set system login class limited permissions all",
		`set system login class limited deny-commands "request system zeroize"`,
		"set system login user carol class limited",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant path must not brick an already-persisted config: %v", err)
	}
	if len(cfg.System.Login.Classes) != 1 {
		t.Fatalf("expected 1 class; got %+v", cfg.System.Login.Classes)
	}
	lc := cfg.System.Login.Classes[0]

	// Every bucket that would let this class run `request system zeroize` — the
	// exact verb the config says is denied — must be gone. PermAll matches any
	// required permission, so it alone would re-open the hole.
	for _, banned := range []LoginClassPermission{PermAll, PermMaint, PermControl, PermClear} {
		for _, p := range lc.MappedPermissions {
			if p == banned {
				t.Fatalf("class kept %s despite an unenforceable deny-commands: %v — "+
					"the persisted-config path preserved the fail-open the strict gate rejects",
					loginClassPermName(banned), lc.MappedPermissions)
			}
		}
	}

	var found string
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "limited") && strings.Contains(w, "deny-commands") {
			found = w
		}
	}
	if found == "" {
		t.Fatalf("tolerant path must warn about the unenforced restriction; warnings=%v", cfg.Warnings)
	}
	// The old #4304 advisory said such a class was "MORE PERMISSIVE". After the
	// fold that is the exact opposite of what happened, so no warning may still
	// claim it.
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "limited") && strings.Contains(w, "MORE PERMISSIVE") {
			t.Fatalf("warning still claims the folded class is MORE PERMISSIVE: %q", w)
		}
	}
}

// TestLoginClassDenyFoldNeverWidens pins the non-widening property of the fold
// directly. A class granting NOTHING must not be handed view or configure
// access by the fold — returning a literal {PermView, PermConfig} would do
// exactly that, turning a restriction gate into a privilege GRANT. This is the
// edge that keeps the repair floor from becoming a floor for classes that were
// never above it.
func TestLoginClassDenyFoldNeverWidens(t *testing.T) {
	t.Run("empty permission set stays empty", func(t *testing.T) {
		if got := repairableFloorFold(nil); len(got) != 0 {
			t.Fatalf("fold GRANTED %v to a class that had no permissions at all", got)
		}
		if got := repairableFloorFold([]LoginClassPermission{}); len(got) != 0 {
			t.Fatalf("fold GRANTED %v to a class that had no permissions at all", got)
		}
	})
	t.Run("a set below the floor is not raised to it", func(t *testing.T) {
		// clear/control/maintenance only: the class never held view or
		// configure, so the fold must hand back neither. A literal-return fold
		// would GRANT both.
		got := repairableFloorFold([]LoginClassPermission{PermClear, PermControl, PermMaint})
		if len(got) != 0 {
			t.Fatalf("fold GRANTED %v to a class holding neither view nor configure", got)
		}
	})
	t.Run("view without configure stays view-only", func(t *testing.T) {
		got := repairableFloorFold([]LoginClassPermission{PermView, PermClear})
		if len(got) != 1 || got[0] != PermView {
			t.Fatalf("fold GRANTED configure to a view+clear class; got %v", got)
		}
	})
	t.Run("PermAll reduces to the floor", func(t *testing.T) {
		// PermAll subsumes both floor buckets (checkPermission returns nil on
		// PermAll for every required permission), so all -> {view,configure} is
		// a strict reduction, not a widening.
		got := repairableFloorFold([]LoginClassPermission{PermAll})
		if len(got) != 2 || got[0] != PermView || got[1] != PermConfig {
			t.Fatalf("all should reduce to {view,configure}; got %v", got)
		}
	})
	t.Run("everything above the floor is dropped", func(t *testing.T) {
		got := repairableFloorFold([]LoginClassPermission{PermView, PermClear, PermControl, PermConfig, PermMaint})
		if len(got) != 2 || got[0] != PermView || got[1] != PermConfig {
			t.Fatalf("expected {view,configure}; got %v", got)
		}
	})

	// End-to-end. NOTE the token choice: `permissions unauthorized` does NOT
	// produce an empty set — mapJunosPermissions folds it to the PermView floor
	// like every other recognized-but-unmappable token. A class with NO
	// `permissions` statement at all is the only shape that maps to the truly
	// empty set, so that is the one that exercises the widening edge.
	tree := buildLoginTree5831(t, []string{
		`set system login class nobody deny-commands "request system zeroize"`,
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	lc := cfg.System.Login.Classes[0]
	if len(lc.DenyLeavesPresent) == 0 {
		t.Fatal("precondition: the deny leaf was not recorded, so the fold never ran")
	}
	if got := lc.MappedPermissions; len(got) != 0 {
		t.Fatalf("tolerant fold GRANTED %v to a class that held no permissions at all", got)
	}
}

// TestLoginClassDenyFoldKeepsTheRepairPath is the counter-example to
// "the fold cannot lock an operator out".
//
// pkg/daemon/daemon_run.go assigns the CONFIGURED login class to any OS user
// whose name matches a `system login user` entry, and `root` is a name the
// username validator accepts (account PROVISIONING skips root; the CLI class
// assignment does not). So the config below binds the CONSOLE operator to a
// custom class. If the tolerant fold collapsed that class to view-only, the
// only login that can delete the offending statement would lose `configure` —
// while validateLoginClassDenyStrict rejects every commit until it IS deleted.
// Recovery would need an out-of-band shell.
//
// "resolveClassPerms consults the built-ins first" does not rescue this: that
// only decides which table answers for a class NAME, not that any login is
// bound to a built-in.
//
// Note what the operator wrote: `permissions [view configure]` plus
// `deny-configuration` means "configure everything EXCEPT security policies".
// Removing ALL configure is more restrictive than they asked for, in the one
// direction that is unrecoverable.
func TestLoginClassDenyFoldKeepsTheRepairPath(t *testing.T) {
	for _, tc := range []struct {
		name  string
		lines []string
		want  []LoginClassPermission
	}{
		{
			// The reviewer's example, verbatim.
			name: "configured root, view+configure, deny-configuration",
			lines: []string{
				"set system login class noc-admin permissions [ view configure ]",
				`set system login class noc-admin deny-configuration "security policies"`,
				"set system login user root class noc-admin",
			},
			want: []LoginClassPermission{PermView, PermConfig},
		},
		{
			// A configure-only class folds to the EMPTY set under a view-only
			// collapse — strictly worse than the case above, because the
			// operator cannot even read the config to find the statement.
			name: "configure-only class must not fold to nothing",
			lines: []string{
				"set system login class cfg-only permissions configure",
				`set system login class cfg-only deny-configuration "security policies"`,
				"set system login user root class cfg-only",
			},
			want: []LoginClassPermission{PermConfig},
		},
		{
			// `permissions all` keeps the repair floor too — and only that.
			name: "permissions all folds down to the floor, not past it",
			lines: []string{
				"set system login class su-ish permissions all",
				`set system login class su-ish deny-commands "request system zeroize"`,
				"set system login user root class su-ish",
			},
			want: []LoginClassPermission{PermView, PermConfig},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfigLenient(buildLoginTree5831(t, tc.lines))
			if err != nil {
				t.Fatalf("tolerant path must not brick an already-persisted config: %v", err)
			}
			lc := cfg.System.Login.Classes[0]
			if len(lc.DenyLeavesPresent) == 0 {
				t.Fatal("precondition: the deny leaf was not recorded, so the fold never ran")
			}
			// Guard the guard: the user->class binding that makes this a
			// LOCKOUT rather than a mere downgrade must actually be in the
			// compiled config.
			var bound bool
			for _, u := range cfg.System.Login.Users {
				if u.Name == "root" && u.Class == lc.Name {
					bound = true
				}
			}
			if !bound {
				t.Fatalf("precondition: `user root class %s` did not compile; users=%+v",
					lc.Name, cfg.System.Login.Users)
			}

			hasConfig := false
			for _, p := range lc.MappedPermissions {
				if p == PermConfig {
					hasConfig = true
				}
			}
			if !hasConfig {
				t.Fatalf("fold STRANDED the box: class %q held `configure` before the fold and "+
					"lost it (%v), but root is bound to that class and every commit is rejected "+
					"until the statement is deleted — there is no in-band way to delete it",
					lc.Name, lc.MappedPermissions)
			}
			if len(lc.MappedPermissions) != len(tc.want) {
				t.Fatalf("expected %v; got %v", tc.want, lc.MappedPermissions)
			}
			for i, p := range tc.want {
				if lc.MappedPermissions[i] != p {
					t.Fatalf("expected %v; got %v", tc.want, lc.MappedPermissions)
				}
			}
		})
	}
}

// TestLoginClassDenyFoldWarningStatesTheRecoveryPath pins the operator-facing
// text. The fold deliberately leaves `deny-configuration` UNENFORCED (xpf's
// coarse model has only all-or-nothing configuration, and "nothing" strands
// repair), so the warning must not imply the restriction is now in force, and
// it must name the way out. A warning that only says "folded" would leave an
// operator believing the deny took effect.
func TestLoginClassDenyFoldWarningStatesTheRecoveryPath(t *testing.T) {
	cfg, err := CompileConfigLenient(buildLoginTree5831(t, []string{
		"set system login class noc-admin permissions [ view configure ]",
		`set system login class noc-admin deny-configuration "security policies"`,
		"set system login user root class noc-admin",
	}))
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	var w string
	for _, cand := range cfg.Warnings {
		if strings.Contains(cand, "noc-admin") && strings.Contains(cand, "deny-configuration") {
			w = cand
		}
	}
	if w == "" {
		t.Fatalf("tolerant path must warn about the unenforced restriction; warnings=%v", cfg.Warnings)
	}
	// The post-fold set, so the operator can see what the class actually holds.
	if !strings.Contains(w, "configure") {
		t.Fatalf("warning does not name the retained `configure` permission: %q", w)
	}
	// The honest limit: the restriction is still not in force for config.
	if !strings.Contains(w, "NOT in force") {
		t.Fatalf("warning implies the restriction took effect; it did not for configuration: %q", w)
	}
	// The forcing function, so the operator knows repair is mandatory.
	if !strings.Contains(w, "every commit is rejected") {
		t.Fatalf("warning does not tell the operator that commits stay blocked until repair: %q", w)
	}
}

// TestLoginClassDenyGateIsScopedToRestrictiveLeaves proves the gate does not
// fire on the additive half even on the tolerant path — an allow-only class
// must keep its permissions untouched. A gate that folded every class carrying
// any of the four regexes would be scoped WIDER than its claim and would
// silently strip access the operator legitimately granted.
func TestLoginClassDenyGateIsScopedToRestrictiveLeaves(t *testing.T) {
	tree := buildLoginTree5831(t, []string{
		"set system login class helper permissions all",
		`set system login class helper allow-commands "show interfaces"`,
		`set system login class helper allow-configuration "interfaces"`,
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	lc := cfg.System.Login.Classes[0]
	if len(lc.DenyLeavesPresent) != 0 {
		t.Fatalf("allow-* leaves must not be recorded as restrictive; got %v", lc.DenyLeavesPresent)
	}
	found := false
	for _, p := range lc.MappedPermissions {
		if p == PermAll {
			found = true
		}
	}
	if !found {
		t.Fatalf("an allow-only class must keep its permissions; got %v", lc.MappedPermissions)
	}
}

// TestLoginClassDenyPresenceSurvivesEmptyValue is the unit-level statement of
// the quoted-empty edge: presence must be recorded even when the value is
// empty, because that is precisely the case a value test cannot see.
func TestLoginClassDenyPresenceSurvivesEmptyValue(t *testing.T) {
	tree := buildLoginTree5831(t, []string{
		"set system login class limited permissions view",
		`set system login class limited deny-commands ""`,
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	lc := cfg.System.Login.Classes[0]
	if lc.DenyCommands != "" {
		t.Fatalf("precondition: expected the quoted-empty regex to flatten to \"\"; got %q", lc.DenyCommands)
	}
	if len(lc.DenyLeavesPresent) != 1 || lc.DenyLeavesPresent[0] != "deny-commands" {
		t.Fatalf("presence of a quoted-empty deny-commands was LOST — a value-based gate "+
			"would accept the most restrictive regex an operator can write; got %v", lc.DenyLeavesPresent)
	}
}
