package cli

import (
	"os"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #7172 cut 4 — deny-configuration on the config-mutation path.
//
// Guards, each with its firing input AND the cheapest edit that would defeat it
// while looking correct (the addition after cut 3's wiring guard escaped its own
// mutation by matching a bare symbol):
//
//	edit-path resolution   fires: `edit system` + `set root-authentication ...`
//	                       defeated by: matching parts[1:] instead of the join
//	navigation not gated   fires: `edit system` under a deny
//	                       defeated by: adding "edit" to configMutationVerbs
//	unrestricted scoping   fires: any class with no deny-configuration
//	                       defeated by: dropping the !ok early return
//	compile failure denies fires: a class with "([unclosed"
//	                       defeated by: `return nil` in the err arm
//	the wiring             fires: any denied mutation through dispatchConfig
//	                       defeated by: `_ = c.checkConfigRegex` -- so the guard
//	                       matches the CALL FORM, not the symbol

func denyConfigCfg(t *testing.T, pattern string) *config.Config {
	t.Helper()
	cfg := &config.Config{}
	cfg.System.Login = &config.LoginConfig{
		Classes: []*config.LoginClass{{
			Name:               "ops",
			DenyConfiguration:  pattern,
			AllowConfiguration: "system host-name",
			DenyLeavesPresent:  []string{"deny-configuration"},
		}},
	}
	return cfg
}

// THE CENTREPIECE. Hierarchical `edit` makes the typed line a fragment, and
// matching the fragment is a bypass an operator hits by working normally.
func TestEditPathIsResolvedBeforeMatching7172(t *testing.T) {
	cfg := denyConfigCfg(t, "system root-authentication")

	// Typed at the top level: the deny matches the line as written.
	if err := checkConfigRegexWith(cfg, "ops", nil,
		"set system root-authentication plain-text-password hunter2"); err == nil {
		t.Fatal("a full-path set matching deny-configuration must be refused")
	}

	// THE MIDDLE ROW: the same mutation reached by navigating first. The typed
	// remainder is `set root-authentication ...`, which does NOT match the deny
	// on its own — only the resolved path does. A gate matching parts[1:] passes
	// the case above and fails this one, which is why the pair is needed.
	err := checkConfigRegexWith(cfg, "ops", []string{"system"},
		"set root-authentication plain-text-password hunter2")
	if err == nil {
		t.Fatal("`edit system` followed by `set root-authentication ...` walked past a deny " +
			"on `system root-authentication`. The gate must match the RESOLVED path " +
			"(edit path + typed remainder), not the fragment the operator typed — " +
			"navigating with `edit` is the ordinary way to work, so this is the bypass " +
			"an operator finds without trying.")
	}

	// And the deny must not over-reach: an unrelated path under the same edit
	// path is still permitted.
	if err := checkConfigRegexWith(cfg, "ops", []string{"system"},
		"set host-name lab1"); err != nil {
		t.Errorf("`edit system` + `set host-name` does not match the deny and must be "+
			"allowed: %v", err)
	}
}

// Navigation is not a mutation and must not be gated.
func TestNavigationVerbsAreNotGated7172(t *testing.T) {
	cfg := denyConfigCfg(t, "system")
	for _, line := range []string{"edit system", "top", "up", "show", "commit", "rollback"} {
		if err := checkConfigRegexWith(cfg, "ops", nil, line); err != nil {
			t.Errorf("%q must not be gated by deny-configuration: %v", line, err)
		}
	}
}

// Every mutating verb is covered, not just `set`. Nine verbs share one gate
// precisely so they cannot drift apart.
func TestEveryMutatingVerbIsGated7172(t *testing.T) {
	cfg := denyConfigCfg(t, "system root-authentication")
	for _, line := range []string{
		"set system root-authentication plain-text-password x",
		"delete system root-authentication",
		"deactivate system root-authentication",
		"activate system root-authentication",
		"annotate system root-authentication note",
		"insert system root-authentication before x",
	} {
		if err := checkConfigRegexWith(cfg, "ops", nil, line); err == nil {
			t.Errorf("%q reached the store despite a matching deny-configuration", line)
		}
	}
}

// SCOPING: a class with no deny-configuration is untouched, and the empty-class
// legacy bypass is unchanged.
func TestUnrestrictedConfigClassIsUnaffected7172(t *testing.T) {
	plain := &config.Config{}
	plain.System.Login = &config.LoginConfig{
		Classes: []*config.LoginClass{{Name: "ops"}},
	}
	if err := checkConfigRegexWith(plain, "ops", nil, "set system host-name lab1"); err != nil {
		t.Errorf("a class with no deny-configuration must not be gated: %v", err)
	}
	if err := checkConfigRegexWith(denyConfigCfg(t, "system"), "", nil,
		"set system host-name lab1"); err != nil {
		t.Errorf("the empty-class legacy path must be unchanged: %v", err)
	}
}

// FAIL-CLOSED on an uncompilable regex.
func TestUncompilableConfigRegexDenies7172(t *testing.T) {
	cfg := denyConfigCfg(t, "([unclosed")
	err := checkConfigRegexWith(cfg, "ops", nil, "set system host-name lab1")
	if err == nil {
		t.Fatal("a class whose deny-configuration does not compile must DENY; skipping " +
			"leaves it unrestricted, the fail-open direction")
	}
	if !strings.Contains(err.Error(), "invalid configuration regex") {
		t.Errorf("the refusal must say why: %v", err)
	}
}

// ALLOW IS NOT ENFORCED IN THIS CUT — same reason as cut 3. The fixture carries
// `allow-configuration "system host-name"`; if it were enforced as an allowlist,
// an unrelated path would be denied.
func TestAllowConfigurationIsNotEnforcedInCut4_7172(t *testing.T) {
	cfg := denyConfigCfg(t, "system root-authentication")
	if err := checkConfigRegexWith(cfg, "ops", nil, "set interfaces ge-0/0/0 unit 0"); err != nil {
		t.Errorf("allow-configuration must NOT be enforced in cut 4 — a live class would "+
			"abruptly lose every path outside its allow pattern, a restriction its author "+
			"was told was inert: %v", err)
	}
}

// AUDIT must not leak the value. A config path carries secrets IN THE PATH.
func TestConfigDenialAuditDoesNotLeakTheValue7172(t *testing.T) {
	cfg := denyConfigCfg(t, "system root-authentication")
	err := checkConfigRegexWith(cfg, "ops", nil,
		"set system root-authentication plain-text-password hunter2")
	if err == nil {
		t.Fatal("expected a denial")
	}
	if strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("the audit line leaked the secret. A config path carries operator data in "+
			"the path itself, so only the verb and the leading element may be rendered: %v",
			err)
	}
	if !strings.Contains(err.Error(), "system") || !strings.Contains(err.Error(), "set") {
		t.Errorf("the audit line must still say WHICH verb and WHICH tree: %v", err)
	}
}

// THE WIRING. Every cell above drives the gate directly, so a disconnected gate
// is invisible to all of them. Matches the CALL FORM rather than the symbol,
// because `_ = c.checkConfigRegex` keeps the name while removing the call —
// that exact mutation defeated cut 3's first wiring guard.
func TestDispatchConfigCallsTheConfigGate7172(t *testing.T) {
	src, err := os.ReadFile("cli_dispatch.go")
	if err != nil {
		t.Fatalf("read cli_dispatch.go: %v", err)
	}
	code := stripGoCommentsForGuard(string(src))
	i := strings.Index(code, "func (c *CLI) dispatchConfig(")
	if i < 0 {
		t.Fatal("dispatchConfig not found")
	}
	rest := code[i:]
	if j := strings.Index(rest, "\nfunc "); j > 0 {
		rest = rest[:j]
	}
	if !strings.Contains(rest, "c.checkConfigRegex(line)") {
		t.Fatal("dispatchConfig no longer CALLS checkConfigRegex(line). Every unit cell in " +
			"this file drives the gate directly and stays green, so nothing else catches " +
			"a disconnected gate. Matching the bare symbol is not enough: " +
			"`_ = c.checkConfigRegex` keeps the name and removes the call.")
	}
	// It must run BEFORE the verb switch, or the first verbs dispatch ungated.
	gate := strings.Index(rest, "c.checkConfigRegex(line)")
	sw := strings.Index(rest, "switch parts[0]")
	if sw >= 0 && gate > sw {
		t.Error("the gate runs AFTER the verb switch, so every case returns before it is " +
			"reached")
	}
}
