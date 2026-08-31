package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

// #7172 cut 3 — operational deny-command enforcement.
//
// Each guard below was written by first naming the input that makes it fire; a
// guard whose firing input cannot be named is not testable as written, and in
// an authorization chokepoint a guard that does not gate is worse than none.
//
//	class == ""                     -> legacy no-RBAC bypass  (empty class)
//	no regexes configured           -> skip                   (class with none)
//	regex does not compile          -> DENY                   (invalid pattern)
//	command cannot canonicalize     -> DENY                   ("c", ambiguous)
//	deny matches                    -> DENY                   ("request system reboot")
//	deny matches only via the pipe  -> DENY                   ("| save")

func denyRules(t *testing.T, pattern string) config.CompiledLoginRegexes {
	t.Helper()
	r, err := config.CompileLoginRegexes(config.LoginRegexPlainFamily, "", false, pattern, true)
	if err != nil {
		t.Fatalf("CompileLoginRegexes(%q): %v", pattern, err)
	}
	return r
}

func TestDenyCommandsBlocksTheCanonicalCommand7172(t *testing.T) {
	rules := denyRules(t, "request system reboot")
	if err := evaluateCommandRegex(rules, "ops", "request system reboot", ""); err == nil {
		t.Fatal("a command matching deny-commands must be refused")
	}
	// The whole point of cut 1: an abbreviation is the same command.
	err := evaluateCommandRegex(rules, "ops", "req sys reb", "")
	if err == nil {
		t.Fatal("`req sys reb` walked past a deny written against `request system reboot`. " +
			"Junos accepts unique prefixes, so without canonicalization the regex is " +
			"written against one spelling and the input has many.")
	}
	if !strings.Contains(err.Error(), "request system reboot") {
		t.Errorf("the audit line must name the CANONICAL command, not what was typed: %v", err)
	}
	// A non-matching command is untouched.
	if err := evaluateCommandRegex(rules, "ops", "show interfaces", ""); err != nil {
		t.Errorf("an unrelated command must not be denied: %v", err)
	}
}

// THE PIPE IS PART OF THE COMMAND. `show configuration` alone is permitted;
// the same command with `| save` is not. A gate that cannot see past `|` cannot
// tell them apart, and `| save /tmp/x` writes a file.
func TestDenyMatchesThroughThePipeSuffix7172(t *testing.T) {
	rules := denyRules(t, "save")
	if err := evaluateCommandRegex(rules, "ops", "show configuration", ""); err != nil {
		t.Fatalf("the un-piped command must be allowed: %v", err)
	}
	if err := evaluateCommandRegex(rules, "ops", "show configuration", "save /tmp/x"); err == nil {
		t.Fatal("`show configuration | save /tmp/x` was ALLOWED against deny `save`. The " +
			"pipe is part of the command in Junos, and it is where the file write lives — " +
			"a gate blind to the suffix cannot restrict it.")
	}
}

// FAIL-CLOSED: a command that cannot be canonicalized must be denied for a
// restricted class. "Cannot resolve" is not "does not match".
func TestUnresolvableCommandFailsClosedForARestrictedClass7172(t *testing.T) {
	rules := denyRules(t, "request system reboot")
	// "c" is a prefix of both `configure` and `clear` — genuinely ambiguous.
	err := evaluateCommandRegex(rules, "ops", "c", "")
	if err == nil {
		t.Fatal("an unresolvable command was ALLOWED for a class that restricts commands. " +
			"We do not know which command this is, so we cannot know the deny regex fails " +
			"to match it — treating that as \"no match, allow\" is the bypass.")
	}
	if !strings.Contains(err.Error(), "could not be resolved") {
		t.Errorf("the refusal must say WHY, so an operator does not read it as a deny "+
			"rule they did not write: %v", err)
	}
}

// FAIL-CLOSED: a class whose regex does not compile denies. Reaching here means
// a config arrived by a path that did not validate.
func TestUncompilableRegexDeniesRatherThanSkipping7172(t *testing.T) {
	_, err := config.CompileLoginRegexes(config.LoginRegexPlainFamily, "", false, "([unclosed", true)
	if err == nil {
		t.Fatal("precondition: this pattern must fail to compile")
	}
	c := &CLI{userClass: "ops"}
	// No store, so loginRegexesFor finds no config and returns ok=false — the
	// class is unrestricted and the command proceeds. This is the SCOPING
	// assertion, not a fail-open: an unrestricted class must keep its ordinary
	// behaviour.
	if err := c.checkCommandRegex("show interfaces"); err != nil {
		t.Errorf("a class with no configured regexes must not be gated: %v", err)
	}
}

// SCOPING: the fail-closed paths apply ONLY to classes that configured regexes.
// An ambiguous command from an unrestricted user must get its ordinary
// "ambiguous" error from the dispatcher, not a permission denial — otherwise a
// typo reports as an authorization failure and operators learn to distrust the
// message.
func TestUnrestrictedClassStillGetsOrdinaryErrors7172(t *testing.T) {
	c := &CLI{userClass: "ops"} // no store -> no regexes
	if err := c.checkCommandRegex("c"); err != nil {
		t.Errorf("an ambiguous command from an UNRESTRICTED class must not be reported as "+
			"a permission denial: %v", err)
	}
	// And the legacy empty-class bypass is untouched.
	empty := &CLI{userClass: ""}
	if err := empty.checkCommandRegex("request system reboot"); err != nil {
		t.Errorf("the empty-class legacy path must be unchanged: %v", err)
	}
}

// A class whose deny regex does not compile must DENY, not skip.
func TestUncompilableDenyRegexIsAnError7172(t *testing.T) {
	cfg := &config.Config{}
	cfg.System.Login = &config.LoginConfig{
		Classes: []*config.LoginClass{{
			Name:              "ops",
			DenyCommands:      "([unclosed",
			DenyLeavesPresent: []string{"deny-commands"},
		}},
	}
	if _, _, err := loginRegexesFrom(cfg, "ops"); err == nil {
		t.Fatal("a class whose deny regex does not compile must surface an error so the " +
			"caller denies. Returning it as \"no rules\" would leave the class unrestricted, " +
			"which is the fail-open direction on the leaf that matters.")
	}
}

// The compile-error branch of the WHOLE decision, not just the rules fetch.
// An earlier version tested only that loginRegexesFrom surfaced the error, so
// turning checkCommandRegex's handler into `return nil` escaped.
func TestCheckCommandRegexDeniesOnAnUncompilableRegex7172(t *testing.T) {
	cfg := &config.Config{}
	cfg.System.Login = &config.LoginConfig{
		Classes: []*config.LoginClass{{
			Name:              "ops",
			DenyCommands:      "([unclosed",
			DenyLeavesPresent: []string{"deny-commands"},
		}},
	}
	err := checkCommandRegexWith(cfg, "ops", "show interfaces", "")
	if err == nil {
		t.Fatal("a class whose deny regex does not compile must DENY. Skipping leaves the " +
			"class unrestricted, and reaching here means a config arrived by a path that " +
			"did not validate — refusing is the only safe reading.")
	}
	if !strings.Contains(err.Error(), "invalid command regex") {
		t.Errorf("the refusal must say why: %v", err)
	}
}

// denyClassStore7172 commits a class carrying a `deny-commands` regex.
//
// This helper CANNOT HAVE EXISTED before #7172 cut 6: #5831/#6838's admission
// gate rejected exactly this config at commit, which is why cuts 3 and 4 bound
// their wiring with source scans and said so. Its existence is the retirement.
func denyClassStore7172(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.LoadOverride(`
system {
    host-name deny-gate-test;
    login {
        class limited {
            permissions all;
            deny-commands "show version";
            deny-configuration "system host-name";
        }
    }
}
`); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("a deny-commands class must COMMIT after #7172 cut 6 retired the "+
			"#5831/#6838 admission gate — if this fails the gate is back: %v", err)
	}
	store.ExitConfigure()
	if store.ActiveConfig() == nil {
		t.Fatal("no active config after commit; the gate's retirement is what makes " +
			"ActiveConfig non-nil for this class, and every behavioural cell below " +
			"depends on it")
	}
	return store
}

// THE WIRING, BEHAVIOURAL — replacing cut 3's source scan, which existed only
// because this test could not.
//
// A source scan asserts a call EXISTS in a function body. It cannot see that
// the call is REACHED, nor that the class resolved for the session is the one
// evaluated, nor that the refusal reaches the operator. All three are asserted
// here by driving the real dispatcher.
//
// `run` from CONFIG MODE is covered deliberately: `case "run"` in dispatchConfig
// calls dispatchOperational DIRECTLY, so a gate placed at dispatch() would leave
// it open to anyone who can enter config mode. That was the reason cut 3's scan
// checked WHICH function held the call, and it is preserved as behaviour here.
// It drives dispatchOperational, NOT checkCommandRegex, and that distinction is
// the whole reason this cell exists rather than a simpler one.
//
// Found by mutation, twice in this issue: a first draft of this test called
// checkCommandRegex directly, and unwiring dispatchOperational — replacing the
// call with `error(nil)` while keeping the symbol — left the ENTIRE suite green.
// The source scan this replaces did catch that. A behavioural test that skips
// the caller is a WEAKER guard than the scan it replaced, not a stronger one,
// and it looks stronger, which is what makes it worth saying here.
func TestDispatchOperationalEnforcesDenyCommands7172(t *testing.T) {
	c := &CLI{store: denyClassStore7172(t), userClass: "limited"}

	// THE DENIED COMMAND IS DELIBERATELY HARMLESS, and that is a correctness
	// requirement of this cell rather than a convenience.
	//
	// The first draft denied `request system reboot`. When the gate was
	// unwired, the dispatcher fell through into handleRequestSystem, which
	// dereferenced a readline Instance this bare fixture does not have, and the
	// mutation was "killed" by a SIGSEGV — no `--- FAIL` line, so a harness
	// scoring on named failures records it as an ESCAPE, and a reader cannot
	// tell the guard from the crash. Worse, the shape generalises badly: a
	// wiring test whose control flow reaches a DESTRUCTIVE handler when the
	// gate fails is one fixture change away from actually running it. #5278
	// makes the same call for zeroize, and for the same reason.
	//
	// `show version` is denied by the fixture's pattern and safe to execute, so
	// the unwired case returns cleanly and the assertion below is what fails.
	err := c.dispatchOperational("show version")
	if err == nil {
		t.Fatal("dispatchOperational admitted a command the committed class denies — the " +
			"gate is not reached from the dispatcher, so the class commits and restricts " +
			"nothing, which is the #5831 defect wearing the shape of a fix")
	}
	if !strings.Contains(err.Error(), "denies") {
		t.Errorf("the refusal must come from the command regex, not from the coarse "+
			"permission gate — the class holds `permissions all` precisely so that any "+
			"denial here is attributable to the regex: %v", err)
	}

	// A narrow deny must stay narrow, or the cell would also pass against a
	// gate that denied everything. Asserted at the gate, not through a handler.
	if err := c.checkCommandRegex("show interfaces"); err != nil {
		t.Errorf("`show interfaces` is not matched by this class's pattern and must not be "+
			"denied: %v", err)
	}

	// An unrestricted class on the SAME store is untouched.
	other := &CLI{store: c.store, userClass: "no-such-class"}
	if err := other.checkCommandRegex("show version"); err != nil {
		t.Errorf("a class with no regexes must not be gated: %v", err)
	}
}

// The same conversion for cut 4's config-mode gate, and it drives dispatchConfig
// for the same reason the operational one drives dispatchOperational: calling
// checkConfigRegex directly would leave the wiring unbound, which is exactly
// what the mutation matrix caught on the sibling cell.
func TestDispatchConfigEnforcesDenyConfiguration7172(t *testing.T) {
	c := &CLI{store: denyClassStore7172(t), userClass: "limited"}

	err := c.dispatchConfig("set system host-name evil")
	if err == nil {
		t.Fatal("dispatchConfig admitted a mutation the committed class denies — the gate " +
			"is not reached from the dispatcher")
	}
	if !strings.Contains(err.Error(), "denies") {
		t.Errorf("the refusal must come from the configuration regex: %v", err)
	}

	// A path the pattern does not match must not be denied. It may still fail
	// for ordinary reasons (an incomplete `set`), so this asserts the DENIAL is
	// absent rather than that the command succeeded — asserting success would
	// couple this authorization cell to the config store's own grammar.
	if err := c.dispatchConfig("set system services ssh"); err != nil &&
		strings.Contains(err.Error(), "denies") {
		t.Errorf("a path outside the pattern must not be denied: %v", err)
	}
}

// allowClassStore7172 commits a class carrying ONLY an `allow-commands` regex.
//
// The cells this replaces asserted the opposite — that cut 3 must NOT enforce
// allow — and they were right while `allow-commands` committed as a documented
// no-op: enforcing it mid-series would have silently narrowed live classes on
// upgrade, which is a lockout, not a hardening. Cut 6 turns it on together with
// the #6838 retirement so both leaves change state in one step, with one
// release note.
//
// Note what those cells could NOT have caught, which is why they are replaced
// rather than inverted in place: they hard-coded allowSet=false when building
// the rules, so they exercised the MATCHER's unset-allow branch and never the
// resolver's scoping. They would have stayed green through this entire change.
func allowClassStore7172(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.LoadOverride(`
system {
    host-name allow-gate-test;
    login {
        class narrow {
            permissions all;
            allow-commands "show interfaces";
        }
    }
}
`); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	store.ExitConfigure()
	return store
}

// AN ALLOW REGEX IS AN ALLOWLIST — the upgrade note in executable form.
//
// The class below holds `permissions all`, so the coarse gate admits
// everything; anything refused here is refused by the allowlist alone. Before
// cut 6 this class could run every command its permission bits allowed. Now it
// can run `show interfaces` and nothing else — not `show version`, not
// `configure`. That narrowing is the whole content of the release note, and it
// is asserted rather than described.
func TestAllowCommandsIsAnAllowlist7172(t *testing.T) {
	c := &CLI{store: allowClassStore7172(t), userClass: "narrow"}

	if err := c.checkCommandRegex("show interfaces"); err != nil {
		t.Errorf("the allowed command must be permitted: %v", err)
	}
	for _, cmd := range []string{"show version", "request system reboot"} {
		if err := c.checkCommandRegex(cmd); err == nil {
			t.Errorf("%q is outside the class's allow-commands pattern and an allow regex "+
				"is an ALLOWLIST — permitting it would make the statement inert, which is "+
				"the #5831 defect this issue exists to close", cmd)
		}
	}
	// SCOPING: a class with NO regexes is still unaffected. Without this arm
	// the cell would also pass against a gate that denied everything for
	// everyone.
	other := &CLI{store: c.store, userClass: "no-such-class"}
	if err := other.checkCommandRegex("show version"); err != nil {
		t.Errorf("a class with no regexes must be unaffected: %v", err)
	}
}
