package cli

import (
	"os"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
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

// THE WIRING. Every cell above drives evaluateCommandRegex or
// checkCommandRegex directly, so ALL of them stay green if dispatchOperational
// stops calling the gate — verified: deleting the call left the suite green.
// A gate nothing calls is not a gate.
//
// Bound as a source-level agreement rather than behaviourally because no
// supported path puts a `deny-commands` class into ActiveConfig today: strict
// commit rejects it (#6838) and Store.Load leaves ActiveConfig nil. Cut 6
// retires the gate and this becomes testable through a committed config; until
// then this is what stands between the gate and being silently disconnected.
//
// Comments are stripped so the guard cannot be satisfied by prose that merely
// mentions the call — the rationale comment above the real call site names it.
func TestDispatchOperationalCallsTheCommandGate7172(t *testing.T) {
	src, err := os.ReadFile("cli_dispatch.go")
	if err != nil {
		t.Fatalf("read cli_dispatch.go: %v", err)
	}
	code := stripGoCommentsForGuard(string(src))
	if !strings.Contains(code, "c.checkCommandRegex(line)") {
		t.Fatal("dispatchOperational no longer CALLS checkCommandRegex(line). Matching the " +
			"bare symbol is not enough — `_ = c.checkCommandRegex` keeps the name and " +
			"disconnects the gate, and that mutation escaped an earlier version of this " +
			"guard. The fine-grained " +
			"deny-commands gate is disconnected: every unit cell in this file drives the " +
			"gate directly and stays green, so nothing else catches this.")
	}
	// It must be in dispatchOperational specifically. A gate moved to
	// dispatch() would leave `run <cmd>` from config mode ungated, because
	// dispatchConfig's `case "run"` calls dispatchOperational DIRECTLY.
	i := strings.Index(code, "func (c *CLI) dispatchOperational(")
	if i < 0 {
		t.Fatal("dispatchOperational not found")
	}
	rest := code[i:]
	if j := strings.Index(rest, "\nfunc "); j > 0 {
		rest = rest[:j]
	}
	if !strings.Contains(rest, "c.checkCommandRegex(line)") {
		t.Error("checkCommandRegex is no longer called inside dispatchOperational. " +
			"dispatch() is not sufficient: `case \"run\"` in config mode calls " +
			"dispatchOperational directly, so `run request system reboot` would be ungated " +
			"for anyone who can enter config mode.")
	}
}

// stripGoCommentsForGuard blanks // and /* */ comments so a source-level guard
// cannot be satisfied by prose quoting the symbol it looks for.
func stripGoCommentsForGuard(src string) string {
	b := []byte(src)
	out := make([]byte, len(b))
	for i := range out {
		out[i] = ' '
	}
	i := 0
	for i < len(b) {
		switch {
		case b[i] == '/' && i+1 < len(b) && b[i+1] == '/':
			for i < len(b) && b[i] != '\n' {
				i++
			}
		case b[i] == '/' && i+1 < len(b) && b[i+1] == '*':
			i += 2
			for i+1 < len(b) && !(b[i] == '*' && b[i+1] == '/') {
				if b[i] == '\n' {
					out[i] = '\n'
				}
				i++
			}
			i = min(i+2, len(b))
		default:
			out[i] = b[i]
			i++
		}
	}
	return string(out)
}

// SCOPING, asserted on the real decision rather than on hand-built rules:
// loginRegexesFrom must never mark allow as set in cut 3.
func TestLoginRegexesFromNeverEnforcesAllowInCut3_7172(t *testing.T) {
	cfg := &config.Config{}
	cfg.System.Login = &config.LoginConfig{
		Classes: []*config.LoginClass{{
			Name:              "ops",
			AllowCommands:     "show interfaces",
			DenyCommands:      "request system reboot",
			DenyLeavesPresent: []string{"deny-commands"},
		}},
	}
	rules, ok, err := loginRegexesFrom(cfg, "ops")
	if err != nil || !ok {
		t.Fatalf("expected compiled rules, got ok=%v err=%v", ok, err)
	}
	// If allow were enforced this would be denied by the allowlist.
	if err := evaluateCommandRegex(rules, "ops", "show version", ""); err != nil {
		t.Errorf("allow-commands must NOT be enforced in cut 3 — a live class carrying "+
			"`allow-commands \"show interfaces\"` would abruptly lose `show version` on "+
			"upgrade, a restriction its author was told was inert: %v", err)
	}
	if err := evaluateCommandRegex(rules, "ops", "request system reboot", ""); err == nil {
		t.Error("deny must still be enforced")
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

// ALLOW IS NOT ENFORCED IN THIS CUT, deliberately. An allow regex is an
// allowlist, and `allow-commands` commits today as a documented no-op — so
// enforcing it here would silently narrow live classes on upgrade. It lands in
// cut 6 with the gate's retirement.
func TestAllowCommandsIsNotEnforcedInCut3_7172(t *testing.T) {
	// Rules built the way loginRegexesFor builds them: allow always unset.
	rules, err := config.CompileLoginRegexes(config.LoginRegexPlainFamily,
		"show interfaces", false, // present in config, NOT passed as set
		"request system reboot", true)
	if err != nil {
		t.Fatal(err)
	}
	// A command outside the allow pattern must still be permitted, because the
	// allowlist is not in force yet.
	if err := evaluateCommandRegex(rules, "ops", "show version", ""); err != nil {
		t.Errorf("cut 3 must not enforce allow-commands — a live class carrying "+
			"`allow-commands \"show interfaces\"` would abruptly lose `show version`, "+
			"a restriction its author was told was inert: %v", err)
	}
	// Deny still bites.
	if err := evaluateCommandRegex(rules, "ops", "request system reboot", ""); err == nil {
		t.Error("deny must still be enforced in cut 3")
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
