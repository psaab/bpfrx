package cli

import (
	"fmt"
	"strings"

	"github.com/psaab/xpf/pkg/cmdtree"
	"github.com/psaab/xpf/pkg/config"
)

// Fine-grained operational-command enforcement for `system login class`
// allow-commands / deny-commands (#7172 cut 3).
//
// This runs AFTER checkPermission, never instead of it: Junos authorizes the
// command family with the coarse permission bits first and the regexes narrow
// within that. A caller reaching this without the coarse gate has skipped a
// check rather than replaced one.
//
// WHY dispatchOperational AND NOT dispatch(). dispatch() looks like the
// narrowest entry — it has the untouched line, pipe included — but it is not
// the only one: `case "run"` in dispatchConfig calls dispatchOperational
// DIRECTLY (cli_dispatch.go), so a config-mode `run request system reboot`
// never passes through dispatch() again. Gating at dispatch() would leave that
// path open, and it is reachable by any operator who can enter config mode.
// dispatchOperational is where all five entry paths converge.
//
// THE PIPE IS PART OF THE COMMAND. Junos matches deny regexes against the
// command including its output pipe, and the security argument is independent
// of parity: `show configuration | save /tmp/x` writes a file and
// `| display set` reformats output a deny may be withholding, so a gate that
// cannot see past `|` cannot restrict either. cliterm.SplitPipe strips the
// suffix before dispatchOperational sees the line, so dispatchWithPipe hands it
// back through pendingPipeSuffix for reassembly here.

// loginRegexesFor compiles the calling class's operational allow/deny pair.
//
// Returns ok=false when the class has no fine-grained rules at all, which is
// the overwhelmingly common case and must stay allocation-free of surprises:
// the caller then skips regex evaluation entirely rather than evaluating an
// empty ruleset.
func (c *CLI) loginRegexesFor(class string) (config.CompiledLoginRegexes, bool, error) {
	var cfg *config.Config
	if c.store != nil {
		cfg = c.store.ActiveConfig()
	}
	return loginRegexesFrom(cfg, class)
}

// loginRegexesFrom resolves the operational allow/deny pair in force for class.
//
// #7172 cut 5b moved the decision into pkg/config so this gate and the gRPC one
// cannot come to disagree about WHOSE regexes are in force; cut 6 turned the
// ALLOW half on there, for both of them at once. The scoping comment that used
// to argue for deny-only here is gone with the scoping: `allow-commands` is
// enforced now, and an allow regex is an allowlist, which is the upgrade note
// docs/system-login.md carries.
func loginRegexesFrom(cfg *config.Config, class string) (config.CompiledLoginRegexes, bool, error) {
	return config.OperationalLoginRegexesFor(cfg, class)
}

// checkCommandRegex enforces the class's allow/deny command regexes against the
// canonical spelling of `line` plus its output pipe.
//
// FAIL-CLOSED ON EVERY UNCERTAIN PATH, and each one is a deliberate branch:
//
//   - a class whose regexes do not COMPILE denies. They are validated at
//     commit, so reaching here means a config arrived by a path that did not
//     validate; refusing is the only safe reading.
//   - a command that cannot be CANONICALIZED denies. We do not know what
//     command we are holding, so we cannot know a deny regex fails to match it.
//     Treating "cannot resolve" as "no match, allow" is precisely the bypass
//     canonicalization exists to close.
//
// Both apply ONLY to a class that configured regexes. A class with none is
// unaffected by either, so an ambiguous command still reaches its ordinary
// "ambiguous command" error rather than a permission denial.
func (c *CLI) checkCommandRegex(line string) error {
	var cfg *config.Config
	if c.store != nil {
		cfg = c.store.ActiveConfig()
	}
	return checkCommandRegexWith(cfg, c.userClass, line, c.pendingPipeSuffix)
}

// checkCommandRegexWith is the store-free whole decision, including the
// fail-closed arms. Split out for the same reason loginRegexesFrom is: nothing
// can put a `deny-commands` class into ActiveConfig until cut 6, so the error
// branches are unreachable through a store and would go untested.
func checkCommandRegexWith(cfg *config.Config, class, line, pipeSuffix string) error {
	if class == "" {
		return nil
	}
	rules, ok, err := loginRegexesFrom(cfg, class)
	if err != nil {
		return fmt.Errorf("permission denied: login class %q has an invalid command regex: %w",
			class, err)
	}
	if !ok {
		return nil
	}

	return evaluateCommandRegex(rules, class, line, pipeSuffix)
}

// evaluateCommandRegex is the pure half: compiled rules and a command line in,
// an error or nil out. Split from checkCommandRegex so the decision can be
// driven directly in tests.
//
// That seam matters more than usual here. Cut 3's enforcement is UNREACHABLE
// through the commit path until cut 6 retires #6838's gate, which refuses every
// config carrying `deny-commands`. A test that drove this through a committed
// config could not exist yet, and writing one that bypasses commit would be
// testing a path no operator can reach while looking like an end-to-end test.
func evaluateCommandRegex(
	rules config.CompiledLoginRegexes,
	class, line, pipeSuffix string,
) error {
	full := strings.TrimSpace(line)
	if suffix := strings.TrimSpace(pipeSuffix); suffix != "" {
		full = full + " | " + suffix
	}

	words := strings.Fields(full)
	canon, res := cmdtree.Canonicalize(cmdtree.OperationalTree, words)
	if res != cmdtree.CanonicalOK {
		return fmt.Errorf(
			"permission denied: login class %q restricts commands and %q could not be "+
				"resolved to a canonical command, so the restriction cannot be evaluated",
			class, firstWord(words))
	}

	decision := rules.Evaluate(strings.Join(canon, " "))
	if decision.Allowed {
		return nil
	}
	// AUDIT WITHOUT LEAKING ARGUMENTS, and the limitation is deliberate.
	//
	// A reader will eventually want the FULL canonical command in this record,
	// and the reason they cannot have it belongs here rather than being
	// rediscovered: canonicalization resolves KEYWORD slots but leaves value
	// slots as the operator typed them, so the joined string can carry a ping
	// target, a filename, a username. Naming only the leading resolved keyword
	// run is what keeps operator data out of the log.
	//
	// Widening this needs a way to tell a keyword from a value in the rendered
	// string, which Canonicalize does not currently report.
	return fmt.Errorf("permission denied: login class %q denies %q (%s)",
		class, canonicalPrefix(canon), decision.Reason)
}

func firstWord(words []string) string {
	if len(words) == 0 {
		return ""
	}
	return words[0]
}

// canonicalPrefix renders the leading KEYWORD run of a canonical command for
// audit, stopping at the first token that is not a resolved keyword.
//
// #7172 requires audit output naming "class, canonical command, and deny reason
// WITHOUT leaking argument values". A canonical command still contains raw
// value slots — `request system login user <name>` or a ping target — so
// joining the whole slice would put operator data into a log line.
func canonicalPrefix(canon []string) string {
	keep := make([]string, 0, len(canon))
	current := cmdtree.OperationalTree
	for _, w := range canon {
		node, ok := current[w]
		if !ok {
			break
		}
		keep = append(keep, w)
		if node.Children == nil {
			break
		}
		current = node.Children
	}
	if len(keep) == 0 {
		return "<unresolved>"
	}
	return strings.Join(keep, " ")
}
