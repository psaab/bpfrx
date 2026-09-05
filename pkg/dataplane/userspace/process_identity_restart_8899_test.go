package userspace

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #8899: a config changing ONLY the helper's process identity — which binary
// runs, which sockets it listens on, where it checkpoints, how it polls — was
// acked during the pending-XSK-startup window WITHOUT restarting the helper.
//
// The restart trigger in that window compared binding PLAN KEYS.
// `snapshotBindingPlanKey` covers workers, ring entries, and interface/fabric
// topology; it is deliberately insensitive to everything else, because it must
// not churn when a tunnel appears or moves (see the four-call-site note in
// ingress_exclusions.go). Process identity is not in it and should not be.
//
// The branch then recorded the DESIRED config as running (`m.cfg = ucfg`) and
// returned success, which is what makes the state non-self-repairing: a later
// IDENTICAL apply compares against the desired config, sees no change, and does
// not restart either. The obvious operator recovery — reapply the same config —
// is exactly the one that cannot work.

func baseUserspaceConfig8899() config.UserspaceConfig {
	return config.UserspaceConfig{
		Binary:        "/usr/sbin/xpf-userspace-dp",
		ControlSocket: "/run/xpf/ctl.sock",
		EventSocket:   "/run/xpf/evt.sock",
		StateFile:     "/var/lib/xpf/state.json",
		Workers:       4,
		RingEntries:   2048,
		PollMode:      "busy",
	}
}

// bumpField8899 returns a copy of cfg with exactly one exported field changed to
// a value different from its current one.
func bumpField8899(t *testing.T, cfg config.UserspaceConfig, name string) config.UserspaceConfig {
	t.Helper()
	out := cfg
	fv := reflect.ValueOf(&out).Elem().FieldByName(name)
	if !fv.IsValid() || !fv.CanSet() {
		t.Fatalf("field %q is not settable — this helper cannot exercise it", name)
	}
	switch fv.Kind() {
	case reflect.String:
		fv.SetString(fv.String() + "-changed-8899")
	case reflect.Bool:
		fv.SetBool(!fv.Bool())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		fv.SetInt(fv.Int() + 8899)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		fv.SetUint(fv.Uint() + 8899)
	case reflect.Ptr:
		// nil -> non-nil is a change; a non-nil pointer becomes nil.
		if fv.IsNil() {
			fv.Set(reflect.New(fv.Type().Elem()))
		} else {
			fv.Set(reflect.Zero(fv.Type()))
		}
	case reflect.Slice:
		fv.Set(reflect.Append(fv, reflect.Zero(fv.Type().Elem())))
	default:
		t.Fatalf("field %q has kind %s, which this helper cannot bump — extend the "+
			"switch rather than skipping the field, or the completeness guard below "+
			"silently stops covering it", name, fv.Kind())
	}
	return out
}

// THE COMPLETENESS GUARD, and it is the one that prevents the NEXT #8899
// rather than only fixing this one.
//
// MY FIRST VERSION OF THIS ASSERTED THE WRONG POLICY, and running it is what
// showed that. It required every exported field of config.UserspaceConfig to be
// compared by `configEqual`. Seventeen fields exist and `configEqual` compares
// seven, so it failed on ten — and had I "fixed" that by adding them, a change
// to `cpu-governor` or an ethtool coalescence setting would RESTART THE
// DATAPLANE. The blanket rule was more dangerous than the bug.
//
// The seven are exactly the helper's process identity: `Binary` is the
// executable, and the other six are its argv or the socket it is dialled on
// (`process.go` builds `--control-socket --state-file --workers --ring-entries
// --poll-mode`, plus the derived event socket). Changing one of them cannot be
// applied to a running child.
//
// The ten are applied by the DAEMON out of band -- `daemon_apply_tail.go` and
// `daemon_run_naming.go` set the CPU governor, netdev budget, RSS indirection
// and coalescence via sysfs/ethtool -- or reach the helper inside the SNAPSHOT
// rather than argv (`SharedUMEM`), or are diagnostic (`RetiredKnobsSeen`). None
// needs a restart, and forcing one would be a regression.
//
// So the guard asserts CLASSIFICATION, not membership: every field must be in
// exactly one of the two sets. A field added to config.UserspaceDataplane fails
// this cell until someone decides which it is — which is the decision that was
// never made for the seven, and the reason #8899 existed.
var processIdentityExempt8899 = map[string]string{
	"SharedUMEM":                  "reaches the helper in the SNAPSHOT (protocol_binding.go), not argv — live-configurable",
	"RSSIndirectionDisabled":      "applied by the daemon via ethtool (daemon_apply_tail.go)",
	"ClaimHostTunables":           "gates the daemon's own sysfs/ethtool writes; the helper never sees it",
	"CPUGovernor":                 "daemon writes it to sysfs; restarting the helper would not apply it",
	"NetdevBudget":                "daemon sysfs tunable",
	"CoalescenceAdaptiveDisabled": "daemon ethtool tunable",
	"CoalescenceAdaptiveExplicit": "daemon ethtool tunable",
	"CoalescenceRXUsecs":          "daemon ethtool tunable",
	"CoalescenceTXUsecs":          "daemon ethtool tunable",
	"RetiredKnobsSeen":            "diagnostic list of retired knobs for the commit warning; not runtime state",
}

func TestEveryUserspaceConfigFieldIsClassifiedForRestart8899(t *testing.T) {
	base := baseUserspaceConfig8899()
	rt := reflect.TypeOf(base)

	// LIVENESS: reflection over the wrong type, or a struct that lost its
	// fields, would make every assertion below vacuous.
	if rt.NumField() == 0 {
		t.Fatal("config.UserspaceConfig has no fields — this guard is reading the wrong type")
	}
	if !configEqual(base, base) {
		t.Fatal("configEqual says a config differs from itself; the fixture or the " +
			"predicate is broken and nothing below can mean anything")
	}

	seen := map[string]bool{}
	identity, exempt := 0, 0
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		if f.PkgPath != "" {
			continue // unexported
		}
		seen[f.Name] = true
		t.Run(f.Name, func(t *testing.T) {
			changed := bumpField8899(t, base, f.Name)
			compared := !configEqual(base, changed)
			reason, isExempt := processIdentityExempt8899[f.Name]

			switch {
			case compared && isExempt:
				t.Errorf("config.UserspaceConfig.%s is BOTH compared by configEqual and "+
					"listed exempt (%q). One of the two is wrong: if it is process "+
					"identity, drop the exemption; if it is a daemon-applied tunable, "+
					"drop it from configEqual or every change to it restarts the "+
					"dataplane.", f.Name, reason)
			case !compared && !isExempt:
				t.Errorf("config.UserspaceConfig.%s is UNCLASSIFIED: configEqual ignores "+
					"it and it is not listed exempt. Decide which it is.\n"+
					"  If it changes the helper's argv, its binary, or a socket it is "+
					"dialled on, add it to configEqual — otherwise a commit changing "+
					"only that field is acked WITHOUT a restart, and during the "+
					"XSK-startup window it is also recorded as running, so reapplying "+
					"the same config cannot repair it either (#8899).\n"+
					"  If the DAEMON applies it out of band (sysfs/ethtool, see "+
					"daemon_apply_tail.go) or it travels in the snapshot, add it to "+
					"processIdentityExempt8899 with the reason.", f.Name)
			}
			if compared {
				identity++
			} else {
				exempt++
			}
		})
	}

	// The exempt list must not name fields that no longer exist — a stale
	// entry silently excuses nothing and hides the next unclassified field
	// behind a name that looks handled.
	for name := range processIdentityExempt8899 {
		if !seen[name] {
			t.Errorf("processIdentityExempt8899 names %q, which is not a field of "+
				"config.UserspaceConfig any more. Remove it.", name)
		}
	}
	if identity == 0 || exempt == 0 {
		t.Errorf("the classification collapsed to one side (identity=%d exempt=%d); "+
			"a guard where every field lands in the same bucket is not discriminating",
			identity, exempt)
	}
}

// The blindness itself, measured, with the controls that make the negatives
// mean something.
//
// lane-8367 measured FOUR fields on #8899 (Binary, ControlSocket, StateFile,
// PollMode). The real population is FIVE: `EventSocket` is equally absent from
// the plan key and equally a process-identity field. The table below is derived
// from the two predicates rather than transcribed, so it cannot drift from them.
func TestPlanKeyIsBlindToProcessIdentityFields8899(t *testing.T) {
	base := baseUserspaceConfig8899()
	snapFor := func(c config.UserspaceConfig) *ConfigSnapshot {
		return &ConfigSnapshot{Version: ProtocolVersion, Generation: 1, Userspace: c}
	}
	baseKey := snapshotBindingPlanKey(snapFor(base))
	if baseKey == "" {
		t.Fatal("NON-VACUITY: the base plan key is empty, so 'unchanged' below would " +
			"be comparing two empty strings and every row would pass")
	}

	// CONTROLS FIRST. A table of all-unchanged rows is indistinguishable from a
	// key function that returns a constant — the shape that produced three wrong
	// verdicts on #8791. These two prove the key discriminates what it covers.
	for _, ctl := range []string{"Workers", "RingEntries"} {
		changed := bumpField8899(t, base, ctl)
		if snapshotBindingPlanKey(snapFor(changed)) == baseKey {
			t.Fatalf("CONTROL FAILED: the plan key did not move when %s changed. The key "+
				"is not discriminating at all, so the blindness rows below are a property "+
				"of the fixture rather than of the key", ctl)
		}
	}

	// Every field the plan key does NOT cover must be covered by configEqual,
	// or the restart cannot be triggered by anything.
	rt := reflect.TypeOf(base)
	blind := 0
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		if f.PkgPath != "" {
			continue
		}
		changed := bumpField8899(t, base, f.Name)
		if snapshotBindingPlanKey(snapFor(changed)) != baseKey {
			continue // the plan key sees it; not a #8899 field
		}
		if _, exempt := processIdentityExempt8899[f.Name]; exempt {
			// Blind to the plan key by design, and it does not need a restart —
			// the daemon applies it out of band, or it travels in the snapshot.
			continue
		}
		blind++
		if configEqual(base, changed) {
			t.Errorf("config.UserspaceConfig.%s is invisible to BOTH the binding plan key "+
				"AND configEqual, and is not listed exempt. Nothing can trigger a restart "+
				"for it (#8899)", f.Name)
		}
	}
	if blind == 0 {
		t.Fatal("no field was found invisible to the plan key — either the key now covers " +
			"everything (in which case this cell should be re-pointed) or the fixture is " +
			"not exercising it")
	}
	// lane-8367 measured FOUR on the issue; the real process-identity population
	// invisible to the plan key is FIVE — `EventSocket` is equally absent and
	// equally argv-adjacent (it is derived from ControlSocket's directory when
	// empty, and the event stream is dialled on it).
	if blind != 5 {
		t.Errorf("expected 5 process-identity fields invisible to the binding plan key "+
			"(Binary, ControlSocket, EventSocket, StateFile, PollMode), got %d. If a "+
			"field moved between the plan key and configEqual, this count is the thing "+
			"that noticed — re-derive it deliberately rather than editing the number",
			blind)
	}
	t.Logf("#8899: %d process-identity fields are invisible to the binding plan key "+
		"and are covered by configEqual instead", blind)
}

// And the wiring: the production predicate, not a re-derivation of it.
func TestProcessRestartRequiredDuringStartup8899(t *testing.T) {
	base := baseUserspaceConfig8899()

	if processRestartRequiredDuringStartup(true, base, base) {
		t.Error("an unchanged config must NOT force a restart during the startup window; " +
			"this would restart the helper on every same-config apply")
	}
	changed := bumpField8899(t, base, "ControlSocket")
	if !processRestartRequiredDuringStartup(true, base, changed) {
		t.Error("#8899: a control-socket change during the XSK-startup window MUST force a " +
			"restart. Without it the apply is acked, the desired config is recorded as " +
			"running, and every later snapshot and status RPC dials the new path while the " +
			"helper still listens on the old one")
	}
	// SCOPE: outside the window this predicate must stay quiet — the normal path
	// already reaches ensureProcessLocked, which consults configEqual itself.
	if processRestartRequiredDuringStartup(false, base, changed) {
		t.Error("outside the pending-XSK-startup window this predicate must not fire; the " +
			"normal apply path already restarts via ensureProcessLocked, and a second " +
			"trigger would stop the helper an extra time")
	}
}

// THE WIRING, which the three cells above do NOT bind.
//
// Measured: removing the `|| processIdentityChangedDuringStartup` disjunct from
// `manager_compile.go` left every other cell in this file GREEN. They exercise
// `processRestartRequiredDuringStartup`, `configEqual` and the plan key — the
// predicate is correct and the dispatcher simply would not consult it. That is
// the same defect this session held another PR for, reproduced here in my own
// work, which is why it gets its own guard rather than a note.
//
// This binds it TEXTUALLY, not by execution, and the distinction is worth
// stating. Driving the real branch needs a live child process, and the existing
// startup-window harness fakes it with `os.FindProcess(os.Getpid())` — so a cell
// that actually reached `stopLocked` would signal the test runner. A source scan
// is the weaker instrument and it is the one this codebase already uses for
// exactly this problem (see `nat64_never_reaches_the_in_place_rewrite_path_6922`).
// It cannot prove the branch behaves correctly; it can prove the call was not
// deleted, which is the failure that actually happened.
func TestStartupRestartConsultsProcessIdentity8899(t *testing.T) {
	src, err := os.ReadFile("manager_compile.go")
	if err != nil {
		t.Fatalf("read manager_compile.go: %v", err)
	}

	// Strip comments first: this file discusses #8899 and
	// processRestartRequiredDuringStartup at length in prose, and a scan a
	// comment can satisfy is not a scan of the code.
	var code strings.Builder
	inBlock := false
	for _, line := range strings.Split(string(src), "\n") {
		l := line
		if inBlock {
			if i := strings.Index(l, "*/"); i >= 0 {
				inBlock = false
				l = l[i+2:]
			} else {
				continue
			}
		}
		if i := strings.Index(l, "/*"); i >= 0 {
			inBlock = true
			l = l[:i]
		}
		if i := strings.Index(l, "//"); i >= 0 {
			l = l[:i]
		}
		code.WriteString(l)
		code.WriteString("\n")
	}
	stripped := code.String()

	// NON-VACUITY: the stripper must not have eaten the code.
	if !strings.Contains(stripped, "publishedPlanChangedDuringStartup") {
		t.Fatal("the comment stripper or manager_compile.go changed shape — the " +
			"binding-plan trigger is not in the stripped source, so this guard is not " +
			"reading what it claims to read")
	}

	if !strings.Contains(stripped, "processRestartRequiredDuringStartup(") {
		t.Fatal("manager_compile.go no longer CALLS processRestartRequiredDuringStartup. " +
			"The predicate can be perfectly correct and every other cell in this file " +
			"still passes — measured. Without this call, a config changing only the " +
			"helper's binary, sockets, state file or poll mode is acked during the " +
			"XSK-startup window without a restart, and `m.cfg = ucfg` then records it " +
			"as running so reapplying the same config cannot repair it (#8899).")
	}

	// And it must gate the RESTART, not merely be computed and discarded — the
	// exact shape the mutation used to prove these cells were blind.
	idx := strings.Index(stripped, "processIdentityChangedDuringStartup")
	if idx < 0 {
		t.Fatal("the restart condition no longer names processIdentityChangedDuringStartup")
	}
	tail := stripped[idx:]
	// The teardown must go through the PREFLIGHT wrapper, not a bare
	// stopLocked(). `stopForNewGenerationLocked` validates the incoming
	// binary/socket/state-file paths BEFORE killing the current helper and
	// refuses with "previous generation left running" on a bad one.
	//
	// This trigger fires on exactly those paths, so a bare stopLocked() turns a
	// mistyped `control-socket` into an outage: the running helper dies and its
	// replacement then fails to start. The binding-plan trigger it shares this
	// branch with does not touch paths, which is why the bare call was
	// tolerable before and is not now.
	end := strings.Index(tail, "m.stopForNewGenerationLocked(")
	if end < 0 {
		bare := strings.Index(tail, "m.stopLocked()")
		if bare >= 0 {
			t.Fatalf("the process-identity restart tears the helper down with a BARE " +
				"m.stopLocked(), bypassing preflightHelperPaths. A bad binary/socket/" +
				"state-file path will kill the running helper and only then fail to " +
				"start its replacement. Use stopForNewGenerationLocked and propagate " +
				"its error (#8899).")
		}
		t.Fatal("no teardown follows the process-identity check; the restart it is " +
			"supposed to trigger is gone")
	}
	// ORDER-INDEPENDENT, deliberately. An earlier version asserted the exact
	// string `if publishedPlanChangedDuringStartup || processIdentityChangedDuringStartup`
	// and failed when the two operands were SWAPPED — a change with no
	// behavioural effect at all. A guard that reds on a harmless refactor gets
	// edited or worked around rather than obeyed, so it protects nothing; what
	// matters is that BOTH terms gate the same restart, not which is written
	// first.
	cond := tail[:end]
	gate := strings.Index(cond, "if ")
	if gate < 0 {
		t.Fatalf("no `if` between the process-identity check and m.stopLocked():\n%s", cond)
	}
	brace := strings.Index(cond[gate:], "{")
	if brace < 0 {
		t.Fatalf("the restart condition has no opening brace:\n%s", cond)
	}
	expr := cond[gate : gate+brace]
	for _, term := range []string{
		"publishedPlanChangedDuringStartup",
		"processIdentityChangedDuringStartup",
	} {
		if !strings.Contains(expr, term) {
			t.Errorf("the restart condition does not test %s. Both the binding-plan "+
				"change and the process-identity change must gate this restart; with "+
				"either missing, its class of config change is acked without one "+
				"(#8899). Condition was: %s", term, expr)
		}
	}
	if !strings.Contains(expr, "||") {
		t.Errorf("the two triggers are no longer OR'd. Requiring BOTH to hold would "+
			"mean a process-identity change with an unchanged binding plan — the exact "+
			"#8899 case — is again acked without a restart. Condition was: %s", expr)
	}
}

// #8899, from review: `--poll-mode` is passed unconditionally and an empty
// configured value is defaulted at spawn, so "" and the default produce the
// IDENTICAL child process. Comparing the raw strings reported a difference that
// does not exist on the wire — and under the new startup-window trigger that
// difference became a spurious RESTART for an operator who merely wrote down
// the default they were already running.
func TestPollModeDefaultIsNotAProcessIdentityChange8899(t *testing.T) {
	running := baseUserspaceConfig8899()
	running.PollMode = ""
	desired := baseUserspaceConfig8899()
	desired.PollMode = defaultPollMode

	// LIVENESS: the two values must actually differ as strings, or this cell
	// asserts that equal things are equal.
	if running.PollMode == desired.PollMode {
		t.Fatal("fixture: the two spellings are identical, so nothing is being normalised")
	}
	if !configEqual(running, desired) {
		t.Errorf("configEqual reports a difference between PollMode %q and %q, but both "+
			"spawn the helper with --poll-mode %s — identical argv. Under the "+
			"startup-window trigger that restarts the dataplane for a config change "+
			"that changes nothing (#8899).", running.PollMode, desired.PollMode, defaultPollMode)
	}
	if processRestartRequiredDuringStartup(true, running, desired) {
		t.Error("writing the default poll-mode explicitly must NOT force a restart " +
			"during the XSK-startup window")
	}

	// And the normalisation must not swallow a REAL change.
	other := baseUserspaceConfig8899()
	other.PollMode = "interrupt"
	if configEqual(running, other) {
		t.Error("configEqual now treats a genuinely different poll-mode as equal; the " +
			"normalisation is too broad and a real process-identity change would be " +
			"acked without a restart")
	}
}

// #8899, from review: WRITING A DEFAULT DOWN EXPLICITLY MUST BE A NO-OP.
//
// Two fields of the spawn identity are resolved rather than used raw —
// `PollMode` ("" -> busy-poll) and `EventSocket` ("" -> derived beside the
// control socket). Comparing either RAW reports a difference that does not
// exist in the spawned process, and under the startup-window trigger that
// difference becomes a spurious RESTART of the dataplane on a commit that
// changes nothing.
//
// THE CLASSIFICATION GUARD CANNOT CATCH THIS, and that is the reason this cell
// is separate rather than another subtest there. That guard asks *is every
// field classified* — and `EventSocket` was classified correctly the whole
// time: it is process identity, it is in `configEqual`, and every mutation of
// the guard passes. **"Is every field classified" and "is every field compared
// correctly" are different questions**, and a guard that enumerates fields is
// blind to HOW each is compared. That blindness is exactly why fixing
// `PollMode` did not generalise to its sibling and nothing noticed.
//
// The structural fix is `helperSpawnIdentity`: `configEqual` is defined AS
// identity equality, so a field cannot be compared by a rule different from
// the one the spawn path applies. This cell pins the two resolvers that exist
// today; the type is what stops a third from drifting.
func TestWritingADefaultExplicitlyIsNotAChange8899(t *testing.T) {
	for _, c := range []struct {
		field   string
		explicit func(config.UserspaceConfig) config.UserspaceConfig
		resolved func(config.UserspaceConfig) string
	}{
		{
			field:    "PollMode",
			explicit: func(c config.UserspaceConfig) config.UserspaceConfig { c.PollMode = defaultPollMode; return c },
			resolved: effectivePollMode,
		},
		{
			field: "EventSocket",
			explicit: func(c config.UserspaceConfig) config.UserspaceConfig {
				c.EventSocket = helperEventSocketPath(c)
				return c
			},
			resolved: helperEventSocketPath,
		},
	} {
		t.Run(c.field, func(t *testing.T) {
			base := baseUserspaceConfig8899()
			// Start from the UNSET spelling for this field.
			switch c.field {
			case "PollMode":
				base.PollMode = ""
			case "EventSocket":
				base.EventSocket = ""
			}
			explicit := c.explicit(base)

			// LIVENESS: the two spellings must differ as raw values, or this
			// asserts that identical things are identical.
			if reflect.DeepEqual(base, explicit) {
				t.Fatalf("fixture: the explicit spelling of %s is byte-identical to the "+
					"unset one, so nothing is being resolved", c.field)
			}
			// And they must resolve to the SAME effective value, or the premise
			// of the cell is wrong rather than the code.
			if c.resolved(base) != c.resolved(explicit) {
				t.Fatalf("fixture: %s resolves differently (%q vs %q); the explicit "+
					"spelling is not the default after all",
					c.field, c.resolved(base), c.resolved(explicit))
			}

			if !configEqual(base, explicit) {
				t.Errorf("configEqual reports a difference for %s between the unset "+
					"spelling and its explicit default, but both spawn the identical "+
					"helper (%s resolves to %q either way). Under the startup-window "+
					"trigger this RESTARTS THE DATAPLANE for a commit that changes "+
					"nothing (#8899).", c.field, c.field, c.resolved(base))
			}
			if processRestartRequiredDuringStartup(true, base, explicit) {
				t.Errorf("writing %s explicitly at its default must not force a restart "+
					"during the XSK-startup window", c.field)
			}

			// The other direction: the resolver must not swallow a REAL change.
			real := base
			switch c.field {
			case "PollMode":
				real.PollMode = "interrupt"
			case "EventSocket":
				real.EventSocket = "/run/xpf/some-other-events.sock"
			}
			if configEqual(base, real) {
				t.Errorf("configEqual now treats a genuinely different %s as equal — the "+
					"resolution is too broad and a real process-identity change would be "+
					"acked without a restart", c.field)
			}
		})
	}
}
