package main

import "testing"

// #5322: several cmd/xpfd privileged lifecycle verbs (seed-runtime,
// publish-generation, cleanup, and the `upgrade kernel` promote|drain|rejoin
// sub-verbs) parsed their flags with `flag.FlagSet.Parse` and then PROCEEDED
// without an NArg() guard, so a leftover/unknown positional operand was
// silently dropped. `flag.Parse` stops at the first non-flag token, so a
// mistyped invocation such as `xpfd publish-generation typo --staged-gen-dir
// /lab` kept the PRODUCTION default and still mutated the live generation while
// reporting success. These tests mirror the #4869 `parseUpgradeArgs` harness:
// the extra-arg cases must RETURN AN ERROR (RED if the guard is reverted), and
// the legitimate forms must still parse cleanly (no false rejection).
//
// (joinArgs is shared with upgrade_args_4869_test.go — same package.)

// ---- seed-runtime (takes no positional args) --------------------------------

func TestParseSeedRuntimeArgsRejectsPositionals_5322(t *testing.T) {
	cases := [][]string{
		{"typo"},                        // bare stray operand
		{"typo", "--sbin-dir", "/x"},    // operand shadows the trailing flags
		{"--sbin-dir", "/x", "typo"},    // trailing stray operand after flags
		{"--capability-check", "extra"}, // probe verb + stray operand
	}
	for _, args := range cases {
		t.Run(joinArgs(args), func(t *testing.T) {
			if _, err := parseSeedRuntimeArgs(args); err == nil {
				t.Fatalf("parseSeedRuntimeArgs(%v) returned nil; expected rejection of the "+
					"leftover positional (must not silently seed with default dirs)", args)
			}
		})
	}
}

func TestParseSeedRuntimeArgsValidForms_5322(t *testing.T) {
	// Bare invocation: no flags, no operands.
	f, err := parseSeedRuntimeArgs(nil)
	if err != nil {
		t.Fatalf("bare seed-runtime: %v", err)
	}
	if f.capCheck {
		t.Fatal("bare seed-runtime must not select --capability-check")
	}
	// Recognized value flag is threaded through.
	f, err = parseSeedRuntimeArgs([]string{"--sbin-dir", "/opt/xpf/sbin"})
	if err != nil {
		t.Fatalf("--sbin-dir: %v", err)
	}
	if f.sbinDir != "/opt/xpf/sbin" {
		t.Fatalf("--sbin-dir not parsed: %q", f.sbinDir)
	}
	// The probe flag parses and is exposed.
	f, err = parseSeedRuntimeArgs([]string{"--capability-check"})
	if err != nil {
		t.Fatalf("--capability-check: %v", err)
	}
	if !f.capCheck {
		t.Fatal("--capability-check must set capCheck")
	}
}

// ---- publish-generation (takes no positional args) --------------------------

func TestParsePublishGenerationArgsRejectsPositionals_5322(t *testing.T) {
	cases := [][]string{
		{"typo"},                             // bare stray operand
		{"typo", "--staged-gen-dir", "/lab"}, // the exact issue-5322 scenario
		{"--staged-gen-dir", "/lab", "typo"}, // trailing stray operand after flags
		{"g0-deadbeef"},                      // a genid-looking operand this verb never takes
	}
	for _, args := range cases {
		t.Run(joinArgs(args), func(t *testing.T) {
			if _, err := parsePublishGenerationArgs(args); err == nil {
				t.Fatalf("parsePublishGenerationArgs(%v) returned nil; expected rejection of the "+
					"leftover positional (must not silently publish/GC with default dirs)", args)
			}
		})
	}
}

func TestParsePublishGenerationArgsValidForms_5322(t *testing.T) {
	// Bare invocation: no flags, no operands.
	if _, err := parsePublishGenerationArgs(nil); err != nil {
		t.Fatalf("bare publish-generation: %v", err)
	}
	// Recognized value flag is threaded through.
	f, err := parsePublishGenerationArgs([]string{"--staged-gen-dir", "/lab"})
	if err != nil {
		t.Fatalf("--staged-gen-dir: %v", err)
	}
	if f.stagedGenDir != "/lab" {
		t.Fatalf("--staged-gen-dir not parsed: %q", f.stagedGenDir)
	}
}

// ---- cleanup (takes no flags or positional args) ----------------------------

func TestParseCleanupArgsRejectsExtras_5322(t *testing.T) {
	cases := [][]string{
		{"typo"},
		{"--foo"}, // cleanup has no flags either
		{"typo", "extra"},
	}
	for _, args := range cases {
		t.Run(joinArgs(args), func(t *testing.T) {
			if err := parseCleanupArgs(args); err == nil {
				t.Fatalf("parseCleanupArgs(%v) returned nil; expected rejection of the "+
					"leftover operand (must not silently tear down all pinned state)", args)
			}
		})
	}
}

func TestParseCleanupArgsValidForm_5322(t *testing.T) {
	if err := parseCleanupArgs(nil); err != nil {
		t.Fatalf("cleanup with no args: %v", err)
	}
	if err := parseCleanupArgs([]string{}); err != nil {
		t.Fatalf("cleanup with empty args: %v", err)
	}
}

// ---- upgrade kernel promote|drain|rejoin (no operand) / arm (one operand) ----

func TestValidateKernelVerbArgsRejectsExtras_5322(t *testing.T) {
	cases := []struct {
		verb string
		pos  []string
	}{
		{"promote", []string{"g0-typo"}},
		{"drain", []string{"extra"}},
		{"rejoin", []string{"extra"}},
		{"status", []string{"extra"}},
		{"arm", nil},                         // arm needs exactly one operand
		{"arm", []string{"6.18.1", "extra"}}, // arm with a second stray operand
	}
	for _, c := range cases {
		t.Run(c.verb+"_"+joinArgs(c.pos), func(t *testing.T) {
			if err := validateKernelVerbArgs(c.verb, c.pos); err == nil {
				t.Fatalf("validateKernelVerbArgs(%q, %v) returned nil; expected rejection "+
					"(must not silently drop a stray operand on a privileged kernel verb)",
					c.verb, c.pos)
			}
		})
	}
}

func TestValidateKernelVerbArgsValidForms_5322(t *testing.T) {
	// No-operand verbs accept exactly zero positionals.
	for _, verb := range []string{"promote", "drain", "rejoin", "status"} {
		if err := validateKernelVerbArgs(verb, nil); err != nil {
			t.Fatalf("validateKernelVerbArgs(%q, nil): %v", verb, err)
		}
	}
	// arm accepts exactly one positional (the target version).
	if err := validateKernelVerbArgs("arm", []string{"6.18.1"}); err != nil {
		t.Fatalf("validateKernelVerbArgs(arm, [6.18.1]): %v", err)
	}
	// An unknown verb is left to the dispatch's own default case: no error here.
	if err := validateKernelVerbArgs("bogus", []string{"x"}); err != nil {
		t.Fatalf("validateKernelVerbArgs(bogus, ...) should defer to dispatch default, got %v", err)
	}
}
