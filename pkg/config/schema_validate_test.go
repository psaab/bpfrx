package config_test

// Tests for the #1319 typed-leaf schema gate. SchemaValidate (and the
// generic walker it drives) lives in pkg/config and validates the AST
// against setSchema; we exercise it end-to-end through configstore.Commit
// / CommitCheck in the configstore tests, and exercise the validators +
// AST walker here against parsed AST trees.

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// schemaCheck parses a Junos hierarchical config snippet and runs
// SchemaValidate against the resulting AST. apply-groups expansion is
// exercised through configstore tests because configstore owns the
// commit/load ordering relative to the compiler.
func schemaCheck(t *testing.T, input string) error {
	t.Helper()
	p := config.NewParser(input)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	return config.SchemaValidate(tree, nil)
}

func flatSchemaCheck(t *testing.T, cmds ...string) error {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, cmd := range cmds {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return config.SchemaValidate(tree, nil)
}

func TestSchemaValidate_TransmitRate_RejectsGarbage(t *testing.T) {
	err := schemaCheck(t, `class-of-service {
    schedulers {
        be {
            transmit-rate asd;
        }
    }
}`)
	if err == nil {
		t.Fatal("expected error for transmit-rate asd, got nil")
	}
	if !strings.Contains(err.Error(), "transmit-rate") {
		t.Fatalf("error should reference transmit-rate: %v", err)
	}
	if !strings.Contains(err.Error(), "asd") {
		t.Fatalf("error should quote bad input: %v", err)
	}
}

func TestSchemaValidate_TransmitRate_AcceptsValid(t *testing.T) {
	if err := schemaCheck(t, `class-of-service {
    schedulers {
        be {
            transmit-rate 1g;
        }
    }
}`); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSchemaValidate_TransmitRate_AcceptsExactModifier(t *testing.T) {
	if err := schemaCheck(t, `class-of-service {
	    schedulers {
	        be {
            transmit-rate 1g {
                exact;
            }
        }
    }
}`); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSchemaValidate_TransmitRate_AcceptsSplitExactModifier(t *testing.T) {
	if err := flatSchemaCheck(t,
		"set class-of-service schedulers be transmit-rate 1g",
		"set class-of-service schedulers be transmit-rate exact",
	); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSchemaValidate_TransmitRate_RejectsSplitExactWithoutRate(t *testing.T) {
	err := flatSchemaCheck(t, "set class-of-service schedulers be transmit-rate exact")
	if err == nil {
		t.Fatal("expected error for transmit-rate exact without a sibling rate, got nil")
	}
	if !strings.Contains(err.Error(), "transmit-rate") {
		t.Fatalf("error should reference transmit-rate: %v", err)
	}
}

func TestSchemaValidate_TransmitRate_RejectsTooSmall(t *testing.T) {
	err := schemaCheck(t, `class-of-service {
    schedulers {
        be {
            transmit-rate 1;
        }
    }
}`)
	if err == nil {
		t.Fatal("expected error for transmit-rate 1, got nil")
	}
}

func TestSchemaValidate_TransmitRate_RejectsMissingValue(t *testing.T) {
	err := flatSchemaCheck(t, "set class-of-service schedulers be transmit-rate")
	if err == nil {
		t.Fatal("expected error for transmit-rate with no value, got nil")
	}
	if !strings.Contains(err.Error(), "missing value") {
		t.Fatalf("error should describe missing value: %v", err)
	}
}

func TestSchemaValidate_TransmitRate_RejectsUnknownModifier(t *testing.T) {
	err := flatSchemaCheck(t, "set class-of-service schedulers be transmit-rate 1g typo")
	if err == nil {
		t.Fatal("expected error for unknown transmit-rate modifier, got nil")
	}
	if !strings.Contains(err.Error(), "unknown modifier") {
		t.Fatalf("error should describe unknown modifier: %v", err)
	}
}

func TestSchemaValidate_Priority_AcceptsStrictHigh(t *testing.T) {
	if err := schemaCheck(t, `class-of-service {
	    schedulers {
        be {
            priority strict-high;
        }
    }
}`); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSchemaValidate_Priority_RejectsUnknown(t *testing.T) {
	err := schemaCheck(t, `class-of-service {
    schedulers {
        be {
            priority foo;
        }
    }
}`)
	if err == nil {
		t.Fatal("expected error for priority foo, got nil")
	}
	if !strings.Contains(err.Error(), "priority") {
		t.Fatalf("error should reference priority: %v", err)
	}
}

func TestSchemaValidate_BufferSize_AcceptsBytes(t *testing.T) {
	if err := schemaCheck(t, `class-of-service {
    schedulers {
        be {
            buffer-size 16m;
        }
    }
}`); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSchemaValidate_BufferSize_RejectsBareInteger(t *testing.T) {
	err := schemaCheck(t, `class-of-service {
    schedulers {
        be {
            buffer-size 50;
        }
    }
}`)
	if err == nil {
		t.Fatal("expected error for ambiguous bare-integer buffer-size 50, got nil")
	}
}

func TestSchemaValidate_BufferSize_AcceptsPercent(t *testing.T) {
	if err := schemaCheck(t, `class-of-service {
    schedulers {
        be {
            buffer-size 10%;
        }
    }
}`); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSchemaValidate_BufferSize_AcceptsQuotedPercent(t *testing.T) {
	if err := schemaCheck(t, `class-of-service {
    schedulers {
        be {
            buffer-size "12.5%";
        }
    }
}`); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSchemaValidate_BufferSize_RejectsGarbage(t *testing.T) {
	err := schemaCheck(t, `class-of-service {
    schedulers {
        be {
            buffer-size purple;
        }
    }
}`)
	if err == nil {
		t.Fatal("expected error for buffer-size purple, got nil")
	}
}

func TestSchemaValidate_BufferSize_RejectsUnknownModifier(t *testing.T) {
	err := flatSchemaCheck(t, "set class-of-service schedulers be buffer-size 16m typo")
	if err == nil {
		t.Fatal("expected error for unknown buffer-size modifier, got nil")
	}
	if !strings.Contains(err.Error(), "unknown modifier") {
		t.Fatalf("error should describe unknown modifier: %v", err)
	}
}

func TestSchemaValidate_BufferSize_RejectsMissingValue(t *testing.T) {
	err := flatSchemaCheck(t, "set class-of-service schedulers be buffer-size")
	if err == nil {
		t.Fatal("expected error for buffer-size with no value, got nil")
	}
}

func TestSchemaValidate_BufferSize_RejectsBareIntegerGreaterThan100(t *testing.T) {
	err := schemaCheck(t, `class-of-service {
    schedulers {
        be {
            buffer-size 150;
        }
    }
	}`)
	if err == nil {
		t.Fatal("expected error for ambiguous bare-integer buffer-size 150, got nil")
	}
}

func TestSchemaValidate_BufferSize_RejectsZeroPercent(t *testing.T) {
	err := schemaCheck(t, `class-of-service {
    schedulers {
        be {
            buffer-size 0%;
        }
    }
}`)
	if err == nil {
		t.Fatal("expected error for zero percent buffer-size, got nil")
	}
	if !strings.Contains(err.Error(), "buffer-size") {
		t.Fatalf("error should reference buffer-size: %v", err)
	}
}

// FlatSetSyntax exercises the alternate AST shape that ParseSetCommand
// + tree.SetPath produces: Keys=["schedulers","be","transmit-rate","1g"]
// (when input is `set class-of-service schedulers be transmit-rate 1g`).
func TestSchemaValidate_FlatSetSyntax_RejectsGarbage(t *testing.T) {
	err := flatSchemaCheck(t, "set class-of-service schedulers be transmit-rate asd")
	if err == nil {
		t.Fatal("expected error for flat-set transmit-rate asd, got nil")
	}
	if !strings.Contains(err.Error(), "transmit-rate") {
		t.Fatalf("error should reference transmit-rate: %v", err)
	}
}

func TestSchemaValidate_FlatSetSyntax_AcceptsValid(t *testing.T) {
	cmds := []string{
		"set class-of-service schedulers be transmit-rate 1g",
		"set class-of-service schedulers be priority strict-high",
		"set class-of-service schedulers be buffer-size 16m",
	}
	if err := flatSchemaCheck(t, cmds...); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestSchemaValidate_AcceptedSchedulerValuesCompileAsValidated(t *testing.T) {
	tree := &config.ConfigTree{}
	cmds := []string{
		"set class-of-service schedulers be transmit-rate 8",
		"set class-of-service schedulers be transmit-rate exact",
		"set class-of-service schedulers be buffer-size 16m",
	}
	for _, cmd := range cmds {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	if err := config.SchemaValidate(tree, nil); err != nil {
		t.Fatalf("schema validate: %v", err)
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	sched := cfg.ClassOfService.Schedulers["be"]
	if sched == nil {
		t.Fatal("expected be scheduler")
	}
	if got := sched.TransmitRateBytes; got != 1 {
		t.Fatalf("transmit-rate bytes/sec = %d, want 1", got)
	}
	if !sched.TransmitRateExact {
		t.Fatal("expected transmit-rate exact")
	}
	if got := sched.BufferSizeBytes; got != 16000000 {
		t.Fatalf("buffer-size bytes = %d, want 16000000", got)
	}
}

func TestSchemaValidate_PercentBufferSizeCompilesAsPercentNotZeroBytes(t *testing.T) {
	tree := &config.ConfigTree{}
	cmds := []string{
		"set class-of-service schedulers be transmit-rate 8",
		"set class-of-service schedulers be buffer-size 10%",
	}
	for _, cmd := range cmds {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	if err := config.SchemaValidate(tree, nil); err != nil {
		t.Fatalf("schema validate: %v", err)
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	sched := cfg.ClassOfService.Schedulers["be"]
	if sched == nil {
		t.Fatal("expected be scheduler")
	}
	if got := sched.BufferSizePercent; got != 10 {
		t.Fatalf("buffer-size percent = %v, want 10", got)
	}
	if got := sched.BufferSizeBytes; got != 0 {
		t.Fatalf("buffer-size bytes = %d, want 0 for percent form", got)
	}
}

// TestSchemaValidate_AcceptsLegacyDPDKSubStanza is migrated from the
// retired pkg/cmdtree schema_validate_test.go (#1528 fixture-strength
// gate). After #1319 PR 1 the generic walker fans out across ALL
// top-level subtrees (the class-of-service-only early-return is gone), so
// this test now guards a sharper invariant: walking the whole AST must
// still be a no-op for untyped subtrees like the orphaned legacy
// `system dataplane ...` sub-stanzas that survive the
// rewriteRetiredDataplaneType bridge. The cos block forces typed-leaf
// validation to fire; the untyped DPDK leaves must be ignored, not
// rejected (rejecting them would preempt the operator-facing
// ErrDPDKDataplaneRetired path and break stored-config rolling upgrade).
func TestSchemaValidate_AcceptsLegacyDPDKSubStanza(t *testing.T) {
	tree := &config.ConfigTree{}
	for _, line := range []string{
		// class-of-service schedulers block — triggers typed validation.
		"set class-of-service schedulers be-sched transmit-rate 1g",
		"set class-of-service schedulers be-sched priority low",
		"set class-of-service schedulers be-sched buffer-size 10%",
		// Legacy DPDK shape — untyped, must NOT be rejected.
		"set system dataplane-type dpdk",
		"set system dataplane cores 2-5",
		"set system dataplane memory 2048",
		"set system dataplane socket-mem \"1024,1024\"",
		"set system dataplane rx-mode adaptive",
		"set system dataplane rx-mode idle-threshold 256",
		"set system dataplane rx-mode resume-threshold 32",
		"set system dataplane rx-mode sleep-timeout 100",
		"set system dataplane ports 0000:03:00.0 interface wan0",
		"set system dataplane ports 0000:03:00.0 rx-mode polling",
		"set system dataplane ports 0000:03:00.0 cores 2-3",
		"set system dataplane ports 0000:06:00.0 interface trust0",
	} {
		path, err := config.ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	if tree.FindChild("class-of-service") == nil {
		t.Fatal("fixture invalid: class-of-service subtree missing")
	}
	if err := config.SchemaValidate(tree, nil); err != nil {
		t.Fatalf("SchemaValidate rejected legacy DPDK sub-stanza alongside valid cos block: %v", err)
	}
}

// Negative: untyped leaves outside the schedulers subtree are NOT
// validated even though the walker now descends all subtrees. This guards
// the "opt-in per leaf" scope contract.
func TestSchemaValidate_OutsideSchedulersIgnored(t *testing.T) {
	// `buffer-size purple` under a different parent should not error
	// at SchemaValidate (no typed-leaf metadata for it elsewhere).
	if err := schemaCheck(t, `class-of-service {
    interfaces {
        ge-0/0/1 {
            unit 0 {
                shaping-rate 10g {
                    burst-size purple-not-validated;
                }
                scheduler-map edge-map;
            }
        }
    }
}`); err != nil {
		t.Fatalf("expected schedulers-only scope; got error on interfaces subtree: %v", err)
	}
}

// TestSchemaValidate_HierarchicalShorthand_RejectsGarbage reproduces the
// Copilot #1 finding: the parser folds `schedulers { be transmit-rate asd; }`
// into a single node Keys=["be","transmit-rate","asd"] (instance name + leaf
// + value packed together). The walker must consume the instance name AND
// still validate the leftover leaf, or garbage slips through commit-check.
func TestSchemaValidate_HierarchicalShorthand_RejectsGarbage(t *testing.T) {
	for _, in := range []string{
		`class-of-service { schedulers { be transmit-rate asd; } }`,
		`class-of-service { schedulers { be priority foo; } }`,
		`class-of-service { schedulers { be transmit-rate 1g typo; } }`,
	} {
		if err := schemaCheck(t, in); err == nil {
			t.Fatalf("expected rejection for shorthand %q, got nil", in)
		}
	}
}

func TestSchemaValidate_HierarchicalShorthand_AcceptsValid(t *testing.T) {
	for _, in := range []string{
		`class-of-service { schedulers { be transmit-rate 1g; } }`,
		`class-of-service { schedulers { be transmit-rate 1g { exact; } } }`,
		`class-of-service { schedulers { be buffer-size 16m; } }`,
		`class-of-service { schedulers { be priority strict-high; } }`,
	} {
		if err := schemaCheck(t, in); err != nil {
			t.Fatalf("expected shorthand %q to pass, got %v", in, err)
		}
	}
}

// TestSchemaValidate_FullyPackedContainerLeaf reproduces Codex r2 #1: the
// parser folds `class-of-service { schedulers be transmit-rate asd; }` into
// ONE node Keys=["schedulers","be","transmit-rate","asd"] (container
// identity + leaf + value). After consuming the `schedulers be` container
// identity, the leftover ["transmit-rate","asd"] is a packed leaf that must
// still be validated at the child schema level.
func TestSchemaValidate_FullyPackedContainerLeaf(t *testing.T) {
	if err := schemaCheck(t, `class-of-service { schedulers be transmit-rate asd; }`); err == nil {
		t.Fatal("expected rejection for fully-packed container leaf, got nil")
	}
	if err := schemaCheck(t, `class-of-service { schedulers be priority foo; }`); err == nil {
		t.Fatal("expected rejection for fully-packed priority garbage, got nil")
	}
	if err := schemaCheck(t, `class-of-service { schedulers be transmit-rate 1g; }`); err != nil {
		t.Fatalf("expected fully-packed valid leaf to pass, got %v", err)
	}
}

// TestSchemaValidate_ModifierTrailingGarbage reproduces Codex r2 #2: a known
// modifier child must not swallow trailing garbage. `transmit-rate 1g {
// exact bogus; }` (hierarchical) and `set ... transmit-rate 1g exact bogus`
// (flat → exact → bogus nesting) both carry an extra `bogus` token past the
// known `exact` modifier that must be rejected.
func TestSchemaValidate_ModifierTrailingGarbage(t *testing.T) {
	if err := schemaCheck(t, `class-of-service { schedulers { be { transmit-rate 1g { exact bogus; } } } }`); err == nil {
		t.Fatal("expected rejection for `exact bogus` trailing garbage, got nil")
	}
	if err := flatSchemaCheck(t, "set class-of-service schedulers be transmit-rate 1g exact bogus"); err == nil {
		t.Fatal("expected rejection for flat `transmit-rate 1g exact bogus`, got nil")
	}
	// The clean `exact` modifier still passes both shapes.
	if err := schemaCheck(t, `class-of-service { schedulers { be { transmit-rate 1g { exact; } } } }`); err != nil {
		t.Fatalf("expected clean `exact` modifier to pass, got %v", err)
	}
	if err := flatSchemaCheck(t,
		"set class-of-service schedulers be transmit-rate 1g",
		"set class-of-service schedulers be transmit-rate exact",
	); err != nil {
		t.Fatalf("expected split exact to pass, got %v", err)
	}
}

// TestSchemaValidate_PackedSiblingSplitModifier reproduces Codex r3 minor:
// the packed-leftover fix must not break the cross-sibling split-modifier
// rule. Two sibling packed nodes — a rate and a bare `exact` — are valid
// together (the `exact` sees its rate sibling), across all three AST
// shapes the parser produces for the split form.
func TestSchemaValidate_PackedSiblingSplitModifier(t *testing.T) {
	for _, in := range []string{
		// Fully-packed sibling nodes under class-of-service.
		`class-of-service {
		    schedulers be transmit-rate 1g;
		    schedulers be transmit-rate exact;
		}`,
		// Instance-name nested, leaf packed, two sibling instances.
		`class-of-service { schedulers { be transmit-rate 1g; be transmit-rate exact; } }`,
		// Fully nested block.
		`class-of-service { schedulers { be { transmit-rate 1g; transmit-rate exact; } } }`,
	} {
		if err := schemaCheck(t, in); err != nil {
			t.Fatalf("expected split-modifier shorthand %q to pass, got %v", in, err)
		}
	}
	// A bare `exact` packed sibling with NO rate sibling still fails.
	if err := schemaCheck(t, `class-of-service { schedulers be transmit-rate exact; }`); err == nil {
		t.Fatal("expected exact-only packed leaf (no rate sibling) to fail, got nil")
	}
}

// TestSetPathGrouping_Golden pins the flat-set grouping produced by
// SetPath over setSchema. #1319 PR 1 adds typed-leaf FIELDS to schemaNode
// (valueType/valueDesc/valueExamples/validator) but MUST NOT add or alter
// any `children` map — SetPath's replace-vs-container decision keys on
// children==nil (ast_edit.go:196), so flipping a leaf to a container is a
// grouping regression. This golden re-serializes a representative config
// (including the schedulers typed leaves and the `destination-port <lo> to
// <hi>` value-tail/range shape) and asserts the round-trip is byte-stable.
// If a future edit adds children to a typed leaf, the schedulers grouping
// changes here and this test fires.
//
// Codex minor #2: to actually exercise the `children == nil` REPLACE path
// (ast_edit.go:196 — a single-value leaf with no children is replaced, not
// appended), `priority` is set TWICE with different values. With
// children==nil the second set replaces the first, so only the latter value
// survives in the golden. If `priority` ever gained a children map, SetPath
// would treat it as a named container and APPEND a duplicate sibling instead
// of replacing — producing two `priority` lines and failing this golden.
func TestSetPathGrouping_Golden(t *testing.T) {
	tree := &config.ConfigTree{}
	cmds := []string{
		"set class-of-service schedulers be transmit-rate 1g",
		"set class-of-service schedulers be transmit-rate exact",
		"set class-of-service schedulers be priority strict-high",
		"set class-of-service schedulers be priority medium-high",
		"set class-of-service schedulers be buffer-size 16m",
		"set firewall family inet filter f1 term t1 from destination-port 20000 to 20003",
		"set security policies from-zone trust to-zone untrust policy p1 match source-address any",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
	}
	for _, cmd := range cmds {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	const golden = `set class-of-service schedulers be transmit-rate 1g
set class-of-service schedulers be transmit-rate exact
set class-of-service schedulers be priority medium-high
set class-of-service schedulers be buffer-size 16m
set firewall family inet filter f1 term t1 from destination-port 20000 to 20003
set security policies from-zone trust to-zone untrust policy p1 match source-address any
set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24
`
	if got := tree.FormatSet(); got != golden {
		t.Fatalf("SetPath grouping changed (typed-leaf fields must not alter grouping):\n--- got ---\n%s\n--- want ---\n%s", got, golden)
	}
}

// Validator unit tests — keep these close to the validator code so a
// failed test points at the validator rather than the AST walker.

func TestValidateRate(t *testing.T) {
	good := []string{"100", "100k", "10m", "1g", "10g", "8k"}
	for _, g := range good {
		if err := config.ValidateRate(g, nil); err != nil {
			t.Errorf("ValidateRate(%q): unexpected error %v", g, err)
		}
	}
	bad := []string{"", "1", "7", "asd", "-1", "1x", "1.0z"}
	for _, b := range bad {
		if err := config.ValidateRate(b, nil); err == nil {
			t.Errorf("ValidateRate(%q): expected error", b)
		}
	}
}

func TestValidateByteSize(t *testing.T) {
	good := []string{"16m", "256k", "1g"}
	for _, g := range good {
		if err := config.ValidateByteSize(g, nil); err != nil {
			t.Errorf("ValidateByteSize(%q): unexpected error %v", g, err)
		}
	}
	bad := []string{"", "0", "50", "100", "150", "purple", "-5", "1.5"}
	for _, b := range bad {
		if err := config.ValidateByteSize(b, nil); err == nil {
			t.Errorf("ValidateByteSize(%q): expected error", b)
		}
	}
}

func TestValidateByteSizeOrPercent(t *testing.T) {
	good := []string{"16m", "256k", "1g", "10%", "12.5%"}
	for _, g := range good {
		if err := config.ValidateByteSizeOrPercent(g, nil); err != nil {
			t.Errorf("ValidateByteSizeOrPercent(%q): unexpected error %v", g, err)
		}
	}
	bad := []string{"", "0", "50", "100", "purple", "-5", "1.5", "0%", "-1%", "101%", "NaN%"}
	for _, b := range bad {
		if err := config.ValidateByteSizeOrPercent(b, nil); err == nil {
			t.Errorf("ValidateByteSizeOrPercent(%q): expected error", b)
		}
	}
}

func TestValidateEnum(t *testing.T) {
	v := config.ValidateEnum([]string{"low", "high"})
	if err := v("low", nil); err != nil {
		t.Errorf("ValidateEnum low: unexpected error %v", err)
	}
	if err := v("LOW", nil); err == nil {
		t.Errorf("ValidateEnum LOW: expected case-sensitive error")
	}
	if err := v("foo", nil); err == nil {
		t.Errorf("ValidateEnum foo: expected error")
	}
}

func TestValidateInteger(t *testing.T) {
	v := config.ValidateInteger(0, 100)
	if err := v("50", nil); err != nil {
		t.Errorf("ValidateInteger 50: unexpected error %v", err)
	}
	if err := v("200", nil); err == nil {
		t.Errorf("ValidateInteger 200: expected out-of-range error")
	}
	if err := v("abc", nil); err == nil {
		t.Errorf("ValidateInteger abc: expected non-integer error")
	}
}

func TestValidatePercent(t *testing.T) {
	v := config.ValidatePercent(0, 100)
	if err := v("50", nil); err != nil {
		t.Errorf("ValidatePercent 50: unexpected error %v", err)
	}
	if err := v("0.5", nil); err != nil {
		t.Errorf("ValidatePercent 0.5: unexpected error %v", err)
	}
	if err := v("150", nil); err == nil {
		t.Errorf("ValidatePercent 150: expected out-of-range error")
	}
}
