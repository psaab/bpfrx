package userspace

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #5717 / #5628 tolerant-load parity for the NAT terminal-action cardinality
// gate.
//
// validateNATTerminalActionCardinalityStrict hard-rejects a NAT rule whose
// `then` block carries zero or two+ mutually-exclusive terminal actions at
// strict commit, but the tolerant load / peer-sync path only WARNS (#1960
// no-brick). So a pre-#5628 persisted config, or one arriving over HA config
// sync, still reaches the snapshot builder malformed. The gate's contract
// rests on ONE claim about what happens next — "the Rust dataplane's
// off-precedence governs (off wins -> exempt)" — and before #5717 nothing
// bound the Go half of that claim: the only tolerant-path test
// (TestNATTerminalActionLenientWarns_5628, pkg/config) covers a zero-action
// DNAT rule and asserts only that a warning STRING appears. It never looks at
// the published snapshot, never covers source NAT, and never covers a
// contradictory (two-action) rule at all.
//
// These tests bind the Go half end-to-end: tolerant compile -> published
// snapshot. The Rust half (the matcher actually honouring `off` over a
// contradictory action) is bound by
// off_wins_over_contradictory_{interface,pool}_action_5717 in
// userspace-dp/src/nat/tests_source.rs.

// compileSetLenient5717 builds a typed config from a flat-set command list on
// the TOLERANT path (CompileConfigLenient) — the load / peer-sync compiler,
// which downgrades the #5628 gate to a warning instead of rejecting. Using the
// ParseSetCommand + SetPath loop is mandatory here: NewParser treats newlines
// as whitespace and would merge every set line into one node.
func compileSetLenient5717(t *testing.T, cmds []string) *config.Config {
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
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient must NOT brick on a malformed NAT rule "+
			"(#1960 no-brick): %v", err)
	}
	return cfg
}

// compileHierLenient5717 is the hierarchical-AST counterpart. The compiler must
// handle BOTH AST shapes, and the #5628 setter change (an `else if` chain to
// independent `if`s) lives on the hierarchical branch specifically — a
// single-node `source-nat { off; pool p1; }` is only reachable this way.
func compileHierLenient5717(t *testing.T, text string) *config.Config {
	t.Helper()
	p := config.NewParser(text)
	tree, perrs := p.Parse()
	if len(perrs) > 0 {
		t.Fatalf("Parse: %v", perrs)
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient must NOT brick on a malformed NAT rule "+
			"(#1960 no-brick): %v", err)
	}
	return cfg
}

func sourceSnapByName5717(t *testing.T, snaps []SourceNATRuleSnapshot, name string) *SourceNATRuleSnapshot {
	t.Helper()
	for i := range snaps {
		if snaps[i].Name == name {
			return &snaps[i]
		}
	}
	t.Fatalf("no source-NAT snapshot published for rule %q; got %d entries: %+v",
		name, len(snaps), snaps)
	return nil
}

// TestTolerantContradictorySNATCarriesOff_5717 pins that a leniently-loaded
// source-NAT rule carrying TWO terminal actions publishes BOTH of them to the
// dataplane, in both AST shapes. Carrying both is what makes the Rust
// off-precedence reachable: if the compiler collapsed the pair to a single
// field it could keep the TRANSLATING one and drop the exemption, publishing
// the inverse of the authored action with no warning at the dataplane
// boundary.
//
// Every sub-test here is `off`-BEARING, which is what the name asserts. The
// `off`-less contradiction (`interface` + `pool`) resolves the other way and
// lives in TestTolerantContradictorySNATWithoutOffCarriesBothActions_5717.
//
// RED on revert: restoring the pre-#5628 `else if` chain in
// compiler_nat_source.go's hierarchical branch makes the single-node
// `source-nat { off; pool p1; }` resolve to ONE field, so the surviving-field
// assertions fail.
func TestTolerantContradictorySNATCarriesOff_5717(t *testing.T) {
	t.Run("flat off+pool", func(t *testing.T) {
		cfg := compileSetLenient5717(t, []string{
			"set security nat source pool p1 address 203.0.113.10",
			"set security nat source rule-set rs1 from zone trust",
			"set security nat source rule-set rs1 to zone untrust",
			"set security nat source rule-set rs1 rule r1 match source-address 10.0.0.0/24",
			"set security nat source rule-set rs1 rule r1 then source-nat off",
			"set security nat source rule-set rs1 rule r1 then source-nat pool p1",
		})
		s := sourceSnapByName5717(t, buildSourceNATSnapshots(cfg, nil), "r1")
		if !s.Off {
			t.Errorf("tolerant contradictory SNAT snapshot Off = false, want true — "+
				"the exemption was dropped on the way to the dataplane, so the Rust "+
				"off-precedence the #5628 gate relies on can never fire: %+v", s)
		}
		if s.PoolName != "p1" {
			t.Errorf("tolerant contradictory SNAT snapshot PoolName = %q, want p1 — "+
				"the contradiction must stay VISIBLE in the published rule, not be "+
				"silently collapsed by the compiler", s.PoolName)
		}
	})

	t.Run("hierarchical single-node off+pool", func(t *testing.T) {
		cfg := compileHierLenient5717(t, `
security {
  nat {
    source {
      pool p1 { address 203.0.113.10; }
      rule-set rs1 {
        from zone trust;
        to zone untrust;
        rule r1 {
          match { source-address 10.0.0.0/24; }
          then { source-nat { off; pool p1; } }
        }
      }
    }
  }
}`)
		s := sourceSnapByName5717(t, buildSourceNATSnapshots(cfg, nil), "r1")
		if !s.Off {
			t.Errorf("hierarchical contradictory SNAT snapshot Off = false, want true "+
				"(pre-#5628 `else if` chain kept one field only): %+v", s)
		}
		if s.PoolName != "p1" {
			t.Errorf("hierarchical contradictory SNAT snapshot PoolName = %q, want p1 "+
				"(pre-#5628 `else if` chain kept one field only)", s.PoolName)
		}
	})

	t.Run("hierarchical single-node interface+off", func(t *testing.T) {
		cfg := compileHierLenient5717(t, `
security {
  nat {
    source {
      rule-set rs1 {
        from zone trust;
        to zone untrust;
        rule r1 {
          match { source-address 10.0.0.0/24; }
          then { source-nat { interface; off; } }
        }
      }
    }
  }
}`)
		s := sourceSnapByName5717(t, buildSourceNATSnapshots(cfg, nil), "r1")
		if !s.Off {
			t.Errorf("hierarchical `interface; off` snapshot Off = false, want true — "+
				"dropping the exemption here makes the rule translate the source onto "+
				"the egress interface, the inverse of the authored action: %+v", s)
		}
		if !s.InterfaceMode {
			t.Errorf("hierarchical `interface; off` snapshot InterfaceMode = false, " +
				"want true (pre-#5628 `else if` chain kept one field only)")
		}
	})
}

// TestTolerantContradictorySNATWithoutOffCarriesBothActions_5717 pins the
// `off`-LESS contradiction: `interface` + `pool p1`. It is a separate top-level
// test rather than a sub-test of TestTolerantContradictorySNATCarriesOff_5717
// because it asserts Off=false — nesting an Off=false case under a
// "CarriesOff" parent misdescribes both.
//
// The Rust-side counterpart (interface_wins_over_pool_without_off_5717 and
// interface_with_pool_no_egress_fails_closed_5717) constructs its snapshot
// DIRECTLY, so it cannot see a Go edit that drops the pool whenever
// InterfaceMode is true — the Rust tests would still pass, because interface
// mode wins there either way. This test is what binds the Go builder.
//
// What surviving both fields buys, precisely: the published rule keeps the
// contradiction, so the strict gate still counts TWO terminal actions and
// rejects the rule on the next commit, and the Rust matcher still sees a
// pool-mode rule whose `interface` precedence it must honour. It does NOT keep
// the contradiction visible to `show`: both source-NAT renderers select ONE
// action to display — pkg/cli/cli_show_nat.go initialises `action` as
// "interface" and overwrites it with `pool <name>` whenever PoolName is
// non-empty, and pkg/natshow/source.go does the same (with `off` as a third,
// lower-precedence branch) — so an `interface` + `pool p1` rule renders as
// `pool p1` and the operator sees no contradiction at all. The
// operator-visible signal for this rule is the tolerant-path WARNING asserted
// below, not the `show` output.
func TestTolerantContradictorySNATWithoutOffCarriesBothActions_5717(t *testing.T) {
	cfg := compileHierLenient5717(t, `
security {
  nat {
    source {
      pool p1 { address 203.0.113.10; }
      rule-set rs1 {
        from zone trust;
        to zone untrust;
        rule r1 {
          match { source-address 10.0.0.0/24; }
          then { source-nat { interface; pool p1; } }
        }
      }
    }
  }
}`)
	s := sourceSnapByName5717(t, buildSourceNATSnapshots(cfg, nil), "r1")
	if !s.InterfaceMode {
		t.Errorf("`interface; pool` snapshot InterfaceMode = false, want true: %+v", s)
	}
	if s.PoolName != "p1" {
		t.Errorf("`interface; pool` snapshot PoolName = %q, want p1 — dropping the "+
			"pool here hides the contradiction from the published rule; the Rust "+
			"precedence test cannot catch it because interface mode wins regardless",
			s.PoolName)
	}
	// PoolAddresses is asserted separately from PoolName because the two are
	// independently droppable and only this one decides pool_mode in Rust:
	// `parse_source_nat_rules` sets pool_mode from
	// `!pool_name.is_empty() || !pool_addresses.is_empty()`, and the resolved
	// addresses are what an allocation would actually translate onto. A builder
	// edit that kept PoolName but dropped the resolved addresses left the
	// PoolName-only assertion GREEN (mutation-measured), so the "both fields
	// survive" claim was only half-bound.
	if len(s.PoolAddresses) != 1 || s.PoolAddresses[0] != "203.0.113.10" {
		t.Errorf("`interface; pool` snapshot PoolAddresses = %v, want [203.0.113.10] — "+
			"the resolved pool must survive too, not just its NAME: the Rust matcher "+
			"derives pool_mode from either field and an allocation translates onto "+
			"these addresses", s.PoolAddresses)
	}
	if s.Off {
		t.Errorf("`interface; pool` snapshot Off = true, want false — there is no "+
			"`off` in this rule and inventing one would flip a translation into an "+
			"exemption: %+v", s)
	}
	// The snapshot assertions above all stay GREEN if the #5628 cardinality
	// gate is deleted outright — the builder happily publishes both fields with
	// no gate at all. The gate's tolerant-path warning is the ONLY thing that
	// tells an operator this rule is malformed (see the `show` note above), so
	// bind it here alongside the fields it is warning about.
	requireCardinalityWarning5717(t, cfg, "r1")
}

// requireCardinalityWarning5717 asserts the tolerant compile recorded the #5628
// terminal-action cardinality warning naming the given rule. The tolerant path
// downgrades validateNATTerminalActionCardinalityStrict's hard error to a
// cfg.Warnings entry (#1960 no-brick, compiler_uniformgates_firewall_nat2.go);
// asserting the rule NAME as well as the prefix keeps this from passing on some
// unrelated cardinality warning.
func requireCardinalityWarning5717(t *testing.T, cfg *config.Config, rule string) {
	t.Helper()
	const prefix = "NAT terminal-action cardinality"
	want := `rule "` + rule + `"`
	for _, w := range cfg.Warnings {
		if strings.Contains(w, prefix) && strings.Contains(w, want) {
			return
		}
	}
	t.Errorf("tolerant compile recorded no %q warning naming %s; got %d warnings: %v — "+
		"without it a malformed rule loads silently and the operator has no signal "+
		"at all, since `show` renders one selected action rather than the contradiction",
		prefix, want, len(cfg.Warnings), cfg.Warnings)
}

// TestTolerantContradictoryDNATResolvesExempt_5717 pins the DNAT half, where
// the precedence decision is made in GO rather than in Rust: the destination
// snapshot builder's `isOff` short-circuit
// (pkg/dataplane/userspace/nat_destination.go) must publish a pool-less
// EXEMPTION entry for a contradictory `off` + `pool` rule, never a translating
// entry pointing at the pool address.
//
// RED on revert: dropping the `if !isOff` guard around the pool lookup makes
// the builder resolve and attach the pool address, so PoolAddress is no longer
// empty — the exemption publishes as a translation to 10.0.0.5.
func TestTolerantContradictoryDNATResolvesExempt_5717(t *testing.T) {
	check := func(t *testing.T, cfg *config.Config) {
		t.Helper()
		snaps := buildDestinationNATSnapshots(cfg, nil)
		if len(snaps) != 1 {
			t.Fatalf("expected exactly 1 DNAT snapshot entry, got %d: %+v", len(snaps), snaps)
		}
		s := snaps[0]
		if !s.Off {
			t.Errorf("tolerant contradictory DNAT snapshot Off = false, want true — "+
				"the exemption was lost: %+v", s)
		}
		if s.PoolAddress != "" {
			t.Errorf("tolerant contradictory DNAT snapshot PoolAddress = %q, want empty "+
				"— an exemption entry must carry NO pool, otherwise the authored "+
				"exemption publishes as a translation to that address", s.PoolAddress)
		}
	}

	t.Run("flat off+pool", func(t *testing.T) {
		check(t, compileSetLenient5717(t, []string{
			"set security nat destination pool dp1 address 10.0.0.5",
			"set security nat destination rule-set rd1 from zone untrust",
			"set security nat destination rule-set rd1 rule r1 match destination-address 192.0.2.10/32",
			"set security nat destination rule-set rd1 rule r1 then destination-nat off",
			"set security nat destination rule-set rd1 rule r1 then destination-nat pool dp1",
		}))
	})

	t.Run("hierarchical single-node pool+off", func(t *testing.T) {
		check(t, compileHierLenient5717(t, `
security {
  nat {
    destination {
      pool dp1 { address 10.0.0.5; }
      rule-set rd1 {
        from zone untrust;
        rule r1 {
          match { destination-address 192.0.2.10/32; }
          then { destination-nat { pool dp1; off; } }
        }
      }
    }
  }
}`)) // pool listed FIRST: `off` must still win, not lose to child order.
	})
}

// TestTolerantActionlessRuleIsNotInert_5717 pins the ACTUAL disposition of a
// leniently-loaded ZERO-action rule, which the #5628 contract comment
// previously described as "inert (installs nothing)".
//
// That description is wrong for source NAT in the way that matters. The
// builder EMITS the rule — it is present in the published snapshot with no
// terminal action — and the Rust matcher's `else` arm
// (userspace-dp/src/nat/source.rs) then clears the tentative counter and
// CONTINUES to the next rule, so matching traffic is translated by the later,
// broader rule. That is the fail-open the gate's own strict rejection text
// names. Destination NAT reaches the same outcome by a different mechanism:
// the builder skips the rule entirely, so the traffic likewise falls through.
//
// This test asserts today's behavior, not a desired one — see the #5717
// scoping note for why changing it is a migration-contract decision. It exists
// so the "inert" framing cannot silently return.
func TestTolerantActionlessRuleIsNotInert_5717(t *testing.T) {
	t.Run("source NAT emits the actionless rule", func(t *testing.T) {
		cfg := compileSetLenient5717(t, []string{
			"set security nat source rule-set rs1 from zone trust",
			"set security nat source rule-set rs1 to zone untrust",
			"set security nat source rule-set rs1 rule r0 match source-address 10.0.0.0/24",
		})
		s := sourceSnapByName5717(t, buildSourceNATSnapshots(cfg, nil), "r0")
		if s.Off || s.InterfaceMode || s.PoolName != "" {
			t.Fatalf("actionless SNAT rule published a terminal action %+v; the "+
				"tolerant path must not invent one", s)
		}
		// The rule IS published — "installs nothing" describes the action, not
		// the rule. sourceSnapByName5717 already failed the test if it were
		// absent; this comment records why that matters.
	})

	t.Run("destination NAT drops the actionless rule", func(t *testing.T) {
		cfg := compileSetLenient5717(t, []string{
			"set security nat destination rule-set rd1 from zone untrust",
			"set security nat destination rule-set rd1 rule r0 match destination-address 192.0.2.10/32",
		})
		if snaps := buildDestinationNATSnapshots(cfg, nil); len(snaps) != 0 {
			t.Fatalf("actionless DNAT rule published %d snapshot entries, want 0: %+v",
				len(snaps), snaps)
		}
	})
}
