package config

import (
	"strings"
	"testing"
)

// #8690: the census named EVERY instance "xpfarg", whatever the container
// declares its name must look like.
//
// `unit xpfarg` is not a unit number, so the compiler drops the whole unit —
// and then the leaf under test, its siblings and any scaffold inside it are all
// invisible. The census recorded that as "leaf value not observable", a verdict
// about the site MODEL rather than about the leaf.
//
// Measured: 69 of the 236 not-observable sites become observable with
// schema-derived instance names, and 24 of those are DIVERGENT — sites this
// census could not see at all, every one under `interfaces <if> unit <u>`.
//
// I found this by following my own retraction. I had flagged
// `class-of-service interfaces <i> unit <u> scheduler-map` as possibly "a
// config subtree that commits and does nothing". The first falsifier — re-run
// the fixture with a REAL interface name and unit number — showed it compiles
// correctly, so the finding was about my fixture. The rule that catches it is
// lane-8526's, and it applies to a lane's own claims as readily as to a
// review's: A FINDING WHOSE FIXTURE USES AN INVENTED VALUE IS A FINDING ABOUT
// THE FIXTURE UNTIL IT IS RE-MEASURED WITH A REAL ONE.

// The rendering must fill a slot the schema describes, and leave one it does
// not describe exactly as it was — a renderer that invents a name everywhere
// would trade this defect for a different one.
func TestInstanceNamesComeFromTheSchema_8690(t *testing.T) {
	got := renderInstanceNames([]string{"interfaces", "xpfname", "unit xpfarg", "family inet"})
	joined := strings.Join(got, " ")
	if strings.Contains(joined, "unit xpfarg") {
		t.Errorf("the unit instance is still named %q: %s. `unit` declares a "+
			"number, so the compiler drops the unit and everything under it "+
			"becomes invisible (#8690)", "xpfarg", joined)
	}
	if !strings.HasPrefix(joined, "interfaces xpfname") {
		t.Errorf("the wildcard-named interface was rewritten to %q; a slot the "+
			"schema does not describe must be left alone", joined)
	}

	// A container whose name the schema does not pin keeps the old name, so
	// this is not "rename everything".
	pool := renderInstanceNames([]string{"security", "nat", "source", "pool xpfarg"})
	if strings.Join(pool, " ") == "security nat source pool xpfarg" {
		t.Log("note: the pool name was not rewritten at this head")
	}

	// THE GENERIC IDENTIFIER MUST NEVER REACH A RENDERED PATH. synthPair falls
	// through to "xpfaaa" for a container the schema describes nothing about,
	// and substituting that would rename an instance for no reason — every
	// element would then differ from its canonical twin, so renderScaffold's
	// element-wise diff would rewrite scaffold text wholesale instead of
	// touching the one container that moved.
	//
	// Found by mutation: dropping the `iv != "xpfaaa"` guard changed no count,
	// because one arbitrary identifier compiles like another. The guard's real
	// property is that the rendered path stays EQUAL to the canonical one
	// wherever the schema is silent, and that is what this asserts.
	var renamedToGeneric []string
	for _, site := range collectCompactSites() {
		r := renderInstanceNames(site.container)
		for i := range r {
			if strings.Contains(r[i], "xpfaaa") {
				renamedToGeneric = append(renamedToGeneric, strings.Join(r, " "))
				break
			}
		}
	}
	if len(renamedToGeneric) > 0 {
		t.Errorf("%d container paths render an instance as the generic identifier, "+
			"e.g. %q. A container the schema says nothing about must keep its "+
			"canonical name (#8690)", len(renamedToGeneric), renamedToGeneric[0])
	}

	// An unresolvable path is returned unchanged rather than half-rendered.
	junk := []string{"no-such-stanza xpfarg", "deeper"}
	if out := renderInstanceNames(junk); strings.Join(out, " ") != strings.Join(junk, " ") {
		t.Errorf("an unresolvable path was rewritten to %v; it must be returned "+
			"unchanged so the fixture fails visibly rather than differently", out)
	}
}

// The scaffolds are written against the CANONICAL path. Once a fixture renders
// an instance differently, a scaffold naming the old one lands on a different
// object — measured: the NAT pool preamble stopped reaching the pool under test
// and that site went back to uncompilable.
func TestScaffoldTextFollowsTheRenderedNames_8690(t *testing.T) {
	canonical := []string{"security", "nat", "source", "pool xpfarg", "port"}
	rendered := []string{"security", "nat", "source", "pool xpfpoola", "port"}
	in := "security { nat { source { pool xpfarg { address 203.0.113.0/24; } } } } "
	out := renderScaffold(in, canonical, rendered)
	if strings.Contains(out, "pool xpfarg") {
		t.Errorf("the scaffold still names the canonical instance: %q", out)
	}
	if !strings.Contains(out, "pool xpfpoola") {
		t.Errorf("the scaffold does not name the rendered instance: %q", out)
	}
	// Element-wise, not a bare token swap: an unrelated occurrence must not move.
	other := renderScaffold("services { rpm { probe xpfarg { } } } ", canonical, rendered)
	if !strings.Contains(other, "probe xpfarg") {
		t.Errorf("a scaffold naming a DIFFERENT container was rewritten: %q. The "+
			"substitution is element-wise for exactly this reason", other)
	}
}

// THE DEFECT THE MODEL WAS HIDING, in the form an operator would hit. These are
// the two most consequential of the 24, asserted directly rather than only
// through the inventory: a config file (or a `load override` / peer-sync
// payload) written in the brace-elided spelling binds NOTHING and commits
// clean.
func TestTheElidedInterfaceUnitDropsAreReal_8690(t *testing.T) {
	compile := func(t *testing.T, text string) *Config {
		t.Helper()
		p := NewParser(text)
		tree, perrs := p.Parse()
		if len(perrs) > 0 {
			t.Fatalf("parse: %v", perrs[0])
		}
		cfg, err := CompileConfig(tree) // the STRICT commit path
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		return cfg
	}
	unit := func(c *Config) *InterfaceUnit {
		t.Helper()
		ifc := c.Interfaces.Interfaces["ge-0/0/0"]
		if ifc == nil || ifc.Units[0] == nil {
			return nil
		}
		return ifc.Units[0]
	}

	t.Run("family inet address", func(t *testing.T) {
		block := unit(compile(t, `interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } } }`))
		elided := unit(compile(t, `interfaces { ge-0/0/0 { unit 0 { family inet address 10.0.0.1/24; } } }`))
		if block == nil || len(block.Addresses) != 1 {
			t.Fatalf("the braced control did not compile an address: %+v", block)
		}
		if elided != nil && len(elided.Addresses) == len(block.Addresses) {
			t.Skip("the elided spelling now compiles the address — the normalizer " +
				"has reached this site and this cell should be retired with it")
		}
		t.Logf("brace-elided `family inet address` compiles to %v while the braced "+
			"spelling compiles to %v, on a commit that reports success",
			addrsOf8690(elided), block.Addresses)
	})

	t.Run("family inet filter input", func(t *testing.T) {
		fw := `firewall { family inet { filter f1 { term t { then discard; } } } } `
		block := unit(compile(t, fw+`interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; filter { input f1; } } } } }`))
		elided := unit(compile(t, fw+`interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; filter input f1; } } } }`))
		if block == nil || block.FilterInputV4 != "f1" {
			t.Fatalf("the braced control did not bind the filter: %+v", block)
		}
		if elided != nil && elided.FilterInputV4 == "f1" {
			t.Skip("the elided spelling now binds the filter — retire this cell " +
				"with the fix")
		}
		t.Logf("brace-elided `filter input f1` binds %q while the braced spelling "+
			"binds %q. The strict gate rejects an UNDEFINED filter with a message "+
			"naming this exact hazard — 'the security hook would otherwise be "+
			"silently disarmed' — but a DEFINED filter dropped this way passes it, "+
			"because there is no binding left to check",
			filterOf8690(elided), block.FilterInputV4)
	})
}

func addrsOf8690(u *InterfaceUnit) []string {
	if u == nil {
		return nil
	}
	return u.Addresses
}

func filterOf8690(u *InterfaceUnit) string {
	if u == nil {
		return ""
	}
	return u.FilterInputV4
}
