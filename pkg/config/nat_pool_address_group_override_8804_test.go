package config

import "testing"

// #8804 follow-up. Declaring the source NAT pool `address` leaf with
// multi:true made it leaf-list ELIGIBLE (isLeafListSchema requires multi), so
// apply-groups switched from scalar OVERRIDE to token UNION and a pool carried
// an address the operator believed they had replaced.
//
// The remedy is groupReplace, NOT dropping multi: multi governs FLAT-SET token
// absorption rather than validation, so removing it leaves SchemaValidate green
// while silently changing the compiled result (14 NAT cells red, measured).
func TestNATPoolAddressGroupOverride8804(t *testing.T) {
	cfgText := func(inline string) string {
		return "groups { g1 { security { nat { source { pool p1 { address 10.0.0.9/32; } } } } } } " +
			"apply-groups g1; " +
			"security { zones { security-zone z1 { host-inbound-traffic { system-services ping; } } " +
			"security-zone z2 { host-inbound-traffic { system-services ping; } } } " +
			"nat { source { pool p1 { " + inline + " } " +
			"rule-set rs1 { from zone z1; to zone z2; rule r1 { match { source-address 10.0.0.0/8; } " +
			"then { source-nat { pool p1; } } } } } } }"
	}
	get := func(t *testing.T, txt string) []string {
		t.Helper()
		tr, perrs := NewParser(txt).Parse()
		if len(perrs) > 0 {
			t.Fatalf("parse: %v", perrs)
		}
		cfg, err := CompileConfigLenient(tr)
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		for _, p := range cfg.Security.NAT.SourcePools {
			if p.Name == "p1" {
				return p.Addresses
			}
		}
		return nil
	}

	// An INLINE address must OVERRIDE the group's, not union with it.
	got := get(t, cfgText("address 10.0.0.1/32;"))
	if len(got) != 1 || got[0] != "10.0.0.1/32" {
		t.Errorf("apply-groups over a source NAT pool address: got %v, want [10.0.0.1/32]\n"+
			"The inline statement must OVERRIDE the inherited one. Getting BOTH "+
			"addresses means the `address` leaf has lost groupReplace and is being "+
			"token-UNIONed as a leaf-list (isLeafListSchema, ast_groups.go, requires "+
			"multi && !groupReplace). Do NOT fix that by dropping multi -- multi "+
			"governs flat-set token absorption, not validation, so dropping it "+
			"leaves SchemaValidate green while changing the compiled result and "+
			"reds 14 NAT cells (#4521, #4422, #5144, #6812, deterministic-NAT).", got)
	}

	// With NO inline address the group's value must still be INHERITED --
	// otherwise this cell would pass just as well if apply-groups stopped
	// working entirely.
	got = get(t, cfgText("port no-translation;"))
	if len(got) != 1 || got[0] != "10.0.0.9/32" {
		t.Errorf("with no inline address the group's must be inherited: got %v, want [10.0.0.9/32]", got)
	}
}
