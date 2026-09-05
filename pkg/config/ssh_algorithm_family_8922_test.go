package config

import (
	"sort"
	"strings"
	"testing"
)

// issue 8922: THE SSH ALGORITHM-LIST FAMILY IS ADMITTED AS A SET.
//
// `system services ssh` declares three algorithm lists -- `key-exchange`,
// `ciphers`, `macs`. They are schema-identical (args:1, multi:true, validator
// ValidateSSHAlgorithm, children nil), read by the same loop over
// firewallMatchValues into three parallel fields, and each renders one line of
// the same sshd drop-in (daemon_hostauth_apply.go:831-842).
//
// `key-exchange` was admitted to the brace-elision fold and the other two were
// not. The consequence is worse than a plain drop: a config hardening all three
// applied KexAlgorithms and silently ignored Ciphers/MACs, because an empty list
// writes NO line at all and sshd keeps its permissive built-in default.
// PARTIAL APPLICATION READS AS SUCCESS -- the drop-in visibly carries the
// operator's key-exchange line, so the change looks landed.
//
// The comment above the key-exchange reader (compiler_system.go) describes this
// exact failure -- "a hardening change that appears applied and is not" -- and
// was written while fixing one leaf of three.
//
// THE FAMILY IS DERIVED FROM THE SCHEMA, NOT LISTED HERE. A literal list would
// need editing by the same person who forgets the siblings; a derived one makes
// a FOURTH algorithm list fail this test on the day it is declared. The
// discriminator is the shape the three share and nothing else under `ssh` does:
// a multi-value identifier list.
func TestSSHAlgorithmListsAreAdmittedTogether8922(t *testing.T) {
	ssh := schemaForPath("system", "services", "ssh")
	if ssh == nil {
		t.Fatal("no `system services ssh` schema node -- this guard is measuring " +
			"nothing (issue 8922)")
	}
	var family, missing []string
	for name, ch := range ssh.children {
		if ch == nil || !ch.multi || ch.args != 1 || ch.valueType != ValueIdentifier {
			continue
		}
		family = append(family, name)
		if !compactNormalizeInScope("ssh", name) {
			missing = append(missing, name)
		}
	}
	sort.Strings(family)
	sort.Strings(missing)

	// A derived family that derives NOTHING would pass silently, so bind the
	// derivation itself: the three known members must be in it. If the schema
	// shape changes so this predicate stops selecting them, that is a change to
	// what this guard covers and must be seen, not absorbed.
	for _, want := range []string{"ciphers", "key-exchange", "macs"} {
		found := false
		for _, f := range family {
			if f == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%q is no longer selected as an SSH algorithm list "+
				"(multi + args:1 + ValueIdentifier). Either the leaf was "+
				"reshaped or the predicate no longer matches the family -- in "+
				"the second case this guard has quietly stopped covering the "+
				"siblings it exists for. family=%v (issue 8922)", want, family)
		}
	}

	if len(missing) > 0 {
		t.Errorf("SSH algorithm list(s) %v are NOT admitted by "+
			"compactNormalizeInScope while their sibling(s) are. family=%v\n"+
			"  All members render into the SAME sshd drop-in, so admitting a "+
			"subset produces the failure this guard exists for: the brace-elided "+
			"spelling delivers the admitted lists and silently drops the rest, "+
			"an empty list writes NO sshd line, and sshd falls back to its "+
			"permissive default. The operator sees their other lines applied and "+
			"concludes the change landed.\n"+
			"  If a member is being EXCLUDED deliberately, say so where the "+
			"exclusion lives and give it a reason that is not 'nobody added it' "+
			"-- that is how the first two came to be missing (issue 8922).",
			missing, family)
	}
}

// The end-to-end statement of the defect: the brace-elided spelling must deliver
// what the braced one delivers, for every member of the family.
func TestElidedSSHAlgorithmListsSurvive8922(t *testing.T) {
	for _, tc := range []struct{ leaf, value string }{
		{"ciphers", "aes256-ctr"},
		{"macs", "hmac-sha2-256"},
		{"key-exchange", "curve25519-sha256"},
	} {
		braced := "system { services { ssh { " + tc.leaf + " " + tc.value + "; } } }"
		elided := "system { services { ssh " + tc.leaf + " " + tc.value + "; } }"
		bc, be := compileTextLenient8922(t, braced)
		ec, ee := compileTextLenient8922(t, elided)
		if be != nil || bc == nil {
			t.Fatalf("%s: braced arm did not compile: %v", tc.leaf, be)
		}
		if ee != nil || ec == nil {
			t.Fatalf("%s: elided arm did not compile: %v", tc.leaf, ee)
		}
		got := sshListValues8922(ec, tc.leaf)
		want := sshListValues8922(bc, tc.leaf)
		if len(want) == 0 {
			t.Fatalf("%s: the BRACED arm delivered nothing, so this cell cannot "+
				"tell a fixed elision from a broken fixture (issue 8922)", tc.leaf)
		}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("`ssh %s %s` written brace-elided delivers %v, braced delivers %v.\n"+
				"  An empty list writes NO line into the sshd drop-in "+
				"(daemon_hostauth_apply.go), so sshd keeps its permissive "+
				"built-in default and the operator's narrowing is silently not "+
				"applied on a commit that reported success (issue 8922).",
				tc.leaf, tc.value, got, want)
		}
	}
}

func compileTextLenient8922(t *testing.T, text string) (*Config, error) {
	t.Helper()
	tr, perrs := NewParser(text).Parse()
	if len(perrs) > 0 || tr == nil {
		t.Fatalf("fixture did not parse: %v", perrs)
	}
	return CompileConfigLenient(tr)
}

func sshListValues8922(c *Config, leaf string) []string {
	switch leaf {
	case "ciphers":
		return c.System.Services.SSH.Ciphers
	case "macs":
		return c.System.Services.SSH.MACs
	case "key-exchange":
		return c.System.Services.SSH.KeyExchange
	}
	return nil
}
