package configstore

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// Issue 8898: the master-password PRF selector was silently dropped when the
// `system` brace was elided, so the config DB was encrypted with a KDF the
// operator did not choose.
//
// TWO FIXES, AND THE FIRST ONE ALONE DID NOTHING. Admitting
// `system master-password` to compactNormalizeInScope repairs the COMPILED
// config -- and this consumer never reads the compiled config. It walks the RAW
// tree, so it never sees the normalizer, which runs inside the compiler. The
// selector still resolved to nothing after the scope entry landed. The scan
// site had to fold too (config.NormalizeCompactForScan), which is #8867's shape
// with a different consumer: the fold is a property of the COMPILE path, and
// every reader outside it has to opt in.

// masterPasswordFixturePRF8898 is deliberately NOT defaultMasterPasswordPRF.
//
// If the fixture uses the default, losing the selector produces the SAME
// effective PRF as keeping it, and the cell passes while the defect is fully
// present. That is not hypothetical: the first version of this measurement used
// `sha256`, which IS the fallback, and reported the row clean. The braced arm
// was live, the comparison was real, and the answer was still wrong.
//
// TestFixtureIsNotTheDefault8898 keeps this honest if the default ever moves.
const masterPasswordFixturePRF8898 = "juniper-prf1"

func TestFixtureIsNotTheDefault8898(t *testing.T) {
	if masterPasswordFixturePRF8898 == defaultMasterPasswordPRF {
		t.Fatalf("the fixture PRF %q is now the compiled DEFAULT. Losing the selector would "+
			"produce the same effective value as keeping it, so every cell below would pass "+
			"with the defect fully present. Choose a supported non-default selector",
			masterPasswordFixturePRF8898)
	}
	if !prfSupported(masterPasswordFixturePRF8898) {
		t.Fatalf("the fixture PRF %q is not supported, so the cells below would be measuring "+
			"a rejected value rather than a dropped one", masterPasswordFixturePRF8898)
	}
}

func masterPasswordSpellings8898() map[string]string {
	v := masterPasswordFixturePRF8898
	return map[string]string{
		"d1-braced":        "system {\n    master-password {\n        pseudorandom-function " + v + ";\n    }\n}",
		"d2-stanza-elided": "system master-password {\n    pseudorandom-function " + v + ";\n}",
		"d3-fully-elided":  "system master-password pseudorandom-function " + v + ";",
	}
}

func TestMasterPasswordPRFSurvivesElision8898(t *testing.T) {
	for name, text := range masterPasswordSpellings8898() {
		tree, errs := config.NewParser(text).Parse()
		if len(errs) > 0 {
			t.Fatalf("%s: fixture does not parse: %v", name, errs[0])
		}
		got := effectiveMasterPasswordPRF(tree)
		if got != masterPasswordFixturePRF8898 {
			t.Errorf("%s: effective PRF = %q, want %q. The selector is dropped and crypto.go "+
				"falls back to %q, so the config DB is encrypted with a KDF the operator did "+
				"not choose", name, got, masterPasswordFixturePRF8898, defaultMasterPasswordPRF)
		}
	}
}

// DISPLAY AND ENFORCEMENT MUST NOT DISAGREE, and that divergence is what makes
// this a security defect rather than a config-loss defect.
//
// ConfigTree.Format() preserves an elided statement verbatim -- it never
// creates one and never canonicalises one -- so `show configuration` renders
// exactly what the operator wrote. If the selector then resolves to something
// else, the operator is looking at a PRF that is not in force, with nothing
// anywhere reporting the difference.
func TestDisplayAndEnforcementAgreeOnPRF8898(t *testing.T) {
	for name, text := range masterPasswordSpellings8898() {
		tree, errs := config.NewParser(text).Parse()
		if len(errs) > 0 {
			t.Fatalf("%s: %v", name, errs[0])
		}
		rendered := tree.Format()
		// LIVENESS: the rendered configuration must actually show the selector,
		// or "display agrees with enforcement" is a claim about two blanks.
		if !strings.Contains(rendered, masterPasswordFixturePRF8898) {
			t.Fatalf("%s: the rendered configuration does not mention %q at all, so this "+
				"comparison is vacuous:\n%s", name, masterPasswordFixturePRF8898, rendered)
		}
		enforced := effectiveMasterPasswordPRF(tree)
		if enforced != masterPasswordFixturePRF8898 {
			t.Errorf("%s: `show configuration` renders %q but the enforced PRF is %q. The "+
				"operator is reading a selector that is not in force, and nothing reports "+
				"the difference", name, masterPasswordFixturePRF8898, enforced)
		}
	}
}

// The scan-site fold must not mutate the caller's tree: configstore hands it
// trees that are persisted, so folding in place would rewrite the stored
// configuration as a side effect of reading the PRF.
func TestPRFScanDoesNotMutateTree8898(t *testing.T) {
	text := masterPasswordSpellings8898()["d3-fully-elided"]
	tree, errs := config.NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("%v", errs[0])
	}
	before := tree.Format()
	if !strings.Contains(before, "master-password pseudorandom-function") {
		t.Fatalf("fixture is not packed as intended: %q", before)
	}
	if got := effectiveMasterPasswordPRF(tree); got != masterPasswordFixturePRF8898 {
		t.Fatalf("precondition: the packed selector must resolve, got %q", got)
	}
	if after := tree.Format(); after != before {
		t.Errorf("resolving the PRF MUTATED the caller's tree.\n before: %q\n after:  %q", before, after)
	}
}
