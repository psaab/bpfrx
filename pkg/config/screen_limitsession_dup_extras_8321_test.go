package config

import (
	"strings"
	"testing"
)

// #8321 grouped-cohort item 5: `recordChildExtras` was invoked TWICE, with
// identical arguments, on both `limit-session source-ip-based` and
// `limit-session destination-ip-based`, so every unexpected child under either
// was recorded twice in `profile.UnknownLeaves`.
//
// The finding named ONE site. There were TWO — the second is the
// destination-ip-based arm eight lines below, which the review did not reach.
// A reviewer's enumeration is a floor.
//
// Consequence, established by reading the consumer rather than assumed:
// `UnknownLeaves` has exactly one reader, `validateScreenUnknownStrict`, and it
// prints `UnknownLeaves[0]` only — so the duplicate was invisible on the
// commit-error surface and nothing else renders the slice. This is a latent
// trap for the next consumer that iterates, not a live operator-visible defect,
// and it is fixed at that severity.
//
// The cell reads the compiled profile directly because that is where the
// duplication was: a cell asserting on the strict-commit error string could not
// distinguish one entry from two, which is the whole reason this survived.
func TestScreenLimitSessionRecordsUnknownChildOnce_8321(t *testing.T) {
	for _, knob := range []string{"source-ip-based", "destination-ip-based"} {
		t.Run(knob, func(t *testing.T) {
			tree := &ConfigTree{}
			for _, line := range []string{
				"set security screen ids-option s1 limit-session " + knob + " 100",
				"set security screen ids-option s1 limit-session " + knob + " bogus-child 7",
			} {
				path, err := ParseSetCommand(line)
				if err != nil {
					t.Fatalf("ParseSetCommand(%q): %v", line, err)
				}
				if err := tree.SetPath(path); err != nil {
					t.Fatalf("SetPath(%q): %v", line, err)
				}
			}
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("lenient compile must not brick (#1960): %v", err)
			}
			profile := cfg.Security.Screen["s1"]
			if profile == nil {
				t.Fatalf("PREMISE: profile s1 must compile, or this cell is vacuous")
			}
			// Count entries recorded under this knob's prefix. The flat-set
			// spelling packs `bogus-child` onto the option node's KEYS and
			// leaves `7` as the child, so the recorded text is
			// "limit-session <knob> 7" — matching the literal "bogus-child"
			// would count zero and the cell would pass vacuously.
			prefix := "limit-session " + knob + " "
			var hits int
			for _, leaf := range profile.UnknownLeaves {
				if strings.HasPrefix(leaf, prefix) {
					hits++
				}
			}
			// Non-vacuity first: if the unexpected child is not recorded AT ALL
			// the count-of-one assertion below would pass on zero.
			if hits == 0 {
				t.Fatalf("PREMISE: the unexpected child must be recorded as an unknown leaf; "+
					"got %v — this fixture no longer reaches recordChildExtras and proves nothing",
					profile.UnknownLeaves)
			}
			if hits != 1 {
				t.Fatalf("#8321 item 5: an unexpected child under `limit-session %s` was recorded "+
					"%d times; recordChildExtras is invoked twice with identical arguments.\n%v",
					knob, hits, profile.UnknownLeaves)
			}
		})
	}
}
