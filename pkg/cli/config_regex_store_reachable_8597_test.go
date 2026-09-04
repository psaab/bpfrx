package cli

import (
	"strings"
	"testing"
)

// #8597 (muse-004 K48) — a rationale asserting unreachability outlived the
// change that made the thing reachable.
//
// checkConfigRegexWith's doc said "no supported path puts a
// `deny-configuration` class into ActiveConfig until cut 6 retires #6838's
// gate, so every branch here is unreachable through a store". #7172 cut 6
// landed and retired that gate — `pkg/config/compiler_tailgates.go` records it
// in as many words — so the config commits now and takes effect.
//
// The identical sentence in permissions_regex.go was corrected by #8289 for the
// deny-COMMANDS half. The deny-CONFIGURATION half was not brought along, and
// the cost was exactly what the stale rationale licensed: every cell in
// permissions_config_regex_7172_test.go drives checkConfigRegexWith DIRECTLY
// and not one goes through a store. For a deny-bypass-critical gate, the wiring
// from ActiveConfig through the session's class and edit path was untested.

// TestDenyConfigurationIsReachableThroughAStore_8597 is the cell the stale
// comment said could not exist.
//
// It drives the store-reading wrapper `c.checkConfigRegex`, not the store-free
// `checkConfigRegexWith` every other cell in this package uses — so it binds
// the WIRING: ActiveConfig is read, the session's class is the one evaluated,
// and the edit path comes from the store rather than from the caller.
func TestDenyConfigurationIsReachableThroughAStore_8597(t *testing.T) {
	store := denyClassStore7172(t)

	// Non-vacuity, first: the committed config must actually carry the
	// deny-configuration rule. If cut 6's retirement were ever reverted, the
	// commit in the helper would fail — but if the rule were merely dropped,
	// every assertion below would pass by permitting everything.
	cfg := store.ActiveConfig()
	if cfg == nil {
		t.Fatal("no active config after commit")
	}
	var found bool
	if cfg.System.Login != nil {
		for _, cls := range cfg.System.Login.Classes {
			if cls != nil && cls.Name == "limited" && cls.DenyConfiguration != "" {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("the committed class carries no deny-configuration rule, so the "+
			"refusals below would be about nothing: %+v", cfg.System.Login)
	}

	c := &CLI{store: store, userClass: "limited"}

	// The denied mutation, refused through the store path.
	if err := c.checkConfigRegex("set system host-name pwned"); err == nil {
		t.Fatal("a `set system host-name` matching the committed class's " +
			"deny-configuration was ALLOWED when the decision was reached through the " +
			"store. Every existing cell for this gate calls checkConfigRegexWith " +
			"directly, so nothing bound ActiveConfig -> class -> decision (#8597/K48)")
	}

	// And the over-reach half, through the same path: an unrelated mutation
	// must still be permitted, or the gate denies everything for this class.
	if err := c.checkConfigRegex("set system domain-name example.net"); err != nil {
		t.Errorf("an unrelated mutation was refused through the store path: %v", err)
	}
}

// TestStoreEditPathReachesTheConfigGate_8597 covers the half the store-free
// cells cannot reach at all: the edit path is READ FROM THE STORE, not passed
// in.
//
// `edit system` followed by `set host-name pwned` types a remainder that does
// not match the deny on its own — only the resolved path does. The store-free
// cells pass the edit path as an argument, so they prove the matcher resolves
// it and say nothing about whether the wrapper obtains it.
func TestStoreEditPathReachesTheConfigGate_8597(t *testing.T) {
	store := denyClassStore7172(t)
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	store.SetEditPath([]string{"system"})

	// Non-vacuity: the store must actually be holding the edit path, or the
	// refusal below would be about the typed line alone.
	if got := store.GetEditPath(); len(got) != 1 || got[0] != "system" {
		t.Fatalf("the store's edit path is %v, not [system]; this cell is about the "+
			"wrapper READING it", got)
	}

	c := &CLI{store: store, userClass: "limited"}
	if err := c.checkConfigRegex("set host-name pwned"); err == nil {
		t.Fatal("`edit system` + `set host-name pwned` was allowed. The typed remainder " +
			"does not match the deny on its own — only the RESOLVED path does — so the " +
			"wrapper must take the edit path from the store. Navigating with `edit` is " +
			"the ordinary way to work, which makes this the bypass an operator finds " +
			"without trying (#8597/K48)")
	}
}

// TestConfigRegexRationaleIsNotStale_8597 pins the comment itself, because a
// stale rationale is what caused this and a corrected one can go stale again.
//
// It asserts the doc no longer claims unreachability, and that it names the
// authority. Keyed on the CLAIM's negation rather than on a phrase, so a
// paraphrase of the same wrong assertion still fails.
func TestConfigRegexRationaleIsNotStale_8597(t *testing.T) {
	src := readCLISource(t, "permissions_config_regex.go")
	i := strings.Index(src, "func checkConfigRegexWith")
	if i < 0 {
		t.Fatal("checkConfigRegexWith is gone; re-derive this cell")
	}
	doc := src[maxInt8597(0, i-2200):i]

	for _, stale := range []string{
		"until cut 6 retires",
		"unreachable through a store",
	} {
		if strings.Contains(doc, stale) && !strings.Contains(doc, "used to say") {
			t.Errorf("the doc still asserts %q as current. #7172 cut 6 has landed and "+
				"the path IS reachable; permissions_regex.go was corrected for the "+
				"deny-commands half by #8289", stale)
		}
	}
	if !strings.Contains(doc, "compiler_tailgates.go") {
		t.Error("the corrected doc does not cite the authority that retired the gate; " +
			"a rationale that names no source is the kind that goes stale unnoticed")
	}
}

func maxInt8597(a, b int) int {
	if a > b {
		return a
	}
	return b
}
