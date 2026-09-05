package config

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// #8755: the population question, which changes the issue's conclusion more
// than any per-site verdict.
//
// A scope entry for the 20 `family inet` / `family inet6` sites reaches the
// PACKED spelling only — `family inet filter input f4;`. It cannot reach the
// idiomatic elision `family inet { filter input f4; }`, because the pass never
// traverses into a braced multi-key container (#8763).
//
// Measured across the shipped configs at 0ab895a56:
//
//	braced   `family inet {` / `family inet6 {`   77
//	packed   `family inet <keyword>`               0
//
// So the remedy reaches a spelling with NO instances in the corpus, and cannot
// reach the one with 77. That belongs at the top of the write-up, ahead of any
// per-site verdict — it is the difference between "here is the remedy" and
// "here is why the remedy does not reach the case that occurs".
//
// THREE LANES MEASURED THIS AND GOT 77, 104 AND 144. The counts differ by
// corpus and by pattern (which files, and whether `groups`/doc snippets count);
// the SHAPE is unanimous — braced everywhere, packed nowhere. This cell states
// its own command so its number is comparable rather than authoritative, which
// is the lesson three greens of 72/77 taught earlier today.
//
// EIGHT TEST AND DOC CONFIGS ARE NOT CUSTOMER CONFIGS. Absence here is
// evidence, not proof. It is the corpus #8690 has used for its shipped-config
// checks throughout, so it is the standard already in force, and this cell
// states the limit rather than leaving a reader to assume coverage.

var (
	bracedFamily8755 = regexp.MustCompile(`family\s+inet6?\s*\{`)
	packedFamily8755 = regexp.MustCompile(`family\s+inet6?\s+[a-z][a-z0-9-]*`)
)

func shippedConfigs8755(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, pat := range []string{"../../test/incus/*.conf", "../../docs/*.conf"} {
		paths, err := filepath.Glob(pat)
		if err != nil {
			t.Fatalf("glob %s: %v", pat, err)
		}
		for _, p := range paths {
			b, err := os.ReadFile(p)
			if err != nil {
				continue
			}
			out[filepath.Base(p)] = string(b)
		}
	}
	return out
}

// THE CANARY. If a packed `family inet <keyword>` ever appears in a shipped
// config, the remedy acquires a population and #8755's conclusion has to be
// re-read. Going red here is INFORMATION, not a regression.
func TestNoShippedConfigUsesThePackedFamilySpelling_8755(t *testing.T) {
	cfgs := shippedConfigs8755(t)
	if len(cfgs) == 0 {
		t.Skip("no shipped configs found at the expected paths")
	}
	var braced, packed int
	var packedIn []string
	names := make([]string, 0, len(cfgs))
	for n := range cfgs {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		body := cfgs[n]
		braced += len(bracedFamily8755.FindAllString(body, -1))
		// No braced-form exclusion is needed and none is written: the packed
		// pattern requires a LETTER after the family name, and `family inet {`
		// has a brace there. I wrote an exclusion first; a mutation deleting it
		// changed nothing, which is what dead code looks like from the outside.
		for _, m := range packedFamily8755.FindAllString(body, -1) {
			packed++
			packedIn = append(packedIn, n+": "+strings.TrimSpace(m))
		}
	}

	// NON-VACUITY: the braced pattern must find something, or "packed=0" is a
	// statement about a regex that matches nothing rather than about the corpus.
	if braced == 0 {
		t.Fatalf("the braced pattern matched NOTHING across %d configs. packed=0 "+
			"below would then be a property of the patterns, not of the corpus",
			len(cfgs))
	}
	// POSITIVE CONTROL: the packed pattern must be able to match.
	if !packedFamily8755.MatchString("unit 0 { family inet filter input f4; }") {
		t.Fatal("the packed pattern does not match a synthetic packed spelling, so " +
			"a zero count below means the pattern is broken")
	}

	t.Logf("#8755 corpus (test/incus/*.conf + docs/*.conf, %d files): braced=%d packed=%d",
		len(cfgs), braced, packed)
	if packed > 0 {
		t.Errorf("%d packed `family inet <keyword>` spelling(s) now appear in shipped "+
			"configs: %v.\nThat is not a failure of the config — it means the #8755 "+
			"remedy (a scope entry, which reaches ONLY the packed spelling) now has a "+
			"real population, and the register's SPELLING BOUND notes saying it "+
			"reaches nothing observed must be re-read", packed, packedIn)
	}
}
