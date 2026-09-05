package config

import (
	"os"
	"sort"
	"strings"
	"testing"
)

// #8755: the reachability half of the brace-elided interface-unit drops.
//
// The issue's load-bearing scope claim is that the flat `set` spelling is
// UNAFFECTED — an operator at the CLI binds the filter correctly, and the loss
// reaches a box only through a hierarchical config file, a `load override` or a
// peer config-sync payload. That claim is what keeps the severity honest: "an
// operator types `set` and gets no filter" would be false.
//
// IT WAS CITED TO A PIN THAT DOES NOT COVER IT.
// `TestFlatSetMergesWhereHierarchicalDuplicates` is about a repeated INSTANCE
// STATEMENT under `security policies ... policy <p>` merging rather than
// duplicating — a different container, a different mechanism, and it says
// nothing about whether an interface unit's packed tail survives the flat
// spelling. Existence is not coverage, and I supplied that citation myself.
//
// Measured here instead, over the population the issue is actually about.

// openSites8755 reads the sites the #8690 register classes `open` — the ones
// #8755 owns. Reading the register rather than a hardcoded list means this
// shrinks by itself as sites are normalized and leave it, instead of going
// stale in the direction that looks like success.
func openSites8755(t *testing.T) []string {
	t.Helper()
	b, err := os.ReadFile("testdata/compact_block_permanent_exclusions_8690.txt")
	if err != nil {
		t.Fatalf("read the #8690 register: %v", err)
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		f := strings.Split(l, "\t")
		if len(f) >= 2 && strings.TrimSpace(f[1]) == "open" {
			out = append(out, strings.TrimSpace(f[0]))
		}
	}
	sort.Strings(out)
	return out
}

func siteByKey8755(key string) (compactSite, bool) {
	for _, s := range collectCompactSites() {
		if strings.Join(s.container, " ")+" "+s.leaf == key {
			return s, true
		}
	}
	return compactSite{}, false
}

// flatSetTree8755 drives ParseSetCommand + SetPath, the only faithful way to
// model a CLI session — CLAUDE.md says so outright, and the cell this issue
// originally cited exists because three people used NewParser instead on one
// day.
func flatSetTree8755(path, leaf, value string) *ConfigTree {
	tokens, err := ParseSetCommand("set " + path + " " + leaf + " " + value)
	if err != nil {
		return nil
	}
	tree := &ConfigTree{}
	tree.SetPath(tokens)
	return tree
}

func compileTree8755(tree *ConfigTree) *Config {
	if tree == nil {
		return nil
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		return nil
	}
	cfg.Warnings = nil
	return cfg
}

// maxKeysPerNode8755 is the depth of tail-packing in a tree: the elided
// spelling folds a whole statement onto ONE node's Keys, the other spellings do
// not.
//
// MEASURED, because my first version of this file asserted the wrong thing.
// For `interfaces <if> unit <u> family inet filter input f1`:
//
//	flat `set`            max Keys per node = 2
//	hierarchical braced   max Keys per node = 2
//	hierarchical ELIDED   max Keys per node = 5
//
// The flat and braced spellings are STRUCTURALLY EQUIVALENT here — SetPath
// builds the same nested chain the parser does — which is why both carry the
// value and why a mutation swapping one for the other changed nothing. I had
// written a cell asserting "this is the flat tree, not the hierarchical one";
// that distinction does not exist for this population, and the mutation that
// exposed it was RIGHT to escape.
//
// The distinction that does exist is elided vs not-elided, and that is what
// this measures.
func maxKeysPerNode8755(tree *ConfigTree) int {
	if tree == nil {
		return 0
	}
	var walk func(n *Node) int
	walk = func(n *Node) int {
		if n == nil {
			return 0
		}
		m := len(n.Keys)
		for _, c := range n.Children {
			if k := walk(c); k > m {
				m = k
			}
		}
		return m
	}
	m := 0
	for _, c := range tree.Children {
		if k := walk(c); k > m {
			m = k
		}
	}
	return m
}

// elidedTree8755 is the spelling this issue is about: the whole statement
// packed onto one node.
func elidedTree8755(container []string, leaf, value string) *ConfigTree {
	if len(container) == 0 {
		return nil
	}
	p := NewParser(nest(container[:len(container)-1],
		container[len(container)-1]+" "+leaf+" "+value+";"))
	tree, perrs := p.Parse()
	if len(perrs) > 0 {
		return nil
	}
	return tree
}

// EVERY site #8755 owns must survive the flat `set` spelling. If one does not,
// the issue's scope paragraph is wrong for that site and its severity framing
// has to change with it — an operator really would lose it at the CLI.
func TestEveryOpenSiteSurvivesTheFlatSetSpelling_8755(t *testing.T) {
	sites := openSites8755(t)
	if len(sites) == 0 {
		t.Skip("no sites classed `open`; the population this cell guards is empty")
	}
	var lost, unmeasurable, normalized []string
	var survived, controlFired int
	for _, key := range sites {
		s, ok := siteByKey8755(key)
		if !ok {
			unmeasurable = append(unmeasurable, key+" [not in the census walk]")
			continue
		}
		v1, v2, ok := synthPair(s.node)
		if !ok {
			unmeasurable = append(unmeasurable, key+" [no probe pair]")
			continue
		}
		rendered := renderInstanceNames(s.container)
		path := strings.Join(rendered, " ")
		ft1, ft2 := flatSetTree8755(path, s.leaf, v1), flatSetTree8755(path, s.leaf, v2)
		// Also unfalsifiable today: no flat tree is tail-packed, so removing
		// this guard kills nothing. It exists because the measurement above
		// (flat 2, braced 2, elided 5) is the ONLY thing separating this cell
		// from one that contrasts the elided spelling with itself, and that
		// separation is a property of the parser rather than of this file.
		if ft1 != nil && maxKeysPerNode8755(ft1) > 2 {
			unmeasurable = append(unmeasurable, key+" [the `flat set` tree is TAIL-PACKED; "+
				"this cell would be measuring the elided spelling it exists to contrast with]")
			continue
		}
		a, b := compileTree8755(ft1), compileTree8755(ft2)
		switch {
		case a == nil || b == nil:
			unmeasurable = append(unmeasurable, key+" [flat set did not compile]")
		case cfgEqual(a, b):
			// UNFALSIFIABLE AT THIS HEAD, and labelled rather than dressed up.
			// No open site is lost under the flat spelling, so this arm fires
			// for nothing and a mutation deleting it kills no cell. What IS
			// tested is that the comparison can report a loss at all — the
			// per-site elided control below, whose removal reds this cell. The
			// arm stays because it is what turns a future regression into a
			// named failure instead of a silent pass.
			lost = append(lost, key)
		default:
			survived++
			// PER-SITE POSITIVE CONTROL. The same comparison, on the ELIDED
			// spelling, must report EQUAL — that is the loss this issue is
			// about. Without it, a comparison broken toward "always different"
			// reports zero losses and reads as a clean result. Found by
			// mutation: killing the loss arm outright changed nothing.
			e1 := compileTree8755(elidedTree8755(rendered, s.leaf, v1))
			e2 := compileTree8755(elidedTree8755(rendered, s.leaf, v2))
			if e1 != nil && e2 != nil {
				if cfgEqual(e1, e2) {
					controlFired++
				} else {
					normalized = append(normalized, key)
				}
			}
		}
	}
	if len(lost) > 0 {
		t.Errorf("%d/%d sites are ALSO dropped by the flat `set` spelling: %v.\n"+
			"#8755's scope paragraph says the flat form is unaffected, and its "+
			"severity framing rests on that — if an operator loses these at the "+
			"CLI the issue is materially worse than filed and the reachability "+
			"claim has to be rewritten, not softened", len(lost), len(sites), lost)
	}
	// NON-VACUITY. A cell that measured nothing would report no losses too.
	if len(unmeasurable) == len(sites) {
		t.Fatalf("not one of the %d sites could be measured: %v. The result above "+
			"is 'no losses found' only because nothing was looked at", len(sites), unmeasurable)
	}
	if len(unmeasurable) > 0 {
		t.Logf("%d/%d unmeasurable, reported rather than counted as clean: %v",
			len(unmeasurable), len(sites), unmeasurable)
	}
	// THE COMPARISON MUST BE ABLE TO REPORT A LOSS. Every surviving site's
	// elided twin is checked, and at least one must come back EQUAL — otherwise
	// "no losses under flat set" is a statement about a comparison that cannot
	// detect one.
	if survived > 0 && controlFired == 0 {
		t.Errorf("%d sites survive the flat spelling and NOT ONE of their elided "+
			"twins compares equal. Either every site has been normalized — in "+
			"which case this cell and #8755 are done — or the comparison cannot "+
			"detect a loss and the zero above means nothing", survived)
	}
	if len(normalized) > 0 {
		t.Logf("%d site(s) now carry the value in the ELIDED spelling too, i.e. "+
			"they have been fixed: %v", len(normalized), normalized)
	}
	t.Logf("#8755 reachability: %d/%d open sites survive the flat `set` spelling",
		len(sites)-len(lost)-len(unmeasurable), len(sites))
}

// The contrast that gives the cell above its meaning: the SAME site, in the
// hierarchical brace-elided spelling, is what #8755 is about. Without this,
// "flat set works" would be compatible with "nothing is broken anywhere".
func TestTheElidedSpellingIsWhereTheLossIs_8755(t *testing.T) {
	const key = "interfaces xpfname unit xpfarg family inet filter input"
	s, ok := siteByKey8755(key)
	if !ok {
		t.Skipf("%s is no longer a census site", key)
	}
	v1, v2, ok := synthPair(s.node)
	if !ok {
		t.Skip("no probe pair")
	}
	rendered := renderInstanceNames(s.container)
	path := strings.Join(rendered, " ")

	ft1 := flatSetTree8755(path, s.leaf, v1)
	if ft1 == nil || maxKeysPerNode8755(ft1) > 2 {
		t.Fatalf("the flat tree is tail-packed (max keys %d); this cell would be "+
			"contrasting the elided spelling with itself", maxKeysPerNode8755(ft1))
	}
	if a, b := compileTree8755(ft1), compileTree8755(flatSetTree8755(path, s.leaf, v2)); a == nil || b == nil || cfgEqual(a, b) {
		t.Fatal("the flat spelling does not carry this leaf either, so the " +
			"contrast this cell draws does not exist")
	}

	// The hierarchical elided spelling, through the parser a config FILE goes
	// through — which is the ingress, and is NOT what a `set` session produces.
	elided := func(v string) *Config {
		p := NewParser(nest(rendered[:len(rendered)-1],
			rendered[len(rendered)-1]+" "+s.leaf+" "+v+";"))
		tree, perrs := p.Parse()
		if len(perrs) > 0 {
			return nil
		}
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			return nil
		}
		cfg.Warnings = nil
		return cfg
	}
	a, b := elided(v1), elided(v2)
	if a == nil || b == nil {
		t.Fatalf("the elided fixture did not compile; the loss cannot be shown here")
	}
	if !cfgEqual(a, b) {
		t.Skip("the elided spelling now carries the value — this site has been " +
			"normalized and this cell should be retired with it")
	}
	t.Logf("`%s %s` is carried by the flat `set` spelling and DROPPED by the "+
		"hierarchical brace-elided one. That asymmetry is #8755's whole scope: "+
		"the ingress is a config file / `load override` / peer-sync payload, "+
		"not the CLI", path, s.leaf)
}
