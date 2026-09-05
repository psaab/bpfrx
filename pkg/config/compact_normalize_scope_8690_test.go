package config

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

// #8690: the normalizer's SCOPE is a safety claim, and this re-derives it from
// measurement on every run rather than trusting the list in
// compactNormalizeInScope.
//
// The rule #8689 established: a site may be normalized only once its elided
// spelling compiles identically to the EMPTY stanza — a positive measurement
// that no reader consumes the packed tail today, so moving it into a child
// cannot break one. Some containers DO read their tail (`redundancy-group 0
// node 0 priority 200` is the shipped HA spelling), which is why membership is
// by measurement and not by family name.
//
// THE RULE IS SUFFICIENT, NOT NECESSARY, and building this cell is what showed
// that. "Elided compiles to empty" proves the tail reaches no reader, so moving
// it cannot lose anything — but a reader that handles BOTH shapes is equally
// safe and is not empty-equivalent. `chassis cluster authentication-key` is
// exactly that: #8689 admitted it, `compileChassis` reads the packed tail AND
// the child, and both spellings compile the PSK correctly. An "must be
// empty-equivalent" assertion would have demanded its removal from a working
// increment.
//
// So what this asserts is the property the rule is a proxy FOR: for every site
// the gate admits, normalizing must not change the compiled result — the
// elided spelling with the pass applied must equal the braced spelling. A
// widening that admits a tail whose reader only understands the packed form
// reds here, with the site named, which is the `redundancy-group 0 node 0
// priority 200` failure. Empty-equivalence is reported alongside, because it is
// still the cheapest evidence when it holds.
func TestCompactNormalizeScopePreservesCompiledResult8690(t *testing.T) {
	var admitted, violating, disarmed, fixtureLimited []string
	emptyEquivalent := 0
	seamObserved := 0
	// SKIP ACCOUNTING. Making admission behavioural gave this loop a failure
	// mode the earlier version could not have: it drives real parses and
	// compiles, so it can now SKIP a site — and a site it skipped is not a site
	// it found safe. Reported per reason, and the in-scope bucket is an error,
	// because that one is a site production DOES normalize and this cell did
	// not examine. (Credit: lane-8015 found this shape in the partial-site
	// guard when making it behavioural; it applies identically here.)
	var unsynthesizable, unparsable []string
	var inScopeUnexaminable []string
	for _, s := range collectCompactSites() {
		if len(s.container) == 0 || strings.HasPrefix(s.container[0], "groups") {
			continue
		}
		parent := s.container[:len(s.container)-1]
		stanza := s.container[len(s.container)-1]
		siteKeyEarly := strings.Join(s.container, " ") + " " + s.leaf
		v1, v2, ok := synthPair(s.node)
		if !ok {
			// No distinguishing pair of values, so scope cannot even be
			// determined for this site — it is UNKNOWN, not safe.
			unsynthesizable = append(unsynthesizable, siteKeyEarly)
			continue
		}
		ctx := contextFor(parent)
		siteKey := strings.Join(s.container, " ") + " " + s.leaf
		elidedText := nest(parent, ctx+stanza+" "+s.leaf+" "+v1+";")

		// ADMISSION COMES FROM THE PASS, NOT FROM A RE-DERIVED MODEL OF IT.
		//
		// The obvious spelling here is `compactNormalizeInScope(stanza,
		// s.leaf)`, and it is WRONG in a way that hides sites. Production calls
		// the predicate with `node.Keys[0]` — the stanza KEYWORD — while this
		// walk's container path carries the schema ARG PLACEHOLDER in that
		// position for any stanza that takes a name. So for `system login user
		// u1 { class ...; }` production asks about ("user", "class") and the
		// re-derived version asks about ("xpfarg", "class"), which no case
		// matches. The guard would then skip the very site being widened and
		// report a clean scope.
		//
		// That is the dangerous direction of error: under-admitting means
		// production normalizes something this cell never examined. So admit by
		// running the actual pass and asking whether it TOUCHED the tree. No
		// model, no drift.
		probe, perrs := NewParser(elidedText).Parse()
		if len(perrs) > 0 || probe == nil {
			unparsable = append(unparsable, siteKey)
			continue
		}
		if normalizeCompactStanzas(probe) == 0 {
			continue // production leaves this site alone; not in scope
		}
		cb1 := compileText(t, nest(parent, ctx+stanza+" { "+s.leaf+" "+v1+"; }"))
		cb2 := compileText(t, nest(parent, ctx+stanza+" { "+s.leaf+" "+v2+"; }"))
		ce := compileText(t, nest(parent, ctx+stanza+" { }"))
		if cb1 == nil || cb2 == nil || ce == nil {
			// The pass DOES normalize this site (checked above), but a
			// reference spelling would not compile, so the safety property
			// could not be evaluated. That is the dangerous bucket.
			inScopeUnexaminable = append(inScopeUnexaminable, siteKey)
			continue
		}
		if cfgEqual(cb1, cb2) {
			continue // the value is not observable here; nothing to protect
		}
		admitted = append(admitted, siteKey)

		// THE SAFETY PROPERTY: with the pass applied, the elided spelling must
		// compile to what the braced spelling compiles to. If it does not, the
		// normalization moved a tail its reader only understood in place.
		cc := compileText(t, elidedText)
		if cc == nil || !cfgEqual(cb1, cc) {
			violating = append(violating, siteKey)
			continue
		}
		// SECOND ARM — the one the "preserves the compiled result" check above
		// is STRUCTURALLY BLIND TO. That check asks whether elided-with-pass
		// equals braced, which is what the pass is FOR: it reports success
		// exactly when the pass did its job. It therefore cannot tell
		// "made a harmless spelling compile correctly" apart from
		// "converted a deliberate commit-time REJECTION into a silent
		// acceptance" — in both cases elided ends up equal to braced.
		//
		// That second case is a real defect and it happened during this
		// increment: admitting `user`/`class` made `system login user u1
		// class super-user;` compile clean where the #6662 gate had rejected
		// it. The normalizer runs at compiler.go:210 and that gate at :349,
		// so a rewritten tree reaches the gate with nothing left to reject.
		//
		// So: compile the elided spelling through the STRICT commit path with
		// the pass disabled. If it was rejected there and is accepted with the
		// pass on, the pass is not normalizing a spelling — it is disarming a
		// gate, and that has to be a deliberate registered decision.
		// THREE STATES, not two. The harmful case is a rejection becoming an
		// ACCEPTANCE. But a site can also fail with the pass enabled for an
		// unrelated reason — the census fixture supplies one synthesized value
		// per leaf, and it is not always type-valid for that leaf's validator
		// (`dhcpv6 ... fixed-address` gets an IPv4 literal, so it trades "has
		// no fixed-address" for "is not an IPv6 address").
		//
		// A two-state test folds that third case into "safe", because the
		// pass-enabled compile did not succeed. That is the fixture answering,
		// not the site: under a type-valid value the same site might well
		// compile clean and be a real disarm. So it is counted and named
		// separately rather than silently passing.
		// LIMITATION, stated because this arm's failure condition is coarser
		// than the harm it is named for. A rejection becoming an acceptance is
		// harmful only when the gate was refusing the packed SPELLING on
		// purpose. There is a second, benign kind: a gate that rejects because
		// the elided spelling DROPPED something, where the pass repairs the
		// drop and the acceptance is the correct outcome. Measured example —
		// `nat source rule-set <r> rule <r> match source-address 10.0.0.0/8;`
		// is refused by the #8430 empty-match gate without the pass ("the
		// dataplane reads an EMPTY match set as UNCONSTRAINED ... would
		// translate EVERY packet") and compiles clean with it, because the
		// criterion survives. That is the pass working.
		//
		// Both shapes trip the condition below, so a widening that legitimately
		// resolves a drop-caused gate will red here and needs a human decision
		// rather than a mechanical fix. The #6662 login case is the harmful
		// kind: the braced form was always accepted, nothing was dropped, and
		// the gate existed to refuse that spelling across an HA version skew.
		// Distinguishing them automatically would need the gates themselves to
		// declare which kind they are; until then this arm reports and a person
		// classifies.
		if off := compileStrict8690(t, elidedText, true); off != nil {
			switch on := compileStrict8690(t, elidedText, false); {
			case on == nil:
				disarmed = append(disarmed, siteKey)
			case on.Error() != off.Error():
				fixtureLimited = append(fixtureLimited, siteKey)
			}
		}
		// SEAM LIVENESS. The check above reads "rejected without the pass,
		// accepted with it". If skipCompactNormalize stopped being honoured,
		// both sides would run the pass, nothing would ever be rejected, and
		// the arm would report a clean scope for the same reason a correct one
		// does — vacuous, and indistinguishable from healthy. So record that
		// the flag actually changed an outcome somewhere: for an
		// empty-equivalent site the un-normalized compile drops the tail and
		// the normalized one keeps it, which must be observable.
		if a, b := compileSeam8690(t, elidedText, true), compileSeam8690(t, elidedText, false); a != nil && b != nil && !cfgEqual(a, b) {
			seamObserved++
		}

		// Informational: was this site also empty-equivalent before the pass
		// existed? That is #8689's stated rule and the cheapest evidence, but a
		// reader handling both shapes is safe without it.
		if compactElidedCompilesEmpty(t, parent, ctx, stanza, s.leaf, v1, ce) {
			emptyEquivalent++
		}
	}
	sort.Strings(admitted)
	sort.Strings(violating)
	sort.Strings(disarmed)
	sort.Strings(fixtureLimited)

	// DEGENERACY GUARD: a walk that admitted nothing would report a clean scope
	// for the same reason a correct one does.
	if len(admitted) == 0 {
		t.Fatal("the scope walk admitted NO site — either collectCompactSites " +
			"stopped producing them or compactNormalizeInScope stopped admitting " +
			"any, and either way this cell is measuring nothing (#8690)")
	}
	if seamObserved == 0 {
		t.Fatal("the skipCompactNormalize seam changed NO outcome across every " +
			"admitted site. The rejection-vs-acceptance arm above depends on " +
			"that flag actually disabling the pass; if it is being ignored, the " +
			"arm silently reports a clean scope no matter what is admitted. " +
			"Fix the seam before trusting this cell (#8690)")
	}
	t.Logf("#8690 normalizer scope: %d admitted sites, %d of them empty-equivalent "+
		"(the rest are read correctly in BOTH shapes, which is equally safe)",
		len(admitted), emptyEquivalent)

	if len(violating) > 0 {
		t.Errorf("%d site(s) are in the normalizer's scope where normalizing "+
			"CHANGES the compiled result: %v.\n"+
			"The elided spelling no longer compiles to what the braced spelling "+
			"does, which means the tail was moved away from a reader that only "+
			"understood it in place — the `redundancy-group 0 node 0 priority "+
			"200` failure. Remove them from compactNormalizeInScope (#8690).",
			len(violating), violating)
	}

	sort.Strings(inScopeUnexaminable)
	if n := len(unsynthesizable) + len(unparsable); n > 0 {
		t.Logf("#8690 scope walk skipped %d site(s) before scope could be "+
			"determined (%d unsynthesizable, %d unparsable). Those are UNKNOWN "+
			"to this cell, not safe — the same gap a behavioural guard acquires "+
			"in exchange for not modelling the predicate.",
			n, len(unsynthesizable), len(unparsable))
	}
	// The in-scope-but-unexaminable set is asserted for EQUALITY against a
	// checked-in list, the same shape as the #2419 inventory itself: a new
	// member reds because the pass started rewriting something this cell cannot
	// see, and a member that becomes examinable ALSO reds, so the list cannot
	// quietly outlive its reason. A bare threshold would permit both.
	if diff := diffSiteSets8690(inScopeUnexaminable, knownUnexaminable8690); diff != "" {
		t.Errorf("the set of sites the pass normalizes but this cell cannot "+
			"EXAMINE has changed:\n%s\n"+
			"Production rewrites these and the cell says nothing about them, so "+
			"they are counted as neither safe nor unsafe — silence that reads "+
			"as a clean scope. A NEW entry means a widening admitted a site "+
			"whose reference spelling will not compile in isolation; give it a "+
			"compilable fixture (a required sibling is usually missing) rather "+
			"than adding it here. A REMOVED entry means one became examinable "+
			"and the list should shrink (#8690).", diff)
	}
	if len(fixtureLimited) > 0 {
		t.Logf("#8690: %d admitted site(s) could not have their gate status "+
			"measured, because the census fixture's value fails a different "+
			"validator with the pass enabled: %v.\n"+
			"These are NOT known-safe — a type-valid value might compile clean "+
			"and make them real disarms. They are reported rather than folded "+
			"into the clean count so the distinction stays visible.",
			len(fixtureLimited), fixtureLimited)
	}
	// STEP 3 of the rule, given somewhere to live. The arm above cannot
	// distinguish a gate refusing the packed SPELLING (harmful to disarm) from
	// one refusing the CONSEQUENCE OF THE DROP, where the pass repairs the drop
	// and the acceptance is the correct outcome. That distinction needs a
	// person, and a person's verdict needs a home — otherwise a benign disarm
	// blocks its family forever and the only way forward is to drop a real fix.
	//
	// An entry here is a CLASSIFICATION with its evidence, not a suppression,
	// and it is held to the same standard as #8704's deepDupUnreportable: the
	// cell below fails for a listed site that is NOT currently disarming, so a
	// stale entry — one whose gate was retired, or whose site left the scope —
	// reds instead of quietly excusing the next real disarm that lands on the
	// same key.
	benign := map[string]string{
		"snmp trap-group xpfarg targets": "the gate refuses the CONSEQUENCE of the drop, not " +
			"the spelling. Measured: with the pass disabled the elided " +
			"`trap-group tg1 targets 10.0.0.1;` loses its targets and snmp rejects with " +
			"\"no targets configured (a trap group with zero targets sends no " +
			"notifications)\"; with the pass enabled the target survives and the same gate " +
			"accepts. The gate is doing its job in both cases — it is the DROP it objects " +
			"to, and the pass repairs the drop. Normalizing here makes the operator's " +
			"config mean what they wrote, which is the acceptance being correct rather " +
			"than the gate being disarmed. Same shape as the #8430 empty-match example " +
			"in the LIMITATION note above.",
	}
	var unclassified []string
	for _, site := range disarmed {
		if _, ok := benign[site]; !ok {
			unclassified = append(unclassified, site)
		}
	}
	for site := range benign {
		found := false
		for _, d := range disarmed {
			if d == site {
				found = true
			}
		}
		if !found {
			t.Errorf("site %q is classified benign in this cell but is NOT currently disarming "+
				"any gate. The classification is stale — its gate may have been retired or the "+
				"site may have left the scope — and a stale entry silently excuses the next "+
				"real disarm that lands on the same key. Delete it (#8690)", site)
		}
	}
	disarmed = unclassified
	if len(disarmed) > 0 {
		t.Errorf("%d site(s) in the normalizer's scope are REJECTED at strict "+
			"commit with the pass disabled and ACCEPTED with it enabled: %v.\n"+
			"That is not a spelling normalization — the pass runs before the "+
			"commit gates, so it is deleting the shape a gate was written to "+
			"refuse and turning a loud rejection into a silent acceptance "+
			"(the #6662 packed-login-body case). If the rejection is genuinely "+
			"obsolete, retire the GATE deliberately; do not disarm it as a side "+
			"effect of widening this scope (#8690).", len(disarmed), disarmed)
	}
}

// compactElidedCompilesEmpty compiles the elided spelling with the normalizer
// SUPPRESSED, so the question asked is the pre-normalization one: does the
// packed tail reach any reader?
func compactElidedCompilesEmpty(t *testing.T, parent []string, ctx, stanza, leaf, v string, empty *Config) bool {
	t.Helper()
	text := nest(parent, ctx+stanza+" "+leaf+" "+v+";")
	tree, perrs := NewParser(text).Parse()
	if len(perrs) > 0 || tree == nil {
		return true // unparseable here is the census's problem, not this cell's
	}
	// The same lenient opts compileText uses, plus the suppression — so the
	// only difference from the census's own measurement is the normalizer.
	opts := lenientCompileOpts()
	opts.skipCompactNormalize = true
	got, err := compileConfigWithOpts(tree, opts)
	if err != nil || got == nil {
		return true
	}
	got.Warnings = nil
	return cfgEqual(got, empty)
}

// #8690: the normalizer must not DISARM a commit gate, and this is the cell
// that caught it doing exactly that during development.
//
// The pass runs at compiler.go:210; the #6662 packed-login-body gate runs at
// :349. So a tree the normalizer has rewritten reaches that gate ALREADY
// un-packed, and the gate sees nothing to reject. Admitting `user`/`class` to
// scope turned this:
//
//	system login user u1 class super-user;   -> REJECTED at commit, with the
//	    error naming the consequence ("the account resolves to the fail-closed
//	    `unauthorized` class ... on a binary before #6701 it instead reached the
//	    legacy no-RBAC allow-everything mode")
//
// into a clean compile. That is not a spelling change: it converts a loud
// commit-time refusal into a silent acceptance, and makes an RBAC class compile
// on this binary that a peer on an older one still drops — the same HA-skew
// hazard #6662 was decided on.
//
// `filedByDesign` lists the four `system login user <u> authentication` leaves
// and NOT `class`, so the registry alone would not have stopped this. The gate
// governs the whole packed login body; only running it before and after shows
// that. Hence the exclusion in compactNormalizeInScope is by CONTAINER.
func TestCompactNormalizeDoesNotDisarmTheLoginPackedGate8690(t *testing.T) {
	tree, perrs := NewParser("system { login { user u1 class super-user; } }").Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	if _, err := CompileConfig(tree); err == nil {
		t.Error("a packed `system login user <u> class ...` body COMPILED CLEAN. " +
			"The #6662 gate must still reject it: normalizing that body before " +
			"the gate runs converts a commit-time refusal into a silent " +
			"acceptance and changes RBAC across an HA sync between binaries " +
			"that disagree (#8690)")
	}

	// ANTI-OVER-REJECT: the braced spelling is the one #6662 tells the operator
	// to write, so it must still compile. A gate that rejected both would
	// satisfy the assertion above while making the documented remedy fail.
	braced, perrs := NewParser("system { login { user u1 { class super-user; } } }").Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse braced: %v", perrs)
	}
	if _, err := CompileConfig(braced); err != nil {
		t.Errorf("the BRACED login body must still compile — it is the rewrite "+
			"#6662's own error message instructs the operator to make: %v", err)
	}
}

// compileStrict8690 compiles through the STRICT commit path — the one that runs
// the commit gates — optionally with the brace-elided normalizer disabled via
// the compileOpts seam. It returns the compile error so a caller can compare
// ACCEPTANCE against REJECTION, which is the distinction the compiled-result
// comparison cannot make.
func compileStrict8690(t *testing.T, text string, skipNormalize bool) error {
	t.Helper()
	tree, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		return fmt.Errorf("parse: %v", perrs)
	}
	_, err := compileConfigWithOpts(tree, compileOpts{skipCompactNormalize: skipNormalize})
	return err
}

// compileSeam8690 is compileStrict8690 returning the compiled Config, used to
// prove the seam is LIVE — see the seamObserved guard.
func compileSeam8690(t *testing.T, text string, skipNormalize bool) *Config {
	t.Helper()
	tree, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		return nil
	}
	cfg, err := compileConfigWithOpts(tree, compileOpts{skipCompactNormalize: skipNormalize})
	if err != nil || cfg == nil {
		return nil
	}
	cfg.Warnings = nil
	return cfg
}

// #8690 requirement: the pass must run at BOTH compile entry points.
//
// It is wired at both (compiler.go, compileConfigWithOpts and the node-aware
// sibling behind CompileConfigForNode), and until this cell existed that
// wiring was untested: deleting the call from the node-aware path reds NOTHING
// in the whole pkg/config suite. That path is the cluster one — Store.SyncApply
// and peer-interface display compile a peer's config through it — so losing the
// pass there does not fail, it makes a peer compile the SAME config
// DIFFERENTLY from the node that authored it. The authoring node folds the
// packed credential into a child and the peer leaves it packed; the two nodes
// then disagree about a pre-shared key or an authentication algorithm while
// both report a clean commit. That is the #8597 K51 asymmetry class, and it is
// exactly what the comment at that call site warns about.
//
// So this asserts the AGREEMENT between the two entry points rather than a
// literal compiled value: a future change to what the pass produces stays
// green here as long as both paths produce it, and any divergence reds.
func TestCompactNormalizeRunsAtBothCompileEntryPoints8690(t *testing.T) {
	const elided = `security { ike { policy p1 { pre-shared-key ascii-text "s3cret"; } } }`
	const packed = `security { ike { policy p1 pre-shared-key ascii-text "s3cret"; } }`

	// POSITIVE CONTROL: the pass must actually touch this input, or the
	// agreement below would hold for the trivial reason that there is nothing
	// to do — the same green a correctly-wired pair produces.
	probe, perrs := NewParser(packed).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	if n := normalizeCompactStanzas(probe); n == 0 {
		t.Fatalf("the fixture is not in the normalizer's scope, so this cell " +
			"cannot observe whether either entry point runs it. Pick a packed " +
			"stanza compactNormalizeInScope admits (#8690)")
	}

	braced := compileText(t, elided)
	if braced == nil {
		t.Fatal("the braced spelling must compile — it is the reference result")
	}
	viaPlain := compileText(t, packed)
	if viaPlain == nil || !cfgEqual(braced, viaPlain) {
		t.Error("the PLAIN entry point did not normalize the packed spelling to " +
			"the braced result (#8690)")
	}

	tree, perrs := NewParser(packed).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	viaNode, err := CompileConfigForNodeLenient(tree, 0)
	if err != nil || viaNode == nil {
		t.Fatalf("node-aware compile of the packed spelling failed: %v", err)
	}
	viaNode.Warnings = nil
	if !cfgEqual(viaPlain, viaNode) {
		t.Error("the two compile entry points DISAGREE on the packed spelling. " +
			"The node-aware path (Store.SyncApply, peer display) is not running " +
			"the brace-elided normalizer, so a cluster peer compiles this " +
			"credential differently from the node that authored it while both " +
			"report a clean commit — the #8597 K51 asymmetry class (#8690)")
	}
}

// The consequential member of family 3, asserted on the compiled config.
//
// `system services ssh root-login deny;` decides whether root may log in at
// all. Brace-elided, the value used to be dropped and the field compiled to
// "", which is not "deny" — the operator wrote a lockout and got the daemon's
// default, on a commit that reported success. That is the same shape as
// #8689's IS-IS authentication key and family 2's zone screen binding: a
// security control silently absent rather than loudly wrong.
//
// The seam supplies the positive half. Without it this cell would assert only
// that two spellings agree, which they would also do if the pass were removed
// and BOTH dropped the value — the vacuous green that "assert the agreement"
// is otherwise vulnerable to.
func TestElidedSSHRootLoginReachesTheDaemon8690(t *testing.T) {
	const braced = `system { services { ssh { root-login deny; } } }`
	const elided = `system { services { ssh root-login deny; } }`

	b, e := compileText(t, braced), compileText(t, elided)
	if b == nil || e == nil {
		t.Fatalf("both spellings must compile (braced=%v elided=%v)", b != nil, e != nil)
	}
	if b.System.Services.SSH.RootLogin != "deny" {
		t.Fatalf("fixture is wrong: the braced spelling must set root-login, got %q",
			b.System.Services.SSH.RootLogin)
	}
	if e.System.Services.SSH.RootLogin != "deny" {
		t.Errorf("brace-elided `ssh root-login deny` compiled to RootLogin=%q, not \"deny\". "+
			"The operator wrote a root lockout and the daemon received the default, "+
			"on a commit that reported success (#8690)", e.System.Services.SSH.RootLogin)
	}

	// POSITIVE CONTROL: with the pass disabled the elided spelling must NOT
	// carry the value. If it does, this cell is not observing the pass and
	// would stay green if the pass were deleted.
	tree, perrs := NewParser(elided).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	off, err := compileConfigWithOpts(tree, compileOpts{skipCompactNormalize: true})
	if err != nil || off == nil {
		t.Fatalf("un-normalized compile failed: %v", err)
	}
	if off.System.Services.SSH.RootLogin == "deny" {
		t.Error("with the normalizer DISABLED the elided spelling still carried " +
			"root-login, so this cell is not observing the pass and would stay " +
			"green if the pass were removed (#8690)")
	}
}

// knownUnexaminable8690 are sites the pass normalizes but whose reference
// spelling does not compile in isolation, so the safety property cannot be
// evaluated for them. They are NOT known-safe; they are known-unmeasured.
//
// Every entry needs a required sibling INSIDE the stanza that the synthesized
// fixture does not supply — a three-color-policer with no rate block, an
// ip-monitoring policy with no probe. That is the #8436 duplicate-block
// dependency lane-8526 measured: the compact spelling cannot carry the sibling
// and re-opening the instance does not merge, so these are unmeasurable by this
// method until #8436 lands, not merely unfixtured.
var knownUnexaminable8690 = []string{
	"class-of-service fairness rss-expectation interface xpfarg queue",
	"class-of-service fairness rss-expectation interface xpfarg queue xpfarg active-workers",
	"class-of-service fairness rss-expectation interface xpfarg queue xpfarg at-least-active-workers",
	"class-of-service fairness rss-expectation interface xpfarg queue xpfarg cstruct",
	"class-of-service fairness rss-expectation interface xpfarg queue xpfarg cstruct-max",
	"class-of-service fairness rss-expectation interface xpfarg queue xpfarg max-worker-flow-share",
	"firewall three-color-policer",
	"firewall three-color-policer xpfarg single-rate committed-burst-size",
	"firewall three-color-policer xpfarg single-rate committed-information-rate",
	"firewall three-color-policer xpfarg single-rate excess-burst-size",
	"firewall three-color-policer xpfarg then loss-priority",
	"firewall three-color-policer xpfarg two-rate committed-burst-size",
	"firewall three-color-policer xpfarg two-rate committed-information-rate",
	"firewall three-color-policer xpfarg two-rate peak-burst-size",
	"firewall three-color-policer xpfarg two-rate peak-information-rate",
	"services ip-monitoring policy xpfarg match rpm-probe",
	"services ip-monitoring policy xpfarg then preferred-route route xpfarg next-hop",
	"services ip-monitoring policy xpfarg then preferred-route routing-instance xpfarg route xpfarg next-hop",
}

// diffSiteSets8690 returns a human-readable difference between a measured set and an
// expected one, or "" when they match.
func diffSiteSets8690(got, want []string) string {
	w := map[string]bool{}
	for _, x := range want {
		w[x] = true
	}
	g := map[string]bool{}
	for _, x := range got {
		g[x] = true
	}
	var b strings.Builder
	for _, x := range got {
		if !w[x] {
			b.WriteString("  NEW (pass normalizes it, cell cannot see it): " + x + "\n")
		}
	}
	for _, x := range want {
		if !g[x] {
			b.WriteString("  GONE (now examinable, drop from the list): " + x + "\n")
		}
	}
	return b.String()
}

// #8690: every rule in compactNormalizeInScope must be scoped by (container,
// head) PAIR — never by a head alone, never by a container alone.
//
// This is not style. A head-only rule is safe only while no container acquires
// that head with a tail somebody reads; a container-only rule is safe only
// while no head appears under that container that somebody reads. Both make
// the predicate's correctness contingent on the CURRENT INVENTORY rather than
// on the rule, and this sweep moves the inventory. Such a rule therefore fails
// at the moment a family lands — inside someone else's merge conflict.
//
// Both directions really existed here. `head == "authentication-key"` was
// head-only, and `containerKeyword == "match"` was container-only and admitted
// `services ip-monitoring policy <p> match rpm-probe` — a different feature in
// a different subtree, reached only because it spells its criteria block
// `match`.
//
// The probe is a sentinel that cannot occur in any config: if the predicate
// still says yes when the container is replaced by a token no schema contains,
// it was not reading the container.
func TestNormalizerScopeIsPairScopedNotTokenScoped8690(t *testing.T) {
	const noSuchContainer = "xpf-no-such-container-8690"
	const noSuchHead = "xpf-no-such-head-8690"

	var headOnly, containerOnly []string
	checked := 0
	var walk func(n *schemaNode, kw string, depth int)
	walk = func(n *schemaNode, kw string, depth int) {
		if n == nil || depth > 9 {
			return
		}
		for name, ch := range n.children {
			if kw != "" && compactNormalizeInScope(kw, name) {
				checked++
				if compactNormalizeInScope(noSuchContainer, name) {
					headOnly = append(headOnly, kw+" "+name)
				}
				if compactNormalizeInScope(kw, noSuchHead) {
					containerOnly = append(containerOnly, kw+" "+name)
				}
			}
			walk(ch, name, depth+1)
		}
		if n.wildcard != nil {
			walk(n.wildcard, kw, depth+1)
		}
	}
	walk(setSchema, "", 0)

	// DEGENERACY CONTROL: if the walk admitted nothing, both checks above are
	// vacuous and this cell reports a clean scope for the same reason a correct
	// one does.
	if checked == 0 {
		t.Fatal("the schema walk found NO admitted pair, so the pair-scoping " +
			"assertions ran against nothing. Either the walk broke or the " +
			"predicate stopped admitting anything (#8690)")
	}
	sort.Strings(headOnly)
	sort.Strings(containerOnly)

	if len(headOnly) > 0 {
		t.Errorf("%d rule(s) admit on the HEAD ALONE — the predicate still says "+
			"yes with the container replaced by a token no schema contains: %v.\n"+
			"That rule is safe only until some other container acquires the same "+
			"head with a tail a reader consumes, and it will fail when a family "+
			"lands rather than when it is written. Scope it to the containers "+
			"that measured safe (#8690).", len(headOnly), dedupe8690(headOnly))
	}
	if len(containerOnly) > 0 {
		t.Errorf("%d rule(s) admit on the CONTAINER ALONE — the predicate still "+
			"says yes with the head replaced by a token no schema contains: %v.\n"+
			"That rule is safe only until some head appears under that container "+
			"that a reader consumes. `containerKeyword == \"match\"` was exactly "+
			"this and reached services ip-monitoring (#8690).",
			len(containerOnly), dedupe8690(containerOnly))
	}
	t.Logf("#8690: %d admitted (container, head) pair(s), none head-only or container-only", checked)
}

func dedupe8690(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range in {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}
