package config

// dupConservationInventory8436 is the ENUMERATION #8436 asked for: every named
// container where two hierarchical blocks do NOT compile to what the flat-set
// spelling produces.
//
// Why this instead of another registry row, in #8436's own words: every instance
// so far (#3884, #4287, #5180, #5631/#5878, #5649, #8426, #8427, #8433) was
// closed by adding a row or a bespoke gate, which is an OPT-IN pattern whose
// opt-ins were being discovered one review at a time. A registry-row test proves
// the row exists; it cannot see the next uncovered container, and the uncovered
// set was written down nowhere. It is written down here.
//
// A LINE HERE IS NOT AN ACCEPTED DEFECT. Each is one of two things, and the
// census's second (strict) compile is what tells them apart:
//
//   - REJECTED AT COMMIT — conservation achieved by refusal (namedDupRules or a
//     bespoke gate). The census compiles LENIENTLY, so it still sees the
//     reduction and the site stays listed; an operator never reaches it.
//   - SILENT — no commit gate at all. Configuration the operator authored is lost
//     with no diagnostic. THESE ARE THE CANDIDATES for the next fix.
//
// Reachability, which narrows the class usefully: flat-set `set` merges correctly
// in every measured case, so none of this is reachable through `set` commands —
// only a hierarchical config file, `load merge` or `load override`.
//
// Regenerate with TestDuplicateBlockConservationCensus8436 -v and read the
// NOT CONSERVED lines, which carry the verdict. Do not paste them in without
// reading the verdict column: a pinned list nobody reads is a list of defects
// with a checkmark next to it.
var dupConservationInventory8436 = []string{
	// ---- SILENT: no commit gate at all. ----
	//
	// EMPTY, as of #8436's last batch. Every container the census could reach
	// that lost configuration silently has been fixed; what remains below is
	// conservation achieved by REFUSAL, where an operator is told rather than
	// quietly given a different config.
	//
	// An empty section is not the end of the census's job — it is the state in
	// which the census earns its keep, because the next NEW non-conserving
	// container now fails TestDuplicateBlockConservationIsPinned8436 as a
	// regression instead of joining a list. Do not delete the section header:
	// a future site belongs here with a reason, not silently.

	// ---- Already REJECTED at strict commit (conservation by refusal) (9). ----
	"applications application",
	"chassis device-map interface",
	"protocols bgp group xpfname neighbor",
	"security flow traceoptions packet-filter",
	"security ike proposal",
	"security ipsec vpn xpfname traffic-selector",
	"security nat nat64 rule-set",
	"system services dhcp-local-server group xpfname pool xpfname static-binding",
	"system services dhcpv6-local-server group xpfname pool xpfname static-binding",
}

// dupConservationSkipped8436 is every named container the census could not
// CHECK — the second half of the enumeration, and the half that was missing.
//
// A SKIP IS NOT A PASS. Until this list existed the census reported skips as
// two integers, and `services rpm probe xpfname test` sat inside one of them
// for seven batches while silently losing configuration: two `test T` blocks
// overwrote each other, and the synthesized fixture omits the required
// `target`, so the compile failed and the site was COUNTED rather than checked.
// A number cannot be read as a defect. (That site is fixed now — see
// compiler_services.go — but it stays listed, because the census still cannot
// probe it.)
//
// TestDuplicateBlockConservationIsPinned8436 fails on a NEW skip and on a stale
// one, so a container the census cannot probe is a recorded decision rather
// than the one place a defect can hide from the guard #8436 asked for.
var dupConservationSkipped8436 = []string{
	// ---- "a spelling did not parse or compile" (5). ----
	//
	// The synthesized duplicate did not survive commit, which is EITHER
	// conservation by refusal OR a fixture the census cannot build. The two are
	// indistinguishable from the census alone, so each was checked BY HAND with
	// a complete config and the verdict recorded here.
	//
	// REFUSED at commit — duplicate policy name in a zone pair is a hard reject
	// (#3473: the duplicate shares a name-keyed hit counter).
	//
	// #8752: THAT REASON IS A STRICT-PATH FACT, AND THIS CENSUS GOVERNS BOTH
	// PATHS. `Store.Load` and `Store.SyncApply` compile leniently — which is the
	// entire point of them, since they read configurations the operator did not
	// just author — and the lenient path does NOT refuse. Measured:
	//
	//	security policies from-zone <a> <b> <c> policy   strict REJECTED, lenient ACCEPTED -> 2 policies
	//	security policies global policy                  strict REJECTED, lenient ACCEPTED -> 2 policies
	//
	// So both entries are exempted here on a rejection that does not happen on
	// the path where the defect lives, and the duplicate WINS: the operator's
	// policy keeps its match criteria while the spurious one contributes a
	// match-less deny. #8752 tracks the fold itself.
	//
	// The entries STAY — the census genuinely cannot synthesize these, so
	// skipping is right — but the REASON is annotated rather than left standing,
	// because a skip with a stated reason reads as settled and nobody
	// re-derives it. A census governing two compile paths cannot take an
	// exception justified on only one; "REFUSED at commit" is unanswerable for
	// the tolerant path by construction.
	"security policies from-zone xpfname xpfname xpfname policy",
	"security policies global policy",
	// REFUSED at commit — "duplicate expectation \"any\" conflicts with
	// \"balanced\"".
	// #8752: re-checked on the LENIENT path too, and this one is correctly
	// skipped — it is refused on BOTH paths (lenient rejects it as well), so the
	// exemption does not rest on a strict-path-only fact. Recorded so the
	// re-check is visible: two of the three entries in this group were wrong and
	// this one was not, which is the difference a reader needs.
	"class-of-service fairness rss-expectation interface xpfname queue",
	// CONSERVES. The census fixture omits the required `match rpm-probe`; with a
	// complete config the duplicate compiles identically to the merged form.
	"services ip-monitoring policy xpfname then preferred-route route",
	// DID NOT CONSERVE, now FIXED. The census fixture omits the required
	// `target`. With a complete config two `test T` blocks overwrote each other
	// — the probe level had been fixed, the test level one layer down had not.
	// This is the site that motivated pinning the skip set.
	"services rpm probe xpfname test",

	// ---- "second leaf not observable in the typed config" (14). ----
	//
	// #8662: was 15. `system login user` left this list when the compact/block
	// census's value synthesis learned to read the schema's valueHint — its
	// second leaf became observable, so the skip entry was claiming a blindness
	// the census no longer has. The two censuses share synthPair, so an
	// improvement to the instrument moves both.
	//
	// The census's own VACUITY guard, and structurally uninteresting for this
	// property rather than unverified: the merged form compiles identically to a
	// block carrying only the first leaf, so the second leaf is invisible to the
	// typed config and the site cannot show a loss either way. Listed so the set
	// is BOUNDED — a container that newly becomes unobservable is a change worth
	// noticing, not a silent drop in coverage.
	"class-of-service interfaces xpfname unit",
	"protocols bgp group",
	"protocols router-advertisement interface xpfname prefix",
	"routing-options rib xpfname static route",
	"routing-options rib xpfname static route xpfname qualified-next-hop",
	"routing-options static route",
	"routing-options static route xpfname qualified-next-hop",
	"security ipsec proposal",
	"security log stream",
	"system services dhcp-local-server group xpfname interface",
	"system services dhcpv6-local-server group xpfname interface",
	"system syslog file",
	"system syslog host",
	"system syslog user",
}
