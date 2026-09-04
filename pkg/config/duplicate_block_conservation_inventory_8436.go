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
	// ---- SILENT: no commit gate at all. The candidate list (16). ----
	"class-of-service interfaces",
	"class-of-service schedulers",
	"class-of-service traffic-control-profiles",
	"protocols isis interface",
	"protocols ospf area xpfname interface",
	"protocols ospf3 area xpfname interface",
	"protocols router-advertisement interface",
	"system ntp server",
	"system services dynamic-dns provider",

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
