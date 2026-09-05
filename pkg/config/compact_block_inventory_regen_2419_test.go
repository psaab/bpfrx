package config

import (
	"os"
	"strconv"
	"strings"
	"testing"
)

// TestRegenerateCompactBlockInventory2419 rewrites the checked-in inventory
// from a live census. It is ENV-GATED and skipped by default: a golden that
// regenerates itself on every run is not a gate, it is a transcript.
//
// Regenerate ONLY when you have classified the diff. Lines REMOVED mean sites
// you fixed; lines ADDED mean compact-blind readers you introduced, and adding
// them here instead of fixing them converts the gate into an allowlist. The
// PR 2 normalizer should drive this file to zero data lines, and the diff is
// the evidence for that claim.
//
//	XPF_GEN_2419=1 go test -run TestRegenerateCompactBlockInventory2419 ./pkg/config/
//
// inventoryNotes is prose that must SURVIVE regeneration.
//
// #8662: the #6940 note below was hand-written into the inventory file and this
// generator silently destroyed it on the next run, because it rewrites the
// whole header. Prose in a generated file is not durable unless the generator
// emits it, so anything worth keeping lives here.
const inventoryNotes = `#
# NOTES (edit these in compact_block_inventory_regen_2419_test.go, not in the
# generated file — the generator rewrites the header and would drop them).
#
# #6940 raised the checked count 546 -> 547 and added
# ` + "`interfaces xpfname aggregated-ether-options minimum-links`" + `. That site
# is NOT a new compiler defect — it is a pre-existing compact-blind reader that
# this census could not SEE until #6940 landed.
#
# Before #6940 the leaf carried no valueType or valueExamples, so the census
# synthesised the generic pair "xpfaaa"/"xpfbbb"; the compiler parsed both with
# ` + "`x, _ = strconv.Atoi(v)`" + `, whose discarded error made BOTH compile to 0.
# The value therefore did not change the compiled config, the vacuity guard
# fired, and the cell was recorded "skipped: leaf value not observable" —
# measured both ways. Giving the leaf a validator and integer examples made the
# two probe values observable, and the compact spelling is genuinely blind.
#
# So one defect was masking another: a blind-spot count that RISES after a fix
# is the fix working. Fixing the compact reader is #2419's job, not #6940's.
#
# #8662 raised the checked count 547 -> 654 and added 97 sites, removing NONE.
# The census predicate required the folded token to declare no children, which
# excluded an entire class SILENTLY — those sites appeared in no skip bucket, so
# the "the census is a FLOOR" note did not account for them. Declaring children
# for ` + "`?`" + ` completion says nothing about whether the compiler reads a folded
# tail, so the predicate was excluding sites for a reason unrelated to the
# property being measured. Both of #8662's hand-verified members sat in it;
# ` + "`class-of-service schedulers xpfarg transmit-rate`" + ` is now tracked here.
#
# #8662 second half raised checked 654 -> 656 and added ONE site, removing none:
# ` + "`security zones security-zone xpfarg interfaces`" + `, the member this issue
# was filed on. It needed a site-MODEL change rather than another predicate
# relaxation — ` + "`interfaces`" + ` there is args:0 with a wildcard for the interface
# name, so the census's assumption that an instance is named by an ` + "`args`" + `
# token excluded it even after the children-bearing widening. synthPair now
# varies the wildcard INSTANCE NAME for that shape.
#
# Measured as its own variable before landing: 15 sites in the class, 9 under
# groups, 1 uncompilable, 3 not-observable, 1 EQUIVALENT and 1 DIVERGENT. The
# equivalent one — ` + "`chassis cluster redundancy-group <n> ip-monitoring family inet`" + `
# — is kept as an over-reach control, deliberately in the chassis-cluster area,
# because that is where this issue's prescribed blanket rule broke the shipped
# HA config.
#
# The standalone probe and the gate's own accounting agreed (+2 checked, +1
# divergent). An earlier probe of this shape did NOT agree with the gate (97 vs
# 60) because it varied two conditions at once; the disagreement is what caught
# it. Where the two accountings differ, neither number is usable.
#
# #8690 unruled-fixture sweep, first increment: checked 677 -> 685, divergent
# 186 -> 191, "no two distinct synthesizable values" 17 -> 7. NOTHING was
# removed — every line of the change is a site that became RULABLE.
#
# The 10 that moved were a verdict about synthPair, not about the leaf:
#
#   - THREE declared value types the type switch never covered (ValueHostname,
#     ValueDate, ValueUnixSocketPath), so six leaves fell through to the
#     one-example bailout;
#   - FIVE ValueEnumOf leaves declaring one example, whose accepted set lives
#     in a ValidateEnum closure. The set does not have to be duplicated here:
#     ValidateEnum NAMES it when it rejects, so a deliberately invalid probe
#     makes the schema state its own answer, and every candidate extracted is
#     re-verified against the same validator. See enumPairFromValidator.
#
# Where they landed: 5 DIVERGENT (` + "`schedulers scheduler <s> start-date`" + `,
# ` + "`stop-date`" + `, ` + "`system dataplane control-socket`" + `, ` + "`system domain-name`" + `,
# ` + "`system services ssh protocol-version`" + `), 3 EQUIVALENT, and 2 that moved to
# the "not observable" bucket — still unruled, but now for the FIXTURE reason
# a contextFor entry addresses rather than for a missing synthesiser.
#
# A blind-spot count that RISES after a fix is the fix working. The five new
# divergent sites are not new defects; they are compact-blind readers this
# census could not see, in ` + "`schedulers`" + ` and ` + "`system`" + `.
#
# Seven sites remain in the no-pair bucket and SIX of them are declared inert
# by their own valueDesc — ` + "`authentication-type`" + ` ("not an OSPF leaf") and the
# four ` + "`system login class`" + ` regexp leaves ("not implemented by xpf"). They are
# not fixture failures and no synthesiser should invent a pair for them; the
# seventh, ` + "`security nat source interface port-overloading`" + `, declares one
# example and a validator whose message does not enumerate.
#`

func TestRegenerateCompactBlockInventory2419(t *testing.T) {
	if os.Getenv("XPF_GEN_2419") != "1" {
		t.Skip("env-gated: set XPF_GEN_2419=1 to regenerate the inventory (classify the diff first)")
	}
	res := runCompactBlockCensus(t)
	var b strings.Builder
	b.WriteString("# #2419 compact/block equivalence — KNOWN-FAILING INVENTORY\n")
	b.WriteString("#\n")
	b.WriteString("# Each line is a config site whose COMPACT spelling (`stanza leaf value;`)\n")
	b.WriteString("# compiles to a different typed config than its BLOCK spelling\n")
	b.WriteString("# (`stanza { leaf value; }`) — i.e. a compiler stanza that reads only\n")
	b.WriteString("# prop.Children and silently drops the value.\n")
	b.WriteString("#\n")
	b.WriteString("# This is an EXPECTED-FAILURE list, not a suppression. The gate in\n")
	b.WriteString("# compact_block_equivalence_2419_test.go asserts the divergent set EQUALS\n")
	b.WriteString("# this file, so a new compact-blind reader reds the suite and a site fixed\n")
	b.WriteString("# without removing its line reds it too.\n")
	b.WriteString("#\n")
	b.WriteString("# `xpfarg` / `xpfname` are synthesized instance names.\n")
	b.WriteString(inventoryNotes + "\n")
	b.WriteString("# checked: ")
	b.WriteString(strconv.Itoa(res.checked))
	b.WriteString("\n#\n")
	for _, k := range []string{
		"leaf value not observable in the typed config",
		"a spelling did not parse or compile",
		"no two distinct synthesizable values",
		"under groups (schema re-host, duplicate coverage)",
	} {
		b.WriteString("# skipped (" + k + "): " + strconv.Itoa(res.skipped[k]) + "\n")
	}
	b.WriteString("#\n")
	for _, site := range res.divergent {
		// #8662: site TAB shape. The shape is what the compact spelling
		// produced — "empty" (the folded value contributed nothing) or
		// "partial" (something was read, but not what was written). A
		// normalizer may only truncate a tail whose shape is "empty", because
		// that is the measurement that no reader consumes it.
		if shape := res.dropShape[site]; shape != "" {
			b.WriteString(site + "\t" + shape + "\n")
			continue
		}
		b.WriteString(site + "\n")
	}
	if err := os.WriteFile(inventoryPath, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %d divergent sites, checked=%d", len(res.divergent), res.checked)
}
