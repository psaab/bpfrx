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
	b.WriteString("#\n")
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
	for _, s := range res.divergent {
		b.WriteString(s + "\n")
	}
	if err := os.WriteFile(inventoryPath, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %d divergent sites, checked=%d", len(res.divergent), res.checked)
}
