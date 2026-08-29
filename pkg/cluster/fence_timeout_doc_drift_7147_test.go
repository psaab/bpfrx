package cluster

import (
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Every duration the operator-facing doc states for FenceConfirmTimeout must
// equal the constant.
//
// WHY THIS EXISTS. The doc and the constant have already disagreed once. The
// constant was raised 250ms -> 1s during the #7147 review after the original
// rationale turned out to be wrong on the facts; the code comment and the PR
// body were updated and the doc's cost table was not. A later doc edit then
// built ON the stale figure, reproducing 250 ms in new prose while the shipped
// behaviour was 1s — committed, as it happens, by the person reviewing the
// drift, who took the number from a PR description rather than from the tree.
// Nothing could catch it: both halves were internally consistent and each read
// as authoritative.
//
// The one-time figure has since been corrected. This guards the NEXT one, which
// is the part a correction cannot do by itself.
//
// It asserts the AGREEMENT rather than pinning the doc to a literal. A literal
// pin would move the drift into this file and would have to be updated by the
// same edit that already got missed — the failure mode it is supposed to
// prevent. It is also deliberately NOT keyed on the specific stale value (250),
// because a guard against one historical number ages into decoration; it is
// keyed on the property "a duration stated next to this constant's name must be
// this constant's value".
func TestDocsFenceConfirmTimeoutMatchesTheConstant7147(t *testing.T) {
	t.Parallel()
	const docPath = "../../docs/ha-failover-status.md"
	raw, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatalf("read %s: %v", docPath, err)
	}

	// A duration literal: "250ms", "250 ms", "1s", "1 s".
	durRe := regexp.MustCompile(`([0-9]+(?:\.[0-9]+)?)\s*(ms|s)\b`)

	stated := 0
	for i, line := range strings.Split(string(raw), "\n") {
		if !strings.Contains(line, "FenceConfirmTimeout") {
			continue
		}
		for _, m := range durRe.FindAllStringSubmatch(line, -1) {
			got, err := time.ParseDuration(m[1] + m[2])
			if err != nil {
				continue
			}
			stated++
			if got != FenceConfirmTimeout {
				t.Errorf("%s:%d states %s beside FenceConfirmTimeout, but the constant "+
					"is %s.\n  line: %s\nAn operator sizing a failover budget reads the "+
					"doc, not the source, and this pair has silently disagreed once "+
					"before.", docPath, i+1, got, FenceConfirmTimeout, strings.TrimSpace(line))
			}
		}
	}

	// Guard the guard. With no duration stated anywhere near the constant this
	// scan matches nothing and passes — a doc that stopped documenting the
	// bound would then look identical to one that documents it correctly, which
	// is the vacuous-pass shape this whole test exists to avoid.
	if stated == 0 {
		t.Fatalf("%s states no duration alongside FenceConfirmTimeout, so this guard "+
			"checked nothing. Either the doc stopped naming the bound (restore it — an "+
			"operator needs the number) or the wording moved out of reach of this scan "+
			"(update the scan).", docPath)
	}

	// A note for anyone who reds this on an unrelated number: the scan reads
	// EVERY duration on a line that names the constant. If a future sentence
	// legitimately mentions another duration on that same line (say the 3s
	// control-socket deadline), split it onto its own line rather than
	// weakening this check.
}
