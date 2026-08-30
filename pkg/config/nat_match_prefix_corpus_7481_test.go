package config

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"testing"
)

// #7481: the Go NAT match-prefix gate and the Rust parsers disagreed, and the
// agreement was asserted by COMMENT.
//
// `natMatchPrefixParses`'s doc claimed it "mirrors the Rust NAT match-prefix
// parser EXACTLY" and named three consumers. One Go predicate, asserted to
// mirror two structurally different Rust implementations, by prose.
//
// Measured across all three over one corpus:
//
//	10.0.0.0/+24   Go reject   ipnet reject   static_nat ACCEPT
//	10.0.0.0/024   Go ACCEPT   ipnet REJECT   static_nat ACCEPT
//
// The second was listed in the issue as a CONTROL that agreed. It does not, and
// it inverts the severity: `/+24` is rejected by this gate so it can only
// arrive through the tolerant load path, whereas `/024` passed an ORDINARY
// STRICT COMMIT and was then dropped by `parse_match_prefix` — a fail-closed
// drop, so the rule matched NOTHING. A NAT rule the operator committed
// successfully that silently never fires.
//
// THE CORPUS IS ONE FILE, read by this test and by the Rust side's
// `nat_match_prefix_corpus_7481` over the same path. Two hand-maintained lists
// is the disease this issue is about, one layer up. A literal added here is
// automatically asserted in both languages; a literal that only one side knows
// about cannot exist.

const natPrefixCorpusPath7481 = "../../testdata/nat_match_prefix_corpus.txt"

type natPrefixCase7481 struct {
	literal string
	accept  bool
	line    int
}

func loadNATPrefixCorpus7481(t *testing.T) []natPrefixCase7481 {
	t.Helper()
	f, err := os.Open(natPrefixCorpusPath7481)
	if err != nil {
		t.Fatalf("open corpus: %v", err)
	}
	defer f.Close()

	var out []natPrefixCase7481
	sc := bufio.NewScanner(f)
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		verdict, quoted, ok := strings.Cut(text, "\t")
		if !ok {
			t.Fatalf("corpus line %d is not <verdict>TAB<quoted literal>: %q", line, text)
		}
		lit, err := strconv.Unquote(strings.TrimSpace(quoted))
		if err != nil {
			t.Fatalf("corpus line %d: literal is not a quoted string: %v", line, err)
		}
		switch strings.TrimSpace(verdict) {
		case "accept":
			out = append(out, natPrefixCase7481{lit, true, line})
		case "reject":
			out = append(out, natPrefixCase7481{lit, false, line})
		default:
			t.Fatalf("corpus line %d: verdict %q is not accept/reject", line, verdict)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	return out
}

func TestGoGateMatchesTheSharedCorpus7481(t *testing.T) {
	corpus := loadNATPrefixCorpus7481(t)

	// ANTI-VACUITY. A corpus that failed to load, or one with only one verdict,
	// makes every assertion below trivially true — and this test's whole job is
	// to be the thing that fails when the two languages drift.
	if len(corpus) < 20 {
		t.Fatalf("loaded only %d corpus entries; the file is missing or truncated, "+
			"and a short corpus is an agreement nobody checked", len(corpus))
	}
	var accepts, rejects int
	for _, c := range corpus {
		if c.accept {
			accepts++
		} else {
			rejects++
		}
	}
	if accepts == 0 || rejects == 0 {
		t.Fatalf("corpus has %d accepts and %d rejects; a single-verdict corpus is "+
			"satisfied by a predicate that always answers the same way", accepts, rejects)
	}

	for _, c := range corpus {
		if got := natMatchPrefixParses(c.literal); got != c.accept {
			t.Errorf("corpus line %d: natMatchPrefixParses(%q) = %v, want %v.\n"+
				"The Go gate and the Rust parsers must classify every literal the same "+
				"way — a divergence means a config either commits and never matches, or "+
				"is refused at commit while the dataplane would have installed it (#7481)",
				c.line, c.literal, got, c.accept)
		}
	}
}

// The EXPORTED wrapper must agree with the unexported predicate, since the
// userspace snapshot builders bind to the exported one (#7215).
func TestExportedWrapperAgrees7481(t *testing.T) {
	for _, c := range loadNATPrefixCorpus7481(t) {
		if NATMatchPrefixParses(c.literal) != natMatchPrefixParses(c.literal) {
			t.Errorf("NATMatchPrefixParses and natMatchPrefixParses disagree on %q",
				c.literal)
		}
	}
}
