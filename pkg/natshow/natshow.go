// Package natshow renders the security/NAT operational show topics that
// the gRPC ShowText path (pkg/grpcapi/server_show_nat.go) and the CLI
// show path (pkg/cli/cli_show_nat.go) previously duplicated verbatim.
//
// Background (#1687, promoted from #1661 item 3): the broad "shared
// security/NAT/flow presentation package" premise was killed at plan
// time — the security topics (alg, address-book, applications, screen,
// ike, security-log, dynamic-address) are independently authored,
// structurally divergent operator contracts and are intentionally NOT
// shared. The NAT detail/table renderers, by contrast, were
// byte-identical between the two consumers (differing only in the
// output sink: gRPC writes a *strings.Builder, the CLI prints to
// os.Stdout, plus a return/return-nil wrapper). Those six renderers
// move here behind an io.Writer sink so both consumers single-source
// them. Golden tests on both consumers assert byte-identical output
// vs the pre-extraction master behavior.
//
// The functions take the gRPC behavior as the canonical contract (the
// gRPC nil/empty guards are reproduced verbatim; the trailing-newline
// shape is the gRPC "\n\n" form, which equals the CLI's
// fmt.Printf("...\n")+fmt.Println() byte-for-byte).
//
// This package imports root pkg/dataplane only for the session/counter
// types named by the session-iteration callbacks and counter reads
// (SessionKey/Value, CounterValue, PersistentNATTable). That import is
// tracked in the #1451 retirement-boundary canary allowlist
// (pkg/dataplane/retirement_boundary_canary_test.go) and the docs table
// in docs/pr/1373-retire-ebpf-dataplane/README.md — it is a net-neutral
// consolidation of the import that already lived in the two source
// files, not #1451 regressing. natshow must never import pkg/grpcapi or
// pkg/cli.
package natshow

import (
	"fmt"
	"io"

	"github.com/psaab/xpf/pkg/dataplane"
)

// noteSessionScanError emits a caveat line when a dataplane session scan
// that backs the per-rule / per-binding "active session" counts failed.
// The detail renderers scan the conntrack table to tally sessions; a
// transient read error (map busy, dataplane reload) otherwise left the
// counts silently understated — a zero that reads as "no sessions"
// rather than "could not read". Surfacing the error tells the operator
// the displayed counts are partial (#5557).
func noteSessionScanError(w io.Writer, err error) {
	if err != nil {
		fmt.Fprintf(w, "Warning: active session counts may be incomplete: %v\n", err)
	}
}

// noteNotInstalled emits the #6534 exclusion annotation for a NAT object the
// userspace snapshot builder drops or disarms. reason is the operator-facing
// text from the shared pkg/config predicate that the BUILDER also consults, so
// the annotation cannot claim something the dataplane disagrees with.
//
// Nothing is printed when reason is empty, so an installed rule's output is
// byte-identical to the pre-#6534 form — the golden tests on both consumers
// keep asserting the same bytes for every healthy config, and only a rule the
// dataplane is genuinely not enforcing gains a line.
//
// The wording leads with NOT INSTALLED rather than appending a parenthetical to
// the Action line: an operator scanning a long rule list is looking down the
// left margin, and a rule that is silently unenforced is exactly the thing that
// must not read as a footnote.
func noteNotInstalled(w io.Writer, reason string) {
	if reason == "" {
		return
	}
	fmt.Fprintf(w, "    Status:                  NOT INSTALLED — %s\n", reason)
}

// noteNotInstalledStatic is noteNotInstalled at the static-NAT renderers' wider
// label column ("Match destination-address:" / "Then static-nat prefix:"), so
// the annotation lines up with the fields it is qualifying instead of hanging
// four columns short of them.
func noteNotInstalledStatic(w io.Writer, reason string) {
	if reason == "" {
		return
	}
	fmt.Fprintf(w, "    Status:                    NOT INSTALLED — %s\n", reason)
}

// Reader is the narrow dataplane surface the NAT renderers need. Both
// the gRPC grpcRuntime (pkg/grpcapi/runtime.go) and the CLI cliRuntime
// (pkg/cli/runtime.go) already satisfy it structurally. A nil Reader is
// permitted and reproduces the "not loaded" / unavailable branches.
type Reader interface {
	IsLoaded() bool
	IterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error
	IterateSessionsV6(fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error
	ReadNATRuleCounter(counterID uint32) (dataplane.CounterValue, error)
	GetPersistentNAT() *dataplane.PersistentNATTable
}
