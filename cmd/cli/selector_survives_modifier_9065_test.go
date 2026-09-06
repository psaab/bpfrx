// #9065 COMPLETENESS GATE.
//
// The defect class is an ordering one: `cmd/cli` branched on a positional
// `args[1]` ladder BEFORE extracting selectors, so at whichever token a ladder
// failed to enumerate, the MODIFIER overwrote the SELECTOR (or both were
// dropped). Per-command cells cannot close that — the class re-opens at the
// next word, which is empirically what happened when `global` was fixed on the
// filtered policy path and `brief` was left broken one line above it.
//
// So this gate is a CENSUS, not a list. It enumerates every node in
// pkg/cmdtree's operational tree that declares a VALUE SLOT beside KEYWORD
// CHILDREN — the exact shape in which a selector and a modifier can both
// appear — and drives the remote CLI with each (selector, modifier) pair. A
// node added to the tree later is covered the day it is added.
//
// THE PREDICATE IS "NOT SILENTLY DROPPED", NOT "ALWAYS CARRIED", and the
// distinction is what keeps the gate from forcing a workaround. The census is
// a cross product, so it generates pairs that are not real commands
// (`show interfaces <name> tunnel` — `tunnel` is an inventory of tunnel
// interfaces and takes no name). Demanding the selector reach the wire there
// would demand the client invent a filter the daemon has no way to apply. What
// the operator must never get is the third outcome: a request issued for a
// DIFFERENT question, with the selector discarded and nothing said. So each
// pair must either carry the selector into the request, or be refused with an
// error. Both are honest; only silence is the defect.
//
// Measured before the fix, this gate reported six drops — one named on the
// issue (`show interfaces <if> extensive`) and five it did not contain
// (`queue`, `statistics`, `tunnel`, and both `show security zones` forms).
//
// WHAT THIS GATE CANNOT SEE, stated because a stated blind spot is a claim and
// this one was measured rather than assumed:
//
//  1. A dispatcher that REFUSES EVERYTHING passes. "Carry or refuse" is
//     satisfied by refusing, so breaking cmdtree.SplitModifiers — so that no
//     word is ever a modifier, or none is ever a selector — makes every pair
//     land in the "unexpected argument" arm and scores a clean board. Both
//     mutations were run and both SURVIVED this gate; they are killed only by
//     the per-command cells beside it.
//  2. A selector honoured CLIENT-SIDE is indistinguishable from one dropped.
//     `show security policies from-zone X to-zone Y` sends an empty
//     GetPolicies and filters the response (showPoliciesFiltered), and so do
//     the `show security zones` and NAT-pool paths this change fixed — the
//     issue prescribes client-side scoping for the NAT pool precisely because
//     the request carries no selector to send.
//
// (2) is why the obvious strengthening of (1) — "every census node must have at
// least one modifier that carries the selector into the request" — is NOT here.
// It was written, run, and withdrawn: it reported the from-zone/to-zone pair
// and the cos rewrite-rule pair as silent drops, and both are correct code. A
// gate that manufactures evidence for a defect that is not there is worse than
// one with a stated hole. The sound version of that predicate is an OUTPUT
// differential — the same command with and without the selector must not
// produce identical output — which needs per-RPC response fixtures this
// generic recorder deliberately does not have. Tracked separately.

package main

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/cmdtree"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc"
)

// selectorRecorder captures every RPC the remote CLI issues, generically. It
// implements grpc.ClientConnInterface, which is the ONE chokepoint every
// generated client method funnels through — a per-method fake would have to be
// extended for each new RPC and would silently stop covering the census.
type selectorRecorder struct {
	method string
	req    string
	calls  int
}

func (r *selectorRecorder) Invoke(_ context.Context, method string, args, _ any, _ ...grpc.CallOption) error {
	r.method, r.req, r.calls = method, fmt.Sprintf("%+v", args), r.calls+1
	return nil
}

func (r *selectorRecorder) NewStream(context.Context, *grpc.StreamDesc, string, ...grpc.CallOption) (grpc.ClientStream, error) {
	return nil, fmt.Errorf("streaming RPCs are out of scope for this gate")
}

// valueSlotNodes9065 is the census: operational-tree paths whose node declares
// a value slot AND carries keyword children.
func valueSlotNodes9065() [][]string {
	var out [][]string
	var walk func(prefix []string, m map[string]*cmdtree.Node)
	walk = func(prefix []string, m map[string]*cmdtree.Node) {
		for name, n := range m {
			if n == nil {
				continue
			}
			p := append(append([]string{}, prefix...), name)
			if (n.HasDynamic() || n.AcceptsArgs || n.IsTypedLeaf()) && len(n.Children) > 0 {
				out = append(out, p)
			}
			walk(p, n.Children)
		}
	}
	walk(nil, cmdtree.OperationalTree)
	sort.Slice(out, func(i, j int) bool {
		return strings.Join(out[i], " ") < strings.Join(out[j], " ")
	})
	return out
}

func nodeAt9065(t *testing.T, path []string) *cmdtree.Node {
	t.Helper()
	node := cmdtree.OperationalTree[path[0]]
	for _, w := range path[1:] {
		if node == nil {
			t.Fatalf("census produced a path that does not resolve: %v", path)
		}
		node = node.Children[w]
	}
	return node
}

// dispatch9065 runs one command line through the remote CLI and reports what
// happened to the selector.
func dispatch9065(t *testing.T, args []string, selector string) (carried bool) {
	t.Helper()
	rec := &selectorRecorder{}
	c := &ctl{client: pb.NewBpfrxServiceClient(rec)}
	err := c.handleShow(args)
	if err != nil {
		if strings.TrimSpace(err.Error()) == "" {
			t.Fatalf("`show %s` was refused with an EMPTY message",
				strings.Join(args, " "))
		}
		return false
	}
	if rec.calls == 0 {
		t.Fatalf("`show %s` issued NO request and reported NO error, so the operator "+
			"sees empty output and is told nothing", strings.Join(args, " "))
	}
	if !strings.Contains(rec.req, selector) {
		t.Fatalf("#9065 SELECTOR SILENTLY DROPPED.\n"+
			"  command: show %s\n"+
			"  issued : %s\n"+
			"  request: %s\n"+
			"The selector reached no field of the request and no error was returned, "+
			"so the daemon answers a DIFFERENT question and nothing tells the "+
			"operator their selector was discarded. Either bind it or refuse the "+
			"command — silence is the defect.",
			strings.Join(args, " "), rec.method, rec.req)
	}
	return true
}

func TestShowSelectorSurvivesModifier9065(t *testing.T) {
	// Two shapes of a value distinctive enough that finding it in the rendered
	// request is proof it came from the command line and not from a default.
	const selector = "zzselector9065zz"

	paths := valueSlotNodes9065()
	if len(paths) == 0 {
		t.Fatal("NON-VACUITY: the census found no value-slot-with-modifiers node, so " +
			"every assertion below is vacuous. Either the tree changed shape or the " +
			"walk is broken; a clean board here is not a pass.")
	}

	covered, carried, refused := 0, 0, 0
	for _, path := range paths {
		if path[0] != "show" {
			// `monitor`/`request`/`test` have their own dispatchers; this gate
			// is scoped to handleShow. The census still WALKS them, so the
			// count below records how much of the class is left uncovered
			// rather than letting the scope silently look total.
			continue
		}
		node := nodeAt9065(t, path)
		var mods []string
		for k := range node.Children {
			mods = append(mods, k)
		}
		sort.Strings(mods)

		for _, mod := range mods {
			covered++
			args := append(append([]string{}, path[1:]...), selector, mod)
			line := strings.Join(args, " ")
			t.Run(strings.ReplaceAll(line, " ", "_"), func(t *testing.T) {
				if dispatch9065(t, args, selector) {
					carried++
				} else {
					refused++
				}
			})
		}
	}
	if covered == 0 {
		t.Fatal("NON-VACUITY: no `show` pair was exercised")
	}
	// GLOBAL POSITIVE FLOOR. "Carry or refuse" is satisfied by refusing
	// everything, and a broken cmdtree.SplitModifiers does exactly that — both
	// such mutations SURVIVED this gate before this line existed. One carry
	// somewhere is the weakest claim that kills them, and unlike a per-node
	// floor it makes no assertion about rows whose selector is honoured
	// client-side (see the header).
	if carried == 0 {
		t.Fatalf("#9065: NOT ONE of %d (selector, modifier) pairs carried its selector "+
			"into a request — every one was refused. A dispatcher that refuses "+
			"everything satisfies the per-pair rule above and is what a broken "+
			"modifier split looks like.", covered)
	}
	t.Logf("#9065 gate: %d pairs over %d census nodes — %d carried the selector, "+
		"%d refused. A pair counted REFUSED is honest but says nothing about "+
		"binding; a drop in `carried` across a change is worth reading.",
		covered, len(paths), carried, refused)
}
