package grpcapi

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// #6851 residual closure. attachPeerSessions fuses the sanitize with the attach
// so that dropping the guard also drops the attach and fails loudly — but
// attachPeerSessions' own doc names what that does NOT cover:
//
//	Replacing this call with a bare `resp.Peer = peerResp` would not be caught
//	here.
//
// That is exact: the behavioural tests drive attachPeerSessions, so they bind
// the pair, but nothing binds fetchPeerSessions' call TO it. Binding it
// behaviourally needs a live cluster.Manager with PeerAlive() plus a real
// authenticated peer dial, which a unit test cannot reach. So it is bound
// structurally instead.
//
// SCOPE, stated rather than implied. This checks ONE function, fetchPeerSessions,
// for two properties: it must call attachPeerSessions, and it must not assign
// resp.Peer directly. It does not verify the sanitizing is correct (the
// behavioural tests do that), and it deliberately does not police the other
// `resp.Peer = peerResp` sites in this file — getSessionSummary at ~:927 and
// getZonePairSummary at ~:1039 attach AGGREGATE responses that carry no
// per-session policy name, so routing them through a session sanitizer would be
// wrong, not safer.
func TestPeerSessionFanOutGoesThroughAttach_6851(t *testing.T) {
	const (
		file   = "server_sessions.go"
		target = "fetchPeerSessions"
		helper = "attachPeerSessions"
	)

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}

	var fn *ast.FuncDecl
	for _, decl := range f.Decls {
		if fd, ok := decl.(*ast.FuncDecl); ok && fd.Name.Name == target {
			fn = fd
			break
		}
	}
	if fn == nil {
		t.Fatalf("%s not found in %s — this canary is keyed to that function by name, so a "+
			"rename must bring it along rather than silently disarm it", target, file)
	}

	callsHelper := false
	var directAssigns []string

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			if id, ok := node.Fun.(*ast.Ident); ok && id.Name == helper {
				callsHelper = true
			}
		case *ast.AssignStmt:
			for _, lhs := range node.Lhs {
				sel, ok := lhs.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "Peer" {
					continue
				}
				directAssigns = append(directAssigns,
					fset.Position(node.Pos()).String())
			}
		}
		return true
	})

	if !callsHelper {
		t.Errorf("%s no longer calls %s. The peer fan-out response carries policy names the "+
			"PEER resolved with its own binary; an older peer renders reserved id 0 as its "+
			"first configured policy, and attaching that unchanged republishes the "+
			"misattribution on every local surface — gRPC, the REST `peer` block, and the "+
			"CLI (#6851/#4626)", target, helper)
	}
	if len(directAssigns) > 0 {
		t.Errorf("%s assigns resp.Peer directly at %s. The attach must go through %s, which "+
			"sanitizes the reserved ids first — assigning around it is exactly the bypass "+
			"that function's doc names as uncovered (#6851)",
			target, strings.Join(directAssigns, ", "), helper)
	}
}
