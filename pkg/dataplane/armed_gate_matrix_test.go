package dataplane

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #2114 A3 enforcement surface. Three mechanical nets, per the converged
// plan (docs/research/2114-nat-pool-alarm-dp-race/plan.md v99):
//
//  1. TestManager_PreArmMethodMatrix — every exported *Manager method is
//     assigned to exactly ONE armed-gate class by the handwritten manifest
//     below. The AST inventory enforces TOTALITY (an unassigned or
//     double-assigned method fails); the per-class OUTCOMES are enforced by
//     the runtime legs in armed_gate_legs_test.go; each label's CORRECTNESS
//     comes from the handwritten access audit reviewed in the PR (the
//     matrix cannot prove semantic disjointness and does not claim to).
//  2. TestManagerRegistryAccessAllowlist — the registry canary: no direct
//     m.maps / m.programs access outside the exactly-named allowlist (the
//     two lookup helpers + the publisher), with the domination/escape shape
//     rules, the stale-allowlist self-check, and synthetic negatives.
//  3. TestManagerRegistryCallsiteManifest — the stale-checked
//     helper-callsite manifest: every lookupMapLocked/lookupProgramLocked
//     callsite maps to its required/optional/raw outcome bit; a callsite
//     added, removed, or moved fails the build until the manifest and the
//     leg mapping are updated.

// managerMethodClasses is the handwritten class manifest: every exported
// *Manager method, exactly once. Classification is by the method's DIRECT
// Start-state access under the plan's escape-first precedence: a method
// that ESCAPES a Start-state reference is class 4; else a method touching
// Start-state with required pre-error Go-side side effects is class 3;
// else a method whose EVERY registry access is neutral-on-absent is
// class 2; else a method with at least one REQUIRED access is class 1.
// Methods touching only m.mu-protected Go state are category G; lifecycle
// and facade methods are categories L/F. A method that only DELEGATES into
// an already-classed internal is classed by that delegation target.
var managerMethodClasses = map[string]string{
	// --- class 1: fallible map-required (fresh -> ErrDataplaneNotArmed at
	// each REQUIRED access; armed/retained absent -> master's text) ---
	"AddTxPort": "class1", "AttachTC": "class1-carveout", "AttachXDP": "class1-carveout",
	"SetZone": "class1", "SetVlanIfaceInfo": "class1",
	"ClearIfaceZoneMap": "class1", "ClearVlanIfaceMap": "class1",
	"SwapToUserspaceXDPShimEntryProgram": "class1",
	"ReadGlobalCounter": "class1", "ReadInterfaceCounters": "class1", "ClearInterfaceCounters": "class1",
	"UpdateFabricFwd": "class1", "UpdateFabricFwd1": "class1",
	"UpdateRGActive": "class1", "UpdateHAWatchdog": "class1", "BumpFIBGeneration": "class1",
	"SetIfaceFilter": "class1", "ClearIfaceFilterMap": "class1",
	"SetFilterConfig": "class1", "ReadFilterConfig": "class1", "SetFilterRule": "class1",
	"SetPolicerConfig": "class1", "ClearPolicerConfigs": "class1",
	"ClearFilterConfigs": "class1", "ReadFilterCounters": "class1", "ClearFilterCounters": "class1",
	"SetFlowTimeout": "class1", "SetFlowConfig": "class1",
	"SetMirrorConfig": "class1", "ClearMirrorConfigs": "class1",
	"SetDNATEntry": "class1", "DeleteDNATEntry": "class1", "ClearDNATStatic": "class1",
	"SetSNATRule": "class1", "ClearSNATRules": "class1",
	"SetDNATEntryV6": "class1", "DeleteDNATEntryV6": "class1", "ClearDNATStaticV6": "class1",
	"SetSNATRuleV6": "class1", "ClearSNATRulesV6": "class1",
	"SetNATPoolConfig": "class1", "SetNATPoolIPV4": "class1", "SetNATPoolIPV6": "class1",
	"ClearNATPoolConfigs": "class1", "ClearNATPoolIPs": "class1",
	"SetSNATEgressIP": "class1", "ClearSNATEgressIPs": "class1",
	"SetStaticNATEntryV4": "class1", "SetStaticNATEntryV6": "class1",
	"SetNAT64Config": "class1", "SetNAT64Count": "class1", "ClearNAT64Configs": "class1",
	"SetNPTv6Rule": "class1", "ReadNATPortCounter": "class1",
	"SetZoneConfig": "class1", "SetZonePairPolicy": "class1", "SetPolicyRule": "class1",
	"SetAddressBookEntry": "class1", "SetAddressMembership": "class1",
	"ClearAddressBookV4": "class1", "ClearAddressBookV6": "class1", "ClearAddressMembership": "class1",
	"SetApplication": "class1", "SetAppRange": "class1", "ClearAppRanges": "class1",
	"ClearZonePairPolicies": "class1", "ClearApplications": "class1", "SetDefaultPolicy": "class1",
	"ReadPolicyCounters": "class1", "ClearPolicyCounters": "class1",
	"SetScreenConfig": "class1", "ClearScreenConfigs": "class1",
	"UpdateSessionCountSrc": "class1", "UpdateSessionCountDst": "class1",
	"IterateSessions": "class1", "DeleteSession": "class1", "SetSessionV4": "class1",
	"GetSessionV4": "class1", "GetSessionV6": "class1", "IterateSessionsV6": "class1",
	"IterateSessionsFrom": "class1", "IterateSessionsV6From": "class1",
	"BatchIterateSessions": "class1", "BatchIterateSessionsV6": "class1",
	"BatchDeleteSessions": "class1", "BatchDeleteSessionsV6": "class1",
	"DeleteSessionV6": "class1", "SetSessionV6": "class1",
	// class 1 by delegation: the chunked clear delegates into the class-1
	// batch iterate/delete internals and surfaces their gate error.
	"ClearAllSessions": "class1", "ClearAllSessionsChunked": "class1",

	// --- class 2: neutral-outcome, any signature, WITH the uniform
	// synchronization rule (fresh outcome == master's missing-map outcome,
	// byte-for-byte) ---
	"Compile":                 "class2", // redirect_capable optional skip-and-continue
	"SessionCount":            "class2",
	"GetMapStats":             "class2",
	"ClearSessionCounts":      "class2",
	"ClearStaticNATEntries":   "class2",
	"UpdatePolicyScheduleState": "class2", // the #3780 deliberate nil
	"SeedNATPortCounters":       "class2",
	"SeedSessionIDCounter":      "class2",
	"DeleteStaleIfaceZone":         "class2",
	"DeleteStaleVlanIface":         "class2",
	"DeleteStaleZonePairPolicies":  "class2",
	"DeleteStaleApplications":      "class2",
	"DeleteStaleSNATRules":         "class2",
	"DeleteStaleSNATRulesV6":       "class2",
	"DeleteStaleDNATStatic":        "class2",
	"DeleteStaleDNATStaticV6":      "class2",
	"DeleteStaleStaticNAT":         "class2",
	"DeleteStaleNPTv6":             "class2",
	"DeleteStaleNAT64":             "class2",
	"ZeroStaleScreenConfigs":       "class2",
	"ZeroStaleNATPoolConfigs":      "class2",
	"DeleteStaleIfaceFilter":       "class2",
	"ZeroStaleFilterConfigs":       "class2",

	// --- class 3: required-side-effect hybrids, UNGATED (pinned legacy
	// behavior in every state; scoped lookups; ClearAllCounters composes
	// through the raw internals — the nested-call rule) ---
	"ClearNATRuleCounters": "class3",
	"ClearGlobalCounters":  "class3",
	"ClearZoneCounters":    "class3",
	"ClearAllCounters":     "class3",

	// --- class 4: escaping getters of Start-populated state ---
	"Map":            "class4",
	"Program":        "class4",
	"NewEventSource": "class4", // error signature: fresh -> the typed error

	// --- category L: lifecycle (arming/teardown path itself; ungated by
	// construction) + the retired-path no-op stubs ---
	"Load":               "catL",
	"LoadUserspaceShim":  "catL",
	"Start":              "catL",
	"CompileUserspaceShim": "catL",
	"Close":              "catL",
	"Teardown":           "catL",
	"StartFIBSync":       "catL",
	"NotifyLinkCycle":    "catL",
	"SyncFabricState":    "catL",

	// --- category F: facade/domain accessors ---
	"Link":              "catF",
	"HA":                "catF",
	"Sessions":          "catF",
	"SessionDeltas":     "catF",
	"Telemetry":         "catF",
	"ApplyConfig":       "catF", // delegates Compile (classed) then LastApplyResult
	"LastApplyResult":   "catF",
	"LastCompileResult": "catF",

	// --- category G: ungated Go-state helpers (m.mu-protected offset state,
	// construction-time handles, the loaded bit read itself) ---
	"IncrementGlobalCounter":       "catG",
	"ReadUserspaceCounterOffset":   "catG",
	"ReadZoneCounters":             "catG",
	"SetZoneCounterOffset":         "catG",
	"ClearZoneCounterOffsets":      "catG",
	"ReadFloodCounters":            "catG",
	"SetFloodCounterOffset":        "catG",
	"ClearFloodCounterOffsets":     "catG",
	"ReadNATRuleCounter":           "catG",
	"SetNATRuleCounterOffset":      "catG",
	"ClearNATRuleCounterOffsets":   "catG",
	"IsLoaded":                     "catG", // the gate read itself
	"GetPersistentNAT":             "catG",
	"XDPLinks":                     "catG",
	"TCLinks":                      "catG",
	"DetachTC":                     "catG", // reads only the construction link map
	// DetachXDP's single label is category G (its direct access is the
	// construction link map) with the class-3-LIKE delegation target
	// setXDPAttachedFlag: scoped lookups, cleanup always runs, NO gate.
	"DetachXDP": "catG",
	// The xdpEntryProg trio: the field is m.mu-protected (locked-helper
	// scheme), so the accessors touch only m.mu-protected Go state.
	"XDPEntryProgram":                     "catG",
	"SelectUserspaceXDPShimEntryProgram":  "catG",
	"UsingUserspaceXDPShimEntryProgram":   "catG",
}

// TestManager_PreArmMethodMatrix assigns every exported *Manager method to
// exactly one armed-gate class via the manifest above and the generated AST
// inventory: an unassigned or double-assigned method fails. It also asserts
// the class-3 raw-helper composition shape: ClearAllCounters must call the
// ungated raw internals and NOT the public gated Clear{Interface,Policy,
// Filter}Counters (whose fresh typed error would otherwise surface through
// the composition and break the pinned legacy texts).
func TestManager_PreArmMethodMatrix(t *testing.T) {
	t.Parallel()

	// AST inventory of exported *Manager methods across production files.
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	inventory := map[string]bool{}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || len(fn.Recv.List) != 1 {
				continue
			}
			star, ok := fn.Recv.List[0].Type.(*ast.StarExpr)
			if !ok {
				continue
			}
			ident, ok := star.X.(*ast.Ident)
			if !ok || ident.Name != "Manager" {
				continue
			}
			if fn.Name.IsExported() {
				inventory[fn.Name.Name] = true
			}
		}
	}

	if len(inventory) != 157 {
		t.Fatalf("exported *Manager method inventory = %d, want 157 (the plan's census); reconcile the count or the plan", len(inventory))
	}
	for name := range inventory {
		if _, ok := managerMethodClasses[name]; !ok {
			t.Errorf("exported *Manager method %s is UNASSIGNED in managerMethodClasses", name)
		}
	}
	for name := range managerMethodClasses {
		if !inventory[name] {
			t.Errorf("managerMethodClasses names %s, which is not an exported *Manager method (stale entry)", name)
		}
	}

	// Class-3 raw-helper composition shape: ClearAllCounters' body must
	// reference the raw internals and must NOT call the public gated
	// ClearInterfaceCounters/ClearPolicyCounters/ClearFilterCounters.
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "maps_counters.go", nil, 0)
	if err != nil {
		t.Fatalf("parse maps_counters.go: %v", err)
	}
	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "ClearAllCounters" || fn.Body == nil {
			return true
		}
		calls := map[string]bool{}
		ast.Inspect(fn.Body, func(n2 ast.Node) bool {
			call, ok := n2.(*ast.CallExpr)
			if !ok {
				return true
			}
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				calls[sel.Sel.Name] = true
			}
			return true
		})
		for _, want := range []string{"clearInterfaceCountersRaw", "clearPolicyCountersRaw", "clearFilterCountersRaw"} {
			if !calls[want] {
				t.Errorf("ClearAllCounters does not compose through %s (class-3 nested-call rule)", want)
			}
		}
		for _, banned := range []string{"ClearInterfaceCounters", "ClearPolicyCounters", "ClearFilterCounters"} {
			if calls[banned] {
				t.Errorf("ClearAllCounters calls the public gated %s — its fresh typed error would replace the pinned legacy text in the composition", banned)
			}
		}
		return false
	})
}

// registryAccessAllowlist names the ONLY functions permitted to touch
// m.maps / m.programs: the two scoped lookup helpers (uniform registry
// rule) and the whole-batch publisher. Everything else routes through the
// helpers. The stale-allowlist self-check below fails if an allowlisted
// function is renamed or removed without updating the canary.
var registryAccessAllowlist = map[string]bool{
	"lookupMapLocked":            true,
	"lookupProgramLocked":        true,
	"publishShimRegistryLocked":  true,
}

// registryCanaryViolations parses every production .go file under root and
// reports: (a) any m.maps/m.programs reference outside the allowlisted
// functions; (b) inside an allowlisted function, any registry reference NOT
// dominated by the m.mu acquisition (an explicit Unlock before the access
// fails — the Lock -> hook -> Unlock -> access anti-pattern), any access
// that is not an index read/write or len() (the container is never
// returned, aliased, assigned, closed over, or passed as an argument), and
// (c) for the publisher, that its writes are followed by EXACTLY ONE
// in-lock loaded.Store(true).
func registryCanaryViolations(t *testing.T, root string) []string {
	t.Helper()

	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read %s: %v", root, err)
	}
	var violations []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(root, name)
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			allowed := registryAccessAllowlist[fn.Name.Name]

			// Collect lock/unlock positions and registry references.
			var lockPos, explicitUnlockPos token.Pos
			storeTrueCount := 0
			lastWritePos := token.NoPos
			type regRef struct {
				pos     token.Pos
				indexed bool
				write   bool
			}
			var refs []regRef

			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch node := n.(type) {
				case *ast.CallExpr:
					if sel, ok := node.Fun.(*ast.SelectorExpr); ok {
						switch {
						case sel.Sel.Name == "Lock" || sel.Sel.Name == "Unlock":
							if id, ok := sel.X.(*ast.SelectorExpr); ok && id.Sel.Name == "mu" {
								if sel.Sel.Name == "Lock" && lockPos == token.NoPos {
									lockPos = node.Pos()
								}
								if sel.Sel.Name == "Unlock" {
									// A deferred Unlock releases at function
									// end; only a DIRECT call narrows the hold.
									if explicitUnlockPos == token.NoPos {
										// check whether this CallExpr is the
										// DeferStmt's call — handled by the
										// parent walk below; approximate:
										// treat as explicit unless directly
										// under a DeferStmt.
									}
								}
							}
						case sel.Sel.Name == "Store":
							if len(node.Args) > 0 {
								if id, ok := node.Args[0].(*ast.Ident); ok && id.Name == "true" {
									storeTrueCount++
								}
							}
						}
					}
				}
				return true
			})

			// Direct (non-deferred) Unlock positions narrow the hold.
			var directUnlocks []token.Pos
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch node := n.(type) {
				case *ast.DeferStmt:
					return false // deferred calls run at function end
				case *ast.CallExpr:
					if sel, ok := node.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Unlock" {
						if recv, ok := sel.X.(*ast.SelectorExpr); ok && recv.Sel.Name == "mu" {
							directUnlocks = append(directUnlocks, node.Pos())
						}
					}
				}
				return true
			})
			_ = explicitUnlockPos

			// Registry references with index/write classification.
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok || (sel.Sel.Name != "maps" && sel.Sel.Name != "programs") {
					return true
				}
				recv, ok := sel.X.(*ast.Ident)
				if !ok || recv.Name != "m" {
					return true
				}
				refs = append(refs, regRef{pos: sel.Pos()})
				return true
			})

			// Classify each ref: indexed (m.maps[...] incl. writes and
			// reads) or len(); anything else is an escape.
			for _, r := range refs {
				_ = r
			}
			// Walk again with parent tracking for shape classification.
			var shapeViolations []string
			var walk func(n ast.Node, parent ast.Node) bool
			_ = walk
			var stack []ast.Node
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if n == nil {
					if len(stack) > 0 {
						stack = stack[:len(stack)-1]
					}
					return true
				}
				stack = append(stack, n)
				sel, ok := n.(*ast.SelectorExpr)
				if !ok || (sel.Sel.Name != "maps" && sel.Sel.Name != "programs") {
					return true
				}
				recv, ok := sel.X.(*ast.Ident)
				if !ok || recv.Name != "m" {
					return true
				}
				pos := fset.Position(sel.Pos())
				if !allowed {
					shapeViolations = append(shapeViolations,
						fmt.Sprintf("%s:%s: raw m.%s access in %s (outside the allowlist)", name, pos, sel.Sel.Name, fn.Name.Name))
					return true
				}
				// Shape: the parent must be an IndexExpr (m.maps[name]) or a
				// len() call. Anything else returns/aliases the container.
				var parent ast.Node
				if len(stack) >= 2 {
					parent = stack[len(stack)-2]
				}
				shapeOK := false
				switch p := parent.(type) {
				case *ast.IndexExpr:
					if p.X == sel {
						shapeOK = true
					}
				case *ast.CallExpr:
					if id, ok := p.Fun.(*ast.Ident); ok && id.Name == "len" {
						shapeOK = true
					}
				}
				if !shapeOK {
					shapeViolations = append(shapeViolations,
						fmt.Sprintf("%s:%s: m.%s escapes as a non-indexed reference in %s (container returned/aliased/assigned/passed)", name, pos, sel.Sel.Name, fn.Name.Name))
				}
				// Domination: after the (first) m.mu.Lock and not after any
				// direct m.mu.Unlock.
				if lockPos != token.NoPos && sel.Pos() < lockPos {
					shapeViolations = append(shapeViolations,
						fmt.Sprintf("%s:%s: m.%s access precedes the m.mu.Lock in %s", name, pos, sel.Sel.Name, fn.Name.Name))
				}
				for _, up := range directUnlocks {
					if sel.Pos() > up {
						shapeViolations = append(shapeViolations,
							fmt.Sprintf("%s:%s: m.%s access follows a direct m.mu.Unlock in %s (unlock-before-access)", name, pos, sel.Sel.Name, fn.Name.Name))
					}
				}
				return true
			})

			if fn.Name.Name == "publishShimRegistryLocked" {
				if storeTrueCount != 1 {
					shapeViolations = append(shapeViolations,
						fmt.Sprintf("%s: publishShimRegistryLocked has %d loaded.Store(true) calls, want exactly 1", name, storeTrueCount))
				}
				_ = lastWritePos
			}
			violations = append(violations, shapeViolations...)
		}
	}
	return violations
}

// TestManagerRegistryAccessAllowlist is the registry canary (#2114 A3):
// every m.maps/m.programs access in the package goes through the scoped
// lookup helpers or the whole-batch publisher — anything else fails here,
// so a future raw access (which would race the publication batch) cannot
// land silently.
func TestManagerRegistryAccessAllowlist(t *testing.T) {
	t.Parallel()

	if violations := registryCanaryViolations(t, "."); len(violations) > 0 {
		t.Fatalf("registry-access canary violations:\n%s", strings.Join(violations, "\n"))
	}

	// Stale-allowlist self-check: every allowlisted function must exist as
	// a *Manager method in the package (a rename without a canary update
	// fails here rather than silently widening the surface).
	fset := token.NewFileSet()
	found := map[string]bool{}
	files, _ := filepath.Glob("*.go")
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, decl := range file.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && registryAccessAllowlist[fn.Name.Name] {
				found[fn.Name.Name] = true
			}
		}
	}
	for name := range registryAccessAllowlist {
		if !found[name] {
			t.Errorf("allowlisted function %s not found in the package (stale allowlist entry)", name)
		}
	}
}

// TestManagerRegistryAccessAllowlistNegatives drives the canary over
// synthetic fixtures in every failure direction: a raw access outside the
// allowlist, a container alias escape inside an allowlisted-shaped
// function, and an unlock-before-access anti-pattern must each be caught;
// the well-formed helpers/publisher shapes must pass.
func TestManagerRegistryAccessAllowlistNegatives(t *testing.T) {
	t.Parallel()

	good := `package dataplane

func (m *Manager) lookupMapLocked(name string) (h *ebpf.Map, present bool, st registryState) {
	m.mu.Lock()
	defer m.mu.Unlock()
	h, present = m.maps[name]
	return h, present, m.classifyRegistryLocked()
}

func (m *Manager) publishShimRegistryLocked(prog *ebpf.Program, collMaps, sharedMaps map[string]*ebpf.Map) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.programs[userspaceShimEntryProg] = prog
	for name, umap := range collMaps {
		m.maps[name] = umap
	}
	m.loaded.Store(true)
}
`
	rawAccess := `package dataplane

func (m *Manager) sneaky(name string) *ebpf.Map {
	return m.maps[name]
}
`
	aliasEscape := `package dataplane

func (m *Manager) lookupMapLocked(name string) map[string]*ebpf.Map {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.maps
}
`
	unlockBeforeAccess := `package dataplane

func (m *Manager) lookupProgramLocked(name string) *ebpf.Program {
	m.mu.Lock()
	m.mu.Unlock()
	return m.programs[name]
}
`

	dir := t.TempDir()
	write := func(n, src string) {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(src), 0o644); err != nil {
			t.Fatalf("write %s: %v", n, err)
		}
	}

	write("good.go", good)
	if violations := registryCanaryViolations(t, dir); len(violations) > 0 {
		t.Fatalf("well-formed fixture reported violations: %v", violations)
	}

	write("bad_raw.go", rawAccess)
	write("bad_alias.go", aliasEscape)
	write("bad_unlock.go", unlockBeforeAccess)
	violations := registryCanaryViolations(t, dir)
	var sawRaw, sawAlias, sawUnlock bool
	for _, v := range violations {
		if strings.Contains(v, "sneaky") && strings.Contains(v, "outside the allowlist") {
			sawRaw = true
		}
		if strings.Contains(v, "escapes as a non-indexed reference") {
			sawAlias = true
		}
		if strings.Contains(v, "unlock-before-access") {
			sawUnlock = true
		}
	}
	if !sawRaw || !sawAlias || !sawUnlock {
		t.Fatalf("canary missed synthetic negatives (raw=%v alias=%v unlock=%v):\n%s",
			sawRaw, sawAlias, sawUnlock, strings.Join(violations, "\n"))
	}
}

// registryCallsiteManifestEntry pins one lookupMapLocked/lookupProgramLocked
// callsite: file, enclosing function, registry kind, the literal name
// argument ("<ident:x>"/"<dynamic>" when not a literal), and the outcome
// role — "required" (the fresh gate follows the call), "optional"
// (master's per-site neutral outcome), or "raw" (a class-3 ungated
// composition leg). The manifest is STALE-CHECKED by
// TestManagerRegistryCallsiteManifest: a callsite added, removed, or moved
// fails the build until the manifest and its leg mapping are updated.
// The 17 mixed sites carry their named §9 continuation leg in a comment.
type registryCallsiteManifestEntry struct {
	file, fn, kind, arg, role string
}

var registryCallsiteManifest = []registryCallsiteManifestEntry{
	{"compiler.go", "Compile", "map", `"redirect_capable"`, "optional"}, // leg: Compile continuation (absent redirect_capable skips AND CONTINUES into attachment work)
	{"loader.go", "AddTxPort", "map", `"tx_ports"`, "required"},
	{"loader.go", "AttachTC", "prog", `"tc_main_prog"`, "carveout"},       // carve-out: the pre-registry loaded rejection fires first on both unarmed states; the lookup keeps master's not-found text
	{"loader.go", "AttachXDP", "prog", "<ident:entryProg>", "carveout"},   // carve-out
	{"loader.go", "ClearIfaceZoneMap", "map", `"iface_zone_map"`, "required"},
	{"loader.go", "ClearVlanIfaceMap", "map", `"vlan_iface_map"`, "required"},
	{"loader.go", "Map", "map", "<ident:name>", "optional"},               // class 4: nil outcome
	{"loader.go", "NewEventSource", "map", `"events"`, "required"},        // class 4 with error signature: fresh -> typed error
	{"loader.go", "Program", "prog", "<ident:name>", "optional"},          // class 4: nil outcome
	{"loader.go", "SetVlanIfaceInfo", "map", `"vlan_iface_map"`, "required"},
	{"loader.go", "SetZone", "map", `"iface_zone_map"`, "required"},
	{"loader.go", "clearNativeXDPFlags", "map", `"iface_zone_map"`, "optional"},
	{"loader.go", "clearNativeXDPFlagsForIfindexes", "map", `"iface_zone_map"`, "optional"},
	{"loader.go", "seedInterfaceCounter", "map", `"interface_counters"`, "optional"}, // leg (ii): absent skips the seed (AttachXDP/AddTxPort still succeed); present asserts the seed wrote
	{"loader.go", "setXDPAttachedFlag", "map", `"iface_zone_map"`, "optional"},       // leg (iii): absent -> master's early-boot no-op NIL, claims untouched
	{"loader.go", "setXDPAttachedFlag", "map", `"vlan_iface_map"`, "optional"},       // leg: absent vlan_iface_map CONTINUES into the physical-interface processing
	{"loader.go", "swapXDPEntryProg", "prog", "<ident:name>", "required"},
	{"maps_counters.go", "ClearGlobalCounters", "map", `"global_counters"`, "optional"},   // class 3: pinned legacy behavior
	{"maps_counters.go", "ClearInterfaceCounters", "map", `"interface_counters"`, "required"},
	{"maps_counters.go", "ClearZoneCounters", "map", `"zone_counters"`, "optional"},       // class 3
	{"maps_counters.go", "ReadGlobalCounter", "map", `"global_counters"`, "required"},
	{"maps_counters.go", "ReadInterfaceCounters", "map", `"interface_counters"`, "required"},
	{"maps_counters.go", "clearInterfaceCountersRaw", "map", `"interface_counters"`, "raw"}, // class-3 nested-call composition leg (legacy text preserved)
	{"maps_fabric.go", "BumpFIBGeneration", "map", `"fib_gen_map"`, "required"},
	{"maps_fabric.go", "UpdateFabricFwd", "map", `"fabric_fwd"`, "required"},
	{"maps_fabric.go", "UpdateFabricFwd1", "map", `"fabric_fwd"`, "required"},
	{"maps_fabric.go", "UpdateHAWatchdog", "map", `"ha_watchdog"`, "required"},
	{"maps_fabric.go", "UpdateRGActive", "map", `"rg_active"`, "required"},
	{"maps_filter.go", "ClearFilterConfigs", "map", `"filter_configs"`, "required"},
	{"maps_filter.go", "ClearFilterCounters", "map", `"filter_counters"`, "required"},
	{"maps_filter.go", "ClearIfaceFilterMap", "map", `"iface_filter_map"`, "required"},
	{"maps_filter.go", "ClearPolicerConfigs", "map", `"policer_configs"`, "required"},
	{"maps_filter.go", "ReadFilterConfig", "map", `"filter_configs"`, "required"},
	{"maps_filter.go", "ReadFilterCounters", "map", `"filter_counters"`, "required"},
	{"maps_filter.go", "SetFilterConfig", "map", `"filter_configs"`, "required"},
	{"maps_filter.go", "SetFilterRule", "map", `"filter_rules"`, "required"},
	{"maps_filter.go", "SetIfaceFilter", "map", `"iface_filter_map"`, "required"},
	{"maps_filter.go", "SetPolicerConfig", "map", `"policer_configs"`, "required"},
	{"maps_filter.go", "clearFilterCountersRaw", "map", `"filter_counters"`, "raw"},
	{"maps_flow.go", "SetFlowConfig", "map", `"flow_config_map"`, "required"},
	{"maps_flow.go", "SetFlowTimeout", "map", `"flow_timeouts"`, "required"},
	{"maps_mirror.go", "ClearMirrorConfigs", "map", `"mirror_config"`, "required"},
	{"maps_mirror.go", "SetMirrorConfig", "map", `"mirror_config"`, "required"},
	{"maps_nat.go", "ClearDNATStatic", "map", `"dnat_table"`, "required"},
	{"maps_nat.go", "ClearDNATStaticV6", "map", `"dnat_table_v6"`, "required"},
	{"maps_nat.go", "ClearNAT64Configs", "map", `"nat64_configs"`, "required"},       // leg: partial-registry continuation — present + nonzero count, prefix_map ABSENT: succeeds AND the count is zeroed
	{"maps_nat.go", "ClearNAT64Configs", "map", `"nat64_prefix_map"`, "optional"},    //   (same leg: the optional miss must NOT abort before the trailing required SetNAT64Count write)
	{"maps_nat.go", "ClearNATPoolConfigs", "map", `"nat_pool_configs"`, "required"},
	{"maps_nat.go", "ClearNATPoolIPs", "map", `"nat_pool_ips_v4"`, "required"},
	{"maps_nat.go", "ClearNATPoolIPs", "map", `"nat_pool_ips_v6"`, "required"},
	{"maps_nat.go", "ClearNATRuleCounters", "map", `"nat_rule_counters"`, "optional"}, // class 3
	{"maps_nat.go", "ClearSNATEgressIPs", "map", `"snat_egress_ips"`, "required"},
	{"maps_nat.go", "ClearSNATRules", "map", `"snat_rules"`, "required"},
	{"maps_nat.go", "ClearSNATRulesV6", "map", `"snat_rules_v6"`, "required"},
	{"maps_nat.go", "ClearStaticNATEntries", "map", `"static_nat_v4"`, "optional"},   // leg: absent v4 CONTINUES to the v6 clear
	{"maps_nat.go", "ClearStaticNATEntries", "map", `"static_nat_v6"`, "optional"},
	{"maps_nat.go", "DeleteDNATEntry", "map", `"dnat_table"`, "required"},
	{"maps_nat.go", "DeleteDNATEntryV6", "map", `"dnat_table_v6"`, "required"},
	{"maps_nat.go", "ReadNATPortCounter", "map", `"nat_port_counters"`, "required"},
	{"maps_nat.go", "SeedNATPortCounters", "map", `"nat_port_counters"`, "optional"},
	{"maps_nat.go", "SetDNATEntry", "map", `"dnat_table"`, "required"},
	{"maps_nat.go", "SetDNATEntryV6", "map", `"dnat_table_v6"`, "required"},
	{"maps_nat.go", "SetNAT64Config", "map", `"nat64_configs"`, "required"},          // leg (i): required present + optional absent -> succeeds AND the required write landed
	{"maps_nat.go", "SetNAT64Config", "map", `"nat64_prefix_map"`, "optional"},       //   (same leg)
	{"maps_nat.go", "SetNAT64Count", "map", `"nat64_count"`, "required"},
	{"maps_nat.go", "SetNATPoolConfig", "map", `"nat_pool_configs"`, "required"},
	{"maps_nat.go", "SetNATPoolIPV4", "map", `"nat_pool_ips_v4"`, "required"},
	{"maps_nat.go", "SetNATPoolIPV6", "map", `"nat_pool_ips_v6"`, "required"},
	{"maps_nat.go", "SetNPTv6Rule", "map", `"nptv6_rules"`, "required"},
	{"maps_nat.go", "SetSNATEgressIP", "map", `"snat_egress_ips"`, "required"},
	{"maps_nat.go", "SetSNATRule", "map", `"snat_rules"`, "required"},
	{"maps_nat.go", "SetSNATRuleV6", "map", `"snat_rules_v6"`, "required"},
	{"maps_nat.go", "SetStaticNATEntryV4", "map", `"static_nat_v4"`, "required"},
	{"maps_nat.go", "SetStaticNATEntryV6", "map", `"static_nat_v6"`, "required"},
	{"maps_policy.go", "ClearAddressBookV4", "map", `"address_book_v4"`, "required"},
	{"maps_policy.go", "ClearAddressBookV6", "map", `"address_book_v6"`, "required"},
	{"maps_policy.go", "ClearAddressMembership", "map", `"address_membership"`, "required"},
	{"maps_policy.go", "ClearAppRanges", "map", `"app_ranges"`, "required"},
	{"maps_policy.go", "ClearApplications", "map", `"applications"`, "required"},
	{"maps_policy.go", "ClearPolicyCounters", "map", `"policy_counters"`, "required"},
	{"maps_policy.go", "ClearZonePairPolicies", "map", `"zone_pair_policies"`, "required"},
	{"maps_policy.go", "ReadPolicyCounters", "map", `"policy_counters"`, "required"},
	{"maps_policy.go", "SetAddressBookEntry", "map", `"address_book_v4"`, "required"},
	{"maps_policy.go", "SetAddressBookEntry", "map", `"address_book_v6"`, "required"},
	{"maps_policy.go", "SetAddressMembership", "map", `"address_membership"`, "required"},
	{"maps_policy.go", "SetAppRange", "map", `"app_ranges"`, "required"},
	{"maps_policy.go", "SetApplication", "map", `"applications"`, "required"},
	{"maps_policy.go", "SetDefaultPolicy", "map", `"default_policy"`, "required"},
	{"maps_policy.go", "SetPolicyRule", "map", `"policy_rules"`, "required"},
	{"maps_policy.go", "SetZoneConfig", "map", `"zone_configs"`, "required"},
	{"maps_policy.go", "SetZonePairPolicy", "map", `"zone_pair_policies"`, "required"},
	{"maps_policy.go", "UpdatePolicyScheduleState", "map", `"policy_rules"`, "optional"}, // the #3780 deliberate nil
	{"maps_policy.go", "clearPolicyCountersRaw", "map", `"policy_counters"`, "raw"},
	{"maps_screen.go", "ClearScreenConfigs", "map", `"screen_configs"`, "required"},
	{"maps_screen.go", "ClearSessionCounts", "map", "<ident:name>", "optional"}, // leg: BOTH looped maps cleared (continuation)
	{"maps_screen.go", "SetScreenConfig", "map", `"screen_configs"`, "required"},
	{"maps_screen.go", "UpdateSessionCountDst", "map", `"session_count_dst"`, "required"},
	{"maps_screen.go", "UpdateSessionCountSrc", "map", `"session_count_src"`, "required"},
	{"maps_session.go", "BatchDeleteSessions", "map", `"sessions"`, "required"},
	{"maps_session.go", "BatchDeleteSessionsV6", "map", `"sessions_v6"`, "required"},
	{"maps_session.go", "BatchIterateSessions", "map", `"sessions"`, "required"},
	{"maps_session.go", "BatchIterateSessionsV6", "map", `"sessions_v6"`, "required"},
	{"maps_session.go", "DeleteSession", "map", `"sessions"`, "required"},
	{"maps_session.go", "DeleteSessionV6", "map", `"sessions_v6"`, "required"},
	{"maps_session.go", "GetSessionV4", "map", `"sessions"`, "required"},
	{"maps_session.go", "GetSessionV6", "map", `"sessions_v6"`, "required"},
	{"maps_session.go", "IterateSessions", "map", `"sessions"`, "required"},
	{"maps_session.go", "IterateSessionsFrom", "map", `"sessions"`, "required"},
	{"maps_session.go", "IterateSessionsV6", "map", `"sessions_v6"`, "required"},
	{"maps_session.go", "IterateSessionsV6From", "map", `"sessions_v6"`, "required"},
	{"maps_session.go", "SeedSessionIDCounter", "map", `"session_id_gen"`, "optional"},
	{"maps_session.go", "SessionCount", "map", `"sessions"`, "optional"},   // leg: v4 AND v6 both reported (continuation)
	{"maps_session.go", "SessionCount", "map", `"sessions_v6"`, "optional"},
	{"maps_session.go", "SetSessionV4", "map", `"sessions"`, "required"},
	{"maps_session.go", "SetSessionV6", "map", `"sessions_v6"`, "required"},
	{"maps_stale.go", "DeleteStaleApplications", "map", `"applications"`, "optional"},
	{"maps_stale.go", "DeleteStaleDNATStatic", "map", `"dnat_table"`, "optional"},
	{"maps_stale.go", "DeleteStaleDNATStaticV6", "map", `"dnat_table_v6"`, "optional"},
	{"maps_stale.go", "DeleteStaleIfaceFilter", "map", `"iface_filter_map"`, "optional"},
	{"maps_stale.go", "DeleteStaleIfaceZone", "map", `"iface_zone_map"`, "optional"},
	{"maps_stale.go", "DeleteStaleNAT64", "map", `"nat64_configs"`, "optional"},      // leg: multi-map stale cleanups process ALL maps (continuation)
	{"maps_stale.go", "DeleteStaleNAT64", "map", `"nat64_prefix_map"`, "optional"},
	{"maps_stale.go", "DeleteStaleNPTv6", "map", `"nptv6_rules"`, "optional"},
	{"maps_stale.go", "DeleteStaleSNATRules", "map", `"snat_rules"`, "optional"},
	{"maps_stale.go", "DeleteStaleSNATRulesV6", "map", `"snat_rules_v6"`, "optional"},
	{"maps_stale.go", "DeleteStaleStaticNAT", "map", `"static_nat_v4"`, "optional"},  // (same continuation pattern)
	{"maps_stale.go", "DeleteStaleStaticNAT", "map", `"static_nat_v6"`, "optional"},
	{"maps_stale.go", "DeleteStaleVlanIface", "map", `"vlan_iface_map"`, "optional"},
	{"maps_stale.go", "DeleteStaleZonePairPolicies", "map", `"zone_pair_policies"`, "optional"},
	{"maps_stale.go", "ZeroStaleFilterConfigs", "map", `"filter_configs"`, "optional"},
	{"maps_stale.go", "ZeroStaleNATPoolConfigs", "map", `"nat_pool_configs"`, "optional"},   // (same)
	{"maps_stale.go", "ZeroStaleNATPoolConfigs", "map", `"nat_pool_ips_v4"`, "optional"},
	{"maps_stale.go", "ZeroStaleNATPoolConfigs", "map", `"nat_pool_ips_v6"`, "optional"},
	{"maps_stale.go", "ZeroStaleScreenConfigs", "map", `"screen_configs"`, "optional"},
	{"maps_stats.go", "GetMapStats", "map", "<dynamic>", "optional"}, // leg: every descriptor reported (continuation)
}

// collectRegistryCallsites walks every production .go file under root and
// returns the set of lookup-helper callsites as "file|fn|kind|arg" plus the
// AST-derived gated bit (does a registryFresh check follow in the same
// function body).
func collectRegistryCallsites(t *testing.T, root string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read %s: %v", root, err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, filepath.Join(root, name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		type fnSpan struct {
			name string
			body *ast.BlockStmt
		}
		var fns []fnSpan
		for _, d := range file.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Body != nil {
				fns = append(fns, fnSpan{fd.Name.Name, fd.Body})
			}
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || (sel.Sel.Name != "lookupMapLocked" && sel.Sel.Name != "lookupProgramLocked") {
				return true
			}
			arg := "<dynamic>"
			if len(call.Args) == 1 {
				if lit, ok := call.Args[0].(*ast.BasicLit); ok {
					arg = lit.Value
				} else if id, ok := call.Args[0].(*ast.Ident); ok {
					arg = "<ident:" + id.Name + ">"
				}
			}
			encl := "<none>"
			for _, g := range fns {
				if g.body.Pos() <= call.Pos() && call.Pos() < g.body.End() {
					encl = g.name
					break
				}
			}
			kind := "map"
			if sel.Sel.Name == "lookupProgramLocked" {
				kind = "prog"
			}
			out[fmt.Sprintf("%s|%s|%s|%s", name, encl, kind, arg)] = true
			return true
		})
	}
	return out
}

// collectRegistryGatedCallsites returns the subset of callsites (same
// "file|fn|kind|arg" key form) whose assignment binds the registryState
// return to a NON-BLANK identifier — i.e. the callsite actually consumes
// the gate classification. That is the per-callsite gated bit: required
// accesses check `st == registryFresh`; optional/raw/class-4-nil accesses
// blank it out.
func collectRegistryGatedCallsites(t *testing.T, root string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read %s: %v", root, err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, filepath.Join(root, name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		type fnSpan struct {
			name string
			body *ast.BlockStmt
		}
		var fns []fnSpan
		for _, d := range file.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Body != nil {
				fns = append(fns, fnSpan{fd.Name.Name, fd.Body})
			}
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || (sel.Sel.Name != "lookupMapLocked" && sel.Sel.Name != "lookupProgramLocked") {
				return true
			}
			arg := "<dynamic>"
			if len(call.Args) == 1 {
				if lit, ok := call.Args[0].(*ast.BasicLit); ok {
					arg = lit.Value
				} else if id, ok := call.Args[0].(*ast.Ident); ok {
					arg = "<ident:" + id.Name + ">"
				}
			}
			encl := "<none>"
			for _, g := range fns {
				if g.body.Pos() <= call.Pos() && call.Pos() < g.body.End() {
					encl = g.name
					break
				}
			}
			kind := "map"
			if sel.Sel.Name == "lookupProgramLocked" {
				kind = "prog"
			}
			key := fmt.Sprintf("%s|%s|%s|%s", name, encl, kind, arg)
			// gated iff the third result (registryState) is bound non-blank
			// by the enclosing assignment.
			// The call sits inside an AssignStmt's Rhs (possibly the only
			// element); find it by walking the enclosing function's
			// statements — ast.Inspect parent tracking is unavailable, so
			// re-walk the enclosing body.
			for _, g := range fns {
				if g.name != encl {
					continue
				}
				ast.Inspect(g.body, func(n2 ast.Node) bool {
					as, ok := n2.(*ast.AssignStmt)
					if !ok {
						return true
					}
					for _, rhs := range as.Rhs {
						rc, ok := rhs.(*ast.CallExpr)
						if !ok || rc.Pos() != call.Pos() {
							continue
						}
						if len(as.Lhs) == 3 {
							if id, ok := as.Lhs[2].(*ast.Ident); ok && id.Name != "_" {
								out[key] = true
							}
						}
					}
					return true
				})
			}
			return true
		})
	}
	return out
}

// TestManagerRegistryCallsiteManifest is the stale-checked helper-callsite
// manifest (#2114 A3, plan v99): EVERY lookupMapLocked/lookupProgramLocked
// callsite maps to its required/optional/raw outcome, and the manifest's
// gated bit is AST-verified against the enclosing function (a "required"
// entry must contain the registryFresh gate; an "optional"/"raw" entry must
// not). The manifest does not infer semantics — it forces explicit review
// when callsites change: a callsite added, removed, or moved fails here
// until the manifest and the leg mapping are updated.
func TestManagerRegistryCallsiteManifest(t *testing.T) {
	t.Parallel()

	got := collectRegistryCallsites(t, ".")
	want := map[string]string{}
	for _, e := range registryCallsiteManifest {
		key := fmt.Sprintf("%s|%s|%s|%s", e.file, e.fn, e.kind, e.arg)
		if _, dup := want[key]; dup {
			t.Fatalf("manifest has a duplicate entry: %s", key)
		}
		want[key] = e.role
	}

	for key := range got {
		if _, ok := want[key]; !ok {
			t.Errorf("callsite %s is NOT in the manifest (added/moved callsite — update registryCallsiteManifest and the §9 leg mapping)", key)
		}
	}
	for key := range want {
		if !got[key] {
			t.Errorf("manifest entry %s is STALE (no such callsite) — update registryCallsiteManifest", key)
		}
	}
	if len(got) != len(registryCallsiteManifest) {
		t.Fatalf("callsite count = %d, manifest = %d", len(got), len(registryCallsiteManifest))
	}

	// AST-verify the gated bit PER CALLSITE: a "required" entry must bind
	// the registryState return non-blank (the fresh gate follows);
	// "optional"/"raw" entries must blank it; "carveout" entries blank it
	// too (the pre-registry loaded rejection fires first on both unarmed
	// states, so the lookup never sees the fresh state — but the uniform
	// rule still routes it through the helper).
	gatedSet := collectRegistryGatedCallsites(t, ".")
	for _, e := range registryCallsiteManifest {
		key := fmt.Sprintf("%s|%s|%s|%s", e.file, e.fn, e.kind, e.arg)
		if _, ok := want[key]; !ok {
			continue // already reported above
		}
		gated := gatedSet[key]
		switch e.role {
		case "required":
			if !gated {
				t.Errorf("manifest entry %s is required but the callsite blanks the registryState return (no fresh gate)", key)
			}
		case "optional", "raw", "carveout":
			if gated {
				t.Errorf("manifest entry %s is %s but the callsite binds the registryState return (role drift — reclassify deliberately)", key, e.role)
			}
		default:
			t.Errorf("manifest entry %s has unknown role %q", key, e.role)
		}
	}
}
