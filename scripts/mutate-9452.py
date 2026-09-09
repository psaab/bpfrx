#!/usr/bin/env python3
"""#9452 mutation matrix. Bounded, occurrence-counted, JSON-scored.

Rules this obeys (each burned a lane in this campaign):
  a) a mutant that does not BUILD is VOID, not survived.
  b) APPLIED is confirmed by occurrence count; a REMOVAL asserts 1 -> 0.
  c) every run is bounded, so a hang scores VOID.
  d) scoring reads `go test -json` Action=="fail" and compares the NAME.
  e) a run that collected nothing is VOID: >= MIN_TESTS must have run.
  f) a log containing "no space left on device" is VOID.
"""
import json, os, shutil, subprocess, sys, tempfile

REPO = "/var/tmp/wt-9452"
PKG = "./pkg/cluster/"
MIN_TESTS = 50
TIMEOUT = 300
ELECTION = os.path.join(REPO, "pkg/cluster/election.go")

CALL_SITE_ORIG = '''			} else if yieldReason, unowned := peerYieldedOwnership(peerGroup); unowned {'''

MUTANTS = [
    # name, [(file, find, replace, expect_before, expect_after)], expected killers
    ("M1 call site severed: readiness gate reverts to the bare continue", [
        (ELECTION,
         '''			} else if yieldReason, unowned := peerYieldedOwnership(peerGroup); unowned {
				// #9452: the peer is ALIVE and reports it is NOT the owner, so
				// holding this RG secondary leaves it owned by NEITHER node.
				// Promote DEGRADED and say so loudly — see
				// peerYieldedOwnership for why this is not the cold-boot case
				// the gate exists for.
				degradedReason = fmt.Sprintf(
					"Promoted DEGRADED: %s while this node is not ready (%s); "+
						"holding secondary would leave redundancy group %d owned by neither node",
					yieldReason, readinessReasonText(rg), rg.GroupID)
			} else {''',
         '''			} else {
				_ = peerYieldedOwnership''', 1, 0),
    ]),
    ("M2 transfer-out arm removed from the predicate", [
        (ELECTION,
         '''	if peerGroup.State == StateSecondaryHold {
		return "peer transferred out (secondary-hold)", true
	}
''', '', 1, 0),
    ]),
    ("M3 weight-0 resignation arm removed from the predicate", [
        (ELECTION,
         '''	if peerGroup.Weight <= 0 {
		return "peer resigned (weight 0)", true
	}
''', '', 1, 0),
    ]),
    ("M4 predicate always true: gate never holds", [
        (ELECTION,
         '''func peerYieldedOwnership(peerGroup *PeerGroupState) (string, bool) {''',
         '''func peerYieldedOwnership(peerGroup *PeerGroupState) (string, bool) {
	return "MUTANT: always yielded", true''', 1, 1),
    ]),
    ("M5 over-correction: a healthy live secondary counts as yielded", [
        (ELECTION,
         '''	if peerGroup.State == StateSecondaryHold {
		return "peer transferred out (secondary-hold)", true
	}''',
         '''	if peerGroup.State == StateSecondaryHold || peerGroup.State == StateSecondary {
		return "peer transferred out (secondary-hold)", true
	}''', 1, 0),
    ]),
    ("M6 degraded reason dropped: promotion happens but is unmarked", [
        (ELECTION,
         '''				degradedReason = fmt.Sprintf(
					"Promoted DEGRADED: %s while this node is not ready (%s); "+
						"holding secondary would leave redundancy group %d owned by neither node",
					yieldReason, readinessReasonText(rg), rg.GroupID)''',
         '''				_, _ = yieldReason, readinessReasonText(rg)''', 1, 0),
    ]),
]


def run_tests():
    # NO TMPDIR/GOTMPDIR override: a long temp prefix overflows sun_path (108 B)
    # in socket-path tests elsewhere in the tree. Default /tmp only.
    env = dict(os.environ)
    env.pop("TMPDIR", None)
    env.pop("GOTMPDIR", None)
    p = subprocess.run(
        ["go", "test", "-json", "-count=1", f"-timeout={TIMEOUT-30}s", PKG],
        cwd=REPO, capture_output=True, text=True, timeout=TIMEOUT, env=env)
    if "no space left on device" in p.stdout + p.stderr:
        return None, None, "DISK-FULL"
    failed, ran = set(), set()
    build_fail = "build failed" in p.stdout + p.stderr or "[build failed]" in p.stdout
    for line in p.stdout.splitlines():
        try:
            ev = json.loads(line)
        except Exception:
            continue
        if ev.get("Test"):
            if ev.get("Action") == "run":
                ran.add(ev["Test"])
            if ev.get("Action") == "fail":
                failed.add(ev["Test"])
        if ev.get("Action") == "output" and "build failed" in (ev.get("Output") or ""):
            build_fail = True
    if build_fail:
        return None, None, "BUILD-FAILED"
    return failed, ran, None


def main():
    backup = {}
    for _, edits in MUTANTS:
        for f, *_ in edits:
            if f not in backup:
                backup[f] = subprocess.run(["git", "-C", REPO, "show", f"HEAD:{os.path.relpath(f, REPO)}"],
                                           capture_output=True, text=True).stdout or open(f).read()
    # back up the WORKING tree (HEAD does not have the fix yet)
    for f in backup:
        backup[f] = open(f).read()

    print("=== BASELINE ===")
    failed, ran, void = run_tests()
    if void:
        print(f"BASELINE VOID: {void}")
        return 2
    print(f"baseline: {len(ran)} tests ran, {len(failed)} failed: {sorted(failed)}")
    if len(ran) < MIN_TESTS:
        print(f"BASELINE VOID: only {len(ran)} tests ran (< {MIN_TESTS})")
        return 2
    if failed:
        print("BASELINE VOID: tests already failing")
        return 2

    results = []
    for name, edits in MUTANTS:
        print(f"\n=== {name} ===")
        applied_ok = True
        for f, find, repl, before, after in edits:
            s = open(f).read()
            n = s.count(find)
            if n != before:
                print(f"  APPLY FAILED: occurrence count for the target is {n}, want {before}")
                applied_ok = False
                break
            s2 = s.replace(find, repl)
            n2 = s2.count(find)
            if n2 != after:
                print(f"  APPLY FAILED: post-count {n2}, want {after}")
                applied_ok = False
                break
            # A REMOVAL reads 0 whether it was applied or never attempted, so
            # prove the replacement landed as well (0 -> >=1) whenever there is
            # one to look for.
            rn_before, rn_after = s.count(repl), s2.count(repl)
            if repl.strip() and rn_after <= rn_before:
                print(f"  APPLY FAILED: replacement count {rn_before} -> {rn_after}, expected an increase")
                applied_ok = False
                break
            open(f, "w").write(s2)
            print(f"  applied: target {n} -> {n2}, replacement {rn_before} -> {rn_after} in {os.path.basename(f)}")
        if not applied_ok:
            for f, orig in backup.items():
                open(f, "w").write(orig)
            results.append((name, "VOID-NOT-APPLIED", []))
            continue
        try:
            failed, ran, void = run_tests()
        except subprocess.TimeoutExpired:
            failed, ran, void = None, None, "HANG"
        for f, orig in backup.items():
            open(f, "w").write(orig)
        if void:
            print(f"  VOID: {void}")
            results.append((name, f"VOID-{void}", []))
            continue
        if len(ran) < MIN_TESTS:
            print(f"  VOID: only {len(ran)} tests ran (< {MIN_TESTS})")
            results.append((name, "VOID-COLLECTED-NOTHING", []))
            continue
        nine = sorted(t for t in failed if "9452" in t)
        other = sorted(t for t in failed if "9452" not in t)
        if failed:
            print(f"  KILLED by {len(failed)} failing test(s); #9452 cells: {nine}")
            if other:
                print(f"  also red (collateral): {other}")
            results.append((name, "KILLED", nine or other))
        else:
            print(f"  SURVIVED ({len(ran)} tests ran, none failed)")
            results.append((name, "SURVIVED", []))

    print("\n=== MATRIX ===")
    for name, verdict, killers in results:
        print(f"{verdict:24s} {name}")
        for k in killers:
            print(f"{'':24s}   killed by {k}")
    return 0


sys.exit(main())
