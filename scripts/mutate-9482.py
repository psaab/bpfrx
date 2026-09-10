#!/usr/bin/env python3
"""#9482 mutation matrix.

NOTE ON A COMPILE-TIME GUARD, because the standard rule needs a carve-out here.
The campaign rule is "a mutant that does not BUILD is VOID, not survived —
reshape it so it compiles". That rule assumes the guard is a TEST. One of the
defences here is a compile-time assertion
(pkg/daemon/bulk_snapshot_published_type_9482.go), and its kill signal IS a build
failure. So a build break is scored:

  KILLED(compile)  only if the compiler diagnostic names the guard's FILE and the
                   missing METHOD — i.e. the guard is what spoke.
  VOID(build)      otherwise — the mutant was malformed and measured nothing.

Everything else follows the usual discipline: occurrence-counted in both
directions, bounded runs, `go test -json` scored on Action=="fail" with the NAME
compared to the cell, >= MIN_TESTS executed, and a REAL ENOSPC check that
excludes the pkg/configstore `injected:` fixture (#9500 — a passing test emits
that string, so an unfiltered grep condemns healthy runs).
"""
import json, os, subprocess, sys

REPO = "/var/tmp/wt-9482"
PKGS = ["./pkg/daemon/", "./pkg/dataplane/userspace/"]
MIN_TESTS = 50
TIMEOUT = 900

ADAPTER = os.path.join(REPO, "pkg/dataplane/userspace/legacy_dataplane.go")
BELT = os.path.join(REPO, "pkg/daemon/bulk_snapshot_published_type_9482.go")
RESOLVER = os.path.join(REPO, "pkg/daemon/daemon_ha_userspace_export.go")

GUARD_FILE = "bulk_snapshot_published_type_9482.go"
GUARD_METHOD = "ExportOwnerRGSessionsPaged"

FWD_SIG = "func (a *LegacyDataPlaneAdapter) ExportOwnerRGSessionsPaged(rgIDs []int)"
BELT_BOTH = '''var (
	_ userspaceSessionExporter = (*dpuserspace.LegacyDataPlaneAdapter)(nil)
	_ userspaceSessionExporter = (*dpuserspace.Manager)(nil)
)'''
BELT_MGR_ONLY = '''var (
	_ userspaceSessionExporter = (*dpuserspace.Manager)(nil)
)'''

MUTANTS = [
    ("Q1 the fix reverted: adapter forwarder renamed away, compile-time belt KEPT", [
        (ADAPTER, FWD_SIG,
         "func (a *LegacyDataPlaneAdapter) ExportOwnerRGSessionsPagedGONE(rgIDs []int)", 1, 0),
    ]),
    ("Q2 the fix reverted AND the belt neutralised, so the BEHAVIOURAL cells are scoreable", [
        (ADAPTER, FWD_SIG,
         "func (a *LegacyDataPlaneAdapter) ExportOwnerRGSessionsPagedGONE(rgIDs []int)", 1, 0),
        (BELT, BELT_BOTH, BELT_MGR_ONLY, 1, 0),
    ]),
    ("Q3 wrong fix: the forwarder delegates to the UNPAGED manager method (compiles, type-asserts)", [
        (ADAPTER, "	return m.ExportOwnerRGSessionsPaged(rgIDs)\n}",
         "	return m.ExportOwnerRGSessions(rgIDs, 0)\n}", 1, 0),
    ]),
    ("Q4 the resolver's refusal branch deleted, so an INCAPABLE dataplane falls through", [
        (RESOLVER, '''	exporter, ok := d.dataplane().(userspaceSessionExporter)
	if !ok {
		return cluster.BulkSnapshot{}, errors.New("dataplane does not export owner-RG sessions")
	}''',
         '''	exporter, _ := d.dataplane().(userspaceSessionExporter)''', 1, 0),
    ]),
]


def build():
    p = subprocess.run(["go", "build", "./..."], cwd=REPO,
                       capture_output=True, text=True, timeout=TIMEOUT)
    return p.returncode, p.stdout + p.stderr


def run_tests():
    env = dict(os.environ)
    env.pop("TMPDIR", None)
    env.pop("GOTMPDIR", None)
    p = subprocess.run(["go", "test", "-json", "-count=1", f"-timeout={TIMEOUT-120}s"] + PKGS,
                       cwd=REPO, capture_output=True, text=True, timeout=TIMEOUT, env=env)
    blob = p.stdout + p.stderr
    real_enospc = [l for l in blob.splitlines()
                   if "no space left on device" in l and "injected:" not in l]
    if real_enospc:
        return None, None, "DISK-FULL"
    if "panic: test timed out" in blob:
        return None, None, "HANG"
    failed, ran = set(), set()
    build_fail = "[build failed]" in blob
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
    if build_fail:
        return None, None, "BUILD-FAILED"
    return failed, ran, None


def main():
    files = {ADAPTER, BELT, RESOLVER}
    backup = {f: open(f).read() for f in files}

    print("=== BASELINE ===")
    rc, out = build()
    if rc != 0:
        print("BASELINE VOID: tree does not build\n" + out[:800])
        return 2
    failed, ran, void = run_tests()
    if void:
        print(f"BASELINE VOID: {void}")
        return 2
    print(f"baseline: {len(ran)} tests ran, {len(failed)} failed")
    if len(ran) < MIN_TESTS or failed:
        print(f"BASELINE VOID (ran={len(ran)} failed={sorted(failed)})")
        return 2

    results = []
    for name, edits in MUTANTS:
        print(f"\n=== {name} ===")
        ok = True
        for f, find, repl, before, after in edits:
            s = open(f).read()
            n = s.count(find)
            if n != before:
                print(f"  APPLY FAILED: target count {n}, want {before}")
                ok = False
                break
            s2 = s.replace(find, repl)
            n2 = s2.count(find)
            if n2 != after:
                print(f"  APPLY FAILED: post-count {n2}, want {after}")
                ok = False
                break
            rb, ra = s.count(repl), s2.count(repl)
            if repl.strip() and ra <= rb:
                print(f"  APPLY FAILED: replacement {rb} -> {ra}, expected an increase")
                ok = False
                break
            open(f, "w").write(s2)
            print(f"  applied: target {n} -> {n2}, replacement {rb} -> {ra} in {os.path.basename(f)}")
        if not ok:
            for f, orig in backup.items():
                open(f, "w").write(orig)
            results.append((name, "VOID-NOT-APPLIED", []))
            continue

        verdict, killers = None, []
        rc, out = build()
        if rc != 0:
            if GUARD_FILE in out and GUARD_METHOD in out:
                verdict = "KILLED(compile)"
                killers = [f"{GUARD_FILE}: the compile-time belt refused the published type"]
                print(f"  {verdict}: {out.strip().splitlines()[-1][:200]}")
            else:
                verdict = "VOID-BUILD-BROKE-FOR-ANOTHER-REASON"
                print(f"  {verdict}:\n{out[:600]}")
        else:
            try:
                failed, ran, void = run_tests()
            except subprocess.TimeoutExpired:
                failed, ran, void = None, None, "HANG"
            if void:
                verdict = f"VOID-{void}"
                print(f"  {verdict}")
            elif len(ran) < MIN_TESTS:
                verdict = "VOID-COLLECTED-NOTHING"
                print(f"  {verdict}: only {len(ran)} tests ran")
            elif failed:
                mine = sorted(t for t in failed if "9482" in t)
                other = sorted(t for t in failed if "9482" not in t)
                verdict = "KILLED"
                killers = mine or other
                print(f"  KILLED; #9482 cells: {mine}")
                if other:
                    print(f"  also red (collateral): {other}")
            else:
                verdict = "SURVIVED"
                print(f"  SURVIVED ({len(ran)} tests ran, none failed)")
        for f, orig in backup.items():
            open(f, "w").write(orig)
        results.append((name, verdict, killers))

    print("\n=== MATRIX ===")
    for name, verdict, killers in results:
        print(f"{verdict:42s} {name}")
        for k in killers:
            print(f"{'':42s}   killed by {k}")
    return 0


sys.exit(main())
