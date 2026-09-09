#!/usr/bin/env python3
"""#9177 mutation matrix. Bounded, occurrence-counted, JSON-scored.

Same discipline as scripts/mutate-9452.py:
  a) a mutant that does not BUILD is VOID, not survived.
  b) APPLIED is confirmed by occurrence count, in BOTH directions — a removal
     reads 0 whether it was applied or never attempted, so the replacement's
     count must also be seen to rise.
  c) every run is bounded, so a hang scores VOID.
  d) scoring reads `go test -json` Action=="fail" and compares the NAME.
  e) a run that collected nothing is VOID: >= MIN_TESTS must have run.
  f) a log containing "no space left on device" is VOID.
"""
import json, os, subprocess, sys

REPO = "/var/tmp/wt-9177"
PKG = "./pkg/cluster/"
MIN_TESTS = 50
TIMEOUT = 600
READER = os.path.join(REPO, "pkg/cluster/sync_conn_read.go")

STATS = '''		s.stats.BulkSyncStartTime.Store(time.Now().UnixNano())
		s.stats.BulkSyncEndTime.Store(0)
		s.stats.BulkSyncSessions.Store(0)
'''

MUTANTS = [
    ("N1 V052 reverted: the three stat stores move back ABOVE the accept", [
        (READER, STATS, '', 1, 0),
        (READER,
         '''		// #2198 F2: the peer is re-priming its authoritative live set. Reset''',
         STATS + '''		// #2198 F2: the peer is re-priming its authoritative live set. Reset''', 1, 1),
    ]),
    ("N2 V052 over-correction: the stat stores DELETED rather than moved", [
        (READER, STATS, '', 1, 0),
    ]),
    ("N3 V053 reverted: the ack comparator back to `<`", [
        (READER, '''		if pending == 0 || epoch != pending {''',
         '''		if pending == 0 || epoch < pending {''', 1, 0),
    ]),
    ("N4 V053 over-correction: the ack comparator refuses EVERY epoch", [
        (READER, '''		if pending == 0 || epoch != pending {''',
         '''		if true {''', 1, 0),
    ]),
]


def run_tests():
    env = dict(os.environ)
    env.pop("TMPDIR", None)
    env.pop("GOTMPDIR", None)
    p = subprocess.run(
        ["go", "test", "-json", "-count=1", f"-timeout={TIMEOUT-60}s", PKG],
        cwd=REPO, capture_output=True, text=True, timeout=TIMEOUT, env=env)
    blob = p.stdout + p.stderr
    if "no space left on device" in blob:
        return None, None, "DISK-FULL"
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
        if ev.get("Action") == "output" and "build failed" in (ev.get("Output") or ""):
            build_fail = True
    if build_fail:
        return None, None, "BUILD-FAILED"
    return failed, ran, None


def main():
    files = {READER}
    backup = {f: open(f).read() for f in files}

    print("=== BASELINE ===")
    failed, ran, void = run_tests()
    if void:
        print(f"BASELINE VOID: {void}")
        return 2
    print(f"baseline: {len(ran)} tests ran, {len(failed)} failed")
    if len(ran) < MIN_TESTS or failed:
        print("BASELINE VOID")
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
                print(f"  APPLY FAILED: replacement count {rb} -> {ra}, expected an increase")
                ok = False
                break
            open(f, "w").write(s2)
            print(f"  applied: target {n} -> {n2}, replacement {rb} -> {ra}")
        if not ok:
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
            print(f"  VOID: only {len(ran)} tests ran")
            results.append((name, "VOID-COLLECTED-NOTHING", []))
            continue
        nine = sorted(t for t in failed if "9177" in t)
        other = sorted(t for t in failed if "9177" not in t)
        if failed:
            print(f"  KILLED; #9177 cells: {nine}")
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
