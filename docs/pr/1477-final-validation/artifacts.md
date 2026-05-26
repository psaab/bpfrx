# #1477 Validation Artifact Index

Phase A: empty pre-merge. This file tracks the populated artifact bundle once
the runbook in `runbook.md` is executed against the #1476 source-removal
merge SHA.

## Phase B fields (populated when validation runs)

- **Candidate commit (full 40-char SHA):** _(populated by §0.1)_
- **#1476 merge PR number:** _(populated by §0.1)_
- **Artifact root path:** _(populated by §0.3, of form
  `docs/pr/1373-retire-ebpf-dataplane/evidence-1477-source-removal-YYYYMMDD-<sha12>/`)_
- **Cluster:** `loss:xpf-userspace-fw0` / `loss:xpf-userspace-fw1`
- **Binary SHA-256s:** _(populated from `metadata/binary-sha256.txt`)_

## Gate verdicts

| # | Gate | Verdict | Notes |
|---|------|---------|-------|
| 1 | CoS-off IPv4/IPv6 push+reverse | _pending_ | |
| 2 | Screen/flood baseline | _pending_ | |
| 3 | SYN-cookie proof (#1374) | _pending_ | |
| 4 | CoS-on 5200-5211 push+reverse | _pending_ | |
| 5 | TCP echo 6200-6211 | _pending_ | |
| 6 | Steady-state matrix (8/8) | _pending_ | |
| 7 | Port-mirror fidelity (#1376) | _pending_ | |
| 8 | HA failover strict acceptance | _pending_ | |
| 9 | HA destructive regression | _pending_ | |
| 10 | Fallback exclusion | _pending_ | |

## Structural check

- `python3 test/incus/retire_ebpf_artifact_schema.py <root> --candidate-commit <sha>`
  output: _pending_

## Posted on #1477

- Comment URL: _pending_
- #1477 closure: _pending_
- #1373 umbrella closure: _pending_

## In-tree helpers (Phase A.5)

Both runbook-referenced helpers are now in-tree on this branch:

- `scripts/cookie-replay.py` — drives SYN-cookie sub-gates 5.4 - 5.8.
  Unit-tested by `scripts/cookie_replay_test.py` (13 tests).
- `scripts/mirror-pcap-fidelity.py` — structured port-mirror PCAP
  byte-equality + count-tolerance check for runbook §9.3.
  Unit-tested by `scripts/mirror_pcap_fidelity_test.py` (10 tests).

Phase B preserves the cookie-replay script source under
`<artifact_root>/syn-cookie/cookie-replay.py` (runbook §5.4 push step) so
the evidence bundle remains reproducible against the exact source-removal
candidate.
