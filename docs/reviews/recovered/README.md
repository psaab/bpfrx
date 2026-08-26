# Recovered review artefacts

Documents in this directory are **recovered evidence**, not living docs. They are
tracked because issue bodies cite them and the paths they were originally written
to do not survive.

Do not edit them. Their value is that they are the document the issues point at;
an edited copy answers a different question. Corrections belong in the issue or
the PR that acts on the finding.

## `opus-review-001.md`

- **Recovered from** `/home/ps/git/opus-review-001.md` — one directory above the
  repo — after issue bodies citing `/tmp/opus-review-001.md` were annotated
  "not recoverable" on the strength of a search that covered `/tmp`,
  `docs/reviews/{archive,recovered,reports}` and git history across all refs, but
  never the repo's parent. Two agents had reported the real path before the
  annotation was corrected.
- **md5** `d3de78f1fdaace39adc9fcfcfeca9c8d`, 2.4 MB, copied byte-for-byte.
- **68 detailed root sections**, `R01`–`R73` with gaps at 05, 32, 35, 54, 59.
- **Review base** `ad959117748181dabe46b8ddc2827de670380cea`.

### Identity, and the limit on that claim

This is the cited document **by every check available**: root titles match open
issue titles word for word (R61/#6800, R62/#6801, R67/#6806, R68/#6807), the
per-root batch names match the `source batch opus-A7-b*.md` strings the issue
bodies cite, and the base SHA appears throughout.

It is **not** provably byte-identical to what `/tmp/opus-review-001.md` held —
that path is genuinely gone, so no comparison is possible. Note also that
`/tmp/claude-opus-review-001.md` and `-002.md` are **different documents** with
near-miss names; a filename that nearly matches is not the file.

### Why the sections matter more than the titles

A title-only re-derivation loses the two parts that stop a lane re-litigating
what the reviewer already settled:

- the **Dedup note**, which records that no existing issue owns the root;
- the **Refutation attempt**, which records what the reviewer tried to disprove
  and what actually fell.

R68 is the worked example: the reviewer **disproved** the original permit-all
consequence — target FRR returns `RMAP_DENY` on a missing named route-map
(`bgpd/bgp_route.c`, checked across stable/8.4 through 10.6 and master) — so the
defect is a route **outage**, not an open door. The review further records that
the repository's own comments and tests assert the refuted version. A lane
working from the title had even odds of building the fix around the wrong failure
direction, against repo comments that would have agreed with it.

R61 is the second: it names **three** services (chrony, rsyslog, sshd) where a
title-derived reading found two, and it identifies the sshd exposure as
specifically the **removal** path — the update path rolls back, the removal path
cannot.

### Still re-derive

The review was taken at `ad959117`. Findings go stale. These sections are
**evidence**, not a verdict: re-derive against current `origin/master` before
acting, and record what changed.
