# Census: ratchets that compute "what changed" by position, sort order, or count

Prompted by the `added9091` defect (#9391 / PR #9399): a helper whose doc
comment claimed to "turn a bare count into something reviewable" returned
`blind[ceiling:]` — the ALPHABETIC TAIL of a sorted slice. When two entries
arrived it named two paths that had NOT moved and stayed silent about the two
that had.

The question this census answers: **is that one bug, or a class?**

## Method, and what it cannot ask

Two AST passes over every `.go` file under `pkg/` (`go/parser`, not grep —
regex cannot tell a call site from a helper body).

**Pass A — the WRONG-diagnostic shape.** `added9091` was invisible at its call
site: it appeared as `added9091(blind)` inside the failure message, and the
positional-ness lived in the helper's BODY. So pass A collects every locally
defined helper whose result is formatted into a failure/log message carrying
member vocabulary (`new`, `added`, `gone`, `no longer`, `GREW`, `SHRANK`,
`missing`, `stale`, `dropped`), then classifies each helper's body:
MEMBERSHIP (a map/index containment test) vs POSITIONAL (returns a slice of its
input).

**Pass B — the MISSING-diagnostic shape.** A test function comparing against a
PACKAGE-LEVEL expectation identifier (`*Ceiling|*Floor|*Baseline|*Budget|
*Known|*Population|*Allowed|*Expected`), classified by whether any failure
message in it presents a non-numeric argument.

### What the census cannot see — stated because a population an instrument produces is evidence about the instrument first

1. **Granularity.** Pass B's unit is the FUNCTION. An assertion that reports
   only counts, sitting in a function that names members for a DIFFERENT
   assertion, reads as MEMBERS. **That blind spot hides the one real finding
   below**, which had to be reached by hand.
2. **Vocabulary.** Both passes key on message wording. A ratchet whose failure
   says "the set moved" without any of the listed words is invisible.
3. **Indirection.** Pass A follows one level — a helper called directly in the
   message. A helper calling a helper is not followed.
4. **Data-file registries.** A ratchet whose expectation lives in `testdata/`
   (#8921's shape) has no package-level identifier and is outside pass B.
   Those are the ones that already do set-diff, so the omission is benign here
   — but it is an omission, not a clean bill.

### Two false-positive modes found by hand-checking verdicts, not by review

- Pass B first matched FUNCTION-LOCAL `wantX` identifiers, so its population
  was 169 — dominated by ordinary tests where `got=3 want=4` is a complete
  diagnostic. Restricting to package-level expectations gave **20**.
- Pass B read only single-literal format strings, while this repo CONCATENATES
  them across lines, so `t.Errorf("..."+"...", members)` parsed as having no
  format. That mis-classified 5 member-naming ratchets as count-only.

Both were caught by reading the named members and disbelieving the list. The
first number this census produced was wrong by 8x.

## Result

### Pass A — the wrong-diagnostic shape: ZERO remaining instances

```
helpers whose result is presented as "what changed":  10
  MEMBERSHIP   1
  OTHER        8
  POSITIONAL   1   <- false positive: `prop.Keys[1:]`, the skip-the-keyword
                      idiom in zoneInterfaceStanzaTokens, not a diff claim
```

**`added9091` was a single occurrence.** Its shape — a helper answering "what
changed" by position — exists nowhere else in the tree. That is a smaller
answer than the prompt assumed, and it is the answer.

### Pass B — the missing-diagnostic shape: 20 ratchets, 5 count-only, all 5 correct

```
epochClockSaneFloor          x3   a clock sanity floor      SCALAR
bootEpoch*Budget                  time budgets              SCALAR
wantOptionsTemplateID             an IPFIX template id      SCALAR
napiProbeFloor                    the historical probe count, used as a
                                  POSITIVE CONTROL          SCALAR
```

For a scalar threshold a count IS the complete diagnostic — `got 30, want >= 40`
names everything there is to name. **None is a defect.**

## The one real finding, which the census could not see

`gateCoverageFloor` and the two blind-class ceilings in #7484 govern a
POPULATION, and their failures report only numbers:

```
COVERAGE IMPROVED — TIGHTEN THE RATCHET:  [gateCoverageFloor: 716 -> 742]
```

When that fired for #9351 I had to write a throwaway differ against
`origin/master` to learn WHICH 26 leaves arrived — and I then described the
members of two classes WRONGLY in the ratchet's own comments and corrected them
from the data. That is the `added9091` cost one step milder: a MISSING
diagnostic rather than a WRONG one.

Pass B classified it as MEMBERS, because the same function names members for a
different assertion (the blind-spot samples). **Blind spot 1, exactly.**

### Remedy, following #8921 / #9094

`testdata/spelling_gate_members_7484.txt` records all **1169** enumerated leaves
with the bucket each lands in, and `TestSpellingGateMembersAreRecorded7484`
reports ARRIVED / DEPARTED / RECLASSIFIED by name. The three counts stay — they
are the ratchet; this is the diagnostic they never had.

**RECLASSIFIED is the case a count cannot see at all.** A leaf moving between
two blind classes holds every total steady while both ceilings now describe
different populations. Verified by perturbing one row in the registry: the cell
reds naming that leaf and its old and new bucket.

## What I would tell the next person

The wrong-diagnostic shape was one bug. The count-only shape is common and
usually CORRECT — it is only a defect when the number governs a POPULATION,
and distinguishing that is a judgement the scanner cannot make. So the useful
rule is not "never report a count":

> **A count is a complete diagnostic for a scalar threshold and an incomplete
> one for a population. If the number bounds a SET, the failure owes the
> members.**
