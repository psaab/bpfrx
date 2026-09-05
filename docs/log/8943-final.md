# #8943 final — the last 13 depth-2 drops

- **Timestamp**: 2026-09-05
- **Action**: admit the remaining 13; the measured depth-2 population reaches zero
- **File(s)**: `pkg/config/compact_normalize_scope.go`,
  `pkg/config/elision_admissions_8879_test.go`,
  `pkg/config/compact_scope_blind_pairs_8852_test.go`,
  `pkg/config/unsplittable_pairs_ratchet_8880_test.go`,
  `pkg/config/testdata/multisite_admissions_8921.txt`

## Verdict table (gate column FIRST)

All thirteen: **gate SILENT, both spellings accepted at strict commit, elided arm
parse-checked, braced arm live against an empty config.**

| pair | warns b/e | braced → elided |
|---|---|---|
| `address-book global` | 0/0 | `addrs=1` → `<nil>` |
| `archival configuration` | 0/0 | `iv=77` → `<nil>` |
| `bgp damping` | 0/0 | `damp=true/27` → `<nil>` |
| `bgp multipath` | 0/0 | `mpAS=true` → `<nil>` |
| `dataplane coalescence` | 0/0 | `rx=37` → `<nil>` |
| `dataplane shared-umem` | 0/0 | `umem=cross-nic` → `<nil>` |
| `flow-monitoring version9` | 0/0 | `v9=1` → `<nil>` |
| `flow-monitoring version-ipfix` | 0/0 | `ipfix=1` → `<nil>` |
| `interface-routes rib-group` | 0/0 | `rg=rg7717` → `rg=` |
| `license autoupdate` | 0/0 | `url=…` → `url=` |
| `policies policy-rematch` | **1/0** | `rematch=true/true` → `false/false` |
| `pre-id-default-policy then` | **1/0** | `init=true` → `<nil>` |
| `rib static` | 0/0 | `static=1` → `static=0` |

**13 admitted, 0 declined. The measured depth-2 population is now 0.**

## Severity axis — reaches the dataplane, or stops at the compiler?

The two `warns=1/0` rows carry advisories, and reading them separates two cases
that look identical in a diff:

- **`pre-id-default-policy then`** — *"accepted for compatibility but is INERT in
  the userspace dataplane"*. The value has no runtime effect either way, so the
  elision costs the **advisory**. Registered in the not-read set (5 of 67).
- **`policies policy-rematch`** — *"configured but only PARTIALLY enforced"*.
  That is **not** inert: losing it loses real, if incomplete, behaviour. It stays
  in the read set.

"Partially enforced" and "inert" read the same in a fingerprint and are opposite
answers on the severity axis. The read/not-read detector distinguished them
because it matches on the advisory's own wording rather than on the presence of
a warning.

The rest reach live configuration: `bgp damping`/`multipath` feed FRR, the
`dataplane` pair feeds the AF_XDP helper, `flow-monitoring` feeds the exporter,
`rib static`/`interface-routes rib-group` feed routing.

## #8921 — three admissions are live at TWO sites, and my own count was wrong

My collision walk reported 2 sites for `bgp damping`, `interface-routes
rib-group` and `rib static`, and I concluded the second was a `groups` re-host
of the same node — pointer-identity confirmed the `groups` subtree shares node
objects, so it looked like duplicate coverage.

**`TestMultisiteAdmissionsAreRecorded8921` corrected that.** Its walk skips
`groups` explicitly, and it named the real second sites:

    bgp damping                 protocols/bgp            + routing-instances/*/protocols/bgp
    interface-routes rib-group  routing-options/…        + routing-instances/*/routing-options/…
    rib static                  routing-options/rib      + routing-instances/*/routing-options/rib

Per-**routing-instance** duplicates, not group re-hosts. My walk's output was
distorted by its own `seen` dedup: it recorded whichever path reached the shared
node first, so the paths it printed were an artifact of traversal order rather
than evidence about where the pair lives. The count was right and the
explanation was wrong — and the explanation is what I would have written into
the commit message.

Spot-checked before recording rather than relying on the guard's contract (item
3 records, it does not adjudicate): at the second site the braced and elided
spellings compile **identically** for both `bgp damping` and `rib static`, so the
extra site benefits from the admission rather than being collateral. All three
recorded in `testdata/multisite_admissions_8921.txt`.

## The #8880 rule, hoisted

The membership-vs-remedy-advice rule now sits at the top of the ratchet's
comment block and in its GREW failure text, rather than buried at the end of one
instance note. Two members have now had causes the advice did not fit
(`as-path`, `syslog`), and the failure text is what a reader sees when it fires.

## Mutations

**13 of 13 killed.** Each admission dropped in turn reds the property assertion
and the population count. Admission count re-verified at 13 afterwards.

## Corpus

9 pass / 5 fail — unchanged across every batch of this campaign.
