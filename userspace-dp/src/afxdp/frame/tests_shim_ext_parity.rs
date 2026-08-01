// #4555: parity between the AF_XDP shim's IPv6 extension-header walk and
// this crate's `walk_ipv6_ext_chain`.
//
// The shim's verdict decides whether a packet matches the session map and
// takes the XDP fast path; this crate's decides how the packet is actually
// forwarded. When they disagree the shim computes a session key userspace
// never installed, so every packet of that flow is redirected to userspace
// — fail-closed, but a permanent loss of the fast path. Two divergences
// existed before #4555: the resolvable chain length (6 vs 7) and the
// walked type set (#4517's Mobility/HIP/Shim6/experimental were missing).
//
// WHY THIS READS EMITTED FACTS AND MODELS NOTHING.
//
// The shim cannot be executed here: it is `no_std`, built for
// `bpfel-unknown-none`. Four successive versions of this test MODELLED it
// from source text, and every one leaked to a more ordinary edit:
//
//   1. classifying arm bodies by substring accepted an extra `+ 8` on the
//      generic advance;
//   2. it also accepted a prepended `if opt[1] == 0 { break; }` — which
//      rejects the ORDINARY 8-byte HbH/DestOpt, destroying parity for
//      essentially every real chain;
//   3. pinning whole arm bodies by token equality still ignored a
//      statement placed inside the walk loop but OUTSIDE the `match`;
//   4. pinning the TEXT `mem::size_of::<FragHdr>()` did not pin its
//      VALUE, so one added field changed the Fragment advance invisibly;
//   5. and the struct-layout resolver written to fix (4) split fields on
//      commas and skipped `//` fragments, so a COMMENT above a field hid
//      the field with it.
//
// Five leaks, each to a more innocuous edit than the last. Every fix was a
// better model, and a better model is still a model.
//
// The first inversion emitted three facts (`XPF_SHIM_FACTS`: `MAX_EXT_HDRS`,
// `size_of::<FragHdr>()`, the 256-entry class table), recorded by
// `make generate` in `pkg/dataplane/userspace_xdp_manifest.json`. That closed
// the tautology — a falsified manifest reds against the object — but it did NOT
// close the coverage, and claiming "nothing left to defeat" was wrong. Three
// scalars cannot witness the walk's BEHAVIOUR. Four edits to the shim left every
// test here green: changing the generic advance to `* 16`, changing the AH
// advance to `* 8`, adding `if offset > 200 { break; }` in the loop body outside
// the `match` (leak #3, verbatim), and — worst — DELETING the generic arm's
// post-advance bounds revalidation, the security property. Worse still, the one
// thing that did red was the #4977 freshness hash, whose message says the object
// may be stale and to run `make generate`; following it regenerates identical
// facts and ships the divergence.
//
// So the walk itself is now EXECUTED. `userspace-xdp/src/ipv6_ext_walk.rs`
// holds the shim's real walk in a module that depends only on `core`, the shim
// calls it, and this file `#[path]`-includes THAT FILE and runs it on real byte
// buffers alongside `walk_ipv6_ext_chain`. Advance arithmetic, bounds
// revalidation and resolvable chain length are outcomes compared over a corpus,
// not claims about source text. The emitted facts are kept for what they are
// uniquely good at: travelling with the ARTIFACT, so a consumer of a prebuilt
// object (the Debian packaging path never compiles the shim crate) can check
// them without a Rust toolchain.
//
// It also fixes a scope problem the source model could not: a compile-time
// assertion in the shim only runs when the shim crate is compiled, which
// the Debian packaging path never does (it runs `make build`, and the
// daemon embeds the tracked `.o`). Facts recorded in the manifest are
// checkable wherever a prebuilt object is consumed.
//
// No source-text check remains. The exhaustion semantics that make the shim
// resolve `MAX_EXT_HDRS` headers where this crate resolves
// `MAX_IPV6_EXT_HEADERS - 1` used to be the one property argued to be
// unemittable — "a shape, not a value". Executing the walk dissolves that:
// the corpus below walks chains of 0..=10 extension headers and compares
// verdicts, so the resolvable length is measured on both sides rather than
// asserted about either.

#![allow(unused_imports)]

use super::*;
use std::path::{Path, PathBuf};

const PROBE_TCP: u8 = 6;

// Extension-header classes, mirroring EH_CLASS_* in
// userspace-xdp/src/lib.rs and pkg/dataplane/userspace_xdp_facts.go.
// These are the values carried in the emitted table.
const EH_CLASS_TERMINAL: u8 = 0;
const EH_CLASS_GENERIC: u8 = 1;
const EH_CLASS_AUTH: u8 = 2;
const EH_CLASS_FRAGMENT: u8 = 3;
const EH_CLASS_NONEXT: u8 = 4;

fn repo_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is <repo>/userspace-dp.
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

/// The shim facts `make generate` recorded alongside the tracked object.
struct ShimFacts {
    max_ext_hdrs: usize,
    frag_hdr_size: usize,
    eh_classes: Vec<u8>,
}

/// Read the emitted facts out of the committed manifest.
///
/// Fails LOUDLY on a missing or unreadable manifest — never skips. A skip
/// would fail open on exactly the drift this exists to catch, the hole
/// `pkg/dataplane/userspace_xdp_manifest.go` calls out for
/// `TestMaxInterfacesMatchesCHeader`'s `t.Skipf`.
fn read_shim_facts() -> ShimFacts {
    let path = repo_root()
        .join("pkg")
        .join("dataplane")
        .join("userspace_xdp_manifest.json");
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "cannot read the shim manifest at {}: {e}. It carries the shim's emitted #4555 \
             facts; run `make generate`. This guard must not be skipped.",
            path.display()
        )
    });

    let facts = json_object_field(&raw, "\"shim_facts\"").unwrap_or_else(|| {
        panic!(
            "the shim manifest has no `shim_facts` block — run `make generate` with a shim that \
             emits XPF_SHIM_FACTS (#4555). Refusing to fall back to modelling the shim's source."
        )
    });

    let max_ext_hdrs = json_number(&facts, "max_ext_hdrs");
    let frag_hdr_size = json_number(&facts, "frag_hdr_size");
    let eh_classes = json_hex_bytes(&facts, "eh_classes_hex");
    assert_eq!(
        eh_classes.len(),
        256,
        "shim_facts.eh_classes has {} entries, want one per IPv6 next-header value",
        eh_classes.len()
    );
    ShimFacts {
        max_ext_hdrs,
        frag_hdr_size,
        eh_classes,
    }
}

// Minimal JSON readers. The manifest is generated by `encoding/json` with
// a fixed shape, so a full parser would be a dependency for no benefit.
// Every helper panics rather than defaulting, so a shape change is loud.

fn json_object_field(src: &str, key: &str) -> Option<String> {
    let at = src.find(key)?;
    let open = src[at..].find('{')? + at;
    let mut depth = 0usize;
    for (i, c) in src[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(src[open..open + i + 1].to_string());
                }
            }
            _ => {}
        }
    }
    None
}

fn json_number(obj: &str, key: &str) -> usize {
    let needle = format!("\"{key}\"");
    let at = obj
        .find(&needle)
        .unwrap_or_else(|| panic!("shim_facts has no `{key}` — run `make generate` (#4555)"));
    let rest = &obj[at + needle.len()..];
    let colon = rest.find(':').expect("malformed shim_facts JSON");
    let digits: String = rest[colon + 1..]
        .trim_start()
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits
        .parse()
        .unwrap_or_else(|e| panic!("shim_facts.{key} is not a number ({digits:?}): {e}"))
}

fn json_hex_bytes(obj: &str, key: &str) -> Vec<u8> {
    let needle = format!("\"{key}\"");
    let at = obj
        .find(&needle)
        .unwrap_or_else(|| panic!("shim_facts has no `{key}` — run `make generate` (#4555)"));
    let rest = &obj[at + needle.len()..];
    let colon = rest.find(':').expect("malformed shim_facts JSON");
    let tail = &rest[colon + 1..];
    let open = tail.find('"').expect("shim_facts hex string not found");
    let close = tail[open + 1..]
        .find('"')
        .expect("shim_facts hex string unterminated")
        + open
        + 1;
    let hex = &tail[open + 1..close];
    assert!(
        hex.len() % 2 == 0,
        "shim_facts.{key} has an odd hex length {}",
        hex.len()
    );
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .unwrap_or_else(|e| panic!("shim_facts.{key} byte at {i}: {e}"))
        })
        .collect()
}

/// Classify one next-header value by RUNNING this crate's walker over a
/// probe packet. The probe is a 40-byte IPv6 header whose Next Header is
/// the value under test, followed by one header at offset 40 declaring
/// `HdrExtLen = 1` and `next = TCP`. The walking arms then land the
/// terminal L4 at three distinguishable offsets:
///   generic  → 40 + (1 + 1) * 8 = 56
///   AH       → 40 + (1 + 2) * 4 = 52
///   fragment → 40 + 8           = 48   (and records a Fragment sighting)
/// while a terminal value stops at 40 reporting itself, and 59 reports
/// `NoNextHeader`.
fn userspace_class(proto: u8) -> u8 {
    let mut buf = vec![0u8; 96];
    buf[0] = 0x60;
    buf[6] = proto;
    buf[40] = PROBE_TCP;
    buf[41] = 1;
    let walk = walk_ipv6_ext_chain(&buf, 0);
    match walk.outcome {
        ExtChainOutcome::NoNextHeader => EH_CLASS_NONEXT,
        ExtChainOutcome::L4(40, p) => {
            assert_eq!(
                p, proto,
                "probe for next-header {proto} stopped at offset 40 reporting protocol {p}"
            );
            EH_CLASS_TERMINAL
        }
        ExtChainOutcome::L4(56, PROBE_TCP) => EH_CLASS_GENERIC,
        ExtChainOutcome::L4(52, PROBE_TCP) => EH_CLASS_AUTH,
        ExtChainOutcome::L4(48, PROBE_TCP) => {
            assert!(
                walk.fragment.is_some(),
                "probe for next-header {proto} advanced 8 bytes without recording a Fragment \
                 sighting — the probe can no longer distinguish the Fragment arm"
            );
            EH_CLASS_FRAGMENT
        }
        other => panic!(
            "probe for next-header {proto} produced an unclassifiable outcome {other:?}; the \
             #4555 parity probe needs updating for the new walker shape"
        ),
    }
}

/// Bytes this crate's walker advances past a Fragment header, measured.
fn userspace_fragment_advance() -> usize {
    const FRAGMENT: u8 = 44;
    let mut buf = vec![0u8; 96];
    buf[0] = 0x60;
    buf[6] = FRAGMENT;
    buf[40] = PROBE_TCP;
    match walk_ipv6_ext_chain(&buf, 0).outcome {
        ExtChainOutcome::L4(off, PROBE_TCP) => off - 40,
        other => panic!("the userspace fragment probe no longer resolves to TCP ({other:?})"),
    }
}

/// Build `n` chained 8-byte DestOpt headers terminated by TCP and report
/// whether this crate's walker resolves the terminal.
fn userspace_resolves_chain_of(n: usize) -> bool {
    const DEST_OPT: u8 = 60;
    let mut buf = vec![0u8; 40 + 8 * n + 20];
    buf[0] = 0x60;
    buf[6] = if n == 0 { PROBE_TCP } else { DEST_OPT };
    for i in 0..n {
        let at = 40 + 8 * i;
        buf[at] = if i + 1 == n { PROBE_TCP } else { DEST_OPT };
    }
    matches!(
        walk_ipv6_ext_chain(&buf, 0).outcome,
        ExtChainOutcome::L4(off, PROBE_TCP) if off == 40 + 8 * n
    )
}

/// Longest chain this crate resolves, measured rather than read off the
/// constant.
fn userspace_max_resolvable_ext_headers() -> usize {
    for n in 0..64 {
        if !userspace_resolves_chain_of(n) {
            return n.saturating_sub(1);
        }
    }
    panic!("walk_ipv6_ext_chain resolved a 64-header chain; it is meant to be bounded");
}

fn class_name(c: u8) -> &'static str {
    match c {
        EH_CLASS_TERMINAL => "Terminal",
        EH_CLASS_GENERIC => "Generic",
        EH_CLASS_AUTH => "Auth",
        EH_CLASS_FRAGMENT => "Fragment",
        EH_CLASS_NONEXT => "NoNext",
        _ => "UNKNOWN",
    }
}

/// The load-bearing #4555 guard: the shim's EMITTED facts and this crate's
/// MEASURED behaviour must agree on the resolvable chain length, the
/// Fragment advance, and the classification of all 256 next-header values.
#[test]
fn shim_ipv6_ext_walk_matches_userspace_walker() {
    let facts = read_shim_facts();

    // Chain length. The bounds are ITERATION counts over loops that exit
    // differently: the shim spends one iteration per header and exits by
    // exhaustion carrying the resolved protocol into parse_l4, so it
    // resolves MAX_EXT_HDRS headers; walk_ipv6_ext_chain needs one FURTHER
    // iteration to return the terminal and folds exhaustion into the
    // fail-closed OverLimit verdict, so it resolves
    // MAX_IPV6_EXT_HEADERS - 1. The relation is therefore
    // `MAX_EXT_HDRS == MAX_IPV6_EXT_HEADERS - 1`, NOT numeric equality —
    // setting the shim to 8 would make it resolve chains this crate fails
    // closed on. What pins the exit semantics this reasoning rests on is the
    // corpus in `shim_walk_and_userspace_walk_agree_over_a_corpus`, which walks
    // chains of 0..=10 extension headers through BOTH walkers and compares
    // verdicts — so the resolvable length is measured on each side rather than
    // argued about either. (An earlier revision cited a source-text check named
    // `shim_walk_exits_by_exhaustion`; that test was deleted when the walk
    // became executable, and this sentence outlived it.)
    let userspace_max = userspace_max_resolvable_ext_headers();
    assert_eq!(
        facts.max_ext_hdrs, userspace_max,
        "#4555 IPv6 extension-header CHAIN-LENGTH drift: the shipped shim resolves chains of up \
         to {} extension headers (its emitted MAX_EXT_HDRS) but this crate's \
         walk_ipv6_ext_chain resolves up to {userspace_max} (MAX_IPV6_EXT_HEADERS = {}). A chain \
         length one side resolves and the other does not makes the two compute different session \
         keys for the same packet, so the flow's key never matches and every packet takes the \
         slow XSK path forever. Raising the shim's bound costs BPF verifier budget and is gated \
         by the #1864 verify-then-install run: change it, re-run `make generate`, and commit the \
         regenerated object and manifest.",
        facts.max_ext_hdrs, MAX_IPV6_EXT_HEADERS,
    );
    assert_eq!(
        facts.max_ext_hdrs,
        MAX_IPV6_EXT_HEADERS - 1,
        "#4555: emitted MAX_EXT_HDRS ({}) != MAX_IPV6_EXT_HEADERS - 1 ({})",
        facts.max_ext_hdrs,
        MAX_IPV6_EXT_HEADERS - 1,
    );

    // Fragment advance, compared as a VALUE on both sides: the shim's
    // emitted size_of::<FragHdr>() against this crate's measured advance.
    let userspace_frag = userspace_fragment_advance();
    assert_eq!(
        facts.frag_hdr_size, userspace_frag,
        "#4555 Fragment-header ADVANCE drift: the shipped shim advances {} bytes past a Fragment \
         header (its emitted size_of::<FragHdr>()) but this crate advances {userspace_frag}. \
         Every L4 offset in a fragmented IPv6 chain would differ between the two, so the shim's \
         session key points at the wrong bytes. The IPv6 Fragment header is fixed at 8 bytes \
         (RFC 8200 §4.5) — if FragHdr changed, that is the bug.",
        facts.frag_hdr_size,
    );

    // Every next-header value: emitted class vs measured class.
    let mut drift: Vec<String> = Vec::new();
    for proto in 0u16..=255 {
        let proto = proto as u8;
        let shim = facts.eh_classes[usize::from(proto)];
        let userspace = userspace_class(proto);
        if shim != userspace {
            drift.push(format!(
                "next-header {proto}: shim={} userspace={}",
                class_name(shim),
                class_name(userspace)
            ));
        }
    }
    assert!(
        drift.is_empty(),
        "#4555 IPv6 extension-header TYPE-SET drift between the shipped shim's emitted \
         classification and this crate's walk_ipv6_ext_chain: {drift:?}. A type one side walks \
         THROUGH and the other treats as terminal makes the two compute different session keys \
         for the same packet, so the flow never matches the XDP fast path. Change both walkers \
         together, and re-run `make generate` for the shim side.",
    );
}

/// NEGATIVE CONTROL for the mutation proof.
///
/// Touches NOTHING on the shim side — no manifest, no shim source. It
/// exercises only this crate's walker and the probe harness the guard
/// measures with, so it stays green under every shim-side mutation and
/// reds only if this crate's behaviour or the probes broke.
#[test]
fn shim_ext_parity_negative_control_unchanged_classifications() {
    for (proto, want) in [
        (0u8, EH_CLASS_GENERIC), // Hop-by-Hop
        (43, EH_CLASS_GENERIC),  // Routing
        (60, EH_CLASS_GENERIC),  // Destination Options
        (44, EH_CLASS_FRAGMENT), // Fragment
        (51, EH_CLASS_AUTH),     // Authentication Header
        (59, EH_CLASS_NONEXT),   // No Next Header
        (50, EH_CLASS_TERMINAL), // ESP — deliberately NOT walked
        (6, EH_CLASS_TERMINAL),  // TCP
        (17, EH_CLASS_TERMINAL), // UDP
        (58, EH_CLASS_TERMINAL), // ICMPv6
    ] {
        assert_eq!(
            userspace_class(proto),
            want,
            "userspace classification of next-header {proto} changed; this is pre-#4555 \
             behaviour the fix must not perturb"
        );
    }

    for n in [0usize, 1, 5] {
        assert!(
            userspace_resolves_chain_of(n),
            "userspace walker stopped resolving a {n}-header chain"
        );
    }
    assert!(
        !userspace_resolves_chain_of(16),
        "userspace walker resolved a 16-header chain; it is meant to fail closed"
    );
    assert_eq!(
        userspace_max_resolvable_ext_headers(),
        MAX_IPV6_EXT_HEADERS - 1,
        "the userspace walker's resolvable chain length no longer matches its own bound; the \
         #4555 measurement harness is broken, independently of the shim"
    );
    assert_eq!(
        userspace_fragment_advance(),
        8,
        "the userspace walker no longer advances 8 bytes past a Fragment header (RFC 8200 §4.5)"
    );
}

// ---------------------------------------------------------------------------
// #4555: BEHAVIOURAL parity — the shim's real walk, executed.
// ---------------------------------------------------------------------------
//
// `ipv6_ext_walk.rs` is the shim's own source. It is `#[path]`-included here and
// compiled for the host, so what runs below is the code the BPF object is built
// from — not a description of it. Everything the source models used to assert
// (advance arithmetic per arm, the post-advance bounds revalidation, the
// resolvable chain length, which types are walked) becomes an observable
// outcome of running it.
#[path = "../../../../userspace-xdp/src/ipv6_ext_walk.rs"]
mod shim_walk;

/// A verdict both walkers can be reduced to, so they can be compared directly.
///
/// #4555 round 5: this used to be the outcome ALONE, which threw away the field
/// the divergence actually lives in. `walk_ipv6_ext_chain` returns an
/// `ExtChainWalk` — outcome PLUS the first Fragment sighting PLUS
/// `non_first_fragment_offset_seen` — and the fragment state is what makes
/// userspace refuse to build a session. Comparing only `.outcome` let a
/// non-first fragment agree (`L4(48, TCP)` on both) while the two sides
/// disagree about whether those bytes are a usable L4 header at all. That is
/// the same label-vs-behaviour gap this whole file exists to close, one level
/// down: I replaced a source model with execution and then discarded the
/// discriminating field. `Verdict` now carries it.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Verdict {
    /// Resolved a terminal upper-layer header at this offset.
    L4(usize, u8),
    /// No-Next-Header (59): a valid terminal with no L4.
    NoL4,
    /// Still on an extension header at the iteration bound.
    OverLimit,
    /// Truncated / declared length overran the packet / offset overflow.
    FailClosed,
}

/// The full compared record: the terminal verdict plus the fragment state that
/// governs whether the resolved L4 may seed a session.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
struct WalkRecord {
    verdict: Verdict,
    /// A Fragment header was sighted anywhere along the chain.
    saw_fragment: bool,
    /// A sighted Fragment header carried non-zero offset bits — a NON-FIRST
    /// fragment, whose payload is not an L4 header.
    non_first_fragment: bool,
}

/// Run the SHIM's walk on `buf` exactly as `parse_ipv6` does.
///
/// The shim's walk returns only `(offset, protocol)`: it does not record
/// fragment state, because nothing downstream of it in the shim consumes any.
/// The fragment fields are therefore derived here from the SAME bytes the shim
/// walked, so the comparison below is still between two things computed from
/// the packet rather than one thing asserted about the other. Where the shim
/// genuinely cannot represent a distinction, `shim_is_not_more_permissive`
/// states it explicitly instead of letting the corpus imply a parity it does
/// not verify.
fn shim_verdict(buf: &[u8], l3: usize) -> Verdict {
    if buf.len() < l3 + 40 {
        return Verdict::FailClosed;
    }
    let data = buf.as_ptr() as usize;
    let data_end = data + buf.len();
    let first = buf[l3 + 6];
    let start = (l3 + 40) as u16;
    match shim_walk::walk_ipv6_ext_headers(data, data_end, l3 as u16, first, start) {
        None => Verdict::FailClosed,
        Some((off, proto)) => match shim_walk::eh_class(proto) {
            shim_walk::EH_CLASS_NONEXT => Verdict::NoL4,
            shim_walk::EH_CLASS_TERMINAL => Verdict::L4(off as usize, proto),
            // Loop exhausted while still on an extension header.
            _ => Verdict::OverLimit,
        },
    }
}

fn userspace_verdict(buf: &[u8], l3: usize) -> Verdict {
    match walk_ipv6_ext_chain(buf, l3).outcome {
        ExtChainOutcome::L4(off, proto) => Verdict::L4(off, proto),
        ExtChainOutcome::NoNextHeader => Verdict::NoL4,
        ExtChainOutcome::OverLimit => Verdict::OverLimit,
        ExtChainOutcome::Truncated => Verdict::FailClosed,
    }
}

/// The FULL userspace record, fragment state included.
fn userspace_record(buf: &[u8], l3: usize) -> WalkRecord {
    let walk = walk_ipv6_ext_chain(buf, l3);
    WalkRecord {
        verdict: userspace_verdict(buf, l3),
        saw_fragment: walk.fragment.is_some(),
        non_first_fragment: walk.non_first_fragment_offset_seen,
    }
}

/// The shim's record, with the fragment fields derived from the same bytes.
fn shim_record(buf: &[u8], l3: usize) -> WalkRecord {
    let verdict = shim_verdict(buf, l3);
    // Re-walk the declared chain to observe what the shim's Fragment arm saw.
    // This mirrors the arm's own reads: it consumes 8 bytes and takes byte 0 as
    // the next header, so a sighting is exactly "the walk entered that arm".
    let (mut saw, mut non_first) = (false, false);
    if buf.len() >= l3 + 40 {
        let mut proto = buf[l3 + 6];
        let mut off = l3 + 40;
        for _ in 0..shim_walk::MAX_EXT_HDRS {
            match shim_walk::eh_class(proto) {
                shim_walk::EH_CLASS_FRAGMENT => {
                    let Some(f) = buf.get(off..off + 8) else { break };
                    saw = true;
                    if (u16::from_be_bytes([f[2], f[3]]) & 0xFFF8) != 0 {
                        non_first = true;
                    }
                    proto = f[0];
                    off += 8;
                }
                shim_walk::EH_CLASS_GENERIC => {
                    let Some(o) = buf.get(off..off + 2) else { break };
                    proto = o[0];
                    off += (usize::from(o[1]) + 1) * 8;
                }
                shim_walk::EH_CLASS_AUTH => {
                    let Some(o) = buf.get(off..off + 2) else { break };
                    proto = o[0];
                    off += (usize::from(o[1]) + 2) * 4;
                }
                _ => break,
            }
            if off > buf.len() {
                break;
            }
        }
    }
    WalkRecord {
        verdict,
        saw_fragment: saw,
        non_first_fragment: non_first,
    }
}

/// Build `IPv6 || headers || 20 bytes of L4`, where each header is
/// `(type, hdr_ext_len)` and occupies `(hdr_ext_len + 1) * 8` bytes — the
/// generic encoding. `trailing` extra bytes may be trimmed to truncate.
fn chain(headers: &[(u8, u8)], terminal: u8, trim: usize) -> Vec<u8> {
    let mut buf = vec![0u8; 40];
    buf[0] = 0x60;
    buf[6] = headers.first().map(|h| h.0).unwrap_or(terminal);
    for (i, (_, len)) in headers.iter().enumerate() {
        let next = headers.get(i + 1).map(|h| h.0).unwrap_or(terminal);
        let size = (usize::from(*len) + 1) * 8;
        let mut hdr = vec![0u8; size];
        hdr[0] = next;
        hdr[1] = *len;
        buf.extend_from_slice(&hdr);
    }
    buf.extend_from_slice(&[0u8; 20]);
    buf.truncate(buf.len().saturating_sub(trim));
    buf
}

/// The load-bearing behavioural guard: over a corpus of real chains, the shim's
/// executed walk and this crate's walker must reach the SAME verdict.
///
/// This is what replaces the deleted source models. It reds on an altered
/// advance (the offsets diverge), on a deleted bounds revalidation (a truncated
/// chain resolves instead of failing closed), on a statement added inside the
/// loop but outside the `match` (the chain length diverges), and on a changed
/// walked type set (a type resolves on one side and terminates on the other).
#[test]
fn shim_walk_and_userspace_walk_agree_over_a_corpus() {
    const TCP: u8 = 6;
    const HBH: u8 = 0;
    const DEST: u8 = 60;
    const AH: u8 = 51;
    const FRAG: u8 = 44;
    const MOBILITY: u8 = 135;

    let mut cases: Vec<(String, Vec<u8>)> = Vec::new();

    // Chain lengths across the 7/8 resolvable boundary, minimum-size headers.
    for n in 0..=10usize {
        let hdrs: Vec<(u8, u8)> = (0..n).map(|_| (DEST, 0)).collect();
        cases.push((format!("{n} x DestOpt(len=0) -> TCP"), chain(&hdrs, TCP, 0)));
    }
    // Declared lengths: the generic advance is (len+1)*8, so these separate
    // `* 8` from any other multiplier.
    for len in [0u8, 1, 2, 5, 15] {
        cases.push((
            format!("HbH(len={len}) -> TCP"),
            chain(&[(HBH, len)], TCP, 0),
        ));
        cases.push((
            format!("HbH(len={len}) + DestOpt(len=1) -> TCP"),
            chain(&[(HBH, len), (DEST, 1)], TCP, 0),
        ));
    }
    // Offsets past 200 while still on an extension header — the shape a
    // statement inside the loop but outside the match perturbs.
    cases.push((
        "3 x DestOpt(len=15) -> TCP (offset passes 200 mid-walk)".into(),
        chain(&[(DEST, 15), (DEST, 15), (DEST, 15)], TCP, 0),
    ));
    cases.push((
        "5 x DestOpt(len=15) -> TCP".into(),
        chain(&[(DEST, 15); 5], TCP, 0),
    ));
    // Truncation: the declared length runs past the packet. Without the
    // post-advance revalidation the walk resolves an L4 offset outside the
    // buffer instead of failing closed.
    for trim in [1usize, 8, 20, 21, 40] {
        cases.push((
            format!("HbH(len=5) -> TCP, trimmed {trim}"),
            chain(&[(HBH, 5)], TCP, trim),
        ));
        cases.push((
            format!("DestOpt(len=15) -> TCP, trimmed {trim}"),
            chain(&[(DEST, 15)], TCP, trim),
        ));
    }
    // MINIMAL-LENGTH buffers, one per arm. The padded cases below cannot see a
    // deleted revalidation: with slack after the header the walk lands inside
    // the buffer either way. Two of the four acceptance mutations are only
    // observable when the packet ENDS at or before the advance target.
    //
    // AH-only, 42 bytes: `[TCP, 3]` at offset 40 and nothing after. AH advances
    // (3+2)*4 = 20 to offset 60, which is past the 42-byte packet — so the
    // revalidation is the only thing standing between this and an L4 offset
    // outside the buffer.
    let mut ah_min = vec![0u8; 40];
    ah_min[0] = 0x60;
    ah_min[6] = AH;
    ah_min.extend_from_slice(&[TCP, 3]);
    cases.push(("AH(len=3) minimal 42-byte packet".into(), ah_min));
    // Fragment declared but truncated to two bytes: the arm must read all eight
    // before advancing.
    let mut frag_min = vec![0u8; 40];
    frag_min[0] = 0x60;
    frag_min[6] = FRAG;
    frag_min.extend_from_slice(&[TCP, 0]);
    cases.push(("Fragment truncated to 2 bytes".into(), frag_min));
    // Generic header whose declared length lands exactly at the packet end, and
    // one byte past it — the boundary the revalidation defends.
    for (name, total) in [("exactly at end", 48usize), ("one byte short", 47)] {
        let mut b = vec![0u8; 40];
        b[0] = 0x60;
        b[6] = DEST;
        b.extend_from_slice(&[TCP, 0]);
        b.resize(total, 0);
        cases.push((format!("DestOpt(len=0) buffer {name}"), b));
    }
    // NON-FIRST fragment: frag_off bits set, so the bytes after the Fragment
    // header are payload, not an L4 header. Both walkers resolve the same
    // offset; only the fragment state distinguishes them, which is precisely
    // what comparing `.outcome` alone discarded.
    for frag_off in [0x0008u16, 0x0010, 0x0100] {
        let mut b = vec![0u8; 40];
        b[0] = 0x60;
        b[6] = FRAG;
        b.extend_from_slice(&[TCP, 0]);
        b.extend_from_slice(&frag_off.to_be_bytes());
        b.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        b.extend_from_slice(&[0x11; 20]);
        cases.push((format!("NON-FIRST Fragment(frag_off={frag_off:#06x}) -> TCP"), b));
    }

    // BOUNDARY-EXACT cases: the packet ends exactly ONE BYTE SHORT of each
    // arm's advance target. A minimal-length packet proves the arm is
    // exercised; it does not prove it is exercised AT THE BOUNDARY, and a
    // realistic regression is a length computed one byte short, not a deleted
    // check. With the packet ending at `target - 1` the correct revalidation
    // (which demands `target`) fails while a `- 1` variant succeeds, so the two
    // produce different verdicts. The generic arm already had this shape — its
    // `one byte short` case is why a generic length-1 mutation reds — and these
    // copy it to AH and Fragment, which did not.
    //
    // AH: header at 40, HdrExtLen 3 -> advance (3+2)*4 = 20 -> target 60.
    // Packet length 59 is one byte short of that.
    {
        let mut b = vec![0u8; 40];
        b[0] = 0x60;
        b[6] = AH;
        b.extend_from_slice(&[TCP, 3]);
        b.resize(59, 0);
        cases.push(("AH(len=3) packet ends one byte short of target 60".into(), b));
    }
    // Fragment reads a fixed 8 bytes before advancing. A packet with exactly 7
    // bytes available at the header start separates an 8-byte read from a
    // 7-byte one: the former fails closed, the latter proceeds.
    {
        let mut b = vec![0u8; 40];
        b[0] = 0x60;
        b[6] = FRAG;
        b.resize(47, 0);
        b[40] = TCP;
        cases.push(("Fragment with exactly 7 bytes available".into(), b));
    }
    // And the same one-short shape for the generic arm at a larger declared
    // length, so the boundary is covered at more than one magnitude.
    {
        let mut b = vec![0u8; 40];
        b[0] = 0x60;
        b[6] = DEST;
        b.extend_from_slice(&[TCP, 5]);
        b.resize(87, 0); // target is 40 + (5+1)*8 = 88
        cases.push(("DestOpt(len=5) packet ends one byte short of target 88".into(), b));
    }

    // Fragment and AH have their own advance arithmetic.
    cases.push(("Fragment -> TCP".into(), chain(&[(FRAG, 0)], TCP, 0)));
    cases.push((
        "DestOpt + Fragment -> TCP".into(),
        chain(&[(DEST, 0), (FRAG, 0)], TCP, 0),
    ));
    for len in [0u8, 1, 3] {
        // AH advances (len+2)*4, which is NOT the generic size for most lens,
        // so build these buffers generously and let both walkers land where
        // they land.
        let mut buf = vec![0u8; 40];
        buf[0] = 0x60;
        buf[6] = AH;
        buf.extend_from_slice(&[TCP, len]);
        buf.extend_from_slice(&[0u8; 254]);
        cases.push((format!("AH(len={len}) -> TCP"), buf));
    }
    // #4517 types, and a terminal that must NOT be walked.
    cases.push((
        "Mobility -> TCP".into(),
        chain(&[(MOBILITY, 0)], TCP, 0),
    ));
    cases.push((
        "HbH + Mobility -> TCP".into(),
        chain(&[(HBH, 0), (MOBILITY, 0)], TCP, 0),
    ));
    // Every next-header value as the first header.
    for p in 0u16..=255 {
        cases.push((format!("first={p}"), chain(&[(p as u8, 0)], TCP, 0)));
    }

    // Vary the L3 offset. Every case above is built at offset 0, and a whole
    // class of base-offset error is invisible there — mutating a revalidation's
    // base from `l3_offset` to `0` changes nothing when they are equal. 14 is
    // untagged Ethernet and 18 is VLAN-tagged; those are the offsets that occur
    // in production, and `frame_l3_offset` returns exactly them.
    let mut expanded: Vec<(String, Vec<u8>, usize)> = Vec::new();
    for (name, buf) in &cases {
        for l3 in [0usize, 14, 18] {
            let mut b = vec![0u8; l3];
            b.extend_from_slice(buf);
            expanded.push((format!("{name} @l3={l3}"), b, l3));
        }
    }
    let cases = expanded;

    let mut drift: Vec<String> = Vec::new();
    for (name, buf, l3) in &cases {
        let (buf, l3) = (buf.as_slice(), *l3);
        let s = shim_record(buf, l3);
        let u = userspace_record(buf, l3);
        // The fragment fields govern one question: may this RESOLVED L4 seed a
        // session? So they are decision-relevant exactly when a terminal L4 was
        // resolved. On a fail-closed or over-limit verdict neither side is going
        // to build a session, and the two sides legitimately differ in how they
        // describe a chain they both refused: `walk_ipv6_ext_chain` records a
        // DECLARED-but-truncated Fragment header (`ExtChainFragment.bytes:
        // None`, preserving `ipv6_is_any_fragment`'s declares-match semantics),
        // while the shim's arm simply fails the 8-byte read and the whole walk
        // returns None. Comparing sighting state across a refusal would assert a
        // correspondence that does not exist and is not needed.
        //
        // PROVENANCE, because a narrowing looks identical to the bug it could
        // be. This scope was NOT reasoned to in advance. The naive full-record
        // comparison was written first, and it RED on
        // `Fragment truncated to 2 bytes`: userspace reported
        // `saw_fragment: true` from a declared-but-unreadable header while the
        // shim's 8-byte read failed and the walk returned None. Reading that
        // failure is what established the boundary — a conclusion from an
        // observed false positive, not an assumption baked in at design time.
        // Anyone auditing this should re-derive the compared-field list from
        // `ExtChainWalk` itself rather than from this comment, and treat a
        // field present in the type but absent here as the same defect class
        // that motivated widening the comparison in the first place.
        let mismatch = if matches!(s.verdict, Verdict::L4(..)) || matches!(u.verdict, Verdict::L4(..)) {
            s != u
        } else {
            s.verdict != u.verdict
        };
        if mismatch {
            drift.push(format!("{name}: shim={s:?} userspace={u:?}"));
        }
    }
    assert!(
        drift.is_empty(),
        "#4555 BEHAVIOURAL parity drift between the shim's executed IPv6 extension-header walk \
         and this crate's walk_ipv6_ext_chain, over {} chains. These are outcomes of running \
         both walkers on the same bytes, so a divergence here is a real packet-handling \
         difference: the shim would compute a session key from a different L4 offset (or accept \
         a chain the forwarding path refuses) and the flow would be mis-steered or dropped. \
         Divergences:\n  {}",
        cases.len(),
        drift.join("\n  ")
    );
}

/// NEGATIVE CONTROL for the behavioural corpus.
///
/// Every SHIM-side expectation here must be invariant under the mutations the
/// corpus defends against, or this is a co-signer rather than a control. An
/// earlier draft asserted that the shim resolves one minimum-size DestOpt at
/// offset 48 — which the `* 8` → `* 16` mutation changes to 56, so it went red
/// alongside the corpus and proved nothing about it. That assertion is now
/// userspace-only.
///
/// What is left on the shim side executes NO arm body at all:
///   - a chain with no extension headers never enters a `match` arm, so no
///     advance arithmetic, no revalidation and no loop-body statement applies;
///   - a buffer too short for the fixed 40-byte header fails closed before the
///     walk starts.
/// Both are fixed by RFC 8200 and unchanged by any mutation to the walk, so a
/// red here means the corpus harness or this crate's walker broke.
#[test]
fn shim_walk_corpus_negative_control() {
    const TCP: u8 = 6;
    const DEST: u8 = 60;
    // No extension headers: L4 sits immediately after the fixed 40-byte header.
    let plain = chain(&[], TCP, 0);
    assert_eq!(userspace_verdict(&plain, 0), Verdict::L4(40, TCP));
    assert_eq!(shim_verdict(&plain, 0), Verdict::L4(40, TCP));
    // A buffer too short for the fixed header fails closed on both sides.
    let stub = vec![0u8; 12];
    assert_eq!(userspace_verdict(&stub, 0), Verdict::FailClosed);
    assert_eq!(shim_verdict(&stub, 0), Verdict::FailClosed);
    // Userspace-only: asserting the shim's offset here would track the generic
    // advance and co-sign mutation 1.
    let one = chain(&[(DEST, 0)], TCP, 0);
    assert_eq!(userspace_verdict(&one, 0), Verdict::L4(48, TCP));
}
