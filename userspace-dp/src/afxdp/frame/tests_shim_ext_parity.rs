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
//
// PROVING THESE GUARDS FIRE: `test/mutation/shim-ext-parity-acceptance.sh`
// mutates `ipv6_ext_walk.rs` — each arm's advance arithmetic, each arm's
// post-advance revalidation (deleted, and weakened by one byte), the Fragment
// read length, the revalidation's L3 base, a statement inside the loop but
// outside the `match` — and requires the guards below to red on every one,
// plus a semantically null edit that must SURVIVE. It is not run by
// `make test` (each row is a full release rebuild); run it after changing
// either walker, or after narrowing anything the corpus compares. A guard is
// worth what its mutation matrix says it is worth.
#[path = "../../../../userspace-xdp/src/ipv6_ext_walk.rs"]
mod shim_walk;

/// A verdict both walkers can be reduced to, so they can be compared directly.
///
/// This is EXACTLY what the shim's walk returns, renormalised — nothing more.
/// A previous revision widened it to a `WalkRecord` carrying `saw_fragment` and
/// `non_first_fragment` as well, which the shim's walk does not produce; the
/// test supplied them by hand-writing a SECOND walk loop and re-deriving them
/// with the same expression `walk_ipv6_ext_chain` uses. Every comparison of
/// those two columns was therefore `X == X` — no edit to the shim could move
/// them, and the widened corpus stayed green on the exact non-first-fragment
/// input it was widened to catch. A wide fake comparison is worse than a narrow
/// honest one, because it manufactures the belief that a regression is covered.
///
/// So the corpus compares the shim's real output against this crate's real
/// outcome, and the fragment state the shim CANNOT represent is handled where
/// it belongs: `shim_is_not_more_permissive` states that gap explicitly, runs
/// both real walkers to demonstrate it, and pins every sub-field of
/// `ExtChainFragment` on the side that has one.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Verdict {
    /// Resolved a terminal upper-layer header at this offset.
    L4(usize, u8),
    /// No-Next-Header (59): a valid terminal with no L4.
    NoL4,
    /// Still on an extension header at the iteration bound.
    ///
    /// This names the SHIM's observable state, not a shim behaviour: the shim's
    /// walk does not fail closed on exhaustion, it returns the last declared
    /// extension-header protocol and `parse_l4`'s catch-all
    /// (`userspace-xdp/src/lib.rs`) then yields ports 0/0 so the session key
    /// misses and the packet is redirected. `walk_ipv6_ext_chain` returns
    /// `OverLimit` for the same chain. The two are folded to one label so the
    /// chain-length boundary is comparable; the fold is a renaming of two
    /// observed outputs, not a claim about what either does next.
    OverLimit,
    /// Truncated / declared length overran the packet / offset overflow.
    FailClosed,
}

/// The SHIM's walk, run on a live slice, returning EXACTLY what it returns.
///
/// `parse_ipv6` calls it with the frame's `data`/`data_end` and the L3 offset
/// `parse_l2` computed; here the slice supplies its own bounds. The `(u16, u8)`
/// is the whole of the shim's extension-header state — there is no fragment
/// sighting, no offset bits, no M flag, because nothing downstream of it in the
/// shim consumes any.
fn raw_shim_walk(buf: &[u8], l3: usize) -> Option<(u16, u8)> {
    if buf.len() < l3 + 40 {
        return None;
    }
    let data = buf.as_ptr() as usize;
    let data_end = data + buf.len();
    shim_walk::walk_ipv6_ext_headers(data, data_end, l3 as u16, buf[l3 + 6], (l3 + 40) as u16)
}

/// Run the SHIM's walk on `buf` exactly as `parse_ipv6` does, as a `Verdict`.
fn shim_verdict(buf: &[u8], l3: usize) -> Verdict {
    match raw_shim_walk(buf, l3) {
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

/// The L3 offsets the SHIM actually produces.
///
/// `parse_l2` (`userspace-xdp/src/lib.rs`) returns `size_of::<EthHdr>()` = 14
/// for untagged Ethernet, or 18 when an 802.1Q/802.1ad tag is present, and
/// `parse_ipv6` passes that value straight into `walk_ipv6_ext_headers` as
/// `l3_offset`; this crate's `frame_l3_offset` returns exactly the same two.
/// A corpus that only ever walks at `l3 = 0` cannot see the `l3_offset` term
/// in either arm's post-advance revalidation — replacing the base
/// `l3_offset as usize` with `0usize` is bit-identical at 0 and a fail-open of
/// exactly `l3` bytes at 14 and 18. 0 is kept because `walk_ipv6_ext_chain`'s
/// other callers pass an L3-relative slice.
const L3_OFFSETS: [usize; 3] = [0, 14, 18];

/// Prefix an L3-relative buffer with `l3` bytes of L2, so one corpus case can
/// be walked at every L3 offset the shim produces. Neither walker parses these
/// bytes — both take the L3 offset as a parameter — but a plausible header
/// keeps a failure dump readable.
fn at_l3(buf: &[u8], l3: usize) -> Vec<u8> {
    let mut out = vec![0u8; l3];
    if l3 == 14 {
        out[12] = 0x86;
        out[13] = 0xDD; // ETH_P_IPV6
    } else if l3 == 18 {
        out[12] = 0x81;
        out[13] = 0x00; // ETH_P_8021Q
        out[16] = 0x86;
        out[17] = 0xDD;
    }
    out.extend_from_slice(buf);
    out
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

/// The corpus of L3-relative chains both walkers are run over.
///
/// Shared by `shim_walk_and_userspace_walk_agree_over_a_corpus` and
/// `shim_is_not_more_permissive` so the two cannot drift apart. Each buffer
/// starts at the IPv6 fixed header; `at_l3` prefixes it for the non-zero L3
/// offsets.
fn parity_corpus() -> Vec<(String, Vec<u8>)> {
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
    // EXACT-BOUNDARY pairs, ONE PER ARM. The rule is the arm's own
    // (`ipv6_ext_walk.rs`): a case can observe a weakened revalidation only when
    // the packet ENDS at or before the advance target. "Exactly at end" must
    // resolve and "one byte short" must fail closed, so any relaxation of the
    // bounds check by even one byte flips the short case and reds this corpus.
    //
    // Having the pair on the GENERIC arm alone was not enough: an off-by-one in
    // the AUTH revalidation, and a Fragment read shortened 8 -> 7, both survived
    // the whole corpus while the identical off-by-one in the generic arm red.
    // The shortest AUTH case left 18 bytes of slack and the shortest FRAGMENT
    // case 6, so neither arm's bound was ever the thing under test. Each of the
    // three below is a genuine fail-open when weakened: a 47-byte buffer goes
    // from `None` to `Some((48, TCP))`, an L4 offset one byte past the packet.
    //
    //   GENERIC  DestOpt(len=0) at 40 advances (0+1)*8 -> 48
    //   AUTH     AH(len=0)      at 40 advances (0+2)*4 -> 48   (RFC 4302)
    //   FRAGMENT Fragment       at 40 reads all 8 bytes -> 48  (RFC 8200 §4.5)
    //
    // All three land on 48, so the pair is (48, 47) for every arm.
    for (arm, first) in [("DestOpt(len=0)", DEST), ("AH(len=0)", AH), ("Fragment", FRAG)] {
        for (name, total) in [("exactly at end", 48usize), ("one byte short", 47)] {
            let mut b = vec![0u8; 40];
            b[0] = 0x60;
            b[6] = first;
            b.extend_from_slice(&[TCP, 0]);
            b.resize(total, 0);
            cases.push((format!("{arm} buffer {name}"), b));
        }
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
    // These sit at a DIFFERENT magnitude from the (48, 47) pairs above, on
    // purpose: the pairs put every arm's boundary at the same target, so an
    // error that scales with the declared length (rather than being a constant
    // off-by-one) could hide in the coincidence. HdrExtLen 3 and 5 move the
    // target to 60 and 88.
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

    cases
}

/// The load-bearing behavioural guard: over a corpus of real chains, at every
/// L3 offset the shim produces, the shim's executed walk and this crate's
/// walker must reach the SAME verdict.
///
/// This is what replaces the deleted source models. It reds on an altered
/// advance (the offsets diverge), on a deleted or weakened bounds revalidation
/// in ANY of the three arms (a truncated chain resolves instead of failing
/// closed), on a statement added inside the loop but outside the `match` (the
/// chain length diverges), on a changed walked type set (a type resolves on one
/// side and terminates on the other), and on a revalidation whose base offset
/// stops accounting for the L3 offset (invisible at `l3 = 0`, a fail-open of
/// `l3` bytes at the 14 and 18 the shim actually passes).
///
/// What it does NOT compare is stated, not implied: the shim's walk returns
/// `(offset, protocol)` and no fragment state, so there is nothing on the shim
/// side to compare `ExtChainWalk::fragment` or `non_first_fragment_offset_seen`
/// against. `shim_is_not_more_permissive` covers that dimension explicitly.
/// Derive the compared-field list from `Verdict` and from the shim's own return
/// type rather than from this comment; a field the shim DOES produce that is
/// absent here is the defect class this file exists to close.
#[test]
fn shim_walk_and_userspace_walk_agree_over_a_corpus() {
    let cases = parity_corpus();
    let mut drift: Vec<String> = Vec::new();
    let mut compared = 0usize;
    for l3 in L3_OFFSETS {
        for (name, base) in &cases {
            let buf = at_l3(base, l3);
            let s = shim_verdict(&buf, l3);
            let u = userspace_verdict(&buf, l3);
            compared += 1;
            if s != u {
                drift.push(format!("[l3={l3}] {name}: shim={s:?} userspace={u:?}"));
            }
        }
    }
    assert_eq!(
        compared,
        cases.len() * L3_OFFSETS.len(),
        "the #4555 corpus loop did not run every case at every L3 offset"
    );
    assert!(
        drift.is_empty(),
        "#4555 BEHAVIOURAL parity drift between the shim's executed IPv6 extension-header walk \
         and this crate's walk_ipv6_ext_chain, over {compared} chain/L3 pairs. These are outcomes \
         of running both walkers on the same bytes, so a divergence here is a real \
         packet-handling difference: the shim would compute a session key from a different L4 \
         offset (or accept a chain the forwarding path refuses) and the flow would be mis-steered \
         or dropped. Divergences:\n  {}",
        drift.join("\n  ")
    );
}

/// The KNOWN, UNCLOSED non-parity, stated rather than papered over — the
/// assertion the file has cited by name since #4555 round 5 without ever
/// containing it.
///
/// `walk_ipv6_ext_chain` returns an `ExtChainWalk`: outcome, PLUS the first
/// `ExtChainFragment` sighting (its 8 raw bytes, or `None` when the buffer
/// truncated them), PLUS `non_first_fragment_offset_seen`. Every one of those
/// is consumed — `ipv6_is_any_fragment` matches on the DECLARATION,
/// `ipv6_is_non_first_fragment` fails closed on unreadable bytes and refuses a
/// non-first fragment's payload as an L4 header, and the NAT64 path reads the
/// offset, the M flag and the 32-bit identification.
///
/// `walk_ipv6_ext_headers` returns `(offset, protocol)`. That is all of it.
///
/// A previous revision "closed" this by hand-writing a second walk loop inside
/// the test and re-deriving the two fragment columns with the same expression
/// `walk_ipv6_ext_chain` uses, then comparing the results. `X == X`: the
/// widened corpus stayed green on the very non-first-fragment input it was
/// widened to catch, and no shim-side edit could have moved either column. This
/// test replaces that with three things that are all measured by RUNNING both
/// real walkers:
///
///   1. the shim IS blind — two chains differing only in the Fragment header's
///      offset/M/identification bytes give the same shim result;
///   2. this crate is NOT — the same two chains give different `ExtChainWalk`s,
///      with every sub-field of `ExtChainFragment` pinned;
///   3. in the dimension the shim does represent, it is not more permissive:
///      over the whole corpus, at every L3 offset, a chain the shim resolves to
///      an L4 is resolved by this crate to the SAME L4.
///
/// NOT A SAFETY CLAIM, and NOT CLOSED — tracked as #6704, pre-existing and not
/// introduced by #4555. On `IPv6 || Fragment(frag_off != 0, next = TCP)` the
/// shim resolves `L4(48, TCP)` and hands offset 48 to `parse_l4`
/// (`userspace-xdp/src/lib.rs`), which reads the fragment PAYLOAD as a TCP
/// header — `sport = be16(b[48..50])`, `dport = be16(b[50..52])`,
/// `data_offset = (b[60] >> 4) * 4`. This crate refuses those bytes everywhere.
/// The shim's lookup can only HIT a session userspace INSTALLED, and userspace
/// never installs one from a non-first fragment; the residual risk is a
/// synthesised 5-tuple COINCIDING with a legitimate session, which then takes
/// that session's fast path with no policy evaluation of its own. This test
/// PINS the asymmetry so it cannot change unnoticed; it does not assert the
/// asymmetry is harmless. Closing it means making the shim's walk carry the
/// sighting — a shim change, `make generate`, and the #1864 verifier gate.
#[test]
fn shim_is_not_more_permissive() {
    const TCP: u8 = 6;
    const FRAG: u8 = 44;

    // `IPv6 || Fragment(next=TCP, frag_off, ident) || 20 payload bytes`.
    // Byte 60 is the payload byte `parse_l4` would read as the TCP data offset,
    // set so the shim's TCP parse ACCEPTS these payload bytes as a header.
    let frag_chain = |frag_off: u16, ident: u32| -> Vec<u8> {
        let mut b = vec![0u8; 40];
        b[0] = 0x60;
        b[6] = FRAG;
        b.extend_from_slice(&[TCP, 0]);
        b.extend_from_slice(&frag_off.to_be_bytes());
        b.extend_from_slice(&ident.to_be_bytes());
        b.extend_from_slice(&[0x11; 20]);
        b[48] = 0x04;
        b[49] = 0xD2; // "source port" 1234, chosen by the sender
        b[60] = 0x50; // data offset 5 words = 20 bytes, so parse_l4 accepts
        b
    };
    // frag_off bytes are the 13-bit offset in the top bits, then two reserved
    // bits, then M (RFC 8200 §4.5): 0x0001 is a FIRST fragment with more to
    // come; 0x0008 is fragment offset 1 — a NON-FIRST fragment.
    let first = frag_chain(0x0001, 0xDEAD_BEEF);
    let non_first = frag_chain(0x0008, 0x0BAD_F00D);

    // 1. The shim is blind, MEASURED by running it — not inferred from its
    //    signature and not restated by a copy of its loop.
    let shim_first = raw_shim_walk(&first, 0);
    let shim_non_first = raw_shim_walk(&non_first, 0);
    assert_eq!(
        shim_first, shim_non_first,
        "#4555: the shim's walk distinguished a first from a non-first fragment. That is the \
         asymmetry this test exists to record as ABSENT — if the shim now carries fragment state, \
         the corpus in shim_walk_and_userspace_walk_agree_over_a_corpus must compare it and this \
         test must be rewritten, not deleted."
    );
    assert_eq!(
        shim_non_first,
        Some((48u16, TCP)),
        "#4555: the shim resolved something other than L4(48, TCP) on a non-first fragment; the \
         documented divergence below is stated against that exact outcome"
    );
    // The bytes the shim's parse_l4 would read as a TCP source port at offset
    // 48 are fragment payload the sender chose, not a header.
    assert_eq!(
        u16::from_be_bytes([non_first[48], non_first[49]]),
        1234,
        "#4555: the L4 offset the shim resolved does not point at the payload bytes this case \
         planted, so the divergence below is being demonstrated on the wrong bytes"
    );

    // 2. This crate is not blind, and every sub-field of `ExtChainFragment` is
    //    pinned — the readable/unreadable discriminant, the 13-bit offset, the
    //    M flag and the 32-bit identification. `.is_some()` alone (what the
    //    previous revision compared) collapses all of it to one bit.
    let uf = walk_ipv6_ext_chain(&first, 0);
    let un = walk_ipv6_ext_chain(&non_first, 0);
    assert_ne!(
        uf, un,
        "#4555: walk_ipv6_ext_chain stopped distinguishing a first from a non-first fragment; the \
         NAT64 and embedded-ICMP consumers depend on that distinction"
    );
    assert_eq!(
        uf.fragment.and_then(|f| f.bytes),
        Some([TCP, 0, 0x00, 0x01, 0xDE, 0xAD, 0xBE, 0xEF]),
        "#4555: the recorded first-fragment bytes changed (next/reserved/offset+M/identification)"
    );
    assert_eq!(
        un.fragment.and_then(|f| f.bytes),
        Some([TCP, 0, 0x00, 0x08, 0x0B, 0xAD, 0xF0, 0x0D]),
        "#4555: the recorded non-first-fragment bytes changed"
    );
    assert!(!uf.non_first_fragment_offset_seen);
    assert!(un.non_first_fragment_offset_seen);
    assert!(!ipv6_is_non_first_fragment(&first));
    assert!(
        ipv6_is_non_first_fragment(&non_first),
        "#4555: this crate stopped refusing a non-first fragment's payload as an L4 header, which \
         is the ONLY thing standing between the shim's L4(48, TCP) and the forwarding path"
    );

    // The readable/unreadable discriminant, on a DECLARED-but-truncated header.
    // This is where the two sides legitimately describe a refusal differently:
    // this crate records the declaration with `bytes: None` (so
    // `ipv6_is_any_fragment` still matches, pre-#6435 semantics) while the
    // shim's 8-byte read fails and the whole walk returns None. Both refuse; the
    // corpus compares the refusal, this pins the description.
    let mut truncated = vec![0u8; 40];
    truncated[0] = 0x60;
    truncated[6] = FRAG;
    truncated.extend_from_slice(&[TCP, 0]);
    let ut = walk_ipv6_ext_chain(&truncated, 0);
    assert_eq!(
        ut.fragment.map(|f| f.bytes),
        Some(None),
        "#4555: a declared-but-truncated Fragment header must be RECORDED with unreadable bytes"
    );
    assert!(ipv6_is_any_fragment(&truncated));
    assert!(!ipv6_is_non_first_fragment(&truncated));
    assert_eq!(
        raw_shim_walk(&truncated, 0),
        None,
        "#4555: the shim must fail its 8-byte Fragment read rather than advance past a truncated \
         header"
    );

    // 3. In the dimension the shim DOES represent, it is not more permissive.
    //    The corpus asserts equality in both directions; this states the
    //    security direction on its own, because that is the half a future
    //    narrowing of the corpus would have to preserve.
    let cases = parity_corpus();
    let mut permissive: Vec<String> = Vec::new();
    for l3 in L3_OFFSETS {
        for (name, base) in &cases {
            let buf = at_l3(base, l3);
            if let Verdict::L4(off, proto) = shim_verdict(&buf, l3) {
                let u = userspace_verdict(&buf, l3);
                if u != Verdict::L4(off, proto) {
                    permissive.push(format!(
                        "[l3={l3}] {name}: shim resolved L4({off}, {proto}) but this crate says \
                         {u:?}"
                    ));
                }
            }
        }
    }
    assert!(
        permissive.is_empty(),
        "#4555: the shim resolved an L4 the forwarding path does not, on {} of {} chain/L3 pairs. \
         The shim would build a session key for a packet userspace refuses to forward the same \
         way. Cases:\n  {}",
        permissive.len(),
        cases.len() * L3_OFFSETS.len(),
        permissive.join("\n  ")
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
