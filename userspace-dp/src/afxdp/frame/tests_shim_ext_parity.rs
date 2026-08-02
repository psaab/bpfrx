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
use std::collections::{BTreeSet, HashSet};
use std::path::{Path, PathBuf};

// IPv6 next-header values used throughout this file. TCP is the terminal
// every probe and corpus chain ends on.
const TCP: u8 = 6;
const HBH: u8 = 0;
const AH: u8 = 51;
const FRAG: u8 = 44;
const DEST: u8 = 60;
const MOBILITY: u8 = 135;

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
    buf[40] = TCP;
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
        ExtChainOutcome::L4(56, TCP) => EH_CLASS_GENERIC,
        ExtChainOutcome::L4(52, TCP) => EH_CLASS_AUTH,
        ExtChainOutcome::L4(48, TCP) => {
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
    let mut buf = vec![0u8; 96];
    buf[0] = 0x60;
    buf[6] = FRAG;
    buf[40] = TCP;
    match walk_ipv6_ext_chain(&buf, 0).outcome {
        ExtChainOutcome::L4(off, TCP) => off - 40,
        other => panic!("the userspace fragment probe no longer resolves to TCP ({other:?})"),
    }
}

/// Build `n` chained 8-byte DestOpt headers terminated by TCP and report
/// whether this crate's walker resolves the terminal.
fn userspace_resolves_chain_of(n: usize) -> bool {
    let mut buf = vec![0u8; 40 + 8 * n + 20];
    buf[0] = 0x60;
    buf[6] = if n == 0 { TCP } else { DEST };
    for i in 0..n {
        let at = 40 + 8 * i;
        buf[at] = if i + 1 == n { TCP } else { DEST };
    }
    matches!(
        walk_ipv6_ext_chain(&buf, 0).outcome,
        ExtChainOutcome::L4(off, TCP) if off == 40 + 8 * n
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
///
/// Floor 5 in `parity_corpus` MEASURES the two non-zero values, by asking
/// `frame_l3_offset` where L3 starts in the prefixes `at_l3` builds. It cannot
/// measure `parse_l2`: that function is in the aya crate and does not link
/// here. That the two agree on 14/18 is the documented claim above, and is the
/// one thing in this file still asserted rather than run.
const L3_OFFSETS: [usize; 3] = [0, 14, 18];

/// One arm's boundary WITNESS PAIR, DECLARED here and VERIFIED by floor 1.
///
/// The pair is `(padded, tight)`: the same single-extension-header packet, cut
/// to exactly `target` bytes and to `target - 1`. Floor 1 requires this crate's
/// walker to resolve the terminal at exactly `target` on the padded twin and to
/// fail closed on the tight one.
///
/// That pairing is the whole point. "Fails closed" ALONE is a proxy: a 40-byte
/// packet declaring an arm also fails closed, at the arm's INITIAL two-byte
/// read, having never reached the advance or the post-advance revalidation —
/// so a corpus of such stubs satisfies a fail-closed count while every
/// boundary case has been deleted. The padded twin resolving AT `target` is
/// what proves the arm ran its advance and landed there; the tight twin then
/// attributes the refusal to the length check, because the two differ by one
/// trailing byte and nothing else.
struct ArmBoundary {
    /// Label used in floor 1's messages and in the corpus case names.
    arm: &'static str,
    /// Class `proto` must MEASURE as, via `userspace_class`. An entry that
    /// files a header under the wrong arm reds rather than mislabelling the
    /// coverage.
    class: u8,
    /// The single extension header the witness declares at offset 40.
    proto: u8,
    /// The header's second byte: HdrExtLen for GENERIC/AUTH, the Fragment
    /// header's `reserved` byte (which neither walker reads) for FRAGMENT.
    hdr_len: u8,
    /// L3-relative offset the arm advances to. NOT a model of the arithmetic:
    /// floor 1 runs `walk_ipv6_ext_chain` on the padded twin and requires the
    /// terminal at exactly this offset, so a wrong value here reds instead of
    /// quietly re-describing the advance this file exists to stop describing.
    target: usize,
}

/// GENERIC advances `(HdrExtLen + 1) * 8`, AUTH `(HdrExtLen + 2) * 4`
/// (RFC 4302), FRAGMENT reads and advances a fixed 8 (RFC 8200 §4.5).
///
/// Two DISTINCT declared lengths for the two length-parameterised arms, one
/// witness for the constant one — derived, not chosen. An arithmetic error in
/// a length-parameterised arm is some `f'(l) = f(l) + a*l + b`; it is invisible
/// at a declared length where `a*l + b == 0`, and an affine expression that
/// vanishes at two distinct `l` is identically zero. So two distinct
/// `hdr_len` values are necessary and sufficient to exclude that whole family,
/// and floor 1 counts DISTINCT lengths rather than cases — two byte-identical
/// witnesses are one magnitude, which is what the previous per-arm count
/// missed. FRAGMENT's read and advance take no declared length, so its error
/// family is the constant `f' = f + b` and one witness excludes it; a second
/// would be decoration.
const ARM_BOUNDARIES: &[ArmBoundary] = &[
    ArmBoundary {
        arm: "GENERIC",
        class: EH_CLASS_GENERIC,
        proto: DEST,
        hdr_len: 0,
        target: 48,
    },
    ArmBoundary {
        arm: "GENERIC",
        class: EH_CLASS_GENERIC,
        proto: DEST,
        hdr_len: 5,
        target: 88,
    },
    ArmBoundary {
        arm: "AUTH",
        class: EH_CLASS_AUTH,
        proto: AH,
        hdr_len: 0,
        target: 48,
    },
    ArmBoundary {
        arm: "AUTH",
        class: EH_CLASS_AUTH,
        proto: AH,
        hdr_len: 3,
        target: 60,
    },
    ArmBoundary {
        arm: "FRAGMENT",
        class: EH_CLASS_FRAGMENT,
        proto: FRAG,
        hdr_len: 0,
        target: 48,
    },
];

/// `IPv6 || (proto, hdr_len) || zeroes`, cut to exactly `total` bytes.
///
/// The declared next header is TCP, so a walk that reaches the advance target
/// resolves a TCP terminal there.
fn boundary_case(proto: u8, hdr_len: u8, total: usize) -> Vec<u8> {
    let mut b = vec![0u8; 40];
    b[0] = 0x60;
    b[6] = proto;
    b.extend_from_slice(&[TCP, hdr_len]);
    b.resize(total, 0);
    b
}

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
    // BOUNDARY WITNESS PAIRS, from `ARM_BOUNDARIES`. Each entry contributes the
    // same packet cut to exactly its advance target and to one byte short of
    // it. The rule is the arm's own (`ipv6_ext_walk.rs`): a case can observe a
    // weakened revalidation only when the packet ENDS at or before the advance
    // target, because with slack after the header the walk lands inside the
    // buffer either way.
    //
    // Having the pair on the GENERIC arm alone was not enough: an off-by-one in
    // the AUTH revalidation, and a Fragment read shortened 8 -> 7, both survived
    // the whole corpus while the identical off-by-one in the generic arm red.
    // The shortest AUTH case left 18 bytes of slack and the shortest FRAGMENT
    // case 6, so neither arm's bound was ever the thing under test. Each tight
    // twin is a genuine fail-open when the bound is weakened: a 47-byte buffer
    // goes from `None` to `Some((48, TCP))`, an L4 offset one byte past the
    // packet.
    //
    // Floor 1 verifies the pair semantics — padded resolves AT `target`, tight
    // fails closed — so these are the corpus's boundary coverage AND its own
    // evidence of being boundary coverage.
    for w in ARM_BOUNDARIES {
        for (name, total) in [
            ("exactly at target", w.target),
            ("one byte short of target", w.target - 1),
        ] {
            cases.push((
                format!(
                    "{} proto={} hdr_len={} buffer {name} {}",
                    w.arm, w.proto, w.hdr_len, w.target
                ),
                boundary_case(w.proto, w.hdr_len, total),
            ));
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
    // Every next-header value as the first header, one minimum-size header in
    // a 68-byte buffer.
    for p in 0u16..=255 {
        cases.push((format!("first={p}"), chain(&[(p as u8, 0)], TCP, 0)));
    }

    // --- NON-VACUITY FLOORS -------------------------------------------------
    //
    // Every assertion that CONSUMES this corpus is of the form "this collection
    // is empty" or "this count equals cases.len() * L3_OFFSETS.len()", and BOTH
    // hold trivially when the corpus is empty: an empty drift list is empty, an
    // empty permissive list is empty, and `0 == 0 * 3`. Emptying this function
    // was measured to leave all five tests reporting `ok` in 0.00s.
    //
    // Two earlier rounds of floors stood here and both were PROXIES.
    //
    //   Round 5 was a single `cases.len() >= 200` whose message promised that no
    //   assertion in the file could pass vacuously. The 256-entry sweep above
    //   clears 200 by itself with 56 to spare, so cutting the corpus down to
    //   that sweep AND deleting the generic arm's post-advance revalidation —
    //   the security property — was measured to leave all five tests `ok`.
    //
    //   Round 6 replaced it with five floors "each binding one shape". Three of
    //   them bound CORRELATES of their shape rather than the shape: per-arm
    //   coverage counted `b[6] == arm && fails_closed`, which a 40-byte packet
    //   satisfies by failing the arm's INITIAL read having never reached the
    //   boundary (and which two byte-identical 47-byte Fragment cases satisfied
    //   twice over, so the "more than one magnitude" claim was unbound); the
    //   chain-length floor counted a terminal OFFSET, which one `DestOpt(len=6)`
    //   header reaches; and the next-header floor read `b[6]` off buffers that
    //   need not be walked at all, which 256 seven-byte stubs satisfy. One
    //   corpus edit defeating all three while all five floors passed was
    //   measured, again with the generic revalidation deleted.
    //
    // So each floor below binds its shape by CONSTRUCTION (the corpus must
    // contain a locally rebuilt reference buffer, byte for byte) and, where the
    // shape is behavioural, by MEASUREMENT with this crate's walker. A count of
    // cases satisfying a predicate is exactly what kept failing; a named buffer
    // that must be present, and must behave as claimed, does not have a
    // degenerate satisfier.
    //
    // None of them claims the corpus is ADEQUATE: adequacy is not a property of
    // a floor, it is what `test/mutation/shim-ext-parity-acceptance.sh` measures
    // by mutating the shim and requiring each guard to red. These floors exist
    // to stop a shape being DELETED between acceptance runs.
    //
    // All of them read only the corpus bytes and this crate's walker. Nothing
    // here touches the shim, so no mutation the acceptance matrix applies can
    // move a floor — a floor red is always a corpus defect, never a shim
    // finding. Neither negative-control test calls this function, so a floor red
    // leaves both CONTROL columns `ok` and the harness's attributability rule
    // intact.
    let present: HashSet<&[u8]> = cases.iter().map(|(_, b)| b.as_slice()).collect();
    let contains = |b: &[u8]| present.contains(b);

    // 1. PER-ARM BOUNDARY WITNESS PAIRS.
    //
    //    For every `ARM_BOUNDARIES` entry the corpus must contain BOTH twins,
    //    and the pair must behave as a boundary witness:
    //      - the PADDED twin (exactly `target` bytes) resolves the terminal at
    //        exactly `target`, which can only happen if the arm ran its advance
    //        and landed there — this is what proves the boundary was REACHED;
    //      - the TIGHT twin (one byte shorter, identical otherwise) fails
    //        closed, which attributes the refusal to the length check at
    //        `target` rather than to an earlier read.
    //    Neither half alone is the property. Round 6 asserted only the
    //    fail-closed half, and a 40-byte packet declaring the arm satisfies that
    //    while failing the arm's first two-byte read.
    //
    //    Binds: per arm, that boundary coverage exists at >= `want` DISTINCT
    //    declared lengths (see `ARM_BOUNDARIES` for why 2/2/1 is derived rather
    //    than chosen), that the corpus still carries those exact buffers, and
    //    that the header each entry names really is classified into the arm it
    //    claims.
    //    Does NOT bind: boundary coverage of an arm reached as a LATER header in
    //    a multi-header chain — every witness here is a single-header packet, so
    //    an arm's bound is exercised only at offset 40 (plus the L3 prefix).
    //    Does NOT bind: any non-boundary shape (truncation, non-first fragment,
    //    over-long declared lengths); those are separate cases above, and only
    //    the acceptance matrix measures whether they are pulling their weight.
    for w in ARM_BOUNDARIES {
        let padded = boundary_case(w.proto, w.hdr_len, w.target);
        let tight = boundary_case(w.proto, w.hdr_len, w.target - 1);
        assert_eq!(
            userspace_class(w.proto),
            w.class,
            "#4555 corpus floor 1: ARM_BOUNDARIES files next-header {} under the {} arm, but this \
             crate classifies it as {}. The witness would report coverage of an arm it does not \
             exercise.",
            w.proto,
            w.arm,
            class_name(userspace_class(w.proto)),
        );
        assert_eq!(
            userspace_verdict(&padded, 0),
            Verdict::L4(w.target, TCP),
            "#4555 corpus floor 1: the {} witness (proto={}, hdr_len={}) does not resolve a \
             terminal at its declared advance target {} when the packet ends exactly there — it \
             gives {:?}. Either the target is wrong or the arm is not reached, and in both cases \
             the tight twin's fail-closed proves nothing about this arm's boundary.",
            w.arm,
            w.proto,
            w.hdr_len,
            w.target,
            userspace_verdict(&padded, 0),
        );
        assert_eq!(
            userspace_verdict(&tight, 0),
            Verdict::FailClosed,
            "#4555 corpus floor 1: the {} witness (proto={}, hdr_len={}) still resolves with the \
             packet one byte short of target {}. The pair no longer isolates the post-advance \
             length check to a single byte.",
            w.arm,
            w.proto,
            w.hdr_len,
            w.target,
        );
        assert!(
            contains(&padded) && contains(&tight),
            "#4555 corpus floor 1: the {} boundary witness pair (proto={}, hdr_len={}, target={}) \
             is no longer in the corpus. Only a packet ENDING at or before an arm's advance target \
             can observe a deleted or one-byte-weakened post-advance revalidation in that arm; a \
             padded case lands inside the buffer with or without the check.",
            w.arm,
            w.proto,
            w.hdr_len,
            w.target,
        );
    }
    for (arm, want) in [("GENERIC", 2usize), ("AUTH", 2), ("FRAGMENT", 1)] {
        let lens: BTreeSet<u8> = ARM_BOUNDARIES
            .iter()
            .filter(|w| w.arm == arm)
            .map(|w| w.hdr_len)
            .collect();
        assert!(
            lens.len() >= want,
            "#4555 corpus floor 1: the {arm} arm has boundary witnesses at only {} distinct \
             declared length(s) {lens:?}, want >= {want}. An arithmetic error of the form \
             `f(l) + a*l + b` is invisible wherever `a*l + b == 0`, so one magnitude cannot \
             exclude it; two distinct lengths can, because an affine expression vanishing at two \
             points is identically zero. Adding a SECOND witness at the SAME declared length does \
             not help, which is why this counts distinct lengths and not cases.",
            lens.len(),
        );
    }

    // 2. THE RESOLVABLE-CHAIN-LENGTH BOUNDARY IS STRADDLED, BY CONSTRUCTION.
    //    `shim_ipv6_ext_walk_matches_userspace_walker` argues the shim's
    //    `MAX_EXT_HDRS == MAX_IPV6_EXT_HEADERS - 1` relation rather than
    //    asserting numeric equality, and cites THIS corpus as what measures the
    //    exit semantics the argument rests on. That citation is only true while
    //    the corpus contains a chain of exactly the longest resolvable NUMBER OF
    //    HEADERS and one header more.
    //
    //    Counting header-count-by-terminal-offset was the round-6 defect: a
    //    single `DestOpt(len=6)` header also lands on `40 + 8 * (MAX - 1)`, so
    //    every seven-header case could be deleted while the floor reported a
    //    seven-header chain present. The two chains are therefore rebuilt here
    //    and required by byte identity, and their verdicts are measured so the
    //    boundary is observed rather than assumed.
    //    Does NOT bind: the intermediate lengths, nor chains built from
    //    non-minimum-size or non-DestOpt headers.
    let at_max_hdrs = MAX_IPV6_EXT_HEADERS - 1;
    let at_max = chain(&vec![(DEST, 0); at_max_hdrs], TCP, 0);
    let over = chain(&vec![(DEST, 0); at_max_hdrs + 1], TCP, 0);
    assert!(
        contains(&at_max) && contains(&over),
        "#4555 corpus floor 2: the corpus no longer contains BOTH the chain of exactly \
         {at_max_hdrs} minimum-size DestOpt headers (the longest this crate resolves) and the \
         chain of {} (the first it refuses). Without the pair, nothing here measures where either \
         walker stops, and the MAX_EXT_HDRS == MAX_IPV6_EXT_HEADERS - 1 relation asserted in \
         shim_ipv6_ext_walk_matches_userspace_walker is argued from a comment rather than \
         observed.",
        at_max_hdrs + 1,
    );
    assert_eq!(
        userspace_verdict(&at_max, 0),
        Verdict::L4(40 + 8 * at_max_hdrs, TCP),
        "#4555 corpus floor 2: this crate no longer resolves a chain of {at_max_hdrs} minimum-size \
         extension headers, so the corpus does not straddle the boundary it claims to"
    );
    assert_eq!(
        userspace_verdict(&over, 0),
        Verdict::OverLimit,
        "#4555 corpus floor 2: this crate no longer refuses a chain of {} minimum-size extension \
         headers; the over-limit side of the boundary is not in the corpus",
        at_max_hdrs + 1,
    );

    // 3. EVERY NEXT-HEADER VALUE IS PRESENTED AS A WALKED FIRST HEADER.
    //    The behavioural walked-type-set comparison — which values one walker
    //    steps THROUGH and the other treats as terminal — exists only where the
    //    corpus supplies that value in a buffer both walkers actually walk.
    //    (`shim_ipv6_ext_walk_matches_userspace_walker` covers all 256 against
    //    the EMITTED table, but that is the manifest's classification, not the
    //    executed walk's.)
    //
    //    Round 6 read `b[6]` off every case, which 256 seven-byte buffers
    //    satisfy — both walkers reject those before reading the fixed IPv6
    //    header, so no classifier ever runs. Here the canonical 68-byte case is
    //    rebuilt for each value and required by byte identity, and each is
    //    required NOT to fail closed, which is the direct statement that the
    //    walk got far enough to classify the value.
    //    Does NOT bind: that each value is presented in more than one position;
    //    only the first-header position is swept, at one declared length.
    let mut missing: Vec<u16> = Vec::new();
    let mut unwalked: Vec<u16> = Vec::new();
    for p in 0u16..=255 {
        let want = chain(&[(p as u8, 0)], TCP, 0);
        if !contains(&want) {
            missing.push(p);
        } else if userspace_verdict(&want, 0) == Verdict::FailClosed {
            unwalked.push(p);
        }
    }
    assert!(
        missing.is_empty() && unwalked.is_empty(),
        "#4555 corpus floor 3: {} of 256 next-header values have no canonical single-header case \
         ({missing:?}) and {} are present but fail closed before classification ({unwalked:?}). \
         The executed walked-type-set comparison is blind to both.",
        missing.len(),
        unwalked.len(),
    );

    // 4. A CHAIN WHOSE WALK REACHES LARGE INTERMEDIATE OFFSETS.
    //    A statement added inside the walk loop but OUTSIDE the `match` (leak
    //    #3, and acceptance row 10) perturbs nothing on a short chain: the
    //    concrete mutation is `if offset > 200 { break; }`, invisible until the
    //    walk is still on an extension header past that offset. Only a chain of
    //    several maximum-declared-length headers gets there.
    //    Binds: those two chains are still in the corpus.
    //    Does NOT bind: any particular offset threshold — the shape is "a
    //    multi-header chain that walks a long way", and a mutation guarded at a
    //    higher offset than these chains reach would survive. That is what the
    //    acceptance matrix measures, not this floor.
    for n in [3usize, 5] {
        let long = chain(&vec![(DEST, 15); n], TCP, 0);
        assert!(
            contains(&long),
            "#4555 corpus floor 4: the chain of {n} x DestOpt(len=15) is gone. A statement placed \
             inside the walk loop but outside the `match` is observable only while the walk is \
             still on an extension header at a large offset, which needs a chain of several \
             maximum-length headers."
        );
    }

    // 5. THE CORPUS WALKS AT EVERY L3 OFFSET THIS CRATE'S L2 PARSER PRODUCES.
    //    `L3_OFFSETS.len() >= 3` stood here in round 5 and asserted a PROXY:
    //    `[0, 0, 0]` has length 3 and restores exactly the l3-blindness the
    //    message described. Round 6 replaced it with `any(!= 0)` and
    //    `contains(0)`, which `[0, 14, 14]` also satisfies while dropping the
    //    tagged offset entirely. So the offsets are MEASURED here: `at_l3`
    //    builds the untagged and 802.1Q prefixes, and `frame_l3_offset` — the
    //    function that computes the L3 offset the forwarding path walks at —
    //    says where L3 starts in each.
    //    Binds: every offset this crate's L2 parser produces is in the array,
    //    plus 0, the offset `walk_ipv6_ext_chain`'s other callers pass when they
    //    hand it an L3-relative slice.
    //    Does NOT bind: the SHIM's `parse_l2`, which is in the aya crate and
    //    cannot be linked here. That the two agree on 14/18 is a documented
    //    claim (see `L3_OFFSETS`), not something this floor measures.
    let probe = chain(&[], TCP, 0);
    for tag in [14usize, 18] {
        let framed = at_l3(&probe, tag);
        let measured = frame_l3_offset(&framed).unwrap_or_else(|| {
            panic!(
                "#4555 corpus floor 5: frame_l3_offset refused the {tag}-byte L2 prefix at_l3 \
                 builds; the floor cannot measure what it claims to"
            )
        });
        assert!(
            L3_OFFSETS.contains(&measured),
            "#4555 corpus floor 5: the L3 offsets ({L3_OFFSETS:?}) omit {measured}, an offset this crate's \
             frame_l3_offset produces (here from the {tag}-byte prefix). Replacing the \
             revalidation's base `l3_offset as usize` with `0usize` is BIT-IDENTICAL at l3 = 0 and \
             a fail-open of exactly l3 bytes at every non-zero offset, so an offset missing from \
             this array is a mutation nothing can see."
        );
    }
    assert!(
        L3_OFFSETS.contains(&0),
        "#4555 corpus floor 5: the L3 offsets ({L3_OFFSETS:?}) no longer include 0, the offset \
         `walk_ipv6_ext_chain`'s other callers pass when they hand it an L3-relative slice"
    );

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
/// What is left on the shim side executes no arm body any mutation touches:
///   - a chain with NO extension headers does enter the walk loop — it runs
///     the classifier once, takes the `match`'s terminal catch-all and breaks —
///     but that path has no advance arithmetic, no post-advance revalidation
///     and no header read to perturb. The acceptance matrix's added
///     `if offset > 200 { break; }` (the statement-inside-the-loop row) IS
///     executed here, at offset 40, where it is false: the statement runs and
///     changes nothing, which is precisely what makes this a control rather
///     than a co-signer. An earlier revision claimed the packet "never enters
///     a `match` arm", which is not what the loop does;
///   - a buffer too short for the fixed 40-byte header fails closed before the
///     walk starts, so no iteration runs at all.
/// Both outcomes are fixed by RFC 8200 and unchanged by any mutation to the
/// walk, so a red here means the corpus harness or this crate's walker broke.
#[test]
fn shim_walk_corpus_negative_control() {
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
