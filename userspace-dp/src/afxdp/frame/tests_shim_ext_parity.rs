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
// better model, and a better model is still a model. So the dependency is
// inverted: the shim EMITS its resolved facts (`XPF_SHIM_FACTS`, a
// `#[used]` static whose fields rustc const-evaluates from the real types
// and the real classifier), `make generate` records them in
// `pkg/dataplane/userspace_xdp_manifest.json`, and this test compares this
// crate's MEASURED behaviour against those numbers. There is no parser, no
// arm-body literal and no struct-layout resolver left to defeat.
//
// It also fixes a scope problem the source model could not: a compile-time
// assertion in the shim only runs when the shim crate is compiled, which
// the Debian packaging path never does (it runs `make build`, and the
// daemon embeds the tracked `.o`). Facts recorded in the manifest are
// checkable wherever a prebuilt object is consumed.
//
// RESIDUAL, stated plainly. One property is still not emitted: that the
// shim's loop exits by EXHAUSTION straight into `parse_l4` with no
// post-loop over-limit check. That is what makes it resolve `MAX_EXT_HDRS`
// headers where this crate resolves `MAX_IPV6_EXT_HEADERS - 1`, and it is
// a shape, not a value — any number the shim exported for it would be an
// assertion about its own semantics rather than a measurement of them,
// which is the modelling this file otherwise removed.
// `shim_walk_exits_by_exhaustion` keeps a narrow source check for exactly
// that one property, and nothing else.

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
    // closed on. `shim_walk_exits_by_exhaustion` pins the exit semantics
    // this reasoning rests on.
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

/// The one property the shim cannot emit as a number: that its walk loop
/// exits by EXHAUSTION straight into `parse_l4`, with no post-loop
/// over-limit check.
///
/// That shape is what makes the shim resolve `MAX_EXT_HDRS` headers where
/// this crate resolves `MAX_IPV6_EXT_HEADERS - 1`, i.e. it is the basis of
/// the `- 1` relation asserted above. It cannot be emitted honestly: any
/// constant the shim exported for it would be an assertion about its own
/// semantics, not a measurement of them — exactly the modelling this file
/// otherwise removed. So it stays a narrow source check whose scope is
/// deliberately ONE property, not the whole walk.
#[test]
fn shim_walk_exits_by_exhaustion() {
    let path = repo_root().join("userspace-xdp").join("src").join("lib.rs");
    let src = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read the shim source at {}: {e}", path.display()));

    const LOOP_HDR: &str = "for _ in 0..MAX_EXT_HDRS {";
    let at = src.find(LOOP_HDR).expect(
        "shim source has no `for _ in 0..MAX_EXT_HDRS {` walk loop — the #4555 `- 1` \
         chain-length relation is derived from this loop's exit semantics; re-derive it by hand.",
    );
    let open = at + LOOP_HDR.len() - 1;
    let mut depth = 0usize;
    let mut close = None;
    for (i, b) in src.as_bytes().iter().enumerate().skip(open) {
        match b {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    close = Some(i);
                    break;
                }
            }
            _ => {}
        }
    }
    let close = close.expect("shim walk loop has unbalanced braces");
    let after = &src[close + 1..];
    let parse_l4_at = after
        .find("parse_l4(data, data_end, offset, protocol)")
        .expect(
            "shim `parse_ipv6` no longer calls `parse_l4(data, data_end, offset, protocol)` after \
             the extension-header walk — re-derive the #4555 chain-length relation by hand.",
        );
    let between = &after[..parse_l4_at];
    for forbidden in ["return None", "return Err", "MAX_EXT_HDRS"] {
        assert!(
            !between.contains(forbidden),
            "the shim's extension-header walk gained a post-loop {forbidden:?} between the loop \
             and parse_l4. That changes how loop EXHAUSTION is treated, so the shim no longer \
             resolves chains of exactly MAX_EXT_HDRS headers and the `MAX_EXT_HDRS == \
             MAX_IPV6_EXT_HEADERS - 1` relation is no longer the right one. Re-derive it. Text \
             between the loop and parse_l4:\n{between}"
        );
    }
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
