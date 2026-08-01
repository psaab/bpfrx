// #4555: drift guard between the two IPv6 extension-header walkers that
// must agree on what "valid enough IPv6" means.
//
// The AF_XDP shim (`userspace-xdp/src/lib.rs`, `parse_ipv6`) and this
// crate's `walk_ipv6_ext_chain` each walk the extension-header chain to
// find the terminal L4 header. The shim's verdict decides whether a
// packet matches the session map and takes the XDP fast path; this
// crate's verdict decides how the packet is actually forwarded. When the
// two disagree, the shim computes a session key userspace never
// installed, so the lookup misses and EVERY packet of that flow is
// redirected to userspace — fail-closed (the redirect leads to full
// userspace policy; no bypass), but a permanent loss of the fast path.
//
// Two such divergences existed before #4555:
//   - the resolvable CHAIN LENGTH: the shim resolved up to 6 extension
//     headers where this crate resolves up to 7, so a chain of exactly 7
//     resolved in userspace and never in the shim;
//   - the walked TYPE SET: #4517 taught the userspace walkers to treat
//     Mobility(135)/HIP(139)/Shim6(140)/experimental(253,254) as generic
//     length-prefixed headers, but left the shim stopping at them.
//
// WHY THIS COMPARES CHAIN LENGTHS AND NOT THE TWO CONSTANTS. The bounds
// are ITERATION counts and the loops spend iterations differently:
//
//   - the shim's loop spends one iteration per extension header and exits
//     by EXHAUSTION carrying the last declared next-header value, with no
//     post-loop over-limit check — `protocol` flows straight into
//     `parse_l4`. It resolves up to `MAX_EXT_HDRS` extension headers.
//   - `walk_ipv6_ext_chain` needs one FURTHER iteration to return the
//     terminal (`_ => return L4(..)`) and folds exhaustion into the
//     fail-closed `OverLimit` verdict (#2292/#4743). It resolves up to
//     `MAX_IPV6_EXT_HEADERS - 1` extension headers.
//
// So the parity condition is `MAX_EXT_HDRS == MAX_IPV6_EXT_HEADERS - 1`.
// Asserting raw numeric equality would demand a shim bound of 8, which
// (a) does not pass the BPF verifier at all and (b) would make the shim
// resolve 8-header chains that userspace fails closed on. This test
// therefore derives the resolvable chain length on each side and compares
// THAT, and additionally asserts the structural property the shim's side
// of the derivation depends on (no post-loop over-limit check), so a
// future shim edit that adds one cannot silently invalidate the +1.
//
// The two constants live in different crates built for different targets
// (`bpfel-unknown-none`, `no_std`) so neither can `use` the other. This
// test therefore parses the shim's walk out of its source text and
// compares it against THIS crate's walker — where the userspace side is
// derived from real behaviour (`walk_ipv6_ext_chain` probed across all
// 256 next-header values and across chain lengths), not from a second
// text parse. Reading a sibling crate's source from a test follows the
// existing in-crate precedent (`v8_carry_field_is_reader_private` in
// `afxdp/types/shared_cos_lease/shared_cos_lease_tests.rs`, and the
// `policer.rs` source scan).
//
// The parser fails LOUDLY — it never silently skips — when it cannot find
// the shim source or cannot recognise the walk's shape. A skip here would
// fail open on exactly the drift it exists to catch, the hole
// `pkg/dataplane/userspace_xdp_manifest.go` calls out for
// `TestMaxInterfacesMatchesCHeader`'s `t.Skipf`. If a shim refactor makes
// this parse fail, that is the signal to re-establish parity by hand and
// teach the parser the new shape.

#![allow(unused_imports)]

use super::*;
use std::path::{Path, PathBuf};

const PROBE_TCP: u8 = 6;

/// How a walker treats one IPv6 next-header value when it appears in the
/// extension-header chain position. Both sides are reduced to this
/// classification and compared value-by-value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EhClass {
    /// Generic length-prefixed extension header: byte 0 = next header,
    /// byte 1 = HdrExtLen, advance `(HdrExtLen + 1) * 8`, keep walking.
    Generic,
    /// Authentication Header (RFC 4302): advance `(len + 2) * 4`.
    Auth,
    /// Fragment header: fixed 8-byte advance.
    Fragment,
    /// No-Next-Header (59): a valid terminal with no L4 header.
    NoNext,
    /// A real upper-layer protocol, or anything neither side walks (ESP):
    /// stop, this is the L4 header.
    Terminal,
}

/// The shim's `parse_ipv6` extension-header walk, recovered from source.
struct ShimWalk {
    /// `MAX_EXT_HDRS` — the loop's iteration bound.
    bound: usize,
    /// Classification of all 256 next-header values.
    classes: [EhClass; 256],
}

impl ShimWalk {
    /// Longest extension-header chain whose L4 the shim still resolves.
    ///
    /// One iteration consumes one extension header, and the loop exits by
    /// exhaustion carrying the last declared next-header value into
    /// `parse_l4` — so `bound` headers are consumed and the L4 after them
    /// is still resolved.
    ///
    /// The shim side of this comparison is a source MODEL, not an
    /// execution — the shim is `no_std` and built for
    /// `bpfel-unknown-none`, so this crate's test binary cannot run it.
    /// Three pins are what make the model trustworthy, and each fails
    /// loudly rather than degrading quietly:
    ///
    ///   1. the loop header text (`shim_loop_open_idx`) and the
    ///      requirement that the loop body contains NOTHING but the
    ///      `match protocol` block (`shim_walk_model`) — so no extra
    ///      per-iteration statement can hide outside the match;
    ///   2. every arm body pinned by whitespace-normalised EQUALITY
    ///      against the literals below, so any change to the advance
    ///      arithmetic or any added statement inside an arm panics
    ///      instead of passing (a `contains` substring test let
    ///      `((opt[1] as u16) + 1) * 8 + 8` and a prepended
    ///      `if opt[1] == 0 { break; }` through — the latter rejects the
    ///      ORDINARY 8-byte HbH/DestOpt, i.e. destroys parity for
    ///      essentially every real chain);
    ///   3. `assert_no_post_loop_overlimit_check`, which pins the
    ///      exhaustion semantics the `bound`-headers-resolvable claim
    ///      rests on.
    fn max_resolvable_ext_headers(&self) -> usize {
        self.bound
    }
}

// The exact bodies of the shim's three walking arms. Compared by
// whitespace-normalised token equality (see `normalise_tokens`), so
// rustfmt reflow is invisible but ANY added, removed or altered token is
// not. Update these ONLY together with a re-derivation of the parity
// argument above.
const SHIM_GENERIC_ARM_BODY: &str = r#"
    let opt = read_bytes(data, data_end, offset as usize, 2)?;
    protocol = opt[0];
    offset = offset.checked_add(((opt[1] as u16) + 1) * 8)?;
    read_bytes(data, data_end, l3_offset as usize, (offset - l3_offset) as usize)?;
"#;

const SHIM_AUTH_ARM_BODY: &str = r#"
    let opt = read_bytes(data, data_end, offset as usize, 2)?;
    protocol = opt[0];
    offset = offset.checked_add(((opt[1] as u16) + 2) * 4)?;
    read_bytes(data, data_end, l3_offset as usize, (offset - l3_offset) as usize)?;
"#;

const SHIM_FRAGMENT_ARM_BODY: &str = r#"
    let frag = read_bytes(data, data_end, offset as usize, 8)?;
    protocol = frag[0];
    offset = offset.checked_add(mem::size_of::<FragHdr>() as u16)?;
"#;

/// Normalise a Rust snippet to a formatting-insensitive token stream:
/// every token is either a run of `[A-Za-z0-9_]` or a single punctuation
/// character, joined by single spaces. Two snippets differing only in
/// line breaks, indentation or rustfmt reflow normalise identically;
/// any added, removed or altered token changes the result.
///
/// The one token deliberately discarded is a trailing comma immediately
/// before a closing delimiter — rustfmt emits it in the multi-line form
/// of a call and omits it in the single-line form, and it is
/// syntactically inert, so keeping it would make these pins hostage to
/// reflow without adding any signal.
fn normalise_tokens(src: &str) -> String {
    let mut tokens: Vec<String> = Vec::new();
    let mut chars = src.chars().peekable();
    while let Some(c) = chars.next() {
        if c.is_whitespace() {
            continue;
        }
        if c.is_alphanumeric() || c == '_' {
            let mut word = String::from(c);
            while let Some(&next) = chars.peek() {
                if next.is_alphanumeric() || next == '_' {
                    word.push(next);
                    chars.next();
                } else {
                    break;
                }
            }
            tokens.push(word);
        } else {
            tokens.push(c.to_string());
        }
    }
    let mut out: Vec<&str> = Vec::with_capacity(tokens.len());
    for (i, tok) in tokens.iter().enumerate() {
        if tok == ","
            && matches!(
                tokens.get(i + 1).map(String::as_str),
                Some(")") | Some("]") | Some("}")
            )
        {
            continue;
        }
        out.push(tok);
    }
    out.join(" ")
}

fn shim_source_path() -> PathBuf {
    // CARGO_MANIFEST_DIR is <repo>/userspace-dp.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("userspace-xdp")
        .join("src")
        .join("lib.rs")
}

fn read_shim_source() -> String {
    let path = shim_source_path();
    std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "cannot read the AF_XDP shim source at {}: {e}. This guard must not be skipped — a \
             skip would fail open on exactly the #4555 drift it exists to catch.",
            path.display()
        )
    })
}

/// Return the substring of `src` starting after the `{` at `open_idx`, up
/// to (excluding) its matching `}`.
fn braced_body(src: &str, open_idx: usize) -> String {
    let bytes = src.as_bytes();
    assert_eq!(
        bytes[open_idx], b'{',
        "braced_body: byte at {open_idx} is not an opening brace"
    );
    let mut depth = 0usize;
    for (i, b) in bytes.iter().enumerate().skip(open_idx) {
        match b {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return src[open_idx + 1..i].to_string();
                }
            }
            _ => {}
        }
    }
    panic!("braced_body: unbalanced braces from offset {open_idx}");
}

/// Byte offset of the walk loop's opening brace.
fn shim_loop_open_idx(src: &str) -> usize {
    const LOOP_HDR: &str = "for _ in 0..MAX_EXT_HDRS {";
    let at = src.find(LOOP_HDR).expect(
        "shim source has no `for _ in 0..MAX_EXT_HDRS {` walk loop — re-establish the #4555 \
         parity by hand and teach this parser the new shape",
    );
    at + LOOP_HDR.len() - 1
}

/// Parse every `const NEXTHDR_<NAME>: u8 = <n>;` in the shim source into a
/// name → value map, so the walk's match arms (written with the named
/// constants) can be resolved to wire values.
fn shim_nexthdr_consts(src: &str) -> std::collections::HashMap<String, u8> {
    let mut out = std::collections::HashMap::new();
    for line in src.lines() {
        let Some(rest) = line.trim().strip_prefix("const NEXTHDR_") else {
            continue;
        };
        let Some((name, value)) = rest.split_once(": u8 = ") else {
            continue;
        };
        let value = value.trim_end_matches(';').trim();
        let parsed: u8 = value
            .parse()
            .unwrap_or_else(|e| panic!("shim const NEXTHDR_{name} value {value:?}: {e}"));
        out.insert(format!("NEXTHDR_{name}"), parsed);
    }
    assert!(
        out.len() >= 6,
        "shim source declares only {} NEXTHDR_* constants ({:?}); the walk cannot be resolved — \
         re-establish the #4555 parity by hand and teach this parser the new shape",
        out.len(),
        out
    );
    out
}

/// Split a `match` arm list into `(pattern, body)` pairs.
fn split_match_arms(arms_src: &str) -> Vec<(String, String)> {
    let mut arms: Vec<(String, String)> = Vec::new();
    let bytes = arms_src.as_bytes();
    let mut arm_start = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        if !bytes[i..].starts_with(b"=>") {
            i += 1;
            continue;
        }
        let pattern = arms_src[arm_start..i].trim().to_string();
        let mut j = i + 2;
        while j < bytes.len() && (bytes[j] as char).is_whitespace() {
            j += 1;
        }
        let (body, next) = if j < bytes.len() && bytes[j] == b'{' {
            let body = braced_body(arms_src, j);
            // Step past the closing brace and an optional comma.
            let mut k = j + body.len() + 2;
            while k < bytes.len() && ((bytes[k] as char).is_whitespace() || bytes[k] == b',') {
                k += 1;
            }
            (body, k)
        } else {
            let end = arms_src[j..]
                .find(',')
                .map(|off| j + off)
                .unwrap_or(arms_src.len());
            (arms_src[j..end].to_string(), (end + 1).min(arms_src.len()))
        };
        arms.push((pattern, body));
        arm_start = next;
        i = next;
    }
    arms
}

/// Reduce the shim's `parse_ipv6` extension-header walk to a [`ShimWalk`]
/// by parsing its source.
fn shim_walk_model(src: &str) -> ShimWalk {
    // --- the loop bound ---
    let bound_line = src
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with("const MAX_EXT_HDRS: usize ="))
        .expect(
            "shim source has no `const MAX_EXT_HDRS: usize = ...;` — re-establish the #4555 \
             parity by hand and teach this parser the new shape",
        );
    let bound: usize = bound_line
        .trim_start_matches("const MAX_EXT_HDRS: usize =")
        .trim()
        .trim_end_matches(';')
        .trim()
        .parse()
        .unwrap_or_else(|e| panic!("parse shim MAX_EXT_HDRS from {bound_line:?}: {e}"));

    // --- the walk loop, then the `match protocol {` inside it ---
    let loop_body = braced_body(src, shim_loop_open_idx(src));
    const MATCH_HDR: &str = "match protocol {";
    let match_at = loop_body.find(MATCH_HDR).expect(
        "shim walk loop has no `match protocol {` — re-establish the #4555 parity by hand and \
         teach this parser the new shape",
    );
    let arms_src = braced_body(&loop_body, match_at + MATCH_HDR.len() - 1);

    // The loop body must be the `match protocol` block and NOTHING else.
    // Pinning only the arm bodies would leave a statement placed inside
    // the loop but OUTSIDE the match entirely invisible — the same
    // blind spot, one level up. `if depth > 3 { break; }` before the
    // match would silently cut the resolvable chain length while every
    // arm still matched its pinned literal.
    // +1 steps past the match block's own closing brace, which sits at
    // `match_at + MATCH_HDR.len() + arms_src.len()`.
    let match_end = match_at + MATCH_HDR.len() + arms_src.len() + 1;
    let outside: String = [&loop_body[..match_at], &loop_body[match_end..]].concat();
    assert!(
        outside.trim().is_empty(),
        "the shim's extension-header walk loop body contains statements outside the `match \
         protocol` block. Those are invisible to this guard's per-arm pins and can change the \
         resolvable chain length on their own. Re-establish the #4555 parity by hand and teach \
         this parser the new shape. Text outside the match:\n{outside}"
    );

    let arms = split_match_arms(&arms_src);
    assert!(
        arms.len() >= 4,
        "shim `match protocol` parsed into only {} arms ({:?}) — re-establish the #4555 parity \
         by hand and teach this parser the new shape",
        arms.len(),
        arms.iter().map(|(p, _)| p).collect::<Vec<_>>()
    );

    // --- classify each arm by whitespace-normalised body EQUALITY ---
    // NOT a substring test: a `contains("+ 1) * 8")` classifier accepts
    // an arm that also advances by a further 8, or that prepends
    // `if opt[1] == 0 { break; }` (which rejects the ordinary 8-byte
    // HbH/DestOpt and so destroys parity for essentially every real
    // chain). Equality makes both of those panic here instead.
    let classify = |pattern: &str, body: &str| -> EhClass {
        let normalised = normalise_tokens(body);
        if normalised == normalise_tokens(SHIM_GENERIC_ARM_BODY) {
            EhClass::Generic
        } else if normalised == normalise_tokens(SHIM_AUTH_ARM_BODY) {
            EhClass::Auth
        } else if normalised == normalise_tokens(SHIM_FRAGMENT_ARM_BODY) {
            EhClass::Fragment
        } else if normalised == "break" {
            // `NEXTHDR_NONE => break` is the No-Next-Header terminal;
            // `_ => break` is the stop-here-this-is-L4 default.
            if pattern.trim() == "_" {
                EhClass::Terminal
            } else {
                EhClass::NoNext
            }
        } else {
            panic!(
                "shim walk arm {pattern:?} does not match any pinned arm body. This guard models \
                 the shim from source rather than executing it, so an arm body it does not \
                 recognise means the model — and the resolvable-chain-length claim built on it — \
                 is no longer known to be right. Re-establish the #4555 parity by hand and update \
                 the pinned literal.\n  got:      {normalised}\n  generic:  {}\n  auth:     {}\n  \
                 fragment: {}",
                normalise_tokens(SHIM_GENERIC_ARM_BODY),
                normalise_tokens(SHIM_AUTH_ARM_BODY),
                normalise_tokens(SHIM_FRAGMENT_ARM_BODY),
            )
        }
    };

    let consts = shim_nexthdr_consts(src);
    let mut default: Option<EhClass> = None;
    let mut model: [Option<EhClass>; 256] = [None; 256];
    for (pattern, body) in &arms {
        let class = classify(pattern, body);
        if pattern.trim() == "_" {
            assert!(default.is_none(), "shim walk has two `_` arms");
            default = Some(class);
            continue;
        }
        for name in pattern.split('|') {
            let name = name.trim();
            let value = *consts.get(name).unwrap_or_else(|| {
                panic!(
                    "shim walk arm names {name:?}, which is not a `const NEXTHDR_*: u8` in the \
                     shim source — re-establish the #4555 parity by hand and teach this parser \
                     the new shape"
                )
            });
            assert!(
                model[usize::from(value)].is_none(),
                "shim walk classifies next-header {value} twice"
            );
            model[usize::from(value)] = Some(class);
        }
    }
    let default = default.expect(
        "shim walk `match protocol` has no `_` arm — re-establish the #4555 parity by hand and \
         teach this parser the new shape",
    );
    let mut classes = [default; 256];
    for (proto, class) in model.iter().enumerate() {
        if let Some(class) = class {
            classes[proto] = *class;
        }
    }
    ShimWalk { bound, classes }
}

/// Pin the structural property [`ShimWalk::max_resolvable_ext_headers`]
/// depends on: the shim's walk loop exits by EXHAUSTION straight into
/// `parse_l4`, with no post-loop over-limit rejection. If a future edit
/// adds one, the shim would resolve one FEWER header than this model
/// claims and the `+ 1` parity relation below would silently become wrong.
fn assert_no_post_loop_overlimit_check(src: &str) {
    let open = shim_loop_open_idx(src);
    let loop_end = open + braced_body(src, open).len() + 2;
    let after = &src[loop_end..];
    let parse_l4_at = after.find("parse_l4(data, data_end, offset, protocol)").expect(
        "shim `parse_ipv6` no longer calls `parse_l4(data, data_end, offset, protocol)` after \
         the extension-header walk — re-establish the #4555 parity by hand and teach this \
         parser the new shape",
    );
    let between = &after[..parse_l4_at];
    for forbidden in ["return None", "return Err", "MAX_EXT_HDRS"] {
        assert!(
            !between.contains(forbidden),
            "the shim's extension-header walk gained a post-loop {forbidden:?} between the loop \
             and parse_l4. That changes how loop EXHAUSTION is treated, so the shim no longer \
             resolves chains of exactly MAX_EXT_HDRS headers and the `shim bound == \
             MAX_IPV6_EXT_HEADERS - 1` parity relation asserted below is no longer the right \
             one. Re-derive it. Text between the loop and parse_l4:\n{between}"
        );
    }
}

/// Classify one next-header value by running THIS crate's
/// `walk_ipv6_ext_chain` over a probe packet, rather than re-parsing its
/// source. The probe is a 40-byte IPv6 header whose Next Header is the
/// value under test, followed by one 8-byte header at offset 40 declaring
/// `HdrExtLen = 1` and `next = TCP`. The three walking arms then land the
/// terminal L4 at three distinguishable offsets:
///   generic  → 40 + (1 + 1) * 8 = 56
///   AH       → 40 + (1 + 2) * 4 = 52
///   fragment → 40 + 8           = 48   (and records a Fragment sighting)
/// while a terminal value stops at 40 reporting itself, and 59 reports
/// `NoNextHeader`.
fn userspace_class(proto: u8) -> EhClass {
    let mut buf = vec![0u8; 96];
    buf[0] = 0x60;
    buf[6] = proto;
    buf[40] = PROBE_TCP; // next header of the probe extension header
    buf[41] = 1; // HdrExtLen
    let walk = walk_ipv6_ext_chain(&buf, 0);
    match walk.outcome {
        ExtChainOutcome::NoNextHeader => EhClass::NoNext,
        ExtChainOutcome::L4(40, p) => {
            assert_eq!(
                p, proto,
                "probe for next-header {proto} stopped at offset 40 reporting protocol {p}"
            );
            EhClass::Terminal
        }
        ExtChainOutcome::L4(56, PROBE_TCP) => EhClass::Generic,
        ExtChainOutcome::L4(52, PROBE_TCP) => EhClass::Auth,
        ExtChainOutcome::L4(48, PROBE_TCP) => {
            assert!(
                walk.fragment.is_some(),
                "probe for next-header {proto} advanced 8 bytes without recording a Fragment \
                 sighting — the probe can no longer distinguish the Fragment arm"
            );
            EhClass::Fragment
        }
        other => panic!(
            "probe for next-header {proto} produced an unclassifiable outcome {other:?}; the \
             #4555 parity probe needs updating for the new walker shape"
        ),
    }
}

/// Build `n` chained 8-byte DestOpt headers terminated by TCP, behind a
/// 40-byte IPv6 header, and return whether `walk_ipv6_ext_chain` resolves
/// the TCP terminal.
fn userspace_resolves_chain_of(n: usize) -> bool {
    const DEST_OPT: u8 = 60;
    let mut buf = vec![0u8; 40 + 8 * n + 20];
    buf[0] = 0x60;
    buf[6] = if n == 0 { PROBE_TCP } else { DEST_OPT };
    for i in 0..n {
        let at = 40 + 8 * i;
        buf[at] = if i + 1 == n { PROBE_TCP } else { DEST_OPT };
        buf[at + 1] = 0; // HdrExtLen 0 → 8 bytes
    }
    matches!(
        walk_ipv6_ext_chain(&buf, 0).outcome,
        ExtChainOutcome::L4(off, PROBE_TCP) if off == 40 + 8 * n
    )
}

/// Longest extension-header chain whose L4 this crate's walker resolves,
/// measured rather than read off the constant.
fn userspace_max_resolvable_ext_headers() -> usize {
    let mut last = 0usize;
    for n in 0..64 {
        if userspace_resolves_chain_of(n) {
            last = n;
        } else {
            return last;
        }
    }
    panic!("walk_ipv6_ext_chain resolved a 64-header chain; it is meant to be bounded");
}

/// The load-bearing #4555 guard: the shim's IPv6 extension-header walk and
/// this crate's `walk_ipv6_ext_chain` must resolve the SAME chain lengths
/// and classify all 256 next-header values the same way.
#[test]
fn shim_ipv6_ext_walk_matches_userspace_walker() {
    let src = read_shim_source();
    assert_no_post_loop_overlimit_check(&src);
    let shim = shim_walk_model(&src);

    let shim_max = shim.max_resolvable_ext_headers();
    let userspace_max = userspace_max_resolvable_ext_headers();
    assert_eq!(
        shim_max, userspace_max,
        "#4555 IPv6 extension-header CHAIN-LENGTH drift: the AF_XDP shim resolves chains of up \
         to {shim_max} extension headers (MAX_EXT_HDRS = {}) but this crate's \
         walk_ipv6_ext_chain resolves up to {userspace_max} (MAX_IPV6_EXT_HEADERS = {}). A \
         chain length one side resolves and the other does not makes the two compute different \
         session keys for the same packet, so the flow's key never matches and every packet \
         takes the slow XSK path forever (fail-closed, but the fast path is permanently lost). \
         The bounds are ITERATION counts with different exit semantics — the shim exits by \
         exhaustion carrying the resolved protocol, this crate needs one more iteration to \
         return the terminal — so the correct relation is `MAX_EXT_HDRS == MAX_IPV6_EXT_HEADERS \
         - 1`, NOT numeric equality. Raising the shim's bound costs BPF verifier budget and is \
         gated by the #1864 verify-then-install run: re-run `make generate` and commit the \
         regenerated object.",
        shim.bound, MAX_IPV6_EXT_HEADERS,
    );

    // The relation the chain-length equality above implies, asserted
    // directly so a reader of a failure sees the arithmetic too.
    assert_eq!(
        shim.bound,
        MAX_IPV6_EXT_HEADERS - 1,
        "#4555: shim MAX_EXT_HDRS ({}) != MAX_IPV6_EXT_HEADERS - 1 ({})",
        shim.bound,
        MAX_IPV6_EXT_HEADERS - 1,
    );

    let mut drift: Vec<String> = Vec::new();
    for proto in 0u16..=255 {
        let proto = proto as u8;
        let shim_class = shim.classes[usize::from(proto)];
        let userspace = userspace_class(proto);
        if shim_class != userspace {
            drift.push(format!(
                "next-header {proto}: shim={shim_class:?} userspace={userspace:?}"
            ));
        }
    }
    assert!(
        drift.is_empty(),
        "#4555 IPv6 extension-header TYPE-SET drift between the AF_XDP shim's parse_ipv6 walk \
         and this crate's walk_ipv6_ext_chain: {drift:?}. A type one side walks THROUGH and the \
         other treats as terminal makes the two compute different session keys for the same \
         packet, so the flow never matches the XDP fast path. Change both walkers together, and \
         re-run `make generate` for the shim side.",
    );
}

/// NEGATIVE CONTROL for the mutation proof.
///
/// This test deliberately touches NOTHING on the shim side — no
/// `read_shim_source`, no `shim_walk_model`. It exercises only this
/// crate's walker and the probe harness the guard above measures with.
/// That independence is the whole point: every mutation used to prove the
/// guard is a mutation of the SHIM source, so a control that shared the
/// source model would red alongside the guard and prove nothing. An
/// earlier draft did exactly that — it asserted shim-side classifications
/// too, and went red on any mutation that made an arm unparseable,
/// co-signing instead of controlling. Those shim-side assertions were
/// redundant anyway: the guard's 256-value comparison already covers them.
///
/// A red HERE means this crate's `walk_ipv6_ext_chain` changed, or the
/// probe construction broke — not that the shim drifted.
///
/// - ESP (50) is terminal (encrypted payload, unreadable inner
///   next-header); TCP (6) / UDP (17) / ICMPv6 (58) are terminal.
/// - Hop-by-Hop (0), Routing (43) and DestOpt (60) are generic.
/// - AH (51) and Fragment (44) have their own advance arithmetic.
/// - No-Next-Header (59) is a terminal with no L4.
/// - Chains of 0, 1 and 5 headers resolve; 16 does not. Those lengths sit
///   on the same side of both the pre-#4555 bound (6) and the post-#4555
///   bound (7), so they are invariant across the fix.
#[test]
fn shim_ext_parity_negative_control_unchanged_classifications() {
    for (proto, want) in [
        (0u8, EhClass::Generic), // Hop-by-Hop
        (43, EhClass::Generic),  // Routing
        (60, EhClass::Generic),  // Destination Options
        (44, EhClass::Fragment), // Fragment
        (51, EhClass::Auth),     // Authentication Header
        (59, EhClass::NoNext),   // No Next Header
        (50, EhClass::Terminal), // ESP — deliberately NOT walked
        (6, EhClass::Terminal),  // TCP
        (17, EhClass::Terminal), // UDP
        (58, EhClass::Terminal), // ICMPv6
    ] {
        assert_eq!(
            userspace_class(proto),
            want,
            "userspace classification of next-header {proto} changed; this is pre-#4555 \
             behaviour the fix must not perturb"
        );
    }

    // Chain lengths invariant across the fix, measured on the userspace
    // walker only.
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
         #4555 guard's measurement harness is broken, independently of the shim"
    );
}
