// #7091: the poll loop must hand `stage_flow_cache_hit` the BINDING's persistent
// mirror sample counter, not a fresh one.
//
// MEASURED FIRST. Replacing the argument with `&mut 0u64` leaves the entire
// `userspace-dp` suite green — rc=0, 4827 tests collected, 0 named failures, on
// an unfiltered `cargo test --release --bins -- --test-threads=1`. The seam is
// genuinely unbound.
//
// WHY THIS IS A SOURCE-SHAPE ASSERTION, stated because a behavioural cell was
// attempted first and is the better instrument when it is available.
//
// The counter is only USED inside `stage_flow_cache_hit`'s in-place fast path,
// which is guarded by `is_self_target && owned_packet_frame.is_none()` — the
// packet must egress the SAME binding it arrived on. A driven cell therefore
// needs a hairpin fixture: a flow whose route sends it back out its ingress
// interface, with `binding_lookup` resolving that ifindex to the same binding
// index. `nat_snapshot()`'s LAN->WAN shape does not, and a cell built on it
// measures nothing: I wrote one, and it reported the binding's counter at 0
// after three flow-cache hits ON THE UNMUTATED TREE, because the mirror block
// was never entered. That is a fixture that cannot produce the state it asserts
// about — the same failure the existing #6304 coverage has one level down.
//
// The #6304 cells in `flow_cache_hit_tests.rs` call `stage_flow_cache_hit`
// DIRECTLY with an explicit `initial_sample_counter`. They bind everything the
// stage does with the counter it is handed and, by construction, cannot observe
// WHICH counter the poll loop hands it. That is this file's subject.
//
// So this asserts the ARGUMENT at the call site, which is exactly the defect:
// the identity of the expression passed, not the behaviour of the callee. The
// repo binds this class the same way — `TestArmProofIsInvokedFromCompileUserspaceShim`
// walks a function for a `CallExpr`, and the #5103 reth guard asserts a call
// site's assignment shape.
//
// Comments are stripped before matching. A source-scanning guard that reads its
// own explanatory prose is satisfied by the sentence describing what it should
// find — and this file names the mutation verbatim, so without stripping it
// would pass against a severed call site.

use std::path::Path;

/// #7091 fail-on-revert: the mirror sample counter passed into
/// `stage_flow_cache_hit` must be the BINDING's field.
#[test]
fn poll_loop_passes_the_bindings_mirror_sample_counter_7091() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("afxdp")
        .join("poll_descriptor")
        .join("mod.rs");
    let src = std::fs::read_to_string(&path).expect("poll_descriptor/mod.rs must be readable");

    // Strip line comments so this file's own prose, and any doc comment at the
    // call site, cannot satisfy the assertions below.
    let code: String = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");

    // NON-VACUITY, checked first: if the call is gone or renamed, every
    // assertion below passes for free and this guard is decoration.
    assert!(
        code.contains("stage_flow_cache_hit("),
        "poll_descriptor/mod.rs no longer calls stage_flow_cache_hit — either the \
         established-flow fast path was restructured, in which case this guard is \
         scanning for something that no longer exists, or it was removed. Either \
         way it is not evidence that the counter is threaded (#7091)"
    );

    assert!(
        code.contains("&mut binding.mirror_sample_counter"),
        "the poll loop does not pass the BINDING's mirror sample counter into \
         stage_flow_cache_hit.\n`mirror_sample_allows` samples on \
         `current % rate == 0` using the value it is handed BEFORE incrementing, \
         so a counter that is 0 on every call selects EVERY call. With \
         `set forwarding-options port-mirroring ... rate N`, every packet served \
         by the flow cache — most packets of every long-lived flow — is cloned to \
         the analyzer instead of one in N: the N-fold clone flood and the O(PPS) \
         true-shared CAS on the target's pending_tx_admitted that #6114 removed \
         and #6304 bound one level down (#7091)"
    );
}

/// #7091 over-reach guard: the counter must be a per-BINDING field, so exactly
/// one binding's counter is threaded per call site.
///
/// Without this, the assertion above is satisfied by a build that ALSO passes a
/// fresh counter somewhere else on the same path — the shape a partial revert
/// would leave. It also fails if the argument is duplicated onto a second call
/// site that a future fast path adds without its own binding state.
#[test]
fn the_mirror_sample_counter_has_exactly_one_poll_loop_call_site_7091() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("afxdp")
        .join("poll_descriptor")
        .join("mod.rs");
    let src = std::fs::read_to_string(&path).expect("poll_descriptor/mod.rs must be readable");
    let code: String = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");

    let threaded = code.matches("&mut binding.mirror_sample_counter").count();
    assert_eq!(
        threaded, 1,
        "expected exactly ONE site threading the binding's mirror sample counter \
         through the poll loop, found {threaded}. Zero means the wiring is severed \
         (see the sibling test); more than one means a second fast path takes it \
         too, and each such path needs its own reachability argument before this \
         guard can speak for it (#7091)"
    );
}
