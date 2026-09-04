// #8274 step 2: the AF_XDP shim's WireGuard record classification, EXECUTED.
//
// The shim steers every UDP datagram on the WireGuard listen port to the
// kernel, where the control thread decrypts it and writes the plaintext
// straight to the `wgN` TUN. Nothing between `try_decap` and that write is a
// security policy — a peer's `allowed-ips` is a cryptographic check on the
// inner SOURCE address, with no destination, no zone pair, no application and
// no direction — so the inner traffic of an authenticated peer is forwarded by
// the kernel with no zone adjudication at all.
//
// Step 2 is the half of the fix that has to survive the kernel verifier: leave
// TRANSPORT-DATA records (type 4) to the userspace worker, keep steering
// handshake and cookie records (types 1, 2, 3) to the kernel. Step 3 adds the
// worker decap stage that adjudicates what step 2 stops handing away.
//
// WHY THIS FILE INCLUDES THE SHIM'S SOURCE AND RUNS IT.
//
// The shim cannot be executed here: it is `no_std`, built for
// `bpfel-unknown-none`. `tests_shim_ext_parity.rs` is the record of what
// happens when a shim property is guarded by a test that MODELS the shim from
// source text instead — five successive models, each leaking to a more ordinary
// edit than the last, the worst of which accepted the DELETION of a security
// property. Its resolution was to move the walk into a `core`-only module the
// shim calls and this crate `#[path]`-includes and executes.
//
// `wg_classify.rs` is that shape for the same reason, and the reason is sharper
// here: this decision is what decides whether a packet's inner plaintext will be
// adjudicated at all.
#[path = "../../../../userspace-xdp/src/wg_classify.rs"]
mod shim_wg;

use shim_wg::{
    WG_TYPE_COOKIE, WG_TYPE_DATA, WG_TYPE_INITIATION, WG_TYPE_RESPONSE,
    wg_record_is_transport_data, wg_steer_to_kernel_on_port_match,
};

/// The acceptance criterion #8274 names first: a type-4 record and a type-1
/// record with IDENTICAL 5-tuples must classify differently.
///
/// The fixture varies ONLY the first payload byte. A fixture that varied the
/// 5-tuple would pass on the pre-existing port match and prove nothing about
/// the change — the issue says so explicitly, and it is the whole reason this
/// cell drives the classifier on payload bytes rather than on packets.
#[test]
fn identical_five_tuples_classify_by_message_type_8274() {
    // Same datagram, same everything, one byte apart.
    assert!(
        wg_record_is_transport_data(Some(WG_TYPE_DATA)),
        "a type-4 record is transport data and must be left to the worker; it is \
         the only WireGuard message that carries an inner IP packet, and the \
         inner packet is what #8274 exists to adjudicate"
    );
    for handshake in [WG_TYPE_INITIATION, WG_TYPE_RESPONSE, WG_TYPE_COOKIE] {
        assert!(
            !wg_record_is_transport_data(Some(handshake)),
            "message type {handshake} is a handshake/cookie record and must keep \
             going to the kernel: the control thread owns the handshake state \
             machine and there is nothing in these records for the dataplane to \
             adjudicate (#8274)"
        );
    }
    // The two ends of the same decision, with the local-destination answer and
    // everything else held equal — this is the "identical 5-tuple" comparison
    // stated as the steer verdict rather than as a property of the byte.
    assert!(
        !wg_steer_to_kernel_on_port_match(true, wg_record_is_transport_data(Some(WG_TYPE_DATA))),
        "a type-4 record on the listen port, to a local destination, must NOT be \
         steered to the kernel any more (#8274)"
    );
    assert!(
        wg_steer_to_kernel_on_port_match(
            true,
            wg_record_is_transport_data(Some(WG_TYPE_INITIATION))
        ),
        "a type-1 record with the SAME 5-tuple must still be steered to the kernel"
    );
}

/// The second acceptance criterion: a truncated payload with no readable type
/// byte classifies as KERNEL-STEERED — the pre-#8274 behaviour — never as
/// worker-claimed.
///
/// The direction matters. Claiming an unreadable record for a worker decap
/// stage that can only reject it would relocate the kernel path's existing
/// malformed-record accounting to a stage that does not have it, and it would
/// do so for exactly the inputs an attacker controls the length of.
#[test]
fn unreadable_payload_stays_kernel_steered_8274() {
    assert!(
        !wg_record_is_transport_data(None),
        "a datagram with no readable first payload byte is not transport data"
    );
    assert!(
        wg_steer_to_kernel_on_port_match(true, wg_record_is_transport_data(None)),
        "a truncated or zero-length datagram on the listen port must keep its \
         pre-#8274 kernel path (#8274)"
    );
}

/// Every message type OTHER than 4 stays on the kernel path, including the
/// reserved 0 and everything above 4.
///
/// This is not thoroughness for its own sake: the control thread's dispatch has
/// an explicit arm for a type byte outside {1,2,3,4} that drops and counts it
/// (#1865). Leaving those on the kernel path preserves that counting instead of
/// silently relocating it to a stage with no such arm.
#[test]
fn only_type_four_is_claimed_by_the_worker_8274() {
    let mut claimed = Vec::new();
    for ty in 0u8..=255 {
        if wg_record_is_transport_data(Some(ty)) {
            claimed.push(ty);
        }
    }
    assert_eq!(
        claimed,
        vec![WG_TYPE_DATA],
        "EXACTLY one message type may be claimed by the worker. Anything else \
         either hands a handshake record to a stage that cannot process it, or \
         relocates the #1865 unknown-type drop counter (#8274)"
    );
}

/// `is_local_destination` is MANDATORY and unchanged by #8274.
///
/// A port-only match would shunt TRANSIT or DNAT UDP that merely happens to use
/// the WireGuard port to the kernel, bypassing the userspace policy engine —
/// a separate and worse bug than the one #8274 fixes, and the shim's own
/// comment says so. The predicate itself reads BPF maps this crate cannot see;
/// what is asserted here is that its answer is REQUIRED, which is the part a
/// refactor can drop.
///
/// Both message types are driven so a fix that made the local-destination
/// answer matter for only ONE of them would still red.
#[test]
fn local_destination_is_required_for_either_message_type_8274() {
    for ty in [WG_TYPE_INITIATION, WG_TYPE_DATA] {
        assert!(
            !wg_steer_to_kernel_on_port_match(false, wg_record_is_transport_data(Some(ty))),
            "a NON-local destination must never be steered to the kernel, whatever \
             the message type (type {ty}): a port-only match shunts transit/DNAT \
             UDP on the WireGuard port past the userspace policy engine (#8274)"
        );
    }
}
