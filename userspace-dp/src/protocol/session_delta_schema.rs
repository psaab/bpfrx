//! #7194: a DERIVED identity for the HA session-open delta schema.
//!
//! ## Why this exists
//!
//! `ConfigSnapshotProtocolVersion` gates the config-snapshot protocol. The
//! session-delta schema rides the same helper/daemon pair with **no identity of
//! its own**, and that gap is not hypothetical: `policy_id`,
//! `policy_counter_idx`, `app_timeout`, `nat64` and `nat64_snat_v4` existed on
//! the binary open frame and the Go consumer while the JSON producer omitted
//! them (#5865), and `rt_flow_session_id` reached the JSON leg one issue after
//! the binary leg (#5212 -> #6312). Every one of those shipped without a
//! version bump, because there was no version to bump.
//!
//! ## Why it is DERIVED rather than a hand-maintained integer
//!
//! A constant someone must remember to bump inherits exactly the discipline
//! that already failed three times. This fingerprint is computed FROM the
//! serde-serialized shape of [`SessionDeltaInfo`], so adding, removing or
//! renaming a wire field changes it automatically and cannot be forgotten.
//!
//! It deliberately hashes the WIRE names (serde `rename` values), not the Rust
//! field names: a `#[serde(rename)]` drift breaks the wire while leaving both
//! field names untouched, and that is precisely the divergence the parity guard
//! was built to catch.
//!
//! ## Canonical form
//!
//! Wire names, sorted ascending as byte strings, joined with `\n`, no trailing
//! newline; FNV-1a/64 over those bytes. The Go mirror
//! (`pkg/dataplane/userspace/session_delta_schema.go`) MUST reproduce this
//! byte-for-byte — the two are asserted to AGREE rather than either being
//! pinned to a literal, so neither side encodes which one is trusted.
//!
//! A fingerprint of 0 is reserved to mean "not advertised" (a helper predating
//! this field). The Go gate treats that as unknown-and-deferred, never as a
//! mismatch, so an older helper is fenced rather than bricked.

use super::binding::SessionDeltaInfo;
use std::sync::OnceLock;

/// FNV-1a/64 over the canonical wire-name string.
fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        hash ^= u64::from(*b);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// The canonical wire-name list for the session-open delta, derived by
/// serializing a default record and reading the object's keys.
///
/// Serializing is what makes this derived: serde emits exactly the wire names,
/// with `rename` already applied. `SessionDeltaInfo` carries no
/// `skip_serializing_if`, so a default record emits every field.
pub(crate) fn session_delta_wire_names() -> Vec<String> {
    let value = serde_json::to_value(SessionDeltaInfo::default())
        .expect("SessionDeltaInfo must serialize");
    let mut names: Vec<String> = match value {
        serde_json::Value::Object(map) => map.keys().cloned().collect(),
        // Not reachable for a struct, but a panic here would take the
        // dataplane down over a diagnostic. An empty list yields a
        // fingerprint the Go side cannot match, which fails closed.
        _ => Vec::new(),
    };
    names.sort();
    names
}

/// Canonical string the fingerprint is taken over. Separate from the hash so a
/// test can diff the STRING when two fingerprints disagree — comparing two
/// u64s tells you that they differ and nothing about why.
pub(crate) fn session_delta_schema_canonical() -> String {
    session_delta_wire_names().join("\n")
}

/// Stable fingerprint of the session-open delta wire schema.
///
/// 0 is reserved for "not advertised" and is never returned for a real schema:
/// FNV-1a of a non-empty canonical string cannot be 0 in practice, and an empty
/// schema is itself a fail-closed condition.
pub(crate) fn session_delta_schema_fingerprint() -> u64 {
    static FP: OnceLock<u64> = OnceLock::new();
    *FP.get_or_init(|| {
        let canonical = session_delta_schema_canonical();
        if canonical.is_empty() {
            return 0;
        }
        fnv1a64(canonical.as_bytes())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_derived_from_the_wire_names_7194() {
        let names = session_delta_wire_names();
        // Anti-vacuity: a truncated or empty extraction must not be able to
        // report a confident fingerprint. 35 is comfortably under the current
        // count and matches the parity guard's floor.
        assert!(
            names.len() >= 35,
            "expected the full session-delta schema, got {} names: {names:?}",
            names.len()
        );
        assert!(names.contains(&"timestamp".to_string()));
        assert!(names.contains(&"rt_flow_session_id".to_string()));
        assert!(names.contains(&"nat64_snat_v4".to_string()));
        assert_ne!(session_delta_schema_fingerprint(), 0);
    }

    #[test]
    fn fingerprint_changes_when_the_wire_set_changes_7194() {
        // The property that makes this non-forgettable: a different name set
        // must produce a different fingerprint. Computed directly rather than
        // by mutating the struct, so the test states the property itself.
        let base = session_delta_schema_canonical();
        let with_extra = {
            let mut n = session_delta_wire_names();
            n.push("a_new_field".to_string());
            n.sort();
            n.join("\n")
        };
        assert_ne!(
            fnv1a64(base.as_bytes()),
            fnv1a64(with_extra.as_bytes()),
            "adding a wire field must change the fingerprint"
        );
    }

    // The Go mirror must produce the SAME u64. Neither side is pinned to the
    // other's output; both are pinned to the PUBLISHED FNV-1a/64 vectors, so
    // "they agree" is a consequence of both being correct rather than of one
    // having been copied from the other.
    #[test]
    fn fnv1a64_matches_the_published_vectors_7194() {
        assert_eq!(fnv1a64(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a64(b"a"), 0xaf63_dc4c_8601_ec8c);
        assert_eq!(fnv1a64(b"foobar"), 0x85944171f73967e8);
    }

    // #7194 M7: the mutation matrix found that deleting the lifecycle stamp
    // escapes every other test. That is the worst failure mode this mechanism
    // has -- an unstamped helper advertises 0, 0 is deliberately PERMITTED as
    // "not advertised", and the gate silently becomes inert forever. The wire
    // fixture cannot catch it either: its specimen is a ProcessStatus::default()
    // that already carries 0.
    //
    // So bind the WIRING, not the function it calls. Comments are stripped
    // first: a source-scanning guard that can be satisfied by its own doc
    // comment quoting the line it greps for is no guard at all -- and this very
    // comment names the symbol.
    #[test]
    fn lifecycle_stamps_the_fingerprint_into_process_status_7194() {
        let src = include_str!("../server/lifecycle.rs");
        let code: String = src
            .lines()
            .map(|l| match l.find("//") {
                Some(i) => &l[..i],
                None => l,
            })
            .collect::<Vec<_>>()
            .join("\n");

        // Whitespace-squashed so the assertion survives rustfmt wrapping the
        // call onto a continuation line.
        let squashed: String = code.chars().filter(|c| !c.is_whitespace()).collect();

        // The DISCRIMINATOR is the CALL, not the field name. A first version of
        // this guard asserted on "session_delta_schema_fingerprint" and the
        // paired mutation cell walked straight through it: replacing the call
        // with `session_delta_schema_fingerprint: 0,` leaves that substring
        // intact, because it is the FIELD name. A guard that matches both the
        // correct and the broken form is decoration.
        assert!(
            squashed.contains("session_delta_schema::session_delta_schema_fingerprint()"),
            "lifecycle.rs must CALL session_delta_schema_fingerprint() when \
             building ProcessStatus. Assigning a literal instead makes the \
             helper advertise 0, which the Go gate permits as \"not \
             advertised\", so the whole mechanism goes silently inert"
        );
        // Anti-vacuity: prove the stripper did not eat the file. If this fails
        // the assertion above is meaningless.
        assert!(
            code.contains("ProcessStatus"),
            "comment stripping destroyed the source; the guard above is vacuous"
        );
    }

    #[test]
    fn canonical_form_is_sorted_and_newline_joined_7194() {
        let canonical = session_delta_schema_canonical();
        let parts: Vec<&str> = canonical.split('\n').collect();
        let mut sorted = parts.clone();
        sorted.sort_unstable();
        assert_eq!(parts, sorted, "canonical form must be sorted");
        assert!(!canonical.ends_with('\n'), "no trailing newline");
    }
}
