//! #2387 VRF/routing-instance session-identity decision-record guard.
//!
//! `userspace-dp/src/afxdp/forwarding/README.md` documents the single-
//! forwarding-domain session-identity limitation and cites
//! `docs/research/2387-vrf-flow-identity/plan.md` as the decision record for
//! the deferred real fix (Track B). That plan lived ONLY on the unmerged
//! `research/2387-vrf-flow-identity` branch, so the in-tree citation dangled —
//! the same failure the #3643/#3651 guard (`pkg/api/zone_counter_doc_ref_test.go`)
//! exists to prevent, which its own comment records happening once before.
//!
//! FAIL-ON-REVERT: deleting the plan doc, dropping its §0 anchors, or restoring
//! the superseded "the fix needs an HA session-sync wire bump" wording in the
//! README makes this test go RED.
//!
//! The doc claims are also bound to the code they describe, so the decision
//! record cannot silently drift away from the runtime:
//!   * `SessionKey` is still the bare 5-tuple (no routing-domain field). When
//!     Track B lands this assertion fires and the README/plan MUST be updated
//!     in the same change — that is the point.
//!   * `install_with_protocol_with_origin` still opens with an unconditional
//!     `remove_entry(&key)`, which is why "decline the cross-domain hit and
//!     fall through to the session-miss path" is not a viable cheap mitigation
//!     (the two colliding flows would evict each other per packet).
//!   * `pkg/cluster/sync_protocol.go` still uses length-gated trailing VALUE
//!     fields, which is why the domain can be carried additively with no
//!     `CurrentHAProtocolVersion` bump (plan §0a, correcting plan §4d).

use std::fs;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("userspace-dp should live directly under the repo root")
        .to_path_buf()
}

fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|e| panic!("cannot read {}: {}", path.display(), e))
}

#[test]
fn vrf_session_identity_decision_record_exists_and_matches_runtime() {
    let root = repo_root();
    let plan_rel = "docs/research/2387-vrf-flow-identity/plan.md";
    let plan_path = root.join(plan_rel);
    let readme_path = root.join("userspace-dp/src/afxdp/forwarding/README.md");

    let readme = read(&readme_path);

    // The README must still be the citer; if the citation is dropped, this
    // guard has no subject and should be deleted deliberately, not silently.
    assert!(
        readme.contains(plan_rel),
        "{} must cite the #2387 decision record {plan_rel}",
        readme_path.display()
    );

    // The decision record itself must be on master, not stranded on a research
    // branch. `read` panics with the path when it is missing.
    let plan = read(&plan_path);

    for anchor in [
        "## 0. v5 engineering-time addendum",
        "### 0a.",
        "does NOT bump SessionSyncWireVersion",
        "install.rs:139",
        "**DENY**",
        "**ISOLATE**",
    ] {
        assert!(
            plan.contains(anchor),
            "{} must keep the {anchor:?} anchor the #2387 README claims rest on",
            plan_path.display()
        );
    }

    // The superseded cost claim (plan §4d as applied to a VALUE-carried domain)
    // must not come back into the shipped README: the fix does NOT need an HA
    // protocol-version bump.
    assert!(
        !readme.contains("wire bump"),
        "{} still carries the superseded \"HA session-sync wire bump\" claim for #2387; \
         the routing-domain rides as a length-gated trailing VALUE field (plan §0a)",
        readme_path.display()
    );
    for required in [
        "The HA session-sync wire does NOT need a version bump",
        "`CurrentHAProtocolVersion` never moves.",
        "Do NOT \"decline the hit and fall through\"",
    ] {
        assert!(
            readme.contains(required),
            "{} must document {required:?} (#2387 plan §0)",
            readme_path.display()
        );
    }
}

#[test]
fn vrf_session_identity_doc_claims_still_match_the_code() {
    let root = repo_root();

    // Claim 1: the identity is still the bare 5-tuple. When Track B widens it,
    // this fires so the decision record is updated in the same change.
    let key_rs = read(&root.join("userspace-dp/src/session/key.rs"));
    assert!(
        !key_rs.contains("routing_domain"),
        "SessionKey grew a routing-domain discriminator — update the #2387 \
         decision record (docs/research/2387-vrf-flow-identity/plan.md) and the \
         \"Session identity is NOT VRF-aware\" section of \
         userspace-dp/src/afxdp/forwarding/README.md in this change"
    );

    // Claim 2: session install unconditionally evicts a same-key incumbent,
    // which is why declining a cross-domain hit and falling through to the
    // session-miss path is not a viable mitigation.
    let install_rs = read(&root.join("userspace-dp/src/session/install.rs"));
    assert!(
        install_rs.contains("let _previous = self.remove_entry(&key);"),
        "session install no longer unconditionally evicts a same-key incumbent — \
         the #2387 README/plan rationale for rejecting \"decline the hit and fall \
         through\" no longer holds and must be revisited"
    );

    // Claim 3: the cross-chassis session wire still grows by length-gated
    // trailing VALUE fields, so a routing-domain is an append, not a flag day.
    let sync_go = read(&root.join("pkg/cluster/sync_protocol.go"));
    assert!(
        sync_go.contains("length-gated trailing field"),
        "pkg/cluster/sync_protocol.go lost its length-gated trailing-field \
         contract — the #2387 plan §0a \"no HA protocol-version bump\" finding \
         must be re-derived"
    );
    assert!(
        sync_go.contains("if off+8 <= len(payload)"),
        "pkg/cluster/sync_protocol.go lost the bounds-gated trailing-field \
         decode that makes an absent #2387 routing-domain decode as the default \
         routing-instance for a legacy peer"
    );

    // Claim 4: the Rust<->Go control-socket session sync is serde-defaulted, so
    // the same append is additive there too.
    let control_rs = read(&root.join("userspace-dp/src/protocol/control.rs"));
    let sync_req = control_rs
        .split_once("pub(crate) struct SessionSyncRequest {")
        .expect("SessionSyncRequest struct should exist in protocol/control.rs")
        .1;
    let sync_req_body = sync_req
        .split_once("\n}")
        .expect("SessionSyncRequest struct should be brace-terminated")
        .0;
    assert!(
        sync_req_body.contains("serde(default)"),
        "SessionSyncRequest is no longer serde-defaulted — the #2387 plan §0a \
         additive control-socket finding must be re-derived"
    );
}
