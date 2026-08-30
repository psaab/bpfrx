// #1345: per-verb handler for sync_session. Body byte-identical to
// handlers.rs lines 309-342 (preserves the nested match on
// sync_req.operation).

use super::super::helpers::{build_synced_session_entry, build_synced_session_key, SyncedKeyIntent};
use super::super::ServerState;
use crate::afxdp::SYNCED_IMPORT_REFUSED_PREFIX;
use crate::{ControlResponse, SessionSyncRequest};

pub(super) fn handle(
    guard: &mut ServerState,
    session_sync: Option<SessionSyncRequest>,
    response: &mut ControlResponse,
) {
    let Some(sync_req) = session_sync else {
        response.ok = false;
        response.error = "missing session sync request".to_string();
        return;
    };
    // #7160 (#2387): resolve the imported session's routing DOMAIN from the
    // #7095 cluster-stable ingress identity, which the sender resolved into
    // THIS node's own ifindex/vlan before the request got here. Derived, never
    // wire-carried — see `Coordinator::synced_routing_domain`.
    //
    // THREE states, and the third is the one that matters. `Some(0)` is the
    // default routing instance and is correct; `Some(n)` is a tenant's; `None`
    // is "this node runs routing instances and the request named nothing to
    // resolve one from". The two verbs answer `None` differently, because the
    // cost of guessing runs opposite ways:
    //   * UPSERT refuses. Importing under domain 0 would file the session in
    //     the DEFAULT instance's identity space, where a reply that resolved
    //     its own domain can reach it through the domain-agnostic fallback
    //     probe — the HA half of the collision #7160 closes.
    //   * DELETE proceeds at domain 0 and lets the per-domain sweep below do
    //     the work. A refused delete LEAKS a session; a delete that sweeps one
    //     domain too many removes nothing that was not named by the 5-tuple.
    let resolved_domain = guard
        .afxdp
        .synced_routing_domain(sync_req.ingress_ifindex, sync_req.ingress_vlan_id);
    match sync_req.operation.as_str() {
        "upsert" if resolved_domain.is_none() => {
            guard.afxdp.note_unknown_routing_domain_import();
            response.ok = false;
            response.error = format!(
                "{SYNCED_IMPORT_REFUSED_PREFIX}{}",
                crate::afxdp::SyncedImportOutcome::RejectedUnknownRoutingDomain
                    .refusal_reason()
                    .expect("a rejection always carries a reason token")
            );
        }
        "upsert" => match build_synced_session_entry(
            &sync_req,
            guard.afxdp.zone_name_to_id_ref(),
            resolved_domain.expect("the None arm above already returned"),
        ) {
            Ok(entry) => {
                // #6785: a SEMANTIC refusal (stale generation / import cap /
                // translated-tuple reserve) used to return `()` and leave
                // `response.ok` true, so Go recorded a success and kept the BPF
                // mirror row for a session this helper never took — the split
                // truth #5305's transactional install already knows how to
                // compensate, but could not, because the only failure it could
                // see was an IPC error. Report the refusal so that rollback runs.
                //
                // The reason token is prefixed so Go can tell a refusal from a
                // transport failure. That distinction is load-bearing, not
                // cosmetic: a transport failure means the session socket is sick
                // and gates takeover-readiness (#5247), whereas a refusal is the
                // correct answer from a HEALTHY helper and must not block
                // failover on a node that is working.
                let outcome = guard.afxdp.upsert_synced_session(entry);
                if let Some(reason) = outcome.refusal_reason() {
                    response.ok = false;
                    response.error =
                        format!("{SYNCED_IMPORT_REFUSED_PREFIX}{reason}");
                }
            }
            Err(err) => {
                response.ok = false;
                response.error = err;
            }
        },
        // #7188: a delete reconstructs the key with `Delete` intent, so a peer
        // that could not state the tunnel discriminator retracts the `None`
        // class rather than being refused. A delete can only under-match; it
        // never publishes an identity, which is the reason the install arm
        // above fails closed and this one does not.
        //
        // #7160 (#2387) makes the identical argument on the ROUTING DOMAIN
        // axis, which is why the two land on the same line: an unresolvable
        // domain refuses on upsert and resolves to 0 here, because a refused
        // delete LEAKS a session while an under-matching one removes nothing
        // the 5-tuple did not already name. Two different fields, one rule —
        // fail closed where an identity is PUBLISHED, fail open where one is
        // only RETRACTED.
        "delete" => match build_synced_session_key(
            &sync_req,
            resolved_domain.unwrap_or(0),
            SyncedKeyIntent::Delete,
        ) {
            Ok(key) => {
                guard.afxdp.delete_synced_session(key.clone());
                // #7160 (#2387): a bare-5-tuple delete (the `clear security
                // flow session` / batch-revoke path) carries no ingress
                // identity, so the key above resolved domain 0 and the exact
                // delete cannot reach a session that lives in a routing
                // instance. Retry once per configured domain so a clear the
                // operator was told succeeded actually revoked the session.
                // Empty — and therefore a no-op — in every deployment with no
                // routing-instance interface membership.
                if key.routing_domain == 0 {
                    for domain in guard.afxdp.routing_domains() {
                        let mut scoped = key.clone();
                        scoped.routing_domain = domain;
                        guard.afxdp.delete_synced_session(scoped);
                    }
                }
            }
            Err(err) => {
                response.ok = false;
                response.error = err;
            }
        },
        other => {
            response.ok = false;
            response.error = format!("unknown session sync operation {other}");
        }
    }
}
