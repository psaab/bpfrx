//! SNAT pool contract/doc drift guard for #1377.

use std::fs;
use std::path::Path;

#[test]
fn snat_contract_documents_current_fail_closed_runtime() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let repo_root = manifest_dir
        .parent()
        .expect("userspace-dp should live directly under the repo root");
    let plan_path = repo_root.join("docs/pr/1373-retire-ebpf-dataplane/plan-1377-snat-pools.md");
    let architecture_path = repo_root.join("docs/userspace-dataplane-architecture.md");
    let gaps_path = repo_root.join("docs/userspace-dataplane-gaps.md");
    // #1327 Step 1 converted the flat poll_descriptor.rs to a directory
    // module. The four source_nat_decision_for_flow call sites all stay
    // in mod.rs (slow-path session resolution, which Step 1 did not
    // attempt to extract — see docs/pr/1327-poll-descriptor-stages/plan.md
    // "Stages 12+ verdict"). Compatibility: keep accepting either layout.
    let poll_path = {
        let flat = manifest_dir.join("src/afxdp/poll_descriptor.rs");
        if flat.exists() {
            flat
        } else {
            manifest_dir.join("src/afxdp/poll_descriptor/mod.rs")
        }
    };

    let plan = fs::read_to_string(&plan_path)
        .unwrap_or_else(|e| panic!("cannot read {}: {}", plan_path.display(), e));
    let architecture = fs::read_to_string(&architecture_path)
        .unwrap_or_else(|e| panic!("cannot read {}: {}", architecture_path.display(), e));
    let gaps = fs::read_to_string(&gaps_path)
        .unwrap_or_else(|e| panic!("cannot read {}: {}", gaps_path.display(), e));
    let poll = fs::read_to_string(&poll_path)
        .unwrap_or_else(|e| panic!("cannot read {}: {}", poll_path.display(), e));

    // Use the actual poll module path in assertion messages and required-doc
    // checks so the test stays accurate across the flat → directory layout
    // transition (#1327 Step 1). Required-doc checks now accept either
    // `userspace-dp/src/afxdp/poll_descriptor.rs` or `.../poll_descriptor/mod.rs`.
    let poll_display = poll_path.display().to_string();
    let poll_module_label = poll_path
        .strip_prefix(repo_root)
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| poll_display.clone());

    let call_lines = source_nat_decision_call_lines(&poll);
    assert_eq!(
        call_lines.len(),
        4,
        "update the #1377 SNAT contract when {poll_module_label} no longer has exactly four source-NAT runtime decision call sites: {call_lines:?}"
    );
    assert!(
        !poll.contains("match_source_nat_for_flow(\n"),
        "{poll_module_label} must not use the legacy Option source-NAT helper"
    );
    assert!(
        !poll.contains("match_source_nat_for_flow(...).unwrap_or_default()"),
        "{poll_module_label} must not document or retain source-NAT unwrap_or_default fail-open handling"
    );
    assert_each_source_nat_call_records_failure(&poll, &call_lines, &poll_module_label);

    // Required tokens for the plan doc. Both poll_descriptor.rs (flat
    // layout) and poll_descriptor/mod.rs (directory layout) are accepted
    // for the path token so the plan doc need not be edited as the
    // userspace-dp tree reorganises.
    let plan_path_token_alternatives = [
        "userspace-dp/src/afxdp/poll_descriptor.rs",
        "userspace-dp/src/afxdp/poll_descriptor/mod.rs",
    ];
    let path_token_present = plan_path_token_alternatives
        .iter()
        .any(|tok| plan.contains(tok));
    assert!(
        path_token_present,
        "{} must mention at least one of {:?} so the #1377 contract tracks current runtime behavior",
        plan_path.display(),
        plan_path_token_alternatives,
    );

    for required in [
        "## Current Fail-Closed Runtime Boundary",
        "match_source_nat_for_flow_result",
        "normal new-session path",
        "pending-neighbor/session-build retry path",
        "fail-closed",
        "record_source_nat_failure",
        "source_nat_pool_missing",
        "source_nat_pool_empty",
        "source_nat_pool_invalid_port_range",
    ] {
        assert!(
            plan.contains(required),
            "{} must mention {:?} so the #1377 contract tracks current runtime behavior",
            plan_path.display(),
            required
        );
    }

    // The enumeration check accepts either path token (per the directory
    // layout switch). The doc enumerates source-NAT sites with the path
    // followed by `:linenum`; tolerate either path style.
    let documented_call_count = plan.matches("poll_descriptor.rs:").count()
        + plan.matches("poll_descriptor/mod.rs:").count();
    assert_eq!(
        documented_call_count,
        call_lines.len(),
        "{} should enumerate the same number of poll-descriptor source-NAT call sites as the code ({call_lines:?})",
        plan_path.display()
    );

    assert_current_capability_doc_matches_fail_closed_contract(&architecture_path, &architecture);
    assert_current_capability_doc_matches_fail_closed_contract(&gaps_path, &gaps);
}

fn source_nat_decision_call_lines(source: &str) -> Vec<usize> {
    source
        .lines()
        .enumerate()
        .filter_map(|(idx, line)| {
            (line.contains("source_nat_decision_for_flow(")
                && !line.contains("fn source_nat_decision_for_flow"))
            .then_some(idx + 1)
        })
        .collect()
}

fn assert_each_source_nat_call_records_failure(
    source: &str,
    call_lines: &[usize],
    module_label: &str,
) {
    let lines: Vec<&str> = source.lines().collect();
    for &line_no in call_lines {
        let start = line_no - 1;
        let end = usize::min(start + 32, lines.len());
        let window = lines[start..end].join("\n");
        assert!(
            window.contains("Err(failure)") && window.contains("record_source_nat_failure("),
            "source-NAT call at {module_label}:{line_no} must record fail-closed failures before forwarding/session creation"
        );
    }
}

fn assert_current_capability_doc_matches_fail_closed_contract(path: &Path, doc: &str) {
    // Accept either `poll_descriptor.rs` (flat layout) or
    // `poll_descriptor/mod.rs` (directory layout post-#1327 Step 1).
    let poll_path_alternatives = ["poll_descriptor.rs", "poll_descriptor/mod.rs"];
    let path_token_present = poll_path_alternatives.iter().any(|tok| doc.contains(tok));
    assert!(
        path_token_present,
        "{} must mention at least one of {:?} so current capability docs match the #1377 runtime contract",
        path.display(),
        poll_path_alternatives,
    );

    for required in [
        "Source NAT",
        "pool",
        "fail-closed",
        "source-NAT call sites",
        "missing pools",
        "empty pools",
        "invalid port",
        "persistent-nat",
        "exhaustion counters",
    ] {
        assert!(
            doc.contains(required),
            "{} must mention {:?} so current capability docs match the #1377 runtime contract",
            path.display(),
            required
        );
    }

    for stale in [
        "runtime remains fail-open",
        "source-NAT call sites can fall through",
        "forward without SNAT",
        "claim userspace pool-mode SNAT is fail-closed",
    ] {
        assert!(
            !doc.contains(stale),
            "{} still contains stale SNAT pool fail-closed wording: {:?}",
            path.display(),
            stale
        );
    }
}
