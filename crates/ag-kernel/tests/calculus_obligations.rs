//! Consistency checks for the descriptive Lean/Rust obligation ledger.

use std::collections::BTreeSet;

use ag_kernel::{ADMISSIBILITY_CALCULUS_RELEASE_V1, ADMISSIBILITY_CALCULUS_REVISION_V1};
use serde_json::Value;

const LEDGER: &str = include_str!("../../../docs/formal-calculus-obligations.json");

#[test]
fn obligation_ledger_is_closed_versioned_and_matches_the_adapter() {
    let ledger: Value = serde_json::from_str(LEDGER).expect("valid obligation JSON");
    assert_eq!(ledger["schema"], "ag.formal-calculus-obligations/v1");
    assert_eq!(
        ledger["baseline"]["revision"],
        ADMISSIBILITY_CALCULUS_REVISION_V1
    );
    assert_eq!(
        ledger["baseline"]["release"],
        ADMISSIBILITY_CALCULUS_RELEASE_V1
    );
    assert_eq!(
        ledger["authority_fence"],
        "lean_theorems_are_specification_evidence_and_never_runtime_authority"
    );

    let allowed: BTreeSet<&str> = [
        "unmapped",
        "structural_only",
        "partially_correspondent",
        "qualified",
    ]
    .into_iter()
    .collect();
    let obligations = ledger["obligations"].as_array().expect("obligation array");
    assert!(!obligations.is_empty());
    let mut ids = BTreeSet::new();
    let mut rungs = BTreeSet::new();
    for obligation in obligations {
        let id = obligation["id"].as_str().expect("obligation ID");
        assert!(ids.insert(id), "duplicate obligation ID {id}");
        let status = obligation["status"].as_str().expect("obligation status");
        assert!(allowed.contains(status), "unknown status {status}");
        assert!(
            obligation["gaps"].is_array(),
            "obligation {id} must disclose its gaps"
        );
        if let Some(rung) = obligation["rung"].as_u64() {
            rungs.insert(rung);
        }
    }
    assert_eq!(rungs, BTreeSet::from([1, 2, 3, 4, 5, 6, 7]));

    for required in [
        "CALC-ID-001",
        "CALC-LOC-001",
        "CALC-INSTANCE-001",
        "CALC-SER-001",
        "CALC-ORD-001",
        "CALC-REF-001",
        "CALC-TOT-001",
        "CALC-PROV-001",
        "CALC-CMP-001",
        "CALC-HIST-001",
        "CALC-STATE-001",
        "CALC-REPLAY-001",
        "CALC-VERSION-001",
    ] {
        assert!(ids.contains(required), "missing obligation {required}");
    }
}
