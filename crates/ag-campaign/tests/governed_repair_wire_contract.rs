//! AG-owned wire-contract and shared-label conformance pins.

use ag_campaign::governed::{
    CanonicalEffectOperationV1, CanonicalEffectResourceV1, CanonicalEffectScopeV1,
    governed_wire_label_is_canonical_v1,
};
use ag_primitives::{Digest, JcsDocument};

const CONTRACT: &[u8] = include_bytes!("../../../conformance/governed-repair-r2/contract.v1.json");
const MANIFEST: &[u8] = include_bytes!("../../../conformance/governed-repair-r2/manifest.v1.json");
const LABELS: &[u8] = include_bytes!("../../../conformance/governed-repair-r2/labels.v1.json");
const RECONCILIATION_ROUNDS: &[u8] =
    include_bytes!("../../../conformance/governed-repair-r2/reconciliation-rounds.v1.json");
const SCOPES: &[u8] = include_bytes!("../../../conformance/governed-repair-r2/scopes.v1.json");
const WIRE_HOSTILES: &[u8] =
    include_bytes!("../../../conformance/governed-repair-r2/wire-hostiles.v1.json");
const WIRE_VECTORS: &[u8] =
    include_bytes!("../../../conformance/governed-repair-r2/wire-vectors.v1.json");
const CONTRACT_SHA256: &str =
    "sha256:d3fc470761d8550f733e2528f0a2589e93717bd120e9b1ffbae687942168458b";
const LABELS_SHA256: &str =
    "sha256:47a2a8d97e700c0296044d5bb7d795e51b609860875062aaa633ced7498215b6";
const SCOPES_SHA256: &str =
    "sha256:905e9b96ba81a2dcc072f243b3bb1b8a02381377b2cebf61e98eaff033c3abaa";
const MANIFEST_SHA256: &str =
    "sha256:74c429d8d32341fc31fba45e4cdd1a0b6d994bace4c7d4d8ccfccfc9dad8aded";
const RECONCILIATION_ROUNDS_SHA256: &str =
    "sha256:408a2fe3ddf75621c43da441cbdcd33c7fe0845abadd9b02adc72038d01496fc";
const WIRE_HOSTILES_SHA256: &str =
    "sha256:9862a1e38bb9db11cd39aebe04b3bd8ffaed7d315b67becc1e164176a20858b9";
const WIRE_VECTORS_SHA256: &str =
    "sha256:ff75b856fd1a3076809d26f40d987b114046226aa15e7eeeb46db3388f36ea90";

#[test]
fn canonical_contract_and_label_corpus_have_pinned_exact_bytes() {
    let canonical_body = |bytes: &'static [u8]| {
        bytes
            .strip_suffix(b"\n")
            .expect("checked-in JSON contract ends with one text-file newline")
    };
    JcsDocument::from_canonical_bytes(canonical_body(CONTRACT))
        .expect("contract body must be exact canonical JSON");
    JcsDocument::from_canonical_bytes(canonical_body(MANIFEST))
        .expect("manifest body must be exact canonical JSON");
    JcsDocument::from_canonical_bytes(canonical_body(LABELS))
        .expect("label corpus body must be exact canonical JSON");
    JcsDocument::from_canonical_bytes(canonical_body(RECONCILIATION_ROUNDS))
        .expect("reconciliation-round corpus body must be exact canonical JSON");
    JcsDocument::from_canonical_bytes(canonical_body(SCOPES))
        .expect("scope corpus body must be exact canonical JSON");
    JcsDocument::from_canonical_bytes(canonical_body(WIRE_HOSTILES))
        .expect("wire hostile corpus body must be exact canonical JSON");
    JcsDocument::from_canonical_bytes(canonical_body(WIRE_VECTORS))
        .expect("wire vector corpus body must be exact canonical JSON");
    assert_eq!(Digest::hash_bytes(CONTRACT).to_string(), CONTRACT_SHA256);
    assert_eq!(Digest::hash_bytes(MANIFEST).to_string(), MANIFEST_SHA256);
    assert_eq!(Digest::hash_bytes(LABELS).to_string(), LABELS_SHA256);
    assert_eq!(
        Digest::hash_bytes(RECONCILIATION_ROUNDS).to_string(),
        RECONCILIATION_ROUNDS_SHA256
    );
    assert_eq!(Digest::hash_bytes(SCOPES).to_string(), SCOPES_SHA256);
    assert_eq!(
        Digest::hash_bytes(WIRE_HOSTILES).to_string(),
        WIRE_HOSTILES_SHA256
    );
    assert_eq!(
        Digest::hash_bytes(WIRE_VECTORS).to_string(),
        WIRE_VECTORS_SHA256
    );
}

#[test]
fn manifest_closes_the_complete_conformance_corpus() {
    let manifest: serde_json::Value = serde_json::from_slice(MANIFEST).unwrap();
    let expected = [
        ("contract.v1.json", CONTRACT_SHA256),
        ("labels.v1.json", LABELS_SHA256),
        (
            "reconciliation-rounds.v1.json",
            RECONCILIATION_ROUNDS_SHA256,
        ),
        ("scopes.v1.json", SCOPES_SHA256),
        ("wire-hostiles.v1.json", WIRE_HOSTILES_SHA256),
        ("wire-vectors.v1.json", WIRE_VECTORS_SHA256),
    ];
    let files = manifest["files"].as_array().unwrap();
    assert_eq!(files.len(), expected.len());
    for ((path, identity), record) in expected.into_iter().zip(files) {
        assert_eq!(record["path"], path);
        assert_eq!(record["sha256"], identity);
    }
}

#[test]
fn ag_scope_identity_matches_the_shared_corpus() {
    let corpus: serde_json::Value = serde_json::from_slice(SCOPES).unwrap();
    for vector in corpus["vectors"].as_array().unwrap() {
        let scope: CanonicalEffectScopeV1 =
            serde_json::from_value(vector["value"].clone()).unwrap();
        scope.validate().unwrap();
        assert_eq!(scope.canonical_document().as_str(), vector["canonical"]);
        assert_eq!(scope.digest().to_string(), vector["identity"]);
    }
}

#[test]
fn ag_validator_accepts_and_refuses_the_shared_label_corpus() {
    let corpus: serde_json::Value = serde_json::from_slice(LABELS).unwrap();
    for value in corpus["accepted"].as_array().unwrap() {
        let value = value.as_str().unwrap();
        assert!(
            governed_wire_label_is_canonical_v1(value),
            "shared accepted label refused: {value:?}"
        );
    }
    for value in corpus["rejected"].as_array().unwrap() {
        let value = value.as_str().unwrap();
        assert!(
            !governed_wire_label_is_canonical_v1(value),
            "shared rejected label accepted: {value:?}"
        );
    }
    assert!(governed_wire_label_is_canonical_v1(&"a".repeat(128)));
    assert!(!governed_wire_label_is_canonical_v1(&"a".repeat(129)));
}

#[test]
fn mutable_ref_words_are_resource_only_exclusions() {
    let corpus: serde_json::Value = serde_json::from_slice(LABELS).unwrap();
    for value in corpus["effect_class_accepted_resource_rejected"]
        .as_array()
        .unwrap()
    {
        let value = value.as_str().unwrap();
        assert!(governed_wire_label_is_canonical_v1(value));
        assert!(
            CanonicalEffectScopeV1::new(
                value.to_owned(),
                vec![CanonicalEffectResourceV1 {
                    resource: "repository".to_owned(),
                    path: "bounded/path".to_owned(),
                    operations: vec![CanonicalEffectOperationV1::Read],
                }],
            )
            .is_ok(),
            "effect class unexpectedly rejected: {value}"
        );
        assert!(
            CanonicalEffectScopeV1::new(
                "repository-read/v1".to_owned(),
                vec![CanonicalEffectResourceV1 {
                    resource: value.to_owned(),
                    path: "bounded/path".to_owned(),
                    operations: vec![CanonicalEffectOperationV1::Read],
                }],
            )
            .is_err(),
            "mutable-ref resource unexpectedly accepted: {value}"
        );
    }
}
