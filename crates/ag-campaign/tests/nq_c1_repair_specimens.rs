//! Immutable NQ C1 history as non-authorizing AG boundary specimens.

use ag_campaign::external_repair_specimen::{ExternalRepairBoundaryV1, NqC1ImmutableSpecimenV1};
use ag_primitives::{Digest, JcsDocument};
use serde_json::{Value, json};

const REJECTED: &[u8] = include_bytes!("fixtures/nq-c1/rejected-candidate.v1.json");
const PRE_SPEND: &[u8] = include_bytes!("fixtures/nq-c1/scope-discovery-pre-spend.v1.json");
const POST_SPEND: &[u8] = include_bytes!("fixtures/nq-c1/consumed-repair-hard-stop.v1.json");
const ARCHITECTURE: &[u8] = include_bytes!("fixtures/nq-c1/architectural-readjudication.v1.json");

fn parse(bytes: &[u8]) -> NqC1ImmutableSpecimenV1 {
    NqC1ImmutableSpecimenV1::parse_fixture_file(bytes)
        .expect("checked-in fixture must be exact")
        .0
}

fn canonical_mutation(bytes: &[u8], mutate: impl FnOnce(&mut Value)) -> Vec<u8> {
    let body = bytes.strip_suffix(b"\n").unwrap();
    let mut value: Value = serde_json::from_slice(body).unwrap();
    mutate(&mut value);
    JcsDocument::canonicalize(&value)
        .unwrap()
        .as_bytes()
        .to_vec()
}

#[test]
fn all_fixture_byte_identities_are_frozen() {
    let expected = [
        (
            REJECTED,
            "sha256:6f72de0980d193daa01c420ff89e381aac81e53ed5605d3b51405620bf3fde45",
            "sha256:52b6d6ef41b8e0c96656cc1250cb0ae67b4d974ea29ddc561f3863e3f8ac8cbb",
        ),
        (
            PRE_SPEND,
            "sha256:c4071eb72f7c80b97c7eb7b9b1abafeaeea515241f5901df43e521806ada443f",
            "sha256:d58c797690da977a367b84c56d2cf9e4223f1413fba9e58ae68c009a2541f6ac",
        ),
        (
            POST_SPEND,
            "sha256:29fbc178281f9a9256f89def4c904ea124251979ee39a9aad965a4d68ecefedf",
            "sha256:1a04b287380d6082d5d13c97bc74f8f1ffca5c527c1e3d550817409bc59e4973",
        ),
        (
            ARCHITECTURE,
            "sha256:f886416da38cf10a1243f2c1fe8635ff3bce6db28c2ae1a0e1e7c18f7087d8c0",
            "sha256:54e7ffa237b5df4f0606c8073e7ae6f60178406c1604761089ad845082242909",
        ),
    ];

    for (bytes, exact_digest, semantic_digest) in expected {
        let (_, identity) = NqC1ImmutableSpecimenV1::parse_fixture_file(bytes).unwrap();
        assert_eq!(identity.exact_bytes, Digest::parse(exact_digest).unwrap());
        assert_eq!(
            identity.ag_semantic,
            Digest::parse(semantic_digest).unwrap()
        );
        assert_ne!(identity.exact_bytes, identity.ag_semantic);
    }
}

#[test]
fn rejected_cut_is_exact_and_remains_non_authorizing() {
    let specimen = parse(REJECTED);
    assert_eq!(
        specimen.boundary(),
        ExternalRepairBoundaryV1::RejectedCandidate
    );
    assert!(!specimen.can_mint_authority());

    let NqC1ImmutableSpecimenV1::RejectedCandidate {
        candidate_commit,
        candidate_tree,
        evidence_packet_identity,
        fresh_review_required,
        gen4_active_commit,
        review_artifact_identity,
        verdict,
        ..
    } = specimen
    else {
        unreachable!()
    };
    assert_eq!(candidate_commit, "74975e6d0ede1ffb0f090a1b5e91e4624ce39783");
    assert_eq!(candidate_tree, "9c4f067cc13861e43b32dba11651ce6904c606fd");
    assert_eq!(
        evidence_packet_identity.as_str(),
        "sha256:cae53d904e741e8286188f7be21bb6f4096a88b3a9eda6cfac6b32a051aadd2d"
    );
    assert_eq!(
        review_artifact_identity.as_str(),
        "sha256:909777824789e9e70c7868c7c22e269a178656b99526c50f204023394e1f8c05"
    );
    assert_eq!(verdict, "REJECTED_REPAIR_ELIGIBLE");
    assert!(fresh_review_required);
    assert_eq!(
        gen4_active_commit,
        "b185039450ad185b5ea159f9237637c1a0c0486b"
    );
}

#[test]
fn the_two_scope_discoveries_cannot_collapse_into_one_authority_story() {
    let before = parse(PRE_SPEND);
    let after = parse(POST_SPEND);
    assert_eq!(
        before.boundary(),
        ExternalRepairBoundaryV1::ScopeDiscoveryBeforeSpend
    );
    assert_eq!(
        after.boundary(),
        ExternalRepairBoundaryV1::ConsumedRepairHardStop
    );
    assert!(!before.can_mint_authority());
    assert!(!after.can_mint_authority());

    let NqC1ImmutableSpecimenV1::ScopeDiscoveryPreSpend {
        authorization_consumed,
        authorized_path_count,
        discovered_missing_path,
        source_mutation_attempted,
        ..
    } = before
    else {
        unreachable!()
    };
    assert!(!authorization_consumed);
    assert!(!source_mutation_attempted);
    assert_eq!(authorized_path_count, 28);
    assert_eq!(
        discovered_missing_path,
        "crates/nq-store/src/governed_projection_capacity.rs"
    );

    let NqC1ImmutableSpecimenV1::ConsumedRepairHardStop {
        authorization_consumed,
        authorization_consumed_at,
        authorization_reusable,
        authorized_path_count,
        changed_paths,
        checkpoint_commit,
        checkpoint_tree,
        diff_identity,
        next_missing_path,
        tests_or_builds_run,
        ..
    } = after
    else {
        unreachable!()
    };
    assert!(authorization_consumed);
    assert!(!authorization_reusable);
    assert_eq!(authorization_consumed_at, "2026-08-13T03:26:17Z");
    assert_eq!(authorized_path_count, 29);
    assert_eq!(changed_paths.len(), 7);
    assert_eq!(
        checkpoint_commit,
        "e9a3d371308562b6c8571215bfba95cfd4ccbc45"
    );
    assert_eq!(checkpoint_tree, "6026c2ef51b156e81079085ef71711309a3416d9");
    assert_eq!(
        diff_identity.as_str(),
        "sha256:4fca39e21209de3225d77b342df467c64e943c5cf975048568c377c15386f735"
    );
    assert_eq!(
        next_missing_path,
        "crates/nq-host-role-contract/assets/schemas/nq.v3_projection_capsule_bound_manifest.v2.schema.json"
    );
    assert!(!tests_or_builds_run);
}

#[test]
fn architecture_readjudication_is_structurally_exclusive_from_bounded_repair() {
    let specimen = parse(ARCHITECTURE);
    assert_eq!(
        specimen.boundary(),
        ExternalRepairBoundaryV1::ArchitecturalReadjudicationRequired
    );
    let NqC1ImmutableSpecimenV1::ArchitecturalReadjudication {
        additional_diagnostic_path_count,
        architecture_required,
        core_path_count,
        diagnostic_file_count,
        diagnostic_reference_count,
        existing_source_scope_admissible,
        overlap_path_count,
        ..
    } = specimen
    else {
        unreachable!()
    };
    assert!(architecture_required);
    assert!(!existing_source_scope_admissible);
    assert_eq!(core_path_count, 32);
    assert_eq!(diagnostic_reference_count, 945);
    assert_eq!(diagnostic_file_count, 33);
    assert_eq!(overlap_path_count, 10);
    assert_eq!(additional_diagnostic_path_count, 23);
}

#[test]
fn strict_fixture_parser_refuses_transport_and_shape_substitution() {
    let body = REJECTED.strip_suffix(b"\n").unwrap();
    assert!(NqC1ImmutableSpecimenV1::parse_canonical(body).is_ok());
    assert!(NqC1ImmutableSpecimenV1::parse_fixture_file(body).is_err());
    assert!(NqC1ImmutableSpecimenV1::parse_fixture_file(&[REJECTED, b"\n"].concat()).is_err());
    assert!(NqC1ImmutableSpecimenV1::parse_canonical(REJECTED).is_err());

    let unknown = canonical_mutation(REJECTED, |value| {
        value
            .as_object_mut()
            .unwrap()
            .insert("standing".into(), json!(true));
    });
    assert!(NqC1ImmutableSpecimenV1::parse_canonical(&unknown).is_err());

    let foreign_schema = canonical_mutation(REJECTED, |value| {
        value["schema"] = json!("nq.c1_gen5_live_c2.repair_authority.v1");
    });
    assert!(NqC1ImmutableSpecimenV1::parse_canonical(&foreign_schema).is_err());
}

#[test]
fn state_and_scope_mutations_refuse_even_when_recanonicalized() {
    let spent_too_early = canonical_mutation(PRE_SPEND, |value| {
        value["authorization_consumed"] = json!(true);
    });
    assert!(NqC1ImmutableSpecimenV1::parse_canonical(&spent_too_early).is_err());

    let reusable = canonical_mutation(POST_SPEND, |value| {
        value["authorization_reusable"] = json!(true);
    });
    assert!(NqC1ImmutableSpecimenV1::parse_canonical(&reusable).is_err());

    let widened = canonical_mutation(POST_SPEND, |value| {
        value["changed_paths"][0]["path"] = json!("crates/outside-scope.rs");
    });
    assert!(NqC1ImmutableSpecimenV1::parse_canonical(&widened).is_err());

    let laundering = canonical_mutation(ARCHITECTURE, |value| {
        value["existing_source_scope_admissible"] = json!(true);
    });
    assert!(NqC1ImmutableSpecimenV1::parse_canonical(&laundering).is_err());
}
