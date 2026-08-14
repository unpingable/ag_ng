//! Ordinary-gate tests for AG's complete producer/Docket-consumer wire corpus.

use super::*;
use ag_primitives::{Digest, JcsDocument};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;

const WIRE_VECTORS: &[u8] =
    include_bytes!("../../../conformance/governed-repair-r2/wire-vectors.v1.json");
const WIRE_HOSTILES: &[u8] =
    include_bytes!("../../../conformance/governed-repair-r2/wire-hostiles.v1.json");

fn corpus() -> Value {
    serde_json::from_slice(WIRE_VECTORS).expect("pinned wire corpus")
}

fn canonical_body(vector: &Value) -> &str {
    vector["canonical"]
        .as_str()
        .expect("canonical vector bytes")
}

fn round_trip<T>(vector: &Value) -> T
where
    T: DeserializeOwned + Serialize,
{
    let typed: T = serde_json::from_value(vector["value"].clone()).expect("typed wire vector");
    assert_eq!(
        JcsDocument::canonicalize(&typed).unwrap().as_str(),
        canonical_body(vector),
        "typed producer/consumer spelling drifted from the exact corpus"
    );
    typed
}

fn assert_digest(actual: &str, vector: &Value, name: &str) {
    assert_eq!(actual, vector["identities"][name].as_str().unwrap());
}

#[test]
fn actual_ag_records_round_trip_and_reproduce_all_corpus_identities() {
    let corpus = corpus();
    for name in [
        "ag_issuance_checkpoint_diff_absent",
        "ag_issuance_checkpoint_diff_present",
    ] {
        let vector = &corpus["records"][name];
        let typed: AgIssuanceV2 = round_trip(vector);
        assert_digest(typed.issuance.as_str(), vector, "issuance");
        assert_digest(typed.effect_scope.digest().as_str(), vector, "scope");
        assert_eq!(
            typed
                .governed_repair_checkpoint
                .as_ref()
                .and_then(|checkpoint| checkpoint.diff_identity.as_ref()),
            (name.ends_with("present"))
                .then(|| {
                    let value = vector["value"]["governed_repair_checkpoint"]["diff_identity"]
                        .as_str()
                        .unwrap();
                    Digest::parse(value).unwrap()
                })
                .as_ref()
        );
    }

    let vector = &corpus["records"]["docket_custody"];
    let custody: DocketCustodyV1 = round_trip(vector);
    assert_digest(custody.reference().as_str(), vector, "custody");

    let vector = &corpus["records"]["docket_settlement"];
    let settlement: DocketSettlementWireR2 = round_trip(vector);
    let model = settlement.into_model().unwrap();
    assert_digest(
        model.expected_reference().unwrap().as_str(),
        vector,
        "settlement",
    );
    assert_digest(
        model
            .cumulative_effect_journal_identity
            .as_ref()
            .unwrap()
            .as_str(),
        vector,
        "cumulative_effect_journal",
    );

    let vector = &corpus["records"]["docket_indeterminate"];
    let indeterminate: IndeterminateOutcomeV1 = round_trip(vector);
    assert_digest(
        indeterminate.reconciliation.as_str(),
        vector,
        "reconciliation",
    );

    for vector in corpus["refusals"].as_array().unwrap() {
        let _: DocketIssuanceRefusalWireV1 = round_trip(vector);
        let typed: DocketIssuanceRefusalV1 =
            serde_json::from_value(vector["value"].clone()).unwrap();
        assert_digest(typed.derived_identity().as_str(), vector, "refusal");
    }
}

#[test]
fn every_closed_acceptance_and_reconciliation_variant_round_trips() {
    let corpus = corpus();
    for vector in corpus["acceptance_variants"].as_object().unwrap().values() {
        let _: DocketAcceptanceWireV1 = round_trip(vector);
    }
    for vector in corpus["reconciliation_variants"]
        .as_object()
        .unwrap()
        .values()
    {
        let _: DocketReconciliationWireV1 = round_trip(vector);
    }
}

#[test]
fn both_governed_result_families_reproduce_requirement_checkpoint_and_seal() {
    let corpus = corpus();
    let issuance: AgIssuanceV2 =
        round_trip(&corpus["records"]["ag_issuance_checkpoint_diff_absent"]);
    let custody: DocketCustodyV1 = round_trip(&corpus["records"]["docket_custody"]);
    for name in [
        "governed_scope_expansion_result",
        "governed_readjudication_result",
    ] {
        let vector = &corpus["records"][name];
        let typed: DocketSealedResultWireV1 = round_trip(vector);
        let expected_requirement = match &typed.outcome {
            DocketSealedRequirementWireV1::ScopeExpansionRequired(value) => {
                docket_scope_requirement_identity(value)
            }
            DocketSealedRequirementWireV1::ReadjudicationRequired(value) => {
                docket_readjudication_identity(value)
                    .expect("the pinned readjudication vector is semantically valid")
            }
        };
        assert_digest(
            expected_requirement.as_str(),
            vector,
            "requirement_identity",
        );
        assert_digest(
            docket_checkpoint_identity(&typed.checkpoint).as_str(),
            vector,
            "checkpoint_identity",
        );
        assert_digest(
            docket_sealed_result_identity(&typed.checkpoint).as_str(),
            vector,
            "sealed_result_identity",
        );
        adapt_docket_result(&issuance, &custody, typed)
            .expect("the exact corpus result crosses the real AG adapter");
    }
}

fn mutate(mut value: Value, pointer: &str, replacement: Value) -> Value {
    let (parent, member) = pointer.rsplit_once('/').expect("non-root pointer");
    let target = value
        .pointer_mut(parent)
        .expect("hostile pointer names an exact vector member");
    if let Some(object) = target.as_object_mut() {
        object.insert(member.to_owned(), replacement);
    } else if let Some(array) = target.as_array_mut() {
        array[member.parse::<usize>().unwrap()] = replacement;
    } else {
        panic!("hostile pointer parent is neither object nor array");
    }
    value
}

fn canonical_decode<T: DeserializeOwned>(value: &Value) -> Result<T, String> {
    JcsDocument::canonicalize(value)
        .map_err(|error| error.to_string())?
        .decode::<T>()
        .map_err(|error| error.to_string())
}

fn base_value<'a>(corpus: &'a Value, name: &str) -> &'a Value {
    &corpus["records"][name]["value"]
}

#[test]
fn hostile_optional_unknown_integer_and_identity_mutations_refuse_at_the_boundary() {
    let corpus = corpus();
    let hostiles: Value = serde_json::from_slice(WIRE_HOSTILES).unwrap();
    for case in hostiles["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let base = case["base"].as_str().unwrap();
        let replacement = if case["value_encoding"] == "json_integer_decimal" {
            serde_json::from_str::<Value>(case["value"].as_str().unwrap())
                .expect("hostile decimal spelling must be a JSON number")
        } else {
            case["value"].clone()
        };
        let mutated = mutate(
            base_value(&corpus, base).clone(),
            case["pointer"].as_str().unwrap(),
            replacement,
        );
        let result = match base {
            "ag_issuance_checkpoint_diff_absent" => canonical_decode::<AgIssuanceV2>(&mutated)
                .and_then(|value| {
                    let original = &corpus["records"]["ag_issuance_checkpoint_diff_absent"];
                    let exact_identity = value.issuance.as_str()
                        == original["identities"]["issuance"].as_str().unwrap();
                    let exact_scope =
                        value.effect_scope.digest().as_str() == value.effect_scope_digest.as_str();
                    if exact_identity && exact_scope {
                        Ok(())
                    } else {
                        Err("issuance/scope identity substitution".to_owned())
                    }
                }),
            "docket_settlement" => {
                canonical_decode::<DocketSettlementWireR2>(&mutated).and_then(|wire| {
                    wire.into_model()
                        .map(|_| ())
                        .map_err(|error| error.to_string())
                })
            }
            "governed_scope_expansion_result" => {
                canonical_decode::<DocketSealedResultWireV1>(&mutated).and_then(|wire| {
                    let issuance: AgIssuanceV2 =
                        round_trip(&corpus["records"]["ag_issuance_checkpoint_diff_absent"]);
                    let custody: DocketCustodyV1 = round_trip(&corpus["records"]["docket_custody"]);
                    adapt_docket_result(&issuance, &custody, wire)
                        .map(|_| ())
                        .map_err(|error| error.to_string())
                })
            }
            _ => panic!("hostile corpus names unknown base {base}"),
        };
        assert!(
            result.is_err(),
            "hostile case unexpectedly acquired a valid exact interpretation: {name}"
        );
    }
}
