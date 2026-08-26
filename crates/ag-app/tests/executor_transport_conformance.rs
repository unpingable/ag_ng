//! Independent AG effect-adapter runner for Docket's external V1 corpus.

use ag_app::effect_executor_adapter::{
    DOCKET_EXECUTOR_DISPATCH_SCHEMA_V1, DOCKET_EXECUTOR_MAX_DOCUMENT_BYTES_V1,
    DOCKET_EXECUTOR_OUTCOME_SCHEMA_V1, DOCKET_EXECUTOR_TRANSPORT_SCHEMA_V1,
    EffectExecutorDispatchV1, EffectExecutorOutcomeV1,
};
use ag_primitives::JcsDocument;
use serde_json::Value;

fn decode_dispatch(input: &[u8]) -> Result<(EffectExecutorDispatchV1, String), String> {
    let document = JcsDocument::parse(input).map_err(|error| error.to_string())?;
    let value: EffectExecutorDispatchV1 =
        serde_json::from_slice(document.as_bytes()).map_err(|error| error.to_string())?;
    if value.work_schema.is_empty() {
        return Err("empty work schema".to_owned());
    }
    let canonical = JcsDocument::canonicalize(&value).map_err(|error| error.to_string())?;
    Ok((value, canonical.as_str().to_owned()))
}

fn decode_outcome(input: &[u8]) -> Result<(EffectExecutorOutcomeV1, String), String> {
    let document = JcsDocument::parse(input).map_err(|error| error.to_string())?;
    let value: EffectExecutorOutcomeV1 =
        serde_json::from_slice(document.as_bytes()).map_err(|error| error.to_string())?;
    let canonical = JcsDocument::canonicalize(&value).map_err(|error| error.to_string())?;
    Ok((value, canonical.as_str().to_owned()))
}

#[test]
#[ignore = "set DOCKET_EXECUTOR_TRANSPORT_CORPUS to Docket's V1 corpus"]
fn independently_conforms_to_docket_executor_transport_v1() {
    let path = std::env::var("DOCKET_EXECUTOR_TRANSPORT_CORPUS").expect("corpus path");
    let bytes = std::fs::read(path).expect("read corpus");
    let corpus: Value = serde_json::from_slice(&bytes).expect("decode corpus");
    assert_eq!(corpus["transport"], DOCKET_EXECUTOR_TRANSPORT_SCHEMA_V1);
    assert_eq!(
        corpus["dispatch_schema"],
        DOCKET_EXECUTOR_DISPATCH_SCHEMA_V1
    );
    assert_eq!(corpus["outcome_schema"], DOCKET_EXECUTOR_OUTCOME_SCHEMA_V1);
    assert_eq!(
        corpus["max_document_bytes"].as_u64(),
        Some(DOCKET_EXECUTOR_MAX_DOCUMENT_BYTES_V1)
    );

    for case in corpus["decode_cases"].as_array().expect("decode cases") {
        let input = case["input"].as_str().expect("input").as_bytes();
        let expected = case["expect"].as_str().expect("expect");
        let canonical = match case["kind"].as_str().expect("kind") {
            "dispatch" => decode_dispatch(input).map(|(_, canonical)| canonical),
            "outcome" => decode_outcome(input).map(|(_, canonical)| canonical),
            other => panic!("unknown case kind {other}"),
        };
        assert_eq!(canonical.is_ok(), expected == "accept", "{}", case["id"]);
        if let (Ok(actual), Some(want)) = (canonical, case["canonical_output"].as_str()) {
            assert_eq!(actual, want, "{}", case["id"]);
        }
    }

    let lifecycle = corpus["lifecycle_cases"]
        .as_array()
        .expect("lifecycle cases");
    for required in [
        "same-attempt-identical-terminal-replay",
        "same-attempt-changed-marker",
        "restart-after-reservation-ambiguous",
        "outcome-changed-attempt",
        "terminal-outcome-substitution",
        "stdin-over-1mib",
    ] {
        assert!(lifecycle.iter().any(|case| case["id"] == required));
    }
}
