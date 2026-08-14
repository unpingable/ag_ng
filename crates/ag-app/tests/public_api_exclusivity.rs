//! Downstream compile and structural specimens for the single production AG
//! governed-repair seam. These checks make private mutable engines and raw
//! issuance signing unavailable to an external crate.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn write_downstream_fixture(root: &std::path::Path) {
    let ag_app = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    fs::create_dir_all(root.join("src/bin")).unwrap();
    fs::write(
        root.join("Cargo.toml"),
        format!(
            "[package]\nname='ag-product-boundary-specimen'\nversion='0.0.0'\nedition='2024'\n\n[dependencies]\nag-app={{path={:?}}}\nag-store={{path={:?}}}\nag-campaign={{path={:?}}}\n",
            ag_app.display().to_string(),
            ag_app.join("../ag-store").display().to_string(),
            ag_app.join("../ag-campaign").display().to_string(),
        ),
    )
    .unwrap();
    fs::write(
        root.join("src/bin/product.rs"),
        r"use ag_app::governed_product::{
    GovernedCampaignServiceV1,
    HaltPreSpendScopeInsufficiencyV1,
    OccurrencePageRequestV1,
    RecordPreSpendScopeDiscoveryV1,
};
fn main() {
    let _ = core::mem::size_of::<GovernedCampaignServiceV1>();
    let _ = core::mem::size_of::<HaltPreSpendScopeInsufficiencyV1>();
    let _ = core::mem::size_of::<OccurrencePageRequestV1>();
    let _ = core::mem::size_of::<RecordPreSpendScopeDiscoveryV1>();
}
",
    )
    .unwrap();
    fs::write(
        root.join("src/bin/forbidden.rs"),
        r"use ag_app::governed_loop::CampaignEngineV1;
use ag_app::governed_ports::AgIssuanceSignerV2;
use ag_store::campaign::CampaignStoreV1;
fn main() {
    let _ = core::mem::size_of::<CampaignEngineV1>();
    let _ = core::mem::size_of::<AgIssuanceSignerV2>();
    let _ = core::mem::size_of::<CampaignStoreV1>();
}
",
    )
    .unwrap();
    fs::write(
        root.join("src/bin/legacy.rs"),
        r"use ag_app::docket_issuance::{DocketIssuanceOffice, IssuanceDecisionLedger, IssuanceSigner};
fn main() {
    let _ = core::mem::size_of::<DocketIssuanceOffice<'static>>();
    let _ = core::mem::size_of::<IssuanceDecisionLedger>();
    let _ = core::mem::size_of::<IssuanceSigner>();
}
",
    )
    .unwrap();
}

fn cargo_check(root: &std::path::Path, binary: &str) -> std::process::Output {
    Command::new(env!("CARGO"))
        .current_dir(root)
        .env("CARGO_TARGET_DIR", root.join("target"))
        .args(["check", "--offline", "--quiet", "--bin", binary])
        .output()
        .unwrap()
}

#[test]
fn downstream_can_compile_product_dtos_but_not_mutable_engines_or_raw_signers() {
    let directory = tempfile::tempdir().unwrap();
    write_downstream_fixture(directory.path());

    let product = cargo_check(directory.path(), "product");
    assert!(
        product.status.success(),
        "product contract must compile downstream: {}",
        String::from_utf8_lossy(&product.stderr)
    );

    let forbidden = cargo_check(directory.path(), "forbidden");
    assert!(!forbidden.status.success());
    let diagnostic = String::from_utf8_lossy(&forbidden.stderr);
    assert!(diagnostic.contains("module `governed_loop` is private"));
    assert!(diagnostic.contains("module `governed_ports` is private"));
    assert!(diagnostic.contains("could not find `campaign` in `ag_store`"));

    let legacy = cargo_check(directory.path(), "legacy");
    assert!(!legacy.status.success());
    assert!(
        String::from_utf8_lossy(&legacy.stderr)
            .contains("could not find `docket_issuance` in `ag_app`")
    );
}

fn rust_sources(root: &Path) -> Vec<PathBuf> {
    fn visit(root: &Path, paths: &mut Vec<PathBuf>) {
        for entry in fs::read_dir(root).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                visit(&path, paths);
            } else if path.extension().is_some_and(|value| value == "rs") {
                paths.push(path);
            }
        }
    }

    let mut paths = Vec::new();
    visit(root, &mut paths);
    paths.sort();
    paths
}

fn metadata() -> serde_json::Value {
    let output = Command::new(env!("CARGO"))
        .current_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
        .args([
            "metadata",
            "--offline",
            "--no-deps",
            "--format-version",
            "1",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn assert_private_product_root() {
    let manifest = include_str!("../Cargo.toml");
    let library = include_str!("../src/lib.rs");
    let engine = include_str!("../src/governed_loop.rs");
    let ports = include_str!("../src/governed_ports.rs");
    let store = include_str!("../src/governed_store.rs");

    assert!(library.contains("pub mod governed_product;"));
    assert!(library.contains("mod governed_loop;"));
    assert!(library.contains("mod governed_ports;"));
    assert!(library.contains("mod governed_store;"));
    assert!(!library.contains("pub mod governed_loop;"));
    assert!(!library.contains("pub mod governed_ports;"));
    assert!(!library.contains("pub mod governed_store;"));
    assert!(!library.contains("docket_issuance"));
    assert!(!engine.contains("pub fn apply_human_disposition"));
    assert!(!store.contains("pub fn commit_human_disposition"));
    assert!(!ports.contains("pub struct AgIssuanceSignerV2"));
    assert!(!ports.contains("pub fn sign("));
    for forbidden in [
        "no-governor",
        "raw-signing",
        "legacy-repair",
        "authority-bypass",
    ] {
        assert!(!manifest.contains(forbidden));
    }
}

fn target_census(metadata: &serde_json::Value) -> BTreeSet<String> {
    metadata["packages"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|package| {
            let package_name = package["name"].as_str().unwrap();
            package["targets"]
                .as_array()
                .unwrap()
                .iter()
                .map(move |target| {
                    let kind = target["kind"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|value| value.as_str().unwrap())
                        .collect::<Vec<_>>()
                        .join("+");
                    let name = target["name"].as_str().unwrap();
                    format!("{package_name}:{kind}:{name}")
                })
        })
        .collect()
}

fn assert_workspace_targets_and_features(metadata: &serde_json::Value) {
    assert_eq!(
        target_census(metadata),
        [
            "ag-app:bin:ag-effectd",
            "ag-app:bin:ag-loopctl",
            "ag-app:bin:ag-worker-fixture",
            "ag-app:bin:agctl",
            "ag-app:bin:agd",
            "ag-app:lib:ag_app",
            "ag-app:test:governed_docket_process",
            "ag-app:test:governed_pre_spend_discovery",
            "ag-app:test:governed_product_cli",
            "ag-app:test:managed_pointer_promotion",
            "ag-app:test:public_api_exclusivity",
            "ag-app:test:worker_live_ingress",
            "ag-campaign:lib:ag_campaign",
            "ag-campaign:test:governed_loop",
            "ag-campaign:test:governed_repair_wire_contract",
            "ag-campaign:test:nq_c1_repair_specimens",
            "ag-effect:lib:ag_effect",
            "ag-kernel:lib:ag_kernel",
            "ag-kernel:test:calculus_obligations",
            "ag-migrate:bin:ag-migrate",
            "ag-migrate:lib:ag_migrate",
            "ag-primitives:lib:ag_primitives",
            "ag-protocol:lib:ag_protocol",
            "ag-providerd:bin:ag-providerd",
            "ag-providerd:lib:ag_providerd",
            "ag-session:lib:ag_session",
            "ag-store:bin:ag-backup",
            "ag-store:lib:ag_store",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    );

    let packages = metadata["packages"].as_array().unwrap();
    let feature_census = packages
        .iter()
        .map(|package| {
            (
                package["name"].as_str().unwrap(),
                package["features"]
                    .as_object()
                    .unwrap()
                    .keys()
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(
        feature_census,
        [
            ("ag-app", vec!["worker-fixture"]),
            ("ag-campaign", vec![]),
            ("ag-effect", vec![]),
            ("ag-kernel", vec![]),
            ("ag-migrate", vec![]),
            ("ag-primitives", vec![]),
            ("ag-protocol", vec![]),
            ("ag-providerd", vec![]),
            ("ag-session", vec![]),
            ("ag-store", vec![]),
        ]
        .into_iter()
        .collect()
    );
}

fn assert_public_modules(library: &str) {
    let mut public_modules = library
        .lines()
        .filter_map(|line| line.strip_prefix("pub mod "))
        .map(|line| line.trim_end_matches(';'))
        .collect::<Vec<_>>();
    public_modules.sort_unstable();
    assert_eq!(
        public_modules,
        [
            "agd",
            "api",
            "config",
            "derived",
            "descriptor_path",
            "doctor",
            "effect_executor_adapter",
            "effectd",
            "effectd_activation",
            "governed_product",
            "managed_pointer",
            "peer",
            "rpc_auth",
            "runtime",
            "signed_transport",
            "transport",
            "worker",
            "worker_protocol",
            "worker_session",
        ]
    );
}

fn public_named_items(source: &str) -> BTreeSet<String> {
    source
        .lines()
        .filter_map(|line| {
            let line = line.trim_start();
            ["pub struct ", "pub enum ", "pub trait ", "pub type "]
                .into_iter()
                .find_map(|prefix| line.strip_prefix(prefix))
                .map(|remainder| {
                    remainder
                        .split(|character: char| {
                            character == '<'
                                || character == '{'
                                || character == '('
                                || character == '='
                                || character.is_whitespace()
                        })
                        .next()
                        .unwrap()
                        .to_owned()
                })
        })
        .collect()
}

fn service_public_methods(source: &str) -> BTreeSet<String> {
    let service = source
        .split_once("impl GovernedCampaignServiceV1 {")
        .unwrap()
        .1
        .split_once("\n}\n\nfn require_expected")
        .unwrap()
        .0;
    service
        .lines()
        .filter_map(|line| line.trim_start().strip_prefix("pub fn "))
        .map(|remainder| remainder.split(['(', '<']).next().unwrap().to_owned())
        .collect()
}

fn assert_closed_product_api(source: &str) {
    assert_eq!(
        source.matches("impl GovernedCampaignServiceV1 {").count(),
        1,
        "the canonical product service must have exactly one implementation block"
    );
    assert_eq!(
        source
            .lines()
            .filter(|line| line.starts_with("pub fn "))
            .count(),
        0,
        "free public functions may not create a second product mutation root"
    );
    assert_eq!(
        service_public_methods(source),
        [
            "allowed_transitions",
            "artifact",
            "authorize",
            "complete",
            "create",
            "create_decision_request",
            "decide",
            "decision_request",
            "dispatch",
            "escalate",
            "halt",
            "halt_pre_spend_scope_insufficiency",
            "list_events",
            "list_occurrences",
            "note_probe",
            "occurrence",
            "open",
            "open_continuation",
            "reconcile_docket",
            "record_pre_spend_scope_discovery",
            "record_proposal",
            "record_refusal",
            "recover",
            "replay",
            "require_standing",
            "state",
            "submit_governed_disposition",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    );
    assert_product_public_types(source);
    assert_product_consequence_edges(source);
}

fn assert_product_public_types(source: &str) {
    assert_eq!(
        public_named_items(source),
        [
            "AdmissionDecisionArtifactV1",
            "AllowedTransitionsViewV1",
            "ArtifactRecordV1",
            "CampaignStateViewV1",
            "CompletedOccurrenceViewV1",
            "CompletionObservationArtifactV1",
            "CreateCampaignV1",
            "CreateDecisionRequestV1",
            "DocketCheckpointArtifactV1",
            "DocketIndeterminateArtifactV1",
            "EffectJournalReferenceArtifactV1",
            "EventPageV1",
            "GovernedAgPolicyRootV1",
            "GovernedArtifactKindV1",
            "GovernedArtifactLinkV1",
            "GovernedCampaignServiceV1",
            "GovernedDocketAdapterRootV1",
            "GovernedEventV1",
            "GovernedOperationV1",
            "GovernedRepairVerifierCatalogV1",
            "GovernedRepairVerifierProfileRecordV1",
            "GovernedRepairVerifierRootV1",
            "GovernedReplayReportV1",
            "HaltPreSpendScopeInsufficiencyResultV1",
            "HaltPreSpendScopeInsufficiencyV1",
            "HaltedOccurrenceViewV1",
            "ObservationResolutionArtifactV1",
            "OccurrencePageRequestV1",
            "OccurrencePageV1",
            "OccurrenceViewV1",
            "PageRequestV1",
            "PinnedDeploymentFileV1",
            "PreSpendRevisionConstraintViewV1",
            "PreSpendScopeDiscoveryResultV1",
            "ProposalContractViewV1",
            "RecordPreSpendScopeDiscoveryV1",
            "ResidualStateArtifactV1",
            "StandingResolutionArtifactV1",
            "SubmitGovernedDispositionResultV1",
            "SubmitGovernedDispositionV1",
            "SuccessorBindingArtifactV1",
            "TerminalWitnessArtifactV1",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    );
}

fn assert_product_consequence_edges(source: &str) {
    for (needle, expected) in [
        ("CampaignEngineV1::open(", 1),
        ("CampaignStoreV1::open(", 14),
        ("AgIssuanceSignerV2::from_pkcs8(", 2),
        ("self.engine.replay(", 1),
        ("self.engine.governed_repair_request(", 1),
        ("self.engine.create_governed_repair_request(", 1),
        ("self.engine.apply_governed_repair_disposition(", 1),
        ("self.engine.current(", 4),
        ("self.engine.halt_pre_spend_scope_insufficiency(", 1),
        ("self.engine.record_pre_spend_scope_discovery(", 1),
        ("self.engine.record_proposal(", 1),
        ("self.engine.open_continuation(", 1),
        ("self.engine.require_standing(", 1),
        ("self.engine.decide(", 1),
        ("self.engine.authorize(", 1),
        ("self.engine.dispatch(", 1),
        ("self.engine.recover(", 2),
        ("self.engine.note_probe(", 1),
        ("self.engine.escalate(", 1),
        ("self.engine.complete(", 1),
        ("store.issuance_signing_permit(", 1),
    ] {
        assert_eq!(
            source.matches(needle).count(),
            expected,
            "canonical product consequence call-edge census changed for {needle:?}"
        );
    }
    assert_eq!(
        include_str!("../src/governed_ports.rs")
            .matches(".sign(")
            .count(),
        1,
        "issuance-signature production call-edge census changed"
    );
}

fn assert_closed_call_edges() {
    let source_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    for path in rust_sources(&source_root) {
        let relative = path.strip_prefix(&source_root).unwrap();
        let source = fs::read_to_string(&path).unwrap();
        for retired in [
            "ag.docket-issuance:v1",
            "DocketIssuanceOffice",
            "IssuanceDecisionLedger",
            "pub struct IssuanceSigner",
            "apply_human_disposition",
            "commit_human_disposition",
        ] {
            assert!(
                !source.contains(retired),
                "retired consequence surface {retired:?} appears in {}",
                relative.display()
            );
        }

        if relative.starts_with("bin/") && relative != Path::new("bin/ag-loopctl.rs") {
            for private_edge in [
                "GovernedCampaignServiceV1",
                "CampaignEngineV1",
                "AgIssuanceSignerV2",
                "governed_store",
            ] {
                assert!(
                    !source.contains(private_edge),
                    "noncanonical binary {} reaches {private_edge}",
                    relative.display()
                );
            }
        }

        if source.contains("CampaignEngineV1") {
            assert!(matches!(
                relative.to_str().unwrap(),
                "governed_loop.rs"
                    | "governed_product.rs"
                    | "governed_loop_tests.rs"
                    | "governed_product_tests.rs"
                    | "governed_repair_docket_process_tests.rs"
                    | "nq_c1_governed_repair_lifecycle_tests.rs"
            ));
        }
        if source.contains("AgIssuanceSignerV2") {
            assert!(matches!(
                relative.to_str().unwrap(),
                "governed_ports.rs" | "governed_product.rs"
            ));
        }
    }
}

#[test]
fn cargo_targets_features_exports_and_call_edges_match_the_closed_product_surface() {
    assert_private_product_root();
    let metadata = metadata();
    assert_workspace_targets_and_features(&metadata);
    assert_public_modules(include_str!("../src/lib.rs"));
    assert_closed_product_api(include_str!("../src/governed_product.rs"));
    assert_closed_call_edges();
}
