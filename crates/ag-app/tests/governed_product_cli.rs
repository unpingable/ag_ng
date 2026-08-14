//! Public product/CLI correspondence without access to private Store or kernel mutation.

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::Command;

use ag_app::governed_product::*;
use ag_campaign::CampaignId;
use ag_campaign::governed::*;
use ag_primitives::{Digest, JcsDocument};
use uuid::Uuid;

fn digest(label: &str) -> Digest {
    Digest::hash_domain("ag-product-cli-public-fixture/v1", label.as_bytes())
}

fn executable(path: &Path, contents: &str) -> PinnedDeploymentFileV1 {
    std::fs::write(path, contents).unwrap();
    let mut permissions = std::fs::metadata(path).unwrap().permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(path, permissions).unwrap();
    PinnedDeploymentFileV1 {
        path: path.to_owned(),
        identity: Digest::hash_bytes(&std::fs::read(path).unwrap()),
    }
}

fn create_cli_fixture(directory: &Path) -> (String, CampaignStateViewV1, Digest) {
    let clock = executable(&directory.join("clock"), "#!/bin/sh\nprintf '1000\\n'\n");
    let observation = executable(&directory.join("observation"), "#!/bin/sh\nexit 64\n");
    let standing = executable(&directory.join("standing"), "#!/bin/sh\nexit 64\n");
    let catalog_path = directory.join("catalog.json");
    let catalog = ExactWorkCatalogV1 {
        schema: EXACT_WORK_CATALOG_SCHEMA_V1.to_owned(),
        policy_basis: digest("policy"),
        entries: BTreeMap::new(),
    };
    std::fs::write(
        &catalog_path,
        JcsDocument::canonicalize(&catalog).unwrap().as_bytes(),
    )
    .unwrap();
    let database = directory.join("campaign.sqlite");
    let service = GovernedCampaignServiceV1::create(
        &database,
        CreateCampaignV1 {
            campaign: CampaignId::from_digest(digest("campaign")),
            occurrence: OccurrenceId::from_uuid(Uuid::from_u128(1)),
            program: ProgramBasisRefV1::from_digest(digest("program")),
            residuals: ResidualSetV1::default(),
            budget: LoopBudgetV1 {
                retry_limit: 1,
                retries_used: 0,
                probe_limit: 1,
                probes_used: 0,
                escalation_limit: 1,
                escalations_used: 0,
            },
            idempotency_key: digest("create"),
            governed_ag_policy_root: GovernedAgPolicyRootV1 {
                schema: GOVERNED_AG_POLICY_ROOT_SCHEMA_V1.to_owned(),
                policy_label: "qualification-fixture-not-human-authority".to_owned(),
                consequence_clock: clock,
                observation_resolver: observation,
                standing_resolver: standing,
                exact_work_catalog: PinnedDeploymentFileV1 {
                    path: catalog_path.clone(),
                    identity: Digest::hash_bytes(&std::fs::read(&catalog_path).unwrap()),
                },
                controlling_review: None,
            },
            governed_repair_verifier_root: None,
            governed_docket_adapter_root: None,
        },
    )
    .unwrap();
    let state = service.state().unwrap();
    let artifact = state.campaign_artifacts.first().unwrap().identity.clone();
    (database.display().to_string(), state, artifact)
}

#[test]
fn cli_reads_public_product_views_and_emits_stable_errors() {
    let directory = tempfile::tempdir().unwrap();
    let (database, state, artifact) = create_cli_fixture(directory.path());

    let program = env!("CARGO_BIN_EXE_ag-loopctl");
    let run = |arguments: &[String]| Command::new(program).args(arguments).output().unwrap();
    for arguments in [
        vec![
            "get-occurrence".to_owned(),
            "--database".to_owned(),
            database.clone(),
            "--campaign".to_owned(),
            state.current.key.campaign.to_string(),
            "--occurrence".to_owned(),
            state.current.key.occurrence.to_string(),
        ],
        vec![
            "get-artifact".to_owned(),
            "--database".to_owned(),
            database.clone(),
            "--identity".to_owned(),
            artifact.to_string(),
        ],
        vec![
            "allowed-transitions".to_owned(),
            "--database".to_owned(),
            database.clone(),
        ],
    ] {
        let output = run(&arguments);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            serde_json::from_slice::<serde_json::Value>(&output.stdout)
                .unwrap()
                .is_object()
        );
    }

    for (command, code) in [
        ("get-artifact", "artifact_not_found"),
        ("get-decision-request", "decision_request_not_found"),
    ] {
        let output = run(&[
            command.to_owned(),
            "--database".to_owned(),
            database.clone(),
            "--identity".to_owned(),
            digest("absent").to_string(),
        ]);
        assert_eq!(output.status.code(), Some(2));
        let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(error["schema"], "ag.governed-loop.cli-error/v1");
        assert_eq!(error["code"], code);
    }
}
