//! Campaign store tests: the exact surface `agctl campaign` dispatches to.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use ag_app::campaign::{self, RunOutcomeV1};
use ag_campaign::{
    CampaignIntentV1, DocketStandingV1, EvidenceArtifactV1, EvidenceContractV1,
    EvidenceRequirementV1, MutationScopeV1, PathGrantV1, RUNTIME_RECEIPT_SCHEMA_V1,
    RuntimeEnvelopeV1, SidecarOutcomeV1, SidecarRuntimeReceiptV1, StageBasisV1, StageProposalV1,
};
use ag_primitives::Digest;

const NOW: u64 = 1_000_000;
const EXPIRY: u64 = 2_000_000;

fn digest(value: &str) -> Digest {
    Digest::hash_bytes(value.as_bytes())
}

fn intent() -> CampaignIntentV1 {
    CampaignIntentV1::new(
        "store-test-campaign".to_owned(),
        digest("human-authorization-instrument"),
        digest("operator-principal"),
        digest("reviewer-principal"),
    )
    .unwrap()
}

fn basis() -> StageBasisV1 {
    StageBasisV1 {
        repository: "repo:governed".to_owned(),
        base_commit: digest("commit-1"),
        base_tree: digest("tree-1"),
    }
}

fn proposal(campaign: &ag_campaign::CampaignId) -> StageProposalV1 {
    StageProposalV1::operator(
        campaign,
        1,
        basis(),
        MutationScopeV1 {
            grants: vec![PathGrantV1 {
                repository: "repo:governed".to_owned(),
                path_prefix: "/src".to_owned(),
            }],
        },
        EvidenceContractV1 {
            required: vec![EvidenceRequirementV1 {
                schema: "ag.test.report/v1".to_owned(),
            }],
        },
    )
    .unwrap()
}

fn snapshot_tree(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut snapshot = BTreeMap::new();
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            for nested in fs::read_dir(&path).unwrap() {
                let nested = nested.unwrap().path();
                snapshot.insert(nested.clone(), fs::read(&nested).unwrap());
            }
        } else {
            snapshot.insert(path.clone(), fs::read(&path).unwrap());
        }
    }
    snapshot
}

#[test]
fn read_operations_have_no_effect_on_the_store() {
    let temporary = tempfile::tempdir().unwrap();
    let dir = temporary.path().join("campaign");
    campaign::init(&dir, &intent()).unwrap();

    // Seed a proposal so status/tail/report have content to read.
    let intent = intent();
    let campaign_id = campaign::validate_intent(&intent).unwrap();
    campaign::propose_stage(&dir, proposal(&campaign_id)).unwrap();

    let before = snapshot_tree(&dir);
    campaign::status(&dir, NOW).unwrap();
    campaign::tail(&dir, 10).unwrap();
    campaign::doctor(&dir).unwrap();
    // Report refuses mid-campaign (ambiguous incomplete effect) but must
    // still be read-only.
    assert!(campaign::report(&dir).is_err());
    campaign::validate_intent(&intent).unwrap();
    let after = snapshot_tree(&dir);
    assert_eq!(before, after, "read operations must not change store bytes");
}

#[test]
fn store_runs_the_envelope_loop_and_doctor_verifies_it() {
    let temporary = tempfile::tempdir().unwrap();
    let dir = temporary.path().join("campaign");
    let campaign_id = campaign::init(&dir, &intent()).unwrap();
    let proposal = proposal(&campaign_id);
    let stage = campaign::propose_stage(&dir, proposal.clone()).unwrap();

    let standing = DocketStandingV1 {
        schema: ag_campaign::DOCKET_STANDING_SCHEMA_V1.to_owned(),
        stage: stage.clone(),
        standing_digest: digest("docket-standing-fixture"),
        expiry_unix: EXPIRY,
    };
    campaign::admit_stage(&dir, standing, NOW).unwrap();

    // Dispatch: consumes standing and renders the exact envelope.
    let RunOutcomeV1::EnvelopeDispatched {
        envelope,
        envelope_file_digest,
        envelope_path,
        ..
    } = campaign::run(&dir, None, NOW).unwrap()
    else {
        panic!("first run must dispatch the envelope");
    };

    // A second dispatch refuses: the standing is already burned.
    assert!(campaign::run(&dir, None, NOW).is_err());

    // The mock sidecar answers the exact envelope artifact. The
    // cross-repository rule binds the envelope FILE bytes: the outcome's
    // file digest is SHA-256 over the bytes on disk, while the typed
    // transcript digest remains the in-domain identity.
    let envelope_bytes = fs::read(&envelope_path).unwrap();
    assert_eq!(envelope_file_digest, Digest::of_bytes(&envelope_bytes));
    let envelope_record: RuntimeEnvelopeV1 = campaign::read_record_file(&envelope_path).unwrap();
    assert_eq!(envelope_record.digest(), envelope);
    assert_ne!(
        envelope_file_digest, envelope,
        "the file-bytes artifact digest is a distinct binding from the typed digest"
    );
    let receipt = SidecarRuntimeReceiptV1 {
        schema: RUNTIME_RECEIPT_SCHEMA_V1.to_owned(),
        envelope_digest: envelope_file_digest.clone(),
        campaign: campaign_id.clone(),
        stage: stage.clone(),
        standing_digest: envelope_record.standing_digest().clone(),
        nonce: *envelope_record.nonce(),
        outcome: SidecarOutcomeV1::Completed,
        post_tree: Some(digest("post-tree-1")),
        artifacts: vec![EvidenceArtifactV1 {
            schema: "ag.test.report/v1".to_owned(),
            digest: digest("artifact-1"),
        }],
    };

    // A receipt binding the typed transcript digest instead of the exact
    // file bytes refuses: cross-repository artifacts bind bytes only.
    let typed_binding = SidecarRuntimeReceiptV1 {
        envelope_digest: envelope.clone(),
        ..receipt.clone()
    };
    assert!(campaign::run(&dir, Some(typed_binding), NOW).is_err());

    let RunOutcomeV1::StageReceiptRecorded {
        receipt: receipt_digest,
        ..
    } = campaign::run(&dir, Some(receipt), NOW).unwrap()
    else {
        panic!("a verified receipt must record the stage receipt");
    };

    let status = campaign::status(&dir, NOW).unwrap();
    assert_eq!(status.current_stage, Some(stage));
    assert_eq!(
        status.current_standing,
        ag_campaign::StandingStateV1::Consumed
    );

    let report = campaign::doctor(&dir).unwrap();
    assert!(report.healthy, "doctor checks failed: {report:?}");

    let events = campaign::tail(&dir, 100).unwrap();
    // created, proposed, admitted, consumed, dispatch, receipt.
    assert_eq!(events.len(), 6);
    let _ = receipt_digest;
}

#[test]
fn store_advances_to_the_review_stage_after_operator_completion() {
    let temporary = tempfile::tempdir().unwrap();
    let dir = temporary.path().join("campaign");
    let campaign_id = campaign::init(&dir, &intent()).unwrap();
    let stage = campaign::propose_stage(&dir, proposal(&campaign_id)).unwrap();
    campaign::admit_stage(
        &dir,
        DocketStandingV1 {
            schema: ag_campaign::DOCKET_STANDING_SCHEMA_V1.to_owned(),
            stage: stage.clone(),
            standing_digest: digest("docket-standing-fixture"),
            expiry_unix: EXPIRY,
        },
        NOW,
    )
    .unwrap();
    let RunOutcomeV1::EnvelopeDispatched {
        envelope_file_digest,
        envelope_path,
        ..
    } = campaign::run(&dir, None, NOW).unwrap()
    else {
        panic!("first run must dispatch the envelope");
    };
    let envelope_record: RuntimeEnvelopeV1 = campaign::read_record_file(&envelope_path).unwrap();
    let receipt = SidecarRuntimeReceiptV1 {
        schema: RUNTIME_RECEIPT_SCHEMA_V1.to_owned(),
        envelope_digest: envelope_file_digest,
        campaign: campaign_id.clone(),
        stage: stage.clone(),
        standing_digest: envelope_record.standing_digest().clone(),
        nonce: *envelope_record.nonce(),
        outcome: SidecarOutcomeV1::Completed,
        post_tree: Some(digest("post-tree-1")),
        artifacts: vec![EvidenceArtifactV1 {
            schema: "ag.test.report/v1".to_owned(),
            digest: digest("artifact-1"),
        }],
    };
    campaign::run(&dir, Some(receipt), NOW).unwrap();

    // The operator stage is receipted; its verdict arrives through the
    // review stage. The next runnable stage is the review stage, even
    // though the operator stage is not yet verdict-terminal.
    let review = StageProposalV1::review(
        &campaign_id,
        2,
        basis(),
        ag_campaign::ReviewScopeV1 {
            subject_stage: stage.clone(),
            read_paths: vec![PathGrantV1 {
                repository: "repo:governed".to_owned(),
                path_prefix: "/src".to_owned(),
            }],
        },
        EvidenceContractV1 {
            required: vec![EvidenceRequirementV1 {
                schema: "ag.test.report/v1".to_owned(),
            }],
        },
    )
    .unwrap();
    let review_stage = review.id();
    campaign::propose_stage(&dir, review).unwrap();
    campaign::admit_stage(
        &dir,
        DocketStandingV1 {
            schema: ag_campaign::DOCKET_STANDING_SCHEMA_V1.to_owned(),
            stage: review_stage.clone(),
            standing_digest: digest("docket-standing-reviewer"),
            expiry_unix: EXPIRY,
        },
        NOW,
    )
    .unwrap();
    let RunOutcomeV1::EnvelopeDispatched {
        stage: dispatched, ..
    } = campaign::run(&dir, None, NOW).unwrap()
    else {
        panic!("the review stage must dispatch once the operator stage is receipted");
    };
    assert_eq!(dispatched, review_stage);

    // A dispatched review stage completes by verdict, never by a worker
    // receipt: a completed sidecar receipt for it refuses at recording.
    let review_envelope_path = dir.join("envelopes").join(format!(
        "{}.json",
        &review_stage.as_str()["sha256:".len()..]
    ));
    let review_bytes = fs::read(&review_envelope_path).unwrap();
    let review_envelope: RuntimeEnvelopeV1 =
        campaign::read_record_file(&review_envelope_path).unwrap();
    let review_receipt = SidecarRuntimeReceiptV1 {
        schema: RUNTIME_RECEIPT_SCHEMA_V1.to_owned(),
        envelope_digest: Digest::of_bytes(&review_bytes),
        campaign: campaign_id.clone(),
        stage: review_stage.clone(),
        standing_digest: review_envelope.standing_digest().clone(),
        nonce: *review_envelope.nonce(),
        outcome: SidecarOutcomeV1::Completed,
        post_tree: None,
        artifacts: vec![EvidenceArtifactV1 {
            schema: "ag.test.report/v1".to_owned(),
            digest: digest("artifact-review"),
        }],
    };
    assert!(campaign::run(&dir, Some(review_receipt), NOW).is_err());
}

#[test]
fn abort_and_resume_are_effectful_and_audited() {
    let temporary = tempfile::tempdir().unwrap();
    let dir = temporary.path().join("campaign");
    campaign::init(&dir, &intent()).unwrap();
    campaign::abort(&dir, digest("halt-reason")).unwrap();
    let halted = campaign::status(&dir, NOW).unwrap();
    assert_eq!(halted.halt_reason, Some(digest("halt-reason")));
    campaign::resume(&dir).unwrap();
    let resumed = campaign::status(&dir, NOW).unwrap();
    assert_eq!(resumed.halt_reason, None);
    let report = campaign::doctor(&dir).unwrap();
    assert!(report.healthy);
}
