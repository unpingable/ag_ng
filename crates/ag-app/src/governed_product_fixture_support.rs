//! Reusable product-contract fixture for cross-repository wire specimens.
//!
//! The fixture is development evidence only. Its external verifier label is
//! `qualification-fixture-not-human-authority`; the direct Store/kernel setup
//! below only seeds a test Docket halt. The returned issuance is obtained by
//! normal product operations and exact artifact retrieval, never constructed.

#![allow(dead_code, reason = "shared by selected cross-repository specimens")]

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use crate::governed_product::*;
use crate::governed_store::{CampaignStoreV1, CampaignTransitionKindV1};
use ag_campaign::CampaignId;
use ag_campaign::governed::*;
use ag_primitives::Digest;
use ring::rand::SystemRandom;
use ring::signature::Ed25519KeyPair;
use uuid::Uuid;

// Far enough ahead of the development host clock that an adjacent Docket
// process can authenticate the issuance while still remaining inside JCS's
// exact integer range.
const NOW: u64 = 4_000_000_000_000;
const INITIAL_WORK: &str = "qualification-fixture-not-human-authority/initial/v1";
const SUCCESSOR_WORK: &str = "qualification-fixture-not-human-authority/successor/v1";

/// Result of the test-only product lifecycle driver.
pub struct AuthorizedSuccessorFixtureV1 {
    /// Exact temporary campaign Store path.
    pub database: PathBuf,
    /// Halted predecessor occurrence from which the exact request was issued.
    pub predecessor: OccurrenceViewV1,
    /// Fresh successor after normal standing, decision, and authorization.
    pub successor: OccurrenceViewV1,
    /// Exact successor proposal submitted through the product API.
    pub successor_proposal: ExactWorkProposalV1,
    /// Exact issuance decoded from the product artifact retrieval operation.
    pub issuance: AgIssuanceV2,
    /// Immutable checkpoint shared by predecessor outcome and successor proposal.
    pub checkpoint: GovernedRepairCheckpointV1,
}

fn digest(label: &str) -> Digest {
    Digest::hash_domain(
        "qualification-fixture-not-human-authority/product-support/v1",
        label.as_bytes(),
    )
}

fn scope(path: &str) -> CanonicalEffectScopeV1 {
    CanonicalEffectScopeV1::new(
        "repair".to_owned(),
        vec![CanonicalEffectResourceV1 {
            resource: "repository".to_owned(),
            path: path.to_owned(),
            operations: vec![CanonicalEffectOperationV1::Modify],
        }],
    )
    .unwrap()
}

fn pinned(path: &Path) -> PinnedDeploymentFileV1 {
    PinnedDeploymentFileV1 {
        path: path.to_owned(),
        identity: Digest::hash_bytes(&std::fs::read(path).unwrap()),
    }
}

fn executable(path: &Path, contents: &str) {
    std::fs::write(path, contents).unwrap();
    let mut permissions = std::fs::metadata(path).unwrap().permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(path, permissions).unwrap();
}

fn policy_root(
    directory: &Path,
    initial_scope: &CanonicalEffectScopeV1,
    successor_scope: &CanonicalEffectScopeV1,
) -> GovernedAgPolicyRootV1 {
    let clock = directory.join("fixture-clock");
    executable(&clock, &format!("#!/bin/sh\nprintf '%s\\n' {NOW}\n"));
    let observation = directory.join("fixture-observation.py");
    executable(
        &observation,
        r#"#!/usr/bin/env python3
import hashlib,json,sys
r=json.load(sys.stdin)
def d(label): return "sha256:"+hashlib.sha256(label.encode()).hexdigest()
o={"schema":"ag.governed-loop.observation-resolution/v1","key":r["key"],"observation":r["observation"],"currentness":d("currentness"),"normalized_preconditions":d("conditions"),"subject":r["subject"],"status":"current","resolved_at_unix_ms":r["now_unix_ms"],"fresh_until_unix_ms":r["now_unix_ms"]+100}
sys.stdout.write(json.dumps(o,sort_keys=True,separators=(",",":")))
"#,
    );
    let standing = directory.join("fixture-standing.py");
    executable(
        &standing,
        r#"#!/usr/bin/env python3
import hashlib,json,sys
r=json.load(sys.stdin)
def d(label): return "sha256:"+hashlib.sha256(label.encode()).hexdigest()
o={"schema":"ag.governed-loop.standing-resolution/v1","resolution":d("standing-resolution"),"currentness":d("standing-current"),"mandate":d("mandate"),"key":r["key"],"observation":r["observation"],"proposal":r["proposal"],"subject":r["subject"],"scope":r["scope"],"status":"current","resolved_at_unix_ms":r["now_unix_ms"],"expires_at_unix_ms":r["now_unix_ms"]+100}
sys.stdout.write(json.dumps(o,sort_keys=True,separators=(",",":")))
"#,
    );
    let catalog_path = directory.join("fixture-catalog.json");
    let catalog = ExactWorkCatalogV1 {
        schema: EXACT_WORK_CATALOG_SCHEMA_V1.to_owned(),
        policy_basis: digest("policy"),
        entries: BTreeMap::from([
            (
                INITIAL_WORK.to_owned(),
                ExactWorkCatalogEntryV1 {
                    work_schema: INITIAL_WORK.to_owned(),
                    subject: digest("subject"),
                    scope: initial_scope.digest(),
                },
            ),
            (
                SUCCESSOR_WORK.to_owned(),
                ExactWorkCatalogEntryV1 {
                    work_schema: SUCCESSOR_WORK.to_owned(),
                    subject: digest("subject"),
                    scope: successor_scope.digest(),
                },
            ),
        ]),
    };
    std::fs::write(
        &catalog_path,
        ag_primitives::JcsDocument::canonicalize(&catalog)
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    GovernedAgPolicyRootV1 {
        schema: GOVERNED_AG_POLICY_ROOT_SCHEMA_V1.to_owned(),
        policy_label: "qualification-fixture-not-human-authority".to_owned(),
        consequence_clock: pinned(&clock),
        observation_resolver: pinned(&observation),
        standing_resolver: pinned(&standing),
        exact_work_catalog: pinned(&catalog_path),
        controlling_review: None,
    }
}

fn verifier_root(directory: &Path) -> GovernedRepairVerifierRootV1 {
    let verifier = directory.join("qualification-fixture-not-human-authority.py");
    executable(
        &verifier,
        r"#!/usr/bin/env python3
import hashlib,json,sys
def jcs(value): return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
def domain(name,payload):
    name=name.encode(); data=(b'ag-ng\0digest\0v1\0'+len(name).to_bytes(16,'big')+name+len(payload).to_bytes(16,'big')+payload)
    return 'sha256:'+hashlib.sha256(data).hexdigest()
r=json.load(sys.stdin)
o={'schema':'ag.governed-loop.governed-repair-verification/v1','disposition':domain('ag.governed-loop.governed-repair-disposition/v1',jcs(r['artifact'])),'request':domain('ag.governed-loop.human-decision-request/v1',jcs(r['request'])),'halted_state_digest':r['request']['halted_state_digest'],'verifier_profile':r['expected_profile'],'verifier_root':r['expected_root'],'verifier_executable':r['expected_executable'],'verification':domain('qualification-fixture-not-human-authority/v1',b'verification'),'verified_at_unix_ms':r['now_unix_ms'],'expires_at_unix_ms':r['now_unix_ms']+1}
sys.stdout.write(json.dumps(o,sort_keys=True,separators=(',',':')))
",
    );
    GovernedRepairVerifierRootV1 {
        schema: GOVERNED_REPAIR_VERIFIER_ROOT_SCHEMA_V1.to_owned(),
        verifier_label: "qualification-fixture-not-human-authority".to_owned(),
        executable_identity: Digest::hash_bytes(&std::fs::read(&verifier).unwrap()),
        executable: verifier,
        catalog: GovernedRepairVerifierCatalogV1 {
            schema: GOVERNED_REPAIR_VERIFIER_CATALOG_SCHEMA_V1.to_owned(),
            profiles: vec![GovernedRepairVerifierProfileRecordV1 {
                profile: digest("profile"),
                principal: HumanPrincipalRefV1::from_digest(digest("principal")),
                mandate: MandateRefV1::from_digest(digest("mandate")),
            }],
        },
    }
}

/// Pins an intentionally unexercised Docket deployment capability for the
/// branch that seeds post-custody evidence through the private test Store. The
/// product must still know at genesis that a Docket route exists before it may
/// spend AG authorization.
fn dormant_docket_root(directory: &Path) -> GovernedDocketAdapterRootV1 {
    let state_directory = directory.join("dormant-docket-state");
    std::fs::create_dir_all(&state_directory).unwrap();
    let config = directory.join("dormant-docket-config.json");
    std::fs::write(&config, b"{}\n").unwrap();
    let issuer_key = directory.join("dormant-docket-issuer-key.pkcs8");
    let key = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    std::fs::write(&issuer_key, key.as_ref()).unwrap();
    let mut permissions = std::fs::metadata(&issuer_key).unwrap().permissions();
    permissions.set_mode(0o600);
    std::fs::set_permissions(&issuer_key, permissions).unwrap();
    let executable = Path::new("/bin/true");
    GovernedDocketAdapterRootV1 {
        schema: GOVERNED_DOCKET_ADAPTER_ROOT_SCHEMA_V1.to_owned(),
        adapter_label: "qualification-fixture-dormant-docket".to_owned(),
        docket_program: pinned(executable),
        state_directory,
        trust_config: pinned(&config),
        standing_resolver: pinned(executable),
        executor_adapter: pinned(executable),
        executor_config: pinned(&config),
        checkpoint_verifier: None,
        issuer_principal: "qualification-fixture-not-human-authority".to_owned(),
        issuer_key_id: "dormant-not-used".to_owned(),
        issuer_key: pinned(&issuer_key),
    }
}

/// Drives a real product approval and then obtains a fresh successor issuance
/// through record-proposal, standing, decision, authorization, and artifact
/// retrieval. The direct Store/kernel use is confined to seeding the test-only
/// Docket-sealed halt; it creates no production path.
pub fn authorized_successor_issuance(
    directory: &Path,
    checkpoint_diff: Option<Digest>,
) -> AuthorizedSuccessorFixtureV1 {
    authorized_successor_issuance_with_docket(directory, checkpoint_diff, None)
}

/// Drives the same exact product lifecycle while retaining a pinned Docket
/// adapter for an adjacent-process successor dispatch.
#[allow(
    clippy::too_many_lines,
    reason = "the fixture intentionally assembles one complete governed lifecycle"
)]
pub fn authorized_successor_issuance_with_docket(
    directory: &Path,
    checkpoint_diff: Option<Digest>,
    docket_root: Option<GovernedDocketAdapterRootV1>,
) -> AuthorizedSuccessorFixtureV1 {
    let database = directory.join("campaign.sqlite");
    let initial_scope = scope("bounded/original");
    let delta = scope("bounded/delta");
    let successor_scope = initial_scope.exact_union(&delta).unwrap();
    let policy = policy_root(directory, &initial_scope, &successor_scope);
    let verifier = verifier_root(directory);
    let uses_process_docket = docket_root.is_some();
    let docket_root = Some(docket_root.unwrap_or_else(|| dormant_docket_root(directory)));
    let mut service = GovernedCampaignServiceV1::create(
        &database,
        CreateCampaignV1 {
            campaign: CampaignId::from_digest(digest("campaign")),
            occurrence: OccurrenceId::from_uuid(Uuid::from_u128(1)),
            program: ProgramBasisRefV1::from_digest(digest("program")),
            residuals: ResidualSetV1::default(),
            budget: LoopBudgetV1 {
                retry_limit: 2,
                retries_used: 0,
                probe_limit: 1,
                probes_used: 0,
                escalation_limit: 1,
                escalations_used: 0,
            },
            idempotency_key: digest("create"),
            governed_ag_policy_root: policy,
            governed_repair_verifier_root: Some(verifier),
            governed_docket_adapter_root: docket_root,
        },
    )
    .unwrap();
    let initial = service.state().unwrap().current;
    let proposal = ExactWorkProposalV1::new(
        initial.key.campaign.clone(),
        digest("subject"),
        initial_scope.clone(),
        INITIAL_WORK.to_owned(),
        digest("executor-work"),
        ProposalGovernanceTermsV1 {
            nonclaims: vec![digest("fixture-not-authority")],
            expires_at_unix_ms: NOW + 1_000,
        },
        None,
    )
    .unwrap();
    let proposed = service
        .record_proposal(
            initial.state_digest(),
            ObservationRefV1::from_digest(digest("initial-observation")),
            proposal,
            ProposalClassV1::Initial,
        )
        .unwrap();
    let standing = service.require_standing(proposed.state_digest()).unwrap();
    let admissible = service.decide(standing.state_digest()).unwrap();
    let authorized = service.authorize(admissible.state_digest()).unwrap();
    let (predecessor, checkpoint) = if uses_process_docket {
        let predecessor = service.dispatch(authorized.state_digest()).unwrap();
        let requirement = predecessor
            .halted()
            .and_then(HaltedOccurrenceViewV1::governed_repair_requirement)
            .expect("real Docket scope expansion halts the exact occurrence");
        let HumanDecisionRequirementV1::ScopeExpansion(required) = requirement else {
            panic!("real Docket returns the exact scope-expansion class")
        };
        assert_eq!(required.original_scope, initial_scope);
        assert_eq!(required.requested_delta, delta);
        let checkpoint = required
            .docket_outcome
            .as_ref()
            .and_then(|outcome| outcome.immutable_work_checkpoint.clone())
            .expect("Docket-sealed requirement carries the immutable work checkpoint");
        assert_eq!(checkpoint.diff_identity, checkpoint_diff);
        (predecessor, checkpoint)
    } else {
        let checkpoint_ref = DocketCheckpointRefV1::from_digest(digest("docket-checkpoint"));
        let checkpoint = GovernedRepairCheckpointV1 {
            repository: digest("repository"),
            commit: "1111111111111111111111111111111111111111".to_owned(),
            tree: "2222222222222222222222222222222222222222".to_owned(),
            diff_identity: checkpoint_diff,
            content_manifest: digest("checkpoint-content"),
            docket_checkpoint: Some(checkpoint_ref.clone()),
        };
        let mut store = CampaignStoreV1::open(&database).unwrap();
        let current = store.current().unwrap();
        assert_eq!(current.state_digest(), authorized.state_digest());
        let issuance = current.issuance().unwrap().clone();
        let custody = DocketCustodyV1 {
            schema: DOCKET_CUSTODY_SCHEMA_V1.to_owned(),
            issuance: issuance.issuance.clone(),
            ag_spend: issuance.spend.clone(),
            execution_standing: DocketExecutionStandingRefV1::from_digest(digest(
                "docket-standing",
            )),
            standing_currentness: StandingCurrentnessRefV1::from_digest(digest("docket-current")),
            attempt: DocketAttemptRefV1::for_issuance(&issuance.issuance),
            executor_marker: ExecutorAttemptMarkerRefV1::from_digest(digest("executor-marker")),
            accepted_at_unix_ms: NOW,
        };
        let dispatched =
            GovernedLoopKernelV1::accept_docket_custody(&current, custody.clone()).unwrap();
        store
            .commit(
                &current,
                &dispatched,
                CampaignTransitionKindV1::DocketCustodyAccepted,
                NOW,
            )
            .unwrap();
        let outcome = DocketGovernedRepairOutcomeRefV1 {
            checkpoint: checkpoint_ref,
            sealed_result: DocketSealedResultRefV1::from_digest(digest("sealed-result")),
            outcome: digest("outcome"),
            issuance: issuance.issuance.clone(),
            custody: custody.reference(),
            attempt: custody.attempt.clone(),
            effect_journal: digest("journal"),
            executor_binding: digest("executor-binding"),
            executor_result: digest("executor-result"),
            executor_receipt: ReceiptRefV1::from_digest(digest("executor-receipt")),
            immutable_work_checkpoint: Some(checkpoint.clone()),
            reported_authorized_effects_occurred: false,
            created_at_unix_ms: NOW,
            expires_at_unix_ms: NOW + 100,
            idempotency: digest("outcome-idempotency"),
        };
        let requirement_value = ScopeExpansionRequiredV1 {
            schema: SCOPE_EXPANSION_REQUIRED_SCHEMA_V1.to_owned(),
            original_scope: initial_scope.clone(),
            original_scope_digest: initial_scope.digest(),
            requested_delta: delta.clone(),
            requested_delta_digest: delta.digest(),
            blocked_operation: BlockedEffectOperationV1 {
                resource: "repository".to_owned(),
                path: "bounded/delta".to_owned(),
                operation: CanonicalEffectOperationV1::Modify,
            },
            reason: digest("reason"),
            dependency_evidence: vec![digest("dependency")],
            limitations: vec![digest("limitation")],
            docket_outcome: Some(outcome.clone()),
            no_unauthorized_effect_reported: true,
        };
        let result = DocketSealedGovernedRepairResultV1::ScopeExpansionRequired {
            outcome: outcome.clone(),
            requirement: requirement_value.clone(),
        };
        let requirement = HumanDecisionRequirementV1::ScopeExpansion(requirement_value);
        let halted = GovernedLoopKernelV1::halt_from_docket_governed_repair(
            &dispatched,
            &outcome,
            &requirement,
            HaltReasonRefV1::from_digest(digest("scope-insufficient")),
        )
        .unwrap();
        store
            .commit_docket_governed_repair_halt(&dispatched, &halted, &result, NOW)
            .unwrap();
        (OccurrenceViewV1::try_from(&halted).unwrap(), checkpoint)
    };

    drop(service);
    let mut service = GovernedCampaignServiceV1::open(&database).unwrap();
    let requirement = predecessor
        .halted()
        .and_then(HaltedOccurrenceViewV1::governed_repair_requirement)
        .cloned()
        .expect("predecessor is durably halted on an exact governed requirement");
    let request = service
        .create_decision_request(CreateDecisionRequestV1 {
            expected_state_digest: predecessor.state_digest.clone(),
            requirement,
            required_verifier_profile: digest("profile"),
            decision_consequences: vec![digest("approve"), digest("reject")],
            nonclaims: vec![digest("fixture-not-authority")],
            idempotency_key: digest("request"),
            expires_at_unix_ms: NOW + 50,
        })
        .unwrap();
    let disposition = GovernedRepairDispositionV1 {
        schema: GOVERNED_REPAIR_DISPOSITION_SCHEMA_V1.to_owned(),
        campaign: predecessor.key.campaign.clone(),
        occurrence: predecessor.key.occurrence,
        halted_state_digest: predecessor.state_digest.clone(),
        disposition: GovernedRepairDispositionKindV1::ApproveExactExpansion {
            request: request.reference(),
            successor_occurrence: OccurrenceId::from_uuid(Uuid::from_u128(2)),
            approved_delta: delta,
            successor_scope: successor_scope.clone(),
            checkpoint: checkpoint.clone(),
        },
        decision: HumanDecisionIdV1::from_digest(digest("decision")),
        principal: HumanPrincipalRefV1::from_digest(digest("principal")),
        mandate: MandateRefV1::from_digest(digest("mandate")),
        verifier_profile: digest("profile"),
        nonce: HumanNonceRefV1::from_digest(digest("nonce")),
        expires_at_unix_ms: NOW + 40,
    };
    let approved = service
        .submit_governed_disposition(SubmitGovernedDispositionV1 {
            expected_state_digest: predecessor.state_digest.clone(),
            request: request.reference(),
            artifact: disposition,
        })
        .unwrap();
    let successor_proposal = ExactWorkProposalV1::new(
        approved.current.key.campaign.clone(),
        digest("subject"),
        successor_scope,
        SUCCESSOR_WORK.to_owned(),
        digest("executor-work"),
        ProposalGovernanceTermsV1 {
            nonclaims: vec![digest("fixture-not-authority")],
            expires_at_unix_ms: NOW + 1_000,
        },
        None,
    )
    .unwrap()
    .with_governed_repair_checkpoint(checkpoint.clone())
    .unwrap();
    let proposed = service
        .record_proposal(
            approved.current.state_digest(),
            ObservationRefV1::from_digest(digest("successor-observation")),
            successor_proposal.clone(),
            ProposalClassV1::Successor,
        )
        .unwrap();
    let standing = service.require_standing(proposed.state_digest()).unwrap();
    let admissible = service.decide(standing.state_digest()).unwrap();
    let authorized = service.authorize(admissible.state_digest()).unwrap();
    let issuance_link = authorized
        .artifacts
        .iter()
        .find(|link| link.kind == GovernedArtifactKindV1::AgIssuance)
        .expect("authorized successor exposes exact issuance artifact");
    let record = service
        .artifact(&issuance_link.identity)
        .unwrap()
        .expect("successor issuance artifact is retrievable");
    let issuance: AgIssuanceV2 = serde_json::from_slice(&record.bytes).unwrap();
    assert_eq!(issuance.issuance.as_digest(), &record.identity);

    AuthorizedSuccessorFixtureV1 {
        database,
        predecessor,
        successor: authorized,
        successor_proposal,
        issuance,
        checkpoint,
    }
}
