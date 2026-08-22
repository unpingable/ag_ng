#!/usr/bin/env bash
set -euo pipefail

fail() {
  echo "governed-loop authority-surface check failed: $*" >&2
  exit 1
}

production_spend_constructors="$({ rg -l 'AgAuthorizationSpendV1 \{' crates/*/src || true; })"
[[ "$production_spend_constructors" == "crates/ag-campaign/src/governed.rs" ]] ||
  fail "authorization spend construction escaped the pure ag-campaign kernel: $production_spend_constructors"

rg -q 'GovernedLoopKernelV1::consume_authorization' crates/ag-app/src/governed_loop.rs ||
  fail "campaign engine no longer delegates one-use spend to the canonical kernel"
rg -q 'create_with_runtime_profile' crates/ag-app/src/bin/ag-loopctl.rs ||
  fail "production campaign genesis is not runtime-profile bound"
rg -q 'campaign was not created through the genesis-bound production surface' crates/ag-app/src/bin/ag-loopctl.rs ||
  fail "production CLI no longer refuses unbound campaign stores"
for operation in SealRuntimeProfile VerifyRuntimeProfile Inspect; do
  rg -q "^[[:space:]]*$operation" crates/ag-app/src/bin/ag-loopctl.rs ||
    fail "deployment qualification command missing: $operation"
done
rg -q 'GovernedRuntimeProfileEnrollmentV1 = read_exact_record' crates/ag-app/src/bin/ag-loopctl.rs &&
  rg -q 'enrollment\.seal\(\)' crates/ag-app/src/bin/ag-loopctl.rs ||
  fail "runtime-profile sealing no longer uses the typed closed enrollment boundary"
rg -q 'write_exact_file' crates/ag-app/src/bin/ag-loopctl.rs ||
  fail "sealed runtime profile is no longer published through create-once storage"

intervention_enum="$(sed -n '/pub enum GovernedInterventionClassV1/,/^}/p' crates/ag-campaign/src/governed.rs)"
if rg -q 'Retry|Approve|Execute' <<<"$intervention_enum"; then
  fail "governed intervention vocabulary acquired a generic authority-collapsing verb"
fi
intervention_record="$(sed -n '/pub struct GovernedInterventionRequestV1/,/^}/p' crates/ag-campaign/src/governed.rs)"
if rg -q 'AgAuthorization|AgSpend|DocketCustody|signature|capability' <<<"$intervention_record"; then
  fail "intervention request contains reusable authority/custody material"
fi
reconciliation_path="$(sed -n '/pub fn request_reconciliation/,/pub fn complete/p' crates/ag-app/src/governed_loop.rs)"
if rg -q 'accept_issuance|\.dispatch\(' <<<"$reconciliation_path"; then
  fail "intervention reconciliation path can accept custody or dispatch"
fi
rg -q 'commit_governed_intervention' crates/ag-store/src/campaign.rs ||
  fail "accepted intervention provenance is not durably bound to its transition"

for operation in PrepareInterventionRequest InspectInterventionRequest PackageInterventionSubmission SubmitIntervention InterventionReceipt InterventionSubmissions; do
  rg -q "^[[:space:]]*$operation" crates/ag-app/src/bin/ag-loopctl.rs ||
    fail "authenticated intervention ingress command missing: $operation"
done
if rg -q '^[[:space:]]*(RequestProbe|RequestSuccessor|RequestHalt|RequestReconciliation)[[:space:]]*[{,]' crates/ag-app/src/bin/ag-loopctl.rs; then
  fail "pre-custody direct intervention CLI adapter remains reachable"
fi
submission_body="$(sed -n '/pub struct GovernedInterventionSubmissionBodyV1/,/^}/p' crates/ag-app/src/intervention_ingress.rs)"
if rg -q 'AgAuthorization|AgSpend|DocketCustody|capability|standing_token|issuer_key' <<<"$submission_body"; then
  fail "submission custody envelope contains authority-bearing material"
fi
rg -q 'request_bytes_b64' crates/ag-app/src/intervention_ingress.rs &&
  rg -q 'request_bytes_digest' crates/ag-app/src/intervention_ingress.rs &&
  rg -q 'target_runtime_profile' crates/ag-app/src/intervention_ingress.rs ||
  fail "submission custody does not bind exact request bytes and target runtime"
rg -q 'record_received' crates/ag-app/src/bin/ag-loopctl.rs ||
  fail "submission ingress does not durably receive custody before governed evaluation"
rg -q 'canonical_submission_result' crates/ag-app/src/bin/ag-loopctl.rs ||
  fail "timeout resend does not reconcile exact canonical AG results before repeat"
rg -q 'CampaignTransitionEvidenceV1::GovernedIntervention' crates/ag-app/src/bin/ag-loopctl.rs ||
  fail "submission result lookup is not tied to canonical transition evidence"
readonly_docket="$(sed -n '/pub struct CommandDocketReconciliationPortV1/,/pub enum GovernedPortErrorV1/p' crates/ag-app/src/governed_ports.rs)"
if rg -q 'AgIssuanceSignerV1|issuer_key|\.dispatch\(' <<<"$readonly_docket"; then
  fail "intervention reconciliation adapter acquired signing or dispatch capability"
fi
rg -q 'intervention-ingress-is-read-only' <<<"$readonly_docket" ||
  fail "intervention reconciliation adapter can accept new Docket custody"
if rg -n 'SubmitIntervention.*(retry|approve|execute)|pub enum GovernedInterventionClassV1.*(Retry|Approve|Execute)' crates/ag-app/src/bin/ag-loopctl.rs crates/ag-campaign/src/governed.rs; then
  fail "generic authority-collapsing mutation entered intervention ingress"
fi

for operation in accept reconcile-issuance reconcile-attempt; do
  rg -q "arguments\(\"$operation\"\)" crates/ag-app/src/governed_ports.rs ||
    fail "Docket adapter operation missing: $operation"
done

if rg -q 'CampaignDriverNG|campaign-driver' crates/*/src Cargo.toml crates/*/Cargo.toml; then
  fail "historical campaign driver entered the canonical authority-bearing product graph"
fi

rg -q 'UNIQUE \(campaign_id, occurrence_id\)' crates/ag-store/src/campaign.rs ||
  fail "one-spend-per-occurrence database fence is missing"
rg -q 'program_counter' crates/ag-store/src/campaign.rs ||
  fail "durable program-counter persistence is missing"
rg -q 'runtime_profile' crates/ag-store/src/campaign.rs ||
  fail "genesis-bound runtime profile persistence is missing"

echo "governed-loop authority surface: PASS"
