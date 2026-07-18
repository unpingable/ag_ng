//! Non-authorizing correspondence membrane for the promoted Lean calculus.
//!
//! This module binds an operational Rust judgment to the exact specification
//! baseline, evaluator, input, authority context, and lifecycle origin under
//! which it was produced. It does not interpret Lean proofs, execute Lean,
//! authenticate an evaluator, or construct [`crate::Authority`].

use std::collections::BTreeMap;

use ag_primitives::{AuthorityDomain, Digest, Epoch, JcsDocument, LifecycleOrigin};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{NativeJudgment, OperationalEvaluation};

/// Canonical schema for one operational decision adapted against the calculus.
pub const CALCULUS_ADAPTER_SCHEMA_V1: &str = "ag.calculus-adapter/v1";
/// Exact public Lean revision reviewed for the v1 adapter contract.
pub const ADMISSIBILITY_CALCULUS_REVISION_V1: &str = "ff491b808ebeab2a132d9ade46d234cf85dcfbe9";
/// Human-readable release name at the pinned revision.
pub const ADMISSIBILITY_CALCULUS_RELEASE_V1: &str = "14.0.0";

/// Exact operational context in which one native decision was evaluated.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CalculusAdapterContextV1 {
    schema: String,
    calculus_revision: String,
    calculus_release: String,
    authority_domain: AuthorityDomain,
    epoch: Epoch,
    lifecycle_origin: LifecycleOrigin,
    evaluator_identity: Digest,
    input_digest: Digest,
}

impl CalculusAdapterContextV1 {
    /// Creates a context pinned to the reviewed calculus baseline.
    #[must_use]
    pub fn new(
        authority_domain: AuthorityDomain,
        epoch: Epoch,
        lifecycle_origin: LifecycleOrigin,
        evaluator_identity: Digest,
        input_digest: Digest,
    ) -> Self {
        Self {
            schema: CALCULUS_ADAPTER_SCHEMA_V1.to_owned(),
            calculus_revision: ADMISSIBILITY_CALCULUS_REVISION_V1.to_owned(),
            calculus_release: ADMISSIBILITY_CALCULUS_RELEASE_V1.to_owned(),
            authority_domain,
            epoch,
            lifecycle_origin,
            evaluator_identity,
            input_digest,
        }
    }

    /// Verifies that serialized context still names the reviewed contract.
    ///
    /// # Errors
    ///
    /// Returns a typed mismatch for a substituted schema, revision, or release.
    pub fn verify(&self) -> Result<(), CalculusAdapterError> {
        if self.schema != CALCULUS_ADAPTER_SCHEMA_V1 {
            return Err(CalculusAdapterError::SchemaMismatch);
        }
        if self.calculus_revision != ADMISSIBILITY_CALCULUS_REVISION_V1
            || self.calculus_release != ADMISSIBILITY_CALCULUS_RELEASE_V1
        {
            return Err(CalculusAdapterError::CalculusBaselineMismatch);
        }
        if self.lifecycle_origin.authority_domain != self.authority_domain
            || self.lifecycle_origin.epoch != self.epoch
        {
            return Err(CalculusAdapterError::LifecycleContextMismatch);
        }
        Ok(())
    }

    /// Returns the authority domain observed by the evaluator.
    #[must_use]
    pub const fn authority_domain(&self) -> &AuthorityDomain {
        &self.authority_domain
    }

    /// Returns the activation epoch observed by the evaluator.
    #[must_use]
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Returns the lifecycle origin carried through the decision.
    #[must_use]
    pub const fn lifecycle_origin(&self) -> &LifecycleOrigin {
        &self.lifecycle_origin
    }

    /// Returns the exact operational evaluator identity.
    #[must_use]
    pub const fn evaluator_identity(&self) -> &Digest {
        &self.evaluator_identity
    }

    /// Returns the exact evaluated input digest.
    #[must_use]
    pub const fn input_digest(&self) -> &Digest {
        &self.input_digest
    }
}

/// Coarse projection of a stored result. Native evidence remains in the result.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CalculusDispositionV1 {
    /// Evaluation completed with native admission evidence.
    Admit,
    /// Evaluation completed with native refusal evidence.
    Refuse,
    /// Operational failure prevented a semantic decision.
    Indeterminate,
}

/// A native Rust result bound to the reviewed calculus adapter contract.
///
/// This is evidence, not authority. Deserialization never creates a sealed
/// authority value, and projection methods reverify the complete binding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CalculusDecisionV1<W, R> {
    context: CalculusAdapterContextV1,
    outcome: OperationalEvaluation<W, R>,
    decision_digest: Digest,
}

impl<W, R> CalculusDecisionV1<W, R>
where
    W: Serialize,
    R: Serialize,
{
    /// Binds one already-computed result to its exact operational context.
    ///
    /// # Errors
    ///
    /// Returns a canonicalization error when exact JCS encoding fails.
    pub fn new(
        context: CalculusAdapterContextV1,
        outcome: OperationalEvaluation<W, R>,
    ) -> Result<Self, CalculusAdapterError> {
        context.verify()?;
        let decision_digest = decision_digest(&context, &outcome)?;
        Ok(Self {
            context,
            outcome,
            decision_digest,
        })
    }

    /// Revalidates the baseline and exact decision digest after custody.
    ///
    /// # Errors
    ///
    /// Returns a typed error for baseline drift, canonicalization failure, or
    /// substitution of any context or native evidence field.
    pub fn verify(&self) -> Result<(), CalculusAdapterError> {
        self.context.verify()?;
        if decision_digest(&self.context, &self.outcome)? != self.decision_digest {
            return Err(CalculusAdapterError::DecisionDigestMismatch);
        }
        Ok(())
    }

    /// Returns the bound operational context.
    #[must_use]
    pub const fn context(&self) -> &CalculusAdapterContextV1 {
        &self.context
    }

    /// Returns the complete native outcome after verifying its exact binding.
    ///
    /// # Errors
    ///
    /// Refuses projection from substituted or stale serialized evidence.
    pub fn outcome(&self) -> Result<&OperationalEvaluation<W, R>, CalculusAdapterError> {
        self.verify()?;
        Ok(&self.outcome)
    }

    /// Returns the digest of the exact context and native outcome.
    #[must_use]
    pub const fn decision_digest(&self) -> &Digest {
        &self.decision_digest
    }

    /// Projects only the coarse disposition; native evidence remains retained.
    ///
    /// # Errors
    ///
    /// Refuses projection from substituted or stale serialized evidence.
    pub fn disposition(&self) -> Result<CalculusDispositionV1, CalculusAdapterError> {
        self.verify()?;
        Ok(match &self.outcome {
            OperationalEvaluation::Evaluated(NativeJudgment::Admit(_)) => {
                CalculusDispositionV1::Admit
            }
            OperationalEvaluation::Evaluated(NativeJudgment::Refuse(_)) => {
                CalculusDispositionV1::Refuse
            }
            OperationalEvaluation::Indeterminate(_) => CalculusDispositionV1::Indeterminate,
        })
    }
}

/// Durable, non-authorizing evidence that a stored decision was projected once.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CalculusUseReceiptV1 {
    decision: Digest,
    consumer: Digest,
    lifecycle_origin: LifecycleOrigin,
    use_digest: Digest,
}

impl CalculusUseReceiptV1 {
    /// Returns the exact decision consumed.
    #[must_use]
    pub const fn decision(&self) -> &Digest {
        &self.decision
    }

    /// Returns the operational consumer identity.
    #[must_use]
    pub const fn consumer(&self) -> &Digest {
        &self.consumer
    }

    /// Returns the exact receipt digest.
    #[must_use]
    pub const fn use_digest(&self) -> &Digest {
        &self.use_digest
    }

    fn verify(&self) -> Result<(), CalculusAdapterError> {
        let expected = canonical_digest(
            "ag-ng:calculus-decision-use:v1",
            &(&self.decision, &self.consumer, &self.lifecycle_origin),
        )?;
        if expected != self.use_digest {
            return Err(CalculusAdapterError::UseReceiptMismatch);
        }
        Ok(())
    }
}

/// Replay state for one lifecycle origin.
///
/// The ledger prevents duplicate projection within the custodied state supplied
/// by its caller. It is not an authority ledger and does not claim protection
/// against rollback to an older copied store; that remains a durable-store and
/// activation-epoch obligation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CalculusDecisionLedgerV1 {
    lifecycle_origin: LifecycleOrigin,
    consumed: BTreeMap<Digest, CalculusUseReceiptV1>,
}

impl CalculusDecisionLedgerV1 {
    /// Creates an empty projection ledger for one lifecycle origin.
    #[must_use]
    pub const fn new(lifecycle_origin: LifecycleOrigin) -> Self {
        Self {
            lifecycle_origin,
            consumed: BTreeMap::new(),
        }
    }

    /// Records the first projection of a verified stored decision.
    ///
    /// # Errors
    ///
    /// Refuses substituted decisions, foreign origins, and replay.
    pub fn consume<W, R>(
        &mut self,
        decision: &CalculusDecisionV1<W, R>,
        consumer: Digest,
    ) -> Result<CalculusUseReceiptV1, CalculusAdapterError>
    where
        W: Serialize,
        R: Serialize,
    {
        self.verify()?;
        decision.verify()?;
        if decision.context.lifecycle_origin != self.lifecycle_origin {
            return Err(CalculusAdapterError::ForeignLifecycleOrigin);
        }
        if self.consumed.contains_key(&decision.decision_digest) {
            return Err(CalculusAdapterError::DecisionAlreadyConsumed);
        }
        let use_digest = canonical_digest(
            "ag-ng:calculus-decision-use:v1",
            &(&decision.decision_digest, &consumer, &self.lifecycle_origin),
        )?;
        let receipt = CalculusUseReceiptV1 {
            decision: decision.decision_digest.clone(),
            consumer,
            lifecycle_origin: self.lifecycle_origin.clone(),
            use_digest,
        };
        self.consumed
            .insert(decision.decision_digest.clone(), receipt.clone());
        Ok(receipt)
    }

    /// Returns a prior use receipt without recreating consumption authority.
    ///
    /// # Errors
    ///
    /// Refuses inspection when any serialized ledger binding is corrupt.
    pub fn receipt(
        &self,
        decision: &Digest,
    ) -> Result<Option<&CalculusUseReceiptV1>, CalculusAdapterError> {
        self.verify()?;
        Ok(self.consumed.get(decision))
    }

    /// Verifies every stored key, origin, and use-receipt digest.
    ///
    /// # Errors
    ///
    /// Returns a typed corruption error for substituted serialized state.
    pub fn verify(&self) -> Result<(), CalculusAdapterError> {
        for (decision, receipt) in &self.consumed {
            if decision != &receipt.decision || receipt.lifecycle_origin != self.lifecycle_origin {
                return Err(CalculusAdapterError::UseReceiptMismatch);
            }
            receipt.verify()?;
        }
        Ok(())
    }
}

/// Refusal at the Lean/Rust correspondence membrane.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum CalculusAdapterError {
    /// Serialized material names another adapter schema.
    #[error("calculus adapter schema does not match the reviewed contract")]
    SchemaMismatch,
    /// Serialized material names another Lean revision or release.
    #[error("calculus baseline does not match the reviewed revision")]
    CalculusBaselineMismatch,
    /// Domain or epoch disagrees with the carried lifecycle origin.
    #[error("calculus adapter domain/epoch does not match its lifecycle origin")]
    LifecycleContextMismatch,
    /// Context or native evidence differs from the committed decision digest.
    #[error("calculus decision digest does not match exact decision bytes")]
    DecisionDigestMismatch,
    /// A decision belongs to another lifecycle origin.
    #[error("calculus decision has a foreign lifecycle origin")]
    ForeignLifecycleOrigin,
    /// The exact decision has already been projected once.
    #[error("calculus decision was already consumed")]
    DecisionAlreadyConsumed,
    /// Serialized one-use state has inconsistent keys, origin, or digest.
    #[error("calculus decision use receipt does not match exact ledger state")]
    UseReceiptMismatch,
    /// Canonical encoding failed.
    #[error("cannot canonicalize calculus adapter evidence: {0}")]
    Canonicalization(String),
}

fn decision_digest<W: Serialize, R: Serialize>(
    context: &CalculusAdapterContextV1,
    outcome: &OperationalEvaluation<W, R>,
) -> Result<Digest, CalculusAdapterError> {
    canonical_digest("ag-ng:calculus-decision:v1", &(context, outcome))
}

fn canonical_digest<T: Serialize>(domain: &str, value: &T) -> Result<Digest, CalculusAdapterError> {
    let encoded = JcsDocument::canonicalize(value)
        .map_err(|error| CalculusAdapterError::Canonicalization(error.to_string()))?;
    let mut bytes = domain.as_bytes().to_vec();
    bytes.push(0);
    bytes.extend(encoded.as_bytes());
    Ok(Digest::hash_bytes(&bytes))
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use ag_primitives::{AuthorityDomain, Epoch, LifecycleNonce, LifecycleOrigin};
    use serde_json::Value;

    use super::*;
    use crate::{FailureEvidence, OperationalFailureKind};

    fn context(label: &str) -> CalculusAdapterContextV1 {
        let authority_domain = AuthorityDomain::parse("ag.test").expect("domain");
        let epoch = Epoch::parse("1").expect("epoch");
        let lifecycle_origin = LifecycleOrigin::new(
            authority_domain.clone(),
            epoch,
            LifecycleNonce::new([7; 16]),
        );
        CalculusAdapterContextV1::new(
            authority_domain,
            epoch,
            lifecycle_origin,
            Digest::hash_bytes(format!("evaluator-{label}").as_bytes()),
            Digest::hash_bytes(format!("input-{label}").as_bytes()),
        )
    }

    fn refusal(label: &str) -> CalculusDecisionV1<String, Vec<String>> {
        CalculusDecisionV1::new(
            context(label),
            OperationalEvaluation::evaluated(NativeJudgment::Refuse(vec![
                "missing-standing".to_owned(),
                "stale-custody".to_owned(),
            ])),
        )
        .expect("adapt refusal")
    }

    #[test]
    fn refusal_round_trip_preserves_exact_native_evidence() {
        let decision = refusal("round-trip");
        let bytes = serde_json::to_vec(&decision).expect("serialize");
        let decoded: CalculusDecisionV1<String, Vec<String>> =
            serde_json::from_slice(&bytes).expect("deserialize");
        decoded.verify().expect("verify");
        assert_eq!(decoded, decision);
        assert_eq!(
            decoded.disposition().expect("verified disposition"),
            CalculusDispositionV1::Refuse
        );
        assert!(matches!(
            decoded.outcome().expect("verified outcome"),
            OperationalEvaluation::Evaluated(NativeJudgment::Refuse(reasons))
                if reasons == &vec!["missing-standing".to_owned(), "stale-custody".to_owned()]
        ));
    }

    #[test]
    fn baseline_context_and_evidence_substitution_refuse() {
        let decision = refusal("substitution");
        let mut value = serde_json::to_value(&decision).expect("value");
        value["context"]["calculus_revision"] = Value::String("0".repeat(40));
        let hostile: CalculusDecisionV1<String, Vec<String>> =
            serde_json::from_value(value).expect("structurally valid hostile decision");
        assert_eq!(
            hostile.verify(),
            Err(CalculusAdapterError::CalculusBaselineMismatch)
        );

        let mut value = serde_json::to_value(&decision).expect("value");
        value["outcome"]["Evaluated"]["Refuse"][0] = Value::String("laundered-refusal".to_owned());
        let hostile: CalculusDecisionV1<String, Vec<String>> =
            serde_json::from_value(value).expect("structurally valid hostile decision");
        assert_eq!(
            hostile.verify(),
            Err(CalculusAdapterError::DecisionDigestMismatch)
        );
        assert_eq!(
            hostile.outcome(),
            Err(CalculusAdapterError::DecisionDigestMismatch)
        );
    }

    #[test]
    fn authority_context_substitution_and_lossy_refusal_refuse() {
        let decision = refusal("context-substitution");
        let original = serde_json::to_value(&decision).expect("value");
        for (field, value) in [
            ("schema", Value::String("ag.calculus-adapter/v2".to_owned())),
            ("authority_domain", Value::String("ag.foreign".to_owned())),
            ("epoch", Value::Number(2_u64.into())),
            (
                "evaluator_identity",
                Value::String(Digest::hash_bytes(b"foreign-evaluator").to_string()),
            ),
            (
                "input_digest",
                Value::String(Digest::hash_bytes(b"foreign-input").to_string()),
            ),
        ] {
            let mut hostile = original.clone();
            hostile["context"][field] = value;
            let hostile: CalculusDecisionV1<String, Vec<String>> =
                serde_json::from_value(hostile).expect("structurally valid hostile decision");
            assert!(
                hostile.verify().is_err(),
                "substituted {field} was accepted"
            );
        }

        let mut lossy = original;
        lossy["outcome"]["Evaluated"]["Refuse"] =
            Value::Array(vec![Value::String("missing-standing".to_owned())]);
        let lossy: CalculusDecisionV1<String, Vec<String>> =
            serde_json::from_value(lossy).expect("structurally valid lossy decision");
        assert_eq!(
            lossy.verify(),
            Err(CalculusAdapterError::DecisionDigestMismatch)
        );
    }

    #[test]
    fn lifecycle_origin_must_match_domain_and_epoch() {
        let mut value = serde_json::to_value(context("origin-mismatch")).expect("context");
        value["lifecycle_origin"]["epoch"] = Value::Number(2_u64.into());
        let hostile: CalculusAdapterContextV1 =
            serde_json::from_value(value).expect("structurally valid context");
        assert_eq!(
            hostile.verify(),
            Err(CalculusAdapterError::LifecycleContextMismatch)
        );
    }

    #[test]
    fn evaluator_and_input_identity_are_part_of_the_decision() {
        let first = refusal("first");
        let second = refusal("second");
        assert_ne!(first.decision_digest(), second.decision_digest());
    }

    #[test]
    fn indeterminate_never_projects_as_refusal_or_admission() {
        let decision = CalculusDecisionV1::<String, Vec<String>>::new(
            context("indeterminate"),
            OperationalEvaluation::indeterminate(FailureEvidence::new(
                OperationalFailureKind::IncompleteEvaluation,
                Digest::hash_bytes(b"right branch never decided"),
            )),
        )
        .expect("adapt indeterminate");
        assert_eq!(
            decision.disposition().expect("verified disposition"),
            CalculusDispositionV1::Indeterminate
        );
        assert_eq!(
            decision.outcome().expect("verified outcome").admitted(),
            None
        );
    }

    #[test]
    fn floating_point_native_evidence_is_not_canonical_adapter_material() {
        let result = CalculusDecisionV1::<f64, ()>::new(
            context("float"),
            OperationalEvaluation::evaluated(NativeJudgment::Admit(1.5)),
        );
        assert!(matches!(
            result,
            Err(CalculusAdapterError::Canonicalization(_))
        ));
    }

    #[test]
    fn consumption_survives_serialized_restart_and_refuses_replay() {
        let decision = refusal("restart");
        let mut ledger =
            CalculusDecisionLedgerV1::new(decision.context().lifecycle_origin().clone());
        let receipt = ledger
            .consume(&decision, Digest::hash_bytes(b"consumer"))
            .expect("first consumption");
        let bytes = serde_json::to_vec(&ledger).expect("serialize ledger");
        let mut restarted: CalculusDecisionLedgerV1 =
            serde_json::from_slice(&bytes).expect("restart ledger");
        restarted.verify().expect("verify restarted ledger");
        assert_eq!(
            restarted.consume(&decision, Digest::hash_bytes(b"other-consumer")),
            Err(CalculusAdapterError::DecisionAlreadyConsumed)
        );
        assert_eq!(
            restarted
                .receipt(decision.decision_digest())
                .expect("verified receipt lookup"),
            Some(&receipt)
        );
    }

    #[test]
    fn substituted_restart_ledger_refuses_as_corrupt() {
        let decision = refusal("hostile-restart");
        let mut ledger =
            CalculusDecisionLedgerV1::new(decision.context().lifecycle_origin().clone());
        ledger
            .consume(&decision, Digest::hash_bytes(b"consumer"))
            .expect("consume");
        let mut value = serde_json::to_value(&ledger).expect("ledger value");
        let (_, receipt) = value["consumed"]
            .as_object_mut()
            .expect("consumed object")
            .iter_mut()
            .next()
            .expect("receipt");
        receipt["consumer"] =
            Value::String(Digest::hash_bytes(b"substituted-consumer").to_string());
        let hostile: CalculusDecisionLedgerV1 =
            serde_json::from_value(value).expect("structurally valid hostile ledger");
        assert_eq!(
            hostile.verify(),
            Err(CalculusAdapterError::UseReceiptMismatch)
        );
    }

    #[test]
    fn foreign_origin_refuses_before_consumption() {
        let decision = refusal("foreign");
        let mut ledger = CalculusDecisionLedgerV1::new(LifecycleOrigin::new(
            AuthorityDomain::parse("ag.test").expect("domain"),
            Epoch::parse("1").expect("epoch"),
            LifecycleNonce::new([8; 16]),
        ));
        assert_eq!(
            ledger.consume(&decision, Digest::hash_bytes(b"consumer")),
            Err(CalculusAdapterError::ForeignLifecycleOrigin)
        );
    }

    #[test]
    fn concurrent_consumers_observe_one_winner() {
        let decision = Arc::new(refusal("concurrent"));
        let ledger = Arc::new(Mutex::new(CalculusDecisionLedgerV1::new(
            decision.context().lifecycle_origin().clone(),
        )));
        let mut joins = Vec::new();
        for index in 0_u8..8 {
            let decision = Arc::clone(&decision);
            let ledger = Arc::clone(&ledger);
            joins.push(std::thread::spawn(move || {
                ledger
                    .lock()
                    .expect("ledger lock")
                    .consume(&decision, Digest::hash_bytes(&[index]))
            }));
        }
        let results: Vec<_> = joins
            .into_iter()
            .map(|join| join.join().expect("consumer join"))
            .collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| { **result == Err(CalculusAdapterError::DecisionAlreadyConsumed) })
                .count(),
            7
        );
    }
}
