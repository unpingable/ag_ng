//! Reconstruction of sealed, process-local authority from committed evidence.

use std::marker::PhantomData;

use ag_primitives::Digest;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    CapacityBook, CustodyBook, EffectCrossingClaim, EffectCrossingWitness, NativeJudgment,
    ObligationBook, StandingBook, evaluate_effect_crossing,
};

mod sealed {
    pub trait Sealed {}
}

/// A closed family for which process-local authority may be reconstructed.
pub trait AuthorityFamily: sealed::Sealed {
    /// Replayable witness native to this family.
    type Witness: Clone + std::fmt::Debug + PartialEq + Eq + Serialize;

    /// Domain separator for committed evidence.
    const DOMAIN: &'static str;
}

macro_rules! authority_family {
    ($name:ident, $witness:ty, $domain:literal) => {
        #[doc = concat!("Authority-family marker for `", stringify!($witness), "`.")]
        #[derive(Debug)]
        pub enum $name {}

        impl sealed::Sealed for $name {}

        impl AuthorityFamily for $name {
            type Witness = $witness;
            const DOMAIN: &'static str = $domain;
        }
    };
}

authority_family!(EffectFamily, EffectCrossingWitness, "effect-crossing");

/// Serialized evidence that a store claims it durably committed.
///
/// This record is intentionally not authority.  Deserializing it establishes
/// only a claim about storage; a family-specific reconstruction function must
/// verify its exact digest, evaluation context, and semantic replay.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionCommit<W> {
    witness: W,
    witness_digest: Digest,
    evaluation_context_digest: Digest,
    commit_digest: Digest,
}

impl<W> AdmissionCommit<W> {
    /// Returns the evidence witness.
    #[must_use]
    pub const fn witness(&self) -> &W {
        &self.witness
    }

    /// Returns the exact witness digest.
    #[must_use]
    pub const fn witness_digest(&self) -> &Digest {
        &self.witness_digest
    }

    /// Returns the exact evaluation-context digest.
    #[must_use]
    pub const fn evaluation_context_digest(&self) -> &Digest {
        &self.evaluation_context_digest
    }

    /// Returns the committed-record digest.
    #[must_use]
    pub const fn commit_digest(&self) -> &Digest {
        &self.commit_digest
    }
}

impl AdmissionCommit<EffectCrossingWitness> {
    /// Builds effect-crossing commit evidence for a durable store transaction.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityError::Canonicalization`] if exact evidence cannot
    /// be encoded as canonical JSON.
    pub fn effect(witness: EffectCrossingWitness) -> Result<Self, AuthorityError> {
        let context = effect_context_digest_from_witness(&witness)?;
        Self::new::<EffectFamily>(witness, context)
    }
}

impl<W> AdmissionCommit<W>
where
    W: Clone + std::fmt::Debug + PartialEq + Eq + Serialize,
{
    fn new<F>(witness: W, evaluation_context_digest: Digest) -> Result<Self, AuthorityError>
    where
        F: AuthorityFamily<Witness = W>,
    {
        let witness_digest = domain_digest(&format!("ag-ng:{}:witness:v1", F::DOMAIN), &witness)?;
        let commit_digest = commit_digest::<F>(&witness_digest, &evaluation_context_digest)?;
        Ok(Self {
            witness,
            witness_digest,
            evaluation_context_digest,
            commit_digest,
        })
    }
}

/// Sealed, process-local authority reconstructed from exact committed evidence.
///
/// The type has no public constructor, does not implement `Serialize` or
/// `Deserialize`, and is deliberately not `Clone`.
#[derive(Debug)]
pub struct Authority<F: AuthorityFamily> {
    witness: F::Witness,
    commit_digest: Digest,
    _family: PhantomData<fn() -> F>,
}

impl<F: AuthorityFamily> Authority<F> {
    /// Returns the replayed native witness.
    #[must_use]
    pub const fn witness(&self) -> &F::Witness {
        &self.witness
    }

    /// Returns the exact durable-evidence commitment.
    #[must_use]
    pub const fn commit_digest(&self) -> &Digest {
        &self.commit_digest
    }

    fn from_verified(record: AdmissionCommit<F::Witness>) -> Self {
        Self {
            witness: record.witness,
            commit_digest: record.commit_digest,
            _family: PhantomData,
        }
    }
}

/// Failure to reconstruct authority from a purported commit record.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum AuthorityError {
    /// Witness bytes do not match the recorded witness digest.
    #[error("committed witness digest does not match exact witness bytes")]
    WitnessDigestMismatch,
    /// Commit binding does not match the witness and evaluation context.
    #[error("committed admission binding digest does not match")]
    CommitDigestMismatch,
    /// The supplied book snapshot differs from the committed evaluation context.
    #[error("admission was not evaluated against the supplied book head(s)")]
    EvaluationContextMismatch,
    /// Replaying the exact claim now produces a native refusal.
    #[error("exact committed claim does not replay as admitted")]
    ReplayRefused,
    /// Replay admits, but with evidence different from the committed witness.
    #[error("replayed witness differs from committed witness")]
    ReplayWitnessMismatch,
    /// Canonical evidence could not be encoded.
    #[error("cannot canonicalize authority evidence: {0}")]
    Canonicalization(String),
}

/// Reconstructs effect authority only after all four native witnesses replay
/// against the exact four-book context committed with the crossing.
///
/// # Errors
///
/// Returns [`AuthorityError`] when digest or context correspondence fails,
/// any native family refuses, or replay yields different composite evidence.
pub fn reconstruct_effect_authority(
    standing_book: &StandingBook,
    custody_book: &CustodyBook,
    obligation_book: &ObligationBook,
    capacity_book: &CapacityBook,
    record: AdmissionCommit<EffectCrossingWitness>,
) -> Result<Authority<EffectFamily>, AuthorityError> {
    verify_record::<EffectFamily>(&record)?;
    let context = effect_context_digest(
        standing_book.head(),
        custody_book.head(),
        obligation_book.head(),
        capacity_book.head(),
    )?;
    if record.evaluation_context_digest != context {
        return Err(AuthorityError::EvaluationContextMismatch);
    }

    let claim = EffectCrossingClaim::new(
        record.witness.standing().claim().clone(),
        record.witness.custody().claim().clone(),
        record.witness.obligation().claim().clone(),
        record.witness.capacity().claim().clone(),
    );
    match evaluate_effect_crossing(
        standing_book,
        custody_book,
        obligation_book,
        capacity_book,
        &claim,
    ) {
        NativeJudgment::Refuse(_) => Err(AuthorityError::ReplayRefused),
        NativeJudgment::Admit(replayed) if replayed != record.witness => {
            Err(AuthorityError::ReplayWitnessMismatch)
        }
        NativeJudgment::Admit(_) => Ok(Authority::from_verified(record)),
    }
}

fn verify_record<F>(record: &AdmissionCommit<F::Witness>) -> Result<(), AuthorityError>
where
    F: AuthorityFamily,
{
    let observed_witness =
        domain_digest(&format!("ag-ng:{}:witness:v1", F::DOMAIN), &record.witness)?;
    if observed_witness != record.witness_digest {
        return Err(AuthorityError::WitnessDigestMismatch);
    }
    let observed_commit =
        commit_digest::<F>(&record.witness_digest, &record.evaluation_context_digest)?;
    if observed_commit != record.commit_digest {
        return Err(AuthorityError::CommitDigestMismatch);
    }
    Ok(())
}

fn commit_digest<F: AuthorityFamily>(
    witness_digest: &Digest,
    context_digest: &Digest,
) -> Result<Digest, AuthorityError> {
    domain_digest(
        &format!("ag-ng:{}:admission-commit:v1", F::DOMAIN),
        &(witness_digest, context_digest),
    )
}

fn effect_context_digest_from_witness(
    witness: &EffectCrossingWitness,
) -> Result<Digest, AuthorityError> {
    effect_context_digest(
        witness.standing().book_head(),
        witness.custody().book_head(),
        witness.obligation().book_head(),
        witness.capacity().book_head(),
    )
}

fn effect_context_digest(
    standing: &Digest,
    custody: &Digest,
    obligation: &Digest,
    capacity: &Digest,
) -> Result<Digest, AuthorityError> {
    domain_digest(
        "ag-ng:effect-crossing:context:v1",
        &(standing, custody, obligation, capacity),
    )
}

fn domain_digest<T: Serialize>(domain: &str, value: &T) -> Result<Digest, AuthorityError> {
    let encoded = serde_jcs::to_vec(value)
        .map_err(|error| AuthorityError::Canonicalization(error.to_string()))?;
    let mut bytes = domain.as_bytes().to_vec();
    bytes.push(0);
    bytes.extend(encoded);
    Ok(Digest::hash_bytes(&bytes))
}

#[cfg(test)]
mod tests {
    use ag_primitives::{AuthorityDomain, BookLocalId, Epoch, LifecycleNonce, LifecycleOrigin};

    use super::*;
    use crate::{
        CapacityBookEntry, CapacityClaim, CapacityRef, CustodyBookEntry, CustodyClaim, CustodyRef,
        EffectCrossingClaim, ObligationBookEntry, ObligationClaim, ObligationRef,
        StandingBookEntry, StandingClaim, StandingRef,
    };

    struct Books {
        standing: StandingBook,
        custody: CustodyBook,
        obligation: ObligationBook,
        capacity: CapacityBook,
    }

    fn origin() -> LifecycleOrigin {
        LifecycleOrigin::new(
            AuthorityDomain::new("authority-test").unwrap(),
            Epoch::new(1).unwrap(),
            LifecycleNonce::new([9; 16]),
        )
    }

    fn admitted_effect() -> (Books, EffectCrossingWitness) {
        let origin = origin();
        let standing_ref =
            StandingRef::new(origin.clone(), BookLocalId::new("standing-1").unwrap());
        let custody_ref = CustodyRef::new(origin.clone(), BookLocalId::new("custody-1").unwrap());
        let obligation_ref =
            ObligationRef::new(origin.clone(), BookLocalId::new("obligation-1").unwrap());
        let capacity_ref =
            CapacityRef::new(origin.clone(), BookLocalId::new("capacity-1").unwrap());
        let mut books = Books {
            standing: StandingBook::new(origin.clone()),
            custody: CustodyBook::new(origin.clone()),
            obligation: ObligationBook::new(origin.clone()),
            capacity: CapacityBook::new(origin.clone()),
        };
        books
            .standing
            .replay_committed(StandingBookEntry::new(
                standing_ref.clone(),
                Digest::hash_bytes(b"standing"),
            ))
            .unwrap();
        books
            .custody
            .replay_committed(CustodyBookEntry::new(
                custody_ref.clone(),
                Digest::hash_bytes(b"custody"),
            ))
            .unwrap();
        books
            .obligation
            .replay_committed(ObligationBookEntry::new(
                obligation_ref.clone(),
                Digest::hash_bytes(b"obligation"),
            ))
            .unwrap();
        books
            .capacity
            .replay_committed(CapacityBookEntry::new(
                capacity_ref.clone(),
                Digest::hash_bytes(b"capacity"),
            ))
            .unwrap();
        let claim = EffectCrossingClaim::new(
            StandingClaim::new(
                origin.clone(),
                Digest::hash_bytes(b"standing"),
                standing_ref,
            ),
            CustodyClaim::new(origin.clone(), Digest::hash_bytes(b"custody"), custody_ref),
            ObligationClaim::new(
                origin.clone(),
                Digest::hash_bytes(b"obligation"),
                obligation_ref,
            ),
            CapacityClaim::new(origin, Digest::hash_bytes(b"capacity"), capacity_ref),
        );
        let NativeJudgment::Admit(witness) = evaluate_effect_crossing(
            &books.standing,
            &books.custody,
            &books.obligation,
            &books.capacity,
            &claim,
        ) else {
            panic!("exact four-book crossing should admit");
        };
        (books, witness)
    }

    #[test]
    fn authority_requires_exact_commit_and_replay() {
        let (books, witness) = admitted_effect();
        let record = AdmissionCommit::effect(witness.clone()).unwrap();
        let authority = reconstruct_effect_authority(
            &books.standing,
            &books.custody,
            &books.obligation,
            &books.capacity,
            record,
        )
        .unwrap();
        assert_eq!(authority.witness(), &witness);
    }

    #[test]
    fn evidence_record_is_not_a_bearer_token() {
        let (books, witness) = admitted_effect();
        let mut record = AdmissionCommit::effect(witness).unwrap();
        record.witness_digest = Digest::hash_bytes(b"forged");
        assert_eq!(
            reconstruct_effect_authority(
                &books.standing,
                &books.custody,
                &books.obligation,
                &books.capacity,
                record,
            )
            .unwrap_err(),
            AuthorityError::WitnessDigestMismatch
        );
    }

    #[test]
    fn changed_book_head_invalidates_reconstruction() {
        let (mut books, witness) = admitted_effect();
        let record = AdmissionCommit::effect(witness).unwrap();
        let second = StandingRef::new(origin(), BookLocalId::new("standing-2").unwrap());
        books
            .standing
            .replay_committed(StandingBookEntry::new(
                second,
                Digest::hash_bytes(b"second"),
            ))
            .unwrap();
        assert_eq!(
            reconstruct_effect_authority(
                &books.standing,
                &books.custody,
                &books.obligation,
                &books.capacity,
                record,
            )
            .unwrap_err(),
            AuthorityError::EvaluationContextMismatch
        );
    }
}
