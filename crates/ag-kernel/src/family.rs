//! Concrete, non-convertible judgment families and named crossings.

use ag_primitives::{
    BookKind, BookRef, CapacityBook as CapacityBookTag, CustodyBook as CustodyBookTag, Digest,
    LifecycleOrigin, ObligationBook as ObligationBookTag, StandingBook as StandingBookTag,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{NativeJudgment, NonEmpty};

/// A reference into the standing book.
pub type StandingRef = BookRef<StandingBookTag>;
/// A reference into the custody book.
pub type CustodyRef = BookRef<CustodyBookTag>;
/// A reference into the obligation book.
pub type ObligationRef = BookRef<ObligationBookTag>;
/// A reference into the capacity book.
pub type CapacityRef = BookRef<CapacityBookTag>;

/// Failure while replaying a committed family-book entry.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum FamilyBookError {
    /// An entry belongs to another lifecycle origin.
    #[error("{kind:?} entry has foreign lifecycle origin")]
    ForeignOrigin {
        /// Book being replayed.
        kind: BookKind,
        /// Origin of this book.
        expected: LifecycleOrigin,
        /// Origin encoded by the entry reference.
        observed: LifecycleOrigin,
    },
    /// A local reference appeared more than once.
    #[error("duplicate {kind:?} book reference")]
    DuplicateReference {
        /// Book being replayed.
        kind: BookKind,
    },
    /// Canonical book-head material could not be encoded.
    #[error("cannot canonicalize {kind:?} book event: {message}")]
    Canonicalization {
        /// Book being replayed.
        kind: BookKind,
        /// Serialization failure.
        message: String,
    },
}

macro_rules! define_family {
    (
        $book:ident, $entry:ident, $claim:ident, $witness:ident,
        $refusal:ident, $failure:ident, $ref_ty:ident, $kind:expr,
        $empty_domain:literal, $decide:ident
    ) => {
        #[doc = concat!("One committed entry in the ", stringify!($book), ".")]
        #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
        pub struct $entry {
            reference: $ref_ty,
            subject_digest: Digest,
        }

        impl $entry {
            /// Creates an exact family-book entry.
            #[must_use]
            pub const fn new(reference: $ref_ty, subject_digest: Digest) -> Self {
                Self {
                    reference,
                    subject_digest,
                }
            }

            /// Returns the typed reference.
            #[must_use]
            pub const fn reference(&self) -> &$ref_ty {
                &self.reference
            }

            /// Returns the exact subject digest.
            #[must_use]
            pub const fn subject_digest(&self) -> &Digest {
                &self.subject_digest
            }
        }

        #[doc = concat!("Replayable state of the ", stringify!($book), ".")]
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct $book {
            origin: LifecycleOrigin,
            head: Digest,
            entries: Vec<$entry>,
        }

        impl $book {
            /// Creates an empty book for one exact lifecycle origin.
            #[must_use]
            pub fn new(origin: LifecycleOrigin) -> Self {
                Self {
                    origin,
                    head: Digest::hash_bytes($empty_domain.as_bytes()),
                    entries: Vec::new(),
                }
            }

            /// Replays one entry known by the caller to be durably committed.
            ///
            /// This pure kernel verifies family correspondence and advances the
            /// deterministic book head. Durable provenance is verified by the
            /// supplying store before this method is called.
            ///
            /// # Errors
            ///
            /// Returns [`FamilyBookError`] for a foreign origin, duplicate
            /// reference, or canonicalization failure.
            pub fn replay_committed(&mut self, entry: $entry) -> Result<(), FamilyBookError> {
                if entry.reference.origin() != &self.origin {
                    return Err(FamilyBookError::ForeignOrigin {
                        kind: $kind,
                        expected: self.origin.clone(),
                        observed: entry.reference.origin().clone(),
                    });
                }
                if self
                    .entries
                    .iter()
                    .any(|existing| existing.reference == entry.reference)
                {
                    return Err(FamilyBookError::DuplicateReference { kind: $kind });
                }

                let material =
                    serde_jcs::to_vec(&($kind, &self.head, &entry)).map_err(|error| {
                        FamilyBookError::Canonicalization {
                            kind: $kind,
                            message: error.to_string(),
                        }
                    })?;
                let mut domain_separated = concat!("ag-ng:book-event:v1:", $empty_domain)
                    .as_bytes()
                    .to_vec();
                domain_separated.push(0);
                domain_separated.extend(material);
                self.head = Digest::hash_bytes(&domain_separated);
                self.entries.push(entry);
                Ok(())
            }

            /// Returns the lifecycle origin of this book.
            #[must_use]
            pub const fn origin(&self) -> &LifecycleOrigin {
                &self.origin
            }

            /// Returns the current deterministic book head.
            #[must_use]
            pub const fn head(&self) -> &Digest {
                &self.head
            }

            /// Returns committed entries in replay order.
            #[must_use]
            pub fn entries(&self) -> &[$entry] {
                &self.entries
            }
        }

        #[doc = concat!("Exact claim against the ", stringify!($book), ".")]
        #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
        pub struct $claim {
            origin: LifecycleOrigin,
            subject_digest: Digest,
            reference: $ref_ty,
        }

        impl $claim {
            /// Creates an exact family claim.
            #[must_use]
            pub const fn new(
                origin: LifecycleOrigin,
                subject_digest: Digest,
                reference: $ref_ty,
            ) -> Self {
                Self {
                    origin,
                    subject_digest,
                    reference,
                }
            }

            /// Returns the claim lifecycle origin.
            #[must_use]
            pub const fn origin(&self) -> &LifecycleOrigin {
                &self.origin
            }

            /// Returns the exact subject digest.
            #[must_use]
            pub const fn subject_digest(&self) -> &Digest {
                &self.subject_digest
            }

            /// Returns the typed family reference.
            #[must_use]
            pub const fn reference(&self) -> &$ref_ty {
                &self.reference
            }
        }

        #[doc = concat!("Replayable native witness for ", stringify!($book), ".")]
        #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
        pub struct $witness {
            claim: $claim,
            book_head: Digest,
            observed_subject_digest: Digest,
        }

        impl $witness {
            /// Returns the exact witnessed claim.
            #[must_use]
            pub const fn claim(&self) -> &$claim {
                &self.claim
            }

            /// Returns the book head at evaluation time.
            #[must_use]
            pub const fn book_head(&self) -> &Digest {
                &self.book_head
            }

            /// Returns the observed entry subject.
            #[must_use]
            pub const fn observed_subject_digest(&self) -> &Digest {
                &self.observed_subject_digest
            }
        }

        #[doc = concat!("One native failure against ", stringify!($book), ".")]
        #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
        pub enum $failure {
            /// The claim was evaluated against a book from another lifecycle.
            BookOriginMismatch {
                /// Origin carried by the claim.
                claim_origin: LifecycleOrigin,
                /// Origin of the evaluated book.
                book_origin: LifecycleOrigin,
            },
            /// The typed reference belongs to another lifecycle.
            ReferenceOriginMismatch {
                /// Origin carried by the claim.
                claim_origin: LifecycleOrigin,
                /// Origin carried by the typed reference.
                reference_origin: LifecycleOrigin,
            },
            /// The exact typed reference is absent.
            MissingReference {
                /// Missing typed reference.
                reference: $ref_ty,
            },
            /// The reference exists but names a different subject.
            SubjectMismatch {
                /// Exact typed reference evaluated.
                reference: $ref_ty,
                /// Subject required by the claim.
                expected: Digest,
                /// Subject recorded by the book.
                observed: Digest,
            },
        }

        #[doc = concat!("Non-empty family-native refusal for ", stringify!($book), ".")]
        #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
        pub struct $refusal {
            failures: NonEmpty<$failure>,
        }

        impl $refusal {
            /// Returns every independently observed native failure.
            #[must_use]
            pub const fn failures(&self) -> &NonEmpty<$failure> {
                &self.failures
            }
        }

        #[doc = concat!("Decides one exact claim against ", stringify!($book), ".")]
        #[must_use]
        pub fn $decide(book: &$book, claim: &$claim) -> NativeJudgment<$witness, $refusal> {
            let mut failures = Vec::new();
            if claim.origin != book.origin {
                failures.push($failure::BookOriginMismatch {
                    claim_origin: claim.origin.clone(),
                    book_origin: book.origin.clone(),
                });
            }
            if claim.reference.origin() != &claim.origin {
                failures.push($failure::ReferenceOriginMismatch {
                    claim_origin: claim.origin.clone(),
                    reference_origin: claim.reference.origin().clone(),
                });
            }

            let observed = book
                .entries
                .iter()
                .find(|entry| entry.reference == claim.reference);
            match observed {
                None => failures.push($failure::MissingReference {
                    reference: claim.reference.clone(),
                }),
                Some(entry) if entry.subject_digest != claim.subject_digest => {
                    failures.push($failure::SubjectMismatch {
                        reference: claim.reference.clone(),
                        expected: claim.subject_digest.clone(),
                        observed: entry.subject_digest.clone(),
                    });
                }
                Some(_) => {}
            }

            if let Some(failures) = NonEmpty::from_vec(failures) {
                NativeJudgment::Refuse($refusal { failures })
            } else {
                let observed = observed.expect("absence produces a refusal");
                NativeJudgment::Admit($witness {
                    claim: claim.clone(),
                    book_head: book.head.clone(),
                    observed_subject_digest: observed.subject_digest.clone(),
                })
            }
        }
    };
}

define_family!(
    StandingBook,
    StandingBookEntry,
    StandingClaim,
    StandingWitness,
    StandingRefusal,
    StandingFailure,
    StandingRef,
    BookKind::Standing,
    "standing",
    decide_standing
);
define_family!(
    CustodyBook,
    CustodyBookEntry,
    CustodyClaim,
    CustodyWitness,
    CustodyRefusal,
    CustodyFailure,
    CustodyRef,
    BookKind::Custody,
    "custody",
    decide_custody
);
define_family!(
    ObligationBook,
    ObligationBookEntry,
    ObligationClaim,
    ObligationWitness,
    ObligationRefusal,
    ObligationFailure,
    ObligationRef,
    BookKind::Obligation,
    "obligation",
    decide_obligation
);
define_family!(
    CapacityBook,
    CapacityBookEntry,
    CapacityClaim,
    CapacityWitness,
    CapacityRefusal,
    CapacityFailure,
    CapacityRef,
    BookKind::Capacity,
    "capacity",
    decide_capacity
);

/// Exact named crossing needed to admit a proposal into governed custody.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalCrossingClaim {
    standing: StandingClaim,
    custody: CustodyClaim,
}

impl ProposalCrossingClaim {
    /// Creates the named proposal crossing.
    #[must_use]
    pub const fn new(standing: StandingClaim, custody: CustodyClaim) -> Self {
        Self { standing, custody }
    }

    /// Returns the standing claim.
    #[must_use]
    pub const fn standing(&self) -> &StandingClaim {
        &self.standing
    }

    /// Returns the custody claim.
    #[must_use]
    pub const fn custody(&self) -> &CustodyClaim {
        &self.custody
    }
}

/// All evidence retained by an admitted proposal crossing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalCrossingWitness {
    standing: StandingWitness,
    custody: CustodyWitness,
}

impl ProposalCrossingWitness {
    /// Returns the standing witness without converting it to custody.
    #[must_use]
    pub const fn standing(&self) -> &StandingWitness {
        &self.standing
    }

    /// Returns the custody witness without converting it to standing.
    #[must_use]
    pub const fn custody(&self) -> &CustodyWitness {
        &self.custody
    }
}

/// Lossless family tag for a proposal-crossing refusal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProposalFamilyRefusal {
    /// Native standing refusal.
    Standing(StandingRefusal),
    /// Native custody refusal.
    Custody(CustodyRefusal),
    /// Individually valid family claims came from different lifecycles.
    OriginMismatch {
        /// Family whose origin differs from the standing claim.
        family: BookKind,
        /// Origin fixed by the standing claim.
        expected: LifecycleOrigin,
        /// Origin carried by the other family claim.
        observed: LifecycleOrigin,
    },
}

/// Non-empty refusal from the named proposal crossing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalCrossingRefusal {
    failures: NonEmpty<ProposalFamilyRefusal>,
}

impl ProposalCrossingRefusal {
    /// Returns every family refusal in evaluation order.
    #[must_use]
    pub const fn failures(&self) -> &NonEmpty<ProposalFamilyRefusal> {
        &self.failures
    }
}

/// Evaluates the only standing-plus-custody crossing needed by proposal ingest.
#[must_use]
pub fn evaluate_proposal_crossing(
    standing_book: &StandingBook,
    custody_book: &CustodyBook,
    claim: &ProposalCrossingClaim,
) -> NativeJudgment<ProposalCrossingWitness, ProposalCrossingRefusal> {
    let standing = decide_standing(standing_book, &claim.standing);
    let custody = decide_custody(custody_book, &claim.custody);
    let mut crossing_failures = Vec::new();
    if claim.custody.origin != claim.standing.origin {
        crossing_failures.push(ProposalFamilyRefusal::OriginMismatch {
            family: BookKind::Custody,
            expected: claim.standing.origin.clone(),
            observed: claim.custody.origin.clone(),
        });
    }
    match (standing, custody) {
        (NativeJudgment::Admit(standing), NativeJudgment::Admit(custody)) => {
            if let Some(failures) = NonEmpty::from_vec(crossing_failures) {
                NativeJudgment::Refuse(ProposalCrossingRefusal { failures })
            } else {
                NativeJudgment::Admit(ProposalCrossingWitness { standing, custody })
            }
        }
        (NativeJudgment::Refuse(standing), custody) => {
            let mut failures = NonEmpty::new(ProposalFamilyRefusal::Standing(standing));
            if let NativeJudgment::Refuse(refusal) = custody {
                failures.push(ProposalFamilyRefusal::Custody(refusal));
            }
            for refusal in crossing_failures {
                failures.push(refusal);
            }
            NativeJudgment::Refuse(ProposalCrossingRefusal { failures })
        }
        (NativeJudgment::Admit(_), NativeJudgment::Refuse(custody)) => {
            let mut failures = NonEmpty::new(ProposalFamilyRefusal::Custody(custody));
            for refusal in crossing_failures {
                failures.push(refusal);
            }
            NativeJudgment::Refuse(ProposalCrossingRefusal { failures })
        }
    }
}

/// Exact named crossing required before an effect can acquire authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectCrossingClaim {
    standing: StandingClaim,
    custody: CustodyClaim,
    obligation: ObligationClaim,
    capacity: CapacityClaim,
}

impl EffectCrossingClaim {
    /// Creates the four-family effect crossing.
    #[must_use]
    pub const fn new(
        standing: StandingClaim,
        custody: CustodyClaim,
        obligation: ObligationClaim,
        capacity: CapacityClaim,
    ) -> Self {
        Self {
            standing,
            custody,
            obligation,
            capacity,
        }
    }

    /// Returns the standing claim.
    #[must_use]
    pub const fn standing(&self) -> &StandingClaim {
        &self.standing
    }

    /// Returns the custody claim.
    #[must_use]
    pub const fn custody(&self) -> &CustodyClaim {
        &self.custody
    }

    /// Returns the obligation claim.
    #[must_use]
    pub const fn obligation(&self) -> &ObligationClaim {
        &self.obligation
    }

    /// Returns the capacity claim.
    #[must_use]
    pub const fn capacity(&self) -> &CapacityClaim {
        &self.capacity
    }
}

/// Composite witness retaining every native family witness.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectCrossingWitness {
    standing: StandingWitness,
    custody: CustodyWitness,
    obligation: ObligationWitness,
    capacity: CapacityWitness,
}

impl EffectCrossingWitness {
    /// Returns the native standing witness.
    #[must_use]
    pub const fn standing(&self) -> &StandingWitness {
        &self.standing
    }

    /// Returns the native custody witness.
    #[must_use]
    pub const fn custody(&self) -> &CustodyWitness {
        &self.custody
    }

    /// Returns the native obligation witness.
    #[must_use]
    pub const fn obligation(&self) -> &ObligationWitness {
        &self.obligation
    }

    /// Returns the native capacity witness.
    #[must_use]
    pub const fn capacity(&self) -> &CapacityWitness {
        &self.capacity
    }
}

/// Lossless family tag for effect-crossing refusal evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EffectFamilyRefusal {
    /// Native standing refusal.
    Standing(StandingRefusal),
    /// Native custody refusal.
    Custody(CustodyRefusal),
    /// Native obligation refusal.
    Obligation(ObligationRefusal),
    /// Native capacity refusal.
    Capacity(CapacityRefusal),
    /// Individually valid family claims came from different lifecycles.
    OriginMismatch {
        /// Family whose origin differs from the standing claim.
        family: BookKind,
        /// Origin fixed by the standing claim.
        expected: LifecycleOrigin,
        /// Origin carried by the other family claim.
        observed: LifecycleOrigin,
    },
}

/// Non-empty refusal from the named effect crossing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectCrossingRefusal {
    failures: NonEmpty<EffectFamilyRefusal>,
}

impl EffectCrossingRefusal {
    /// Returns every native family refusal in evaluation order.
    #[must_use]
    pub const fn failures(&self) -> &NonEmpty<EffectFamilyRefusal> {
        &self.failures
    }
}

/// Evaluates all four effect families without short-circuiting.
#[must_use]
pub fn evaluate_effect_crossing(
    standing_book: &StandingBook,
    custody_book: &CustodyBook,
    obligation_book: &ObligationBook,
    capacity_book: &CapacityBook,
    claim: &EffectCrossingClaim,
) -> NativeJudgment<EffectCrossingWitness, EffectCrossingRefusal> {
    let standing = decide_standing(standing_book, &claim.standing);
    let custody = decide_custody(custody_book, &claim.custody);
    let obligation = decide_obligation(obligation_book, &claim.obligation);
    let capacity = decide_capacity(capacity_book, &claim.capacity);
    let mut crossing_failures = Vec::new();
    for (family, observed) in [
        (BookKind::Custody, &claim.custody.origin),
        (BookKind::Obligation, &claim.obligation.origin),
        (BookKind::Capacity, &claim.capacity.origin),
    ] {
        if observed != &claim.standing.origin {
            crossing_failures.push(EffectFamilyRefusal::OriginMismatch {
                family,
                expected: claim.standing.origin.clone(),
                observed: observed.clone(),
            });
        }
    }

    match (standing, custody, obligation, capacity) {
        (
            NativeJudgment::Admit(standing),
            NativeJudgment::Admit(custody),
            NativeJudgment::Admit(obligation),
            NativeJudgment::Admit(capacity),
        ) => {
            if let Some(failures) = NonEmpty::from_vec(crossing_failures) {
                NativeJudgment::Refuse(EffectCrossingRefusal { failures })
            } else {
                NativeJudgment::Admit(EffectCrossingWitness {
                    standing,
                    custody,
                    obligation,
                    capacity,
                })
            }
        }
        (NativeJudgment::Refuse(standing), custody, obligation, capacity) => {
            let mut failures = NonEmpty::new(EffectFamilyRefusal::Standing(standing));
            if let NativeJudgment::Refuse(refusal) = custody {
                failures.push(EffectFamilyRefusal::Custody(refusal));
            }
            if let NativeJudgment::Refuse(refusal) = obligation {
                failures.push(EffectFamilyRefusal::Obligation(refusal));
            }
            if let NativeJudgment::Refuse(refusal) = capacity {
                failures.push(EffectFamilyRefusal::Capacity(refusal));
            }
            for refusal in crossing_failures {
                failures.push(refusal);
            }
            NativeJudgment::Refuse(EffectCrossingRefusal { failures })
        }
        (NativeJudgment::Admit(_), NativeJudgment::Refuse(custody), obligation, capacity) => {
            let mut failures = NonEmpty::new(EffectFamilyRefusal::Custody(custody));
            if let NativeJudgment::Refuse(refusal) = obligation {
                failures.push(EffectFamilyRefusal::Obligation(refusal));
            }
            if let NativeJudgment::Refuse(refusal) = capacity {
                failures.push(EffectFamilyRefusal::Capacity(refusal));
            }
            for refusal in crossing_failures {
                failures.push(refusal);
            }
            NativeJudgment::Refuse(EffectCrossingRefusal { failures })
        }
        (
            NativeJudgment::Admit(_),
            NativeJudgment::Admit(_),
            NativeJudgment::Refuse(obligation),
            capacity,
        ) => {
            let mut failures = NonEmpty::new(EffectFamilyRefusal::Obligation(obligation));
            if let NativeJudgment::Refuse(refusal) = capacity {
                failures.push(EffectFamilyRefusal::Capacity(refusal));
            }
            for refusal in crossing_failures {
                failures.push(refusal);
            }
            NativeJudgment::Refuse(EffectCrossingRefusal { failures })
        }
        (
            NativeJudgment::Admit(_),
            NativeJudgment::Admit(_),
            NativeJudgment::Admit(_),
            NativeJudgment::Refuse(capacity),
        ) => {
            let mut failures = NonEmpty::new(EffectFamilyRefusal::Capacity(capacity));
            for refusal in crossing_failures {
                failures.push(refusal);
            }
            NativeJudgment::Refuse(EffectCrossingRefusal { failures })
        }
    }
}

#[cfg(test)]
mod tests {
    use ag_primitives::{AuthorityDomain, BookLocalId, Epoch, LifecycleNonce};

    use super::*;

    fn origin(domain: &str, nonce: u8) -> LifecycleOrigin {
        LifecycleOrigin::new(
            AuthorityDomain::new(domain).unwrap(),
            Epoch::new(1).unwrap(),
            LifecycleNonce::new([nonce; 16]),
        )
    }

    fn local_id(value: &str) -> BookLocalId {
        BookLocalId::new(value).unwrap()
    }

    fn subject(value: &str) -> Digest {
        Digest::hash_bytes(value.as_bytes())
    }

    #[test]
    fn one_family_retains_simultaneous_native_failures() {
        let book = StandingBook::new(origin("book", 1));
        let claim_origin = origin("claim", 2);
        let foreign_reference = StandingRef::new(origin("reference", 3), local_id("standing-1"));
        let claim = StandingClaim::new(claim_origin, subject("subject"), foreign_reference);

        let NativeJudgment::Refuse(refusal) = decide_standing(&book, &claim) else {
            panic!("foreign absent claim must refuse");
        };
        assert_eq!(refusal.failures().len(), 3);
        assert!(matches!(
            refusal.failures().first(),
            StandingFailure::BookOriginMismatch { .. }
        ));
    }

    #[test]
    fn effect_crossing_keeps_all_four_native_refusals() {
        let origin = origin("effect", 4);
        let standing = StandingClaim::new(
            origin.clone(),
            subject("standing"),
            StandingRef::new(origin.clone(), local_id("standing-1")),
        );
        let custody = CustodyClaim::new(
            origin.clone(),
            subject("custody"),
            CustodyRef::new(origin.clone(), local_id("custody-1")),
        );
        let obligation = ObligationClaim::new(
            origin.clone(),
            subject("obligation"),
            ObligationRef::new(origin.clone(), local_id("obligation-1")),
        );
        let capacity = CapacityClaim::new(
            origin.clone(),
            subject("capacity"),
            CapacityRef::new(origin.clone(), local_id("capacity-1")),
        );
        let claim = EffectCrossingClaim::new(standing, custody, obligation, capacity);
        let NativeJudgment::Refuse(refusal) = evaluate_effect_crossing(
            &StandingBook::new(origin.clone()),
            &CustodyBook::new(origin.clone()),
            &ObligationBook::new(origin.clone()),
            &CapacityBook::new(origin),
            &claim,
        ) else {
            panic!("four absent entries must refuse");
        };
        assert_eq!(refusal.failures().len(), 4);
        assert!(matches!(
            refusal.failures().iter().next(),
            Some(EffectFamilyRefusal::Standing(_))
        ));
        assert!(matches!(
            refusal.failures().iter().nth(3),
            Some(EffectFamilyRefusal::Capacity(_))
        ));
    }

    #[test]
    fn named_effect_crossing_retains_every_witness() {
        let origin = origin("effect", 5);
        let standing_ref = StandingRef::new(origin.clone(), local_id("standing-1"));
        let custody_ref = CustodyRef::new(origin.clone(), local_id("custody-1"));
        let obligation_ref = ObligationRef::new(origin.clone(), local_id("obligation-1"));
        let capacity_ref = CapacityRef::new(origin.clone(), local_id("capacity-1"));
        let mut standing_book = StandingBook::new(origin.clone());
        let mut custody_book = CustodyBook::new(origin.clone());
        let mut obligation_book = ObligationBook::new(origin.clone());
        let mut capacity_book = CapacityBook::new(origin.clone());
        standing_book
            .replay_committed(StandingBookEntry::new(
                standing_ref.clone(),
                subject("standing"),
            ))
            .unwrap();
        custody_book
            .replay_committed(CustodyBookEntry::new(
                custody_ref.clone(),
                subject("custody"),
            ))
            .unwrap();
        obligation_book
            .replay_committed(ObligationBookEntry::new(
                obligation_ref.clone(),
                subject("obligation"),
            ))
            .unwrap();
        capacity_book
            .replay_committed(CapacityBookEntry::new(
                capacity_ref.clone(),
                subject("capacity"),
            ))
            .unwrap();
        let claim = EffectCrossingClaim::new(
            StandingClaim::new(origin.clone(), subject("standing"), standing_ref),
            CustodyClaim::new(origin.clone(), subject("custody"), custody_ref),
            ObligationClaim::new(origin.clone(), subject("obligation"), obligation_ref),
            CapacityClaim::new(origin, subject("capacity"), capacity_ref),
        );

        let NativeJudgment::Admit(witness) = evaluate_effect_crossing(
            &standing_book,
            &custody_book,
            &obligation_book,
            &capacity_book,
            &claim,
        ) else {
            panic!("exact committed entries must admit");
        };
        assert_eq!(witness.standing().claim(), claim.standing());
        assert_eq!(witness.custody().claim(), claim.custody());
        assert_eq!(witness.obligation().claim(), claim.obligation());
        assert_eq!(witness.capacity().claim(), claim.capacity());
    }

    #[test]
    fn individually_valid_foreign_lifecycles_cannot_cross() {
        let standing_origin = origin("standing", 10);
        let custody_origin = origin("custody", 11);
        let obligation_origin = origin("obligation", 12);
        let capacity_origin = origin("capacity", 13);
        let standing_ref = StandingRef::new(standing_origin.clone(), local_id("standing-1"));
        let custody_ref = CustodyRef::new(custody_origin.clone(), local_id("custody-1"));
        let obligation_ref =
            ObligationRef::new(obligation_origin.clone(), local_id("obligation-1"));
        let capacity_ref = CapacityRef::new(capacity_origin.clone(), local_id("capacity-1"));
        let mut standing_book = StandingBook::new(standing_origin.clone());
        let mut custody_book = CustodyBook::new(custody_origin.clone());
        let mut obligation_book = ObligationBook::new(obligation_origin.clone());
        let mut capacity_book = CapacityBook::new(capacity_origin.clone());
        standing_book
            .replay_committed(StandingBookEntry::new(
                standing_ref.clone(),
                subject("standing"),
            ))
            .unwrap();
        custody_book
            .replay_committed(CustodyBookEntry::new(
                custody_ref.clone(),
                subject("custody"),
            ))
            .unwrap();
        obligation_book
            .replay_committed(ObligationBookEntry::new(
                obligation_ref.clone(),
                subject("obligation"),
            ))
            .unwrap();
        capacity_book
            .replay_committed(CapacityBookEntry::new(
                capacity_ref.clone(),
                subject("capacity"),
            ))
            .unwrap();
        let claim = EffectCrossingClaim::new(
            StandingClaim::new(standing_origin, subject("standing"), standing_ref),
            CustodyClaim::new(custody_origin, subject("custody"), custody_ref),
            ObligationClaim::new(obligation_origin, subject("obligation"), obligation_ref),
            CapacityClaim::new(capacity_origin, subject("capacity"), capacity_ref),
        );

        let NativeJudgment::Refuse(refusal) = evaluate_effect_crossing(
            &standing_book,
            &custody_book,
            &obligation_book,
            &capacity_book,
            &claim,
        ) else {
            panic!("foreign lifecycle witnesses must not compose");
        };
        assert_eq!(refusal.failures().len(), 3);
        assert!(
            refusal
                .failures()
                .iter()
                .all(|failure| matches!(failure, EffectFamilyRefusal::OriginMismatch { .. }))
        );
    }
}
