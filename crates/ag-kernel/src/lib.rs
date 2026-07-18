//! Pure governed-admissibility kernel.
//!
//! This crate deliberately contains no I/O and no policy language.  It keeps
//! judgment families distinct, composes their evidence without loss, and
//! reconstructs process-local authority from committed evidence.  Durable
//! provenance remains the responsibility of the store that supplies that
//! evidence.
//!
//! Book references are intentionally not interchangeable:
//!
//! ```compile_fail
//! use ag_kernel::{CustodyRef, StandingRef};
//!
//! fn needs_standing(_: StandingRef) {}
//! fn cannot_cross_books(custody: CustodyRef) {
//!     needs_standing(custody);
//! }
//! ```
//!
//! Authority is not a wire token and cannot be deserialized:
//!
//! ```compile_fail
//! use ag_kernel::{Authority, EffectFamily};
//!
//! let _: Authority<EffectFamily> = serde_json::from_str("{}").unwrap();
//! ```
//!
//! Its private seal also prevents direct construction:
//!
//! ```compile_fail
//! use ag_kernel::{Authority, EffectCrossingWitness, EffectFamily};
//! use ag_primitives::Digest;
//!
//! fn forge(
//!     witness: EffectCrossingWitness,
//!     commit_digest: Digest,
//! ) -> Authority<EffectFamily> {
//!     Authority { witness, commit_digest, _family: core::marker::PhantomData }
//! }
//! ```

mod authority;
mod family;
mod judgment;
mod path;
mod recomposition;

pub use authority::{
    AdmissionCommit, Authority, AuthorityError, AuthorityFamily, EffectFamily,
    reconstruct_effect_authority,
};
pub use family::{
    CapacityBook, CapacityBookEntry, CapacityClaim, CapacityFailure, CapacityRef, CapacityRefusal,
    CapacityWitness, CustodyBook, CustodyBookEntry, CustodyClaim, CustodyFailure, CustodyRef,
    CustodyRefusal, CustodyWitness, EffectCrossingClaim, EffectCrossingRefusal,
    EffectCrossingWitness, EffectFamilyRefusal, FamilyBookError, ObligationBook,
    ObligationBookEntry, ObligationClaim, ObligationFailure, ObligationRef, ObligationRefusal,
    ObligationWitness, ProposalCrossingClaim, ProposalCrossingRefusal, ProposalCrossingWitness,
    ProposalFamilyRefusal, StandingBook, StandingBookEntry, StandingClaim, StandingFailure,
    StandingRef, StandingRefusal, StandingWitness, decide_capacity, decide_custody,
    decide_obligation, decide_standing, evaluate_effect_crossing, evaluate_proposal_crossing,
};
pub use judgment::{
    FailureEvidence, NativeJudgment, NonEmpty, OperationalEvaluation, OperationalFailureKind,
};
pub use path::{EvaluationTrace, LocatedObstruction, PathVerdict, TraceOutcome, TraceStep};
pub use recomposition::{
    AccountedBoundary, BoundaryManifest, BoundaryRequirement, BoundarySlice, ManifestError,
    RecompositionFailure, RecompositionRefusal, RecompositionWitness, recompose,
};
