//! Authority-safe primitive types used across AG-ng.
//!
//! This crate deliberately contains no policy engine, storage, transport, or
//! effect implementation. It supplies the small value types those layers use
//! to avoid ambient strings, unstable Unix identities, non-canonical hashes,
//! and transferable bearer capabilities.
#![forbid(unsafe_code)]

mod capability;
mod digest;
mod identity;
mod origin;

pub use capability::{
    BudgetDimensionV1, CapabilityDefinitionError, CapabilityUseContextV1, CapabilityUseError,
    InferenceBudgetV1, InferenceCapabilityId, InferenceCapabilityV1, InferenceEnvelopeV1,
    InferenceMethodId, InferenceUsageV1, ModelId, ProviderEndpointId, RevocationStateV1,
    SessionLifecycleStateV1, ValidatedInferenceUseV1,
};
pub use digest::{
    Digest, DigestParseError, JcsDocument, JcsError, MAX_JCS_SAFE_INTEGER, MIN_JCS_SAFE_INTEGER,
};
pub use identity::{
    BootIdentity, CgroupIdentity, DaemonPrincipalV1, EnrollmentId, ExecutableIdentityV1,
    HostCredentialObservationV1, InputSetIdentity, LaunchProfileIdentityV1, OperatorPrincipalV1,
    Principal, PrincipalChainError, PrincipalChainNodeV1, PrincipalChainV1,
    PrincipalEnrollmentStateV1, PrincipalId, PrincipalKindV1, PrincipalNameError,
    PrincipalSeparationFailure, PrincipalSeparationPredicateV1, PrincipalV1, ProjectId, RoleId,
    ServicePrincipalV1, SessionId, SystemdUnitIdentity, WorkerProviderRouteV1,
    WorkerSessionPrincipalV1,
};
pub use origin::{
    AnyBookRef, AuthorityDomain, AuthorityDomainId, BookKind, BookKindMismatch, BookLocalId,
    BookRef, BookTag, CapacityBook, CapacityBookRef, CustodyBook, CustodyBookRef, Epoch, EpochId,
    IdentifierError, LifecycleNonce, LifecycleNonceParseError, LifecycleOrigin, ObligationBook,
    ObligationBookRef, StandingBook, StandingBookRef,
};
