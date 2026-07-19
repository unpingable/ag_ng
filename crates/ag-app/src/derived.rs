//! Scoped verifier-derived authority for managed-pointer promotion.
//!
//! This module does not execute a verifier process and does not accept a
//! command line.  A broker adapter must implement [`PinnedPromotionVerifier`]
//! using an already admitted executable descriptor and launch profile.  The
//! validator accepts authority only after exact proposal, principal,
//! verifier, hostile-specimen, and durable one-time-burn correspondence.

use std::collections::{BTreeMap, BTreeSet};

use ag_effect::{CanonicalEffectProposalV1, EffectFamilyV1, RatificationV1, TargetId};
use ag_effect::{EFFECT_CATALOG_SCHEMA_V1, EFFECT_SCHEMA_V1};
use ag_primitives::{
    AuthorityDomain, Digest, Epoch, ExecutableIdentityV1, JcsDocument, LaunchProfileIdentityV1,
    PrincipalChainV1, PrincipalId, PrincipalKindV1, PrincipalSeparationPredicateV1,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema for a human-installed derived-promotion scope.
pub const DERIVED_SCOPE_SCHEMA_V1: &str = "ag.derived-promotion-scope/v1";
/// Schema for an exact typed verifier request.
pub const DERIVED_VERIFIER_REQUEST_SCHEMA_V1: &str = "ag.derived-promotion-verifier-request/v1";
/// Schema for an exact verifier receipt.
pub const DERIVED_VERIFIER_RECEIPT_SCHEMA_V1: &str = "ag.derived-promotion-verifier-receipt/v1";
/// Schema for persisted validated derived-authorization evidence.
pub const DERIVED_AUTHORIZATION_SCHEMA_V1: &str = "ag.derived-promotion-authorization/v1";

/// Exact executable bytes plus the complete admitted launch/protocol profile.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinnedPromotionVerifierIdentityV1 {
    /// Exact executable byte, size, and build identity.
    pub executable: ExecutableIdentityV1,
    /// Exact argv/environment/confinement/descriptor/protocol profile.
    pub launch_profile: LaunchProfileIdentityV1,
}

impl PinnedPromotionVerifierIdentityV1 {
    /// Creates an exact verifier identity. A pathname is deliberately absent.
    #[must_use]
    pub const fn new(
        executable: ExecutableIdentityV1,
        launch_profile: LaunchProfileIdentityV1,
    ) -> Self {
        Self {
            executable,
            launch_profile,
        }
    }
}

/// Expected result for one compiled hostile verifier specimen.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedVerifierOutcomeV1 {
    /// The specimen must be entailed.
    Entailed,
    /// The specimen must be rejected as not entailed.
    NotEntailed,
}

/// Closed result class returned by the pinned verifier.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifierOutcomeClassV1 {
    /// The exact obligation was entailed.
    Entailed,
    /// The exact obligation was not entailed.
    NotEntailed,
    /// The verifier could not decide. This never creates authority.
    Unknown,
}

impl ExpectedVerifierOutcomeV1 {
    const fn matches(self, observed: VerifierOutcomeClassV1) -> bool {
        matches!(
            (self, observed),
            (Self::Entailed, VerifierOutcomeClassV1::Entailed)
                | (Self::NotEntailed, VerifierOutcomeClassV1::NotEntailed)
        )
    }
}

/// Proposal judgment emitted by the admitted verifier.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum PromotionVerifierJudgmentV1 {
    /// Exact promotion obligation is entailed.
    Entailed {
        /// Proof/core/check evidence in governed custody.
        evidence: Digest,
    },
    /// Exact promotion obligation is not entailed.
    NotEntailed {
        /// Counterexample/core/check evidence in governed custody.
        evidence: Digest,
    },
    /// Evaluation could not decide and is operationally indeterminate.
    Unknown {
        /// Failure evidence in governed custody.
        evidence: Digest,
    },
}

impl PromotionVerifierJudgmentV1 {
    /// Returns the closed result class.
    #[must_use]
    pub const fn outcome(&self) -> VerifierOutcomeClassV1 {
        match self {
            Self::Entailed { .. } => VerifierOutcomeClassV1::Entailed,
            Self::NotEntailed { .. } => VerifierOutcomeClassV1::NotEntailed,
            Self::Unknown { .. } => VerifierOutcomeClassV1::Unknown,
        }
    }
}

/// Human-installed body of a bounded verifier-derived promotion scope.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivedPromotionScopeBodyV1 {
    /// Exact schema.
    pub schema: String,
    /// Authority domain in which the scope may be spent.
    pub authority_domain: AuthorityDomain,
    /// Revocation epoch in which the scope may be spent.
    pub epoch: Epoch,
    /// Exact root-owned target catalog admitted by the scope.
    pub catalog_identity: Digest,
    /// Closed managed-pointer target set.
    pub allowed_targets: BTreeSet<TargetId>,
    /// Exact verifier executable and launch/protocol profile.
    pub verifier: PinnedPromotionVerifierIdentityV1,
    /// Exact verifier rule/solver semantics revision.
    pub verifier_semantics: Digest,
    /// Compiled hostile corpus and expected result for every specimen.
    pub hostile_specimens: BTreeMap<Digest, ExpectedVerifierOutcomeV1>,
    /// Exact stable adapter roots admitted to exercise this scope.
    pub adapter_roots: BTreeSet<PrincipalId>,
    /// Named proposer/ratifier separation rule.
    pub separation: PrincipalSeparationPredicateV1,
    /// Inclusive lower time bound.
    pub not_before_unix_ms: u64,
    /// Exclusive upper time bound.
    pub expires_unix_ms: u64,
    /// Maximum one-time derived authorizations under this scope.
    pub max_uses: u32,
}

/// Digest-bound, human-installed derived-promotion scope.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivedPromotionScopeV1 {
    digest: Digest,
    body: DerivedPromotionScopeBodyV1,
}

impl DerivedPromotionScopeV1 {
    /// Validates and digest-binds a scope body.
    ///
    /// # Errors
    ///
    /// Returns [`DerivedAuthorityError::InvalidScope`] for an empty, unbounded,
    /// or incoherent scope and a canonicalization error if JCS construction
    /// fails.
    pub fn new(body: DerivedPromotionScopeBodyV1) -> Result<Self, DerivedAuthorityError> {
        validate_scope_body(&body)?;
        let digest = digest_value("ag-ng/derived-promotion-scope/v1", &body)?;
        Ok(Self { digest, body })
    }

    /// Verifies the stored digest and all bounded shape invariants.
    ///
    /// # Errors
    ///
    /// Returns a scope or digest error if deserialized bytes were changed or
    /// no longer describe a bounded v1 scope.
    pub fn verify(&self) -> Result<(), DerivedAuthorityError> {
        validate_scope_body(&self.body)?;
        let observed = digest_value("ag-ng/derived-promotion-scope/v1", &self.body)?;
        if observed != self.digest {
            return Err(DerivedAuthorityError::ScopeDigestMismatch);
        }
        Ok(())
    }

    /// Returns the exact scope digest.
    #[must_use]
    pub const fn digest(&self) -> &Digest {
        &self.digest
    }

    /// Returns the human-installed scope body.
    #[must_use]
    pub const fn body(&self) -> &DerivedPromotionScopeBodyV1 {
        &self.body
    }
}

/// Exact typed request presented to the pinned verifier.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivedVerifierRequestV1 {
    /// Exact request schema.
    pub schema: String,
    /// Broker-created single-use invocation nonce.
    pub invocation_nonce: Digest,
    /// Human-installed scope digest.
    pub scope: Digest,
    /// Complete broker-owned canonical proposal.
    pub canonical_proposal: CanonicalEffectProposalV1,
    /// Explicit catalog binding checked against the proposal and scope.
    pub catalog_identity: Digest,
    /// Explicit admission-judgment binding checked against the proposal.
    pub judgment: Digest,
    /// Authenticated adapter principal-chain digest.
    pub adapter_chain: Digest,
    /// Exact verifier semantics revision.
    pub verifier_semantics: Digest,
    /// Digest of the complete hostile-specimen expectation catalog.
    pub hostile_specimen_catalog: Digest,
}

impl DerivedVerifierRequestV1 {
    /// Returns a domain-separated digest of the exact typed request.
    ///
    /// # Errors
    ///
    /// Returns a canonicalization error if the request cannot be represented
    /// as strict JCS.
    pub fn digest(&self) -> Result<Digest, DerivedAuthorityError> {
        digest_value("ag-ng/derived-promotion-verifier-request/v1", self)
    }
}

/// Result of running one configured hostile specimen.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostileSpecimenResultV1 {
    /// Exact specimen identity from the human-installed scope.
    pub specimen: Digest,
    /// Verifier result class.
    pub observed: VerifierOutcomeClassV1,
    /// Exact proof/core/failure evidence in governed custody.
    pub evidence: Digest,
}

/// Exact receipt body returned by the pinned verifier adapter.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivedVerifierReceiptBodyV1 {
    /// Exact receipt schema.
    pub schema: String,
    /// Exact typed request digest.
    pub request: Digest,
    /// Echoed broker invocation nonce.
    pub invocation_nonce: Digest,
    /// Echoed human-installed scope.
    pub scope: Digest,
    /// Exact canonical proposal digest judged by the verifier.
    pub proposal: Digest,
    /// Exact catalog identity used by the verifier.
    pub catalog_identity: Digest,
    /// Exact admission-judgment record used by the verifier.
    pub judgment: Digest,
    /// Authenticated adapter principal-chain digest.
    pub adapter_chain: Digest,
    /// Exact verifier executable and launch/protocol profile.
    pub verifier: PinnedPromotionVerifierIdentityV1,
    /// Exact verifier semantics revision.
    pub verifier_semantics: Digest,
    /// Exact hostile-specimen catalog digest.
    pub hostile_specimen_catalog: Digest,
    /// Proposal judgment. Only `Entailed` can create derived authority.
    pub proposal_judgment: PromotionVerifierJudgmentV1,
    /// One result for every and only configured hostile specimen.
    pub hostile_specimen_results: Vec<HostileSpecimenResultV1>,
}

/// Digest-bound verifier receipt. It is evidence, not bearer authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivedVerifierReceiptV1 {
    digest: Digest,
    body: DerivedVerifierReceiptBodyV1,
}

impl DerivedVerifierReceiptV1 {
    /// Digest-binds a typed verifier receipt body.
    ///
    /// # Errors
    ///
    /// Returns a canonicalization error if the receipt body cannot be encoded
    /// as strict JCS.
    pub fn new(body: DerivedVerifierReceiptBodyV1) -> Result<Self, DerivedAuthorityError> {
        let digest = digest_value("ag-ng/derived-promotion-verifier-receipt/v1", &body)?;
        Ok(Self { digest, body })
    }

    /// Verifies the exact receipt body digest.
    ///
    /// # Errors
    ///
    /// Returns [`DerivedAuthorityError::VerifierReceiptDigestMismatch`] when
    /// deserialized receipt bytes differ from the digest.
    pub fn verify_digest(&self) -> Result<(), DerivedAuthorityError> {
        let observed = digest_value("ag-ng/derived-promotion-verifier-receipt/v1", &self.body)?;
        if observed != self.digest {
            return Err(DerivedAuthorityError::VerifierReceiptDigestMismatch);
        }
        Ok(())
    }

    /// Returns the exact verifier receipt digest.
    #[must_use]
    pub const fn digest(&self) -> &Digest {
        &self.digest
    }

    /// Returns the exact receipt body.
    #[must_use]
    pub const fn body(&self) -> &DerivedVerifierReceiptBodyV1 {
        &self.body
    }
}

/// Operational failure from an admitted typed verifier adapter.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierInvocationFailureV1 {
    /// Exact failure evidence in governed custody.
    pub evidence: Digest,
}

/// Typed boundary implemented by a pinned, unprivileged verifier adapter.
///
/// Implementations receive a typed request and return a typed receipt. There
/// is intentionally no path, command, argv, environment, or shell method.
pub trait PinnedPromotionVerifier {
    /// Returns the executable and launch/protocol identity actually admitted
    /// for this adapter instance.
    fn identity(&self) -> &PinnedPromotionVerifierIdentityV1;

    /// Evaluates one exact request.
    ///
    /// # Errors
    ///
    /// Returns governed operational failure evidence on timeout, crash,
    /// malformed output, unavailable solver, or any other indeterminate path.
    fn verify(
        &mut self,
        request: &DerivedVerifierRequestV1,
    ) -> Result<DerivedVerifierReceiptV1, VerifierInvocationFailureV1>;
}

/// Exact one-time burn requested after every semantic check succeeds.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivedReceiptBurnV1 {
    /// Human-installed derived scope.
    pub scope: Digest,
    /// Exact canonical proposal.
    pub proposal: Digest,
    /// Exact verifier receipt.
    pub verifier_receipt: Digest,
    /// Broker invocation nonce echoed by the verifier.
    pub invocation_nonce: Digest,
    /// Exact authenticated adapter chain.
    pub adapter_chain: Digest,
}

/// Stable failure from the durable one-time receipt ledger.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum DerivedReceiptBurnError {
    /// Burn scope does not match the exact verified scope supplied to storage.
    #[error("derived receipt burn scope binding mismatch")]
    ScopeBindingMismatch,
    /// This exact verifier receipt was already consumed.
    #[error("derived verifier receipt was already consumed")]
    ReceiptAlreadyUsed,
    /// This canonical proposal already received derived authorization.
    #[error("canonical proposal already received derived authorization")]
    ProposalAlreadyUsed,
    /// This broker invocation nonce was already consumed.
    #[error("derived verifier invocation nonce was already consumed")]
    InvocationAlreadyUsed,
    /// The bounded human-installed scope has no remaining uses.
    #[error("derived promotion scope is exhausted")]
    ScopeExhausted,
    /// The store could not determine whether the burn committed.
    #[error("derived receipt burn is operationally indeterminate: {evidence}")]
    Indeterminate {
        /// Durable failure evidence.
        evidence: Digest,
    },
}

/// Durable atomic replay fence for derived verifier receipts.
pub trait DerivedReceiptBurnStore {
    /// Atomically burns receipt, proposal, invocation nonce, and one scope use.
    ///
    /// The implementation must verify `scope`, require `burn.scope` to equal
    /// its digest, enforce unique receipt/proposal/nonce keys, and increment
    /// the scope-use count in the same full-sync transaction. It returns a
    /// durable burn-receipt digest only after commit.
    ///
    /// # Errors
    ///
    /// Returns [`DerivedReceiptBurnError`] for replay, exhaustion, or an
    /// operationally indeterminate durable transition.
    fn burn_once(
        &mut self,
        scope: &DerivedPromotionScopeV1,
        burn: &DerivedReceiptBurnV1,
    ) -> Result<Digest, DerivedReceiptBurnError>;
}

/// Persistable evidence behind one validated derived authorization.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivedAuthorizationEvidenceV1 {
    /// Exact evidence schema.
    pub schema: String,
    /// Human-installed scope.
    pub scope: Digest,
    /// Canonical proposal selected by the verifier.
    pub proposal: Digest,
    /// Exact verifier receipt consumed by the broker.
    pub verifier_receipt: Digest,
    /// Durable one-time burn receipt.
    pub burn_receipt: Digest,
    /// Exact authenticated adapter chain.
    pub adapter_chain: Digest,
    /// Existing closed effect authorization record.
    pub ratification: RatificationV1,
}

/// Process-local result returned only after the one-time burn commits.
///
/// This value is deliberately neither serializable nor cloneable. Its
/// [`DerivedAuthorizationEvidenceV1`] is persisted as evidence before the
/// proposal lifecycle consumes the derived authorization.
#[derive(Debug)]
pub struct ValidatedDerivedCodePromotionV1 {
    evidence: DerivedAuthorizationEvidenceV1,
}

impl ValidatedDerivedCodePromotionV1 {
    /// Returns persistable exact authorization evidence.
    #[must_use]
    pub const fn evidence(&self) -> &DerivedAuthorizationEvidenceV1 {
        &self.evidence
    }

    /// Consumes the process-local validation result into persistable evidence.
    #[must_use]
    pub fn into_evidence(self) -> DerivedAuthorizationEvidenceV1 {
        self.evidence
    }
}

/// Validator bound to one human-installed derived-promotion scope.
#[derive(Clone, Debug)]
pub struct DerivedPromotionValidatorV1 {
    scope: DerivedPromotionScopeV1,
}

impl DerivedPromotionValidatorV1 {
    /// Creates a validator after checking the exact human-installed scope.
    ///
    /// # Errors
    ///
    /// Returns a scope error if its digest, schema, target set, verifier
    /// identity, time interval, specimen set, roots, or count is invalid.
    pub fn new(scope: DerivedPromotionScopeV1) -> Result<Self, DerivedAuthorityError> {
        scope.verify()?;
        Ok(Self { scope })
    }

    /// Returns the exact human-installed scope.
    #[must_use]
    pub const fn scope(&self) -> &DerivedPromotionScopeV1 {
        &self.scope
    }

    /// Verifies and durably burns one verifier-derived code-promotion authority.
    ///
    /// All validation occurs before the single burn call. No validated result
    /// exists unless that burn returns a durable receipt.
    ///
    /// # Errors
    ///
    /// Returns [`DerivedAuthorityError`] for any scope, proposal, verifier,
    /// principal, hostile-specimen, replay, exhaustion, or operational failure.
    pub fn validate_and_burn<V, B>(
        &self,
        proposal: &CanonicalEffectProposalV1,
        authenticated_adapter: &PrincipalChainV1,
        invocation_nonce: Digest,
        now_unix_ms: u64,
        verifier: &mut V,
        burns: &mut B,
    ) -> Result<ValidatedDerivedCodePromotionV1, DerivedAuthorityError>
    where
        V: PinnedPromotionVerifier,
        B: DerivedReceiptBurnStore,
    {
        self.scope.verify()?;
        let scope = self.scope.body();
        if now_unix_ms < scope.not_before_unix_ms || now_unix_ms >= scope.expires_unix_ms {
            return Err(DerivedAuthorityError::ScopeNotCurrentlyValid);
        }

        proposal
            .verify_digest()
            .map_err(|_| DerivedAuthorityError::ProposalDigestMismatch)?;
        let body = proposal.body();
        if body.schema != EFFECT_SCHEMA_V1 || body.catalog_schema != EFFECT_CATALOG_SCHEMA_V1 {
            return Err(DerivedAuthorityError::ProposalSchemaMismatch);
        }
        if body.authority_domain != scope.authority_domain
            || body.epoch != scope.epoch
            || body.proposer.authority_domain() != &body.authority_domain
            || body.proposer.epoch() != body.epoch
        {
            return Err(DerivedAuthorityError::AuthorityContextMismatch);
        }
        if body.catalog_identity != scope.catalog_identity {
            return Err(DerivedAuthorityError::CatalogNotInScope);
        }
        if body.effects.is_empty() {
            return Err(DerivedAuthorityError::EmptyProposal);
        }
        for effect in &body.effects {
            if effect.family() != EffectFamilyV1::CodePromotion {
                return Err(DerivedAuthorityError::NonPromotionEffect);
            }
            if !scope.allowed_targets.contains(effect.target()) {
                return Err(DerivedAuthorityError::TargetNotInScope);
            }
        }

        validate_adapter(scope, body, authenticated_adapter)?;
        if verifier.identity() != &scope.verifier {
            return Err(DerivedAuthorityError::VerifierIdentityMismatch);
        }

        let adapter_chain = authenticated_adapter.id();
        let hostile_specimen_catalog = hostile_specimen_catalog_digest(scope)?;
        let request = DerivedVerifierRequestV1 {
            schema: DERIVED_VERIFIER_REQUEST_SCHEMA_V1.to_owned(),
            invocation_nonce: invocation_nonce.clone(),
            scope: self.scope.digest().clone(),
            canonical_proposal: proposal.clone(),
            catalog_identity: body.catalog_identity.clone(),
            judgment: body.judgment.clone(),
            adapter_chain: adapter_chain.clone(),
            verifier_semantics: scope.verifier_semantics.clone(),
            hostile_specimen_catalog,
        };
        let receipt = verifier.verify(&request).map_err(|failure| {
            DerivedAuthorityError::VerifierInvocationIndeterminate {
                evidence: failure.evidence,
            }
        })?;
        validate_verifier_receipt(scope, &request, verifier.identity(), &receipt)?;

        let burn = DerivedReceiptBurnV1 {
            scope: self.scope.digest().clone(),
            proposal: proposal.digest().clone(),
            verifier_receipt: receipt.digest().clone(),
            invocation_nonce,
            adapter_chain: adapter_chain.clone(),
        };
        let burn_receipt = burns.burn_once(&self.scope, &burn)?;
        let ratification = RatificationV1::DerivedCodePromotion {
            proposal: proposal.digest().clone(),
            verifier_executable: scope.verifier.executable.sha256.clone(),
            verifier_launch_profile: scope.verifier.launch_profile.profile_digest.clone(),
            verifier_receipt: receipt.digest().clone(),
            adapter: authenticated_adapter.clone(),
        };
        Ok(ValidatedDerivedCodePromotionV1 {
            evidence: DerivedAuthorizationEvidenceV1 {
                schema: DERIVED_AUTHORIZATION_SCHEMA_V1.to_owned(),
                scope: self.scope.digest().clone(),
                proposal: proposal.digest().clone(),
                verifier_receipt: receipt.digest().clone(),
                burn_receipt,
                adapter_chain,
                ratification,
            },
        })
    }
}

/// Refusal or operational failure in derived promotion validation.
#[derive(Debug, Error)]
pub enum DerivedAuthorityError {
    /// Scope structure is unbounded or incoherent.
    #[error("invalid derived promotion scope")]
    InvalidScope,
    /// Stored scope body does not match its digest.
    #[error("derived promotion scope digest mismatch")]
    ScopeDigestMismatch,
    /// Scope is not currently within its half-open validity interval.
    #[error("derived promotion scope is not currently valid")]
    ScopeNotCurrentlyValid,
    /// Canonical proposal bytes no longer match the broker digest.
    #[error("canonical proposal digest mismatch")]
    ProposalDigestMismatch,
    /// Canonical proposal is not the exact supported effect schema.
    #[error("canonical proposal schema is not supported")]
    ProposalSchemaMismatch,
    /// Proposal, proposer, adapter, scope, domain, or epoch disagree.
    #[error("derived authority context mismatch")]
    AuthorityContextMismatch,
    /// Proposal catalog differs from the human-installed scope.
    #[error("proposal target catalog is outside derived scope")]
    CatalogNotInScope,
    /// A canonical proposal must contain at least one exact effect.
    #[error("empty proposal cannot receive derived authority")]
    EmptyProposal,
    /// Every effect must be a managed-pointer promotion.
    #[error("derived authority applies only to all-code-promotion proposals")]
    NonPromotionEffect,
    /// A managed-pointer target is outside the closed scope.
    #[error("managed-pointer target is outside derived scope")]
    TargetNotInScope,
    /// Authenticated adapter root is not admitted by the scope.
    #[error("authenticated adapter root is not admitted")]
    AdapterNotAdmitted,
    /// Adapter chain must terminate in an independently enrolled service.
    #[error("authenticated adapter leaf is not a service principal")]
    AdapterNotService,
    /// Adapter and proposer do not satisfy the named separation predicate.
    #[error("authenticated adapter is not independent from proposer")]
    PrincipalChainsNotIndependent,
    /// Runtime verifier executable/profile differs from the scope.
    #[error("pinned verifier executable or launch profile mismatch")]
    VerifierIdentityMismatch,
    /// Verifier invocation did not produce a semantic receipt.
    #[error("pinned verifier invocation is indeterminate: {evidence}")]
    VerifierInvocationIndeterminate {
        /// Exact failure evidence.
        evidence: Digest,
    },
    /// Receipt body no longer matches its digest.
    #[error("verifier receipt digest mismatch")]
    VerifierReceiptDigestMismatch,
    /// Receipt does not echo every exact request and configuration binding.
    #[error("verifier receipt binding mismatch")]
    VerifierReceiptBindingMismatch,
    /// Verifier did not entail the exact canonical proposal obligation.
    #[error("verifier did not entail the exact promotion obligation")]
    VerifierDidNotEntail,
    /// Hostile specimen result set is missing, duplicated, or has extras.
    #[error("verifier hostile-specimen result set mismatch")]
    HostileSpecimenSetMismatch,
    /// At least one hostile specimen produced the wrong result.
    #[error("verifier hostile-specimen check failed")]
    HostileSpecimenFailed,
    /// Strict JCS construction failed.
    #[error("derived authority canonicalization failed: {0}")]
    Canonicalization(String),
    /// Durable receipt/proposal/nonce burn failed.
    #[error(transparent)]
    Burn(#[from] DerivedReceiptBurnError),
}

fn validate_scope_body(body: &DerivedPromotionScopeBodyV1) -> Result<(), DerivedAuthorityError> {
    if body.schema != DERIVED_SCOPE_SCHEMA_V1
        || body.allowed_targets.is_empty()
        || body.hostile_specimens.is_empty()
        || body.adapter_roots.is_empty()
        || body.not_before_unix_ms >= body.expires_unix_ms
        || body.max_uses == 0
        || body.verifier.executable.size == 0
    {
        return Err(DerivedAuthorityError::InvalidScope);
    }
    Ok(())
}

fn validate_adapter(
    scope: &DerivedPromotionScopeBodyV1,
    proposal: &ag_effect::CanonicalProposalBodyV1,
    adapter: &PrincipalChainV1,
) -> Result<(), DerivedAuthorityError> {
    if adapter.authority_domain() != &scope.authority_domain
        || adapter.epoch() != scope.epoch
        || proposal.authority_domain != scope.authority_domain
        || proposal.epoch != scope.epoch
    {
        return Err(DerivedAuthorityError::AuthorityContextMismatch);
    }
    if adapter.leaf().kind != PrincipalKindV1::Service {
        return Err(DerivedAuthorityError::AdapterNotService);
    }
    if !scope.adapter_roots.contains(&adapter.root().principal_id) {
        return Err(DerivedAuthorityError::AdapterNotAdmitted);
    }
    proposal
        .proposer
        .satisfies(adapter, scope.separation)
        .map_err(|_| DerivedAuthorityError::PrincipalChainsNotIndependent)
}

fn validate_verifier_receipt(
    scope: &DerivedPromotionScopeBodyV1,
    request: &DerivedVerifierRequestV1,
    verifier: &PinnedPromotionVerifierIdentityV1,
    receipt: &DerivedVerifierReceiptV1,
) -> Result<(), DerivedAuthorityError> {
    receipt.verify_digest()?;
    let body = receipt.body();
    let request_digest = request.digest()?;
    if body.schema != DERIVED_VERIFIER_RECEIPT_SCHEMA_V1
        || body.request != request_digest
        || body.invocation_nonce != request.invocation_nonce
        || body.scope != request.scope
        || body.proposal != *request.canonical_proposal.digest()
        || body.catalog_identity != request.catalog_identity
        || body.judgment != request.judgment
        || body.adapter_chain != request.adapter_chain
        || &body.verifier != verifier
        || body.verifier != scope.verifier
        || body.verifier_semantics != request.verifier_semantics
        || body.hostile_specimen_catalog != request.hostile_specimen_catalog
    {
        return Err(DerivedAuthorityError::VerifierReceiptBindingMismatch);
    }
    if body.proposal_judgment.outcome() != VerifierOutcomeClassV1::Entailed {
        return Err(DerivedAuthorityError::VerifierDidNotEntail);
    }

    if body.hostile_specimen_results.len() != scope.hostile_specimens.len() {
        return Err(DerivedAuthorityError::HostileSpecimenSetMismatch);
    }
    let mut seen = BTreeSet::new();
    for result in &body.hostile_specimen_results {
        if !seen.insert(result.specimen.clone()) {
            return Err(DerivedAuthorityError::HostileSpecimenSetMismatch);
        }
        let expected = scope
            .hostile_specimens
            .get(&result.specimen)
            .ok_or(DerivedAuthorityError::HostileSpecimenSetMismatch)?;
        if !expected.matches(result.observed) {
            return Err(DerivedAuthorityError::HostileSpecimenFailed);
        }
    }
    if seen.len() != scope.hostile_specimens.len() {
        return Err(DerivedAuthorityError::HostileSpecimenSetMismatch);
    }
    Ok(())
}

fn hostile_specimen_catalog_digest(
    scope: &DerivedPromotionScopeBodyV1,
) -> Result<Digest, DerivedAuthorityError> {
    digest_value(
        "ag-ng/derived-promotion-hostile-specimens/v1",
        &scope.hostile_specimens,
    )
}

fn digest_value<T: Serialize + ?Sized>(
    domain: &str,
    value: &T,
) -> Result<Digest, DerivedAuthorityError> {
    let document = JcsDocument::canonicalize(value)
        .map_err(|error| DerivedAuthorityError::Canonicalization(error.to_string()))?;
    Ok(Digest::hash_domain(domain, document.as_bytes()))
}

#[cfg(test)]
mod tests {
    use ag_effect::{
        EFFECT_CATALOG_SCHEMA_V1, EFFECT_SCHEMA_V1, EffectCatalogV1, EffectCompilationCutV1,
        EffectCompilerV1, EffectIntentV1, GitObjectFormatV1,
        MANAGED_POINTER_CANDIDATE_PREPARATION_SCHEMA_V1, MANAGED_POINTER_COMPLETE_INPUTS_SCHEMA_V1,
        MANAGED_POINTER_EXACT_BASIS_SCHEMA_V1, MANAGED_POINTER_PREPARATION_EFFECTS_SCHEMA_V1,
        MANAGED_POINTER_PREPARATION_STANDING_SCHEMA_V1,
        MANAGED_POINTER_PREPARED_CANDIDATE_SCHEMA_V1, ManagedPointerCandidatePreparationReceiptV1,
        ManagedPointerCompleteInputsV1, ManagedPointerExactBasisV1,
        ManagedPointerPreparationEffectsV1, ManagedPointerPreparationStandingReceiptV1,
        PreparedManagedPointerCandidateV1, ProposalIntentV1, TargetDefinitionV1,
        TargetObservationV1,
    };
    use ag_primitives::{PrincipalChainNodeV1, PrincipalKindV1};

    use super::*;

    #[derive(Clone, Copy)]
    enum VerifierMode {
        Valid,
        WrongProposal,
        WrongCatalog,
        WrongJudgment,
        WrongAdapter,
        FailedSpecimen,
        MissingSpecimen,
        NotEntailed,
        Indeterminate,
    }

    struct FakeVerifier {
        identity: PinnedPromotionVerifierIdentityV1,
        specimens: BTreeMap<Digest, ExpectedVerifierOutcomeV1>,
        mode: VerifierMode,
        calls: usize,
    }

    impl PinnedPromotionVerifier for FakeVerifier {
        fn identity(&self) -> &PinnedPromotionVerifierIdentityV1 {
            &self.identity
        }

        fn verify(
            &mut self,
            request: &DerivedVerifierRequestV1,
        ) -> Result<DerivedVerifierReceiptV1, VerifierInvocationFailureV1> {
            self.calls += 1;
            if matches!(self.mode, VerifierMode::Indeterminate) {
                return Err(VerifierInvocationFailureV1 {
                    evidence: digest("verifier-indeterminate"),
                });
            }
            let mut results: Vec<_> = self
                .specimens
                .iter()
                .map(|(specimen, expected)| HostileSpecimenResultV1 {
                    specimen: specimen.clone(),
                    observed: match expected {
                        ExpectedVerifierOutcomeV1::Entailed => VerifierOutcomeClassV1::Entailed,
                        ExpectedVerifierOutcomeV1::NotEntailed => {
                            VerifierOutcomeClassV1::NotEntailed
                        }
                    },
                    evidence: digest(&format!("specimen-evidence:{specimen}")),
                })
                .collect();
            if matches!(self.mode, VerifierMode::FailedSpecimen)
                && let Some(first) = results.first_mut()
            {
                first.observed = VerifierOutcomeClassV1::Unknown;
            }
            if matches!(self.mode, VerifierMode::MissingSpecimen) {
                results.pop();
            }
            let mut body = DerivedVerifierReceiptBodyV1 {
                schema: DERIVED_VERIFIER_RECEIPT_SCHEMA_V1.to_owned(),
                request: request.digest().unwrap(),
                invocation_nonce: request.invocation_nonce.clone(),
                scope: request.scope.clone(),
                proposal: request.canonical_proposal.digest().clone(),
                catalog_identity: request.catalog_identity.clone(),
                judgment: request.judgment.clone(),
                adapter_chain: request.adapter_chain.clone(),
                verifier: self.identity.clone(),
                verifier_semantics: request.verifier_semantics.clone(),
                hostile_specimen_catalog: request.hostile_specimen_catalog.clone(),
                proposal_judgment: PromotionVerifierJudgmentV1::Entailed {
                    evidence: digest("proposal-proof"),
                },
                hostile_specimen_results: results,
            };
            match self.mode {
                VerifierMode::WrongProposal => body.proposal = digest("wrong-proposal"),
                VerifierMode::WrongCatalog => body.catalog_identity = digest("wrong-catalog"),
                VerifierMode::WrongJudgment => body.judgment = digest("wrong-judgment"),
                VerifierMode::WrongAdapter => body.adapter_chain = digest("wrong-adapter"),
                VerifierMode::NotEntailed => {
                    body.proposal_judgment = PromotionVerifierJudgmentV1::NotEntailed {
                        evidence: digest("counterexample"),
                    };
                }
                VerifierMode::Valid
                | VerifierMode::FailedSpecimen
                | VerifierMode::MissingSpecimen
                | VerifierMode::Indeterminate => {}
            }
            Ok(DerivedVerifierReceiptV1::new(body).unwrap())
        }
    }

    #[derive(Default)]
    struct MemoryBurns {
        receipts: BTreeSet<Digest>,
        proposals: BTreeSet<Digest>,
        nonces: BTreeSet<Digest>,
        scope_uses: BTreeMap<Digest, u32>,
    }

    impl DerivedReceiptBurnStore for MemoryBurns {
        fn burn_once(
            &mut self,
            scope: &DerivedPromotionScopeV1,
            burn: &DerivedReceiptBurnV1,
        ) -> Result<Digest, DerivedReceiptBurnError> {
            if scope.verify().is_err() || &burn.scope != scope.digest() {
                return Err(DerivedReceiptBurnError::ScopeBindingMismatch);
            }
            if self.receipts.contains(&burn.verifier_receipt) {
                return Err(DerivedReceiptBurnError::ReceiptAlreadyUsed);
            }
            if self.proposals.contains(&burn.proposal) {
                return Err(DerivedReceiptBurnError::ProposalAlreadyUsed);
            }
            if self.nonces.contains(&burn.invocation_nonce) {
                return Err(DerivedReceiptBurnError::InvocationAlreadyUsed);
            }
            let uses = self.scope_uses.entry(scope.digest().clone()).or_default();
            if *uses >= scope.body().max_uses {
                return Err(DerivedReceiptBurnError::ScopeExhausted);
            }
            self.receipts.insert(burn.verifier_receipt.clone());
            self.proposals.insert(burn.proposal.clone());
            self.nonces.insert(burn.invocation_nonce.clone());
            *uses += 1;
            Digest::from_serializable(burn).map_err(|_| DerivedReceiptBurnError::Indeterminate {
                evidence: digest("burn-jcs-failure"),
            })
        }
    }

    struct Fixture {
        validator: DerivedPromotionValidatorV1,
        proposal: CanonicalEffectProposalV1,
        adapter: PrincipalChainV1,
        verifier_identity: PinnedPromotionVerifierIdentityV1,
        specimens: BTreeMap<Digest, ExpectedVerifierOutcomeV1>,
    }

    fn digest(value: &str) -> Digest {
        Digest::hash_domain("ag-ng/test/derived/v1", value.as_bytes())
    }

    fn domain() -> AuthorityDomain {
        AuthorityDomain::new("test:derived").unwrap()
    }

    fn epoch() -> Epoch {
        Epoch::new(7).unwrap()
    }

    fn principal(value: &str) -> PrincipalId {
        PrincipalId::new(digest(value))
    }

    fn proposer_chain() -> PrincipalChainV1 {
        let root = principal("proposer-root");
        PrincipalChainV1::new(
            domain(),
            epoch(),
            vec![
                PrincipalChainNodeV1::root(root.clone(), PrincipalKindV1::Daemon),
                PrincipalChainNodeV1::child(
                    principal("proposer-worker"),
                    PrincipalKindV1::WorkerSession,
                    root,
                ),
            ],
        )
        .unwrap()
    }

    fn adapter_chain(root: PrincipalId) -> PrincipalChainV1 {
        PrincipalChainV1::new(
            domain(),
            epoch(),
            vec![PrincipalChainNodeV1::root(root, PrincipalKindV1::Service)],
        )
        .unwrap()
    }

    fn verifier_identity(value: &str) -> PinnedPromotionVerifierIdentityV1 {
        PinnedPromotionVerifierIdentityV1::new(
            ExecutableIdentityV1::new(digest(&format!("exe:{value}")), 4096, Some(digest("build"))),
            LaunchProfileIdentityV1::new(digest(&format!("profile:{value}")), digest("protocol")),
        )
    }

    fn prepared_candidate(
        target: &TargetId,
        catalog_identity: &Digest,
        artifact: &Digest,
    ) -> PreparedManagedPointerCandidateV1 {
        let exact_basis = ManagedPointerExactBasisV1 {
            schema: MANAGED_POINTER_EXACT_BASIS_SCHEMA_V1.to_owned(),
            authority_domain: domain(),
            epoch: epoch(),
            target: target.clone(),
            catalog_identity: catalog_identity.clone(),
            security_profile_identity: digest("effectd-security-profile"),
            reference: "refs/heads/main".to_owned(),
            repository_identity: digest("repository-identity"),
            prestate_identity: digest("repository-layout-and-prestate"),
            repository_device: 11,
            repository_inode: 12,
            git_directory_device: 13,
            git_directory_inode: 14,
            uid: 1000,
            gid: 1000,
            object_format: GitObjectFormatV1::Sha1,
            current_object: "b".repeat(40),
            current_tree: "c".repeat(40),
        };
        let exact_basis_identity = exact_basis.identity().unwrap();
        let complete_inputs = ManagedPointerCompleteInputsV1 {
            schema: MANAGED_POINTER_COMPLETE_INPUTS_SCHEMA_V1.to_owned(),
            exact_basis: exact_basis_identity.clone(),
            artifact: artifact.clone(),
            artifact_byte_length: 128,
            candidate_pack_digest: digest("candidate-pack"),
            candidate_object: "d".repeat(40),
            candidate_tree: "e".repeat(40),
            candidate_parent: "b".repeat(40),
            staging_root: "/var/lib/ag-effectd/promotion-staging".to_owned(),
            helper_executable: digest("promotion-helper"),
            helper_launch_profile: digest("promotion-helper-profile"),
            max_artifact_bytes: 1024,
            quarantine_budget_bytes: 2048,
        };
        let complete_inputs_identity = complete_inputs.identity(GitObjectFormatV1::Sha1).unwrap();
        let standing = ManagedPointerPreparationStandingReceiptV1 {
            schema: MANAGED_POINTER_PREPARATION_STANDING_SCHEMA_V1.to_owned(),
            authority_domain: domain(),
            epoch: epoch(),
            target: target.clone(),
            catalog_identity: catalog_identity.clone(),
            security_profile_identity: digest("effectd-security-profile"),
            issued_at_unix_ms: 124,
            expires_at_unix_ms: 1_125,
            max_artifact_bytes: 1024,
            quarantine_budget_bytes: 2048,
            nonce: "derived-test-preparation".to_owned(),
        };
        let preparation_receipt = ManagedPointerCandidatePreparationReceiptV1 {
            schema: MANAGED_POINTER_CANDIDATE_PREPARATION_SCHEMA_V1.to_owned(),
            standing: standing.identity().unwrap(),
            exact_basis: exact_basis_identity.clone(),
            complete_inputs: complete_inputs_identity,
            artifact: artifact.clone(),
            protected_prestate: exact_basis_identity.clone(),
            protected_poststate: exact_basis_identity,
            effects: ManagedPointerPreparationEffectsV1 {
                schema: MANAGED_POINTER_PREPARATION_EFFECTS_SCHEMA_V1.to_owned(),
                candidate_custody_bytes: 128,
                charged_quarantine_bytes: 128,
                target_object_database_bytes: 0,
                authoritative_pointer_writes: 0,
                network_requests: 0,
            },
        };
        PreparedManagedPointerCandidateV1 {
            schema: MANAGED_POINTER_PREPARED_CANDIDATE_SCHEMA_V1.to_owned(),
            preparation_standing: standing,
            exact_basis,
            complete_inputs,
            preparation_receipt,
        }
    }

    fn fixture(include_host_effect: bool, max_uses: u32) -> Fixture {
        fixture_named(include_host_effect, max_uses, "proposal-1", "intent-1")
    }

    #[allow(clippy::too_many_lines)]
    fn fixture_named(
        include_host_effect: bool,
        max_uses: u32,
        proposal_id: &str,
        intent_id: &str,
    ) -> Fixture {
        let promotion_target = TargetId::parse("repository.main").unwrap();
        let file_target = TargetId::parse("managed.file").unwrap();
        let catalog_identity = digest("catalog");
        let mut targets = BTreeMap::new();
        targets.insert(
            promotion_target.clone(),
            TargetDefinitionV1::ManagedPointer {
                allowed_root: "/srv/git".to_owned(),
                repository: "repository.git".to_owned(),
                reference: "refs/heads/main".to_owned(),
                repository_identity: digest("repository-identity"),
                uid: 1000,
                gid: 1000,
                staging_root: "/var/lib/ag-effectd/promotion-staging".to_owned(),
                promotion_ttl_ms: 1_000,
                helper_executable: digest("promotion-helper"),
                helper_launch_profile: digest("promotion-helper-profile"),
            },
        );
        targets.insert(
            file_target.clone(),
            TargetDefinitionV1::ManagedFile {
                path: "/etc/example.conf".to_owned(),
                mode: 0o640,
                uid: 0,
                gid: 0,
            },
        );
        let compiler = EffectCompilerV1::new(
            EffectCatalogV1 {
                schema: EFFECT_CATALOG_SCHEMA_V1.to_owned(),
                identity: catalog_identity.clone(),
                targets,
            },
            digest("effectd-security-profile"),
        );
        let content = digest("file-content");
        let candidate_artifact = digest("candidate-bundle");
        let mut effects = vec![EffectIntentV1::ManagedPointerPromotion {
            target: promotion_target.clone(),
            artifact: candidate_artifact.clone(),
        }];
        if include_host_effect {
            effects.push(EffectIntentV1::ManagedFilePut {
                target: file_target.clone(),
                content: content.clone(),
            });
        }
        let intent = ProposalIntentV1 {
            schema: EFFECT_SCHEMA_V1.to_owned(),
            intent_id: intent_id.to_owned(),
            authority_domain: domain(),
            epoch: epoch(),
            proposer: proposer_chain(),
            judgment: digest("admission-judgment"),
            admitted_artifacts: BTreeSet::from([candidate_artifact.clone(), content]),
            effects,
        };
        let mut observations = BTreeMap::new();
        observations.insert(
            promotion_target.clone(),
            TargetObservationV1::ManagedPointer {
                current_object: "b".repeat(40),
                current_tree: "c".repeat(40),
                candidate_object: "d".repeat(40),
                candidate_tree: "e".repeat(40),
                candidate_parent: "b".repeat(40),
                candidate_pack_digest: digest("candidate-pack"),
                object_format: GitObjectFormatV1::Sha1,
                repository_identity: digest("repository-identity"),
                prestate_identity: digest("repository-layout-and-prestate"),
                repository_device: 11,
                repository_inode: 12,
                git_directory_device: 13,
                git_directory_inode: 14,
                repository_uid: 1000,
                repository_gid: 1000,
                clean: true,
                reference_checked_out: false,
            },
        );
        let prepared_candidates = BTreeMap::from([(
            promotion_target.clone(),
            prepared_candidate(&promotion_target, &catalog_identity, &candidate_artifact),
        )]);
        observations.insert(
            file_target,
            TargetObservationV1::ManagedFile {
                current_content: Some(digest("old-content")),
                regular_file: true,
            },
        );
        let proposal = compiler
            .compile(
                proposal_id.to_owned(),
                &intent,
                &intent.proposer,
                digest("signed-governor-source"),
                EffectCompilationCutV1 {
                    compiled_at_unix_ms: 125,
                    observations: &observations,
                    prepared_candidates: &prepared_candidates,
                },
            )
            .unwrap();
        let adapter = adapter_chain(principal("nightshift-root"));
        let verifier_identity = verifier_identity("admitted");
        let specimens = BTreeMap::from([
            (
                digest("foreign-base"),
                ExpectedVerifierOutcomeV1::NotEntailed,
            ),
            (
                digest("exact-candidate"),
                ExpectedVerifierOutcomeV1::Entailed,
            ),
        ]);
        let scope = DerivedPromotionScopeV1::new(DerivedPromotionScopeBodyV1 {
            schema: DERIVED_SCOPE_SCHEMA_V1.to_owned(),
            authority_domain: domain(),
            epoch: epoch(),
            catalog_identity,
            allowed_targets: BTreeSet::from([promotion_target]),
            verifier: verifier_identity.clone(),
            verifier_semantics: digest("verifier-semantics"),
            hostile_specimens: specimens.clone(),
            adapter_roots: BTreeSet::from([adapter.root().principal_id.clone()]),
            separation: PrincipalSeparationPredicateV1::DistinctRootsNoSharedLineage,
            not_before_unix_ms: 100,
            expires_unix_ms: 200,
            max_uses,
        })
        .unwrap();
        Fixture {
            validator: DerivedPromotionValidatorV1::new(scope).unwrap(),
            proposal,
            adapter,
            verifier_identity,
            specimens,
        }
    }

    fn fake(fixture: &Fixture, mode: VerifierMode) -> FakeVerifier {
        FakeVerifier {
            identity: fixture.verifier_identity.clone(),
            specimens: fixture.specimens.clone(),
            mode,
            calls: 0,
        }
    }

    #[test]
    fn exact_promotion_entailment_burns_once_and_returns_closed_ratification() {
        let fixture = fixture(false, 2);
        let mut verifier = fake(&fixture, VerifierMode::Valid);
        let mut burns = MemoryBurns::default();
        let nonce = digest("invocation-1");
        let validated = fixture
            .validator
            .validate_and_burn(
                &fixture.proposal,
                &fixture.adapter,
                nonce.clone(),
                150,
                &mut verifier,
                &mut burns,
            )
            .unwrap();
        assert!(matches!(
            &validated.evidence().ratification,
            RatificationV1::DerivedCodePromotion { proposal, .. }
                if proposal == fixture.proposal.digest()
        ));
        assert_eq!(verifier.calls, 1);

        let error = fixture
            .validator
            .validate_and_burn(
                &fixture.proposal,
                &fixture.adapter,
                nonce,
                150,
                &mut verifier,
                &mut burns,
            )
            .unwrap_err();
        assert!(matches!(
            error,
            DerivedAuthorityError::Burn(DerivedReceiptBurnError::ReceiptAlreadyUsed)
        ));
    }

    #[test]
    fn fresh_receipt_cannot_authorize_the_same_proposal_twice() {
        let fixture = fixture(false, 2);
        let mut verifier = fake(&fixture, VerifierMode::Valid);
        let mut burns = MemoryBurns::default();
        fixture
            .validator
            .validate_and_burn(
                &fixture.proposal,
                &fixture.adapter,
                digest("invocation-1"),
                150,
                &mut verifier,
                &mut burns,
            )
            .unwrap();
        let error = fixture
            .validator
            .validate_and_burn(
                &fixture.proposal,
                &fixture.adapter,
                digest("invocation-2"),
                150,
                &mut verifier,
                &mut burns,
            )
            .unwrap_err();
        assert!(matches!(
            error,
            DerivedAuthorityError::Burn(DerivedReceiptBurnError::ProposalAlreadyUsed)
        ));
    }

    #[test]
    fn mixed_host_effect_plan_never_reaches_verifier_or_mandate_fallback() {
        let fixture = fixture(true, 1);
        let mut verifier = fake(&fixture, VerifierMode::Valid);
        let mut burns = MemoryBurns::default();
        let error = fixture
            .validator
            .validate_and_burn(
                &fixture.proposal,
                &fixture.adapter,
                digest("invocation"),
                150,
                &mut verifier,
                &mut burns,
            )
            .unwrap_err();
        assert!(matches!(error, DerivedAuthorityError::NonPromotionEffect));
        assert_eq!(verifier.calls, 0);
    }

    #[test]
    fn every_exact_receipt_binding_is_enforced() {
        for mode in [
            VerifierMode::WrongProposal,
            VerifierMode::WrongCatalog,
            VerifierMode::WrongJudgment,
            VerifierMode::WrongAdapter,
        ] {
            let fixture = fixture(false, 1);
            let mut verifier = fake(&fixture, mode);
            let mut burns = MemoryBurns::default();
            let error = fixture
                .validator
                .validate_and_burn(
                    &fixture.proposal,
                    &fixture.adapter,
                    digest("invocation"),
                    150,
                    &mut verifier,
                    &mut burns,
                )
                .unwrap_err();
            assert!(matches!(
                error,
                DerivedAuthorityError::VerifierReceiptBindingMismatch
            ));
            assert!(burns.receipts.is_empty());
        }
    }

    #[test]
    fn hostile_specimens_must_be_complete_and_successful() {
        for (mode, expected_error) in [
            (VerifierMode::FailedSpecimen, "failed"),
            (VerifierMode::MissingSpecimen, "missing"),
        ] {
            let fixture = fixture(false, 1);
            let mut verifier = fake(&fixture, mode);
            let mut burns = MemoryBurns::default();
            let error = fixture
                .validator
                .validate_and_burn(
                    &fixture.proposal,
                    &fixture.adapter,
                    digest("invocation"),
                    150,
                    &mut verifier,
                    &mut burns,
                )
                .unwrap_err();
            match expected_error {
                "failed" => assert!(matches!(
                    error,
                    DerivedAuthorityError::HostileSpecimenFailed
                )),
                "missing" => assert!(matches!(
                    error,
                    DerivedAuthorityError::HostileSpecimenSetMismatch
                )),
                _ => unreachable!(),
            }
            assert!(burns.receipts.is_empty());
        }
    }

    #[test]
    fn non_entailment_and_indeterminate_never_burn() {
        for mode in [VerifierMode::NotEntailed, VerifierMode::Indeterminate] {
            let fixture = fixture(false, 1);
            let mut verifier = fake(&fixture, mode);
            let mut burns = MemoryBurns::default();
            let error = fixture
                .validator
                .validate_and_burn(
                    &fixture.proposal,
                    &fixture.adapter,
                    digest("invocation"),
                    150,
                    &mut verifier,
                    &mut burns,
                )
                .unwrap_err();
            assert!(matches!(
                error,
                DerivedAuthorityError::VerifierDidNotEntail
                    | DerivedAuthorityError::VerifierInvocationIndeterminate { .. }
            ));
            assert!(burns.receipts.is_empty());
        }
    }

    #[test]
    fn verifier_identity_and_adapter_independence_are_checked_before_invocation() {
        let fixture = fixture(false, 1);
        let mut wrong_verifier = fake(&fixture, VerifierMode::Valid);
        wrong_verifier.identity = verifier_identity("foreign");
        let mut burns = MemoryBurns::default();
        let error = fixture
            .validator
            .validate_and_burn(
                &fixture.proposal,
                &fixture.adapter,
                digest("invocation"),
                150,
                &mut wrong_verifier,
                &mut burns,
            )
            .unwrap_err();
        assert!(matches!(
            error,
            DerivedAuthorityError::VerifierIdentityMismatch
        ));
        assert_eq!(wrong_verifier.calls, 0);

        let foreign_adapter = adapter_chain(principal("foreign-adapter-root"));
        let mut verifier = fake(&fixture, VerifierMode::Valid);
        let error = fixture
            .validator
            .validate_and_burn(
                &fixture.proposal,
                &foreign_adapter,
                digest("foreign-adapter"),
                150,
                &mut verifier,
                &mut burns,
            )
            .unwrap_err();
        assert!(matches!(error, DerivedAuthorityError::AdapterNotAdmitted));
        assert_eq!(verifier.calls, 0);

        let worker_adapter = proposer_chain();
        let mut verifier = fake(&fixture, VerifierMode::Valid);
        let error = fixture
            .validator
            .validate_and_burn(
                &fixture.proposal,
                &worker_adapter,
                digest("worker-adapter"),
                150,
                &mut verifier,
                &mut burns,
            )
            .unwrap_err();
        assert!(matches!(error, DerivedAuthorityError::AdapterNotService));
        assert_eq!(verifier.calls, 0);

        let proposer_root = fixture.proposal.body().proposer.root().principal_id.clone();
        let non_independent = adapter_chain(proposer_root);
        let mut non_independent_scope = fixture.validator.scope().body().clone();
        non_independent_scope.adapter_roots =
            BTreeSet::from([non_independent.root().principal_id.clone()]);
        let non_independent_validator = DerivedPromotionValidatorV1::new(
            DerivedPromotionScopeV1::new(non_independent_scope).unwrap(),
        )
        .unwrap();
        let mut verifier = fake(&fixture, VerifierMode::Valid);
        let error = non_independent_validator
            .validate_and_burn(
                &fixture.proposal,
                &non_independent,
                digest("invocation"),
                150,
                &mut verifier,
                &mut burns,
            )
            .unwrap_err();
        assert!(matches!(
            error,
            DerivedAuthorityError::PrincipalChainsNotIndependent
        ));
        assert_eq!(verifier.calls, 0);
    }

    #[test]
    fn scope_time_and_count_are_bounded() {
        let fixture = fixture(false, 1);
        let mut verifier = fake(&fixture, VerifierMode::Valid);
        let mut burns = MemoryBurns::default();
        let expired = fixture
            .validator
            .validate_and_burn(
                &fixture.proposal,
                &fixture.adapter,
                digest("expired"),
                200,
                &mut verifier,
                &mut burns,
            )
            .unwrap_err();
        assert!(matches!(
            expired,
            DerivedAuthorityError::ScopeNotCurrentlyValid
        ));
        assert_eq!(verifier.calls, 0);

        let first = fixture_named(false, 1, "proposal-a", "intent-a");
        let second = fixture_named(false, 1, "proposal-b", "intent-b");
        assert_eq!(
            first.validator.scope().digest(),
            second.validator.scope().digest()
        );
        let mut first_verifier = fake(&first, VerifierMode::Valid);
        let mut second_verifier = fake(&second, VerifierMode::Valid);
        first
            .validator
            .validate_and_burn(
                &first.proposal,
                &first.adapter,
                digest("count-a"),
                150,
                &mut first_verifier,
                &mut burns,
            )
            .unwrap();
        let exhausted = second
            .validator
            .validate_and_burn(
                &second.proposal,
                &second.adapter,
                digest("count-b"),
                150,
                &mut second_verifier,
                &mut burns,
            )
            .unwrap_err();
        assert!(matches!(
            exhausted,
            DerivedAuthorityError::Burn(DerivedReceiptBurnError::ScopeExhausted)
        ));
    }
}
