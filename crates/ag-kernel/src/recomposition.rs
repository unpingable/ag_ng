//! Exact accounting at decomposition/recomposition boundaries.

use ag_primitives::{Digest, LifecycleOrigin};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{LocatedObstruction, NativeJudgment, NonEmpty, PathVerdict};

/// One exact slice required to account for a decomposed claim.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundaryRequirement {
    boundary_id: Digest,
    expected_slice_digest: Digest,
}

impl BoundaryRequirement {
    /// Creates a boundary requirement.
    #[must_use]
    pub const fn new(boundary_id: Digest, expected_slice_digest: Digest) -> Self {
        Self {
            boundary_id,
            expected_slice_digest,
        }
    }

    /// Returns the stable boundary identifier.
    #[must_use]
    pub const fn boundary_id(&self) -> &Digest {
        &self.boundary_id
    }

    /// Returns the exact expected slice digest.
    #[must_use]
    pub const fn expected_slice_digest(&self) -> &Digest {
        &self.expected_slice_digest
    }
}

/// Invalid decomposition manifest.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum ManifestError {
    /// A decomposition must name at least one boundary.
    #[error("a recomposition manifest cannot be empty")]
    Empty,
    /// The same boundary identifier appeared more than once.
    #[error("duplicate boundary identifier")]
    DuplicateBoundary,
}

/// Daemon-created manifest defining all and only the required boundaries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundaryManifest {
    origin: LifecycleOrigin,
    whole_claim_digest: Digest,
    requirements: NonEmpty<BoundaryRequirement>,
}

impl BoundaryManifest {
    /// Creates a manifest after rejecting empty or duplicate boundary sets.
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError::Empty`] for no requirements and
    /// [`ManifestError::DuplicateBoundary`] for a repeated boundary ID.
    pub fn new(
        origin: LifecycleOrigin,
        whole_claim_digest: Digest,
        requirements: Vec<BoundaryRequirement>,
    ) -> Result<Self, ManifestError> {
        let requirements = NonEmpty::from_vec(requirements).ok_or(ManifestError::Empty)?;
        let values: Vec<_> = requirements.iter().collect();
        for (index, requirement) in values.iter().enumerate() {
            if values[index + 1..]
                .iter()
                .any(|other| other.boundary_id == requirement.boundary_id)
            {
                return Err(ManifestError::DuplicateBoundary);
            }
        }
        Ok(Self {
            origin,
            whole_claim_digest,
            requirements,
        })
    }

    /// Returns the lifecycle origin of the decomposition.
    #[must_use]
    pub const fn origin(&self) -> &LifecycleOrigin {
        &self.origin
    }

    /// Returns the digest of the whole claim being recomposed.
    #[must_use]
    pub const fn whole_claim_digest(&self) -> &Digest {
        &self.whole_claim_digest
    }

    /// Returns the exact ordered requirements.
    #[must_use]
    pub const fn requirements(&self) -> &NonEmpty<BoundaryRequirement> {
        &self.requirements
    }
}

/// One evaluated slice presented for recomposition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundarySlice<O> {
    origin: LifecycleOrigin,
    boundary_id: Digest,
    slice_digest: Digest,
    verdict: PathVerdict<O>,
}

impl<O> BoundarySlice<O> {
    /// Creates a presented slice.
    #[must_use]
    pub const fn new(
        origin: LifecycleOrigin,
        boundary_id: Digest,
        slice_digest: Digest,
        verdict: PathVerdict<O>,
    ) -> Self {
        Self {
            origin,
            boundary_id,
            slice_digest,
            verdict,
        }
    }

    /// Returns the slice lifecycle origin.
    #[must_use]
    pub const fn origin(&self) -> &LifecycleOrigin {
        &self.origin
    }

    /// Returns the boundary identifier.
    #[must_use]
    pub const fn boundary_id(&self) -> &Digest {
        &self.boundary_id
    }

    /// Returns the exact evaluated slice digest.
    #[must_use]
    pub const fn slice_digest(&self) -> &Digest {
        &self.slice_digest
    }

    /// Returns the boundary obstruction verdict.
    #[must_use]
    pub const fn verdict(&self) -> &PathVerdict<O> {
        &self.verdict
    }
}

/// Exact accounting retained for one clean boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountedBoundary<O> {
    boundary_id: Digest,
    slice_digest: Digest,
    verdict: PathVerdict<O>,
}

impl<O> AccountedBoundary<O> {
    /// Returns the boundary identifier.
    #[must_use]
    pub const fn boundary_id(&self) -> &Digest {
        &self.boundary_id
    }

    /// Returns the exact slice digest.
    #[must_use]
    pub const fn slice_digest(&self) -> &Digest {
        &self.slice_digest
    }

    /// Returns the retained clean verdict.
    #[must_use]
    pub const fn verdict(&self) -> &PathVerdict<O> {
        &self.verdict
    }
}

/// Accounting witness for a successfully recomposed claim.
///
/// This value is evidence, not authority.  Clean slices do not independently
/// authorize the recomposed whole.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecompositionWitness<O> {
    origin: LifecycleOrigin,
    whole_claim_digest: Digest,
    boundaries: NonEmpty<AccountedBoundary<O>>,
}

impl<O> RecompositionWitness<O> {
    /// Returns the exact lifecycle origin.
    #[must_use]
    pub const fn origin(&self) -> &LifecycleOrigin {
        &self.origin
    }

    /// Returns the whole-claim digest.
    #[must_use]
    pub const fn whole_claim_digest(&self) -> &Digest {
        &self.whole_claim_digest
    }

    /// Returns every accounted boundary in manifest order.
    #[must_use]
    pub const fn boundaries(&self) -> &NonEmpty<AccountedBoundary<O>> {
        &self.boundaries
    }
}

/// A laundering or boundary-obstruction failure.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecompositionFailure<O> {
    /// A required boundary was not presented.
    MissingBoundary {
        /// Boundary required by the manifest.
        boundary_id: Digest,
    },
    /// More than one slice claimed the same required boundary.
    DuplicateBoundary {
        /// Multiply presented boundary.
        boundary_id: Digest,
    },
    /// A slice was not named by the daemon-created manifest.
    UnaccountedBoundary {
        /// Boundary absent from the manifest.
        boundary_id: Digest,
    },
    /// A slice came from another lifecycle origin.
    ForeignOrigin {
        /// Boundary carrying the foreign origin.
        boundary_id: Digest,
        /// Manifest lifecycle origin.
        expected: LifecycleOrigin,
        /// Presented slice lifecycle origin.
        observed: LifecycleOrigin,
    },
    /// A named boundary's exact claim/slice digest was changed.
    RewrittenSlice {
        /// Boundary whose slice was changed.
        boundary_id: Digest,
        /// Slice digest fixed by the manifest.
        expected: Digest,
        /// Presented slice digest.
        observed: Digest,
    },
    /// A correctly named slice retained one or more obstructions.
    ObstructedBoundary {
        /// Obstructed boundary.
        boundary_id: Digest,
        /// Every located obstruction retained by the slice.
        obstructions: NonEmpty<LocatedObstruction<O>>,
    },
}

/// Non-empty, lossless refusal to recompose a claim.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecompositionRefusal<O> {
    failures: NonEmpty<RecompositionFailure<O>>,
}

impl<O> RecompositionRefusal<O> {
    /// Returns all laundering and obstruction failures.
    #[must_use]
    pub const fn failures(&self) -> &NonEmpty<RecompositionFailure<O>> {
        &self.failures
    }
}

/// Accounts for every decomposition boundary without healing or filtering any
/// obstruction.
#[must_use]
pub fn recompose<O: Clone>(
    manifest: &BoundaryManifest,
    slices: &[BoundarySlice<O>],
) -> NativeJudgment<RecompositionWitness<O>, RecompositionRefusal<O>> {
    let mut failures = Vec::new();

    for slice in slices {
        let accounted = manifest
            .requirements
            .iter()
            .any(|required| required.boundary_id == slice.boundary_id);
        if !accounted {
            failures.push(RecompositionFailure::UnaccountedBoundary {
                boundary_id: slice.boundary_id.clone(),
            });
        }
        if slice.origin != manifest.origin {
            failures.push(RecompositionFailure::ForeignOrigin {
                boundary_id: slice.boundary_id.clone(),
                expected: manifest.origin.clone(),
                observed: slice.origin.clone(),
            });
        }
    }

    for requirement in manifest.requirements.iter() {
        let matching: Vec<_> = slices
            .iter()
            .filter(|slice| slice.boundary_id == requirement.boundary_id)
            .collect();
        if matching.is_empty() {
            failures.push(RecompositionFailure::MissingBoundary {
                boundary_id: requirement.boundary_id.clone(),
            });
            continue;
        }
        if matching.len() > 1 {
            failures.push(RecompositionFailure::DuplicateBoundary {
                boundary_id: requirement.boundary_id.clone(),
            });
        }
        for slice in matching {
            if slice.slice_digest != requirement.expected_slice_digest {
                failures.push(RecompositionFailure::RewrittenSlice {
                    boundary_id: requirement.boundary_id.clone(),
                    expected: requirement.expected_slice_digest.clone(),
                    observed: slice.slice_digest.clone(),
                });
            }
            if !slice.verdict.is_clean()
                && let Some(obstructions) =
                    NonEmpty::from_vec(slice.verdict.clone().into_obstructions())
            {
                failures.push(RecompositionFailure::ObstructedBoundary {
                    boundary_id: requirement.boundary_id.clone(),
                    obstructions,
                });
            }
        }
    }

    if let Some(failures) = NonEmpty::from_vec(failures) {
        return NativeJudgment::Refuse(RecompositionRefusal { failures });
    }

    let mut boundaries = Vec::with_capacity(manifest.requirements.len());
    for required in manifest.requirements.iter() {
        let Some(slice) = slices
            .iter()
            .find(|slice| slice.boundary_id == required.boundary_id)
        else {
            return NativeJudgment::Refuse(RecompositionRefusal {
                failures: NonEmpty::new(RecompositionFailure::MissingBoundary {
                    boundary_id: required.boundary_id.clone(),
                }),
            });
        };
        boundaries.push(AccountedBoundary {
            boundary_id: slice.boundary_id.clone(),
            slice_digest: slice.slice_digest.clone(),
            verdict: slice.verdict.clone(),
        });
    }
    let Some(boundaries) = NonEmpty::from_vec(boundaries) else {
        return NativeJudgment::Refuse(RecompositionRefusal {
            failures: NonEmpty::new(RecompositionFailure::MissingBoundary {
                boundary_id: manifest.requirements.first().boundary_id.clone(),
            }),
        });
    };
    NativeJudgment::Admit(RecompositionWitness {
        origin: manifest.origin.clone(),
        whole_claim_digest: manifest.whole_claim_digest.clone(),
        boundaries,
    })
}

#[cfg(test)]
mod tests {
    use ag_primitives::{AuthorityDomain, Epoch, LifecycleNonce};

    use super::*;

    fn origin(value: &str) -> LifecycleOrigin {
        LifecycleOrigin::new(
            AuthorityDomain::new(value).unwrap(),
            Epoch::new(1).unwrap(),
            LifecycleNonce::new([7; 16]),
        )
    }

    fn digest(value: &str) -> Digest {
        Digest::hash_bytes(value.as_bytes())
    }

    #[test]
    fn clean_exact_slices_recompose_without_minting_authority() {
        let origin = origin("test-domain");
        let manifest = BoundaryManifest::new(
            origin.clone(),
            digest("whole"),
            vec![
                BoundaryRequirement::new(digest("a"), digest("slice-a")),
                BoundaryRequirement::new(digest("b"), digest("slice-b")),
            ],
        )
        .unwrap();
        let slices = vec![
            BoundarySlice::<&str>::new(
                origin.clone(),
                digest("a"),
                digest("slice-a"),
                PathVerdict::clean(),
            ),
            BoundarySlice::new(origin, digest("b"), digest("slice-b"), PathVerdict::clean()),
        ];
        let NativeJudgment::Admit(witness) = recompose(&manifest, &slices) else {
            panic!("exact clean slices must recompose");
        };
        assert_eq!(witness.boundaries().len(), 2);
    }

    #[test]
    fn laundering_and_obstructions_are_all_preserved() {
        let expected_origin = origin("expected");
        let manifest = BoundaryManifest::new(
            expected_origin,
            digest("whole"),
            vec![
                BoundaryRequirement::new(digest("a"), digest("slice-a")),
                BoundaryRequirement::new(digest("missing"), digest("slice-missing")),
            ],
        )
        .unwrap();
        let slices = vec![
            BoundarySlice::new(
                origin("foreign"),
                digest("a"),
                digest("rewritten"),
                PathVerdict::obstructed(digest("edge"), "blocked"),
            ),
            BoundarySlice::new(
                origin("foreign"),
                digest("extra"),
                digest("extra-slice"),
                PathVerdict::clean(),
            ),
        ];
        let NativeJudgment::Refuse(refusal) = recompose(&manifest, &slices) else {
            panic!("hostile slices must refuse");
        };
        assert_eq!(refusal.failures().len(), 6);
        assert!(
            refusal
                .failures()
                .iter()
                .any(|failure| matches!(failure, RecompositionFailure::ObstructedBoundary { .. }))
        );
        assert!(
            refusal
                .failures()
                .iter()
                .any(|failure| matches!(failure, RecompositionFailure::UnaccountedBoundary { .. }))
        );
        assert!(
            refusal
                .failures()
                .iter()
                .any(|failure| matches!(failure, RecompositionFailure::MissingBoundary { .. }))
        );
    }
}
