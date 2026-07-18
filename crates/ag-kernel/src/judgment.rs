//! Total semantic judgments and the separate operational envelope.

use ag_primitives::Digest;
use serde::{Deserialize, Serialize};

/// A non-empty sequence with a distinguished first element.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NonEmpty<T> {
    head: T,
    tail: Vec<T>,
}

impl<T> NonEmpty<T> {
    /// Creates a non-empty sequence.
    #[must_use]
    pub const fn new(head: T) -> Self {
        Self {
            head,
            tail: Vec::new(),
        }
    }

    /// Converts a vector when it contains at least one value.
    #[must_use]
    pub fn from_vec(values: Vec<T>) -> Option<Self> {
        let mut values = values.into_iter();
        let head = values.next()?;
        Some(Self {
            head,
            tail: values.collect(),
        })
    }

    /// Appends a value without permitting the sequence to become empty.
    pub fn push(&mut self, value: T) {
        self.tail.push(value);
    }

    /// Returns the first value.
    #[must_use]
    pub const fn first(&self) -> &T {
        &self.head
    }

    /// Iterates in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        std::iter::once(&self.head).chain(self.tail.iter())
    }

    /// Returns the number of values.
    #[must_use]
    pub const fn len(&self) -> usize {
        1 + self.tail.len()
    }

    /// A non-empty sequence is never empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }

    /// Converts into a vector in insertion order.
    #[must_use]
    pub fn into_vec(self) -> Vec<T> {
        let mut values = Vec::with_capacity(self.len());
        values.push(self.head);
        values.extend(self.tail);
        values
    }

    /// Maps each value one-for-one, preserving cardinality and order.
    pub fn map<U>(self, mut map: impl FnMut(T) -> U) -> NonEmpty<U> {
        NonEmpty {
            head: map(self.head),
            tail: self.tail.into_iter().map(map).collect(),
        }
    }
}

impl<T> IntoIterator for NonEmpty<T> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        self.into_vec().into_iter()
    }
}

/// A total family-native semantic decision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum NativeJudgment<W, R> {
    /// The exact claim was admitted with replayable evidence.
    Admit(W),
    /// The exact claim was refused with family-native evidence.
    Refuse(R),
}

impl<W, R> NativeJudgment<W, R> {
    /// Maps admitted evidence without changing refusal evidence.
    pub fn map_admit<U>(self, map: impl FnOnce(W) -> U) -> NativeJudgment<U, R> {
        match self {
            Self::Admit(witness) => NativeJudgment::Admit(map(witness)),
            Self::Refuse(refusal) => NativeJudgment::Refuse(refusal),
        }
    }

    /// Maps refusal evidence without changing admitted evidence.
    pub fn map_refuse<U>(self, map: impl FnOnce(R) -> U) -> NativeJudgment<W, U> {
        match self {
            Self::Admit(witness) => NativeJudgment::Admit(witness),
            Self::Refuse(refusal) => NativeJudgment::Refuse(map(refusal)),
        }
    }
}

/// A class of failure that prevented a semantic judgment from completing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationalFailureKind {
    /// A required observation was unavailable.
    ObservationUnavailable,
    /// Evaluation exceeded its admitted time bound.
    Timeout,
    /// Durable custody could not be established or replayed.
    CustodyFailure,
    /// A store operation failed.
    StoreFailure,
    /// The trusted clock was unavailable or invalid.
    ClockFailure,
    /// Evaluation stopped before every required branch was decided.
    IncompleteEvaluation,
}

/// Exact evidence that evaluation could not reach a semantic judgment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailureEvidence {
    kind: OperationalFailureKind,
    evidence_digest: Digest,
}

impl FailureEvidence {
    /// Creates operational failure evidence.
    #[must_use]
    pub const fn new(kind: OperationalFailureKind, evidence_digest: Digest) -> Self {
        Self {
            kind,
            evidence_digest,
        }
    }

    /// Returns the failure class.
    #[must_use]
    pub const fn kind(&self) -> OperationalFailureKind {
        self.kind
    }

    /// Returns the digest of the detailed, custodied evidence.
    #[must_use]
    pub const fn evidence_digest(&self) -> &Digest {
        &self.evidence_digest
    }
}

/// An operational attempt either completes a semantic judgment or records why
/// no semantic judgment was reached.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OperationalEvaluation<W, R> {
    /// Evaluation completed and produced a total semantic judgment.
    Evaluated(NativeJudgment<W, R>),
    /// Evaluation could not complete.  This is neither admission nor refusal.
    Indeterminate(NonEmpty<FailureEvidence>),
}

impl<W, R> OperationalEvaluation<W, R> {
    /// Wraps a completed semantic judgment.
    #[must_use]
    pub const fn evaluated(judgment: NativeJudgment<W, R>) -> Self {
        Self::Evaluated(judgment)
    }

    /// Creates an indeterminate result from its first item of evidence.
    #[must_use]
    pub const fn indeterminate(evidence: FailureEvidence) -> Self {
        Self::Indeterminate(NonEmpty::new(evidence))
    }

    /// Returns admitted evidence only after completed semantic admission.
    #[must_use]
    pub const fn admitted(&self) -> Option<&W> {
        match self {
            Self::Evaluated(NativeJudgment::Admit(witness)) => Some(witness),
            Self::Evaluated(NativeJudgment::Refuse(_)) | Self::Indeterminate(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indeterminate_cannot_be_observed_as_admission() {
        let result = OperationalEvaluation::<(), ()>::indeterminate(FailureEvidence::new(
            OperationalFailureKind::StoreFailure,
            Digest::of_bytes(b"disk unavailable"),
        ));
        assert_eq!(result.admitted(), None);
    }

    #[test]
    fn non_empty_mapping_preserves_order_and_cardinality() {
        let mut values = NonEmpty::new(1);
        values.push(2);
        values.push(3);
        let mapped = values.map(|value| value * 10);
        assert_eq!(mapped.into_vec(), vec![10, 20, 30]);
    }
}
