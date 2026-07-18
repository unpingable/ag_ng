//! Lossless path-obstruction composition and separate evaluation traces.

use ag_primitives::Digest;
use serde::{Deserialize, Serialize};

use crate::{FailureEvidence, NonEmpty};

/// An obstruction located at an exact evaluation edge.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocatedObstruction<O> {
    edge_id: Digest,
    obstruction: O,
}

impl<O> LocatedObstruction<O> {
    /// Locates an obstruction.
    #[must_use]
    pub const fn new(edge_id: Digest, obstruction: O) -> Self {
        Self {
            edge_id,
            obstruction,
        }
    }

    /// Returns the stable edge identifier.
    #[must_use]
    pub const fn edge_id(&self) -> &Digest {
        &self.edge_id
    }

    /// Returns the family-native obstruction.
    #[must_use]
    pub const fn obstruction(&self) -> &O {
        &self.obstruction
    }

    /// Renames the obstruction domain without dropping its location.
    pub fn rename<U>(self, rename: impl FnOnce(O) -> U) -> LocatedObstruction<U> {
        LocatedObstruction {
            edge_id: self.edge_id,
            obstruction: rename(self.obstruction),
        }
    }
}

/// Ordered boundary obstructions.  Clean means exactly an empty log.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathVerdict<O> {
    obstructions: Vec<LocatedObstruction<O>>,
}

impl<O> Default for PathVerdict<O> {
    fn default() -> Self {
        Self::clean()
    }
}

impl<O> PathVerdict<O> {
    /// Creates the unique clean verdict.
    #[must_use]
    pub const fn clean() -> Self {
        Self {
            obstructions: Vec::new(),
        }
    }

    /// Creates a verdict with one obstruction.
    #[must_use]
    pub fn obstructed(edge_id: Digest, obstruction: O) -> Self {
        Self {
            obstructions: vec![LocatedObstruction::new(edge_id, obstruction)],
        }
    }

    /// Appends an obstruction at the end of the path.
    pub fn push(&mut self, edge_id: Digest, obstruction: O) {
        self.obstructions
            .push(LocatedObstruction::new(edge_id, obstruction));
    }

    /// Appends the later path to this path.  Later clean edges cannot heal an
    /// earlier obstruction.
    #[must_use]
    pub fn compose(mut self, later: Self) -> Self {
        self.obstructions.extend(later.obstructions);
        self
    }

    /// Renames each obstruction one-for-one, preserving order and location.
    pub fn rename<U>(self, mut rename: impl FnMut(O) -> U) -> PathVerdict<U> {
        PathVerdict {
            obstructions: self
                .obstructions
                .into_iter()
                .map(|item| item.rename(&mut rename))
                .collect(),
        }
    }

    /// Returns whether the obstruction log is exactly empty.
    #[must_use]
    pub const fn is_clean(&self) -> bool {
        self.obstructions.is_empty()
    }

    /// Returns the ordered obstruction log.
    #[must_use]
    pub fn obstructions(&self) -> &[LocatedObstruction<O>] {
        &self.obstructions
    }

    /// Consumes the verdict and returns its ordered obstruction log.
    #[must_use]
    pub fn into_obstructions(self) -> Vec<LocatedObstruction<O>> {
        self.obstructions
    }
}

/// The operational result recorded for one evaluated edge.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TraceOutcome {
    /// The edge completed cleanly with custodied witness evidence.
    Clean {
        /// Digest of the exact replayable witness.
        witness_digest: Digest,
    },
    /// The edge completed with custodied refusal evidence.
    Obstructed {
        /// Digest of the exact native refusal.
        refusal_digest: Digest,
    },
    /// The edge was not evaluated because a named dependency blocked it.
    Skipped {
        /// Digest of the exact recorded skip reason.
        reason_digest: Digest,
    },
    /// The edge could not be semantically evaluated.
    Indeterminate {
        /// Non-empty operational failure evidence.
        evidence: NonEmpty<FailureEvidence>,
    },
}

/// One append-only trace step.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceStep {
    edge_id: Digest,
    outcome: TraceOutcome,
}

impl TraceStep {
    /// Creates a trace step.
    #[must_use]
    pub const fn new(edge_id: Digest, outcome: TraceOutcome) -> Self {
        Self { edge_id, outcome }
    }

    /// Returns the edge identifier.
    #[must_use]
    pub const fn edge_id(&self) -> &Digest {
        &self.edge_id
    }

    /// Returns the recorded outcome.
    #[must_use]
    pub const fn outcome(&self) -> &TraceOutcome {
        &self.outcome
    }
}

/// Ordered operational trace, intentionally separate from [`PathVerdict`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvaluationTrace {
    steps: Vec<TraceStep>,
}

impl EvaluationTrace {
    /// Creates an empty trace.
    #[must_use]
    pub const fn new() -> Self {
        Self { steps: Vec::new() }
    }

    /// Appends a step without changing any prior step.
    pub fn push(&mut self, step: TraceStep) {
        self.steps.push(step);
    }

    /// Returns the ordered steps.
    #[must_use]
    pub fn steps(&self) -> &[TraceStep] {
        &self.steps
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn edge(value: u8) -> Digest {
        Digest::of_bytes(&[value])
    }

    #[test]
    fn composition_is_ordered_and_clean_never_heals() {
        let first = PathVerdict::obstructed(edge(1), "first");
        let second = PathVerdict::obstructed(edge(2), "second");
        let composed = first.compose(PathVerdict::clean()).compose(second);
        let values: Vec<_> = composed
            .obstructions()
            .iter()
            .map(LocatedObstruction::obstruction)
            .copied()
            .collect();
        assert_eq!(values, vec!["first", "second"]);
    }

    #[test]
    fn composition_is_associative_for_small_hostile_paths() {
        for left_size in 0..=3 {
            for middle_size in 0..=3 {
                for right_size in 0..=3 {
                    let make = |start: u8, len| {
                        let mut path = PathVerdict::clean();
                        for offset in 0..len {
                            path.push(edge(start + offset), start + offset);
                        }
                        path
                    };
                    let left = make(0, left_size);
                    let middle = make(10, middle_size);
                    let right = make(20, right_size);
                    assert_eq!(
                        left.clone().compose(middle.clone()).compose(right.clone()),
                        left.compose(middle.compose(right))
                    );
                }
            }
        }
    }

    #[test]
    fn trace_does_not_change_path_verdict() {
        let verdict = PathVerdict::<()>::clean();
        let mut trace = EvaluationTrace::new();
        trace.push(TraceStep::new(
            edge(1),
            TraceOutcome::Skipped {
                reason_digest: Digest::of_bytes(b"blocked dependency"),
            },
        ));
        assert!(verdict.is_clean());
        assert_eq!(trace.steps().len(), 1);
    }
}
