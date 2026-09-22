//! Deterministic selection among independently admitted finish candidates.
//!
//! This module does not grant [`crate::SprintState::Completed`] authority.
//! Completion remains the result of [`crate::assess_completion`] plus the
//! durable completion transaction. Candidate selection happens earlier and is
//! deliberately unable to make an inadmissible candidate look preferable by
//! assigning it a small implementation cost.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use crate::Digest;

/// Closed hard-gate result produced by the candidate-evaluation policy.
///
/// The aggregate evidence digest must bind the exact acceptance, security,
/// behavior-preservation, risk, clarity, and rollback evaluations. This type
/// records the evaluation result; the subsystem producing the digest remains
/// responsible for validating the referenced evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinishCandidateAdmissibility {
    acceptance_and_security: FinishCandidateGateStatus,
    outside_behavior: FinishCandidateGateStatus,
    unresolved_risk_count: u64,
    clarity: FinishCandidateGateStatus,
    immediate_rollback: FinishCandidateGateStatus,
    evidence_digest: Digest,
}

/// Explicit result of one binary candidate-admission gate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FinishCandidateGateStatus {
    /// The referenced evaluation evidence passed this gate.
    Passed,
    /// The referenced evaluation evidence failed this gate.
    Failed,
}

impl FinishCandidateGateStatus {
    const fn passed(self) -> bool {
        matches!(self, Self::Passed)
    }
}

impl FinishCandidateAdmissibility {
    /// Creates an exact candidate-admission result.
    #[must_use]
    pub const fn new(
        acceptance_and_security: FinishCandidateGateStatus,
        outside_behavior: FinishCandidateGateStatus,
        unresolved_risk_count: u64,
        clarity: FinishCandidateGateStatus,
        immediate_rollback: FinishCandidateGateStatus,
        evidence_digest: Digest,
    ) -> Self {
        Self {
            acceptance_and_security,
            outside_behavior,
            unresolved_risk_count,
            clarity,
            immediate_rollback,
            evidence_digest,
        }
    }

    /// Digest of the exact aggregate evidence evaluated by the admission
    /// policy.
    #[must_use]
    pub const fn evidence_digest(&self) -> &Digest {
        &self.evidence_digest
    }
}

/// Quantified costs compared after every hard gate passes.
///
/// All candidates in one cohort must use the same measurement-policy digest.
/// The comparison is the field order below; there is no weighted sum and a
/// later field can never compensate for an earlier field.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FinishCandidateCost {
    /// Newly introduced public API, schema, or protocol items.
    pub new_public_interface_items: u64,
    /// Newly introduced direct runtime or build dependencies.
    pub new_direct_dependencies: u64,
    /// Production paths changed by the candidate.
    pub production_paths_changed: u64,
    /// Added, removed, or modified production lines under the common policy.
    pub production_lines_changed: u64,
    /// Runtime cost in units fixed by the common measurement policy.
    pub runtime_cost_units: u64,
    /// Maintenance cost in units fixed by the common measurement policy.
    pub maintenance_cost_units: u64,
}

/// One hard-gate-admitted candidate and its deterministic cost vector.
///
/// Construction is closed so an inadmissible candidate cannot enter the
/// ordering function. This is selection evidence, not sprint-completion
/// evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OptimalFinishCandidate {
    candidate_digest: Digest,
    cohort_digest: Digest,
    measurement_policy_digest: Digest,
    evaluated_snapshot: Digest,
    admissibility_evidence_digest: Digest,
    cost: FinishCandidateCost,
}

impl OptimalFinishCandidate {
    /// Admits a candidate to deterministic comparison only when every hard
    /// finish-selection invariant passed.
    ///
    /// # Errors
    ///
    /// Returns [`OptimalFinishError`] when acceptance or security failed,
    /// behavior outside the requested change was not preserved, any unresolved
    /// risk remains, clarity was sacrificed, or immediate rollback was not
    /// proven.
    pub fn admit(
        candidate_digest: Digest,
        cohort_digest: Digest,
        measurement_policy_digest: Digest,
        evaluated_snapshot: Digest,
        admissibility: &FinishCandidateAdmissibility,
        cost: FinishCandidateCost,
    ) -> Result<Self, OptimalFinishError> {
        if !admissibility.acceptance_and_security.passed() {
            return Err(OptimalFinishError::Inadmissible(
                FinishCandidateHardGate::AcceptanceAndSecurity,
            ));
        }
        if !admissibility.outside_behavior.passed() {
            return Err(OptimalFinishError::Inadmissible(
                FinishCandidateHardGate::OutsideBehaviorPreserved,
            ));
        }
        if admissibility.unresolved_risk_count != 0 {
            return Err(OptimalFinishError::UnresolvedRisk {
                count: admissibility.unresolved_risk_count,
            });
        }
        if !admissibility.clarity.passed() {
            return Err(OptimalFinishError::Inadmissible(
                FinishCandidateHardGate::ClarityPreserved,
            ));
        }
        if !admissibility.immediate_rollback.passed() {
            return Err(OptimalFinishError::Inadmissible(
                FinishCandidateHardGate::ImmediateRollback,
            ));
        }
        Ok(Self {
            candidate_digest,
            cohort_digest,
            measurement_policy_digest,
            evaluated_snapshot,
            admissibility_evidence_digest: admissibility.evidence_digest.clone(),
            cost,
        })
    }

    /// Content identity of the candidate implementation.
    #[must_use]
    pub const fn candidate_digest(&self) -> &Digest {
        &self.candidate_digest
    }

    /// Identity of the objective and candidate cohort being compared.
    #[must_use]
    pub const fn cohort_digest(&self) -> &Digest {
        &self.cohort_digest
    }

    /// Identity of the common metric definitions and benchmark policy.
    #[must_use]
    pub const fn measurement_policy_digest(&self) -> &Digest {
        &self.measurement_policy_digest
    }

    /// Exact private snapshot against which this candidate was evaluated.
    #[must_use]
    pub const fn evaluated_snapshot(&self) -> &Digest {
        &self.evaluated_snapshot
    }

    /// Digest of the exact aggregate hard-gate evidence.
    #[must_use]
    pub const fn admissibility_evidence_digest(&self) -> &Digest {
        &self.admissibility_evidence_digest
    }

    /// Lexicographic cost vector.
    #[must_use]
    pub const fn cost(&self) -> FinishCandidateCost {
        self.cost
    }
}

/// Hard gates which must pass before cost comparison is legal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FinishCandidateHardGate {
    /// Every acceptance and security constraint passed.
    AcceptanceAndSecurity,
    /// Behavior outside the requested change was preserved.
    OutsideBehaviorPreserved,
    /// The common clarity standard passed.
    ClarityPreserved,
    /// Immediate rollback was independently proven usable.
    ImmediateRollback,
}

impl Display for FinishCandidateHardGate {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::AcceptanceAndSecurity => "acceptance and security",
            Self::OutsideBehaviorPreserved => "outside behavior preservation",
            Self::ClarityPreserved => "clarity preservation",
            Self::ImmediateRollback => "immediate rollback",
        };
        formatter.write_str(label)
    }
}

/// Deterministic candidate-selection failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OptimalFinishError {
    /// A hard gate did not pass.
    Inadmissible(FinishCandidateHardGate),
    /// One or more unresolved security, compatibility, or integrity risks
    /// remain.
    UnresolvedRisk {
        /// Exact unresolved risk count.
        count: u64,
    },
    /// Candidates were evaluated for different objectives or cohorts.
    CohortMismatch,
    /// Candidates used different metric definitions or benchmark policies.
    MeasurementPolicyMismatch,
    /// One content identity was associated with different candidate data.
    CandidateIdentityCollision,
    /// No candidate was supplied.
    EmptyCandidateSet,
    /// One candidate identity appeared more than once in the set.
    DuplicateCandidate,
}

impl Display for OptimalFinishError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inadmissible(gate) => write!(formatter, "candidate failed the {gate} hard gate"),
            Self::UnresolvedRisk { count } => {
                write!(formatter, "candidate retains {count} unresolved risks")
            }
            Self::CohortMismatch => {
                formatter.write_str("finish candidates belong to different objective cohorts")
            }
            Self::MeasurementPolicyMismatch => {
                formatter.write_str("finish candidates use different measurement policies")
            }
            Self::CandidateIdentityCollision => {
                formatter.write_str("one candidate digest is bound to different candidate data")
            }
            Self::EmptyCandidateSet => formatter.write_str("candidate set is empty"),
            Self::DuplicateCandidate => {
                formatter.write_str("candidate set contains a duplicate identity")
            }
        }
    }
}

impl Error for OptimalFinishError {}

/// Compares two admitted candidates.
///
/// [`Ordering::Less`] means `left` is preferred. The six cost fields are
/// compared in declaration order. If all substantive costs are equal, the
/// candidate digest is an identity-only canonical tie-break so input order can
/// never affect selection.
///
/// # Errors
///
/// Returns [`OptimalFinishError`] when the candidates belong to different
/// cohorts, use different measurement policies, or reuse one candidate digest
/// for different data.
pub fn compare_optimal_finish_candidates(
    left: &OptimalFinishCandidate,
    right: &OptimalFinishCandidate,
) -> Result<Ordering, OptimalFinishError> {
    if left.cohort_digest != right.cohort_digest {
        return Err(OptimalFinishError::CohortMismatch);
    }
    if left.measurement_policy_digest != right.measurement_policy_digest {
        return Err(OptimalFinishError::MeasurementPolicyMismatch);
    }
    if left.candidate_digest == right.candidate_digest {
        return if left == right {
            Ok(Ordering::Equal)
        } else {
            Err(OptimalFinishError::CandidateIdentityCollision)
        };
    }
    Ok(left
        .cost
        .cmp(&right.cost)
        .then_with(|| left.candidate_digest.cmp(&right.candidate_digest)))
}

/// Selects one canonical optimum from a nonempty, unique candidate cohort.
///
/// Selection is independent of input order. Every candidate must already have
/// passed the hard-gate constructor.
///
/// # Errors
///
/// Returns [`OptimalFinishError`] for an empty set, duplicate/colliding
/// identities, mixed cohorts, or mixed measurement policies.
pub fn select_optimal_finish_candidate(
    candidates: &[OptimalFinishCandidate],
) -> Result<&OptimalFinishCandidate, OptimalFinishError> {
    let mut iter = candidates.iter();
    let Some(mut selected) = iter.next() else {
        return Err(OptimalFinishError::EmptyCandidateSet);
    };
    let mut identities = BTreeMap::new();
    identities.insert(selected.candidate_digest(), selected);
    for candidate in iter {
        if let Some(existing) = identities.insert(candidate.candidate_digest(), candidate) {
            if existing != candidate {
                return Err(OptimalFinishError::CandidateIdentityCollision);
            }
            return Err(OptimalFinishError::DuplicateCandidate);
        }
        if compare_optimal_finish_candidates(candidate, selected)? == Ordering::Less {
            selected = candidate;
        }
    }
    Ok(selected)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASS: FinishCandidateGateStatus = FinishCandidateGateStatus::Passed;
    const FAIL: FinishCandidateGateStatus = FinishCandidateGateStatus::Failed;

    fn digest(label: &str) -> Digest {
        Digest::sha256(label.as_bytes())
    }

    fn admission() -> FinishCandidateAdmissibility {
        FinishCandidateAdmissibility::new(PASS, PASS, 0, PASS, PASS, digest("evidence"))
    }

    fn cost() -> FinishCandidateCost {
        FinishCandidateCost {
            new_public_interface_items: 1,
            new_direct_dependencies: 1,
            production_paths_changed: 2,
            production_lines_changed: 20,
            runtime_cost_units: 30,
            maintenance_cost_units: 40,
        }
    }

    fn candidate(label: &str, candidate_cost: FinishCandidateCost) -> OptimalFinishCandidate {
        OptimalFinishCandidate::admit(
            digest(label),
            digest("cohort"),
            digest("policy"),
            digest(&format!("snapshot-{label}")),
            &admission(),
            candidate_cost,
        )
        .expect("valid candidate")
    }

    #[test]
    fn every_hard_gate_is_non_compensable() {
        let cases = [
            (
                FinishCandidateAdmissibility::new(
                    FAIL,
                    PASS,
                    0,
                    PASS,
                    PASS,
                    digest("failed-acceptance"),
                ),
                OptimalFinishError::Inadmissible(FinishCandidateHardGate::AcceptanceAndSecurity),
            ),
            (
                FinishCandidateAdmissibility::new(
                    PASS,
                    FAIL,
                    0,
                    PASS,
                    PASS,
                    digest("changed-behavior"),
                ),
                OptimalFinishError::Inadmissible(FinishCandidateHardGate::OutsideBehaviorPreserved),
            ),
            (
                FinishCandidateAdmissibility::new(PASS, PASS, 2, PASS, PASS, digest("risks")),
                OptimalFinishError::UnresolvedRisk { count: 2 },
            ),
            (
                FinishCandidateAdmissibility::new(PASS, PASS, 0, FAIL, PASS, digest("unclear")),
                OptimalFinishError::Inadmissible(FinishCandidateHardGate::ClarityPreserved),
            ),
            (
                FinishCandidateAdmissibility::new(PASS, PASS, 0, PASS, FAIL, digest("no-rollback")),
                OptimalFinishError::Inadmissible(FinishCandidateHardGate::ImmediateRollback),
            ),
        ];
        for (invalid, expected) in cases {
            let result = OptimalFinishCandidate::admit(
                digest("tiny-diff"),
                digest("cohort"),
                digest("policy"),
                digest("snapshot"),
                &invalid,
                FinishCandidateCost {
                    new_public_interface_items: 0,
                    new_direct_dependencies: 0,
                    production_paths_changed: 0,
                    production_lines_changed: 0,
                    runtime_cost_units: 0,
                    maintenance_cost_units: 0,
                },
            );
            assert_eq!(result, Err(expected));
        }
    }

    #[test]
    fn costs_are_strictly_lexicographic_without_weights() {
        let baseline = candidate("baseline", cost());
        let mut axes = [cost(); 6];
        axes[0].new_public_interface_items = 0;
        axes[0].new_direct_dependencies = u64::MAX;
        axes[1].new_direct_dependencies = 0;
        axes[1].production_paths_changed = u64::MAX;
        axes[2].production_paths_changed = 1;
        axes[2].production_lines_changed = u64::MAX;
        axes[3].production_lines_changed = 19;
        axes[3].runtime_cost_units = u64::MAX;
        axes[4].runtime_cost_units = 29;
        axes[4].maintenance_cost_units = u64::MAX;
        axes[5].maintenance_cost_units = 39;
        for (index, axis_cost) in axes.into_iter().enumerate() {
            let preferred = candidate(&format!("axis-{index}"), axis_cost);
            assert_eq!(
                compare_optimal_finish_candidates(&preferred, &baseline),
                Ok(Ordering::Less)
            );
        }
    }

    #[test]
    fn mixed_cohorts_and_policies_are_rejected() {
        let left = candidate("left", cost());
        let mut other_cohort = candidate("right", cost());
        other_cohort.cohort_digest = digest("other-cohort");
        assert_eq!(
            compare_optimal_finish_candidates(&left, &other_cohort),
            Err(OptimalFinishError::CohortMismatch)
        );

        let mut other_policy = candidate("right", cost());
        other_policy.measurement_policy_digest = digest("other-policy");
        assert_eq!(
            compare_optimal_finish_candidates(&left, &other_policy),
            Err(OptimalFinishError::MeasurementPolicyMismatch)
        );
    }

    #[test]
    fn canonical_tie_break_is_input_order_independent() {
        let left = candidate("left", cost());
        let right = candidate("right", cost());
        let expected = if left.candidate_digest() < right.candidate_digest() {
            left.candidate_digest().clone()
        } else {
            right.candidate_digest().clone()
        };
        assert_eq!(
            select_optimal_finish_candidate(&[left.clone(), right.clone()])
                .expect("select forward")
                .candidate_digest(),
            &expected
        );
        assert_eq!(
            select_optimal_finish_candidate(&[right, left])
                .expect("select reverse")
                .candidate_digest(),
            &expected
        );
    }

    #[test]
    fn empty_duplicate_and_identity_collision_sets_are_rejected() {
        assert_eq!(
            select_optimal_finish_candidate(&[]),
            Err(OptimalFinishError::EmptyCandidateSet)
        );
        let first = candidate("same", cost());
        assert_eq!(
            select_optimal_finish_candidate(&[first.clone(), first.clone()]),
            Err(OptimalFinishError::DuplicateCandidate)
        );
        let mut collision = first.clone();
        collision.cost.runtime_cost_units += 1;
        assert_eq!(
            compare_optimal_finish_candidates(&first, &collision),
            Err(OptimalFinishError::CandidateIdentityCollision)
        );
        assert_eq!(
            select_optimal_finish_candidate(&[first, collision]),
            Err(OptimalFinishError::CandidateIdentityCollision)
        );
    }
}
