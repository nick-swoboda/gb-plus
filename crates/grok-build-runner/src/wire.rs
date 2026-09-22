//! Strict canonical protocol contracts and bounded binary framing for the runner.
//!
//! The desktop and runner exchange one closed set of typed JSON messages inside
//! `u32` big-endian frames. Decoding always re-encodes the typed value and
//! requires byte-for-byte equality, which rejects alternate field order,
//! whitespace, escape spellings, duplicate fields, and other non-canonical
//! preimages. Every DTO also rejects unknown fields.

use std::fmt::{self, Display, Formatter};
use std::io::{self, Cursor, Read, Write};
use std::path::{Component, Path, PathBuf};

#[cfg(any(test, feature = "future-contracts"))]
use grok_build_core::validate_current_direct_exec_command_v1;
use grok_build_core::{
    COMMAND_OUTPUT_CAPTURE_DRAIN_ALLOWANCE_BYTES_V1, CONTRACT_VERSION, ChangeSet,
    CommandDomainCleanupDisposition, CommandOutputAbandonmentReasonV2,
    CommandOutputArtifactSetReferenceV1, CommandOutputCaptureAcquiredV1,
    CommandOutputCaptureStoreHeadV1, CommandSpec, CommandTerminationV1,
    DescriptorRelativeManifestEntry, DescriptorRelativeWorkspaceManifest, Digest, EffectIntent,
    EffectKind, EnvironmentVariable, ExecutionNetwork, ExecutionOrigin, ExecutionPolicyRequest,
    FileOperation, MutationMode, PathScope, PersistedRunnerEffectDispatchClaim,
    PostCompletionRollbackApplicationArtifactAuthority, ResourceLimits,
    RunnerEffectRequestAuthority, RunnerLaunchPreparationAttempt, RunnerSessionPolicyRecord,
    RunnerSessionPurpose, SensitiveOutputDetectionPolicyReferenceV1, SprintLiveStateCapturePlan,
    SprintLiveStateCaptureRequest, SprintSpec, TaskIntegrationRequest, WorkerLease, WorkspaceGrant,
    WorkspaceNetworkPolicy, WorkspacePermissions, current_command_output_capture_maximum_v1,
};
#[cfg(test)]
use grok_build_core::{
    CommandOutputArtifactSourceV1, CommandOutputCaptureDirectoryIdentityV1,
    CommandOutputCaptureFileIdentityV1, CommandOutputCaptureIntentV1,
};
use serde::{Deserialize, Serialize};

use crate::cleanup_proof::{
    CommandDomainCleanupBackend, CommandDomainCleanupBinding, CommandDomainCleanupProofError,
    MAX_COMMAND_DOMAIN_CLEANUP_EVIDENCE_BYTES, ValidatedCommandDomainCleanupProof,
};
use crate::command::contained_boundary::{
    ContainedExecutionEvidence, ContainedSensitiveOutputRejectionEvidence,
};
use crate::command::{CapturedOutput, CommandTermination};
use crate::command_output_store::{
    SensitiveOutputCleanJournalReceiptV2, SensitiveOutputRejectionJournalReceiptV2,
    SensitiveOutputRejectionNativeProofRejoinV1,
};
use crate::service::{SessionValidatedCommandEnvelope, SessionValidatedCommandEnvelopeV12};
use crate::{
    CapabilityApplyOutcome, CapabilityRecoveryReport, CapabilityRollbackArtifact,
    CapabilityRollbackArtifactKind, CapabilityRollbackArtifactReference,
    CapabilityRollbackExpectedEndpoint, CapabilityRollbackLiveConflict,
    CapabilityRollbackObservedEndpoint, CapabilityRollbackOutcome, CapabilityRollbackPathConflict,
    CapabilityRollbackPathObservation, CapabilityRollbackSuccessEvidence,
    CapabilityRollbackTargetContract, FileMutationReceipt, FileReadResult, LiteralSearchResult,
    MAX_COMMAND_OUTPUT_ARTIFACT_BYTES, StageBundleReference, WorkspaceManifest,
};

mod contracts;
mod framing;
mod v14;
mod v15;

pub use contracts::*;
pub use framing::*;
pub use v14::*;
pub use v15::*;

#[cfg(test)]
mod tests;
