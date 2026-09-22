include!("part_01.rs");
include!("part_02.rs");
include!("part_03.rs");
include!("part_04.rs");
include!("part_05.rs");
include!("part_06.rs");

/// The same static-target attempt, prepared under an externally supplied grant
/// and compiled policy.
///
/// Used when the command must run on a **composed** service, whose handoff was
/// journaled under one specific authority. `service_owned` compares the two, so
/// a command that issues its own grant can never run there however valid that
/// grant is on its own terms.
#[cfg(target_os = "linux")]
pub(crate) fn linux_measurement_attempt_under(
    grant: grok_build_core::IssuedWorkspaceGrant,
    policy: grok_build_core::CompiledExecutionPolicy,
) -> macos_contained_walking_skeleton_command::WalkingSkeletonAttempt {
    macos_contained_walking_skeleton_command::linux_static_attempt_under(grant, policy)
}
