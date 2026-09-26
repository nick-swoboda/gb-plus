//! Baseline command fixture for the production walking-skeleton test.
//!
//! The test compiles this file to an absolute path with static ELF linkage on
//! Linux, allowing executable admission without a controlled PATH or dynamic
//! loader mounts. Its nonzero exit models the failing baseline expected by
//! `validate_fake_history`. The current spine refuses at containment before
//! executing it.
//!
//! `walking_skeleton_production_spine.rs` owns compilation and ELF verification.

fn main() -> std::process::ExitCode {
    // A distinctive non-zero code, so a run that somehow terminated would be
    // attributable to this program rather than to any tool that wraps it.
    std::process::ExitCode::from(9)
}
