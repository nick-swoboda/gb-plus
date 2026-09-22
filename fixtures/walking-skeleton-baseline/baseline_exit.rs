//! The walking skeleton's baseline acceptance check, as a single source file.
//!
//! The fixture project's real acceptance check would be `cargo test`, and a
//! bare `cargo` is exactly what the contained boundary refuses: `prepare_v12`
//! answers "a bare executable name requires an explicit controlled PATH"
//! before any containment backend is composed, so the spine stopped one gate
//! short of the backend's own refusal. Two properties are needed to get past
//! that gate honestly, and this file exists to supply both from something the
//! repository can rebuild rather than from a path that happens to exist:
//!
//! 1. **Absolute.** The test compiles this file to a known absolute path
//!    inside its own private root and commits that path as the sprint's
//!    automated acceptance criterion, so the executable identity
//!    `prepare_v12` authenticates is a real file it can stat, open and hash.
//! 2. **Static.** Built with `-C target-feature=+crt-static` on Linux it links
//!    no interpreter, which keeps a target linkage on
//!    `LinuxTargetLinkageV1::StaticElf` — the arm `validate_mounts` serves with
//!    zero interpreter and runtime-object mounts. That is what keeps the
//!    deferred loader-closure item deferred instead of forcing it.
//!
//! The exit code is deliberately non-zero. The walking-skeleton transcript's
//! fourth turn is the *failing* baseline the requested change is supposed to
//! fix, and `validate_fake_history` requires that turn to be
//! `CommandFinished { termination: Exit(code) }` with `code != 0`. Nothing in
//! this repository executes this program today: every containment backend
//! refuses before launch, and that refusal is the spine's measured stop.
//!
//! Built by `walking_skeleton_production_spine.rs`; see
//! `baseline_command_source` and `build_baseline_command` there for the exact
//! `rustc` invocation and the ELF assertions applied to its output.

fn main() -> std::process::ExitCode {
    // A distinctive non-zero code, so a run that somehow terminated would be
    // attributable to this program rather than to any tool that wraps it.
    std::process::ExitCode::from(9)
}
