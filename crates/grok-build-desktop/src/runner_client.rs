//! Compatibility surface for the extracted runner client and legacy lifecycle owner.

#[cfg(test)]
include!("runner_client/tests/extracted_core.rs");

#[cfg(not(test))]
pub use grok_build_runner_client::*;

mod lifecycle_owner;

pub use lifecycle_owner::{
    ApplicationLifecycleBindingView, DesktopRunnerLifecycleOwner, DesktopRunnerLifecycleStateView,
    FinalVerifierLifecycleBindingView, LiveStateVerifierLifecycleBindingView,
    ReconciliationCustodyView, RunnerLifecycleBindingView, RunnerLifecycleOwnerConfig,
    RunnerLifecycleReconciliation,
};

#[cfg(all(test, unix))]
mod tests;
