//! Explicit, app-owned workflow jobs. Disabled extension inventory never evaluates code.
mod journal;
mod recovery;
mod runner;
mod store;
pub(crate) use journal::{Job, JobInput, JobState};
pub(crate) use runner::execute;
pub(crate) use store::WorkflowRegistry;

#[cfg(test)]
mod tests;

#[cfg(all(test, target_os = "macos"))]
pub(crate) mod live_fixture;
