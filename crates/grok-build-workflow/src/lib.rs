//! Bounded adaptation of the Apache-2.0 xai-workflow interpreter.
//!
//! The host supplies cancellation-aware operations and persists intent before
//! effects. The interpreter owns no filesystem, network, process or credentials.
#![forbid(unsafe_code)]

mod engine;
mod functions;
mod limits;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;

/// Maximum source and input/output value size, in bytes.
pub const MAX_BYTES: usize = 64 * 1024;
/// Maximum result-bearing host operations per evaluation, including replays.
pub const MAX_HOST_CALLS: u64 = 256;
/// Maximum agents in one parallel request; the app separately enforces two slots.
pub const MAX_PARALLEL: usize = 8;

/// Closed options accepted from an untrusted workflow; never execution authority.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentOptions {
    /// Bounded user task for the child.
    pub prompt: String,
    /// App role requested: explore, plan or worker. Absence requests plan.
    #[serde(default)]
    pub agent_type: Option<String>,
    /// Optional display-only label.
    #[serde(default)]
    pub label: Option<String>,
}

/// Exact, bounded operations adapted from xai-workflow's host interface.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum HostCall {
    /// Execute one child and return its separately attributed result.
    Agent(AgentOptions),
    /// Execute bounded children through the app scheduler in input order.
    Parallel {
        /// Closed child requests.
        agents: Vec<AgentOptions>,
    },
    /// Update a quiet workflow phase label.
    Phase {
        /// Bounded display text.
        text: String,
    },
    /// Retain bounded workflow diagnostics, subject to the context's privacy.
    Log {
        /// Bounded display text.
        text: String,
    },
    /// Read the app's workflow-specific budget, never the ordinary family budget.
    Budget,
    /// An explicit pause checkpoint; completed replay proceeds after user resume.
    Pause {
        /// Validated upstream pause category.
        kind: String,
        /// Bounded pause explanation.
        message: String,
    },
    /// Save a bounded named value in workflow-owned scratch storage.
    WriteScratch {
        /// A simple name, not a host path.
        name: String,
        /// Exact text, bounded individually and in aggregate by the app.
        content: String,
    },
    /// Read a previously checkpointed scratch value.
    ReadScratch {
        /// A simple name, not a host path.
        name: String,
    },
}

/// App-issued cancellation and deadline predicate. It cannot be supplied by script.
pub type CancelCheck = Arc<dyn Fn() -> bool + Send + Sync>;

/// Exact completed host value and app-verified replay evidence.
pub struct HostReply {
    /// Bounded JSON value, identical when replayed.
    pub value: Value,
    /// True only when the app reused a completed durable checkpoint.
    pub replayed: bool,
}

/// Authority boundary implemented by the app, or a bounded deterministic fixture.
pub trait WorkflowHost {
    /// Persist this sequence and exact request before effects, or reuse its exact
    /// completed result on explicit resume. Waits must observe `cancel` and their
    /// independent deadlines. An uncertain effect must not be replayed.
    ///
    /// # Errors
    /// Returns a refusal on changed authority, exhausted limits or uncertain effects.
    fn call(
        &self,
        sequence: u64,
        request: HostCall,
        cancel: &CancelCheck,
    ) -> Result<HostReply, String>;
}

/// Script completion, including explicit pause without implicit resumption.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkflowOutcome {
    /// Validated final JSON value.
    Completed {
        /// Exact bounded result.
        result: Value,
    },
    /// Explicit pause; any resume must be initiated by the user.
    Paused {
        /// Upstream pause category, validated by the interpreter.
        kind: String,
        /// Bounded explanation.
        message: String,
    },
    /// Cancel predicate or deadline stopped execution.
    Cancelled,
    /// Script or host refusal; no automatic retry is implied.
    Failed {
        /// Bounded explanation; the app applies its transient-data policy.
        error: String,
    },
}

/// Evaluate one explicitly invoked script with fixed limits and a closed host API.
/// Script inventory and extension installation must never call this function.
#[must_use]
pub fn run_workflow(
    script: &str,
    args: &Value,
    host: std::rc::Rc<dyn WorkflowHost>,
    cancel: CancelCheck,
) -> WorkflowOutcome {
    engine::run(script, args, host, cancel)
}

/// Validate structured data before conversion or persistence.
///
/// # Errors
/// Rejects excess bytes, depth, nodes, collection sizes or nonfinite numbers.
pub fn validate_value(value: &Value) -> Result<(), String> {
    limits::validate_value(value)
}

#[cfg(test)]
mod tests;
