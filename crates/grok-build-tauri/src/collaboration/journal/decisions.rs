//! User decisions preserve attribution and revalidate the original parent workspace.
use super::{Decision, Journal, Path, Payload, RunId};
use grok_build_plus_host::{
    BoundProject, accept_pending_file_proposal, preflight_pending_file_set,
    rollback_accepted_file_proposal,
};
use std::collections::BTreeSet;
use std::path::PathBuf;

impl Journal {
    pub(in crate::collaboration) fn decide(
        &mut self,
        state: &Path,
        run: &RunId,
        accept: bool,
        bound: &BoundProject,
        conflicting_paths: &BTreeSet<PathBuf>,
    ) -> Result<(), String> {
        let index = self
            .entries
            .iter()
            .position(|entry| &entry.run == run)
            .ok_or("Child proposal has no retained result.")?;
        let decision = self.entries[index].decision;
        if matches!(
            (decision, accept),
            (Decision::Accepted, true) | (Decision::Rejected, false)
        ) {
            return Ok(());
        }
        if decision == Decision::Accepted || decision == Decision::Rejected {
            return Err("This child proposal already has a different final decision.".into());
        }
        if !accept {
            return self.set_decision(state, index, Decision::Rejected);
        }
        if decision == Decision::Accepting {
            return Err("An earlier Accept has an uncertain completion. Inspect the files before discarding the retained review; it cannot be reapplied automatically.".into());
        }
        let Payload::Available {
            pending,
            assistant: Some(_),
            ..
        } = &self.entries[index].payload
        else {
            return Err("The child result is unavailable or incomplete. Reattach context or discard its retained review; unavailable changes cannot be accepted.".into());
        };
        let pending = pending.clone();
        if pending.items.is_empty() {
            return Err("This child has no completed proposed changes to accept.".into());
        }
        if pending
            .items
            .iter()
            .any(|proposal| conflicting_paths.contains(&proposal.relative_path))
        {
            return Err("Another unresolved parent or child proposal touches the same file. Reconcile or reject that proposal before Accept.".into());
        }
        preflight_pending_file_set(bound, &pending).map_err(|e| e.to_string())?;
        self.set_decision(state, index, Decision::Accepting)?;
        for (written, proposal) in pending.items.iter().enumerate() {
            if let Err(error) = accept_pending_file_proposal(bound, proposal) {
                let mut rollback_error = None;
                for applied in pending.items[..written].iter().rev() {
                    if let Err(error) = rollback_accepted_file_proposal(bound, applied) {
                        rollback_error.get_or_insert(error.to_string());
                    }
                }
                if let Some(rollback) = rollback_error {
                    return Err(format!(
                        "Child Accept requires reconciliation after rollback could not be proven: {rollback}"
                    ));
                }
                self.set_decision(state, index, Decision::Pending)?;
                return Err(error.to_string());
            }
        }
        self.set_decision(state, index, Decision::Accepted)
    }
    fn set_decision(
        &mut self,
        state: &Path,
        index: usize,
        decision: Decision,
    ) -> Result<(), String> {
        let before = self.clone();
        self.entries[index].decision = decision;
        self.save_or_restore(state, before)
    }
}
