//! Stop intent and cancellation ownership share the admission/cleanup lock order.
use super::{BTreeSet, QueueCoordinator, RunId, children::ChildState};

impl QueueCoordinator {
    pub(crate) fn cancel_run_ids(&self, requested: &[RunId]) -> Result<(), String> {
        let handles = {
            // Admission and terminal cleanup take cancels before the durable
            // book. Keep that order through selection: a finishing child cannot
            // disappear between its active snapshot and its handle lookup.
            let cancels = self
                .cancels
                .lock()
                .map_err(|_| "Queue cancellation registry is unavailable.")?;
            let ids = self.mutate(|book| {
                let mut ids = BTreeSet::new();
                for id in requested {
                    let active = book
                        .runs
                        .iter()
                        .find(|run| run.id == *id)
                        .map(|run| run.state.active())
                        .or_else(|| {
                            book.children
                                .iter()
                                .find(|child| child.id == *id)
                                .map(|child| child.state.active())
                        })
                        .ok_or("Cancellation identity is no longer retained.")?;
                    if active {
                        ids.insert(id.clone());
                    }
                }
                for child in &mut book.children {
                    if child.state.active() && requested.contains(&child.parent) {
                        child.state = ChildState::StopRequested;
                        ids.insert(child.id.clone());
                    }
                }
                Ok(ids)
            })?;
            ids.iter()
                .map(|id| {
                    cancels.get(id).cloned().ok_or_else(|| {
                        format!(
                            "Active agent run {} has no cancellation handle; disconnect refused.",
                            id.as_str()
                        )
                    })
                })
                .collect::<Result<Vec<_>, _>>()?
        };
        // Every stop intent is durable before transport effects. Release the
        // registry lock so a cancellation acknowledgement can finish cleanup.
        let mut first_error = None;
        for handle in handles {
            if let Err(error) = handle.request_cancel() {
                first_error.get_or_insert(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}
