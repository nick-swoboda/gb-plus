use std::sync::atomic::Ordering;

use super::{QueueCoordinator, QueueItemState, active_run_count};

const ENGINE_CHANGE_HOLD: &str = "Held after changing engines. Choose Send next when ready.";

impl QueueCoordinator {
    pub(crate) fn hold_for_engine_change(&self) -> Result<(), String> {
        if crate::bounded_process::model_cleanup_pending() {
            return Err(
                "A previous CLI is still stopping. Wait for cleanup before switching engines."
                    .into(),
            );
        }
        if self.lifecycle_suspended.load(Ordering::Acquire) {
            return Err("Unlock the app before switching engines.".into());
        }
        if !self.view().available {
            return Err("Saved queue state is unavailable. Reopen the app and check Diagnostics before switching engines.".into());
        }
        self.mutate(|book| {
            if active_run_count(book) != 0
                || book.executions.held() != 0
                || book
                    .items
                    .iter()
                    .any(|item| item.state == QueueItemState::Running)
            {
                return Err(
                    "Finish or stop running chats in all projects before switching engines.".into(),
                );
            }
            for item in &mut book.items {
                if item.state == QueueItemState::Queued && item.auto_start {
                    item.auto_start = false;
                    item.blocked_reason = Some(ENGINE_CHANGE_HOLD.into());
                }
            }
            Ok(())
        })
    }
}

pub(super) fn is_hold_reason(reason: Option<&str>) -> bool {
    matches!(
        reason,
        Some("Held from an earlier version." | ENGINE_CHANGE_HOLD)
    )
}
