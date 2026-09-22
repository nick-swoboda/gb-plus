use super::{FamilyController, Value, json};

impl FamilyController {
    pub(super) fn message(
        &self,
        invocation: &str,
        agent: &str,
        text: String,
        transient: bool,
    ) -> Result<Value, String> {
        let child = self.latest(agent)?;
        let live = self
            .0
            .queue
            .reserve_child_message(&self.0.parent, &child.id, transient)?;
        let id = self.state()?.journal.message(
            &self.0.state_root,
            &child,
            invocation,
            text,
            transient,
        )?;
        Ok(
            json!({"agentId":child.agent_id,"messageId":id,"delivery":if live {"pending_at_child_boundary"} else {"retained_for_next_continuation"},"consumption":"not_confirmed"}),
        )
    }
}
