//! Queue-owned execution authority and legacy migration.
use super::{
    BTreeSet, MAX_QUEUE_BYTES, OwnerStateRoot, QUEUE_SCHEMA_VERSION, QueueBook, QueueStore,
};

pub(super) fn migrate_legacy(book: &mut QueueBook) -> Result<(), String> {
    if !book.executions.is_empty() {
        return Err("Legacy queue data cannot contain newer execution authority.".into());
    }
    for run in book.runs.iter().filter(|run| run.state.active()) {
        book.executions.admit_parent(
            run.id.clone(),
            run.project_id.clone(),
            run.workspace_id.clone(),
        )?;
    }
    book.schema_version = QUEUE_SCHEMA_VERSION;
    Ok(())
}

pub(super) fn validate_bindings(book: &QueueBook) -> Result<(), String> {
    book.executions.validate()?;
    let active = book
        .runs
        .iter()
        .filter(|run| run.state.active())
        .map(|run| run.id.clone())
        .collect::<BTreeSet<_>>();
    if book.executions.roots() != active {
        return Err("Model execution families do not match the exact active queue runs.".into());
    }
    for member in book.executions.members() {
        let run = book
            .runs
            .iter()
            .find(|run| run.id == member.family && run.state.active())
            .ok_or("Model execution is not owned by an active queue run.")?;
        if member.project != run.project_id
            || (member.role.is_none() && member.workspace != run.workspace_id)
        {
            return Err("Model execution changed its queue project or workspace binding.".into());
        }
        if member.role.is_some() && !book.children.iter().any(|child| child.id == member.run) {
            return Err("Child execution has no admitted app journal binding.".into());
        }
        if let grok_build_plus_host::PlusExecutionState::Waiting { ordinal } = member.execution
            && (ordinal >= book.next_ordinal
                || book.items.iter().any(|item| item.ordinal == ordinal)
                || book
                    .steer_intents
                    .iter()
                    .any(|intent| intent.ordinal == ordinal))
        {
            return Err("Model execution order conflicts with retained queue work.".into());
        }
    }
    Ok(())
}

impl QueueStore {
    pub(super) fn preserve_migration_backup(&self, name: &str, bytes: &[u8]) -> Result<(), String> {
        OwnerStateRoot::new(&self.state_root)
            .file(name, MAX_QUEUE_BYTES)
            .and_then(|backup| match backup.read()? {
                Some(_) => Ok(()),
                None => backup.replace(bytes),
            })
            .map_err(|error| format!("Cannot preserve the queue migration backup: {error}"))
    }
}

#[cfg(test)]
pub(super) mod tests;
