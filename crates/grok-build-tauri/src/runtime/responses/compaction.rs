//! Opaque compaction is committed atomically alongside its recoverable prefix.

use super::{Effect, ResponsesJournal, Value, worktree_recovery_digest};

impl ResponsesJournal {
    /// Called only after a validated continuation has completed. Old effect
    /// identities remain tombstones; old calls cannot become executable again.
    pub(super) fn retire_compacted_prefix(&mut self) -> Result<(), String> {
        let cut = self.record.replay_start;
        if cut == 0 {
            return Ok(());
        }
        if cut > self.items.len()
            || self
                .record
                .effects
                .values()
                .any(|effect| matches!(effect, Effect::Intent { .. }))
        {
            return Err(
                "Compacted history still has an uncertain effect; its prefix was retained.".into(),
            );
        }
        let mut retired = self.record.retired_call_ids.clone();
        for item in &self.items[..cut] {
            if item["type"] == "function_call" {
                let identity = item["call_id"]
                    .as_str()
                    .ok_or("Compacted invocation has no identity.")?;
                retired.insert(worktree_recovery_digest(identity.as_bytes()));
            }
        }
        if retired.len() > super::MAX_ITEMS {
            return Err("Compacted invocation history reached its identity bound; reset context explicitly.".into());
        }
        for effect in self.record.effects.values_mut() {
            if let Effect::Completed {
                request_digest,
                output_ordinal,
            } = effect
            {
                if *output_ordinal < cut {
                    *effect = Effect::Retired {
                        request_digest: request_digest.clone(),
                    };
                } else {
                    *output_ordinal -= cut;
                }
            }
        }
        self.record.retired_call_ids = retired;
        self.items.drain(..cut);
        self.record.replay_start = 0;
        self.record.measured_items = self.record.measured_items.saturating_sub(cut);
        if let Some(start) = self.record.tainted_from.as_mut() {
            *start = start.saturating_sub(cut);
        }
        Ok(())
    }

    pub(crate) fn needs_compaction(&self) -> Result<bool, String> {
        let Some(threshold) = self.record.compact_at else {
            return Ok(false);
        };
        // Exact prior usage plus a conservative byte ceiling for new text/tool
        // items. This is an admission estimate and is never displayed as usage.
        let estimated = match self.record.measured_tokens {
            Some(known) => {
                let start = self.record.measured_items.max(self.record.replay_start);
                known.saturating_add(
                    serde_json::to_vec(&self.items[start..])
                        .map_err(|e| e.to_string())?
                        .len() as u64,
                )
            }
            None => serde_json::to_vec(self.input())
                .map_err(|e| e.to_string())?
                .len() as u64,
        };
        Ok(estimated.saturating_add(16_384) >= threshold)
    }

    pub(crate) fn complete_compaction(&mut self, response: &Value) -> Result<(), String> {
        if !self.record.request_pending || self.record.interrupted {
            return Err("Compaction has no pending durable request intent.".into());
        }
        let output = response
            .get("output")
            .and_then(Value::as_array)
            .filter(|items| !items.is_empty() && items.len() <= 128)
            .ok_or("Compaction returned no bounded output list.")?;
        let mut opaque = false;
        for item in output {
            match item.get("type").and_then(Value::as_str) {
                Some("compaction") => {
                    if item
                        .get("encrypted_content")
                        .and_then(Value::as_str)
                        .is_none_or(str::is_empty)
                    {
                        return Err("Compaction omitted its opaque encrypted content.".into());
                    }
                    opaque = true;
                }
                Some("message") | None
                    if item.get("role").and_then(Value::as_str) == Some("user") => {}
                _ => return Err("Compaction returned an unsupported or effectful item.".into()),
            }
        }
        if !opaque {
            return Err("Compaction did not return an opaque compaction item.".into());
        }
        let previous = self.record.replay_start;
        self.record.replay_start = self.items.len();
        self.items.extend(output.iter().cloned());
        // Keep the prior prefix in the same atomic record, including exact
        // effect results. Tainted context remains memory-only throughout.
        self.record.compaction_previous_start = Some(previous);
        self.record.request_pending = false;
        self.record.measured_tokens = response
            .pointer("/usage/output_tokens")
            .and_then(Value::as_u64);
        self.record.measured_items = self.items.len();
        self.persist()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn compaction_preserves_opaque_item_and_prefix_until_continuation_completes() {
        let root = std::env::temp_dir().join(format!(
            "gbplus-compact-{}-{}",
            std::process::id(),
            crate::runtime::types::unix_time_millis()
        ));
        let mut journal = ResponsesJournal::open(&root).unwrap();
        journal.begin_turn("Remember original fact", None).unwrap();
        let original = journal.input().to_vec();
        journal.request_intent().unwrap();
        let opaque = json!({"type":"compaction","id":"compact-1","encrypted_content":"EXACT==opaque","future_metadata":{"x":7}});
        journal
            .complete_compaction(&json!({"output":[opaque.clone()]}))
            .unwrap();
        assert_eq!(journal.input(), &[opaque]);
        assert_eq!(journal.items[0], original[0]);
        assert_eq!(journal.record.compaction_previous_start, Some(0));
        journal.request_intent().unwrap();
        journal.complete_response(&json!({"id":"response-after-compact","status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"continued"}]}]})).unwrap();
        let restored = ResponsesJournal::open(&root).unwrap();
        assert_eq!(restored.record.compaction_previous_start, None);
        assert_eq!(restored.record.replay_start, 0);
        assert!(!restored.items.contains(&original[0]));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn completed_compaction_frees_prefix_space_without_reexecuting_old_invocations() {
        let root = std::env::temp_dir().join(format!(
            "gbplus-compact-effects-{}-{}",
            std::process::id(),
            crate::runtime::types::unix_time_millis()
        ));
        let mut journal = ResponsesJournal::open(&root).unwrap();
        journal.begin_turn("Read the long document", None).unwrap();
        let call = json!({"type":"function_call","call_id":"old-call","name":"read_file","arguments":"{}"});
        journal.request_intent().unwrap();
        journal
            .complete_response(
                &json!({"id":"old-response","status":"completed","output":[call.clone()]}),
            )
            .unwrap();
        journal.effect_intent("old-response", &call).unwrap();
        journal
            .complete_effect(
                "old-response",
                &call,
                &"x".repeat(2 * 1024 * 1024),
                super::super::PendingFileSet::default(),
            )
            .unwrap();
        journal.request_intent().unwrap();
        journal.complete_compaction(&json!({"output":[{"type":"compaction","encrypted_content":"EXACT compacted value"}]})).unwrap();
        assert!(serde_json::to_vec(&journal.items).unwrap().len() > 2 * 1024 * 1024);
        journal.request_intent().unwrap();
        journal.complete_response(&json!({"id":"continued","status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"remembered"}]}]})).unwrap();
        assert!(serde_json::to_vec(&journal.items).unwrap().len() < 1024);
        let mut restored = ResponsesJournal::open(&root).unwrap();
        assert!(restored.effect_intent("old-response", &call).is_err());
        restored.begin_turn("Next", None).unwrap();
        restored.request_intent().unwrap();
        assert!(
            restored
                .complete_response(&json!({"id":"duplicate","status":"completed","output":[call]}))
                .is_err()
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn retired_transient_prefix_never_turns_compaction_into_durable_capture_context() {
        let root = std::env::temp_dir().join(format!(
            "gbplus-compact-private-{}-{}",
            std::process::id(),
            crate::runtime::types::unix_time_millis()
        ));
        let mut journal = ResponsesJournal::open(&root).unwrap();
        journal
            .begin_turn("Read this capture", Some("PRIVATE_IMAGE_FIXTURE"))
            .unwrap();
        journal.request_intent().unwrap();
        journal.complete_compaction(&json!({"output":[{"type":"compaction","encrypted_content":"PRIVATE_COMPACTED_FIXTURE"}]})).unwrap();
        journal.request_intent().unwrap();
        journal.complete_response(&json!({"id":"private-done","status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"PRIVATE_DERIVED_FIXTURE"}]}]})).unwrap();
        assert_eq!(journal.record.tainted_from, Some(0));
        let disk = std::fs::read_to_string(root.join(super::super::FILE)).unwrap();
        for value in [
            "PRIVATE_IMAGE_FIXTURE",
            "PRIVATE_COMPACTED_FIXTURE",
            "PRIVATE_DERIVED_FIXTURE",
        ] {
            assert!(!disk.contains(value));
        }
        super::super::TRANSIENT
            .get()
            .unwrap()
            .lock()
            .unwrap()
            .remove(&root);
        assert!(ResponsesJournal::open(&root).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}
