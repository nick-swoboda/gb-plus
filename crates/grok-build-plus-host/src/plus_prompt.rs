//! Shared upstream-derived behavior with the native app tool protocol.

use std::sync::OnceLock;

/// App adaptation of the pinned upstream system prompt, shared by both transports.
pub const PLUS_APP_SYSTEM_PROMPT: &str = include_str!("../prompts/system.md");

pub(crate) fn native_system_prompt() -> &'static str {
    static PROMPT: OnceLock<String> = OnceLock::new();
    PROMPT.get_or_init(|| {
        format!(
            "{PLUS_APP_SYSTEM_PROMPT}\n<gb_plus_tool_protocol>\n{}\n</gb_plus_tool_protocol>",
            super::plus_tools::native_tool_instructions()
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_request_includes_behavior_and_keeps_exact_tools_and_model() {
        let identity = crate::PlusLiveIdentity::from_configured_key("fixture-prompt-key").unwrap();
        let input = [serde_json::json!({"role":"user","content":"Review only; do not edit."})];
        let request = crate::encode_plus_live_conversation_request(
            &input,
            "grok-4.6",
            Some("high"),
            &identity,
        )
        .unwrap();
        let body: serde_json::Value = serde_json::from_str(&request.body).unwrap();
        let instructions = body["instructions"].as_str().unwrap();
        assert!(instructions.starts_with(PLUS_APP_SYSTEM_PROMPT));
        assert!(instructions.contains("You are Grok released by xAI."));
        assert!(instructions.contains("without making unsolicited project edits"));
        assert!(instructions.contains("only when tool output supports the claim"));
        assert!(instructions.contains("Emit only native function_call items"));
        assert!(!instructions.contains("plus_tool NAME"));
        assert!(!instructions.contains("${"));
        assert_eq!(body["input"], serde_json::json!(input));
        assert_eq!(body["model"], "grok-4.6");
        assert_eq!(body["reasoning"]["effort"], "high");
        assert_eq!(body["store"], false);
        assert_eq!(body["tools"], crate::plus_live_tool_declarations());
        assert_eq!(request.endpoint, crate::PLUS_LIVE_ENDPOINT);
    }
}
