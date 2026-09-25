use super::*;
use crate::runtime::cancel::RuntimeCancelHandle;
use crate::runtime::types::RuntimeTransport;

fn selection() -> ModelSelection {
    ModelSelection {
        schema_version: 1,
        transport: RuntimeTransport::GrokCliAcp,
        model: ModelDescriptor {
            id: "grok-4.7".into(),
            name: "Grok 4.7".into(),
            context_window: Some(500_000),
            long_context_threshold: None,
            accepts_images: None,
            reasoning_efforts: vec!["high".into(), "xhigh".into()],
        },
        reasoning_effort: Some("high".into()),
        verified_at: 1,
    }
}

fn exercise(marker: Option<&str>) -> (Result<(), String>, Vec<Value>, Value) {
    let (root, workspace, pool, config) = super::super::standard_tests::fixture();
    std::fs::write(
        config.cli_path(),
        include_str!("../../../../tests/fixtures/model-selection-acp.sh"),
    )
    .unwrap();
    if let Some(marker) = marker {
        std::fs::write(workspace.join(marker), "fixture").unwrap();
    }
    let mut process = process::AcpProcess::spawn(&config, RuntimeCancelHandle::new()).unwrap();
    process.session_config = process
        .request("session/new", &json!({}), &|_| Ok(()))
        .unwrap();
    let mut requested = selection();
    if marker == Some("default-effort") {
        requested.reasoning_effort = None;
    }
    let result = apply_selection(&mut process, "model-session", &requested, &|_| Ok(()));
    let active = process.session_config.clone();
    process.terminate().unwrap();
    let requests = std::fs::read_to_string(workspace.join("requests.jsonl"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    drop(process);
    pool.clear().unwrap();
    std::fs::remove_dir_all(root).unwrap();
    (result, requests, active)
}

#[test]
fn standard_selection_uses_active_controls_even_when_saved_history_has_the_old_effort() {
    let (result, requests, active) = exercise(None);
    result.unwrap();
    validate_active_selection(&active, &selection()).unwrap();
    let controls: Vec<_> = requests
        .iter()
        .filter(|row| row["method"] == "session/set_config_option")
        .map(|row| row["params"].clone())
        .collect();
    assert_eq!(
        controls,
        [
            json!({"sessionId":"model-session","configId":"model","value":"grok-4.7"}),
            json!({"sessionId":"model-session","configId":"reasoning_effort","value":"high"}),
        ]
    );
    assert!(!requests.iter().any(|row| matches!(
        row["method"].as_str(),
        Some("session/prompt" | "session/set_model" | "_x.ai/session/state")
    )));
}

#[test]
fn default_effort_keeps_the_clis_active_level_without_sending_an_effort_override() {
    let (result, requests, active) = exercise(Some("default-effort"));
    result.unwrap();
    assert_eq!(
        config_option(&active, "reasoning_effort").unwrap().unwrap()["currentValue"],
        "xhigh"
    );
    assert_eq!(
        requests
            .iter()
            .filter(|row| row["method"] == "session/set_config_option")
            .count(),
        1
    );
    assert!(
        !requests
            .iter()
            .any(|row| row["params"]["configId"] == "reasoning_effort")
    );
}

#[test]
fn older_cli_without_session_controls_retains_the_verified_legacy_path() {
    let (result, requests, _) = exercise(Some("legacy"));
    result.unwrap();
    assert!(
        requests
            .iter()
            .any(|row| row["method"] == "session/set_model"
                && row["params"]["_meta"]["reasoningEffort"] == "high")
    );
    assert!(
        requests
            .iter()
            .any(|row| row["method"] == "_x.ai/session/state")
    );
    assert!(
        !requests
            .iter()
            .any(|row| row["method"] == "session/set_config_option")
    );
}

#[test]
fn unconfirmed_active_effort_or_model_refuses_without_sending_a_prompt() {
    for marker in ["wrong-effort", "wrong-model"] {
        let (result, requests, _) = exercise(Some(marker));
        assert!(result.is_err());
        assert!(!requests.iter().any(|row| row["method"] == "session/prompt"));
    }
}

#[test]
fn missing_ambiguous_or_oversized_selection_evidence_is_refused() {
    let valid = json!({"configOptions":[
        {"id":"model","type":"select","currentValue":"grok-4.7"},
        {"id":"reasoning_effort","type":"select","currentValue":"high"},
    ]});
    validate_active_selection(&valid, &selection()).unwrap();
    let mut missing = valid.clone();
    missing["configOptions"].as_array_mut().unwrap().pop();
    let mut duplicate = valid.clone();
    duplicate["configOptions"]
        .as_array_mut()
        .unwrap()
        .push(valid["configOptions"][1].clone());
    let mut unsupported = valid.clone();
    unsupported["configOptions"][1]["type"] = json!("boolean");
    for config in [
        missing,
        duplicate,
        unsupported,
        json!({"configOptions": vec![valid["configOptions"][0].clone(); 33]}),
    ] {
        assert!(validate_active_selection(&config, &selection()).is_err());
    }
}
