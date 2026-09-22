//! Provider item replay and crash/effect boundaries with real app tool dispatch.

use super::*;
use crate::runtime::types::{AdapterContext, AdapterTurnOutcome};
use grok_build_plus_host::{PlusLiveIdentity, PlusSessionStore, bind_project_folder};

fn root(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "gbplus-responses-{label}-{}-{}",
        std::process::id(),
        crate::runtime::types::unix_time_millis()
    ))
}

fn response(id: &str, output: Vec<Value>) -> Value {
    let mut response = json!({"id":id,"status":"completed"});
    response["output"] = Value::Array(output);
    response
}

fn answer(text: &str) -> Value {
    json!({"type":"message","id":"message-fixture","status":"completed","role":"assistant","content":[{"type":"output_text","text":text,"annotations":[]}]})
}

#[test]
fn native_collaboration_uses_fixed_catalog_scope_privacy_and_exact_effect_identity() {
    use crate::runtime::collaboration_tools::{ParentTools, fixtures::Owner};
    for fail in [false, true] {
        let root = root(if fail { "child-fail" } else { "child-pass" });
        let workspace = root.join("workspace");
        std::fs::create_dir_all(&workspace).unwrap();
        let bound = bind_project_folder(&workspace).unwrap();
        let store = PlusSessionStore::from_state_root(root.join("store"));
        let context = AdapterContext {
            scope: crate::runtime::types::RuntimeInvocationScope::fixture(),
            extension_context: "",
            hooks: None,
            bound: &bound,
            store: &store,
        };
        let owner = std::sync::Arc::new(Owner {
            fail,
            ..Owner::default()
        });
        let external = ParentTools::new(None, owner.clone()).unwrap();
        let identity = PlusLiveIdentity::from_configured_key("fixture-never-sent").unwrap();
        let live = turn::NativeTurn {
            prompt: "child fixture",
            context: &context,
            identity: &identity,
            external: Some(&external),
            events: &|_| Ok(()),
            steering: &|_| Ok(Vec::new()),
        };
        let mut journal = ResponsesJournal::open(&root.join("journal")).unwrap();
        journal.require_transient_context().unwrap();
        journal.begin_turn(live.prompt, None).unwrap();
        let call = json!({"type":"function_call","call_id":"child-call","name":"app_agent_spawn","arguments":"{\"role\":\"explore\",\"prompt\":\"inspect\"}"});
        let mut requests = 0;
        let result = live
            .run(&mut journal, |request| {
                let body: Value = serde_json::from_str(&request.body).unwrap();
                assert_eq!(body["store"], false);
                assert_eq!(
                    body["tools"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .filter(|tool| tool["name"]
                            .as_str()
                            .is_some_and(|name| name.starts_with("app_agent_")))
                        .count(),
                    5
                );
                requests += 1;
                Ok(serde_json::to_vec(&if requests == 1 {
                    response("child-response", vec![call.clone()])
                } else {
                    response("child-finished", vec![answer("Done")])
                })
                .unwrap())
            })
            .unwrap();
        assert_eq!(requests, if fail { 1 } else { 2 });
        assert_eq!(owner.calls.lock().unwrap().len(), 1);
        assert!(owner.calls.lock().unwrap()[0].1);
        assert_eq!(
            matches!(result.outcome, AdapterTurnOutcome::Failed(_)),
            fail
        );
        assert!(
            !std::fs::read_to_string(root.join("journal").join(FILE))
                .unwrap()
                .contains("fixture-child-result")
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn native_hook_denial_prevents_proposal_and_external_dispatch_without_replay() {
    use crate::runtime::extension_tools::fixtures::Executor;
    for (external_call, uncertain) in [(false, false), (true, false), (false, true)] {
        let root = root(if uncertain {
            "hook-uncertain"
        } else if external_call {
            "hook-external"
        } else {
            "hook-proposal"
        });
        let workspace = root.join("workspace");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::write(workspace.join("file.txt"), "before").unwrap();
        let bound = bind_project_folder(&workspace).unwrap();
        let store = PlusSessionStore::from_state_root(root.join("store"));
        let hook = std::sync::Arc::new(crate::extensions::hooks::fixtures::Deny::default());
        let context = AdapterContext {
            scope: crate::runtime::types::RuntimeInvocationScope::fixture(),
            extension_context: "",
            bound: &bound,
            store: &store,
            hooks: Some(if uncertain {
                std::sync::Arc::new(crate::extensions::hooks::fixtures::Interrupt)
            } else {
                hook.clone()
            }),
        };
        let external = Executor::default();
        let identity = PlusLiveIdentity::from_configured_key("fixture-never-sent").unwrap();
        let live = turn::NativeTurn {
            prompt: "Run the reviewed fixture",
            context: &context,
            identity: &identity,
            external: Some(&external),
            events: &|_| Ok(()),
            steering: &|_| Ok(Vec::new()),
        };
        let call = json!({"type":"function_call","call_id":"hook-call",
            "name":if external_call { Executor::name() } else { "propose_write".into() },
            "arguments":if external_call { "{\"value\":\"test\"}" } else { "{\"path\":\"file.txt\",\"after\":\"after\"}" }});
        let mut journal = ResponsesJournal::open(&root.join("journal")).unwrap();
        journal.begin_turn(live.prompt, None).unwrap();
        let mut requests = 0;
        let result = live
            .run(&mut journal, |_| {
                requests += 1;
                Ok(serde_json::to_vec(&if requests == 1 {
                    response("hook-response", vec![call.clone()])
                } else {
                    response(
                        "hook-refusal-acknowledged",
                        vec![answer("The hook refused the call.")],
                    )
                })
                .unwrap())
            })
            .unwrap();
        if uncertain {
            assert!(matches!(result.outcome, AdapterTurnOutcome::Failed(_)));
        } else {
            assert_eq!(result.outcome, AdapterTurnOutcome::Completed);
        }
        assert!(result.pending.items.is_empty());
        assert_eq!(requests, if uncertain { 1 } else { 2 });
        assert_eq!(*hook.0.lock().unwrap(), usize::from(!uncertain));
        assert!(external.calls.lock().unwrap().is_empty());
        assert_eq!(
            std::fs::read_to_string(workspace.join("file.txt")).unwrap(),
            "before"
        );
        assert_eq!(
            journal
                .begin_turn("Continue without that tool.", None)
                .is_err(),
            uncertain
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn native_extension_calls_use_identified_dispatch_exact_output_and_transient_replay() {
    use crate::runtime::extension_tools::fixtures::Executor;
    let root = root("mcp-dispatch");
    let workspace = root.join("workspace");
    std::fs::create_dir_all(&workspace).unwrap();
    let bound = bind_project_folder(&workspace).unwrap();
    let store = PlusSessionStore::from_state_root(root.join("app-store"));
    let context = AdapterContext {
        scope: crate::runtime::types::RuntimeInvocationScope::fixture(),
        extension_context: "",
        hooks: None,
        bound: &bound,
        store: &store,
    };
    let external = Executor::default();
    let identity = PlusLiveIdentity::from_configured_key("fixture-never-sent").unwrap();
    let live = turn::NativeTurn {
        prompt: "Use the enabled fixture.",
        context: &context,
        identity: &identity,
        external: Some(&external),
        events: &|_| Ok(()),
        steering: &|_| Ok(Vec::new()),
    };
    let call = json!({"type":"function_call","call_id":"external-1","name":Executor::name(),
        "arguments":"{\"value\":\"TRANSIENT_MCP_ARGUMENT\"}"});
    let mut journal = ResponsesJournal::open(&root.join("journal")).unwrap();
    journal
        .begin_turn("Use the enabled fixture.", None)
        .unwrap();
    let mut requests = Vec::new();
    let completed = live
        .run(&mut journal, |request| {
            let request: Value = serde_json::from_str(request.json_body()).unwrap();
            assert_eq!(request["store"], false);
            let tools = request["tools"].as_array().unwrap();
            assert!(tools.iter().any(|tool| tool["name"] == Executor::name()));
            requests.push(request);
            Ok(serde_json::to_vec(&if requests.len() == 1 {
                response("extension-response-1", vec![call.clone()])
            } else {
                response("extension-response-2", vec![answer("Fixture completed.")])
            })
            .unwrap())
        })
        .unwrap();
    assert_eq!(completed.outcome, AdapterTurnOutcome::Completed);
    let calls = external.calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert!(calls[0].0.contains("extension-response-1"));
    assert!(calls[0].0.contains("external-1"));
    assert_eq!(calls[0].2["value"], "TRANSIENT_MCP_ARGUMENT");
    let output = requests[1]["input"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["type"] == "function_call_output")
        .unwrap();
    assert_eq!(output["call_id"], "external-1");
    let result: Value = serde_json::from_str(output["output"].as_str().unwrap()).unwrap();
    assert_eq!(result["content"][0]["text"], "TRANSIENT_MCP_RESULT");
    let disk = std::fs::read_to_string(root.join("journal").join(FILE)).unwrap();
    assert!(!disk.contains("TRANSIENT_MCP_ARGUMENT") && !disk.contains("TRANSIENT_MCP_RESULT"));
    TRANSIENT
        .get()
        .unwrap()
        .lock()
        .unwrap()
        .remove(&root.join("journal"));
    assert!(ResponsesJournal::open(&root.join("journal")).is_err());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn version_two_migration_preserves_source_and_version_three_refuses_copied_context() {
    let source = root("v2-scope");
    let foreign = root("foreign-scope");
    let mut journal = ResponsesJournal::open(&source).unwrap();
    journal
        .begin_turn("Remember the original workspace", None)
        .unwrap();
    journal.request_intent().unwrap();
    journal
        .complete_response(&response("scope-response", vec![answer("remembered")]))
        .unwrap();
    let exact = journal.input().to_vec();
    let mut legacy = serde_json::to_value(&journal.record).unwrap();
    legacy["schemaVersion"] = json!(2);
    legacy.as_object_mut().unwrap().remove("bindingDigest");
    legacy.as_object_mut().unwrap().remove("retiredCallIds");
    let bytes = serde_json::to_vec(&legacy).unwrap();
    OwnerStateRoot::new(&source)
        .file("responses-v2.json", MAX_JOURNAL_BYTES)
        .unwrap()
        .replace(&bytes)
        .unwrap();
    std::fs::remove_file(source.join(FILE)).unwrap();
    let restored = ResponsesJournal::open(&source).unwrap();
    assert_eq!(restored.input(), exact);
    assert_eq!(
        std::fs::read(source.join("responses-v2.json")).unwrap(),
        bytes
    );
    let bound = std::fs::read(source.join(FILE)).unwrap();
    OwnerStateRoot::new(&foreign)
        .file(FILE, MAX_JOURNAL_BYTES)
        .unwrap()
        .replace(&bound)
        .unwrap();
    assert!(ResponsesJournal::open(&foreign).is_err());
    assert_eq!(std::fs::read(foreign.join(FILE)).unwrap(), bound);
    std::fs::remove_dir_all(source).unwrap();
    std::fs::remove_dir_all(foreign).unwrap();
}

#[test]
fn every_incomplete_turn_cut_reopens_interrupted_without_repeating_effects() {
    for cut in ["user", "call", "effect", "compaction", "rejection"] {
        let root = root(cut);
        let mut journal = ResponsesJournal::open(&root).unwrap();
        journal
            .begin_turn("Do the requested action.", None)
            .unwrap();
        let call =
            json!({"type":"function_call","call_id":"call-cut","name":"list_dir","arguments":"{}"});
        match cut {
            "call" | "effect" => {
                journal.request_intent().unwrap();
                journal
                    .complete_response(&response("response-cut", vec![call.clone()]))
                    .unwrap();
                if cut == "effect" {
                    journal.effect_intent("response-cut", &call).unwrap();
                    journal
                        .complete_effect(
                            "response-cut",
                            &call,
                            "recorded result",
                            PendingFileSet::default(),
                        )
                        .unwrap();
                }
            }
            "compaction" => {
                journal.request_intent().unwrap();
                journal
                    .complete_compaction(
                        &json!({"output":[{"type":"compaction","encrypted_content":"opaque-cut"}]}),
                    )
                    .unwrap();
            }
            "rejection" => {
                journal.request_intent().unwrap();
                journal.rejected_request(429).unwrap();
            }
            _ => {}
        }
        let prefix = journal.input().to_vec();
        drop(journal);
        let mut recovered = ResponsesJournal::open(&root).unwrap();
        assert_eq!(recovered.input(), prefix);
        assert!(
            recovered.begin_turn("New request", None).is_err(),
            "cut {cut}"
        );
        assert!(recovered.request_intent().is_err(), "cut {cut}");
        let persisted: Value =
            serde_json::from_slice(&std::fs::read(root.join(FILE)).unwrap()).unwrap();
        assert_eq!(persisted["interrupted"], true);
        if cut == "effect" {
            // Reading a recorded result is allowed; dispatching a new effect is not.
            assert_eq!(
                recovered
                    .effect_intent("response-cut", &call)
                    .unwrap()
                    .unwrap()["output"],
                "recorded result"
            );
        } else {
            assert!(recovered.effect_intent("response-cut", &call).is_err());
        }
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn legacy_journal_migration_retains_source_and_classifies_unfinished_history() {
    for completed in [false, true] {
        let root = root(if completed {
            "legacy-complete"
        } else {
            "legacy-cut"
        });
        let mut journal = ResponsesJournal::open(&root).unwrap();
        journal.begin_turn("Remember this", None).unwrap();
        journal.request_intent().unwrap();
        let output = if completed {
            answer("Remembered")
        } else {
            json!({"type":"function_call","call_id":"legacy-call","name":"list_dir","arguments":"{}"})
        };
        journal
            .complete_response(&response("legacy-response", vec![output]))
            .unwrap();
        drop(journal);
        let mut value: Value =
            serde_json::from_slice(&std::fs::read(root.join(FILE)).unwrap()).unwrap();
        value["schemaVersion"] = json!(1);
        value.as_object_mut().unwrap().remove("turnActive");
        value.as_object_mut().unwrap().remove("bindingDigest");
        value.as_object_mut().unwrap().remove("retiredCallIds");
        let original = serde_json::to_vec(&value).unwrap();
        OwnerStateRoot::new(&root)
            .file("responses-v1.json", MAX_JOURNAL_BYTES)
            .unwrap()
            .replace(&original)
            .unwrap();
        std::fs::remove_file(root.join(FILE)).unwrap();
        let mut migrated = ResponsesJournal::open(&root).unwrap();
        assert_eq!(
            std::fs::read(root.join("responses-v1.json")).unwrap(),
            original
        );
        assert_eq!(migrated.record.schema_version, SCHEMA_VERSION);
        assert_eq!(migrated.begin_turn("Next", None).is_ok(), completed);
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn reset_issues_a_new_durable_context_identity_and_unknown_versions_remain_untouched() {
    let root = root("identity-reset");
    let first = ResponsesJournal::open(&root)
        .unwrap()
        .context_id()
        .to_owned();
    assert_eq!(ResponsesJournal::open(&root).unwrap().context_id(), first);
    ResponsesJournal::reset(&root).unwrap();
    assert_ne!(ResponsesJournal::open(&root).unwrap().context_id(), first);
    assert!(root.join("responses-before-reset.json").exists());
    let unknown = b"{\"schemaVersion\":999}";
    std::fs::write(root.join(FILE), unknown).unwrap();
    assert!(ResponsesJournal::open(&root).is_err());
    assert_eq!(std::fs::read(root.join(FILE)).unwrap(), unknown);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn second_turn_after_restart_replays_exact_reasoning_calls_and_outputs_without_effects() {
    let root = root("continuity");
    let workspace = root.join("workspace");
    std::fs::create_dir_all(&workspace).unwrap();
    let bound = bind_project_folder(&workspace).unwrap();
    let store = PlusSessionStore::from_state_root(root.join("app-store"));
    let context = AdapterContext {
        scope: crate::runtime::types::RuntimeInvocationScope::fixture(),
        extension_context: "",
        hooks: None,
        bound: &bound,
        store: &store,
    };
    let identity = PlusLiveIdentity::from_configured_key("fixture-never-sent").unwrap();
    let live = turn::NativeTurn {
        prompt: "Remember that the answer is 42.",
        context: &context,
        identity: &identity,
        external: None,
        events: &|_| Ok(()),
        steering: &|_| Ok(Vec::new()),
    };
    let call = json!({"type":"function_call","id":"fc-item","call_id":"call-1","name":"propose_write","arguments":"{\"path\":\"answer.txt\",\"after\":\"the answer is 42\"}","status":"completed"});
    let reasoning = json!({"type":"reasoning","id":"reasoning-1","encrypted_content":"opaque==preserve-exactly","summary":[]});
    let first_response = response("response-1", vec![reasoning.clone(), call.clone()]);
    let mut journal = ResponsesJournal::open(&root.join("journal")).unwrap();
    journal
        .begin_turn("Remember that the answer is 42.", None)
        .unwrap();
    let mut requests = Vec::new();
    let first = live
        .run(&mut journal, |request| {
            let request: Value = serde_json::from_str(request.json_body()).unwrap();
            assert_eq!(request["store"], false);
            assert!(request.get("previous_response_id").is_none());
            requests.push(request);
            let reply = if requests.len() == 1 {
                first_response.clone()
            } else {
                response("response-2", vec![answer("Staged for Accept.")])
            };
            Ok(serde_json::to_vec(&reply).unwrap())
        })
        .unwrap();
    assert_eq!(first.outcome, AdapterTurnOutcome::Completed);
    assert!(
        first
            .assistant_text
            .contains("You: Remember that the answer is 42.\n")
    );
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[1]["input"][1], reasoning);
    assert_eq!(requests[1]["input"][2], call);
    assert_eq!(requests[1]["input"][3]["type"], "function_call_output");
    assert_eq!(requests[1]["input"][3]["call_id"], "call-1");
    assert_eq!(first.pending.items.len(), 1);
    assert!(!workspace.join("answer.txt").exists());
    let recorded_output = journal.effect_intent("response-1", &call).unwrap().unwrap();
    assert_eq!(recorded_output, requests[1]["input"][3]);
    let prefix = journal.input().to_vec();
    drop(journal);
    let mut reopened = ResponsesJournal::open(&root.join("journal")).unwrap();
    assert_eq!(reopened.input(), prefix);
    reopened.begin_turn("What was the answer?", None).unwrap();
    let second = live
        .run(&mut reopened, |request| {
            let value: Value = serde_json::from_str(request.json_body()).unwrap();
            assert_eq!(&value["input"].as_array().unwrap()[..prefix.len()], prefix);
            Ok(serde_json::to_vec(&response("response-3", vec![answer("42")])).unwrap())
        })
        .unwrap();
    assert_eq!(second.outcome, AdapterTurnOutcome::Completed);
    assert!(second.pending.items.is_empty());
    assert!(!workspace.join("answer.txt").exists());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn uncertain_network_or_effect_intent_is_interrupted_and_cannot_repeat() {
    for effect_cut in [false, true] {
        let root = root(if effect_cut {
            "effect-cut"
        } else {
            "request-cut"
        });
        let mut journal = ResponsesJournal::open(&root).unwrap();
        journal.begin_turn("Do one action.", None).unwrap();
        journal.request_intent().unwrap();
        let call = json!({"type":"function_call","call_id":"call-1","name":"list_dir","arguments":"{\"path\":\".\"}"});
        if effect_cut {
            journal
                .complete_response(&response("response-1", vec![call.clone()]))
                .unwrap();
            assert!(
                journal
                    .effect_intent("response-1", &call)
                    .unwrap()
                    .is_none()
            );
        }
        drop(journal);
        let mut reopened = ResponsesJournal::open(&root).unwrap();
        assert!(
            reopened
                .begin_turn("Try again.", None)
                .unwrap_err()
                .contains("interrupted")
        );
        assert!(reopened.request_intent().is_err());
        if effect_cut {
            assert!(reopened.effect_intent("response-1", &call).is_err());
        }
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn websocket_loss_after_a_tool_result_interrupts_without_retry_or_effect_replay() {
    let root = root("websocket-loss");
    let workspace = root.join("workspace");
    std::fs::create_dir_all(&workspace).unwrap();
    let bound = bind_project_folder(&workspace).unwrap();
    let store = PlusSessionStore::from_state_root(root.join("app-store"));
    let context = AdapterContext {
        scope: crate::runtime::types::RuntimeInvocationScope::fixture(),
        extension_context: "",
        hooks: None,
        bound: &bound,
        store: &store,
    };
    let identity = PlusLiveIdentity::from_configured_key("fixture-never-sent").unwrap();
    let live = turn::NativeTurn {
        prompt: "Stage one proposal.",
        context: &context,
        identity: &identity,
        external: None,
        events: &|_| Ok(()),
        steering: &|_| Ok(Vec::new()),
    };
    let call = json!({"type":"function_call","call_id":"one-proposal","name":"propose_write","arguments":"{\"path\":\"answer.txt\",\"after\":\"42\"}"});
    let mut journal = ResponsesJournal::open(&root.join("journal")).unwrap();
    journal.begin_turn(live.prompt, None).unwrap();
    let mut submissions = 0;
    let result = live
        .run(&mut journal, |request| {
            submissions += 1;
            if submissions == 1 {
                return Ok(
                    serde_json::to_vec(&response("before-loss", vec![call.clone()])).unwrap(),
                );
            }
            let body: Value = serde_json::from_str(request.json_body()).unwrap();
            assert_eq!(
                body["input"].as_array().unwrap().last().unwrap()["call_id"],
                "one-proposal"
            );
            Err(grok_build_plus_host::PlusHostError::LiveTransport(
                "Native WebSocket closed or lost transport; submitted delivery is uncertain."
                    .into(),
            ))
        })
        .unwrap();
    assert_eq!(submissions, 2, "An uncertain submission cannot be retried");
    assert!(matches!(result.outcome, AdapterTurnOutcome::Failed(_)));
    assert_eq!(result.pending.items.len(), 1);
    assert!(!workspace.join("answer.txt").exists());
    let recorded = journal
        .effect_intent("before-loss", &call)
        .unwrap()
        .unwrap();
    drop(journal);
    let mut recovered = ResponsesJournal::open(&root.join("journal")).unwrap();
    assert_eq!(
        recovered.effect_intent("before-loss", &call).unwrap(),
        Some(recorded)
    );
    assert!(recovered.begin_turn("Do it again.", None).is_err());
    assert!(recovered.request_intent().is_err());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn high_power_items_and_following_reasoning_are_memory_only() {
    let root = root("transient");
    let mut journal = ResponsesJournal::open(&root).unwrap();
    journal
        .begin_turn("Use the explicitly granted browser.", None)
        .unwrap();
    journal.request_intent().unwrap();
    let call = json!({"type":"function_call","call_id":"call-1","name":"browser_type","arguments":"{\"text\":\"TRANSIENT_INPUT_SECRET\"}"});
    journal
        .complete_response(&response("response-1", vec![call.clone()]))
        .unwrap();
    journal.effect_intent("response-1", &call).unwrap();
    journal
        .complete_effect(
            "response-1",
            &call,
            "TRANSIENT_PAGE_CONTENT",
            PendingFileSet::default(),
        )
        .unwrap();
    journal.request_intent().unwrap();
    let reasoning = json!({"type":"reasoning","encrypted_content":"TAINTED_ENCRYPTED_CONTENT"});
    journal
        .complete_response(&response(
            "response-2",
            vec![reasoning, answer("TAINTED_ANSWER")],
        ))
        .unwrap();
    let disk = std::fs::read_to_string(root.join(FILE)).unwrap();
    for secret in [
        "TRANSIENT_INPUT_SECRET",
        "TRANSIENT_PAGE_CONTENT",
        "TAINTED_ENCRYPTED_CONTENT",
        "TAINTED_ANSWER",
    ] {
        assert!(!disk.contains(secret), "journal persisted {secret}");
    }
    assert_eq!(
        ResponsesJournal::open(&root).unwrap().input(),
        journal.input()
    );
    TRANSIENT.get().unwrap().lock().unwrap().remove(&root);
    assert!(
        ResponsesJournal::open(&root)
            .err()
            .unwrap()
            .contains("no longer available")
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn duplicate_call_ids_and_incomplete_completions_never_admit_effects() {
    let root = root("invalid-output");
    let mut journal = ResponsesJournal::open(&root).unwrap();
    journal.begin_turn("hello", None).unwrap();
    journal.request_intent().unwrap();
    let call = json!({"type":"function_call","call_id":"same","name":"list_dir","arguments":"{}"});
    assert!(
        journal
            .complete_response(&response("response-1", vec![call.clone(), call]))
            .is_err()
    );
    assert!(
        journal
            .complete_response(
                &json!({"id":"response-1","status":"incomplete","output":[answer("partial")]})
            )
            .is_err()
    );
    assert_eq!(journal.input().len(), 1);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn completed_call_identity_cannot_be_reused_by_another_response() {
    let root = root("cross-response-call");
    let mut journal = ResponsesJournal::open(&root).unwrap();
    journal.begin_turn("hello", None).unwrap();
    journal.request_intent().unwrap();
    let call = json!({"type":"function_call","call_id":"same","name":"list_dir","arguments":"{}"});
    journal
        .complete_response(&response("response-1", vec![call.clone()]))
        .unwrap();
    journal.effect_intent("response-1", &call).unwrap();
    journal
        .complete_effect(
            "response-1",
            &call,
            "recorded directory",
            PendingFileSet::default(),
        )
        .unwrap();
    journal.request_intent().unwrap();
    let before = journal.input().to_vec();
    assert!(
        journal
            .complete_response(&response("response-2", vec![call]))
            .is_err()
    );
    assert_eq!(journal.input(), before);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn default_model_metadata_admits_compaction_without_manual_selection() {
    let root = root("default-model-metadata");
    let mut journal = ResponsesJournal::open(&root).unwrap();
    let mut model = crate::runtime::models::ModelDescriptor {
        id: journal.model().into(),
        name: "Fixture".into(),
        context_window: Some(100_000),
        long_context_threshold: Some(70_000),
        accepts_images: None,
        reasoning_efforts: Vec::new(),
    };
    journal.refresh_model_metadata(&model).unwrap();
    assert_eq!(
        ResponsesJournal::open(&root).unwrap().record.compact_at,
        Some(70_000)
    );
    model.id = "grok-another".into();
    assert!(journal.refresh_model_metadata(&model).is_err());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn only_definitive_pre_output_rejections_retry() {
    for uncertain in [false, true] {
        let root = root(if uncertain {
            "no-uncertain-retry"
        } else {
            "rate-retry"
        });
        std::fs::create_dir_all(root.join("workspace")).unwrap();
        let bound = bind_project_folder(root.join("workspace")).unwrap();
        let store = PlusSessionStore::from_state_root(root.join("store"));
        let context = AdapterContext {
            scope: crate::runtime::types::RuntimeInvocationScope::fixture(),
            extension_context: "",
            hooks: None,
            bound: &bound,
            store: &store,
        };
        let identity = PlusLiveIdentity::from_configured_key("fixture-never-sent").unwrap();
        let live = turn::NativeTurn {
            prompt: "Hello",
            context: &context,
            identity: &identity,
            external: None,
            events: &|_| Ok(()),
            steering: &|_| Ok(Vec::new()),
        };
        let mut journal = ResponsesJournal::open(&root.join("journal")).unwrap();
        journal.begin_turn("Hello", None).unwrap();
        let mut attempts = 0;
        let result = live
            .run(&mut journal, |_| {
                attempts += 1;
                if uncertain {
                    return Err(grok_build_plus_host::PlusHostError::LiveTransport(
                        "connection lost after submission".into(),
                    ));
                }
                if attempts == 1 {
                    return Err(grok_build_plus_host::PlusHostError::LiveHttp { status: 429 });
                }
                Ok(
                    serde_json::to_vec(&response("response-retried", vec![answer("Hello")]))
                        .unwrap(),
                )
            })
            .unwrap();
        assert_eq!(attempts, if uncertain { 1 } else { 2 });
        assert_eq!(journal.record.interrupted, uncertain);
        assert_eq!(result.outcome == AdapterTurnOutcome::Completed, !uncertain);
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn native_child_roles_hide_tools_and_refuse_fabricated_calls_before_hooks() {
    use crate::runtime::extension_tools::fixtures::Restricted;
    use grok_build_plus_host::PlusRuntimeToolPolicy;
    let root = root("child-role");
    let workspace = root.join("workspace");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::write(workspace.join("file.txt"), "before").unwrap();
    let bound = bind_project_folder(&workspace).unwrap();
    let store = PlusSessionStore::from_state_root(root.join("store"));
    let hook = std::sync::Arc::new(crate::extensions::hooks::fixtures::Deny::default());
    let context = AdapterContext {
        scope: crate::runtime::types::RuntimeInvocationScope::fixture(),
        extension_context: "",
        bound: &bound,
        store: &store,
        hooks: Some(hook.clone()),
    };
    let external = Restricted(PlusRuntimeToolPolicy::Explore);
    let identity = PlusLiveIdentity::from_configured_key("fixture-never-sent").unwrap();
    let live = turn::NativeTurn {
        prompt: "Explore only",
        context: &context,
        identity: &identity,
        external: Some(&external),
        events: &|_| Ok(()),
        steering: &|_| Ok(Vec::new()),
    };
    let mut journal = ResponsesJournal::open(&root.join("journal")).unwrap();
    journal.begin_turn(live.prompt, None).unwrap();
    let mut requests = 0;
    let result=live.run(&mut journal,|request| {
        let body:Value=serde_json::from_str(&request.body).unwrap();
        let tools=body["tools"].as_array().unwrap();assert!(!tools.is_empty());
        assert!(tools.iter().all(|t| PlusRuntimeToolPolicy::Explore.allows(t["name"].as_str().unwrap())));
        requests+=1;
        Ok(serde_json::to_vec(&if requests==1 {
            response("child-forged-call",vec![json!({"type":"function_call","call_id":"child-proposal","name":"propose_write","arguments":"{\"path\":\"file.txt\",\"after\":\"after\"}"})])
        } else { response("child-refusal",vec![answer("The app refused that tool.")]) }).unwrap())
    }).unwrap();
    assert_eq!(result.outcome, AdapterTurnOutcome::Completed);
    assert!(result.pending.items.is_empty());
    assert_eq!(requests, 2);
    assert_eq!(*hook.0.lock().unwrap(), 0);
    assert_eq!(
        std::fs::read_to_string(workspace.join("file.txt")).unwrap(),
        "before"
    );
    std::fs::remove_dir_all(root).unwrap();
}

// Append to runtime/responses/tests.rs before applying the implementation fix.
#[test]
fn temporary_child_reply_has_no_secondary_session_store_transcript() {
    fn inspect(path: &std::path::Path, marker: &str) {
        for entry in std::fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                inspect(&path, marker);
            } else {
                assert!(
                    !String::from_utf8_lossy(&std::fs::read(&path).unwrap()).contains(marker),
                    "Temporary payload reached {}",
                    path.display()
                );
            }
        }
    }
    use crate::runtime::extension_tools::fixtures::Restricted;
    use grok_build_plus_host::PlusRuntimeToolPolicy;
    let root = root("temporary-child-reply");
    let workspace = root.join("workspace");
    let state = root.join("state");
    std::fs::create_dir_all(&workspace).unwrap();
    let bound = bind_project_folder(&workspace).unwrap();
    let store = PlusSessionStore::from_state_root(state.join("child-run-stores"));
    let context = AdapterContext {
        scope: crate::runtime::types::RuntimeInvocationScope::fixture(),
        extension_context: "",
        hooks: None,
        bound: &bound,
        store: &store,
    };
    let role = Restricted(PlusRuntimeToolPolicy::Explore);
    let identity = PlusLiveIdentity::from_configured_key("fixture-never-sent").unwrap();
    let marker = "TEMPORARY_CHILD_REPLY_CANARY";
    let live = turn::NativeTurn {
        prompt: marker,
        context: &context,
        identity: &identity,
        external: Some(&role),
        events: &|_| Ok(()),
        steering: &|_| Ok(Vec::new()),
    };
    let mut journal = ResponsesJournal::open(&state.join("journal")).unwrap();
    journal.require_transient_context().unwrap();
    journal.begin_turn(marker, None).unwrap();
    let turn = live
        .run(&mut journal, |_| {
            Ok(serde_json::to_vec(&response("private-reply", vec![answer(marker)])).unwrap())
        })
        .unwrap();
    assert!(turn.assistant_text.contains(marker));
    assert_eq!(turn.outcome, AdapterTurnOutcome::Completed);
    assert!(
        store.load_chat_transcript().unwrap().is_none(),
        "A child duplicated temporary output into its persistent app session store"
    );

    inspect(&state, marker);
    std::fs::remove_dir_all(root).unwrap();
}
#[test]
fn temporary_worker_proposals_survive_only_in_the_bounded_process_cache() {
    temporary_worker_case(false);
    temporary_worker_case(true);
}

fn temporary_worker_case(late: bool) {
    use crate::runtime::extension_tools::fixtures::Restricted;
    use grok_build_plus_host::PlusRuntimeToolPolicy;
    let root = root(if late {
        "temporary-worker-late-guidance"
    } else {
        "temporary-worker-proposal"
    });
    let workspace = root.join("workspace");
    let state = root.join("state");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::write(workspace.join("file.txt"), "before").unwrap();
    let bound = bind_project_folder(&workspace).unwrap();
    let store = PlusSessionStore::from_state_root(state.join("child-run-stores"));
    let context = AdapterContext {
        scope: crate::runtime::types::RuntimeInvocationScope::fixture(),
        extension_context: "",
        hooks: None,
        bound: &bound,
        store: &store,
    };
    let role = Restricted(PlusRuntimeToolPolicy::Worker);
    let identity = PlusLiveIdentity::from_configured_key("fixture-never-sent").unwrap();
    let marker = "TEMPORARY_CHILD_PROPOSAL_CANARY";
    let submitted = std::sync::atomic::AtomicBool::new(false);
    let observed = std::sync::atomic::AtomicBool::new(false);
    let steering = |action| {
        use crate::runtime::types::{RuntimeSteeringAction, RuntimeSteeringMessage};
        use std::sync::atomic::Ordering;
        match action {
            RuntimeSteeringAction::SubmitPending
                if late && !submitted.swap(true, Ordering::AcqRel) =>
            {
                Ok(vec![RuntimeSteeringMessage {
                    id: crate::contracts::SteerIntentId::new("late-child-guidance"),
                    text: marker.into(),
                    transient: true,
                }])
            }
            RuntimeSteeringAction::Record(
                _,
                crate::queue::SteerIntentState::ObservedInProviderHistory,
            ) => {
                observed.store(true, Ordering::Release);
                Ok(Vec::new())
            }
            _ => Ok(Vec::new()),
        }
    };
    let prompt = if late {
        "Inspect the workspace before receiving guidance."
    } else {
        marker
    };
    let live = turn::NativeTurn {
        prompt,
        context: &context,
        identity: &identity,
        external: Some(&role),
        events: &|_| Ok(()),
        steering: &steering,
    };
    let journal_root = state.join("journal");
    let mut journal = ResponsesJournal::open(&journal_root).unwrap();
    if !late {
        journal.require_transient_context().unwrap();
    }
    journal.begin_turn(prompt, None).unwrap();
    let call = json!({"type":"function_call","call_id":"private-proposal-call","name":"propose_write","arguments":json!({"path":"file.txt","after":marker}).to_string()});
    let mut requests = 0;
    let turn = live
        .run(&mut journal, |request| {
            requests += 1;
            if late && requests == 2 { assert!(request.body.contains(marker)); }
            Ok(serde_json::to_vec(&if late && requests == 1 {
                response("public-read", vec![json!({"type":"function_call","call_id":"public-read-call","name":"list_dir","arguments":"{}"})])
            } else if requests == if late { 2 } else { 1 } {
                response("private-proposal", vec![call.clone()])
            } else {
                response("private-completed", vec![answer("Proposed")])
            })
            .unwrap())
        })
        .unwrap();
    assert_eq!(turn.outcome, AdapterTurnOutcome::Completed);
    assert_eq!(requests, if late { 3 } else { 2 });
    if late {
        assert!(observed.load(std::sync::atomic::Ordering::Acquire));
    }
    assert_eq!(turn.pending.items.len(), 1);
    assert_temporary_proposal_state(&journal_root, &workspace, &store, &turn.pending);
    std::fs::remove_dir_all(root).unwrap();
}

fn assert_temporary_proposal_state(
    journal_root: &std::path::Path,
    workspace: &std::path::Path,
    store: &PlusSessionStore,
    pending: &PendingFileSet,
) {
    let disk: Value =
        serde_json::from_slice(&std::fs::read(journal_root.join(FILE)).unwrap()).unwrap();
    assert!(
        disk["pending"]["items"].as_array().unwrap().is_empty(),
        "A tainted provider journal retained proposal payload bytes"
    );
    let restored = ResponsesJournal::open(journal_root).unwrap();
    assert_eq!(
        serde_json::to_value(restored.pending()).unwrap(),
        serde_json::to_value(pending).unwrap()
    );
    assert_eq!(
        std::fs::read_to_string(workspace.join("file.txt")).unwrap(),
        "before"
    );
    assert!(store.load_chat_transcript().unwrap().is_none());
    TRANSIENT
        .get()
        .unwrap()
        .lock()
        .unwrap()
        .remove(journal_root);
    assert!(ResponsesJournal::open(journal_root).is_err());
}
