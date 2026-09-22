use super::*;
use serde_json::{Value, json};

fn bytes(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}

fn initialized() -> McpProtocol {
    initialized_version(MCP_PROTOCOL_VERSION)
}

fn initialized_version(version: &str) -> McpProtocol {
    let mut protocol = McpProtocol::default();
    let (identity, request) = protocol.begin(McpOperation::Initialize, json!({})).unwrap();
    let request: Value = serde_json::from_slice(&request).unwrap();
    assert_eq!(
        request["params"]["capabilities"],
        json!({"elicitation":{"form":{},"url":{}}})
    );
    let events = protocol
        .receive(&bytes(&json!({
            "jsonrpc":"2.0", "id":identity.as_str(),
            "result":{"protocolVersion":version,"capabilities":{"tools":{}},
                "serverInfo":{"name":"fixture","version":"1"}}
        })))
        .unwrap();
    assert!(matches!(
        events.as_slice(),
        [McpEvent::Send(_), McpEvent::Initialized]
    ));
    assert_eq!(protocol.negotiated_version().unwrap().as_str(), version);
    protocol
}

#[test]
fn negotiated_revision_controls_elicitation_without_open_ended_compatibility() {
    let url = bytes(
        &json!({"jsonrpc":"2.0","id":20,"method":"elicitation/create","params":{
            "mode":"url","message":"Authenticate with the fixture","url":"https://example.com/flow",
            "elicitationId":"fixture-flow"
        }}),
    );
    let mut june = initialized_version("2025-06-18");
    assert!(matches!(
        june.receive(&bytes(&elicitation(&json!(10))))
            .unwrap()
            .as_slice(),
        [McpEvent::Elicitation { .. }]
    ));
    assert!(june.receive(&url).is_err());
    let mut november = initialized_version("2025-11-25");
    assert!(matches!(
        november.receive(&url).unwrap().as_slice(),
        [McpEvent::Elicitation { .. }]
    ));
    for unsupported in ["2025-03-26", "2025-11-26", "2026-01-01", "latest"] {
        assert!(McpProtocolVersion::parse(unsupported).is_err());
    }
}

#[test]
fn request_ids_do_not_authorize_effects_or_collide_with_peer_requests() {
    let mut protocol = initialized();
    let (identity, _) = protocol
        .begin(
            McpOperation::CallTool,
            json!({"name":"lookup","arguments":{}}),
        )
        .unwrap();
    let ping = protocol
        .receive(&bytes(
            &json!({"jsonrpc":"2.0","id":identity.as_str(),"method":"ping"}),
        ))
        .unwrap();
    assert!(matches!(ping.as_slice(), [McpEvent::Send(_)]));
    let result = protocol
        .receive(&bytes(
            &json!({"jsonrpc":"2.0","id":identity.as_str(),"result":{"content":[]}}),
        ))
        .unwrap();
    assert!(matches!(
        result.as_slice(),
        [McpEvent::Result {
            operation: McpOperation::CallTool,
            ..
        }]
    ));
    assert!(protocol.interrupt().is_empty());
}

#[test]
fn sampling_and_roots_are_refused_without_calling_host_or_model() {
    let mut protocol = initialized();
    for (id, method) in [
        (1, "sampling/createMessage"),
        (2, "roots/list"),
        (3, "future/execute"),
    ] {
        let events = protocol
            .receive(&bytes(
                &json!({"jsonrpc":"2.0","id":id,"method":method,"params":{"projectId":"foreign"}}),
            ))
            .unwrap();
        let [McpEvent::Send(answer)] = events.as_slice() else {
            panic!("must refuse unsupported request")
        };
        let answer: Value = serde_json::from_slice(answer).unwrap();
        assert_eq!(answer["error"]["code"], -32601);
    }
}

#[test]
fn malformed_response_keeps_pending_delivery_uncertain_and_closes_connection() {
    let mut protocol = initialized();
    let (identity, _) = protocol
        .begin(
            McpOperation::CallTool,
            json!({"name":"write","arguments":{}}),
        )
        .unwrap();
    assert!(protocol.receive(&bytes(&json!({"jsonrpc":"2.0","id":identity.as_str(),"result":{},"error":{"code":1,"message":"x"}}))).is_err());
    assert_eq!(protocol.interrupt(), vec![identity]);
    assert!(protocol.begin(McpOperation::Ping, json!({})).is_err());
}

#[test]
fn unmatched_and_duplicate_responses_are_not_completed_requests() {
    let mut protocol = initialized();
    let (identity, _) = protocol.begin(McpOperation::Ping, json!({})).unwrap();
    let response = bytes(&json!({"jsonrpc":"2.0","id":identity.as_str(),"result":{}}));
    protocol.receive(&response).unwrap();
    assert!(protocol.receive(&response).is_err());
    let mut protocol = initialized();
    assert!(
        protocol
            .receive(&bytes(
                &json!({"jsonrpc":"2.0","id":"other-connection","result":{}})
            ))
            .is_err()
    );
}

fn elicitation(id: &Value) -> Value {
    json!({"jsonrpc":"2.0","id":id,"method":"elicitation/create","params":{
        "message":"Choose a fixture label","requestedSchema":{"type":"object","properties":{"label":{"type":"string"}}}
    }})
}

#[test]
fn duplicate_elicitation_never_prompts_twice_and_replies_reuse_exact_answer() {
    let mut protocol = initialized();
    let request = bytes(&elicitation(&json!(77)));
    assert!(matches!(
        protocol.receive(&request).unwrap().as_slice(),
        [McpEvent::Elicitation { .. }]
    ));
    assert!(matches!(
        protocol.receive(&request).unwrap().as_slice(),
        [McpEvent::Observation]
    ));
    let answer = protocol
        .answer_elicitation(&json!(77), &json!({"action":"decline"}))
        .unwrap();
    let events = protocol.receive(&request).unwrap();
    let [McpEvent::Send(repeated)] = events.as_slice() else {
        panic!("exact cached answer expected")
    };
    assert_eq!(&answer, repeated);
    assert!(
        protocol
            .answer_elicitation(&json!(77), &json!({"action":"accept"}))
            .is_err()
    );
    let mut changed = elicitation(&json!(77));
    changed["params"]["message"] = json!("changed");
    assert!(protocol.receive(&bytes(&changed)).is_err());
}

#[test]
fn cancellation_is_directional_and_does_not_claim_a_tool_effect_was_undone() {
    let mut protocol = initialized();
    let (identity, _) = protocol
        .begin(
            McpOperation::CallTool,
            json!({"name":"mutate","arguments":{}}),
        )
        .unwrap();
    protocol
        .receive(&bytes(&elicitation(&json!(identity.as_str()))))
        .unwrap();
    let events = protocol.receive(&bytes(&json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":identity.as_str()}}))).unwrap();
    assert!(matches!(
        events.as_slice(),
        [McpEvent::ElicitationCancelled(_)]
    ));
    assert!(
        protocol
            .answer_elicitation(&json!(identity.as_str()), &json!({"action":"accept"}))
            .is_err()
    );
    let cancelled: Value = serde_json::from_slice(&protocol.cancel(&identity).unwrap()).unwrap();
    assert_eq!(cancelled["params"]["requestId"], identity.as_str());
    assert_eq!(protocol.interrupt(), vec![identity]);
}

#[test]
fn lifecycle_and_frame_bounds_refuse_before_dispatch() {
    let mut protocol = McpProtocol::default();
    assert!(
        protocol
            .begin(McpOperation::CallTool, json!({"name":"x","arguments":{}}))
            .is_err()
    );
    assert!(
        protocol
            .begin(
                McpOperation::Initialize,
                json!({"capabilities":{"sampling":{}}})
            )
            .is_err()
    );
    let (identity, _) = protocol.begin(McpOperation::Initialize, json!({})).unwrap();
    assert!(protocol.receive(&bytes(&json!({"jsonrpc":"2.0","id":identity.as_str(),"result":{"protocolVersion":"other","capabilities":{"tools":{}},"serverInfo":{"name":"x","version":"1"}}}))).is_err());
    let mut protocol = initialized();
    assert!(
        protocol
            .receive(&vec![b' '; MCP_MAX_FRAME_BYTES + 1])
            .is_err()
    );
}

#[test]
fn request_bound_keeps_cancellation_capacity_and_unknown_notifications_are_inert() {
    let mut protocol = initialized();
    let mut ids = Vec::new();
    for _ in 0..8 {
        ids.push(protocol.begin(McpOperation::Ping, json!({})).unwrap().0);
    }
    assert!(protocol.begin(McpOperation::Ping, json!({})).is_err());
    protocol.cancel(&ids[0]).unwrap();
    let events = protocol
        .receive(&bytes(
            &json!({"jsonrpc":"2.0","method":"future/execute","params":{"command":"never runs"}}),
        ))
        .unwrap();
    assert!(matches!(events.as_slice(), [McpEvent::Observation]));
    assert_eq!(protocol.interrupt().len(), 8);
}

fn tool(schema_type: &str) -> Value {
    json!({"name":"read_file","description":"Untrusted server tool", "inputSchema":{"type":"object","properties":{"value":{"type":schema_type}}},"annotations":{"readOnlyHint":true}})
}

fn catalog(project: &str, server: char, entry: &Value) -> McpCatalog {
    let mut catalog = McpCatalog::new(
        crate::ProjectId::new(project),
        server.to_string().repeat(64),
    )
    .unwrap();
    catalog.push_page(None, &json!({"tools":[entry]})).unwrap();
    catalog
}

#[test]
fn catalog_fingerprint_binds_project_server_schema_and_annotations() {
    let first = catalog("project-a", 'a', &tool("string"));
    let tool_a = first.tools().unwrap().next().unwrap();
    assert!(tool_a.app_name().starts_with("gbext_"));
    assert!(tool_a.app_name().len() <= 64);
    assert_ne!(tool_a.app_name(), "read_file");
    assert!(tool_a.claimed_read_only()); // descriptive only, never a permission.
    for other in [
        catalog("project-b", 'a', &tool("string")),
        catalog("project-a", 'b', &tool("string")),
        catalog("project-a", 'a', &tool("number")),
    ] {
        assert_ne!(
            tool_a.fingerprint(),
            other.tools().unwrap().next().unwrap().fingerprint()
        );
    }
    let mut changed = tool("string");
    changed["annotations"]["readOnlyHint"] = json!(false);
    assert_ne!(
        tool_a.fingerprint(),
        catalog("project-a", 'a', &changed)
            .tools()
            .unwrap()
            .next()
            .unwrap()
            .fingerprint()
    );
}

#[test]
fn catalog_pages_cannot_repeat_or_offer_partial_authority() {
    let mut catalog = McpCatalog::new(crate::ProjectId::new("project"), "a".repeat(64)).unwrap();
    assert!(catalog.tools().is_err());
    assert_eq!(
        catalog
            .push_page(None, &json!({"tools":[tool("string")],"nextCursor":"two"}))
            .unwrap(),
        Some("two".into())
    );
    assert!(catalog.tools().is_err());
    assert!(
        catalog
            .push_page(Some("two"), &json!({"tools":[],"nextCursor":"two"}))
            .is_err()
    );
    assert!(catalog.tools().is_err());
    assert!(
        catalog
            .push_page(Some("two"), &json!({"tools":[]}))
            .is_err()
    );
}

#[test]
fn catalog_change_duplicates_and_required_tasks_refuse_admission() {
    let mut catalog = catalog("project", 'a', &tool("string"));
    let name = catalog
        .tools()
        .unwrap()
        .next()
        .unwrap()
        .app_name()
        .to_owned();
    assert!(catalog.resolve(&name).is_ok());
    assert!(catalog.resolve("read_file").is_err());
    catalog.invalidate();
    assert!(catalog.resolve(&name).is_err());
    let mut catalog = McpCatalog::new(crate::ProjectId::new("project"), "a".repeat(64)).unwrap();
    assert!(
        catalog
            .push_page(None, &json!({"tools":[tool("string"),tool("string")]}))
            .is_err()
    );
    assert!(catalog.tools().is_err());
    let mut catalog = McpCatalog::new(crate::ProjectId::new("project"), "a".repeat(64)).unwrap();
    let mut entry = tool("string");
    entry["execution"] = json!({"taskSupport":"required"});
    assert!(catalog.push_page(None, &json!({"tools":[entry]})).is_err());
}

#[test]
fn diagnostic_debug_omits_tool_payloads_and_peer_input() {
    let mut protocol = initialized();
    let mut request = elicitation(&json!("PRIVATE-PEER-ID"));
    request["params"]["message"] = json!("PRIVATE-FORM-CONTENT");
    let events = protocol.receive(&bytes(&request)).unwrap();
    let diagnostic = format!("{events:?}");
    assert!(!diagnostic.contains("PRIVATE-"));
    let mut entry = tool("string");
    entry["description"] = json!("PRIVATE-SCHEMA-CONTENT");
    let catalog = catalog("project", 'a', &entry);
    assert!(!format!("{:?}", catalog.tools().unwrap().next().unwrap()).contains("PRIVATE-"));
}

#[test]
fn unknown_tool_results_and_nontext_elicitation_modes_fail_closed() {
    let mut protocol = initialized();
    let (identity, _) = protocol
        .begin(
            McpOperation::CallTool,
            json!({"name":"tool","arguments":{}}),
        )
        .unwrap();
    assert!(protocol.receive(&bytes(&json!({"jsonrpc":"2.0","id":identity.as_str(),"result":{"content":[{"type":"execute","command":"never runs"}]}}))).is_err());
    assert_eq!(protocol.interrupt(), vec![identity]);
    for value in [json!(false), json!(null), json!(3)] {
        let mut protocol = initialized();
        let mut request = elicitation(&json!(1));
        request["params"]["mode"] = value;
        assert!(protocol.receive(&bytes(&request)).is_err());
    }
}
