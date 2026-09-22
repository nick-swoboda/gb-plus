use super::*;
use crate::ProjectId;
use serde_json::{Value, json};

fn fixture(project: &str, server: char, property: &str) -> McpCatalog {
    let mut catalog =
        McpCatalog::new(ProjectId::new(project), server.to_string().repeat(64)).unwrap();
    catalog.push_page(None, &json!({"tools":[{
        "name":"read_file", "inputSchema":{"type":"object","properties":{"value":{"type":property}}},
        "annotations":{"readOnlyHint":true}
    }]})).unwrap();
    catalog
}

fn review(catalog: &McpCatalog, revision: u64, policy: McpToolPolicy) -> McpPermissionReview<'_> {
    let tool = catalog.tools().unwrap().next().unwrap();
    McpPermissionReview {
        revision,
        app_name: tool.app_name(),
        fingerprint: tool.fingerprint(),
        policy,
        class: McpEffectClass::ReviewedReadOnly,
    }
}

#[test]
fn legacy_names_migrate_denials_but_reusable_grants_need_new_review() {
    let catalog = fixture("project-a", 'a', "string");
    let tool = catalog.tools().unwrap().next().unwrap();
    assert_eq!(tool.app_name().len(), 54);
    assert!(format!("gbplus__{}", tool.app_name()).len() <= 64);
    let legacy_name = format!("{}deadbeef", tool.app_name());
    let mut value = json!({"version":1,"project":"project-a","revision":7,"policies":{
        &legacy_name:{"fingerprint":tool.fingerprint(),"policy":"deny"}
    }});
    let bytes = serde_json::to_vec(&value).unwrap();
    let migrated = McpPermissionBook::restore(catalog.project(), Some(&bytes)).unwrap();
    assert_eq!(migrated.version, 2);
    assert_eq!(migrated.revision(), 8);
    assert_eq!(
        migrated
            .decision(&catalog, tool.app_name(), McpEffectClass::Unclassified)
            .unwrap(),
        McpPermissionDecision::Denied
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&bytes).unwrap()["version"],
        1
    );
    value["policies"][&legacy_name]["policy"] = json!("allowReviewedReadOnly");
    let migrated = McpPermissionBook::restore(
        catalog.project(),
        Some(&serde_json::to_vec(&value).unwrap()),
    )
    .unwrap();
    assert_eq!(
        migrated
            .decision(&catalog, tool.app_name(), McpEffectClass::ReviewedReadOnly)
            .unwrap(),
        McpPermissionDecision::ApprovalRequired
    );
    value["policies"][format!("{}aaaaaaaa", tool.app_name())] =
        value["policies"][&legacy_name].clone();
    assert!(
        McpPermissionBook::restore(
            catalog.project(),
            Some(&serde_json::to_vec(&value).unwrap())
        )
        .is_err()
    );
}

#[test]
fn claims_never_grant_and_mutating_or_unclassified_effects_need_individual_approval() {
    let catalog = fixture("project-a", 'a', "string");
    let tool = catalog.tools().unwrap().next().unwrap();
    assert!(tool.claimed_read_only());
    let mut book = McpPermissionBook::restore(&ProjectId::new("project-a"), None).unwrap();
    for class in [
        McpEffectClass::ReviewedReadOnly,
        McpEffectClass::Mutating,
        McpEffectClass::Unclassified,
    ] {
        assert_eq!(
            book.decision(&catalog, tool.app_name(), class).unwrap(),
            McpPermissionDecision::ApprovalRequired
        );
    }
    for class in [McpEffectClass::Mutating, McpEffectClass::Unclassified] {
        let mut change = review(&catalog, 0, McpToolPolicy::AllowReviewedReadOnly);
        change.class = class;
        assert!(
            book.change(&catalog, &change, &mut |_| panic!(
                "must refuse before persistence"
            ))
            .is_err()
        );
    }
    let mut persisted = Vec::new();
    book.change(
        &catalog,
        &review(&catalog, 0, McpToolPolicy::AllowReviewedReadOnly),
        &mut |bytes| {
            persisted = bytes.to_vec();
            Ok(())
        },
    )
    .unwrap();
    let restored =
        McpPermissionBook::restore(&ProjectId::new("project-a"), Some(&persisted)).unwrap();
    assert_eq!(
        restored
            .decision(&catalog, tool.app_name(), McpEffectClass::ReviewedReadOnly)
            .unwrap(),
        McpPermissionDecision::AllowedReadOnly
    );
    for class in [McpEffectClass::Mutating, McpEffectClass::Unclassified] {
        assert_eq!(
            restored.decision(&catalog, tool.app_name(), class).unwrap(),
            McpPermissionDecision::ApprovalRequired
        );
    }
}

#[test]
fn server_project_schema_and_catalog_lifetime_are_all_binding_boundaries() {
    let mut catalog = fixture("project-a", 'a', "string");
    let mut book = McpPermissionBook::restore(&ProjectId::new("project-a"), None).unwrap();
    book.change(
        &catalog,
        &review(&catalog, 0, McpToolPolicy::AllowReviewedReadOnly),
        &mut |_| Ok(()),
    )
    .unwrap();
    let name = catalog
        .tools()
        .unwrap()
        .next()
        .unwrap()
        .app_name()
        .to_owned();
    for other in [
        fixture("project-a", 'b', "string"),
        fixture("project-a", 'a', "number"),
    ] {
        let other_name = other.tools().unwrap().next().unwrap().app_name();
        assert_eq!(
            book.decision(&other, other_name, McpEffectClass::ReviewedReadOnly)
                .unwrap(),
            McpPermissionDecision::ApprovalRequired
        );
    }
    let foreign = fixture("project-b", 'a', "string");
    assert!(
        book.decision(
            &foreign,
            foreign.tools().unwrap().next().unwrap().app_name(),
            McpEffectClass::ReviewedReadOnly
        )
        .is_err()
    );
    catalog.invalidate();
    assert!(
        book.decision(&catalog, &name, McpEffectClass::ReviewedReadOnly)
            .is_err()
    );
}

#[test]
fn failed_durable_commit_and_stale_review_never_change_live_authority() {
    let catalog = fixture("project-a", 'a', "string");
    let mut book = McpPermissionBook::restore(&ProjectId::new("project-a"), None).unwrap();
    let change = review(&catalog, 0, McpToolPolicy::AllowReviewedReadOnly);
    assert!(
        book.change(&catalog, &change, &mut |_| Err(
            "injected write failure".into()
        ))
        .is_err()
    );
    assert_eq!(book.revision(), 0);
    assert_eq!(
        book.decision(&catalog, change.app_name, change.class)
            .unwrap(),
        McpPermissionDecision::ApprovalRequired
    );
    book.change(&catalog, &change, &mut |_| Ok(())).unwrap();
    assert!(
        book.change(&catalog, &change, &mut |_| panic!("stale UI cannot write"))
            .is_err()
    );
    let mut wrong = review(&catalog, 1, McpToolPolicy::Deny);
    let foreign_fingerprint = "f".repeat(64);
    wrong.fingerprint = &foreign_fingerprint;
    assert!(
        book.change(&catalog, &wrong, &mut |_| panic!(
            "changed preview cannot write"
        ))
        .is_err()
    );
    book.change(
        &catalog,
        &review(&catalog, 1, McpToolPolicy::Deny),
        &mut |_| Ok(()),
    )
    .unwrap();
    assert_eq!(
        book.decision(&catalog, change.app_name, change.class)
            .unwrap(),
        McpPermissionDecision::Denied
    );
    book.change(
        &catalog,
        &review(&catalog, 2, McpToolPolicy::Ask),
        &mut |_| Ok(()),
    )
    .unwrap();
    assert_eq!(
        book.decision(&catalog, change.app_name, change.class)
            .unwrap(),
        McpPermissionDecision::ApprovalRequired
    );
}

#[test]
fn corrupt_unknown_and_cross_project_permission_records_are_not_reset() {
    let project = ProjectId::new("project-a");
    let catalog = fixture("project-a", 'a', "string");
    let mut book = McpPermissionBook::restore(&project, None).unwrap();
    let mut bytes = Vec::new();
    book.change(
        &catalog,
        &review(&catalog, 0, McpToolPolicy::Deny),
        &mut |value| {
            bytes = value.to_vec();
            Ok(())
        },
    )
    .unwrap();
    assert!(McpPermissionBook::restore(&ProjectId::new("project-b"), Some(&bytes)).is_err());
    let mut future: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    future["version"] = json!(65535);
    assert!(
        McpPermissionBook::restore(&project, Some(&serde_json::to_vec(&future).unwrap())).is_err()
    );
    for invalid in [b"{".to_vec(), vec![b' '; MCP_MAX_PERMISSION_BYTES + 1]] {
        assert!(McpPermissionBook::restore(&project, Some(&invalid)).is_err());
    }
    assert!(McpPermissionBook::restore(&project, Some(&bytes)).is_ok());
}
