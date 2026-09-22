//! App-issued role attenuation shared by declaration and execution boundaries.
use crate::{PlusToolName, ToolClass};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
/// Tool ceiling for an app-issued execution role. This never grants workspace authority.
pub enum PlusRuntimeToolPolicy {
    #[default]
    /// Existing top-level app execution; normal grants still apply.
    Parent,
    /// Workspace reads only.
    Explore,
    /// Workspace reads only, with planning instructions owned by the app.
    Plan,
    /// Workspace reads and staged proposals; no machine or extension authority.
    Worker,
}

impl PlusRuntimeToolPolicy {
    /// Whether this role permits the tool class, independently of other checks.
    #[must_use]
    pub fn allows(self, name: &str) -> bool {
        if self == Self::Parent {
            return true;
        }
        let Some(tool) = PlusToolName::from_wire(name) else {
            return false;
        };
        match tool.descriptor().class {
            ToolClass::WorkspaceRead => true,
            ToolClass::Proposal => self == Self::Worker,
            _ => false,
        }
    }

    /// Remove tools outside this role before a provider sees its catalog.
    ///
    /// # Errors
    /// Refuses malformed or foreign declarations in a child catalog.
    pub fn restrict_declarations(self, tools: &mut Vec<Value>) -> Result<(), String> {
        if self == Self::Parent {
            return Ok(());
        }
        for tool in tools.iter() {
            let name = tool
                .get("name")
                .and_then(Value::as_str)
                .ok_or("App tool declaration omitted its typed name.")?;
            if PlusToolName::from_wire(name).is_none() {
                return Err("Child catalog cannot contain extension or delegation tools.".into());
            }
        }
        tools.retain(|tool| {
            tool.get("name")
                .and_then(Value::as_str)
                .is_some_and(|name| self.allows(name))
        });
        Ok(())
    }

    /// Return an authoritative refusal for tools outside this role.
    #[must_use]
    pub fn refusal(self, name: &str) -> Option<&'static str> {
        (!self.allows(name)).then_some("This child role has no authority for that tool. Only its app-issued role catalog is available.")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PLUS_TOOL_DESCRIPTORS;
    use serde_json::json;

    struct Restricted(PlusRuntimeToolPolicy);
    impl crate::PlusExternalToolExecutor for Restricted {
        fn tool_policy(&self) -> PlusRuntimeToolPolicy {
            self.0
        }
        fn execute(
            &self,
            _: &crate::PlusToolRequest,
        ) -> Option<Result<String, crate::PlusHostError>> {
            panic!("forbidden child dispatch")
        }
    }
    #[test]
    fn low_level_dispatch_refuses_child_effects_and_keeps_worker_proposals_staged() {
        let root = std::env::temp_dir().join(format!(
            "gbplus-role-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("file.txt"), "before").unwrap();
        let bound = crate::bind_project_folder(&root).unwrap();
        let proposal = crate::plus_tool_request_from_name_and_args(
            "propose_write",
            r#"{"path":"file.txt","after":"after"}"#,
        )
        .unwrap();
        let browser = crate::plus_tool_request_from_name_and_args("browser_inspect", "{}").unwrap();
        for role in [
            PlusRuntimeToolPolicy::Explore,
            PlusRuntimeToolPolicy::Plan,
            PlusRuntimeToolPolicy::Worker,
        ] {
            let report = crate::run_plus_tool_loop_on_store_in_mode_observed_external(
                &bound,
                None,
                &[proposal.clone(), browser.clone()],
                crate::PlusSessionMode::Agent,
                &mut |_| Ok(()),
                Some(&Restricted(role)),
            )
            .unwrap();
            assert_eq!(report.steps[0].ok, role == PlusRuntimeToolPolicy::Worker);
            assert!(!report.steps[1].ok);
            assert_eq!(
                report.pending_set.items.is_empty(),
                role != PlusRuntimeToolPolicy::Worker
            );
            assert_eq!(
                std::fs::read_to_string(root.join("file.txt")).unwrap(),
                "before"
            );
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn each_catalog_entry_obeys_the_role_and_unclassified_tools_refuse() {
        for role in [
            PlusRuntimeToolPolicy::Explore,
            PlusRuntimeToolPolicy::Plan,
            PlusRuntimeToolPolicy::Worker,
        ] {
            let mut tools = PLUS_TOOL_DESCRIPTORS
                .iter()
                .map(|d| json!({"name":d.wire_name}))
                .collect::<Vec<_>>();
            role.restrict_declarations(&mut tools).unwrap();
            for descriptor in PLUS_TOOL_DESCRIPTORS {
                let expected = descriptor.class == ToolClass::WorkspaceRead
                    || (role == PlusRuntimeToolPolicy::Worker
                        && descriptor.class == ToolClass::Proposal);
                assert_eq!(role.allows(descriptor.wire_name), expected);
                assert_eq!(
                    tools.iter().any(|t| t["name"] == descriptor.wire_name),
                    expected
                );
                assert_eq!(role.refusal(descriptor.wire_name).is_none(), expected);
            }
            for name in [
                "gbagent_spawn",
                "gbext_fake",
                "run_contained",
                "desktop_click",
                "browser_inspect",
                "todo_write",
                "unknown",
            ] {
                assert!(!role.allows(name), "{role:?}: {name}");
            }
        }
    }

    #[test]
    fn legitimate_workspace_reads_and_worker_proposals_remain_available() {
        for role in [
            PlusRuntimeToolPolicy::Explore,
            PlusRuntimeToolPolicy::Plan,
            PlusRuntimeToolPolicy::Worker,
        ] {
            for name in ["list_dir", "read_file", "grep", "glob"] {
                assert!(role.allows(name));
            }
        }
        for name in ["propose_write", "propose_replace"] {
            assert!(PlusRuntimeToolPolicy::Worker.allows(name));
            assert!(!PlusRuntimeToolPolicy::Explore.allows(name));
            assert!(!PlusRuntimeToolPolicy::Plan.allows(name));
        }
    }
}
