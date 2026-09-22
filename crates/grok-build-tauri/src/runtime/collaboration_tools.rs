//! Reserved app-owned tools share one typed authority boundary on both transports.
use super::types::{RuntimeEvent, RuntimeEventSink};

pub(super) struct ParentTools {
    external: Option<std::sync::Arc<dyn PlusExternalToolExecutor>>,
    owner: std::sync::Arc<dyn grok_build_plus_host::PlusCollaborationExecutor>,
}
impl ParentTools {
    pub(super) fn new(
        external: Option<std::sync::Arc<dyn PlusExternalToolExecutor>>,
        owner: std::sync::Arc<dyn grok_build_plus_host::PlusCollaborationExecutor>,
    ) -> Result<Self, String> {
        if super::extension_tools::policy(external.as_deref()) != PlusRuntimeToolPolicy::Parent {
            return Err("A child cannot wrap parent collaboration authority.".into());
        }
        Ok(Self { external, owner })
    }
}
impl PlusExternalToolExecutor for ParentTools {
    fn collaboration(&self) -> Option<&dyn grok_build_plus_host::PlusCollaborationExecutor> {
        Some(self.owner.as_ref())
    }
    fn execute(
        &self,
        request: &grok_build_plus_host::PlusToolRequest,
    ) -> Option<Result<String, grok_build_plus_host::PlusHostError>> {
        self.external
            .as_ref()
            .and_then(|external| external.execute(request))
    }
    fn extension_tools(
        &self,
    ) -> Result<Vec<grok_build_plus_host::PlusExtensionTool>, grok_build_plus_host::PlusHostError>
    {
        self.external
            .as_ref()
            .map_or_else(|| Ok(Vec::new()), |external| external.extension_tools())
    }
    fn execute_extension(
        &self,
        invocation: &str,
        name: &str,
        arguments: &Value,
    ) -> Option<Result<Value, grok_build_plus_host::PlusHostError>> {
        self.external
            .as_ref()
            .and_then(|external| external.execute_extension(invocation, name, arguments))
    }
}
use grok_build_plus_host::{
    PlusCollaborationCommand, PlusExternalToolExecutor, PlusRuntimeToolPolicy,
};
use serde_json::Value;

pub(super) fn binding(
    external: Option<&dyn PlusExternalToolExecutor>,
) -> Result<Option<String>, String> {
    let Some(owner) = external.and_then(PlusExternalToolExecutor::collaboration) else {
        return Ok(None);
    };
    if super::extension_tools::policy(external) != PlusRuntimeToolPolicy::Parent
        || owner.binding().is_empty()
        || owner.binding().len() > 256
        || owner.binding().chars().any(char::is_control)
    {
        return Err(
            "Child roles and unbound controllers cannot declare collaboration authority.".into(),
        );
    }
    Ok(Some(owner.binding().to_owned()))
}

pub(super) fn execute(
    external: Option<&dyn PlusExternalToolExecutor>,
    invocation: &str,
    name: &str,
    arguments: &Value,
    transient: bool,
    events: &RuntimeEventSink<'_>,
) -> Result<Value, String> {
    if binding(external)?.is_none() {
        return Err("App-owned Grok collaboration is disabled for this run.".into());
    }
    let command = PlusCollaborationCommand::parse(name, arguments)?;
    events(RuntimeEvent::ToolRequest {
        name: name.into(),
        detail: "App-owned Grok family operation requested.".into(),
    })?;
    let result = external
        .and_then(PlusExternalToolExecutor::collaboration)
        .ok_or("Collaboration owner disappeared.")?
        .execute(invocation, command, transient)?;
    if !result.is_object() || result.to_string().len() > 512 * 1024 {
        return Err("Collaboration result exceeded its object or byte bound.".into());
    }
    events(RuntimeEvent::ToolCompleted {
        name: name.into(),
        detail: "App family operation completed; the parent owns a model lease again.".into(),
    })?;
    Ok(result)
}

#[cfg(test)]
pub(crate) mod fixtures {
    use grok_build_plus_host::{PlusCollaborationCommand, PlusCollaborationExecutor};
    use serde_json::{Value, json};
    use std::sync::Mutex;
    #[derive(Default)]
    pub(crate) struct Owner {
        pub(crate) fail: bool,
        pub(crate) calls: Mutex<Vec<(String, bool)>>,
    }
    impl PlusCollaborationExecutor for Owner {
        fn binding(&self) -> &'static str {
            "fixture-run"
        }
        fn execute(
            &self,
            invocation: &str,
            _: PlusCollaborationCommand,
            transient: bool,
        ) -> Result<Value, String> {
            self.calls
                .lock()
                .unwrap()
                .push((invocation.into(), transient));
            if self.fail {
                Err("Fixture parent reacquisition failed.".into())
            } else {
                Ok(json!({"result":"fixture-child-result"}))
            }
        }
    }
}
