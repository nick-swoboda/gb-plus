//! A child executor owns no machine, extension, credential-store or hook handles.
use grok_build_plus_host::{
    PlusExternalToolExecutor, PlusHostError, PlusRuntimeToolPolicy, PlusToolRequest,
};
pub(super) struct ChildTools(PlusRuntimeToolPolicy);
impl ChildTools {
    pub(super) fn new(policy: PlusRuntimeToolPolicy) -> Result<Self, String> {
        if policy == PlusRuntimeToolPolicy::Parent {
            return Err("A child executor cannot acquire the parent role.".into());
        }
        Ok(Self(policy))
    }
}
impl PlusExternalToolExecutor for ChildTools {
    fn tool_policy(&self) -> PlusRuntimeToolPolicy {
        self.0
    }
    fn execute(&self, _: &PlusToolRequest) -> Option<Result<String, PlusHostError>> {
        Some(Err(PlusHostError::Live(
            "This child owns no high-power dispatcher.".into(),
        )))
    }
}
