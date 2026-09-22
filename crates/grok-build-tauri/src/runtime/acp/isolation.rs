//! App-owned disk configuration. No user CLI configuration is copied here.

pub(super) const ACP_CONFIG: &str = r#"[permission]
allow = ["MCPTool(gbplus__*)"]

[features]
telemetry = false
session_recap = false
turn_summary = false
title_refresh = false
goal_summary = false
auto_wake = false
backend_tools = false
feedback = false
voice_mode = false
lsp_tools = false
web_fetch = false

[telemetry]
trace_upload = false
mixpanel_enabled = false
otel_enabled = false

[subagents]
enabled = false

[workflows]
enabled = false

[memory]
enabled = false

[plugins]
paths = []
enabled = []

[compat.claude]
skills = false
rules = false
agents = false
mcps = false
hooks = false
sessions = false

[compat.cursor]
skills = false
rules = false
agents = false
mcps = false
hooks = false
sessions = false

[compat.codex]
sessions = false
"#;
