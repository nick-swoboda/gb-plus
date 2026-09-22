# Source attribution and adaptations

Copyright 2023–2026 SpaceXAI. Portions of the interpreter evaluation, control
tokens, host function registration and workflow call sequencing are adapted from
`crates/codegen/xai-workflow` at public source commit
`37949780c144e37df692e3d669051a21fec24f20` (source version 1.0.24), Apache-2.0.
GB Plus adaptations copyright 2026 GB Plus contributors, Apache-2.0.

This adaptation keeps the Rhai language, args scope, agent/parallel calls,
explicit complete/pause control, scratch/phase/log/budget interfaces, and bounded
host-call sequencing. It replaces the default package constructor, metadata
execution, unbounded channels, blocking reply receives, and provider-owned
options with explicit pure packages and one app-controlled host boundary.

The app must journal intent before effects and bound every host call. No generic
Git/command/template/telemetry adapter exists. Unsupported upstream calls refuse.
Unknown agent options, model/provider selection, arbitrary host paths and
provider-supplied resume identities are outside this admitted interface.
