//! Local configurations identify native bytes in the already-reviewed capsule.

use grok_build_plus_host::{ServiceArchitecture, service_elf_architecture};
use serde::Serialize;
use serde_json::Value;

use super::Bundle;

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LocalSpec {
    pub(crate) content: String,
    pub(crate) command: String,
    pub(crate) arguments: Vec<String>,
    pub(crate) executable_digest: grok_build_plus_host::Digest,
    pub(crate) executable_bytes: u64,
    pub(crate) architecture: ServiceArchitecture,
}

pub(in crate::extensions) fn parse(
    config: &Value,
    content: &str,
    bundle: &Bundle,
) -> Result<Option<LocalSpec>, String> {
    if config.get("type").and_then(Value::as_str) != Some("stdio") {
        return Ok(None);
    }
    let fields = config
        .as_object()
        .ok_or("Local MCP configuration is not an object.")?;
    if fields
        .keys()
        .any(|key| !matches!(key.as_str(), "type" | "command" | "args"))
    {
        return Err("Contained MCP accepts a bundled native executable and literal arguments. Host paths, runtime downloads, account settings and environment expansion are unavailable.".into());
    }
    let command = config
        .get("command")
        .and_then(Value::as_str)
        .ok_or("Contained MCP requires a bundled command path.")?;
    super::super::super::content::validate_path(command)?;
    // The complete mounted bundle must be eligible; silently removing a manifest
    // file would change the reviewed installation's meaning.
    if bundle.files.keys().any(|path| {
        path.split('/')
            .any(|part| !grok_build_plus_host::service_path_component_allowed(part))
    }) {
        return Err("This extension contains files unavailable to a contained service.".into());
    }
    let image = bundle
        .files
        .get(command)
        .ok_or("The contained MCP executable is absent from the frozen bundle.")?;
    if !image.executable {
        return Err("The frozen MCP executable does not have executable status.".into());
    }
    let architecture = service_elf_architecture(&image.bytes)?;
    let arguments = match config.get("args") {
        None => Vec::new(),
        Some(Value::Array(values)) if values.len() <= 32 => values
            .iter()
            .map(|value| {
                let text = value
                    .as_str()
                    .filter(|text| !text.chars().any(char::is_control))
                    .ok_or("Contained MCP arguments must be bounded literal text.")?;
                Ok(text.to_owned())
            })
            .collect::<Result<Vec<_>, String>>()?,
        _ => return Err("Contained MCP accepts at most 32 literal arguments.".into()),
    };
    if arguments.iter().map(String::len).sum::<usize>() > 32 * 1024 {
        return Err("Contained MCP argument bytes exceeded their bound.".into());
    }
    Ok(Some(LocalSpec {
        content: content.into(),
        command: command.into(),
        arguments,
        executable_digest: grok_build_plus_host::Digest::sha256(&image.bytes),
        executable_bytes: image.bytes.len() as u64,
        architecture,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::ProjectId;
    use crate::extensions::content::Blob;
    use serde_json::json;
    use std::collections::BTreeMap;

    fn fixture_bundle() -> Bundle {
        let mut bytes = vec![0; 64];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4..7].copy_from_slice(&[2, 1, 1]);
        bytes[16] = 3;
        bytes[18] = 183;
        Bundle {
            files: BTreeMap::from([(
                "bin/server".into(),
                Blob {
                    executable: true,
                    bytes,
                },
            )]),
        }
    }

    #[test]
    fn local_specs_bind_native_inventory_and_literal_arguments_without_starting_it() {
        let bundle = fixture_bundle();
        let map = json!({"local":{"type":"stdio","command":"bin/server","args":["--stdio","${LITERAL}"]}});
        let rows = super::super::specs(
            &ProjectId::new("project"),
            &"a".repeat(64),
            &"b".repeat(64),
            &map,
            &bundle,
        )
        .unwrap();
        let spec = rows[0].1.as_ref().unwrap();
        let local = spec.local.as_ref().unwrap();
        assert_eq!(local.executable_bytes, 64);
        assert_eq!(local.architecture, ServiceArchitecture::LinuxAarch64);
        assert_eq!(local.arguments, ["--stdio", "${LITERAL}"]);
        assert_eq!(
            local.executable_digest,
            grok_build_plus_host::Digest::sha256(&bundle.files["bin/server"].bytes)
        );
        for (project, content, arguments) in [
            ("other", "a".repeat(64), json!(["--stdio", "${LITERAL}"])),
            ("project", "c".repeat(64), json!(["--stdio", "${LITERAL}"])),
            ("project", "a".repeat(64), json!(["--changed"])),
        ] {
            let mut changed = map.clone();
            changed["local"]["args"] = arguments;
            let rows = super::super::specs(
                &ProjectId::new(project),
                &content,
                &"b".repeat(64),
                &changed,
                &bundle,
            )
            .unwrap();
            assert_ne!(spec.identity, rows[0].1.as_ref().unwrap().identity);
        }
    }

    #[test]
    fn local_configuration_refuses_host_commands_scripts_foreign_fields_and_unbounded_arguments() {
        let bundle = fixture_bundle();
        for config in [
            json!({"type":"stdio","command":"/bin/sh"}),
            json!({"type":"stdio","command":"../server"}),
            json!({"type":"stdio","command":"node"}),
            json!({"type":"stdio","command":"bin/server","env":{"TOKEN":"reference"}}),
            json!({"type":"stdio","command":"bin/server","args":"--stdio"}),
            json!({"type":"stdio","command":"bin/server","args":[true]}),
            json!({"type":"stdio","command":"bin/server","args":["a".repeat(32769)]}),
        ] {
            assert!(parse(&config, "fixture", &bundle).is_err());
        }
        for (executable, bytes) in [
            (false, bundle.files["bin/server"].bytes.clone()),
            (true, b"#!/bin/sh\nexit 0\n".to_vec()),
            (true, vec![0; 64]),
        ] {
            let mut changed = fixture_bundle();
            changed
                .files
                .insert("bin/server".into(), Blob { executable, bytes });
            assert!(
                parse(
                    &json!({"type":"stdio","command":"bin/server"}),
                    "fixture",
                    &changed
                )
                .is_err()
            );
        }
    }
}
