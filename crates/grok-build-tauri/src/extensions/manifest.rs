//! A preview is an inventory, never executable authority.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;

use super::content::{Bundle, validate_path};
use super::{digest, failure, identifier};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum ComponentKind {
    Skills,
    Tools,
    Automations,
    Agents,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Component {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) kind: ComponentKind,
    pub(crate) path: String,
    pub(crate) quarantine: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct FileView {
    path: String,
    bytes: usize,
    executable: bool,
    sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ExtensionPreview {
    pub(crate) digest: String,
    pub(crate) name: String,
    pub(crate) version: String,
    pub(crate) description: String,
    pub(crate) license: String,
    pub(crate) source: String,
    pub(crate) byte_count: usize,
    pub(crate) components: Vec<Component>,
    pub(crate) inventory: Vec<FileView>,
}

impl ExtensionPreview {
    /// Support/quarantine may improve in a later app version. Every immutable
    /// inventory and source field must still match before that classification
    /// is refreshed. Refresh never changes project enablement by itself.
    pub(super) fn same_inventory(&self, checked: &Self) -> bool {
        let mut previous = self.clone();
        let mut current = checked.clone();
        for component in &mut previous.components {
            component.quarantine = None;
        }
        for component in &mut current.components {
            component.quarantine = None;
        }
        previous == current
    }
}

pub(super) fn inspect(bundle: &Bundle, source: String) -> Result<ExtensionPreview, String> {
    let manifests = [
        "plugin.json",
        ".grok-plugin/plugin.json",
        ".claude-plugin/plugin.json",
        ".codex-plugin/plugin.json",
    ]
    .into_iter()
    .filter(|path| bundle.files.contains_key(*path))
    .collect::<Vec<_>>();
    if manifests.len() != 1 {
        return Err("An extension must have exactly one unambiguous plugin.json manifest.".into());
    }
    let manifest: Value =
        serde_json::from_str(bundle.text(manifests[0], 64 * 1024)?).map_err(failure)?;
    let object = manifest
        .as_object()
        .ok_or("Extension manifest must be an object.")?;
    super::credentials::validate(bundle, &manifest)?;
    let name = string(&manifest, "name", 80)?;
    if !identifier(&name) {
        return Err("Extension name must use lowercase letters, digits and hyphens.".into());
    }
    let version = string(&manifest, "version", 80)?;
    if version.is_empty()
        || !version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-+".contains(&b))
    {
        return Err("Extension version is missing or invalid.".into());
    }
    let description = optional_string(&manifest, "description", 4096)?;
    let license = optional_string(&manifest, "license", 256)?;
    let license_file = ["LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING"]
        .into_iter()
        .find(|path| bundle.files.contains_key(*path));
    let license_ok = !license.is_empty() && license_file.is_some();
    if let Some(path) = license_file {
        bundle.text(path, 256 * 1024)?;
    }
    let mut components = Vec::new();
    collect_skills(bundle, &manifest, license_ok, &mut components)?;
    collect_templates(bundle, &manifest, license_ok, &mut components)?;
    collect_services(bundle, &manifest, license_ok, &mut components)?;
    collect_unsupported(bundle, object, &mut components);
    if components.len() > 128 {
        return Err("Extension component inventory exceeds 128 entries.".into());
    }
    let mut identities = BTreeSet::new();
    components.retain(|c| identities.insert(c.id.clone()));
    components.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(ExtensionPreview {
        digest: digest(&bundle.encode()?),
        name,
        version,
        description,
        license: if license.is_empty() {
            "Unspecified".into()
        } else {
            license
        },
        source,
        byte_count: bundle.byte_len(),
        components,
        inventory: bundle
            .files
            .iter()
            .map(|(path, blob)| FileView {
                path: path.clone(),
                bytes: blob.bytes.len(),
                executable: blob.executable,
                sha256: digest(&blob.bytes),
            })
            .collect(),
    })
}

fn component(kind: ComponentKind, path: &str, name: &str, quarantine: Option<String>) -> Component {
    Component {
        id: digest(format!("{kind:?}\0{path}").as_bytes()),
        name: name.to_owned(),
        kind,
        path: path.to_owned(),
        quarantine,
    }
}

fn under_roots(path: &str, roots: &[String]) -> bool {
    roots.iter().any(|root| {
        path == root
            || path
                .strip_prefix(root)
                .is_some_and(|suffix| suffix.starts_with('/'))
    })
}

fn component_roots(manifest: &Value, key: &str, default: &str) -> Result<Vec<String>, String> {
    let values = match manifest.get(key) {
        None => vec![default.to_owned()],
        Some(Value::String(path)) => vec![path.clone()],
        Some(Value::Array(paths)) if paths.len() <= 32 => paths
            .iter()
            .map(|path| {
                path.as_str()
                    .map(str::to_owned)
                    .ok_or("Extension component root is not text.")
            })
            .collect::<Result<Vec<_>, _>>()?,
        _ => return Err("Extension component roots must be bounded paths.".into()),
    };
    values
        .into_iter()
        .map(|value| {
            let value = value.strip_prefix("./").unwrap_or(&value).to_owned();
            validate_path(&value)?;
            Ok(value)
        })
        .collect()
}

fn string(manifest: &Value, key: &str, maximum: usize) -> Result<String, String> {
    let value = manifest
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("Extension manifest omitted {key}."))?;
    if value.len() > maximum
        || value
            .chars()
            .any(|c| c.is_control() && !matches!(c, '\n' | '\t'))
    {
        return Err(format!(
            "Extension manifest {key} is oversized or contains controls."
        ));
    }
    Ok(value.to_owned())
}
fn optional_string(manifest: &Value, key: &str, maximum: usize) -> Result<String, String> {
    if manifest.get(key).is_none() {
        Ok(String::new())
    } else {
        string(manifest, key, maximum)
    }
}

fn collect_skills(
    bundle: &Bundle,
    manifest: &Value,
    license_ok: bool,
    components: &mut Vec<Component>,
) -> Result<(), String> {
    let skill_roots = component_roots(manifest, "skills", "skills")?;
    for path in bundle
        .files
        .keys()
        .filter(|path| path.ends_with("/SKILL.md") || path.as_str() == "SKILL.md")
    {
        if !under_roots(path, &skill_roots) {
            continue;
        }
        let body = bundle.text(path, 64 * 1024).and_then(|body| {
            super::store::append_references(bundle, path, body, &mut String::new())?;
            Ok(body)
        });
        let reason = body.err().or_else(|| {
            (!license_ok)
                .then(|| "Include a declared license and its license text before enabling.".into())
        });
        let name = std::path::Path::new(path)
            .parent()
            .and_then(std::path::Path::file_name)
            .and_then(std::ffi::OsStr::to_str)
            .unwrap_or("skill");
        components.push(component(ComponentKind::Skills, path, name, reason));
    }
    Ok(())
}

fn collect_templates(
    bundle: &Bundle,
    manifest: &Value,
    license_ok: bool,
    components: &mut Vec<Component>,
) -> Result<(), String> {
    for (field, default, kind, reason) in [
        (
            "agents",
            "agents",
            ComponentKind::Agents,
            "Agent descriptors require the app-owned child scheduler.",
        ),
        (
            "commands",
            "commands",
            ComponentKind::Automations,
            "Command templates are not yet an admitted app extension component.",
        ),
        (
            "workflows",
            "workflows",
            ComponentKind::Automations,
            "Workflow execution requires the bounded app workflow engine.",
        ),
    ] {
        let roots = component_roots(manifest, field, default)?;
        for path in bundle.files.keys().filter(|path| under_roots(path, &roots)) {
            if std::path::Path::new(path)
                .extension()
                .is_some_and(|extension| {
                    ["md", "rhai", "json"]
                        .iter()
                        .any(|expected| extension.eq_ignore_ascii_case(expected))
                })
            {
                let quarantine = if field == "workflows"
                    && std::path::Path::new(path)
                        .extension()
                        .is_some_and(|ext| ext.eq_ignore_ascii_case("rhai"))
                    && license_ok
                {
                    bundle.text(path, grok_build_workflow::MAX_BYTES).err()
                } else {
                    Some(reason.into())
                };
                components.push(component(kind, path, path, quarantine));
            }
        }
    }
    Ok(())
}

fn collect_services(
    bundle: &Bundle,
    manifest: &Value,
    license_ok: bool,
    components: &mut Vec<Component>,
) -> Result<(), String> {
    for (field, default, kind, reason) in [
        (
            "mcpServers",
            ".mcp.json",
            ComponentKind::Tools,
            "MCP configuration awaits server admission and an independent app broker.",
        ),
        (
            "hooks",
            "hooks/hooks.json",
            ComponentKind::Automations,
            "Command hooks require an admitted contained service and app hook boundary.",
        ),
        (
            "lspServers",
            ".lsp.json",
            ComponentKind::Tools,
            "Language-server process components are quarantined.",
        ),
    ] {
        if bundle.files.contains_key(default) {
            components.push(component(kind, default, field, Some(reason.into())));
        }
        if let Some(value) = manifest.get(field) {
            let path = if let Some(path) = value.as_str() {
                let path = path.strip_prefix("./").unwrap_or(path);
                validate_path(path)?;
                bundle.text(path, 128 * 1024)?;
                path.to_owned()
            } else if value.is_object() {
                format!("manifest:{field}")
            } else {
                return Err(format!("Extension {field} must be a path or object."));
            };
            if path != default {
                components.push(component(kind, &path, field, Some(reason.into())));
            }
        }
    }
    if license_ok {
        for item in components
            .iter_mut()
            .filter(|item| item.name == "mcpServers")
        {
            let supported = (|| {
                let config: Value = if item.path == "manifest:mcpServers" {
                    manifest.clone()
                } else {
                    serde_json::from_str(bundle.text(&item.path, 128 * 1024)?)
                        .map_err(|_| "MCP configuration is invalid JSON.")?
                };
                super::mcp::configuration_available(
                    config
                        .get("mcpServers")
                        .ok_or("MCP configuration has no server object.")?,
                    bundle,
                )
            })();
            item.quarantine = supported.err();
        }
        for item in components.iter_mut().filter(|item| item.name == "hooks") {
            let supported = (|| {
                let config: Value = if item.path == "manifest:hooks" {
                    manifest.clone()
                } else {
                    serde_json::from_str(bundle.text(&item.path, 128 * 1024)?)
                        .map_err(|_| "Hook configuration is invalid JSON.")?
                };
                super::hooks::config::parse(
                    config
                        .get("hooks")
                        .ok_or("Hook configuration omitted hooks.")?,
                    &digest(&bundle.encode()?),
                    &item.id,
                    bundle,
                )
            })();
            item.quarantine = supported.err();
        }
    }
    Ok(())
}

fn collect_unsupported(
    bundle: &Bundle,
    object: &serde_json::Map<String, Value>,
    components: &mut Vec<Component>,
) {
    let known = [
        "name",
        "version",
        "description",
        "author",
        "homepage",
        "repository",
        "license",
        "keywords",
        "skills",
        "agents",
        "commands",
        "workflows",
        "hooks",
        "mcpServers",
        "lspServers",
    ];
    for key in object.keys().filter(|key| !known.contains(&key.as_str())) {
        components.push(component(
            ComponentKind::Automations,
            &format!("manifest:{}", digest(key.as_bytes())),
            "Unsupported manifest field",
            Some("Unknown manifest fields cannot add execution or installation authority.".into()),
        ));
    }
    for path in bundle.files.keys().filter(|path| {
        matches!(
            path.as_str(),
            "package.json" | "Makefile" | "install.sh" | "setup.py" | ".gitattributes"
        ) || path.ends_with("/install.sh")
    }) {
        components.push(component(
            ComponentKind::Automations,
            path,
            "Installation component",
            Some(
                "Installation scripts, package managers and checkout filters are never executed."
                    .into(),
            ),
        ));
    }
}
