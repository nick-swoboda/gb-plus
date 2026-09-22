//! Versioned metadata is separate from immutable content and contains no credentials.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs::File;
use std::path::{Path, PathBuf};

use super::content::{Bundle, MAX_CAPSULE_BYTES};
use super::manifest::{ComponentKind, ExtensionPreview, inspect};
use super::{digest, failure, valid_digest};
use crate::contracts::ProjectId;
use crate::owner_state::{OwnerStateFile, OwnerStateRoot};

const SCHEMA: u16 = 1;
const MAX_METADATA: u64 = 8 * 1024 * 1024;
const MAX_VERSIONS: usize = 128;
const MAX_INSTALLED_BYTES: usize = 2 * 1024 * 1024 * 1024;
static PREVIEW_SLOT: std::sync::Mutex<()> = std::sync::Mutex::new(());

mod hooks;
pub(super) mod workflows;

#[derive(Clone, Debug)]
pub(crate) struct ExtensionStore {
    root: PathBuf,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Record {
    version: u16,
    binding: String,
    revision: u64,
    entries: BTreeMap<String, StoredVersion>,
    projects: BTreeMap<ProjectId, BTreeMap<String, Selection>>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredVersion {
    preview: ExtensionPreview,
    complete: bool,
    installed: bool,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Selection {
    digest: String,
    components: BTreeSet<String>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ExtensionView {
    pub(crate) revision: u64,
    pub(crate) extensions: Vec<InstalledView>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct InstalledView {
    preview: ExtensionPreview,
    installed: bool,
    complete: bool,
    enabled_components: Vec<String>,
}

impl ExtensionStore {
    pub(crate) fn preview_https(
        &self,
        url: &str,
        byte_len: u64,
        sha256: &str,
    ) -> Result<ExtensionPreview, String> {
        let _budget = PREVIEW_SLOT
            .try_lock()
            .map_err(|_| "Another extension preview is in progress.")?;
        let bytes = crate::asset_download::extension_archive::fetch(url, byte_len, sha256)?;
        self.preview_bundle(
            &super::archive::decode(&bytes)?,
            format!("{url} (archive SHA-256 {sha256}, {byte_len} bytes)"),
        )
    }
    pub(crate) fn new(state_root: &Path) -> Self {
        Self {
            root: state_root.join("extensions-v1"),
        }
    }

    pub(crate) fn preview_local(&self, source: &Path) -> Result<ExtensionPreview, String> {
        let _budget = PREVIEW_SLOT
            .try_lock()
            .map_err(|_| "Another extension preview is in progress.")?;
        super::protected_sources::validate_local_root(source, self.app_root()?)?;
        let bundle = Bundle::capture(source)?;
        self.preview_bundle(&bundle, format!("local:{}", source.display()))
    }

    pub(super) fn preview_bundle(
        &self,
        bundle: &Bundle,
        source: String,
    ) -> Result<ExtensionPreview, String> {
        if source.len() > 4096 || source.chars().any(char::is_control) {
            return Err("Extension source is invalid.".into());
        }
        let preview = inspect(bundle, source)?;
        let bytes = bundle.encode()?;
        let _lock = self.lock()?;
        let mut record = self.read()?;
        if let Some(existing) = record.entries.get(&preview.digest) {
            if existing.complete {
                self.load_bundle(&preview.digest)?;
                return Ok(existing.preview.clone());
            }
        } else {
            if record.entries.len() >= MAX_VERSIONS
                || record
                    .entries
                    .values()
                    .map(|v| v.preview.byte_count)
                    .sum::<usize>()
                    .saturating_add(preview.byte_count)
                    > MAX_INSTALLED_BYTES
            {
                return Err("Extension storage capacity reached; review retained versions before adding content.".into());
            }
            record.entries.insert(
                preview.digest.clone(),
                StoredVersion {
                    preview: preview.clone(),
                    complete: false,
                    installed: false,
                },
            );
            self.commit(&mut record)?; // bounded reservation precedes any content write.
        }
        let capsule = self.capsule(&preview.digest)?;
        match capsule.read().map_err(failure)? {
            Some(existing) if existing == bytes => {}
            Some(_) => {
                return Err(
                    "Content-addressed extension bytes differ; existing content was retained."
                        .into(),
                );
            }
            None => capsule.replace(&bytes).map_err(failure)?,
        }
        self.load_bundle(&preview.digest)?;
        record
            .entries
            .get_mut(&preview.digest)
            .ok_or("Extension reservation disappeared.")?
            .complete = true;
        self.commit(&mut record)?;
        Ok(preview)
    }

    pub(crate) fn install(&self, content_digest: &str) -> Result<(), String> {
        let _lock = self.lock()?;
        let mut record = self.read()?;
        let entry = record
            .entries
            .get_mut(content_digest)
            .ok_or("Preview this exact extension before installing it.")?;
        if !entry.complete {
            return Err(
                "Extension preview was interrupted; preview it again before installing.".into(),
            );
        }
        let checked = inspect(
            &self.load_bundle(content_digest)?,
            entry.preview.source.clone(),
        )?;
        if !entry.preview.same_inventory(&checked) {
            return Err("Extension preview no longer matches its frozen content.".into());
        }
        entry.preview = checked;
        entry.installed = true;
        // Installation deliberately changes no project enablement.
        self.commit(&mut record)
    }

    pub(crate) fn set_enabled(
        &self,
        project: &ProjectId,
        content_digest: &str,
        component_id: &str,
        enabled: bool,
    ) -> Result<(), String> {
        validate_project(project)?;
        let _lock = self.lock()?;
        let mut record = self.read()?;
        let entry = record
            .entries
            .get(content_digest)
            .ok_or("Extension version is not installed.")?;
        if !entry.installed || !entry.complete {
            return Err("Install the completed extension preview first.".into());
        }
        if !enabled {
            if !entry
                .preview
                .components
                .iter()
                .any(|component| component.id == component_id)
            {
                return Err("Extension component is not in its stored inventory.".into());
            }
            let name = entry.preview.name.clone();
            if let Some(selections) = record.projects.get_mut(project)
                && let Some(selection) = selections.get_mut(&name)
            {
                if selection.digest != content_digest {
                    return Err(
                        "This project is using another extension version. Refresh Extensions."
                            .into(),
                    );
                }
                selection.components.remove(component_id);
                if selection.components.is_empty() {
                    selections.remove(&name);
                }
            }
            return self.commit(&mut record);
        }
        let checked = inspect(
            &self.load_bundle(content_digest)?,
            entry.preview.source.clone(),
        )?;
        let component = checked
            .components
            .iter()
            .find(|c| c.id == component_id)
            .ok_or("Extension component is not in its frozen inventory.")?;
        if component.quarantine.is_some() {
            return Err(component.quarantine.clone().unwrap_or_default());
        }
        let name = entry.preview.name.clone();
        if !entry.preview.same_inventory(&checked) {
            return Err("Extension inventory changed before enablement.".into());
        }
        record
            .entries
            .get_mut(content_digest)
            .ok_or("Extension content disappeared.")?
            .preview = checked;
        if record.projects.len() >= 128 && !record.projects.contains_key(project) {
            return Err("Extension project metadata capacity reached.".into());
        }
        let selections = record.projects.entry(project.clone()).or_default();
        if selections.len() >= 32 && !selections.contains_key(&name) {
            return Err("A project can enable at most 32 extensions.".into());
        }
        let selection = selections.entry(name).or_insert_with(|| Selection {
            digest: content_digest.to_owned(),
            components: BTreeSet::new(),
        });
        if selection.digest != content_digest {
            // Updating a version never inherits another component's authority.
            content_digest.clone_into(&mut selection.digest);
            selection.components.clear();
        }
        selection.components.insert(component_id.to_owned());
        self.commit(&mut record)
    }

    pub(crate) fn view(&self, project: &ProjectId) -> Result<ExtensionView, String> {
        validate_project(project)?;
        let record = self.read()?;
        let selection = record.projects.get(project);
        let mut extensions = record
            .entries
            .values()
            .map(|entry| {
                let mut preview = entry.preview.clone();
                let origin = self.check_origin(&preview.source);
                if let Err(reason) = &origin {
                    for component in &mut preview.components {
                        component.quarantine = Some(reason.clone());
                    }
                }
                if origin.is_ok()
                    && entry.complete
                    && preview
                        .components
                        .iter()
                        .any(|component| matches!(component.name.as_str(), "mcpServers" | "hooks"))
                {
                    let checked =
                        inspect(&self.load_bundle(&preview.digest)?, preview.source.clone())?;
                    if !preview.same_inventory(&checked) {
                        return Err(
                            "Extension inventory differs from its immutable preview.".into()
                        );
                    }
                    preview = checked;
                }
                Ok(InstalledView {
                    enabled_components: selection
                        .and_then(|project| project.get(&entry.preview.name))
                        .filter(|s| s.digest == entry.preview.digest)
                        .map_or_else(Vec::new, |s| s.components.iter().cloned().collect()),
                    preview,
                    installed: entry.installed,
                    complete: entry.complete,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        extensions.sort_by(|a, b| {
            (&a.preview.name, &a.preview.version, &a.preview.digest).cmp(&(
                &b.preview.name,
                &b.preview.version,
                &b.preview.digest,
            ))
        });
        Ok(ExtensionView {
            revision: record.revision,
            extensions,
        })
    }

    /// Freeze enabled skill text once at run admission. Updates affect later runs.
    pub(crate) fn skill_context(&self, project: &ProjectId) -> Result<String, String> {
        validate_project(project)?;
        let record = self.read()?;
        let Some(selections) = record.projects.get(project) else {
            return Ok(String::new());
        };
        let mut output = String::new();
        let mut count = 0;
        for (name, selection) in selections {
            let entry = record
                .entries
                .get(&selection.digest)
                .ok_or("Enabled extension content is unavailable.")?;
            let bundle = self.load_bundle(&selection.digest)?;
            let preview = inspect(&bundle, entry.preview.source.clone())?;
            for component in preview
                .components
                .iter()
                .filter(|c| selection.components.contains(&c.id))
            {
                if component.quarantine.is_some() {
                    return Err("An enabled extension component needs a new review.".into());
                }
                if component.kind != ComponentKind::Skills {
                    continue;
                }
                count += 1;
                if count > 16 {
                    return Err("At most sixteen skills may be loaded into one run.".into());
                }
                let body = bundle.text(&component.path, 64 * 1024)?;
                writeln!(
                    output,
                    "\nEnabled skill {name}/{} · version {} · content {}\n{}\n",
                    component.name, preview.version, preview.digest, body
                )
                .map_err(failure)?;
                append_references(&bundle, &component.path, body, &mut output)?;
                if output.len() > 128 * 1024 {
                    return Err(
                        "Enabled skills and references exceed the 128 KiB run context limit."
                            .into(),
                    );
                }
            }
        }
        Ok(output)
    }

    pub(crate) fn preview_file(&self, content_digest: &str, path: &str) -> Result<String, String> {
        let record = self.read()?;
        if !record
            .entries
            .get(content_digest)
            .is_some_and(|entry| entry.complete)
        {
            return Err("Extension preview is unavailable.".into());
        }
        Ok(self
            .load_bundle(content_digest)?
            .preview_text(path, 256 * 1024)?
            .to_owned())
    }

    pub(crate) fn mcp_servers(
        &self,
        project: &ProjectId,
        content_digest: &str,
        component_id: &str,
    ) -> Result<super::mcp::ServerInventory, String> {
        validate_project(project)?;
        let record = self.read()?;
        let entry = record
            .entries
            .get(content_digest)
            .filter(|entry| entry.installed && entry.complete)
            .ok_or("Install the reviewed extension before inspecting its MCP servers.")?;
        let bundle = self.load_bundle(content_digest)?;
        let preview = inspect(&bundle, entry.preview.source.clone())?;
        if !entry.preview.same_inventory(&preview) {
            return Err("MCP extension no longer matches its frozen preview.".into());
        }
        let component = preview
            .components
            .iter()
            .find(|c| {
                c.id == component_id && c.kind == ComponentKind::Tools && c.name == "mcpServers"
            })
            .ok_or("The selected component is not a frozen MCP configuration.")?;
        if let Some(reason) = &component.quarantine {
            return Err(format!("This MCP component remains quarantined: {reason}"));
        }
        let config: serde_json::Value = if component.path == "manifest:mcpServers" {
            let path = [
                "plugin.json",
                ".grok-plugin/plugin.json",
                ".claude-plugin/plugin.json",
                ".codex-plugin/plugin.json",
            ]
            .into_iter()
            .find(|path| bundle.files.contains_key(*path))
            .ok_or("Frozen manifest is absent.")?;
            serde_json::from_str(bundle.text(path, 64 * 1024)?)
                .map_err(|_| "Frozen manifest is invalid JSON.")?
        } else {
            serde_json::from_str(bundle.text(&component.path, 128 * 1024)?)
                .map_err(|_| "MCP configuration is invalid JSON.")?
        };
        let servers = config
            .get("mcpServers")
            .ok_or("MCP configuration has no mcpServers object.")?;
        super::mcp::specs(project, content_digest, component_id, servers, &bundle)
    }

    /// Pin installed content selected for this run. No provider argument can
    /// install, choose, or enable a server through this path.
    pub(crate) fn enabled_mcp_servers(
        &self,
        project: &ProjectId,
    ) -> Result<Vec<super::mcp::ServerSpec>, String> {
        validate_project(project)?;
        let record = self.read()?;
        let mut servers = Vec::new();
        for selection in record
            .projects
            .get(project)
            .into_iter()
            .flat_map(|p| p.values())
        {
            let entry = record
                .entries
                .get(&selection.digest)
                .ok_or("Enabled MCP content is unavailable.")?;
            for component in entry.preview.components.iter().filter(|component| {
                selection.components.contains(&component.id)
                    && component.kind == ComponentKind::Tools
                    && component.name == "mcpServers"
            }) {
                if component.quarantine.is_some() {
                    return Err("An enabled MCP component remains quarantined.".into());
                }
                for (_, spec) in self.mcp_servers(project, &selection.digest, &component.id)? {
                    servers
                        .push(spec.ok_or("Enabled MCP configuration requires a new admission.")?);
                    if servers.len() > 4 {
                        return Err("A run can enable at most four MCP servers.".into());
                    }
                }
            }
        }
        Ok(servers)
    }

    pub(in crate::extensions) fn load_bundle(
        &self,
        content_digest: &str,
    ) -> Result<Bundle, String> {
        let record = self.read()?;
        let entry = record
            .entries
            .get(content_digest)
            .ok_or("Extension origin is unavailable.")?;
        self.check_origin(&entry.preview.source)?;
        let bytes = self
            .capsule(content_digest)?
            .read()
            .map_err(failure)?
            .ok_or("Extension capsule is missing; no fallback source will be loaded.")?;
        if digest(&bytes) != content_digest {
            return Err("Extension content hash changed; nothing was loaded.".into());
        }
        Bundle::decode(&bytes)
    }
    fn app_root(&self) -> Result<&Path, String> {
        self.root
            .parent()
            .ok_or_else(|| "Extension app-state root is unavailable.".into())
    }
    fn check_origin(&self, source: &str) -> Result<(), String> {
        if let Some(local) = source.strip_prefix("local:") {
            super::protected_sources::validate_local_root(Path::new(local), self.app_root()?)?;
        }
        Ok(())
    }
    fn capsule(&self, content_digest: &str) -> Result<OwnerStateFile, String> {
        if !valid_digest(content_digest) {
            return Err("Extension content identity is invalid.".into());
        }
        OwnerStateRoot::new(self.root.join("content"))
            .file(format!("{content_digest}.gbext"), MAX_CAPSULE_BYTES)
            .map_err(failure)
    }
    fn file(&self) -> Result<OwnerStateFile, String> {
        OwnerStateRoot::new(&self.root)
            .file("metadata.json", MAX_METADATA)
            .map_err(failure)
    }
    fn lock(&self) -> Result<File, String> {
        let file = OwnerStateRoot::new(&self.root)
            .file("writer.lock", 0)
            .map_err(failure)?
            .open_process_file()
            .map_err(failure)?;
        rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| "Extension metadata is being updated. Try again.")?;
        Ok(file)
    }
    fn binding(&self) -> String {
        digest(format!("GB Plus extension metadata v1\0{}", self.root.display()).as_bytes())
    }
    fn read(&self) -> Result<Record, String> {
        let Some(bytes) = self.file()?.read().map_err(failure)? else {
            return Ok(Record {
                version: SCHEMA,
                binding: self.binding(),
                revision: 0,
                entries: BTreeMap::new(),
                projects: BTreeMap::new(),
            });
        };
        let record: Record = serde_json::from_slice(&bytes)
            .map_err(|_| "Extension metadata is unreadable; originals remain recoverable.")?;
        self.validate(&record)?;
        Ok(record)
    }
    fn validate(&self, record: &Record) -> Result<(), String> {
        if record.version != SCHEMA
            || record.binding != self.binding()
            || record.entries.len() > MAX_VERSIONS
            || record.projects.len() > 128
        {
            return Err(
                "Unknown, moved or oversized extension metadata was retained without execution."
                    .into(),
            );
        }
        let mut bytes = 0usize;
        for (key, entry) in &record.entries {
            let p = &entry.preview;
            if !valid_digest(key)
                || key != &p.digest
                || !super::identifier(&p.name)
                || p.components.len() > 128
                || p.inventory.len() > super::content::MAX_FILES
                || p.byte_count > super::content::MAX_BYTES
                || entry.installed && !entry.complete
            {
                return Err("Extension metadata contains an inconsistent inventory.".into());
            }
            bytes = bytes.saturating_add(p.byte_count);
        }
        if bytes > MAX_INSTALLED_BYTES {
            return Err("Extension storage reservation is oversized.".into());
        }
        for (project, selections) in &record.projects {
            validate_project(project)?;
            if selections.len() > 32 {
                return Err("Project extension bound exceeded.".into());
            }
            for (name, selection) in selections {
                let entry = record
                    .entries
                    .get(&selection.digest)
                    .ok_or("Project extension references missing content.")?;
                if !entry.complete
                    || !entry.installed
                    || name != &entry.preview.name
                    || selection.components.len() > 128
                    || selection.components.iter().any(|id| {
                        !entry
                            .preview
                            .components
                            .iter()
                            .any(|c| &c.id == id && c.quarantine.is_none())
                    })
                {
                    return Err(
                        "Project extension selection is inconsistent or quarantined.".into(),
                    );
                }
            }
        }
        Ok(())
    }
    fn commit(&self, record: &mut Record) -> Result<(), String> {
        record.revision = record
            .revision
            .checked_add(1)
            .ok_or("Extension revision capacity reached.")?;
        self.validate(record)?;
        let bytes = serde_json::to_vec(record).map_err(failure)?;
        if bytes.len() as u64 > MAX_METADATA {
            return Err("Extension metadata exceeds its durable bound.".into());
        }
        if let Some(previous) = self.file()?.read().map_err(failure)? {
            OwnerStateRoot::new(&self.root)
                .file("metadata-before-update.json", MAX_METADATA)
                .map_err(failure)?
                .replace(&previous)
                .map_err(failure)?;
        }
        self.file()?.replace(&bytes).map_err(failure)?;
        if self.file()?.read().map_err(failure)?.as_deref() != Some(bytes.as_slice()) {
            return Err("Extension metadata readback differed; refresh before continuing.".into());
        }
        Ok(())
    }
}

fn validate_project(project: &ProjectId) -> Result<(), String> {
    let value = project.as_str();
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return Err("Extension project identity is invalid.".into());
    }
    Ok(())
}

pub(super) fn append_references(
    bundle: &Bundle,
    skill_path: &str,
    body: &str,
    output: &mut String,
) -> Result<(), String> {
    let directory = skill_path
        .rsplit_once('/')
        .map_or("", |(directory, _)| directory);
    let mut seen = BTreeSet::new();
    for tail in body.split("](").skip(1) {
        let Some((target, _)) = tail.split_once(')') else {
            continue;
        };
        if target.contains(':')
            || !Path::new(target)
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("md"))
            || target.contains(['#', '?'])
        {
            continue;
        }
        let target = target.strip_prefix("./").unwrap_or(target);
        let path = if directory.is_empty() {
            target.to_owned()
        } else {
            format!("{directory}/{target}")
        };
        super::content::validate_path(&path)?;
        if !seen.insert(path.clone()) {
            continue;
        }
        if seen.len() > 16 {
            return Err("A skill has more than sixteen local text references.".into());
        }
        let text = bundle.text(&path, 32 * 1024)?;
        if output
            .len()
            .saturating_add(text.len())
            .saturating_add(path.len())
            > 128 * 1024
        {
            return Err("Skill reference context exceeds its bound.".into());
        }
        writeln!(output, "\nSkill reference {path}\n{text}\n").map_err(failure)?;
    }
    Ok(())
}
