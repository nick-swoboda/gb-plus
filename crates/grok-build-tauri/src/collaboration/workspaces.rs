//! A common dirty-file snapshot and independent, app-owned Git worktrees.
use crate::bounded_process::{Limits, collect_git_snapshot};
use crate::runtime::cancel::RuntimeCancelHandle;
use grok_build_plus_host::{BoundProject, ServiceSnapshot, bind_project_folder};
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

mod custody;
use custody::FamilyDirectory;

pub(super) struct Workspaces {
    snapshot: ServiceSnapshot,
    owner: std::sync::Arc<FamilyDirectory>,
    git_ready: bool,
    serial_reason: Option<String>,
    created: usize,
}

pub(super) struct ChildWorkspace {
    pub(super) bound: BoundProject,
    pub(super) snapshot: String,
    pub(super) isolated: bool,
    pub(super) serial_reason: Option<String>,
    pub(super) excluded_paths: Vec<String>,
    // Retains the non-Git captured copy until its owning child finishes.
    _copy: Option<ServiceSnapshot>,
    _owner: std::sync::Arc<FamilyDirectory>,
}

impl Workspaces {
    pub(super) fn digest(&self) -> String {
        self.snapshot.digest().to_string()
    }
    pub(super) fn capture(
        state: &Path,
        family: &str,
        bound: &BoundProject,
        cancel: &RuntimeCancelHandle,
    ) -> Result<Self, String> {
        cancel.ensure_not_cancelled()?;
        let owner = std::sync::Arc::new(FamilyDirectory::create(state, family)?);
        let protected = crate::extensions::protected_sources::paths(state)?;
        let snapshot = ServiceSnapshot::capture_workspace(
            bound.folder(),
            owner.path(),
            "snapshot",
            &protected,
            &|| cancel.cancelled(),
        )?;
        if snapshot.size().1 > 128 * 1024 * 1024 {
            return Err("Child collaboration snapshot exceeds 128 MiB; narrow the workspace before delegating.".into());
        }
        let source_git =
            std::fs::symlink_metadata(bound.folder().join(".git")).is_ok_and(|metadata| {
                !metadata.file_type().is_symlink() && (metadata.is_file() || metadata.is_dir())
            });
        let mut result = Self {
            snapshot,
            owner,
            git_ready: false,
            serial_reason: None,
            created: 0,
        };
        if !source_git {
            result.serial_reason = Some("This project has no Git administration entry; child model executions remain serial.".into());
        } else if result.initialize_git(cancel).is_err() {
            // A failed private object store remains owned for cleanup. No source
            // Git configuration or checkout is ever executed as a fallback.
            result.serial_reason = Some("Safe managed Git isolation is unavailable; children use captured views and execute serially.".into());
        } else {
            result.git_ready = true;
        }
        Ok(result)
    }

    fn initialize_git(&self, cancel: &RuntimeCancelHandle) -> Result<(), String> {
        self.owner.mkdir("template")?;
        let template = format!(
            "--template={}",
            self.owner.path().join("template").display()
        );
        self.git(
            self.owner.path(),
            &[
                "init",
                "--bare",
                "--object-format=sha256",
                &template,
                "objects.git",
            ],
            &[],
            cancel,
        )?;
        let import = self.snapshot.git_fast_import(&|| cancel.cancelled())?;
        self.git(
            &self.owner.path().join("objects.git"),
            &["fast-import", "--quiet"],
            &import,
            cancel,
        )?;
        let commit = self.git(
            &self.owner.path().join("objects.git"),
            &["rev-parse", "refs/heads/gbplus-snapshot"],
            &[],
            cancel,
        )?;
        if !crate::extensions::valid_digest(
            std::str::from_utf8(&commit)
                .map_err(|_| "Invalid isolated Git commit.")?
                .trim(),
        ) {
            return Err("Managed Git snapshot did not produce its expected SHA-256 commit.".into());
        }
        Ok(())
    }

    pub(super) fn create_child(
        &mut self,
        cancel: &RuntimeCancelHandle,
    ) -> Result<ChildWorkspace, String> {
        cancel.ensure_not_cancelled()?;
        self.owner.revalidate()?;
        self.snapshot.revalidate()?;
        if self.created >= 32 {
            return Err("Child workspace bound exceeded.".into());
        }
        self.created += 1;
        let name = format!("child-{}", self.created);
        let child = self.owner.path().join(&name);
        let copy = if self.git_ready {
            let child_text = child.to_str().ok_or("Child path is not UTF-8.")?;
            self.git(
                &self.owner.path().join("objects.git"),
                &[
                    "worktree",
                    "add",
                    "--detach",
                    "--no-checkout",
                    child_text,
                    "refs/heads/gbplus-snapshot",
                ],
                &[],
                cancel,
            )?;
            std::fs::set_permissions(&child, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| e.to_string())?;
            let admin = self.owner.path().join("objects.git/worktrees").join(&name);
            self.snapshot
                .materialize_worktree(&child, &admin, &|| cancel.cancelled())?;
            self.git(&child, &["read-tree", "HEAD"], &[], cancel)?;
            None
        } else {
            Some(ServiceSnapshot::capture_workspace(
                self.snapshot.path(),
                self.owner.path(),
                &name,
                &[],
                &|| cancel.cancelled(),
            )?)
        };
        self.owner.revalidate()?;
        cancel.ensure_not_cancelled()?;
        Ok(ChildWorkspace {
            bound: bind_project_folder(&child).map_err(|e| e.to_string())?,
            snapshot: self.snapshot.digest().to_string(),
            excluded_paths: self.snapshot.exclusions().to_vec(),
            isolated: self.git_ready,
            serial_reason: self.serial_reason.clone(),
            _copy: copy,
            _owner: self.owner.clone(),
        })
    }

    fn git(
        &self,
        directory: &Path,
        args: &[&str],
        input: &[u8],
        cancel: &RuntimeCancelHandle,
    ) -> Result<Vec<u8>, String> {
        cancel.ensure_not_cancelled()?;
        self.owner.revalidate()?;
        if !directory.starts_with(self.owner.path()) {
            return Err("Git child operation escaped its private family directory.".into());
        }
        let mut command = Command::new("/usr/bin/git");
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_OPTIONAL_LOCKS", "0")
            .env("GIT_ATTR_NOSYSTEM", "1")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .current_dir(directory)
            .args([
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "credential.helper=",
                "-c",
                "commit.gpgSign=false",
                "-c",
                "protocol.allow=never",
            ])
            .args(args);
        let output = collect_git_snapshot(
            command,
            input,
            &Limits {
                input: 160 * 1024 * 1024,
                output: 16 * 1024,
                error: 16 * 1024,
                timeout: Duration::from_secs(20),
            },
            Box::new(self.owner.clone()),
        )?;
        self.owner.revalidate()?;
        cancel.ensure_not_cancelled()?;
        if !output.status.success() {
            return Err("Fixed managed Git preparation failed; no child was admitted.".into());
        }
        Ok(output.stdout)
    }
}

#[cfg(test)]
mod tests;
