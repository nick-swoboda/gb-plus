//! User-attached images stay in memory; a missing attachment never becomes a text-only retry.

use crate::owner_state::OwnerStateRoot;
use grok_build_plus_host::worktree_recovery_digest;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};

const PREFIX: &str = "\n\n[GB Plus image: ";
static NEXT: AtomicU64 = AtomicU64::new(1);

pub(crate) struct UserImage {
    pub(crate) bytes: Vec<u8>,
    pub(crate) width: u32,
    pub(crate) height: u32,
    pub(crate) sha256: String,
    project: String,
    workspace: String,
    session: String,
}

impl Drop for UserImage {
    fn drop(&mut self) {
        self.bytes.fill(0);
    }
}

#[derive(Clone, Default)]
pub(crate) struct CliImages {
    images: Arc<Mutex<BTreeMap<String, UserImage>>>,
    root: Option<PathBuf>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ImageIntent {
    schema_version: u16,
    project: String,
    workspace: String,
    session: String,
    sha256: String,
}

impl CliImages {
    pub(crate) fn new(root: &Path) -> Self {
        Self {
            root: Some(root.join("cli-image-intents")),
            ..Self::default()
        }
    }

    fn intent(&self, id: &str) -> Result<crate::owner_state::OwnerStateFile, String> {
        OwnerStateRoot::new(
            self.root
                .as_ref()
                .ok_or("Image input is not configured for this runtime.")?,
        )
        .file(format!("{id}.json"), 4096)
        .map_err(|e| e.to_string())
    }

    pub(crate) fn stage(
        &self,
        project: &str,
        workspace: &str,
        session: &str,
        bytes: Vec<u8>,
    ) -> Result<String, String> {
        let (width, height) = validate_png(&bytes)?;
        let sha256 = worktree_recovery_digest(&bytes);
        let identity = worktree_recovery_digest(
            format!(
                "{}:{}:{}:{}",
                std::process::id(),
                super::types::unix_time_millis(),
                NEXT.fetch_add(1, Ordering::Relaxed),
                sha256
            )
            .as_bytes(),
        );
        let mut images = self
            .images
            .lock()
            .map_err(|_| "Image attachments are unavailable.")?;
        if images.len() >= 2 {
            return Err("Two images are already waiting to be sent. Send or remove them before attaching another.".into());
        }
        let intent = ImageIntent {
            schema_version: 1,
            project: project.into(),
            workspace: workspace.into(),
            session: session.into(),
            sha256: sha256.clone(),
        };
        self.intent(&identity)?
            .replace(&serde_json::to_vec(&intent).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        images.insert(
            identity.clone(),
            UserImage {
                bytes,
                width,
                height,
                sha256,
                project: project.into(),
                workspace: workspace.into(),
                session: session.into(),
            },
        );
        Ok(format!("{PREFIX}{identity}]"))
    }

    pub(crate) fn take<'a>(
        &self,
        prompt: &'a str,
        scope: &super::types::RuntimeInvocationScope,
    ) -> Result<(&'a str, Option<UserImage>), String> {
        let Some((text, suffix)) = prompt.rsplit_once(PREFIX) else {
            return Ok((prompt, None));
        };
        let Some(id) = suffix
            .strip_suffix(']')
            .filter(|id| id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()))
        else {
            return Ok((prompt, None));
        };
        let mut images = self
            .images
            .lock()
            .map_err(|_| "Image attachments are unavailable.")?;
        let Some(bytes) = self.intent(id)?.read().map_err(|e| e.to_string())? else {
            return Err(
                "Image attachment metadata is unavailable. Reattach the image before sending."
                    .into(),
            );
        };
        let intent: ImageIntent = serde_json::from_slice(&bytes)
            .map_err(|_| "Image attachment metadata is damaged; it was retained.")?;
        if intent.schema_version != 1
            || intent.project != scope.project_id.as_str()
            || intent.workspace != scope.workspace_id.as_str()
            || intent.session != scope.session_id.as_str()
        {
            return Err("Image attachment metadata does not match this chat.".into());
        }
        let image = images.get(id).ok_or("This message's image is no longer available. Reattach it before retrying; no prompt was sent.")?;
        if intent.sha256 != image.sha256
            || image.project != scope.project_id.as_str()
            || image.workspace != scope.workspace_id.as_str()
            || image.session != scope.session_id.as_str()
        {
            return Err("The image belongs to another project, workspace or chat.".into());
        }
        Ok((text, images.remove(id)))
    }

    pub(crate) fn discard(&self, marker: &str) -> Result<(), String> {
        let id = marker
            .strip_prefix(PREFIX)
            .and_then(|value| value.strip_suffix(']'))
            .ok_or("Image attachment identity is invalid.")?;
        self.images
            .lock()
            .map_err(|_| "Image attachments are unavailable.")?
            .remove(id);
        Ok(())
    }

    pub(crate) fn discard_queued(&self, item: &crate::queue::QueueItem) -> Result<(), String> {
        let Some((_, suffix)) = item.prompt.rsplit_once(PREFIX) else {
            return Ok(());
        };
        let Some(id) = suffix.strip_suffix(']') else {
            return Ok(());
        };
        let mut images = self
            .images
            .lock()
            .map_err(|_| "Image attachments are unavailable.")?;
        if images.get(id).is_some_and(|image| {
            image.project == item.project_id.as_str()
                && image.workspace == item.workspace_id.as_str()
                && image.session == item.session_id.as_str()
        }) {
            images.remove(id);
        }
        Ok(())
    }
}

fn validate_png(bytes: &[u8]) -> Result<(u32, u32), String> {
    if bytes.len() > 6 * 1024 * 1024 || !bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        return Err("Attach a PNG image up to 6 MiB.".into());
    }
    let mut reader = png::Decoder::new(std::io::Cursor::new(bytes))
        .read_info()
        .map_err(|_| "The image cannot be decoded.")?;
    let size = (reader.info().width, reader.info().height);
    if size.0 == 0 || size.1 == 0 || size.0 > 1280 || size.1 > 900 {
        return Err("Image dimensions exceed the attachment limit.".into());
    }
    let length = reader
        .output_buffer_size()
        .filter(|size| *size <= 8 * 1024 * 1024)
        .ok_or("Decoded image exceeds the attachment limit.")?;
    let mut decoded = vec![0; length];
    let result = reader
        .next_frame(&mut decoded)
        .map_err(|_| "The image is damaged.");
    decoded.fill(0);
    result?;
    Ok(size)
}
