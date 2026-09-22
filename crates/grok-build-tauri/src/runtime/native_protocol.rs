//! Explicit per-conversation protocol preference. Default remains HTTP.
use crate::owner_state::OwnerStateRoot;
use serde::{Deserialize, Serialize};
use std::path::Path;
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum NativeProtocol {
    #[default]
    Http,
    #[serde(rename = "websocket")]
    WebSocket,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Preference {
    schema_version: u16,
    protocol: NativeProtocol,
    verified_at: u64,
}
impl NativeProtocol {
    pub(crate) fn load(root: &Path) -> Result<Self, String> {
        let Some(bytes) = file(root)?.read().map_err(|e| e.to_string())? else {
            return Ok(Self::Http);
        };
        let value: Preference = serde_json::from_slice(&bytes).map_err(
            |_| "Native protocol preference is unreadable; its original bytes remain recoverable.",
        )?;
        if value.schema_version != 1 || value.verified_at == 0 {
            return Err(
                "Native protocol preference has an unsupported version or verification state."
                    .into(),
            );
        }
        Ok(value.protocol)
    }
    // Caller holds idle scheduler ownership, has completed the exact selected
    // model/tool probe using this protocol, closed it, and revalidated app scope.
    pub(crate) fn save_verified(self, root: &Path) -> Result<(), String> {
        let value = Preference {
            schema_version: 1,
            protocol: self,
            verified_at: crate::runtime::types::unix_time_millis(),
        };
        file(root)?
            .replace(&serde_json::to_vec(&value).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())
    }
}
fn file(root: &Path) -> Result<crate::owner_state::OwnerStateFile, String> {
    OwnerStateRoot::new(root)
        .file("native-protocol-v1.json", 4096)
        .map_err(|e| e.to_string())
}

// Reads existing local model parameters only; never sends or reconstructs data.
pub(crate) fn current_model(root: &Path) -> Result<(String, Option<String>), String> {
    if let Some(selection) =
        super::models::ModelSelection::load(root, super::types::RuntimeTransport::XaiKeychain)?
    {
        return Ok((selection.model.id, selection.reasoning_effort));
    }
    let journal = super::responses::ResponsesJournal::open(root)?;
    Ok((
        journal.model().into(),
        journal.reasoning_effort().map(str::to_owned),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn protocol_choice_is_explicit_scoped_and_unknown_versions_remain_recoverable() {
        let root = std::env::temp_dir().join(format!(
            "gbplus-native-protocol-{}-{}",
            std::process::id(),
            crate::runtime::types::unix_time_millis()
        ));
        let first = root.join("first");
        let other = root.join("other");
        assert_eq!(NativeProtocol::load(&first).unwrap(), NativeProtocol::Http);
        NativeProtocol::WebSocket.save_verified(&first).unwrap();
        assert_eq!(
            NativeProtocol::load(&first).unwrap(),
            NativeProtocol::WebSocket
        );
        assert_eq!(NativeProtocol::load(&other).unwrap(), NativeProtocol::Http);
        let owner = file(&first).unwrap();
        let unavailable = br#"{"schemaVersion":99,"protocol":"websocket","verifiedAt":1}"#;
        owner.replace(unavailable).unwrap();
        assert!(NativeProtocol::load(&first).is_err());
        assert_eq!(owner.read().unwrap().unwrap(), unavailable);
        NativeProtocol::Http.save_verified(&first).unwrap();
        assert_eq!(NativeProtocol::load(&first).unwrap(), NativeProtocol::Http);
        std::fs::remove_dir_all(root).unwrap();
    }
}
