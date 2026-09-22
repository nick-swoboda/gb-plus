pub(crate) use crate::types::{
    BrokerAction, BrokerSecret, CredentialVersion, MAX_SECRET_BYTES, McpCredentialKey,
};
use std::fmt;
use std::io::{Read, Write};

const REQUEST_MAGIC: &[u8; 8] = b"GBKCBR1\0";
const MCP_REQUEST_MAGIC: &[u8; 8] = b"GBKCMR1\0";
const RESPONSE_MAGIC: &[u8; 8] = b"GBKCBS1\0";
const MAX_ERROR_BYTES: usize = 4 * 1024;
const REQUEST_HEADER_BYTES: usize = 14;
const RESPONSE_HEADER_BYTES: usize = 13;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CredentialTarget {
    Provider(CredentialVersion),
    Mcp(McpCredentialKey),
}

#[cfg(any(target_os = "macos", test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BrokerNamespace {
    Provider,
    Mcp,
}
#[cfg(any(target_os = "macos", test))]
impl BrokerNamespace {
    pub(crate) const fn accepts(self, target: CredentialTarget) -> bool {
        matches!(
            (self, target),
            (Self::Provider, CredentialTarget::Provider(_)) | (Self::Mcp, CredentialTarget::Mcp(_))
        )
    }
    #[cfg(target_os = "macos")]
    pub(crate) const fn executable(self) -> &'static str {
        match self {
            Self::Provider => crate::BROKER_EXECUTABLE_NAME,
            Self::Mcp => crate::MCP_BROKER_EXECUTABLE_NAME,
        }
    }
    #[cfg(target_os = "macos")]
    pub(crate) const fn identifier(self) -> &'static str {
        match self {
            Self::Provider => crate::BROKER_CODE_IDENTIFIER,
            Self::Mcp => crate::MCP_BROKER_CODE_IDENTIFIER,
        }
    }
}

pub(crate) struct Request {
    pub(crate) action: BrokerAction,
    pub(crate) target: CredentialTarget,
    pub(crate) secret: Option<BrokerSecret>,
}

impl fmt::Debug for Request {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Request")
            .field("action", &self.action)
            .field("target", &self.target)
            .field("secret", &self.secret.as_ref().map(|_| "[redacted]"))
            .finish()
    }
}

impl Request {
    #[cfg(test)]
    pub(crate) fn read_from(mut reader: impl Read) -> Result<Self, String> {
        let request = Self::read_frame_from(&mut reader)?;
        let mut trailing = [0_u8; 1];
        if reader
            .read(&mut trailing)
            .map_err(|_| "Keychain broker could not finish the request frame.".to_owned())?
            != 0
        {
            return Err("Keychain broker refused trailing request bytes.".into());
        }
        Ok(request)
    }

    pub(crate) fn read_socket_frame(mut reader: impl Read) -> Result<Self, String> {
        Self::read_frame_from(&mut reader)
    }

    fn read_frame_from(mut reader: impl Read) -> Result<Self, String> {
        let mut magic = [0_u8; 8];
        reader
            .read_exact(&mut magic)
            .map_err(|_| "Keychain broker received an incomplete request prefix.")?;
        let (action, target, length) = if &magic == REQUEST_MAGIC {
            let mut header = [0_u8; 6];
            reader
                .read_exact(&mut header)
                .map_err(|_| "Keychain broker received an incomplete provider header.")?;
            (
                BrokerAction::parse(header[0])?,
                CredentialTarget::Provider(CredentialVersion::parse(header[1])?),
                u32::from_be_bytes(header[2..6].try_into().expect("fixed slice")) as usize,
            )
        } else if &magic == MCP_REQUEST_MAGIC {
            let mut header = [0_u8; 37];
            reader
                .read_exact(&mut header)
                .map_err(|_| "Keychain broker received an incomplete MCP header.")?;
            (
                BrokerAction::parse(header[0])?,
                CredentialTarget::Mcp(McpCredentialKey::from_digest(
                    header[1..33].try_into().expect("fixed slice"),
                )),
                u32::from_be_bytes(header[33..37].try_into().expect("fixed slice")) as usize,
            )
        } else {
            return Err("Keychain broker refused an invalid request protocol.".into());
        };
        let expects_secret = action == BrokerAction::Store;
        if expects_secret != (length != 0) {
            return Err("Keychain broker refused an invalid operation payload.".into());
        }
        if length > MAX_SECRET_BYTES {
            return Err("Keychain broker refused an oversized request payload.".into());
        }
        if action == BrokerAction::Store
            && matches!(target,CredentialTarget::Provider(version) if version!=CredentialVersion::BrokerV3)
        {
            return Err("Keychain broker permits stores only to the broker-owned v3 item.".into());
        }
        let secret = if length == 0 {
            None
        } else {
            let mut bytes = vec![0_u8; length];
            reader
                .read_exact(&mut bytes)
                .map_err(|_| "Keychain broker received an incomplete secret payload.".to_owned())?;
            Some(BrokerSecret::new(bytes)?)
        };
        Ok(Self {
            action,
            target,
            secret,
        })
    }

    pub(crate) fn write_to(
        action: BrokerAction,
        version: CredentialVersion,
        secret: Option<&[u8]>,
        mut writer: impl Write,
    ) -> Result<(), String> {
        let length = secret.map_or(0, <[u8]>::len);
        if length > MAX_SECRET_BYTES
            || (action == BrokerAction::Store) != (length != 0)
            || (action == BrokerAction::Store && version != CredentialVersion::BrokerV3)
        {
            return Err("Keychain broker client refused an invalid request payload.".into());
        }
        let mut header = [0_u8; REQUEST_HEADER_BYTES];
        header[..8].copy_from_slice(REQUEST_MAGIC);
        header[8] = action as u8;
        header[9] = version as u8;
        let length = u32::try_from(length).map_err(|_| {
            "Keychain broker client refused an oversized request payload.".to_owned()
        })?;
        header[10..14].copy_from_slice(&length.to_be_bytes());
        writer
            .write_all(&header)
            .and_then(|()| {
                if let Some(secret) = secret {
                    writer.write_all(secret)
                } else {
                    Ok(())
                }
            })
            .and_then(|()| writer.flush())
            .map_err(|_| "Keychain broker request channel closed before completion.".to_owned())
    }
    pub(crate) fn write_mcp_to(
        action: BrokerAction,
        key: McpCredentialKey,
        secret: Option<&[u8]>,
        mut writer: impl Write,
    ) -> Result<(), String> {
        let length = secret.map_or(0, <[u8]>::len);
        if length > MAX_SECRET_BYTES || (action == BrokerAction::Store) != (length != 0) {
            return Err("Keychain MCP request payload refused.".into());
        }
        let mut header = [0_u8; 45];
        header[..8].copy_from_slice(MCP_REQUEST_MAGIC);
        header[8] = action as u8;
        header[9..41].copy_from_slice(&key.digest());
        header[41..45].copy_from_slice(
            &u32::try_from(length)
                .map_err(|_| "Keychain MCP payload bound")?
                .to_be_bytes(),
        );
        writer
            .write_all(&header)
            .and_then(|()| writer.write_all(secret.unwrap_or_default()))
            .and_then(|()| writer.flush())
            .map_err(|_| "Keychain MCP request channel ended.".into())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum ResponseStatus {
    Ok = 0,
    Absent = 1,
    Refused = 2,
    Error = 3,
}

impl ResponseStatus {
    fn parse(value: u8) -> Result<Self, String> {
        match value {
            0 => Ok(Self::Ok),
            1 => Ok(Self::Absent),
            2 => Ok(Self::Refused),
            3 => Ok(Self::Error),
            _ => Err("Keychain broker client refused an unknown response status.".into()),
        }
    }
}

pub(crate) struct Response {
    pub(crate) status: ResponseStatus,
    pub(crate) payload: Vec<u8>,
}

impl Drop for Response {
    fn drop(&mut self) {
        self.payload.fill(0);
    }
}

impl Response {
    pub(crate) fn ok(secret: Option<&[u8]>) -> Self {
        Self {
            status: ResponseStatus::Ok,
            payload: secret.map_or_else(Vec::new, <[u8]>::to_vec),
        }
    }

    pub(crate) fn absent() -> Self {
        Self {
            status: ResponseStatus::Absent,
            payload: Vec::new(),
        }
    }

    pub(crate) fn refused(reason: &str) -> Self {
        Self::message(ResponseStatus::Refused, reason)
    }

    pub(crate) fn error(reason: &str) -> Self {
        Self::message(ResponseStatus::Error, reason)
    }

    fn message(status: ResponseStatus, reason: &str) -> Self {
        let reason = bounded_message(reason);
        Self {
            status,
            payload: reason.into_bytes(),
        }
    }

    pub(crate) fn write_to(&self, mut writer: impl Write) -> Result<(), String> {
        let max = if self.status == ResponseStatus::Ok {
            MAX_SECRET_BYTES
        } else {
            MAX_ERROR_BYTES
        };
        if self.payload.len() > max {
            return Err("Keychain broker refused an oversized response.".into());
        }
        let mut header = [0_u8; RESPONSE_HEADER_BYTES];
        header[..8].copy_from_slice(RESPONSE_MAGIC);
        header[8] = self.status as u8;
        let length = u32::try_from(self.payload.len())
            .map_err(|_| "Keychain broker refused an oversized response.".to_owned())?;
        header[9..13].copy_from_slice(&length.to_be_bytes());
        writer
            .write_all(&header)
            .and_then(|()| writer.write_all(&self.payload))
            .and_then(|()| writer.flush())
            .map_err(|_| "Keychain broker response channel closed before completion.".to_owned())
    }

    #[cfg(test)]
    pub(crate) fn read_from(mut reader: impl Read) -> Result<Self, String> {
        let response = Self::read_frame_from(&mut reader)?;
        let mut trailing = [0_u8; 1];
        if reader
            .read(&mut trailing)
            .map_err(|_| "Keychain broker client could not finish the response frame.".to_owned())?
            != 0
        {
            return Err("Keychain broker client refused trailing response bytes.".into());
        }
        Ok(response)
    }

    pub(crate) fn read_socket_frame(mut reader: impl Read) -> Result<Self, String> {
        Self::read_frame_from(&mut reader)
    }

    fn read_frame_from(mut reader: impl Read) -> Result<Self, String> {
        let mut header = [0_u8; RESPONSE_HEADER_BYTES];
        reader
            .read_exact(&mut header)
            .map_err(|_| "Keychain broker returned an incomplete response header.".to_owned())?;
        if &header[..8] != RESPONSE_MAGIC {
            return Err("Keychain broker client refused an invalid response protocol.".into());
        }
        let status = ResponseStatus::parse(header[8])?;
        let length = u32::from_be_bytes(header[9..13].try_into().expect("fixed slice")) as usize;
        let max = if status == ResponseStatus::Ok {
            MAX_SECRET_BYTES
        } else {
            MAX_ERROR_BYTES
        };
        if length > max {
            return Err("Keychain broker client refused an oversized response payload.".into());
        }
        let mut payload = vec![0_u8; length];
        reader
            .read_exact(&mut payload)
            .map_err(|_| "Keychain broker returned an incomplete response payload.".to_owned())?;
        Ok(Self { status, payload })
    }

    pub(crate) fn take_secret(mut self) -> Result<BrokerSecret, String> {
        if self.status != ResponseStatus::Ok {
            return Err("Keychain broker response did not contain a secret.".into());
        }
        BrokerSecret::new(std::mem::take(&mut self.payload))
    }

    pub(crate) fn message_text(&self) -> String {
        let text = String::from_utf8_lossy(&self.payload);
        bounded_message(&text)
    }
}

fn bounded_message(reason: &str) -> String {
    let sanitized: String = reason
        .chars()
        .map(|character| {
            if character.is_control() && character != '\n' && character != '\t' {
                ' '
            } else {
                character
            }
        })
        .collect();
    if sanitized.len() <= MAX_ERROR_BYTES {
        return sanitized;
    }
    let mut end = MAX_ERROR_BYTES;
    while !sanitized.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &sanitized[..end.saturating_sub(3)])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_rejects_trailing_oversized_and_cross_version_store_frames() {
        let mut valid = Vec::new();
        Request::write_to(
            BrokerAction::Store,
            CredentialVersion::BrokerV3,
            Some(b"fixture-key"),
            &mut valid,
        )
        .expect("valid frame");
        let decoded = Request::read_from(valid.as_slice()).expect("decode valid frame");
        assert_eq!(decoded.action, BrokerAction::Store);
        assert_eq!(
            decoded.target,
            CredentialTarget::Provider(CredentialVersion::BrokerV3)
        );
        assert_eq!(
            decoded.secret.as_ref().expect("secret").as_slice(),
            b"fixture-key"
        );

        let mut trailing = valid.clone();
        trailing.push(0);
        assert!(Request::read_from(trailing.as_slice()).is_err());
        assert!(
            Request::write_to(
                BrokerAction::Store,
                CredentialVersion::StableV2,
                Some(b"fixture-key"),
                Vec::new()
            )
            .is_err()
        );
        assert!(
            Request::write_to(
                BrokerAction::Store,
                CredentialVersion::BrokerV3,
                Some(&vec![b'x'; MAX_SECRET_BYTES + 1]),
                Vec::new()
            )
            .is_err()
        );

        let response = Response::refused("fixture refusal");
        let mut encoded_response = Vec::new();
        response
            .write_to(&mut encoded_response)
            .expect("encode response frame");
        let decoded_response =
            Response::read_from(encoded_response.as_slice()).expect("decode response frame");
        assert_eq!(decoded_response.status, ResponseStatus::Refused);
        assert_eq!(decoded_response.message_text(), "fixture refusal");
        encoded_response.push(0);
        assert!(Response::read_from(encoded_response.as_slice()).is_err());
    }

    #[test]
    fn mcp_frames_cannot_select_a_provider_item_and_keep_every_action_bounded() {
        let first = McpCredentialKey::from_digest([0x11; 32]);
        let second = McpCredentialKey::from_digest([0x22; 32]);
        assert_ne!(first.account(), second.account());
        for version in [
            CredentialVersion::LegacyV1,
            CredentialVersion::StableV2,
            CredentialVersion::BrokerV3,
        ] {
            assert_ne!(first.account(), crate::provider_account(version));
        }
        for action in [
            BrokerAction::Inspect,
            BrokerAction::LoadInteractive,
            BrokerAction::LoadWithoutUi,
            BrokerAction::Store,
            BrokerAction::Delete,
        ] {
            let secret =
                (action == BrokerAction::Store).then_some(b"synthetic-mcp-token".as_slice());
            let mut bytes = Vec::new();
            Request::write_mcp_to(action, first, secret, &mut bytes).unwrap();
            let decoded = Request::read_from(bytes.as_slice()).unwrap();
            assert_eq!(decoded.target, CredentialTarget::Mcp(first));
            assert_eq!(decoded.action, action);
            for cut in 0..bytes.len() {
                assert!(Request::read_from(&bytes[..cut]).is_err());
            }
            bytes.push(0);
            assert!(Request::read_from(bytes.as_slice()).is_err());
        }
        assert!(
            Request::write_mcp_to(
                BrokerAction::Store,
                first,
                Some(&vec![0; MAX_SECRET_BYTES + 1]),
                Vec::new()
            )
            .is_err()
        );
        assert!(
            Request::write_mcp_to(BrokerAction::Delete, first, Some(b"unexpected"), Vec::new())
                .is_err()
        );
    }

    #[test]
    fn provider_and_mcp_helpers_refuse_each_others_targets() {
        let mcp = CredentialTarget::Mcp(McpCredentialKey::from_digest([1; 32]));
        assert!(BrokerNamespace::Mcp.accepts(mcp));
        assert!(!BrokerNamespace::Provider.accepts(mcp));
        for version in [
            CredentialVersion::LegacyV1,
            CredentialVersion::StableV2,
            CredentialVersion::BrokerV3,
        ] {
            let provider = CredentialTarget::Provider(version);
            assert!(BrokerNamespace::Provider.accepts(provider));
            assert!(!BrokerNamespace::Mcp.accepts(provider));
        }
    }

    #[test]
    fn provider_requests_keep_the_frozen_v1_helper_wire_bytes() {
        // Fixed vectors for the preserved provider binary's protocol, independent
        // of the new decoder and the separately versioned MCP framing.
        let mut load = Vec::new();
        Request::write_to(
            BrokerAction::LoadWithoutUi,
            CredentialVersion::BrokerV3,
            None,
            &mut load,
        )
        .unwrap();
        assert_eq!(load, b"GBKCBR1\0\x03\x03\0\0\0\0");
        let mut store = Vec::new();
        Request::write_to(
            BrokerAction::Store,
            CredentialVersion::BrokerV3,
            Some(b"fixture"),
            &mut store,
        )
        .unwrap();
        assert_eq!(store, b"GBKCBR1\0\x04\x03\0\0\0\x07fixture");
        let loaded = Request::read_socket_frame(load.as_slice()).unwrap();
        assert_eq!(loaded.action, BrokerAction::LoadWithoutUi);
    }

    #[test]
    fn socket_reply_variants_preserve_status_and_reject_incomplete_payloads() {
        for reply in [
            Response::ok(None),
            Response::absent(),
            Response::error("fixture failure"),
        ] {
            let mut bytes = Vec::new();
            reply.write_to(&mut bytes).unwrap();
            let decoded = Response::read_socket_frame(bytes.as_slice()).unwrap();
            assert_eq!(decoded.status, reply.status);
            assert_eq!(decoded.payload, reply.payload);
            if reply.status != ResponseStatus::Ok {
                assert!(decoded.take_secret().is_err());
            }
            assert!(Response::read_socket_frame(&bytes[..bytes.len() - 1]).is_err());
        }
        let mut bytes = Vec::new();
        Response::ok(Some(b"synthetic token"))
            .write_to(&mut bytes)
            .unwrap();
        assert_eq!(
            Response::read_socket_frame(bytes.as_slice())
                .unwrap()
                .take_secret()
                .unwrap()
                .as_slice(),
            b"synthetic token"
        );
    }

    #[test]
    fn secret_debug_and_drop_contract_never_format_bytes() {
        let secret = BrokerSecret::new(b"do-not-format".to_vec()).expect("secret");
        assert_eq!(format!("{secret:?}"), "BrokerSecret([redacted])");
    }
}
