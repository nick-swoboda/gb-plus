//! Durable permission decisions contain identities, never credentials or tool data.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{McpCatalog, McpTool};
use crate::ProjectId;

const MAX_POLICIES: usize = 256;
/// Maximum encoded permission book; callers use owner-only atomic persistence.
pub const MCP_MAX_PERMISSION_BYTES: usize = 128 * 1024;

/// App classification is independent of server annotations. Unknown stays Ask.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum McpEffectClass {
    /// Reviewed app classification for this exact bound tool fingerprint.
    ReviewedReadOnly,
    /// The tool can change state.
    Mutating,
    /// Its effects have not been classified by the app.
    Unclassified,
}

/// User decision for an exact project/server/tool/schema binding.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum McpToolPolicy {
    /// Every invocation requires a separate, identified approval.
    Ask,
    /// Reusable only while the app still classifies this binding as read-only.
    AllowReviewedReadOnly,
    /// Refuse this bound tool without prompting.
    Deny,
}

/// Result of permission inspection, not a dispatched invocation or effect receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum McpPermissionDecision {
    /// A matching durable read-only approval exists.
    AllowedReadOnly,
    /// Require approval for the current identified invocation and exact arguments.
    ApprovalRequired,
    /// A matching explicit denial exists.
    Denied,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PolicyRecord {
    fingerprint: String,
    policy: McpToolPolicy,
}

/// Versioned project permission book. Construct and update it behind the same
/// owner-only record's exclusive writer lock; never deserialize frontend input
/// into a catalog or treat a provider field as an app project identity.
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct McpPermissionBook {
    version: u16,
    project: ProjectId,
    revision: u64,
    policies: BTreeMap<String, PolicyRecord>,
}

impl McpPermissionBook {
    /// Decode bounded persisted state for the Rust-resolved project. Missing
    /// state defaults to Ask. Unknown versions and malformed bytes are refused;
    /// the caller must retain those bytes rather than reset them automatically.
    ///
    /// # Errors
    /// Refuses unknown versions, moved/cross-project books, malformed identities,
    /// and count/byte budget violations.
    pub fn restore(project: &ProjectId, bytes: Option<&[u8]>) -> Result<Self, String> {
        if project.as_str().is_empty()
            || project.as_str().len() > 256
            || project.as_str().chars().any(char::is_control)
        {
            return Err("MCP permission project identity is invalid.".into());
        }
        let mut book = match bytes {
            Some(bytes) if bytes.len() <= MCP_MAX_PERMISSION_BYTES => {
                serde_json::from_slice::<Self>(bytes)
                    .map_err(|_| "MCP permissions are unreadable; retain their original bytes.")?
            }
            Some(_) => return Err("MCP permission byte budget exceeded.".into()),
            None => Self {
                version: 2,
                project: project.clone(),
                revision: 0,
                policies: BTreeMap::new(),
            },
        };
        if !matches!(book.version, 1 | 2)
            || &book.project != project
            || book.policies.len() > MAX_POLICIES
        {
            return Err("Unknown, moved or oversized MCP permissions remain unavailable.".into());
        }
        if book.policies.iter().any(|(name, record)| {
            name.strip_prefix("gbext_").is_none_or(|suffix| {
                !hex(
                    suffix,
                    if book.version == 1 {
                        56
                    } else {
                        super::MCP_APP_TOOL_HASH_HEX_LENGTH
                    },
                )
            }) || !hex(&record.fingerprint, 64)
                || record.policy == McpToolPolicy::Ask
        }) {
            return Err("MCP permissions contain an invalid binding.".into());
        }
        if book.version == 1 {
            // The old name exceeded the CLI's fully qualified name limit.
            // Preserve denials while requiring new review of any reusable grant.
            // Original bytes remain untouched until the caller's backed-up commit.
            let mut shortened = BTreeMap::new();
            let mut seen = std::collections::BTreeSet::new();
            for (name, record) in book.policies {
                let name = name[..6 + super::MCP_APP_TOOL_HASH_HEX_LENGTH].to_owned();
                if !seen.insert(name.clone()) {
                    return Err(
                        "Legacy MCP name migration collided; retain the original permissions."
                            .into(),
                    );
                }
                if record.policy == McpToolPolicy::Deny {
                    shortened.insert(name, record);
                }
            }
            book.policies = shortened;
            book.version = 2;
            book.revision = book
                .revision
                .checked_add(1)
                .ok_or("MCP permission revision exhausted.")?;
        }
        Ok(book)
    }

    /// Revision shown in the approval UI and required for a later edit.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Inspect only a complete, still-valid catalog owned by this project.
    /// Metadata claims cannot affect this decision. A changed fingerprint always
    /// requires review, even if its app tool name remains the same.
    ///
    /// # Errors
    /// Refuses a foreign project, stale catalog, or unknown tool name.
    pub fn decision(
        &self,
        catalog: &McpCatalog,
        app_name: &str,
        class: McpEffectClass,
    ) -> Result<McpPermissionDecision, String> {
        let tool = self.resolve(catalog, app_name)?;
        Ok(
            match self
                .policies
                .get(app_name)
                .filter(|r| r.fingerprint == tool.fingerprint())
            {
                Some(record) if record.policy == McpToolPolicy::Deny => {
                    McpPermissionDecision::Denied
                }
                Some(record)
                    if record.policy == McpToolPolicy::AllowReviewedReadOnly
                        && class == McpEffectClass::ReviewedReadOnly =>
                {
                    McpPermissionDecision::AllowedReadOnly
                }
                _ => McpPermissionDecision::ApprovalRequired,
            },
        )
    }

    /// Apply an explicit UI decision to the exact previewed binding. The caller
    /// resolves catalog and classification from app state, then atomically writes
    /// and reads back `persist` bytes while retaining the writer lock. An error
    /// never changes in-memory authority. On an uncertain write, reload the file
    /// and reconcile; never retry an invocation as a consequence of this method.
    ///
    /// # Errors
    /// Refuses stale UI revisions/fingerprints, unsupported reusable grants,
    /// invalidated catalogs, capacity exhaustion, and failed durable commits.
    pub fn change(
        &mut self,
        catalog: &McpCatalog,
        review: &McpPermissionReview<'_>,
        persist: &mut impl FnMut(&[u8]) -> Result<(), String>,
    ) -> Result<(), String> {
        let tool = self.resolve(catalog, review.app_name)?;
        if review.revision != self.revision || review.fingerprint != tool.fingerprint() {
            return Err("MCP permission preview changed. Review the current tool again.".into());
        }
        if review.policy == McpToolPolicy::AllowReviewedReadOnly
            && review.class != McpEffectClass::ReviewedReadOnly
        {
            return Err("Mutating or unclassified MCP calls require individual approval.".into());
        }
        let mut next = self.clone();
        if review.policy == McpToolPolicy::Ask {
            next.policies.remove(review.app_name);
        } else {
            next.policies.insert(
                review.app_name.to_owned(),
                PolicyRecord {
                    fingerprint: tool.fingerprint().to_owned(),
                    policy: review.policy,
                },
            );
        }
        if next.policies.len() > MAX_POLICIES {
            return Err("MCP permission capacity reached. Revoke a policy first.".into());
        }
        next.revision = next
            .revision
            .checked_add(1)
            .ok_or("MCP permission revision exhausted.")?;
        let bytes = serde_json::to_vec(&next).map_err(|_| "Cannot encode MCP permissions.")?;
        if bytes.len() > MCP_MAX_PERMISSION_BYTES {
            return Err("MCP permission byte budget exceeded.".into());
        }
        persist(&bytes)?;
        *self = next;
        Ok(())
    }

    fn resolve<'a>(&self, catalog: &'a McpCatalog, name: &str) -> Result<&'a McpTool, String> {
        if catalog.project() != &self.project {
            return Err("MCP permission book belongs to another project.".into());
        }
        catalog.resolve(name)
    }
}

/// App-resolved review inputs. Only policy, revision, app name and fingerprint
/// are UI selections; classification must be supplied independently by Rust.
pub struct McpPermissionReview<'a> {
    /// Revision presented to the user.
    pub revision: u64,
    /// Namespaced tool displayed in that preview.
    pub app_name: &'a str,
    /// Exact fingerprint displayed in that preview.
    pub fingerprint: &'a str,
    /// User's selected policy.
    pub policy: McpToolPolicy,
    /// App classification bound to this exact tool's metadata and server.
    pub class: McpEffectClass,
}

fn hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
#[path = "permissions_tests.rs"]
mod tests;
