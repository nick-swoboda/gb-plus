//! Authenticated transport catalogs and per-conversation model preferences.

use std::collections::BTreeSet;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::types::RuntimeTransport;
use crate::owner_state::OwnerStateRoot;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ModelDescriptor {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) context_window: Option<u64>,
    pub(crate) long_context_threshold: Option<u64>,
    pub(crate) accepts_images: Option<bool>,
    pub(crate) reasoning_efforts: Vec<String>,
}

impl ModelDescriptor {
    pub(crate) fn compact_at(&self) -> Option<u64> {
        // Integer floor avoids an f64 roundoff crossing a request boundary.
        let window = self
            .context_window
            .map(|value| value / 5 * 4 + value % 5 * 4 / 5);
        match (window, self.long_context_threshold) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ModelSelection {
    pub(crate) schema_version: u16,
    pub(crate) transport: RuntimeTransport,
    pub(crate) model: ModelDescriptor,
    pub(crate) reasoning_effort: Option<String>,
    pub(crate) verified_at: u64,
}

impl ModelSelection {
    pub(crate) fn load(root: &Path, transport: RuntimeTransport) -> Result<Option<Self>, String> {
        let file = OwnerStateRoot::new(root)
            .file("model-selection-v1.json", 16 * 1024)
            .map_err(|e| e.to_string())?;
        let record: Option<Self> = file
            .read()
            .map_err(|e| e.to_string())?
            .map(|bytes| {
                serde_json::from_slice(&bytes).map_err(|_| {
                    "Stored model selection is unreadable; it was retained.".to_owned()
                })
            })
            .transpose()?;
        if let Some(record) = &record {
            record.validate(transport)?;
        }
        Ok(record)
    }

    pub(crate) fn save(&self, root: &Path) -> Result<(), String> {
        self.validate(self.transport)?;
        let bytes = serde_json::to_vec(self).map_err(|e| e.to_string())?;
        OwnerStateRoot::new(root)
            .file("model-selection-v1.json", 16 * 1024)
            .map_err(|e| e.to_string())?
            .replace(&bytes)
            .map_err(|e| e.to_string())
    }

    fn validate(&self, transport: RuntimeTransport) -> Result<(), String> {
        if self.schema_version != 1
            || self.transport != transport
            || !identifier(&self.model.id)
            || self.model.name.len() > 256
            || self.model.reasoning_efforts.len() > 16
            || self
                .reasoning_effort
                .as_deref()
                .is_some_and(|value| !effort(value))
        {
            return Err("Model selection has an unsupported schema or invalid binding.".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ModelCatalog {
    pub(crate) transport: RuntimeTransport,
    pub(crate) models: Vec<ModelDescriptor>,
    pub(crate) selected: Option<ModelSelection>,
}

pub(crate) fn native_catalog(
    minimal: &Value,
    language: &Value,
) -> Result<Vec<ModelDescriptor>, String> {
    let rows = array(language, "models")?;
    let available = array(minimal, "data")?;
    let mut models = Vec::new();
    for row in rows {
        let id = model_id(row, "id")?;
        let Some(base) = available
            .iter()
            .find(|model| model.get("id").and_then(Value::as_str) == Some(id))
        else {
            continue;
        };
        if row
            .get("owned_by")
            .and_then(Value::as_str)
            .is_some_and(|owner| owner != "xai")
        {
            continue;
        }
        let modalities = row.get("input_modalities").and_then(Value::as_array);
        if modalities.is_some_and(|values| !values.iter().any(|v| v.as_str() == Some("text"))) {
            continue;
        }
        models.push(ModelDescriptor {
            id: id.into(),
            name: id.into(),
            context_window: positive(base.get("context_length"))
                .or_else(|| positive(row.get("context_length"))),
            long_context_threshold: positive(row.get("long_context_threshold")),
            accepts_images: modalities
                .map(|values| values.iter().any(|v| v.as_str() == Some("image"))),
            // The native catalog does not promise effort levels. Explicit
            // choices are admitted only by an exact live tool-capability probe.
            reasoning_efforts: Vec::new(),
        });
    }
    unique(models)
}

pub(crate) fn acp_catalog(value: &Value) -> Result<Vec<ModelDescriptor>, String> {
    parse_acp_catalog(value, false)
}

pub(crate) fn acp_catalog_for_engine(
    value: &Value,
    standard: bool,
) -> Result<Vec<ModelDescriptor>, String> {
    if standard {
        parse_acp_catalog(value, true)
    } else {
        acp_catalog(value)
    }
}

fn parse_acp_catalog(value: &Value, standard: bool) -> Result<Vec<ModelDescriptor>, String> {
    let mut models = Vec::new();
    for row in array(value, "availableModels")? {
        let id = model_id(row, "modelId")?;
        // No foreign provider delegation is implied by a CLI catalog entry.
        if !standard && !id.starts_with("grok-") && id != "grok" {
            continue;
        }
        let meta = &row["_meta"];
        let levels = meta.get("reasoningEfforts").and_then(Value::as_array);
        if levels.is_some_and(|levels| levels.len() > 16) {
            return Err("Model effort catalog exceeds its bound.".into());
        }
        let mut reasoning_efforts = Vec::new();
        for level in levels.into_iter().flatten() {
            let token = level
                .get("value")
                .and_then(Value::as_str)
                .ok_or("Model effort is malformed.")?;
            if !effort(token) {
                return Err("Model effort is not supported by this app.".into());
            }
            if !reasoning_efforts.iter().any(|v| v == token) {
                reasoning_efforts.push(token.into());
            }
        }
        models.push(ModelDescriptor {
            id: id.into(),
            name: row
                .get("name")
                .and_then(Value::as_str)
                .filter(|v| v.len() <= 256)
                .unwrap_or(id)
                .into(),
            context_window: positive(meta.get("totalContextTokens")),
            long_context_threshold: positive(meta.get("longContextThreshold")),
            accepts_images: meta
                .get("acceptsImages")
                .and_then(Value::as_bool)
                .or_else(|| {
                    meta.get("inputModalities")
                        .and_then(Value::as_array)
                        .map(|values| values.iter().any(|v| v.as_str() == Some("image")))
                }),
            reasoning_efforts,
        });
    }
    unique(models)
}

fn array<'a>(value: &'a Value, key: &str) -> Result<&'a Vec<Value>, String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .filter(|rows| rows.len() <= 512)
        .ok_or("Authenticated model catalog is missing or exceeds its bound.".into())
}
fn model_id<'a>(row: &'a Value, key: &str) -> Result<&'a str, String> {
    row.get(key)
        .and_then(Value::as_str)
        .filter(|id| identifier(id))
        .ok_or("Model catalog contains an invalid identity.".into())
}
fn unique(models: Vec<ModelDescriptor>) -> Result<Vec<ModelDescriptor>, String> {
    let mut ids = BTreeSet::new();
    if models.iter().any(|model| !ids.insert(&model.id)) {
        return Err("Authenticated catalog contains duplicate model identities.".into());
    }
    Ok(models)
}
pub(crate) fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:/".contains(&byte))
}
pub(crate) fn effort(value: &str) -> bool {
    matches!(
        value,
        "none" | "minimal" | "low" | "medium" | "high" | "xhigh" | "max"
    )
}
fn positive(value: Option<&Value>) -> Option<u64> {
    value.and_then(Value::as_u64).filter(|value| *value > 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn native_catalog_joins_authenticated_language_metadata_and_keeps_unknown_window() {
        let models = native_catalog(&json!({"data":[{"id":"grok-known","context_length":1001},{"id":"grok-unknown"}]}), &json!({"models":[{"id":"grok-known","input_modalities":["text","image"],"long_context_threshold":700},{"id":"grok-unknown","input_modalities":["text"],"long_context_threshold":0},{"id":"unauthorized"}]})).unwrap();
        assert_eq!(models.len(), 2);
        assert_eq!(models[0].compact_at(), Some(700));
        assert_eq!(models[0].accepts_images, Some(true));
        assert_eq!(models[1].compact_at(), None);
    }
    #[test]
    fn acp_catalog_excludes_foreign_models_and_requires_bounded_explicit_metadata() {
        let models = acp_catalog(&json!({"availableModels":[{"modelId":"foreign-model"},{"modelId":"grok-test","_meta":{"totalContextTokens":1001,"reasoningEfforts":[{"value":"high"}]}}]})).unwrap();
        assert_eq!(models.len(), 1);
        assert_eq!(models[0].compact_at(), Some(800));
        assert_eq!(models[0].accepts_images, None);
        assert_eq!(models[0].reasoning_efforts, vec!["high"]);
    }
}
