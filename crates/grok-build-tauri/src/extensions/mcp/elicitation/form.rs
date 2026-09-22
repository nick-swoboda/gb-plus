//! A bounded primitive form subset; unsupported constraints are never ignored.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use serde_json::Value;

const MAX_NUMBER: f64 = 9_007_199_254_740_991.0;

#[derive(Clone)]
pub(super) struct Form {
    pub(super) fields: Vec<Field>,
    schemas: BTreeMap<String, Value>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Field {
    name: String,
    title: String,
    description: String,
    kind: String,
    required: bool,
    options: Vec<String>,
    default: Option<Value>,
    constraints: Value,
}

impl Form {
    pub(super) fn parse(schema: &Value) -> Result<Self, String> {
        let object = schema
            .as_object()
            .ok_or("MCP form schema must be an object.")?;
        if schema["type"] != "object"
            || object.keys().any(|key| {
                !matches!(
                    key.as_str(),
                    "type" | "properties" | "required" | "additionalProperties" | "$schema"
                )
            })
            || schema
                .get("additionalProperties")
                .is_some_and(|v| !v.is_boolean())
            || schema.to_string().len() > 32 * 1024
        {
            return Err("MCP form uses unsupported or oversized object constraints.".into());
        }
        let properties = schema["properties"]
            .as_object()
            .filter(|p| !p.is_empty() && p.len() <= 16)
            .ok_or("MCP forms support one to sixteen primitive fields.")?;
        let mut required = BTreeSet::new();
        if let Some(value) = schema.get("required") {
            for item in value
                .as_array()
                .filter(|items| items.len() <= 16)
                .ok_or("MCP required fields are invalid.")?
            {
                let name = item
                    .as_str()
                    .filter(|name| properties.contains_key(*name))
                    .ok_or("MCP required field is absent.")?;
                if !required.insert(name) {
                    return Err("MCP required field is duplicated.".into());
                }
            }
        }
        let mut fields = Vec::new();
        let mut schemas = BTreeMap::new();
        for (name, schema) in properties {
            let field = parse_field(name, schema, required.contains(name.as_str()))?;
            if let Some(value) = &field.default {
                validate_value(&field, schema, value)?;
            }
            fields.push(field);
            schemas.insert(name.clone(), schema.clone());
        }
        Ok(Self { fields, schemas })
    }

    pub(super) fn validate(&self, content: &Value) -> Result<(), String> {
        let values = content
            .as_object()
            .filter(|value| value.len() <= 16)
            .ok_or("MCP form answer must be a bounded object.")?;
        if content.to_string().len() > 32 * 1024
            || values.keys().any(|key| !self.schemas.contains_key(key))
        {
            return Err("MCP form answer contains an unknown field or exceeds its bound.".into());
        }
        for field in &self.fields {
            match values.get(&field.name) {
                Some(value) => validate_value(field, &self.schemas[&field.name], value)?,
                None if field.required => {
                    return Err(format!("Complete the required field: {}.", field.title));
                }
                None => {}
            }
        }
        Ok(())
    }
}

fn parse_field(name: &str, schema: &Value, required: bool) -> Result<Field, String> {
    let object = schema
        .as_object()
        .ok_or("MCP field schema must be an object.")?;
    let kind = schema["type"]
        .as_str()
        .filter(|kind| matches!(*kind, "string" | "number" | "integer" | "boolean"))
        .ok_or("MCP form field type is not in the supported primitive subset.")?;
    if name.is_empty()
        || name.len() > 128
        || name.chars().any(char::is_control)
        || credential_field(name)
        || object.keys().any(|key| !match key.as_str() {
            "type" | "title" | "description" | "default" => true,
            "minLength" | "maxLength" | "enum" | "format" => kind == "string",
            "minimum" | "maximum" => matches!(kind, "number" | "integer"),
            _ => false,
        })
    {
        return Err("MCP form requests a credential or an unsupported field constraint.".into());
    }
    let title = bounded_text(schema.get("title"), name, 256)?;
    if title.trim().is_empty() || credential_field(&title) {
        return Err("Credentials cannot be collected through an MCP form.".into());
    }
    let description = bounded_text(schema.get("description"), "", 2048)?;
    let mut options = Vec::new();
    if let Some(choices) = schema.get("enum") {
        for choice in choices
            .as_array()
            .filter(|choices| !choices.is_empty() && choices.len() <= 32)
            .ok_or("MCP form choices exceeded their bound.")?
        {
            let choice = bounded_text(Some(choice), "", 512)?;
            if options.contains(&choice) {
                return Err("MCP form choice is duplicated.".into());
            }
            options.push(choice);
        }
    }
    for key in ["minLength", "maxLength"] {
        if schema
            .get(key)
            .is_some_and(|value| value.as_u64().is_none_or(|value| value > 4096))
        {
            return Err("MCP form string length is invalid or exceeds 4096 characters.".into());
        }
    }
    if schema["minLength"].as_u64().unwrap_or(0) > schema["maxLength"].as_u64().unwrap_or(4096) {
        return Err("MCP form string bounds are inconsistent.".into());
    }
    for key in ["minimum", "maximum"] {
        if schema.get(key).is_some_and(|value| {
            value
                .as_f64()
                .is_none_or(|value| !value.is_finite() || value.abs() > MAX_NUMBER)
        }) {
            return Err("MCP form numeric bound is outside exact browser-safe limits.".into());
        }
    }
    if schema["minimum"].as_f64().unwrap_or(-MAX_NUMBER)
        > schema["maximum"].as_f64().unwrap_or(MAX_NUMBER)
    {
        return Err("MCP form numeric bounds are inconsistent.".into());
    }
    if schema.get("format").is_some_and(|value| {
        !matches!(value.as_str(), Some("email" | "uri" | "date" | "date-time"))
    }) {
        return Err("MCP form string format is unsupported.".into());
    }
    Ok(Field {
        name: name.into(),
        title,
        description,
        kind: kind.into(),
        required,
        options,
        default: schema.get("default").cloned(),
        constraints: serde_json::json!({"minLength":schema.get("minLength"),"maxLength":schema.get("maxLength"),
            "minimum":schema.get("minimum"),"maximum":schema.get("maximum"),"format":schema.get("format")}),
    })
}

fn bounded_text(value: Option<&Value>, fallback: &str, maximum: usize) -> Result<String, String> {
    let value = match value {
        Some(value) => value.as_str().ok_or("MCP form text is not a string.")?,
        None => fallback,
    };
    if value.len() > maximum
        || value
            .chars()
            .any(|c| c.is_control() && !matches!(c, '\n' | '\t'))
    {
        return Err("MCP form text is invalid or oversized.".into());
    }
    Ok(value.into())
}

fn validate_value(field: &Field, schema: &Value, value: &Value) -> Result<(), String> {
    let valid = match field.kind.as_str() {
        "string" => value.as_str().is_some_and(|text| {
            let length = text.chars().count() as u64;
            length <= 4096
                && length >= schema["minLength"].as_u64().unwrap_or(0)
                && length <= schema["maxLength"].as_u64().unwrap_or(4096)
                && (field.options.is_empty() || field.options.iter().any(|option| option == text))
                && !sensitive_value(text)
                && valid_format(text, schema["format"].as_str())
        }),
        "boolean" => value.is_boolean(),
        "number" | "integer" => value.as_f64().is_some_and(|number| {
            number.is_finite()
                && number.abs() <= MAX_NUMBER
                && (field.kind != "integer" || number.fract() == 0.0)
                && number >= schema["minimum"].as_f64().unwrap_or(-MAX_NUMBER)
                && number <= schema["maximum"].as_f64().unwrap_or(MAX_NUMBER)
        }),
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(format!(
            "Review the type, limits or private data in field: {}.",
            field.title
        ))
    }
}

fn sensitive_value(value: &str) -> bool {
    ["xai-", "sk-", "ghp_", "gho_", "Bearer "]
        .iter()
        .any(|prefix| value.starts_with(prefix))
        || value.contains("-----BEGIN") && value.contains("PRIVATE KEY-----")
}

fn credential_field(value: &str) -> bool {
    let name: String = value
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_lowercase())
        .collect();
    super::super::super::credentials::credential_name(value)
        || matches!(
            name.as_str(),
            "cardnumber"
                | "creditcard"
                | "creditcardnumber"
                | "paymentcard"
                | "securitycode"
                | "cvv"
                | "cvc"
                | "pin"
                | "pincode"
        )
}

fn valid_format(text: &str, format: Option<&str>) -> bool {
    match format {
        None => true,
        Some("uri") => tauri::Url::parse(text).is_ok(),
        Some("email") => {
            text.len() <= 320
                && !text.chars().any(char::is_whitespace)
                && text.split_once('@').is_some_and(|(local, domain)| {
                    !local.is_empty()
                        && !domain.contains('@')
                        && domain.contains('.')
                        && !domain.starts_with('.')
                        && !domain.ends_with('.')
                })
        }
        Some("date") => valid_date(text),
        Some("date-time") => valid_datetime(text),
        _ => false,
    }
}

fn valid_date(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.len() != 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes
            .iter()
            .enumerate()
            .any(|(i, b)| i != 4 && i != 7 && !b.is_ascii_digit())
    {
        return false;
    }
    let year: u16 = text[..4].parse().unwrap_or(0);
    let month: usize = text[5..7].parse().unwrap_or(0);
    let day: u8 = text[8..].parse().unwrap_or(0);
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let days = [
        0,
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    (1..=12).contains(&month) && day > 0 && day <= days[month]
}

fn valid_datetime(text: &str) -> bool {
    let Some((date, time)) = text.split_once(['T', 't']) else {
        return false;
    };
    if !valid_date(date) {
        return false;
    }
    let time = if let Some(time) = time.strip_suffix(['Z', 'z']) {
        time
    } else {
        let Some(index) = time.rfind(['+', '-']) else {
            return false;
        };
        let zone = &time[index + 1..];
        if zone.len() != 5
            || zone.as_bytes()[2] != b':'
            || !zone[..2].parse::<u8>().is_ok_and(|h| h <= 23)
            || !zone[3..].parse::<u8>().is_ok_and(|m| m <= 59)
        {
            return false;
        }
        &time[..index]
    };
    let (whole, fraction) = time
        .split_once('.')
        .map_or((time, None), |(whole, part)| (whole, Some(part)));
    if fraction.is_some_and(|part| {
        part.is_empty() || part.len() > 32 || !part.bytes().all(|b| b.is_ascii_digit())
    }) {
        return false;
    }
    let bytes = whole.as_bytes();
    bytes.len() == 8
        && bytes[2] == b':'
        && bytes[5] == b':'
        && bytes
            .iter()
            .enumerate()
            .all(|(i, b)| i == 2 || i == 5 || b.is_ascii_digit())
        && whole[..2].parse::<u8>().is_ok_and(|h| h <= 23)
        && whole[3..5].parse::<u8>().is_ok_and(|m| m <= 59)
        && whole[6..].parse::<u8>().is_ok_and(|s| s <= 59)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn form_constraints_types_and_sensitive_values_are_enforced_before_send() {
        let form = Form::parse(&json!({"type":"object","properties":{
            "name":{"type":"string","minLength":2,"maxLength":20},
            "count":{"type":"integer","minimum":1,"maximum":3},
            "confirm":{"type":"boolean"},"color":{"type":"string","enum":["red","blue"]}
        },"required":["name","confirm"]}))
        .unwrap();
        form.validate(&json!({"name":"Alex","confirm":false,"count":2,"color":"blue"}))
            .unwrap();
        for answer in [
            json!({"name":"A","confirm":true}),
            json!({"name":"Alex"}),
            json!({"name":"Alex","confirm":"true"}),
            json!({"name":"Alex","confirm":true,"count":2.5}),
            json!({"name":"Alex","confirm":true,"extra":"x"}),
            json!({"name":"sk-private","confirm":true}),
            json!({"name":"Alex","confirm":true,"color":"green"}),
        ] {
            assert!(form.validate(&answer).is_err());
        }
        for field in [
            json!({"type":"string","pattern":".*"}),
            json!({"type":"object"}),
            json!({"type":"string","title":"Password"}),
            json!({"type":"string","title":"Credit card number"}),
            json!({"type":"string","minLength":10,"maxLength":1}),
        ] {
            assert!(Form::parse(&json!({"type":"object","properties":{"value":field}})).is_err());
        }
    }
    #[test]
    fn date_formats_check_calendar_timezone_and_numeric_bounds() {
        assert!(valid_date("2024-02-29"));
        assert!(!valid_date("2025-02-29"));
        assert!(valid_datetime("2026-09-10T12:34:56.123-07:00"));
        for invalid in [
            "2026-09-10T24:00:00Z",
            "2026-09-10T00:00:00",
            "2026-09-10T00:00:00+😎:",
            "2026-09-31T00:00:00Z",
        ] {
            assert!(!valid_datetime(invalid));
        }
    }
}
