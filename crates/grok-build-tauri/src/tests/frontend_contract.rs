use std::collections::{BTreeMap, BTreeSet};

pub(super) struct CssContract<'a> {
    source: &'a str,
}

impl<'a> CssContract<'a> {
    pub(super) const fn parse(source: &'a str) -> Self {
        Self { source }
    }

    pub(super) fn property(&self, selector: &str, property: &str) -> &'a str {
        let marker = format!("{selector} {{");
        for (offset, _) in self.source.match_indices(&marker) {
            if offset != 0 && self.source.as_bytes().get(offset - 1) != Some(&b'\n') {
                continue;
            }
            let body = self.source[offset + marker.len()..]
                .split_once('}')
                .map(|(body, _)| body)
                .unwrap_or_default();
            for declaration in body.split(';') {
                let Some((name, value)) = declaration.split_once(':') else {
                    continue;
                };
                if name.trim() == property {
                    return value.trim();
                }
            }
        }
        panic!("missing CSS property {property:?} on selector {selector:?}");
    }

    pub(super) fn hard_coded_pixel_font_sizes(&self) -> Vec<f32> {
        self.source
            .split(';')
            .filter_map(|declaration| declaration.rsplit_once("font-size:"))
            .filter_map(|(_, value)| value.trim().strip_suffix("px"))
            .filter_map(|value| value.trim().parse().ok())
            .collect()
    }
}

#[derive(Debug)]
struct Tag {
    name: String,
    attributes: BTreeMap<String, String>,
    offset: usize,
}

pub(super) struct HtmlContract {
    tags: Vec<Tag>,
}

impl HtmlContract {
    pub(super) fn parse(source: &str) -> Self {
        let mut tags = Vec::new();
        let mut cursor = 0;
        while let Some(relative_start) = source[cursor..].find('<') {
            let start = cursor + relative_start;
            let Some(relative_end) = source[start..].find('>') else {
                break;
            };
            let end = start + relative_end;
            let body = source[start + 1..end].trim();
            if !body.starts_with(['!', '?', '/'])
                && let Some(tag) = parse_tag(body, start)
            {
                tags.push(tag);
            }
            cursor = end + 1;
        }
        Self { tags }
    }

    pub(super) fn require_id(&self, id: &str) {
        assert!(self.element(id).is_some(), "missing element #{id}");
    }

    pub(super) fn require_attribute(&self, id: &str, name: &str, value: &str) {
        let tag = self
            .element(id)
            .unwrap_or_else(|| panic!("missing element #{id}"));
        assert_eq!(tag.attributes.get(name).map(String::as_str), Some(value));
    }

    pub(super) fn assert_unique_ids(&self) {
        let mut ids = BTreeSet::new();
        for tag in &self.tags {
            if let Some(id) = tag.attributes.get("id") {
                assert!(ids.insert(id), "duplicate element id {id}");
            }
        }
    }

    pub(super) fn before(&self, first: &str, second: &str) -> bool {
        self.element(first).expect("first element").offset
            < self.element(second).expect("second element").offset
    }

    pub(super) fn module_sources(&self) -> Vec<&str> {
        self.tags
            .iter()
            .filter(|tag| tag.name == "script")
            .filter(|tag| {
                tag.attributes
                    .get("type")
                    .is_some_and(|value| value == "module")
            })
            .filter_map(|tag| tag.attributes.get("src").map(String::as_str))
            .collect()
    }

    pub(super) fn focus_order(&self) -> Vec<&str> {
        self.tags
            .iter()
            .filter(|tag| !tag.attributes.contains_key("hidden"))
            .filter(|tag| !tag.attributes.contains_key("disabled"))
            .filter(|tag| {
                matches!(
                    tag.name.as_str(),
                    "button" | "input" | "select" | "textarea"
                ) || tag.name == "a" && tag.attributes.contains_key("href")
                    || tag
                        .attributes
                        .get("tabindex")
                        .is_some_and(|value| value != "-1")
            })
            .filter_map(|tag| tag.attributes.get("id").map(String::as_str))
            .collect()
    }

    fn element(&self, id: &str) -> Option<&Tag> {
        self.tags
            .iter()
            .find(|tag| tag.attributes.get("id").is_some_and(|value| value == id))
    }
}

fn parse_tag(body: &str, offset: usize) -> Option<Tag> {
    let bytes = body.as_bytes();
    let mut cursor = 0;
    let name = take_while(body, &mut cursor, |byte| {
        !byte.is_ascii_whitespace() && byte != b'/'
    });
    if name.is_empty() {
        return None;
    }
    let mut attributes = BTreeMap::new();
    while cursor < bytes.len() {
        skip_while(body, &mut cursor, |byte| {
            byte.is_ascii_whitespace() || byte == b'/'
        });
        let key = take_while(body, &mut cursor, |byte| {
            !byte.is_ascii_whitespace() && !matches!(byte, b'=' | b'/')
        });
        if key.is_empty() {
            break;
        }
        skip_while(body, &mut cursor, |byte| byte.is_ascii_whitespace());
        let value = if bytes.get(cursor) == Some(&b'=') {
            cursor += 1;
            skip_while(body, &mut cursor, |byte| byte.is_ascii_whitespace());
            match bytes.get(cursor).copied() {
                Some(quote @ (b'\'' | b'"')) => {
                    cursor += 1;
                    let start = cursor;
                    while bytes.get(cursor).is_some_and(|byte| *byte != quote) {
                        cursor += 1;
                    }
                    let value = body[start..cursor].to_owned();
                    cursor = cursor.saturating_add(1);
                    value
                }
                _ => take_while(body, &mut cursor, |byte| {
                    !byte.is_ascii_whitespace() && byte != b'/'
                })
                .to_owned(),
            }
        } else {
            String::new()
        };
        attributes.insert(key.to_owned(), value);
    }
    Some(Tag {
        name: name.to_owned(),
        attributes,
        offset,
    })
}

fn take_while<'a>(source: &'a str, cursor: &mut usize, keep: impl Fn(u8) -> bool) -> &'a str {
    let start = *cursor;
    while source
        .as_bytes()
        .get(*cursor)
        .is_some_and(|byte| keep(*byte))
    {
        *cursor += 1;
    }
    &source[start..*cursor]
}

fn skip_while(source: &str, cursor: &mut usize, skip: impl Fn(u8) -> bool) {
    while source
        .as_bytes()
        .get(*cursor)
        .is_some_and(|byte| skip(*byte))
    {
        *cursor += 1;
    }
}

pub(super) fn assert_no_forbidden_javascript_apis(sources: &[&str]) {
    for source in sources {
        let tokens = javascript_tokens(source);
        assert!(!tokens.iter().any(|token| token == "innerHTML"));
        assert!(!tokens.iter().any(|token| token == "eval"));
        assert!(
            !tokens
                .windows(3)
                .any(|tokens| tokens == ["document", ".", "write"])
        );
    }
}

fn javascript_tokens(source: &str) -> Vec<String> {
    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let mut cursor = 0;
    while cursor < bytes.len() {
        if bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        } else if matches!(bytes[cursor], b'\'' | b'"' | b'`') {
            let quote = bytes[cursor];
            cursor += 1;
            while cursor < bytes.len() {
                if bytes[cursor] == b'\\' {
                    cursor = cursor.saturating_add(2);
                } else if bytes[cursor] == quote {
                    cursor += 1;
                    break;
                } else {
                    cursor += 1;
                }
            }
        } else if bytes[cursor..].starts_with(b"//") {
            cursor += bytes[cursor..]
                .iter()
                .position(|byte| *byte == b'\n')
                .unwrap_or(bytes.len() - cursor);
        } else if bytes[cursor..].starts_with(b"/*") {
            cursor += bytes[cursor + 2..]
                .windows(2)
                .position(|pair| pair == b"*/")
                .map_or(bytes.len() - cursor, |length| length + 4);
        } else if bytes[cursor].is_ascii_alphabetic() || matches!(bytes[cursor], b'_' | b'$') {
            let start = cursor;
            cursor += 1;
            while bytes
                .get(cursor)
                .is_some_and(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$'))
            {
                cursor += 1;
            }
            tokens.push(source[start..cursor].to_owned());
        } else {
            tokens.push(char::from(bytes[cursor]).to_string());
            cursor += 1;
        }
    }
    tokens
}
