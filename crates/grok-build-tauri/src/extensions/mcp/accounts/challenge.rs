//! Bounded RFC 9110 challenge parsing; metadata still requires network admission.
use super::auth_contract::{Endpoint, validate_scopes};
use std::collections::BTreeMap;

pub(crate) struct Challenge {
    pub(crate) resource_metadata: Option<Endpoint>,
    pub(crate) scopes: Option<Vec<String>>,
}

pub(crate) fn parse(headers: &[&str]) -> Result<Option<Challenge>, String> {
    if headers.len() > 8 || headers.iter().map(|s| s.len()).sum::<usize>() > 8192 {
        return Err("OAuth challenge headers exceeded their bound.".into());
    }
    let mut bearer = None;
    for header in headers {
        let mut input = Input::new(header)?;
        let mut challenges = 0;
        while !input.done() {
            challenges += 1;
            if challenges > 8 {
                return Err("Too many OAuth challenges.".into());
            }
            let scheme = input.token()?.to_ascii_lowercase();
            input.space();
            let mut fields = BTreeMap::new();
            while !input.done() {
                let start = input.pos;
                let key = input.token()?.to_ascii_lowercase();
                input.space();
                if !input.take(b'=') {
                    // At a challenge separator the next token is an auth scheme.
                    // Token68 challenge bodies are not used by supported flows.
                    input.pos = start;
                    break;
                }
                input.space();
                let value = input.value()?;
                if fields.len() >= 16 || fields.insert(key, value).is_some() {
                    return Err("OAuth challenge parameters are duplicated or oversized.".into());
                }
                input.space();
                if input.done() {
                    break;
                }
                if !input.take(b',') {
                    return Err("OAuth challenge separator is invalid.".into());
                }
                input.space();
                if input.done() {
                    return Err("OAuth challenge has a trailing separator.".into());
                }
            }
            if scheme == "bearer" {
                if bearer.is_some() {
                    return Err("OAuth requires one unambiguous Bearer challenge.".into());
                }
                let resource_metadata = fields
                    .get("resource_metadata")
                    .map(|s| Endpoint::parse(s))
                    .transpose()?;
                let scopes = fields
                    .get("scope")
                    .map(|s| {
                        if s.is_empty()
                            || s.starts_with(' ')
                            || s.ends_with(' ')
                            || s.contains("  ")
                        {
                            return Err("OAuth challenge scope syntax is invalid.".into());
                        }
                        validate_scopes(s.split(' ').map(str::to_owned).collect())
                    })
                    .transpose()?;
                bearer = Some(Challenge {
                    resource_metadata,
                    scopes,
                });
            }
        }
    }
    Ok(bearer)
}

struct Input<'a> {
    bytes: &'a [u8],
    pos: usize,
}
impl<'a> Input<'a> {
    fn new(text: &'a str) -> Result<Self, String> {
        if text.is_empty()
            || !text
                .bytes()
                .all(|b| b == b'\t' || (0x20..=0x7e).contains(&b))
        {
            return Err("OAuth challenge is not bounded ASCII.".into());
        }
        let mut value = Self {
            bytes: text.as_bytes(),
            pos: 0,
        };
        value.space();
        Ok(value)
    }
    fn done(&self) -> bool {
        self.pos == self.bytes.len()
    }
    fn space(&mut self) {
        while self
            .bytes
            .get(self.pos)
            .is_some_and(|b| *b == b' ' || *b == b'\t')
        {
            self.pos += 1;
        }
    }
    fn take(&mut self, byte: u8) -> bool {
        if self.bytes.get(self.pos) == Some(&byte) {
            self.pos += 1;
            true
        } else {
            false
        }
    }
    fn token(&mut self) -> Result<&'a str, String> {
        let start = self.pos;
        while self
            .bytes
            .get(self.pos)
            .is_some_and(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(b))
        {
            self.pos += 1;
        }
        if start == self.pos {
            return Err("OAuth challenge token is invalid.".into());
        }
        std::str::from_utf8(&self.bytes[start..self.pos])
            .map_err(|_| "OAuth challenge token is invalid.".into())
    }
    fn value(&mut self) -> Result<String, String> {
        if !self.take(b'"') {
            return self.token().map(str::to_owned);
        }
        let mut value = String::new();
        while let Some(&byte) = self.bytes.get(self.pos) {
            self.pos += 1;
            if byte == b'"' {
                return Ok(value);
            }
            let byte = if byte == b'\\' {
                let byte = *self
                    .bytes
                    .get(self.pos)
                    .ok_or("OAuth challenge escape is incomplete.")?;
                self.pos += 1;
                byte
            } else {
                byte
            };
            if byte < 0x20 || byte == 0x7f {
                return Err("OAuth quoted value contains controls.".into());
            }
            value.push(char::from(byte));
        }
        Err("OAuth quoted challenge is incomplete.".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn quoted_commas_and_other_challenges_do_not_change_bearer_binding() {
        let challenge=parse(&[r#"Basic realm="public, realm", Bearer resource_metadata="https://example.com/.well-known/oauth-protected-resource", scope="write read", error_description="ignored, text""#]).unwrap().unwrap();
        assert_eq!(challenge.scopes.unwrap(), vec!["read", "write"]);
        assert_eq!(
            challenge.resource_metadata.unwrap().text(),
            "https://example.com/.well-known/oauth-protected-resource"
        );
        assert!(parse(&[r#"Basic realm="only""#]).unwrap().is_none());
        assert!(
            parse(&["Bearer"])
                .unwrap()
                .unwrap()
                .resource_metadata
                .is_none()
        );
    }
    #[test]
    fn ambiguity_controls_unbounded_and_malformed_challenges_refuse() {
        for text in [
            r#"Bearer scope="read", Scope="write""#,
            r#"Bearer scope="read", Bearer scope="write""#,
            "Bearer scope=\"read\r\nX: x\"",
            r#"Bearer scope=" read""#,
            r#"Bearer scope="read read""#,
            r#"Bearer resource_metadata="http://127.0.0.1/""#,
            "Bearer scope=\"read",
            "Bearer scope=read,",
        ] {
            assert!(parse(&[text]).is_err(), "{text:?}");
        }
        assert!(parse(&[&"x".repeat(8193)]).is_err());
    }
}
