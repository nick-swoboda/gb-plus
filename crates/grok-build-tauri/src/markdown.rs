//! `CommonMark` becomes presentation tokens, never executable HTML.

use pulldown_cmark::{Event, Options, Parser, Tag, TagEnd};
use serde::Serialize;

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub(crate) enum Token {
    Open {
        tag: &'static str,
        href: Option<String>,
        language: Option<String>,
        start: Option<u64>,
    },
    Close,
    Text {
        text: String,
    },
    Code {
        text: String,
    },
    Break,
    Rule,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Document {
    tokens: Vec<Token>,
    plain_text: String,
}

pub(crate) fn render(input: &str) -> Result<Document, String> {
    if input.len() > 1024 * 1024 {
        return Err("Reply exceeds the Markdown display limit.".into());
    }
    let mut result = Document {
        tokens: Vec::new(),
        plain_text: String::new(),
    };
    let options =
        Options::ENABLE_TABLES | Options::ENABLE_STRIKETHROUGH | Options::ENABLE_TASKLISTS;
    let mut depth = 0_u16;
    let mut table_head = false;
    for event in Parser::new_ext(input, options) {
        if result.tokens.len() >= 65536 {
            return Err("Reply has too many Markdown elements.".into());
        }
        let token = match event {
            Event::Start(tag) => {
                depth += 1;
                if depth > 128 {
                    return Err("Reply Markdown is nested too deeply.".into());
                }
                if tag == Tag::TableHead {
                    table_head = true;
                    result.tokens.push(open(Tag::TableHead, true));
                    open(Tag::TableRow, true)
                } else {
                    open(tag, table_head)
                }
            }
            Event::End(tag) => {
                depth = depth.saturating_sub(1);
                if tag == TagEnd::TableHead {
                    table_head = false;
                    result.tokens.push(Token::Close);
                }
                if matches!(
                    tag,
                    TagEnd::Paragraph
                        | TagEnd::Heading(_)
                        | TagEnd::CodeBlock
                        | TagEnd::Item
                        | TagEnd::TableHead
                        | TagEnd::TableRow
                ) {
                    result.plain_text.push('\n');
                } else if tag == TagEnd::TableCell {
                    result.plain_text.push(' ');
                }
                Token::Close
            }
            Event::Code(text) => {
                result.plain_text.push_str(&text);
                Token::Code {
                    text: text.into_string(),
                }
            }
            Event::Text(text)
            | Event::Html(text)
            | Event::InlineHtml(text)
            | Event::InlineMath(text)
            | Event::DisplayMath(text)
            | Event::FootnoteReference(text) => {
                result.plain_text.push_str(&text);
                Token::Text {
                    text: text.into_string(),
                }
            }
            Event::SoftBreak | Event::HardBreak => {
                result.plain_text.push('\n');
                Token::Break
            }
            Event::Rule => Token::Rule,
            Event::TaskListMarker(checked) => Token::Text {
                text: if checked { "☑ " } else { "☐ " }.into(),
            },
        };
        result.tokens.push(token);
    }
    Ok(result)
}

fn open(tag: Tag<'_>, table_head: bool) -> Token {
    let mut href = None;
    let mut language = None;
    let mut start = None;
    let tag = match tag {
        Tag::Paragraph => "p",
        Tag::Heading { level, .. } => match level as u8 {
            1 => "h1",
            2 => "h2",
            3 => "h3",
            4 => "h4",
            5 => "h5",
            _ => "h6",
        },
        Tag::BlockQuote(_) => "blockquote",
        Tag::CodeBlock(kind) => {
            if let pulldown_cmark::CodeBlockKind::Fenced(value) = kind {
                language = Some(value.chars().take(64).collect());
            }
            "pre"
        }
        Tag::List(number) => {
            start = number;
            if number.is_some() { "ol" } else { "ul" }
        }
        Tag::Item => "li",
        Tag::Table(_) => "table",
        Tag::TableHead => "thead",
        Tag::TableRow => "tr",
        Tag::TableCell => {
            if table_head {
                "th"
            } else {
                "td"
            }
        }
        Tag::Emphasis => "em",
        Tag::Strong => "strong",
        Tag::Strikethrough => "del",
        Tag::Link { dest_url, .. } | Tag::Image { dest_url, .. } => {
            href = safe_link(&dest_url);
            if href.is_some() { "a" } else { "span" }
        }
        _ => "span",
    };
    Token::Open {
        tag,
        href,
        language,
        start,
    }
}

fn safe_link(value: &str) -> Option<String> {
    if value.len() > 8192 || value.chars().any(char::is_control) {
        return None;
    }
    let url = url::Url::parse(value).ok()?;
    matches!(url.scheme(), "https" | "http" | "mailto").then(|| url.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markup_does_not_become_authority_or_remote_media() {
        let doc = render("**Hello** [bad](javascript:alert%281%29) ![alt](https://example.com/a.png) <script>bad()</script>").unwrap();
        let encoded = serde_json::to_string(&doc).unwrap();
        assert!(!encoded.contains("javascript:"));
        assert!(!encoded.contains("\"tag\":\"img\""));
        assert!(encoded.contains("<script>bad()</script>"));
        assert!(doc.plain_text.contains("Hello"));
        assert!(!doc.plain_text.contains("**"));
    }

    #[test]
    fn commonmark_renders_code_tables_and_bounded_input() {
        let doc = render("# Title\n\n```rust\nlet x = 1;\n```\n\n| A | B |\n|---|---|\n| x | y |")
            .unwrap();
        let encoded = serde_json::to_string(&doc).unwrap();
        assert!(encoded.contains("\"language\":\"rust\""));
        assert!(encoded.contains("\"tag\":\"table\""));
        assert!(encoded.contains("\"tag\":\"th\""));
        let mut tags = Vec::new();
        for token in &doc.tokens {
            match token {
                Token::Open { tag, .. } => {
                    if *tag == "th" {
                        assert_eq!(tags, ["table", "thead", "tr"]);
                    }
                    tags.push(*tag);
                }
                Token::Close => {
                    assert!(tags.pop().is_some());
                }
                _ => {}
            }
        }
        assert!(tags.is_empty());
        assert_eq!(
            render("A **bold** word.").unwrap().plain_text.trim(),
            "A bold word."
        );
        assert!(render(&"x".repeat(1024 * 1024 + 1)).is_err());
    }
}
