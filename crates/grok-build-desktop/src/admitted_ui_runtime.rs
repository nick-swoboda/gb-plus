//! Admitted legacy UI-runtime pin.
//!
//! Links `slint =1.17.1` so the product lock cannot silently drop the
//! evaluated crate. This module is not a [`crate::UiRuntime`] implementor
//! and starts no window.

/// Exact product-admitted UI crate identity.
pub const ADMITTED_UI_RUNTIME: &str = "slint=1.17.1";

/// Returns the admitted pin and type-links `slint` without an event loop.
#[must_use]
pub fn admitted_ui_runtime_pin() -> &'static str {
    let _ = std::any::type_name::<slint::SharedString>();
    ADMITTED_UI_RUNTIME
}

/// Builds one `slint::SharedString` so the shipped path uses the admitted crate.
#[must_use]
pub fn admitted_ui_runtime_probe(text: &str) -> String {
    slint::SharedString::from(text).to_string()
}

#[cfg(test)]
mod tests {
    use super::{ADMITTED_UI_RUNTIME, admitted_ui_runtime_pin, admitted_ui_runtime_probe};

    #[test]
    fn admitted_pin_links_slint_1_17_1() {
        assert_eq!(admitted_ui_runtime_pin(), ADMITTED_UI_RUNTIME);
        assert_eq!(admitted_ui_runtime_pin(), "slint=1.17.1");
        assert_eq!(admitted_ui_runtime_probe("gb+-2"), "gb+-2");
        assert_eq!(admitted_ui_runtime_probe(""), "");
    }

    #[test]
    fn workspace_lockfile_pins_admitted_slint() {
        let lock = include_str!("../../../Cargo.lock");
        let mut found = false;
        let mut name = None;
        let mut version = None;
        for line in lock.lines() {
            let trimmed = line.trim();
            if trimmed == "[[package]]" {
                if name.as_deref() == Some("slint") {
                    found = true;
                    assert_eq!(version.as_deref(), Some("1.17.1"));
                }
                name = None;
                version = None;
                continue;
            }
            if let Some(rest) = trimmed.strip_prefix("name = \"") {
                name = Some(rest.trim_end_matches('"').to_owned());
            } else if let Some(rest) = trimmed.strip_prefix("version = \"") {
                version = Some(rest.trim_end_matches('"').to_owned());
            }
        }
        if name.as_deref() == Some("slint") {
            found = true;
            assert_eq!(version.as_deref(), Some("1.17.1"));
        }
        assert!(found, "product Cargo.lock must contain slint 1.17.1");
    }
}
