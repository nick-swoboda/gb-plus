//! Isolated Slint `1.17.1` closure fixture.
//!
//! Not a product window. Does not implement folder, chat, or visual-diff UI.

/// Exact pin under evaluation. Mentions a `slint` type so the reviewed
/// crate is part of the isolated graph without starting an event loop.
#[must_use]
pub fn evaluated_slint_version() -> &'static str {
    let _ = std::any::type_name::<slint::SharedString>();
    "1.17.1"
}

#[cfg(test)]
mod tests {
    #[test]
    fn evaluated_pin_matches_declared_constant() {
        assert_eq!(super::evaluated_slint_version(), "1.17.1");
    }
}
