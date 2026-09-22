//! Deliberately incomplete project used by the Gate 1 walking skeleton.

/// Returns the current fixture state.
#[must_use]
pub const fn status() -> &'static str {
    "TODO"
}

/// Embeds the report created by the deterministic fake provider.
#[must_use]
pub const fn report() -> &'static str {
    include_str!("../docs/report.txt")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requested_state_and_report_are_present() {
        assert_eq!(status(), "ready");
        assert_eq!(report(), "walking skeleton complete\n");
    }
}
