//! Closed compatibility table for the two inspected Streamable HTTP revisions.

/// Negotiated MCP behavior; no open-ended date/version comparison grants features.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum McpProtocolVersion {
    /// Streamable HTTP, tools and form elicitation; no URL elicitation.
    June2025,
    /// Adds the separately handled URL elicitation mode.
    November2025,
}

impl McpProtocolVersion {
    /// Exact wire/header value for this admitted revision.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::June2025 => "2025-06-18",
            Self::November2025 => "2025-11-25",
        }
    }

    /// Parse only explicitly inspected revisions.
    ///
    /// # Errors
    /// Unknown dates and legacy transport revisions remain unsupported.
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "2025-06-18" => Ok(Self::June2025),
            "2025-11-25" => Ok(Self::November2025),
            _ => Err("MCP server selected an unsupported protocol revision.".into()),
        }
    }
}
