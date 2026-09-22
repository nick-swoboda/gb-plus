//! Locked space palette for GB Plus chrome.
//!
//! Visual tokens only. Not execution authority. Hex lives here; the window
//! binds `SpaceChrome` from these accessors instead of scattering literals.

use crate::plus_host::PlusCommandSecurityKind;

/// One locked space-palette swatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpaceToken {
    name: &'static str,
    hex: &'static str,
    r: u8,
    g: u8,
    b: u8,
}

impl SpaceToken {
    /// Stable token name used by the window binding.
    #[must_use]
    pub const fn name(self) -> &'static str {
        self.name
    }

    /// Locked `#RRGGBB` form.
    #[must_use]
    pub const fn hex(self) -> &'static str {
        self.hex
    }

    /// Locked RGB triple.
    #[must_use]
    pub const fn rgb(self) -> (u8, u8, u8) {
        (self.r, self.g, self.b)
    }

    /// Range between min and max channel. Greys sit low; chromatic tokens sit high.
    #[must_use]
    pub const fn channel_range(self) -> u8 {
        let max = if self.r > self.g { self.r } else { self.g };
        let max = if max > self.b { max } else { self.b };
        let min = if self.r < self.g { self.r } else { self.g };
        let min = if min < self.b { min } else { self.b };
        max - min
    }
}

/// Void. Window background.
pub const SPACE_VOID: SpaceToken = SpaceToken {
    name: "void",
    hex: "#07090A",
    r: 0x07,
    g: 0x09,
    b: 0x0A,
};

/// Floor. Main cockpit canvas above the void.
pub const SPACE_FLOOR: SpaceToken = SpaceToken {
    name: "floor",
    hex: "#101416",
    r: 0x10,
    g: 0x14,
    b: 0x16,
};

/// Recessed. Readouts and wells.
pub const SPACE_RECESSED: SpaceToken = SpaceToken {
    name: "recessed",
    hex: "#171C20",
    r: 0x17,
    g: 0x1C,
    b: 0x20,
};

/// Space grey. Panels.
pub const SPACE_GREY: SpaceToken = SpaceToken {
    name: "space-grey",
    hex: "#22282D",
    r: 0x22,
    g: 0x28,
    b: 0x2D,
};

/// Space grey raised. Inputs.
pub const SPACE_RAISED: SpaceToken = SpaceToken {
    name: "space-grey-raised",
    hex: "#30373A",
    r: 0x30,
    g: 0x37,
    b: 0x3A,
};

/// Edge. Subdued structural hairlines.
pub const SPACE_EDGE: SpaceToken = SpaceToken {
    name: "edge",
    hex: "#5E666E",
    r: 0x5E,
    g: 0x66,
    b: 0x6E,
};

/// Silver. Hairline borders, icons, Needs attention chip.
pub const SPACE_SILVER: SpaceToken = SpaceToken {
    name: "silver",
    hex: "#A8B0B8",
    r: 0xA8,
    g: 0xB0,
    b: 0xB8,
};

/// Silver bright. Hover / secondary.
pub const SPACE_SILVER_BRIGHT: SpaceToken = SpaceToken {
    name: "silver-bright",
    hex: "#CDD3D9",
    r: 0xCD,
    g: 0xD3,
    b: 0xD9,
};

/// White. Primary text.
pub const SPACE_WHITE: SpaceToken = SpaceToken {
    name: "white",
    hex: "#F5F7F9",
    r: 0xF5,
    g: 0xF7,
    b: 0xF9,
};

/// Muted. Hints and Setting up chip.
pub const SPACE_MUTED: SpaceToken = SpaceToken {
    name: "muted",
    hex: "#8C949C",
    r: 0x8C,
    g: 0x94,
    b: 0x9C,
};

/// Product accent. Command security On, focus, primary actions.
pub const SPACE_ACCENT: SpaceToken = SpaceToken {
    name: "accent",
    hex: "#39785B",
    r: 57,
    g: 120,
    b: 91,
};

/// Warn. Command security Off. Never used as On/success green.
pub const SPACE_WARN: SpaceToken = SpaceToken {
    name: "warn",
    hex: "#B08C48",
    r: 0xB0,
    g: 0x8C,
    b: 0x48,
};

/// Refuse. Reject controls and hard errors.
pub const SPACE_REFUSE: SpaceToken = SpaceToken {
    name: "refuse",
    hex: "#A04848",
    r: 0xA0,
    g: 0x48,
    b: 0x48,
};

/// Central table the window applies, in binding order.
///
/// Order: void, floor, recessed, grey, raised, edge, silver, silver-bright,
/// white, muted, accent, warn, refuse.
#[must_use]
pub fn space_palette() -> [SpaceToken; 13] {
    [
        SPACE_VOID,
        SPACE_FLOOR,
        SPACE_RECESSED,
        SPACE_GREY,
        SPACE_RAISED,
        SPACE_EDGE,
        SPACE_SILVER,
        SPACE_SILVER_BRIGHT,
        SPACE_WHITE,
        SPACE_MUTED,
        SPACE_ACCENT,
        SPACE_WARN,
        SPACE_REFUSE,
    ]
}

/// The only product accent. Not warn gold and not refuse.
#[must_use]
pub fn product_accent() -> SpaceToken {
    SPACE_ACCENT
}

/// Chip fill the window paints next to Command security copy.
///
/// Off is warn, never accent. On is accent. Setting up is muted. Needs
/// attention is refuse red because contained runs are unavailable.
#[must_use]
pub fn command_security_chip_fill(kind: PlusCommandSecurityKind) -> SpaceToken {
    match kind {
        PlusCommandSecurityKind::Off => SPACE_WARN,
        PlusCommandSecurityKind::On => SPACE_ACCENT,
        PlusCommandSecurityKind::SettingUp => SPACE_MUTED,
        PlusCommandSecurityKind::NeedsAttention => SPACE_REFUSE,
    }
}

/// Accept / Accept file / Accept group fill.
#[must_use]
pub fn accept_action_fill() -> SpaceToken {
    SPACE_ACCENT
}

/// Reject / Reject file / Reject group fill.
#[must_use]
pub fn reject_action_fill() -> SpaceToken {
    SPACE_REFUSE
}

/// Persistent left-rail destinations. Chat is the first-run work surface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlusNavKind {
    /// Bind folder, sessions, git.
    Project,
    /// Transcript and compose. Default view.
    Chat,
    /// Staged diffs and Accept / Reject.
    Review,
    /// Command security copy, outcomes, advanced guest controls.
    Status,
    /// Quiet About / attribution. `AboutSlint` lives only here.
    Settings,
}

/// Rail + main-view order the window binds.
#[must_use]
pub fn plus_nav_kinds() -> [PlusNavKind; 5] {
    [
        PlusNavKind::Project,
        PlusNavKind::Chat,
        PlusNavKind::Review,
        PlusNavKind::Status,
        PlusNavKind::Settings,
    ]
}

/// Locked rail label for a destination.
#[must_use]
pub fn plus_nav_label(kind: PlusNavKind) -> &'static str {
    match kind {
        PlusNavKind::Project => "Project",
        PlusNavKind::Chat => "Chat",
        PlusNavKind::Review => "Review",
        PlusNavKind::Status => "Checks",
        PlusNavKind::Settings => "Settings / About",
    }
}

/// Main-view index the window's `main-view` property uses.
#[must_use]
pub fn plus_nav_view_index(kind: PlusNavKind) -> i32 {
    match kind {
        PlusNavKind::Project => 0,
        PlusNavKind::Chat => 1,
        PlusNavKind::Review => 2,
        PlusNavKind::Status => 3,
        PlusNavKind::Settings => 4,
    }
}

/// Inverse of [`plus_nav_view_index`]. Unknown indexes fall back to Chat.
#[must_use]
pub fn plus_nav_from_index(index: i32) -> PlusNavKind {
    plus_nav_kinds()
        .into_iter()
        .find(|kind| plus_nav_view_index(*kind) == index)
        .unwrap_or_else(plus_default_nav)
}

/// First-run / default main view. Not the jammed all-panels stack.
#[must_use]
pub fn plus_default_nav() -> PlusNavKind {
    PlusNavKind::Chat
}

/// Accent badge on the Review rail item when a write is staged.
#[must_use]
pub fn plus_review_badge_visible(has_pending: bool) -> bool {
    has_pending
}

#[cfg(test)]
mod tests {
    use super::{
        PlusNavKind, SPACE_ACCENT, SPACE_EDGE, SPACE_FLOOR, SPACE_GREY, SPACE_MUTED, SPACE_RAISED,
        SPACE_RECESSED, SPACE_REFUSE, SPACE_SILVER, SPACE_SILVER_BRIGHT, SPACE_VOID, SPACE_WARN,
        SPACE_WHITE, accept_action_fill, command_security_chip_fill, plus_default_nav,
        plus_nav_from_index, plus_nav_kinds, plus_nav_label, plus_nav_view_index,
        plus_review_badge_visible, product_accent, reject_action_fill, space_palette,
    };
    use crate::plus_host::{
        PlusCommandSecurityKind, present_command_security_contained_outcome,
        present_command_security_panel, present_command_security_status,
    };

    #[test]
    fn space_theme_palette_tokens_match_locked_hex() {
        assert_eq!(SPACE_VOID.name(), "void");
        assert_eq!(SPACE_VOID.hex(), "#07090A");
        assert_eq!(SPACE_VOID.rgb(), (0x07, 0x09, 0x0A));
        assert_eq!(SPACE_FLOOR.name(), "floor");
        assert_eq!(SPACE_FLOOR.hex(), "#101416");
        assert_eq!(SPACE_FLOOR.rgb(), (0x10, 0x14, 0x16));
        assert_eq!(SPACE_RECESSED.name(), "recessed");
        assert_eq!(SPACE_RECESSED.hex(), "#171C20");
        assert_eq!(SPACE_RECESSED.rgb(), (0x17, 0x1C, 0x20));
        assert_eq!(SPACE_GREY.name(), "space-grey");
        assert_eq!(SPACE_GREY.hex(), "#22282D");
        assert_eq!(SPACE_GREY.rgb(), (0x22, 0x28, 0x2D));
        assert_eq!(SPACE_RAISED.hex(), "#30373A");
        assert_eq!(SPACE_RAISED.rgb(), (0x30, 0x37, 0x3A));
        assert_eq!(SPACE_EDGE.name(), "edge");
        assert_eq!(SPACE_EDGE.hex(), "#5E666E");
        assert_eq!(SPACE_EDGE.rgb(), (0x5E, 0x66, 0x6E));
        assert_eq!(SPACE_SILVER.hex(), "#A8B0B8");
        assert_eq!(SPACE_SILVER.rgb(), (0xA8, 0xB0, 0xB8));
        assert_eq!(SPACE_SILVER_BRIGHT.hex(), "#CDD3D9");
        assert_eq!(SPACE_SILVER_BRIGHT.rgb(), (0xCD, 0xD3, 0xD9));
        assert_eq!(SPACE_WHITE.hex(), "#F5F7F9");
        assert_eq!(SPACE_WHITE.rgb(), (0xF5, 0xF7, 0xF9));
        assert_eq!(SPACE_MUTED.hex(), "#8C949C");
        assert_eq!(SPACE_MUTED.rgb(), (0x8C, 0x94, 0x9C));
        assert_eq!(SPACE_ACCENT.hex(), "#39785B");
        assert_eq!(SPACE_ACCENT.rgb(), (57, 120, 91));
        assert_eq!(product_accent(), SPACE_ACCENT);
        assert_eq!(SPACE_WARN.hex(), "#B08C48");
        assert_eq!(SPACE_WARN.rgb(), (0xB0, 0x8C, 0x48));
        assert_eq!(SPACE_REFUSE.hex(), "#A04848");
        assert_eq!(SPACE_REFUSE.rgb(), (0xA0, 0x48, 0x48));

        let table = space_palette();
        assert_eq!(
            table,
            [
                SPACE_VOID,
                SPACE_FLOOR,
                SPACE_RECESSED,
                SPACE_GREY,
                SPACE_RAISED,
                SPACE_EDGE,
                SPACE_SILVER,
                SPACE_SILVER_BRIGHT,
                SPACE_WHITE,
                SPACE_MUTED,
                SPACE_ACCENT,
                SPACE_WARN,
                SPACE_REFUSE,
            ]
        );
        assert_eq!(
            table
                .iter()
                .filter(|token| token.hex() == "#39785B")
                .count(),
            1,
            "exactly one product accent"
        );
        for forbidden in ["#005FB8", "#60CDFF", "#0078D4", "#6750A4", "#0A84FF"] {
            assert!(
                table.iter().all(|token| token.hex() != forbidden),
                "no blue/purple product token {forbidden}"
            );
        }
        let chromatic: Vec<_> = table
            .iter()
            .copied()
            .filter(|token| token.channel_range() > 20)
            .collect();
        assert_eq!(
            chromatic,
            [SPACE_ACCENT, SPACE_WARN, SPACE_REFUSE],
            "only accent/warn/refuse are chromatic; no second product accent"
        );
    }

    #[test]
    fn space_theme_command_security_chip_fill_maps_kinds() {
        assert_eq!(
            command_security_chip_fill(PlusCommandSecurityKind::Off),
            SPACE_WARN
        );
        assert_ne!(
            command_security_chip_fill(PlusCommandSecurityKind::Off),
            SPACE_ACCENT,
            "Off chip must never be accent green"
        );
        assert_eq!(
            command_security_chip_fill(PlusCommandSecurityKind::On),
            SPACE_ACCENT
        );
        assert_eq!(
            command_security_chip_fill(PlusCommandSecurityKind::SettingUp),
            SPACE_MUTED
        );
        assert_eq!(
            command_security_chip_fill(PlusCommandSecurityKind::NeedsAttention),
            SPACE_REFUSE
        );
        assert_ne!(
            command_security_chip_fill(PlusCommandSecurityKind::SettingUp),
            command_security_chip_fill(PlusCommandSecurityKind::NeedsAttention)
        );
        for kind in [
            PlusCommandSecurityKind::SettingUp,
            PlusCommandSecurityKind::NeedsAttention,
        ] {
            let fill = command_security_chip_fill(kind);
            assert_ne!(fill, SPACE_WARN);
            assert_ne!(fill, SPACE_ACCENT);
        }

        let off_status = present_command_security_status(PlusCommandSecurityKind::Off);
        let off_panel = present_command_security_panel(PlusCommandSecurityKind::Off);
        assert_eq!(off_status, "Command security: Off");
        assert!(
            off_panel.contains("Command security: Off") && off_panel.contains("not fully isolated"),
            "Off copy must stay honest: {off_panel}"
        );
        let on_panel = present_command_security_panel(PlusCommandSecurityKind::On);
        assert!(on_panel.contains("Command security: On"));
        let setting = present_command_security_panel(PlusCommandSecurityKind::SettingUp);
        assert!(setting.contains("Command security: Setting up"));
        let needs = present_command_security_panel(PlusCommandSecurityKind::NeedsAttention);
        assert!(needs.contains("Command security: Needs attention"));
        let poisoned = "Command succeeded (Exited { code: 0 })\npermit minted";
        let off_run =
            present_command_security_contained_outcome(PlusCommandSecurityKind::Off, poisoned);
        assert!(
            off_run.contains("Command security: Off")
                && off_run.contains("not fully isolated")
                && !off_run.contains("Command succeeded")
                && !off_run.contains("Command security: On"),
            "{off_run}"
        );
    }

    #[test]
    fn space_theme_accept_reject_action_fills() {
        assert_eq!(accept_action_fill(), SPACE_ACCENT);
        assert_eq!(accept_action_fill().hex(), "#39785B");
        assert_eq!(reject_action_fill(), SPACE_REFUSE);
        assert_eq!(reject_action_fill().hex(), "#A04848");
        assert_ne!(accept_action_fill(), reject_action_fill());
    }

    #[test]
    fn space_theme_window_binds_palette_chips_and_actions() {
        let window = include_str!("plus_window.rs");
        let shipped = window
            .split("#[cfg(test)]")
            .next()
            .expect("shipped window source precedes tests");
        for needle in [
            "space_palette",
            "apply_space_palette",
            "command_security_chip_fill",
            "accept_action_fill",
            "reject_action_fill",
            "SpaceChrome",
            "command-security-chip",
            "SpaceButton",
            "SpaceButtonRole.accept",
            "SpaceButtonRole.accept-secondary",
            "SpaceButtonRole.refuse",
            "SpaceLineEdit",
            "SpaceReadout",
            "ScrollView",
            "TextInput",
            "selection-background-color",
            "has-pending-review",
            "guest-copy",
            "space-void",
            "space-floor",
            "space-recessed",
            "space-edge",
            "preferred-width: 1200px",
            "min-width: 900px",
            "min-height: 600px",
            "select-nav",
            "plus_nav_view_index",
            "plus_default_nav",
            "Palette.color-scheme",
        ] {
            assert!(
                shipped.contains(needle),
                "window must bind {needle} from the shipped theme table"
            );
        }
        for scatter in [
            "#07090A", "#101416", "#171C20", "#22282D", "#30373A", "#5E666E", "#39785B", "#B08C48",
            "#A04848", "#60CDFF", "#005FB8", "#0078D4",
        ] {
            assert!(
                !shipped.contains(scatter),
                "window must not scatter hex {scatter}; tokens live in plus_theme.rs"
            );
        }
        assert!(
            !shipped.contains("TextEdit"),
            "read-only transcript must not leak Fluent TextEdit chrome"
        );
        let theme = include_str!("plus_theme.rs");
        let theme_shipped = theme
            .split("#[cfg(test)]")
            .next()
            .expect("theme tokens precede tests");
        assert!(theme_shipped.contains("#39785B"));
        assert!(theme_shipped.contains("#B08C48"));
        assert!(theme_shipped.contains("#A04848"));
    }

    #[test]
    fn space_theme_nav_views_map_rail_to_main() {
        assert_eq!(plus_default_nav(), PlusNavKind::Chat);
        assert_eq!(plus_nav_view_index(plus_default_nav()), 1);
        assert_eq!(plus_nav_kinds().map(plus_nav_view_index), [0, 1, 2, 3, 4]);
        assert_eq!(plus_nav_label(PlusNavKind::Project), "Project");
        assert_eq!(plus_nav_label(PlusNavKind::Chat), "Chat");
        assert_eq!(plus_nav_label(PlusNavKind::Review), "Review");
        assert_eq!(plus_nav_label(PlusNavKind::Status), "Checks");
        assert_eq!(plus_nav_label(PlusNavKind::Settings), "Settings / About");
        assert_eq!(plus_nav_from_index(0), PlusNavKind::Project);
        assert_eq!(plus_nav_from_index(2), PlusNavKind::Review);
        assert_eq!(plus_nav_from_index(4), PlusNavKind::Settings);
        assert_eq!(plus_nav_from_index(99), PlusNavKind::Chat);
        assert!(plus_review_badge_visible(true));
        assert!(!plus_review_badge_visible(false));

        let window = include_str!("plus_window.rs");
        let shipped = window
            .split("#[cfg(test)]")
            .next()
            .expect("shipped window source precedes tests");
        for kind in plus_nav_kinds() {
            let label = plus_nav_label(kind);
            assert!(
                shipped.contains(&format!("text: \"{label}\"")),
                "rail must bind locked label {label}"
            );
        }
        assert!(shipped.contains("select-nav"));
        assert!(shipped.contains("plus_nav_view_index"));
        assert!(shipped.contains("plus_default_nav"));
        assert!(
            shipped.contains("min-width: 900px") && shipped.contains("min-height: 600px"),
            "window must resize below 1040×720"
        );
        assert!(
            !shipped.contains("min-width: 1040px") && !shipped.contains("min-height: 720px"),
            "must not lock min 1040×720 as the exclusive layout"
        );
        assert_eq!(
            shipped.matches("AboutSlint {").count(),
            1,
            "AboutSlint must appear once"
        );
        let before_settings = shipped
            .split("if (main-view == 4)")
            .next()
            .expect("settings view marker");
        assert!(
            !before_settings.contains("AboutSlint {"),
            "AboutSlint must be absent from Chat / Review / Status / Project"
        );
        let settings = shipped
            .split("if (main-view == 4)")
            .nth(1)
            .expect("settings view body");
        assert!(
            settings.contains("AboutSlint {")
                && settings.contains("clip: true")
                && settings.contains("width: 140px"),
            "AboutSlint must be small and clipped on Settings / About: {settings}"
        );
    }
}
