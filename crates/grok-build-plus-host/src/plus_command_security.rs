//! Optional extra security for command runs.
//!
//! This is a presentation and preference gate, not a new execution authority.
//! Chat, file proposals, and Accept work while Command security is Off.
//! Contained / proof-grade Run is available only when the real stack is ready
//! and the user chose extra security.

use super::plus_guest::{
    PlusGuestLifecycle, PlusGuestUnavailable, present_plus_guest_unavailable_outcome_with_kind,
};
use super::plus_lifecycle::PlusGuestLifecycleKind;
use super::plus_probe::plus_presentation_is_known_good_terminal;
use super::plus_refusals::{
    PLUS_REFUSAL_NOT_SUCCESS, PLUS_REFUSAL_WHAT_HAPPENED, PLUS_REFUSAL_WHAT_TO_DO,
};
use super::{
    BoundProject, CommandOutcomeClass, PresentedCommandOutcome, plus_gui_contained_command_outcome,
};

/// Locked user-facing feature name.
pub const PLUS_EXTRA_SECURITY: &str = "extra security for command runs";

/// Locked status prefix.
pub const PLUS_COMMAND_SECURITY: &str = "Command security";

/// Locked status word: extra security is not enabled.
pub const PLUS_COMMAND_SECURITY_OFF: &str = "Off";

/// Locked status word: extra security was chosen and is still setting up.
pub const PLUS_COMMAND_SECURITY_SETTING_UP: &str = "Setting up";

/// Locked status word: the real extra-security stack is ready.
pub const PLUS_COMMAND_SECURITY_ON: &str = "On";

/// Locked status word: extra security was chosen but the stack needs repair.
pub const PLUS_COMMAND_SECURITY_NEEDS_ATTENTION: &str = "Needs attention";

/// First-run / settings: enable extra security.
pub const PLUS_TURN_ON_EXTRA_SECURITY: &str = "Turn on extra security";

/// First-run / settings: keep Command security Off.
pub const PLUS_NOT_NOW: &str = "Not now";

/// Owner-only file under the desktop state root. Missing means Off.
pub const PLUS_COMMAND_SECURITY_FILE: &str = "plus-command-security";

/// Window legend listing the four locked status words.
pub const PLUS_COMMAND_SECURITY_LEGEND: &str =
    "Command security: Off | Setting up | On | Needs attention";

/// Stored choice. Missing or unknown file contents are Off.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlusCommandSecurityPreference {
    /// User chose Not now, or has not chosen extra security.
    Off,
    /// User chose Turn on extra security.
    Extra,
}

/// Presented Command security state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlusCommandSecurityKind {
    /// Extra security is not enabled.
    Off,
    /// Extra security was chosen and setup is still running.
    SettingUp,
    /// Extra security stack is actually ready.
    On,
    /// Extra security was chosen but the stack is missing or broken.
    NeedsAttention,
}

/// I/O-free: map preference + lifecycle + in-progress onto a status kind.
#[must_use]
pub fn classify_command_security(
    preference: PlusCommandSecurityPreference,
    lifecycle: PlusGuestLifecycleKind,
    setup_in_progress: bool,
) -> PlusCommandSecurityKind {
    match preference {
        PlusCommandSecurityPreference::Off => PlusCommandSecurityKind::Off,
        PlusCommandSecurityPreference::Extra if setup_in_progress => {
            PlusCommandSecurityKind::SettingUp
        }
        PlusCommandSecurityPreference::Extra if lifecycle == PlusGuestLifecycleKind::Ready => {
            PlusCommandSecurityKind::On
        }
        PlusCommandSecurityPreference::Extra => PlusCommandSecurityKind::NeedsAttention,
    }
}

/// Locked `Command security: …` line for a kind.
#[must_use]
pub fn present_command_security_status(kind: PlusCommandSecurityKind) -> String {
    let word = match kind {
        PlusCommandSecurityKind::Off => PLUS_COMMAND_SECURITY_OFF,
        PlusCommandSecurityKind::SettingUp => PLUS_COMMAND_SECURITY_SETTING_UP,
        PlusCommandSecurityKind::On => PLUS_COMMAND_SECURITY_ON,
        PlusCommandSecurityKind::NeedsAttention => PLUS_COMMAND_SECURITY_NEEDS_ATTENTION,
    };
    format!("{PLUS_COMMAND_SECURITY}: {word}")
}

/// I/O-free status panel for the window Command security surface.
#[must_use]
pub fn present_command_security_panel(kind: PlusCommandSecurityKind) -> String {
    let status = present_command_security_status(kind);
    match kind {
        PlusCommandSecurityKind::Off => format!(
            "{status}\n{PLUS_EXTRA_SECURITY} is optional. Chat, file proposals, and Accept work without it.\nCommands are not fully isolated."
        ),
        PlusCommandSecurityKind::SettingUp => format!(
            "{status}\n{PLUS_EXTRA_SECURITY} is still setting up. Contained command runs wait until Command security is On."
        ),
        PlusCommandSecurityKind::On => format!(
            "{status}\n{PLUS_EXTRA_SECURITY} is on. Agent command runs use stronger isolation."
        ),
        PlusCommandSecurityKind::NeedsAttention => format!(
            "{status}\n{PLUS_EXTRA_SECURITY} needs repair. Commands are not fully isolated until Command security is On."
        ),
    }
}

/// I/O-free contained/proof-grade presentation for a Command security kind.
///
/// Off, Setting up, and Needs attention never pass through a stack success.
/// `stack_text` is used only when kind is On, or as honest failure detail
/// when kind is Needs attention and that text is not a proof-grade success.
#[must_use]
pub fn present_command_security_contained_outcome(
    kind: PlusCommandSecurityKind,
    stack_text: &str,
) -> String {
    match kind {
        PlusCommandSecurityKind::Off => present_command_security_off_refusal(),
        PlusCommandSecurityKind::SettingUp => present_command_security_setting_up_refusal(),
        PlusCommandSecurityKind::NeedsAttention => {
            present_command_security_needs_attention_refusal(stack_text)
        }
        PlusCommandSecurityKind::On => present_command_security_on_outcome(stack_text),
    }
}

/// Typed Command-security presentation; stack text never selects authority.
#[must_use]
pub fn present_command_security_contained_typed(
    kind: PlusCommandSecurityKind,
    stack: Option<PresentedCommandOutcome>,
) -> PresentedCommandOutcome {
    match kind {
        PlusCommandSecurityKind::Off => PresentedCommandOutcome::new(
            CommandOutcomeClass::Refused,
            present_command_security_off_refusal(),
        ),
        PlusCommandSecurityKind::SettingUp => PresentedCommandOutcome::new(
            CommandOutcomeClass::Refused,
            present_command_security_setting_up_refusal(),
        ),
        PlusCommandSecurityKind::NeedsAttention => PresentedCommandOutcome::new(
            CommandOutcomeClass::Refused,
            present_command_security_needs_attention_typed(stack.as_ref()),
        ),
        PlusCommandSecurityKind::On => match stack {
            Some(outcome) => outcome.prefixed(&present_command_security_status(kind)),
            None => PresentedCommandOutcome::new(
                CommandOutcomeClass::Idle,
                present_command_security_status(kind),
            ),
        },
    }
}

/// Stored token for a preference. Missing files are treated as Off.
#[must_use]
pub fn encode_command_security_preference(
    preference: PlusCommandSecurityPreference,
) -> &'static str {
    match preference {
        PlusCommandSecurityPreference::Off => "off",
        PlusCommandSecurityPreference::Extra => "extra",
    }
}

/// Parse a stored token. Anything other than `extra` is Off.
#[must_use]
pub fn parse_command_security_preference(text: &str) -> PlusCommandSecurityPreference {
    if text.trim().eq_ignore_ascii_case("extra") {
        PlusCommandSecurityPreference::Extra
    } else {
        PlusCommandSecurityPreference::Off
    }
}

/// Window Run / Checks / tool `run_contained` when a preference is in force.
///
/// Off and Setting up never start a contained command. On starts one only
/// after classification says the real stack is ready.
#[must_use]
pub fn plus_contained_command_with_security(
    bound: &BoundProject,
    preference: PlusCommandSecurityPreference,
    setup_in_progress: bool,
    lifecycle: &PlusGuestLifecycle,
) -> String {
    plus_contained_command_with_security_typed(bound, preference, setup_in_progress, lifecycle).text
}

/// Typed contained-command path selected by Command security.
#[must_use]
pub fn plus_contained_command_with_security_typed(
    bound: &BoundProject,
    preference: PlusCommandSecurityPreference,
    setup_in_progress: bool,
    lifecycle: &PlusGuestLifecycle,
) -> PresentedCommandOutcome {
    let kind = classify_command_security(preference, lifecycle.kind(), setup_in_progress);
    match kind {
        PlusCommandSecurityKind::On => {
            let stack = plus_gui_contained_command_outcome(bound);
            if stack.is_authoritative_terminal() {
                present_command_security_contained_typed(PlusCommandSecurityKind::On, Some(stack))
            } else {
                present_command_security_contained_typed(
                    PlusCommandSecurityKind::NeedsAttention,
                    Some(stack),
                )
            }
        }
        PlusCommandSecurityKind::NeedsAttention => {
            let reasons = match lifecycle {
                PlusGuestLifecycle::GuestDown { reasons }
                | PlusGuestLifecycle::ServiceMissing { reasons } => reasons.clone(),
                PlusGuestLifecycle::Ready(_) => {
                    vec!["extra security for command runs is not actually ready".into()]
                }
            };
            let stack = present_plus_guest_unavailable_outcome_with_kind(
                lifecycle.kind(),
                "",
                &PlusGuestUnavailable { reasons },
            );
            present_command_security_contained_typed(
                PlusCommandSecurityKind::NeedsAttention,
                Some(PresentedCommandOutcome::new(
                    CommandOutcomeClass::Refused,
                    stack,
                )),
            )
        }
        PlusCommandSecurityKind::Off | PlusCommandSecurityKind::SettingUp => {
            present_command_security_contained_typed(kind, None)
        }
    }
}

fn present_command_security_needs_attention_typed(
    stack: Option<&PresentedCommandOutcome>,
) -> String {
    let stack_text = stack
        .filter(|outcome| !outcome.is_authoritative_terminal())
        .map_or("", |outcome| outcome.text.as_str());
    present_command_security_needs_attention_refusal(stack_text)
}

fn present_command_security_off_refusal() -> String {
    format!(
        "{}\n{PLUS_EXTRA_SECURITY} is not on.\nContained command runs are unavailable while Command security is Off.\nChat, file proposals, and Accept still work.\nCommands are not fully isolated.\n{PLUS_REFUSAL_WHAT_HAPPENED} Command security is Off.\n{PLUS_REFUSAL_WHAT_TO_DO} Click {PLUS_TURN_ON_EXTRA_SECURITY} for stronger isolation when the agent runs commands, or keep working without it.\n{PLUS_REFUSAL_NOT_SUCCESS}",
        present_command_security_status(PlusCommandSecurityKind::Off)
    )
}

fn present_command_security_setting_up_refusal() -> String {
    format!(
        "{}\n{PLUS_EXTRA_SECURITY} is still setting up.\nContained command runs are unavailable until Command security is On.\nCommands are not fully isolated yet.\n{PLUS_REFUSAL_WHAT_HAPPENED} Command security is Setting up.\n{PLUS_REFUSAL_WHAT_TO_DO} Wait for setup to finish, or click {PLUS_NOT_NOW} to keep Command security Off.\n{PLUS_REFUSAL_NOT_SUCCESS}",
        present_command_security_status(PlusCommandSecurityKind::SettingUp)
    )
}

fn present_command_security_needs_attention_refusal(stack_text: &str) -> String {
    let mut lines = vec![
        present_command_security_status(PlusCommandSecurityKind::NeedsAttention),
        format!("{PLUS_EXTRA_SECURITY} needs repair."),
        "Contained command runs are unavailable until Command security is On.".into(),
        "Commands are not fully isolated.".into(),
        format!("{PLUS_REFUSAL_WHAT_HAPPENED} Command security is Needs attention."),
        format!(
            "{PLUS_REFUSAL_WHAT_TO_DO} Click {PLUS_TURN_ON_EXTRA_SECURITY} again after fixing setup, or click {PLUS_NOT_NOW}."
        ),
        PLUS_REFUSAL_NOT_SUCCESS.to_owned(),
    ];
    if !stack_text.is_empty()
        && !plus_presentation_is_known_good_terminal(stack_text)
        && !stack_text.contains("Command succeeded")
        && !stack_text.contains(&present_command_security_status(
            PlusCommandSecurityKind::On,
        ))
    {
        lines.push(stack_text.to_owned());
    }
    lines.join("\n")
}

fn present_command_security_on_outcome(stack_text: &str) -> String {
    let status = present_command_security_status(PlusCommandSecurityKind::On);
    if stack_text.is_empty() {
        status
    } else {
        format!("{status}\n{stack_text}")
    }
}
