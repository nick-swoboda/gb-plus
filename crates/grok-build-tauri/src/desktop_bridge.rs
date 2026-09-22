//! Narrow macOS Accessibility, frontmost-window, and PID-bound event bridge.

#![allow(unsafe_code)]

use core_graphics::base::kCGErrorSuccess;
use core_graphics::display::CGGetDisplaysWithPoint;
use core_graphics::event::{
    CGEvent, CGEventFlags, CGEventType, CGMouseButton, EventField, KeyCode, ScrollEventUnit,
};
use core_graphics::event_source::{CGEventSource, CGEventSourceStateID};
use core_graphics::geometry::CGPoint as EventPoint;
use objc2_app_kit::NSWorkspace;
use objc2_core_foundation::{
    CFArray, CFBoolean, CFDictionary, CFNumber, CFRetained, CFString, CFType, CGPoint, CGRect,
    CGSize,
};
use objc2_core_graphics::{
    CGRectMakeWithDictionaryRepresentation, CGWindowListCopyWindowInfo, CGWindowListOption,
    kCGNullWindowID, kCGWindowBounds, kCGWindowLayer, kCGWindowName, kCGWindowNumber,
    kCGWindowOwnerPID,
};

use crate::capture_bridge::screen_locked;
use crate::desktop::{
    DesktopAction, DesktopModifier, DesktopMouseButton, DesktopPlatform, DesktopRect, DesktopTarget,
};

const MAX_WINDOW_RECORDS: usize = 4_096;
const MAX_TARGET_TEXT_BYTES: usize = 512;

#[link(name = "ApplicationServices", kind = "framework")]
unsafe extern "C" {
    fn AXIsProcessTrusted() -> u8;
    fn AXIsProcessTrustedWithOptions(options: Option<&CFDictionary>) -> u8;
    static kAXTrustedCheckOptionPrompt: &'static CFString;
}

pub(crate) struct MacDesktopPlatform;

impl DesktopPlatform for MacDesktopPlatform {
    fn accessibility_trusted(&self) -> Result<bool, String> {
        // SAFETY: `AXIsProcessTrusted` takes no arguments, has no ownership
        // transfer, and returns the documented CoreServices Boolean value.
        Ok(unsafe { AXIsProcessTrusted() } != 0)
    }

    fn request_accessibility(&self) -> Result<(), String> {
        let prompt = CFBoolean::new(true);
        // SAFETY: this process-wide ApplicationServices constant is available
        // throughout the macOS 15 deployment floor and points to a CFString.
        let key = unsafe { kAXTrustedCheckOptionPrompt };
        let options = CFDictionary::<CFString, CFBoolean>::from_slices(&[key], &[prompt]);
        // SAFETY: the typed CFDictionary is live for this call and contains
        // exactly the documented prompt key and CFBoolean value. No object is
        // transferred. Prompting is asynchronous; the return value is only a
        // snapshot of current trust and must never be interpreted as the
        // outcome of the prompt. A later Arm performs a fresh preflight.
        let _ = unsafe { AXIsProcessTrustedWithOptions(Some(options.as_opaque())) };
        Ok(())
    }

    fn snapshot_frontmost(&self) -> Result<DesktopTarget, String> {
        snapshot_frontmost()
    }

    fn post_event(&self, target: &DesktopTarget, action: &DesktopAction) -> Result<(), String> {
        post_event(target, action)
    }

    fn screen_locked(&self) -> Result<bool, String> {
        screen_locked()
    }
}

fn snapshot_frontmost() -> Result<DesktopTarget, String> {
    let workspace = NSWorkspace::sharedWorkspace();
    let app = workspace
        .frontmostApplication()
        .ok_or_else(|| "macOS reported no frontmost application for Desktop Control.".to_owned())?;
    let pid = app.processIdentifier();
    if pid <= 1 {
        return Err("macOS reported an invalid frontmost application PID.".into());
    }
    let application = app
        .localizedName()
        .map_or_else(|| format!("PID {pid}"), |name| name.to_string());
    let application = bounded_system_text(application, "frontmost application name")?;
    let bundle_id = app
        .bundleIdentifier()
        .map(|bundle| bounded_system_text(bundle.to_string(), "frontmost bundle identity"))
        .transpose()?;
    let window = first_frontmost_window(pid)?;

    let confirm = workspace.frontmostApplication().ok_or_else(|| {
        "The frontmost application disappeared during target selection.".to_owned()
    })?;
    if confirm.processIdentifier() != pid {
        return Err(
            "The frontmost application changed during Desktop Control target selection.".into(),
        );
    }
    let confirm_bundle = confirm
        .bundleIdentifier()
        .map(|bundle| bounded_system_text(bundle.to_string(), "frontmost bundle identity"))
        .transpose()?;
    if confirm_bundle != bundle_id {
        return Err("The frontmost application identity changed during target selection.".into());
    }

    Ok(DesktopTarget {
        application,
        bundle_id,
        pid,
        window_id: window.window_id,
        window_title: window.title,
        bounds: window.bounds,
        display_id: window.display_id,
    })
}

struct WindowRecord {
    window_id: u32,
    title: String,
    bounds: DesktopRect,
    display_id: u32,
}

fn first_frontmost_window(pid: i32) -> Result<WindowRecord, String> {
    let options =
        CGWindowListOption::OptionOnScreenOnly | CGWindowListOption::ExcludeDesktopElements;
    let array = CGWindowListCopyWindowInfo(options, kCGNullWindowID)
        .ok_or_else(|| "CoreGraphics returned no on-screen window metadata.".to_owned())?;
    // SAFETY: `CGWindowListCopyWindowInfo` documents an array of
    // CoreFoundation dictionaries. We first cast only the array element root
    // to `CFType`, then type-ID-check every element and value before use.
    let array: CFRetained<CFArray<CFType>> = unsafe { CFRetained::cast_unchecked(array) };
    for item in array.iter().take(MAX_WINDOW_RECORDS) {
        let Some(dictionary) = item.downcast_ref::<CFDictionary>() else {
            continue;
        };
        // SAFETY: CoreGraphics documents CFString keys and CFType values for
        // every window-info dictionary. Individual values are still checked
        // through `CFRetained::downcast` before being interpreted.
        let dictionary = unsafe { dictionary.cast_unchecked::<CFString, CFType>() };
        // SAFETY: all referenced `kCGWindow*` symbols are process-wide
        // CoreGraphics CFString constants available on the deployment floor.
        let owner_pid = number_value(dictionary, unsafe { kCGWindowOwnerPID });
        let layer = number_value(dictionary, unsafe { kCGWindowLayer });
        if owner_pid != Some(i64::from(pid)) || layer != Some(0) {
            continue;
        }
        let Some(window_id) = number_value(dictionary, unsafe { kCGWindowNumber })
            .and_then(|value| u32::try_from(value).ok())
            .filter(|value| *value != 0)
        else {
            continue;
        };
        let Some(bounds) = rect_value(dictionary, unsafe { kCGWindowBounds }) else {
            continue;
        };
        if !valid_rect(bounds) {
            continue;
        }
        let center = EventPoint::new(
            bounds.x + bounds.width / 2.0,
            bounds.y + bounds.height / 2.0,
        );
        let mut displays = [0_u32; 16];
        let mut count = 0_u32;
        // SAFETY: `displays` contains exactly 16 writable display-ID slots and
        // the advertised maximum is exactly 16. The out-count pointer is
        // valid. A fixed buffer avoids the dependency convenience wrapper's
        // count/query race if display topology changes between two calls.
        let result =
            unsafe { CGGetDisplaysWithPoint(center, 16, displays.as_mut_ptr(), &raw mut count) };
        if result != kCGErrorSuccess || count == 0 || count > 16 {
            return Err(format!(
                "CoreGraphics display lookup failed closed: code {result}, count {count}."
            ));
        }
        let display_id = displays
            .into_iter()
            .take(usize::try_from(count).unwrap_or(0))
            .find(|display| *display != 0)
            .ok_or_else(|| "The frontmost window is not bound to an online display.".to_owned())?;
        let title = string_value(dictionary, unsafe { kCGWindowName })
            .filter(|title| !title.is_empty())
            .unwrap_or_else(|| "Untitled window".into());
        let title = bounded_system_text(title, "frontmost window title")?;
        return Ok(WindowRecord {
            window_id,
            title,
            bounds,
            display_id,
        });
    }
    Err("The frontmost application has no ordinary on-screen layer-zero window to arm.".into())
}

fn number_value(dictionary: &CFDictionary<CFString, CFType>, key: &CFString) -> Option<i64> {
    dictionary.get(key)?.downcast::<CFNumber>().ok()?.as_i64()
}

fn string_value(dictionary: &CFDictionary<CFString, CFType>, key: &CFString) -> Option<String> {
    dictionary
        .get(key)?
        .downcast::<CFString>()
        .ok()
        .map(|value| value.to_string())
}

fn rect_value(dictionary: &CFDictionary<CFString, CFType>, key: &CFString) -> Option<DesktopRect> {
    let value = dictionary.get(key)?.downcast::<CFDictionary>().ok()?;
    let mut rect = CGRect::new(CGPoint::new(0.0, 0.0), CGSize::new(0.0, 0.0));
    // SAFETY: `value` passed a CoreFoundation dictionary type-ID check and
    // CoreGraphics documents `kCGWindowBounds` as the output of
    // `CGRectCreateDictionaryRepresentation`; `rect` is a valid out pointer.
    if !unsafe { CGRectMakeWithDictionaryRepresentation(Some(&value), &raw mut rect) } {
        return None;
    }
    Some(DesktopRect {
        x: normalized(rect.origin.x),
        y: normalized(rect.origin.y),
        width: normalized(rect.size.width),
        height: normalized(rect.size.height),
    })
}

fn valid_rect(rect: DesktopRect) -> bool {
    rect.x.is_finite()
        && rect.y.is_finite()
        && rect.width.is_finite()
        && rect.height.is_finite()
        && rect.width >= 1.0
        && rect.height >= 1.0
        && rect.width <= 100_000.0
        && rect.height <= 100_000.0
        && rect.x.abs() <= 1_000_000.0
        && rect.y.abs() <= 1_000_000.0
}

fn normalized(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

fn bounded_system_text(value: String, label: &str) -> Result<String, String> {
    if value.is_empty()
        || value.len() > MAX_TARGET_TEXT_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(format!("macOS returned malformed or oversized {label}."));
    }
    Ok(value)
}

fn post_event(target: &DesktopTarget, action: &DesktopAction) -> Result<(), String> {
    verify_event_target(target)?;
    match action {
        DesktopAction::Click { x, y, button } => post_click(target, *x, *y, *button),
        DesktopAction::Type { text } => post_text(target, text),
        DesktopAction::Key { key, modifiers } => post_key(target, key, modifiers),
        DesktopAction::Scroll { delta_x, delta_y } => post_scroll(target, *delta_x, *delta_y),
    }
}

fn verify_event_target(target: &DesktopTarget) -> Result<(), String> {
    let current = snapshot_frontmost()?;
    if target.same_binding(&current) {
        Ok(())
    } else {
        Err(
            "Desktop Control exact PID/window/display/geometry binding changed at the native event boundary."
                .into(),
        )
    }
}

fn source() -> Result<CGEventSource, String> {
    CGEventSource::new(CGEventSourceStateID::Private)
        .map_err(|()| "CoreGraphics could not create a private event source.".to_owned())
}

fn post_click(
    target: &DesktopTarget,
    x: f64,
    y: f64,
    button: DesktopMouseButton,
) -> Result<(), String> {
    let point = EventPoint::new(target.bounds.x + x, target.bounds.y + y);
    let (down_type, up_type, cg_button) = match button {
        DesktopMouseButton::Left => (
            CGEventType::LeftMouseDown,
            CGEventType::LeftMouseUp,
            CGMouseButton::Left,
        ),
        DesktopMouseButton::Right => (
            CGEventType::RightMouseDown,
            CGEventType::RightMouseUp,
            CGMouseButton::Right,
        ),
        DesktopMouseButton::Center => (
            CGEventType::OtherMouseDown,
            CGEventType::OtherMouseUp,
            CGMouseButton::Center,
        ),
    };
    let down = CGEvent::new_mouse_event(source()?, down_type, point, cg_button)
        .map_err(|()| "CoreGraphics could not construct the mouse-down event.".to_owned())?;
    down.set_integer_value_field(EventField::MOUSE_EVENT_CLICK_STATE, 1);
    verify_event_target(target)?;
    down.post_to_pid(target.pid);
    let up = CGEvent::new_mouse_event(source()?, up_type, point, cg_button)
        .map_err(|()| "CoreGraphics could not construct the mouse-up event.".to_owned())?;
    up.set_integer_value_field(EventField::MOUSE_EVENT_CLICK_STATE, 1);
    let still_exact = verify_event_target(target);
    up.post_to_pid(target.pid);
    still_exact
}

fn post_text(target: &DesktopTarget, text: &str) -> Result<(), String> {
    let down = CGEvent::new_keyboard_event(source()?, 0, true)
        .map_err(|()| "CoreGraphics could not construct the Unicode key-down event.".to_owned())?;
    down.set_string(text);
    verify_event_target(target)?;
    down.post_to_pid(target.pid);
    let up = CGEvent::new_keyboard_event(source()?, 0, false)
        .map_err(|()| "CoreGraphics could not construct the Unicode key-up event.".to_owned())?;
    up.set_string(text);
    let still_exact = verify_event_target(target);
    up.post_to_pid(target.pid);
    still_exact
}

fn post_key(
    target: &DesktopTarget,
    key: &str,
    modifiers: &[DesktopModifier],
) -> Result<(), String> {
    let keycode =
        keycode(key).ok_or_else(|| "Desktop key is outside the fixed allowlist.".to_owned())?;
    let flags = modifier_flags(modifiers);
    let down = CGEvent::new_keyboard_event(source()?, keycode, true)
        .map_err(|()| "CoreGraphics could not construct the key-down event.".to_owned())?;
    down.set_flags(flags);
    verify_event_target(target)?;
    down.post_to_pid(target.pid);
    let up = CGEvent::new_keyboard_event(source()?, keycode, false)
        .map_err(|()| "CoreGraphics could not construct the key-up event.".to_owned())?;
    up.set_flags(flags);
    let still_exact = verify_event_target(target);
    up.post_to_pid(target.pid);
    still_exact
}

fn post_scroll(target: &DesktopTarget, delta_x: i32, delta_y: i32) -> Result<(), String> {
    let event =
        CGEvent::new_scroll_event(source()?, ScrollEventUnit::PIXEL, 2, delta_y, delta_x, 0)
            .map_err(|()| "CoreGraphics could not construct the scroll event.".to_owned())?;
    verify_event_target(target)?;
    event.post_to_pid(target.pid);
    Ok(())
}

fn modifier_flags(modifiers: &[DesktopModifier]) -> CGEventFlags {
    modifiers
        .iter()
        .fold(CGEventFlags::empty(), |flags, modifier| {
            flags
                | match modifier {
                    DesktopModifier::Command => CGEventFlags::CGEventFlagCommand,
                    DesktopModifier::Control => CGEventFlags::CGEventFlagControl,
                    DesktopModifier::Option => CGEventFlags::CGEventFlagAlternate,
                    DesktopModifier::Shift => CGEventFlags::CGEventFlagShift,
                }
        })
}

fn keycode(key: &str) -> Option<u16> {
    let special = match key {
        "Enter" => Some(KeyCode::RETURN),
        "Tab" => Some(KeyCode::TAB),
        "Escape" => Some(KeyCode::ESCAPE),
        "Backspace" => Some(KeyCode::DELETE),
        "Delete" => Some(KeyCode::FORWARD_DELETE),
        "Space" => Some(KeyCode::SPACE),
        "ArrowUp" => Some(KeyCode::UP_ARROW),
        "ArrowDown" => Some(KeyCode::DOWN_ARROW),
        "ArrowLeft" => Some(KeyCode::LEFT_ARROW),
        "ArrowRight" => Some(KeyCode::RIGHT_ARROW),
        "Home" => Some(KeyCode::HOME),
        "End" => Some(KeyCode::END),
        "PageUp" => Some(KeyCode::PAGE_UP),
        "PageDown" => Some(KeyCode::PAGE_DOWN),
        _ => None,
    };
    special.or_else(|| {
        key.bytes()
            .next()
            .filter(|_| key.len() == 1)
            .and_then(ascii_keycode)
    })
}

fn ascii_keycode(byte: u8) -> Option<u16> {
    Some(match byte.to_ascii_uppercase() {
        b'A' => KeyCode::ANSI_A,
        b'B' => KeyCode::ANSI_B,
        b'C' => KeyCode::ANSI_C,
        b'D' => KeyCode::ANSI_D,
        b'E' => KeyCode::ANSI_E,
        b'F' => KeyCode::ANSI_F,
        b'G' => KeyCode::ANSI_G,
        b'H' => KeyCode::ANSI_H,
        b'I' => KeyCode::ANSI_I,
        b'J' => KeyCode::ANSI_J,
        b'K' => KeyCode::ANSI_K,
        b'L' => KeyCode::ANSI_L,
        b'M' => KeyCode::ANSI_M,
        b'N' => KeyCode::ANSI_N,
        b'O' => KeyCode::ANSI_O,
        b'P' => KeyCode::ANSI_P,
        b'Q' => KeyCode::ANSI_Q,
        b'R' => KeyCode::ANSI_R,
        b'S' => KeyCode::ANSI_S,
        b'T' => KeyCode::ANSI_T,
        b'U' => KeyCode::ANSI_U,
        b'V' => KeyCode::ANSI_V,
        b'W' => KeyCode::ANSI_W,
        b'X' => KeyCode::ANSI_X,
        b'Y' => KeyCode::ANSI_Y,
        b'Z' => KeyCode::ANSI_Z,
        b'0' => KeyCode::ANSI_0,
        b'1' => KeyCode::ANSI_1,
        b'2' => KeyCode::ANSI_2,
        b'3' => KeyCode::ANSI_3,
        b'4' => KeyCode::ANSI_4,
        b'5' => KeyCode::ANSI_5,
        b'6' => KeyCode::ANSI_6,
        b'7' => KeyCode::ANSI_7,
        b'8' => KeyCode::ANSI_8,
        b'9' => KeyCode::ANSI_9,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_allowlist_maps_without_a_general_keycode_escape_hatch() {
        assert_eq!(keycode("Enter"), Some(KeyCode::RETURN));
        assert_eq!(keycode("a"), Some(KeyCode::ANSI_A));
        assert_eq!(keycode("9"), Some(KeyCode::ANSI_9));
        assert_eq!(keycode("F12"), None);
        assert_eq!(keycode(";"), None);
    }

    #[test]
    fn geometry_normalization_is_stable_and_rejects_invalid_rectangles() {
        assert!((normalized(1.234) - 1.23).abs() < f64::EPSILON);
        assert!(valid_rect(DesktopRect {
            x: -100.0,
            y: 0.0,
            width: 800.0,
            height: 600.0,
        }));
        assert!(!valid_rect(DesktopRect {
            x: 0.0,
            y: 0.0,
            width: f64::NAN,
            height: 600.0,
        }));
    }

    #[test]
    fn modifiers_map_only_to_fixed_coregraphics_flags() {
        let flags = modifier_flags(&[DesktopModifier::Command, DesktopModifier::Shift]);
        assert!(flags.contains(CGEventFlags::CGEventFlagCommand));
        assert!(flags.contains(CGEventFlags::CGEventFlagShift));
        assert!(!flags.contains(CGEventFlags::CGEventFlagControl));
    }
}
