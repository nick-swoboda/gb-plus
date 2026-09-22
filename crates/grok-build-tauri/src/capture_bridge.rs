//! Narrow macOS `ScreenCaptureKit` and `CoreGraphics` bridge.

#![allow(unsafe_code)]

use std::ptr::NonNull;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::time::Duration;

use block2::RcBlock;
use core_graphics::access::ScreenCaptureAccess;
use core_graphics::display::CGDisplay;
use objc2::AnyThread as _;
use objc2::rc::Retained;
use objc2_core_foundation::{
    CFBoolean, CFRetained, CFString, CGPoint, CGRect, CGSize, kCFBooleanFalse, kCFBooleanTrue,
};
use objc2_core_graphics::{
    CGBitmapContextCreate, CGColorSpace, CGContext, CGImage, CGImageAlphaInfo,
    CGImageByteOrderInfo, CGSessionCopyCurrentDictionary,
};
use objc2_foundation::{NSArray, NSError};
use objc2_screen_capture_kit::{
    SCContentFilter, SCDisplay, SCScreenshotManager, SCShareableContent, SCStreamConfiguration,
};

use crate::capture::{CaptureDisplay, CapturePlatform, CapturedPng};

const CALLBACK_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_OUTPUT_WIDTH: u32 = 1280;
const MAX_OUTPUT_HEIGHT: u32 = 900;
const MAX_OUTPUT_PIXELS: usize = 1_152_000;
const MAX_RGBA_BYTES: usize = MAX_OUTPUT_PIXELS * 4;
const MAX_PNG_BYTES: usize = 6 * 1024 * 1024;
const BGRA: u32 = u32::from_be_bytes(*b"BGRA");

pub(crate) struct MacCapturePlatform;

impl CapturePlatform for MacCapturePlatform {
    fn preflight(&self) -> Result<bool, String> {
        Ok(ScreenCaptureAccess.preflight())
    }

    fn request(&self) -> Result<bool, String> {
        Ok(ScreenCaptureAccess.request())
    }

    fn main_display(&self) -> Result<CaptureDisplay, String> {
        let display = CGDisplay::main();
        let width = u32::try_from(display.pixels_wide())
            .map_err(|_| "Main display width exceeds the Capture bound.".to_owned())?;
        let height = u32::try_from(display.pixels_high())
            .map_err(|_| "Main display height exceeds the Capture bound.".to_owned())?;
        if display.id == 0 || width == 0 || height == 0 {
            return Err("macOS returned no valid main display for Capture.".into());
        }
        Ok(CaptureDisplay {
            id: display.id,
            width,
            height,
            label: format!("Main display {} · {width}×{height}", display.id),
        })
    }

    fn capture_display(&self, display: &CaptureDisplay) -> Result<CapturedPng, String> {
        capture_display(display)
    }

    fn screen_locked(&self) -> Result<bool, String> {
        screen_locked()
    }
}

pub(crate) fn screen_locked() -> Result<bool, String> {
    let dictionary = CGSessionCopyCurrentDictionary()
        .ok_or_else(|| "CoreGraphics returned no current session dictionary.".to_owned())?;
    let key = CFString::from_static_str("CGSSessionScreenIsLocked");
    // SAFETY: both pointers are live CoreFoundation objects for this call. The
    // dictionary is retained above; the fixed key is a valid CFString. We only
    // compare the non-retained value pointer with the process-wide CFBoolean
    // singletons and never construct an object from an untyped value.
    let value = unsafe { dictionary.value(std::ptr::from_ref(&*key).cast()) };
    let true_ptr = unsafe { kCFBooleanTrue }
        .map(|value| std::ptr::from_ref::<CFBoolean>(value).cast())
        .ok_or_else(|| "CoreFoundation exposed no true singleton.".to_owned())?;
    let false_ptr = unsafe { kCFBooleanFalse }
        .map(|value| std::ptr::from_ref::<CFBoolean>(value).cast())
        .ok_or_else(|| "CoreFoundation exposed no false singleton.".to_owned())?;
    if value == true_ptr {
        Ok(true)
    } else if value.is_null() || value == false_ptr {
        Ok(false)
    } else {
        Err("CoreGraphics returned a malformed screen-lock value.".into())
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the asynchronous ScreenCaptureKit callbacks share one bounded completion/timeout ownership transaction"
)]
fn capture_display(display: &CaptureDisplay) -> Result<CapturedPng, String> {
    let (width, height) = bounded_output_geometry(display.width, display.height)?;
    let (sender, receiver) = mpsc::sync_channel(1);
    let completed = Arc::new(AtomicBool::new(false));
    let shot_completed = Arc::clone(&completed);
    let shot_sender = sender.clone();
    let screenshot: RcBlock<dyn Fn(*mut CGImage, *mut NSError)> =
        RcBlock::new(move |image: *mut CGImage, error: *mut NSError| {
            if shot_completed.swap(true, Ordering::AcqRel) {
                return;
            }
            let result = if !error.is_null() {
                Err(nserror(error, "ScreenCaptureKit screenshot failed"))
            } else if let Some(image) = NonNull::new(image) {
                // SAFETY: ScreenCaptureKit documents a valid non-retained
                // CGImage for the duration of this completion callback. We
                // retain it before conversion so every CoreGraphics call is
                // bounded by owned lifetime.
                let image = unsafe { CFRetained::<CGImage>::retain(image) };
                encode_png(&image)
            } else {
                Err("ScreenCaptureKit completed without an image or error.".into())
            };
            let _ = shot_sender.send(result);
        });

    let share_completed = Arc::clone(&completed);
    let share_sender = sender;
    let screenshot_for_share = screenshot.clone();
    let display_id = display.id;
    let shareable: RcBlock<dyn Fn(*mut SCShareableContent, *mut NSError)> = RcBlock::new(
        move |content: *mut SCShareableContent, error: *mut NSError| {
            if share_completed.load(Ordering::Acquire) {
                return;
            }
            let result = (|| {
                if !error.is_null() {
                    return Err(nserror(
                        error,
                        "ScreenCaptureKit content enumeration failed",
                    ));
                }
                // SAFETY: the callback contract supplies either null or a
                // valid SCShareableContent reference. Retaining the non-null
                // pointer makes enumeration lifetime independent of the
                // callback's autorelease pool.
                let content = unsafe { Retained::<SCShareableContent>::retain(content) }
                    .ok_or_else(|| {
                        "ScreenCaptureKit returned no shareable content after permission."
                            .to_owned()
                    })?;
                // SAFETY: `content` is retained and the admitted selector is
                // available on the macOS 15 product floor.
                let displays = unsafe { content.displays() };
                let mut selected: Option<Retained<SCDisplay>> = None;
                for index in 0..displays.count() {
                    let candidate = displays.objectAtIndex(index);
                    // SAFETY: the retained NSArray guarantees each candidate
                    // is a live SCDisplay; displayID is a scalar getter.
                    if unsafe { candidate.displayID() } == display_id {
                        selected = Some(candidate);
                        break;
                    }
                }
                let selected = selected.ok_or_else(|| {
                    "The armed display disappeared before Capture began.".to_owned()
                })?;
                let excluded = NSArray::new();
                // SAFETY: SCContentFilter is AnyThread. Both the selected
                // display and empty excluded-window array are retained through
                // this call and contain the exact generated types.
                let filter = unsafe {
                    SCContentFilter::initWithDisplay_excludingWindows(
                        SCContentFilter::alloc(),
                        &selected,
                        &excluded,
                    )
                };
                // SAFETY: the admitted configuration selectors are available
                // on macOS 15. Values are fixed/bounded, audio and microphone
                // are explicitly disabled, and SDR BGRA is selected.
                let configuration = unsafe {
                    let configuration = SCStreamConfiguration::new();
                    configuration.setWidth(width as usize);
                    configuration.setHeight(height as usize);
                    configuration.setPixelFormat(BGRA);
                    configuration.setShowsCursor(true);
                    configuration.setCapturesAudio(false);
                    configuration.setCaptureMicrophone(false);
                    configuration.setShouldBeOpaque(true);
                    configuration
                };
                // SAFETY: filter/configuration are retained across the exact
                // call, and `screenshot_for_share` is an owned heap block also
                // held by the waiting caller until completion/timeout. The
                // selector is the sole admitted one-frame API.
                unsafe {
                    SCScreenshotManager::captureImageWithFilter_configuration_completionHandler(
                        &filter,
                        &configuration,
                        Some(&screenshot_for_share),
                    );
                }
                Ok(())
            })();
            if let Err(error) = result
                && !share_completed.swap(true, Ordering::AcqRel)
            {
                let _ = share_sender.send(Err(error));
            }
        },
    );

    // SAFETY: `shareable` is an owned heap block held in this stack frame
    // until a terminal callback. The exact selector is present on macOS 15.
    unsafe {
        SCShareableContent::getShareableContentExcludingDesktopWindows_onScreenWindowsOnly_completionHandler(
            false,
            true,
            &shareable,
        );
    }
    match receiver.recv_timeout(CALLBACK_TIMEOUT) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => {
            // There is no cancellation API for these one-shot selectors. Keep
            // our block ownership alive if the OS may invoke it late; the
            // manager permits only one capture operation at a time, bounding
            // this fail-safe leak to a timed-out operation.
            std::mem::forget(shareable);
            std::mem::forget(screenshot);
            Err("ScreenCaptureKit did not complete the bounded still within 30 seconds.".into())
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            Err("ScreenCaptureKit completion channel ended without a frame.".into())
        }
    }
}

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "the positive finite scale is clamped to at most one and both source dimensions are u32, so rounded results remain in 1..=u32::MAX"
)]
fn bounded_output_geometry(source_width: u32, source_height: u32) -> Result<(u32, u32), String> {
    if source_width == 0 || source_height == 0 {
        return Err("Capture source geometry is empty.".into());
    }
    let width_ratio = f64::from(MAX_OUTPUT_WIDTH) / f64::from(source_width);
    let height_ratio = f64::from(MAX_OUTPUT_HEIGHT) / f64::from(source_height);
    let scale = width_ratio.min(height_ratio).min(1.0);
    let width = (f64::from(source_width) * scale).round().max(1.0) as u32;
    let height = (f64::from(source_height) * scale).round().max(1.0) as u32;
    let pixels = usize::try_from(width)
        .ok()
        .and_then(|width| {
            usize::try_from(height)
                .ok()
                .and_then(|height| width.checked_mul(height))
        })
        .ok_or_else(|| "Capture output pixel count overflowed.".to_owned())?;
    if pixels > MAX_OUTPUT_PIXELS {
        return Err("Capture output exceeds the fixed pixel bound.".into());
    }
    Ok((width, height))
}

fn encode_png(image: &CGImage) -> Result<CapturedPng, String> {
    let width = CGImage::width(Some(image));
    let height = CGImage::height(Some(image));
    let pixels = width
        .checked_mul(height)
        .ok_or_else(|| "Capture image pixel count overflowed.".to_owned())?;
    let bytes_per_row = width
        .checked_mul(4)
        .ok_or_else(|| "Capture row size overflowed.".to_owned())?;
    let byte_count = bytes_per_row
        .checked_mul(height)
        .ok_or_else(|| "Capture RGBA size overflowed.".to_owned())?;
    if width == 0 || height == 0 || pixels > MAX_OUTPUT_PIXELS || byte_count > MAX_RGBA_BYTES {
        return Err("ScreenCaptureKit returned empty or oversized image geometry.".into());
    }
    let width_u32 =
        u32::try_from(width).map_err(|_| "Capture PNG width exceeds u32.".to_owned())?;
    let height_u32 =
        u32::try_from(height).map_err(|_| "Capture PNG height exceeds u32.".to_owned())?;
    let mut rgba = vec![0_u8; byte_count];
    let color_space = CGColorSpace::new_device_rgb()
        .ok_or_else(|| "CoreGraphics could not create the bounded RGB color space.".to_owned())?;
    let bitmap_info = CGImageAlphaInfo::PremultipliedLast.0 | CGImageByteOrderInfo::Order32Big.0;
    // SAFETY: `rgba` has exactly `bytes_per_row * height` writable bytes and
    // remains pinned by this stack frame until the retained context is dropped.
    // Geometry and multiplication are checked above; the color space is owned.
    let context = unsafe {
        CGBitmapContextCreate(
            rgba.as_mut_ptr().cast(),
            width,
            height,
            8,
            bytes_per_row,
            Some(&color_space),
            bitmap_info,
        )
    }
    .ok_or_else(|| "CoreGraphics could not create the bounded RGBA context.".to_owned())?;
    let rect = CGRect::new(
        CGPoint::new(0.0, 0.0),
        CGSize::new(f64::from(width_u32), f64::from(height_u32)),
    );
    CGContext::draw_image(Some(&context), rect, Some(image));
    drop(context);
    drop(color_space);

    if !rgba.chunks_exact(4).any(|pixel| pixel[3] != 0) {
        rgba.fill(0);
        return Err("ScreenCaptureKit returned a fully transparent blank frame.".into());
    }
    flip_rows(&mut rgba, bytes_per_row, height);
    unpremultiply_rgba(&mut rgba);
    let mut png_bytes = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut png_bytes, width_u32, height_u32);
        encoder.set_color(png::ColorType::Rgba);
        encoder.set_depth(png::BitDepth::Eight);
        encoder.set_compression(png::Compression::Fast);
        let mut writer = encoder
            .write_header()
            .map_err(|error| format!("Capture PNG header failed: {error}"))?;
        writer
            .write_image_data(&rgba)
            .map_err(|error| format!("Capture PNG encoding failed: {error}"))?;
    }
    rgba.fill(0);
    if png_bytes.len() > MAX_PNG_BYTES {
        png_bytes.fill(0);
        return Err("Capture PNG exceeded the fixed 6 MiB provider bound.".into());
    }
    Ok(CapturedPng {
        bytes: png_bytes,
        width: u32::try_from(width).unwrap_or(u32::MAX),
        height: u32::try_from(height).unwrap_or(u32::MAX),
    })
}

fn flip_rows(bytes: &mut [u8], bytes_per_row: usize, height: usize) {
    for row in 0..height / 2 {
        let opposite = height - row - 1;
        let (before, after) = bytes.split_at_mut(opposite * bytes_per_row);
        before[row * bytes_per_row..(row + 1) * bytes_per_row]
            .swap_with_slice(&mut after[..bytes_per_row]);
    }
}

fn unpremultiply_rgba(bytes: &mut [u8]) {
    for pixel in bytes.chunks_exact_mut(4) {
        let alpha = u16::from(pixel[3]);
        if alpha == 0 || alpha == 255 {
            continue;
        }
        for channel in &mut pixel[..3] {
            *channel = ((u16::from(*channel) * 255 + alpha / 2) / alpha).min(255) as u8;
        }
    }
}

fn nserror(error: *mut NSError, context: &str) -> String {
    // SAFETY: callers invoke this only for a non-null NSError supplied for the
    // duration of a documented completion callback. Retaining it makes the
    // description/code reads independent of the callback autorelease pool.
    let Some(error) = (unsafe { Retained::<NSError>::retain(error) }) else {
        return format!("{context}: unknown macOS error");
    };
    format!(
        "{context}: {} (code {})",
        error.localizedDescription(),
        error.code()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn geometry_is_aspect_preserving_and_bounded() {
        assert_eq!(bounded_output_geometry(2560, 1600), Ok((1280, 800)));
        assert_eq!(bounded_output_geometry(1200, 2400), Ok((450, 900)));
        assert!(bounded_output_geometry(0, 100).is_err());
    }

    #[test]
    fn row_flip_and_unpremultiply_are_deterministic() {
        let mut rows = vec![1, 2, 3, 255, 4, 5, 6, 255];
        flip_rows(&mut rows, 4, 2);
        assert_eq!(rows, vec![4, 5, 6, 255, 1, 2, 3, 255]);
        let mut pixel = vec![64, 32, 16, 128];
        unpremultiply_rgba(&mut pixel);
        assert_eq!(pixel, vec![128, 64, 32, 128]);
    }
}
