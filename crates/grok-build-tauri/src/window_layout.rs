use std::time::Duration;

use tauri::{LogicalPosition, LogicalSize, PhysicalRect, WebviewWindow};

struct Layout {
    position: LogicalPosition<f64>,
    content: LogicalSize<f64>,
    outer: LogicalSize<f64>,
}

pub(crate) fn show(window: WebviewWindow) {
    tauri::async_runtime::spawn(async move {
        if let Err(error) = fit(&window).await {
            eprintln!("GB Plus window placement: {error}");
        }
        if let Err(error) = window.show() {
            eprintln!("GB Plus window could not be shown: {error}");
        }
    });
}

async fn fit(window: &WebviewWindow) -> Result<(), String> {
    let monitor = window
        .current_monitor()
        .map_err(|error| error.to_string())?
        .or(window
            .primary_monitor()
            .map_err(|error| error.to_string())?)
        .ok_or("No screen is available for the main window")?;
    let scale = window.scale_factor().map_err(|error| error.to_string())?;
    let outer = window
        .outer_size()
        .map_err(|error| error.to_string())?
        .to_logical::<f64>(scale);
    let inner = window
        .inner_size()
        .map_err(|error| error.to_string())?
        .to_logical::<f64>(scale);
    let chrome = LogicalSize::new(
        (outer.width - inner.width).max(0.0),
        (outer.height - inner.height).max(0.0),
    );
    let layout = layout(monitor.work_area(), monitor.scale_factor(), chrome)
        .ok_or("The screen's usable bounds are unavailable")?;
    window
        .set_min_size(Some(LogicalSize::new(
            900.0_f64.min(layout.content.width),
            600.0_f64.min(layout.content.height),
        )))
        .map_err(|error| error.to_string())?;
    window
        .set_size(layout.content)
        .map_err(|error| error.to_string())?;
    window
        .set_position(layout.position)
        .map_err(|error| error.to_string())?;

    // AppKit queues size and position separately; wait for both before showing.
    for _ in 0..30 {
        tokio::time::sleep(Duration::from_millis(16)).await;
        let scale = window.scale_factor().map_err(|error| error.to_string())?;
        let position = window
            .outer_position()
            .map_err(|error| error.to_string())?
            .to_logical::<f64>(scale);
        let size = window
            .outer_size()
            .map_err(|error| error.to_string())?
            .to_logical::<f64>(scale);
        if settled(&layout, position, size) {
            return Ok(());
        }
    }
    Err("Startup size and position did not settle within the screen bounds".into())
}

fn layout(work: &PhysicalRect<i32, u32>, scale: f64, chrome: LogicalSize<f64>) -> Option<Layout> {
    if !scale.is_finite() || scale <= 0.0 {
        return None;
    }
    let outer = work.size.to_logical::<f64>(scale);
    let content = LogicalSize::new(outer.width - chrome.width, outer.height - chrome.height);
    if !content.width.is_finite()
        || !content.height.is_finite()
        || content.width <= 0.0
        || content.height <= 0.0
    {
        return None;
    }
    Some(Layout {
        position: work.position.to_logical(scale),
        content,
        outer,
    })
}

fn settled(layout: &Layout, position: LogicalPosition<f64>, size: LogicalSize<f64>) -> bool {
    (position.x - layout.position.x).abs() <= 1.0
        && (position.y - layout.position.y).abs() <= 1.0
        && (size.width - layout.outer.width).abs() <= 1.0
        && (size.height - layout.outer.height).abs() <= 1.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use tauri::{PhysicalPosition, PhysicalSize};

    #[test]
    fn startup_frame_fills_usable_bounds_on_retina_and_offset_monitors() {
        for (origin, size, scale) in [
            ((0, 24), (1440, 816), 1.0),
            ((0, 64), (2880, 1612), 2.0),
            ((-3840, 50), (3840, 2050), 2.0),
            ((1920, -1056), (1920, 1032), 1.0),
        ] {
            let work = PhysicalRect {
                position: PhysicalPosition::from(origin),
                size: PhysicalSize::from(size),
            };
            let chrome = LogicalSize::new(0.0, 28.0);
            let frame = layout(&work, scale, chrome).unwrap();
            assert!((frame.position.x - f64::from(origin.0) / scale).abs() < f64::EPSILON);
            assert!((frame.position.y - f64::from(origin.1) / scale).abs() < f64::EPSILON);
            assert!(
                (frame.content.width + chrome.width - f64::from(size.0) / scale).abs()
                    < f64::EPSILON
            );
            assert!(
                (frame.content.height + chrome.height - f64::from(size.1) / scale).abs()
                    < f64::EPSILON
            );
            assert!(settled(&frame, frame.position, frame.outer));
            assert!(!settled(
                &frame,
                LogicalPosition::new(frame.position.x + frame.outer.width / 2.0, frame.position.y),
                frame.outer
            ));
            assert!(!settled(
                &frame,
                frame.position,
                LogicalSize::new(1040.0, 720.0)
            ));
        }
    }

    #[test]
    fn unusable_display_geometry_is_rejected_without_dividing_by_zero() {
        let work = PhysicalRect {
            position: (0, 0).into(),
            size: (800, 500).into(),
        };
        for scale in [0.0, -1.0, f64::NAN, f64::INFINITY] {
            assert!(layout(&work, scale, LogicalSize::new(0.0, 28.0)).is_none());
        }
        assert!(layout(&work, 1.0, LogicalSize::new(0.0, 600.0)).is_none());
        assert_eq!(
            layout(&work, 1.0, LogicalSize::new(0.0, 28.0))
                .unwrap()
                .content,
            LogicalSize::new(800.0, 472.0)
        );
    }
}
