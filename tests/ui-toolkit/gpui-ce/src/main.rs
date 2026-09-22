use std::{ops::Range, time::Duration};

use gpui::{
    App, Application, Bounds, ClipboardItem, Context, Element, ElementId, ElementInputHandler,
    Entity, EntityInputHandler, FocusHandle, Focusable, GlobalElementId, InspectorElementId,
    KeyBinding, LayoutId, Pixels, Point, SharedString, Style, Timer, UTF16Selection, Window,
    WindowBounds, WindowOptions, actions, div, prelude::*, px, relative, rgb, size, uniform_list,
};

const MESSAGE_COUNT: usize = 1_000;

actions!(
    evaluation,
    [
        CloseWindow,
        CopyTranscript,
        PasteIntoComposer,
        FocusNext,
        FocusPrevious,
        ToggleReducedMotion,
        IncreaseTextScale,
    ]
);

#[derive(Clone, Copy)]
struct UiPreferences {
    reduced_motion: bool,
    text_scale: f32,
}

struct ImeBuffer {
    content: String,
    selection: Range<usize>,
    marked: Option<Range<usize>>,
    focus_handle: FocusHandle,
}

impl ImeBuffer {
    fn new(focus_handle: FocusHandle) -> Self {
        Self {
            content: "IME composition boundary".to_owned(),
            selection: 0..0,
            marked: None,
            focus_handle,
        }
    }

    fn replace_utf16(&mut self, range: Option<Range<usize>>, new_text: &str) -> Range<usize> {
        let bytes = range
            .map(|range| utf16_range_to_bytes(&self.content, range))
            .or_else(|| self.marked.clone())
            .unwrap_or_else(|| self.selection.clone());
        self.content.replace_range(bytes.clone(), new_text);
        let inserted = bytes.start..bytes.start + new_text.len();
        self.selection = inserted.end..inserted.end;
        self.marked = None;
        inserted
    }
}

impl Focusable for ImeBuffer {
    fn focus_handle(&self, _cx: &App) -> FocusHandle {
        self.focus_handle.clone()
    }
}

impl EntityInputHandler for ImeBuffer {
    fn text_for_range(
        &mut self,
        range_utf16: Range<usize>,
        adjusted_range: &mut Option<Range<usize>>,
        _window: &mut Window,
        _cx: &mut Context<Self>,
    ) -> Option<String> {
        let range = utf16_range_to_bytes(&self.content, range_utf16);
        adjusted_range.replace(
            byte_to_utf16(&self.content, range.start)..byte_to_utf16(&self.content, range.end),
        );
        Some(self.content[range].to_owned())
    }

    fn selected_text_range(
        &mut self,
        _ignore_disabled_input: bool,
        _window: &mut Window,
        _cx: &mut Context<Self>,
    ) -> Option<UTF16Selection> {
        Some(UTF16Selection {
            range: byte_to_utf16(&self.content, self.selection.start)
                ..byte_to_utf16(&self.content, self.selection.end),
            reversed: false,
        })
    }

    fn marked_text_range(
        &self,
        _window: &mut Window,
        _cx: &mut Context<Self>,
    ) -> Option<Range<usize>> {
        self.marked.as_ref().map(|range| {
            byte_to_utf16(&self.content, range.start)..byte_to_utf16(&self.content, range.end)
        })
    }

    fn unmark_text(&mut self, _window: &mut Window, cx: &mut Context<Self>) {
        self.marked = None;
        cx.notify();
    }

    fn replace_text_in_range(
        &mut self,
        range_utf16: Option<Range<usize>>,
        new_text: &str,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.replace_utf16(range_utf16, new_text);
        cx.notify();
    }

    fn replace_and_mark_text_in_range(
        &mut self,
        range_utf16: Option<Range<usize>>,
        new_text: &str,
        new_selected_range: Option<Range<usize>>,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let inserted = self.replace_utf16(range_utf16, new_text);
        self.marked = (!inserted.is_empty()).then_some(inserted.clone());
        if let Some(relative_selection) = new_selected_range {
            let relative = utf16_range_to_bytes(new_text, relative_selection);
            self.selection = inserted.start + relative.start..inserted.start + relative.end;
        }
        cx.notify();
    }

    fn bounds_for_range(
        &mut self,
        _range_utf16: Range<usize>,
        element_bounds: Bounds<Pixels>,
        _window: &mut Window,
        _cx: &mut Context<Self>,
    ) -> Option<Bounds<Pixels>> {
        Some(element_bounds)
    }

    fn character_index_for_point(
        &mut self,
        _point: Point<Pixels>,
        _window: &mut Window,
        _cx: &mut Context<Self>,
    ) -> Option<usize> {
        Some(byte_to_utf16(&self.content, self.selection.end))
    }
}

struct ImeElement {
    input: Entity<ImeBuffer>,
}

impl IntoElement for ImeElement {
    type Element = Self;

    fn into_element(self) -> Self::Element {
        self
    }
}

impl Element for ImeElement {
    type RequestLayoutState = ();
    type PrepaintState = ();

    fn id(&self) -> Option<ElementId> {
        None
    }

    fn source_location(&self) -> Option<&'static core::panic::Location<'static>> {
        None
    }

    fn request_layout(
        &mut self,
        _id: Option<&GlobalElementId>,
        _inspector_id: Option<&InspectorElementId>,
        window: &mut Window,
        cx: &mut App,
    ) -> (LayoutId, Self::RequestLayoutState) {
        let mut style = Style::default();
        style.size.width = relative(1.0).into();
        style.size.height = px(32.0).into();
        (window.request_layout(style, [], cx), ())
    }

    fn prepaint(
        &mut self,
        _id: Option<&GlobalElementId>,
        _inspector_id: Option<&InspectorElementId>,
        _bounds: Bounds<Pixels>,
        _request_layout: &mut Self::RequestLayoutState,
        _window: &mut Window,
        _cx: &mut App,
    ) -> Self::PrepaintState {
    }

    fn paint(
        &mut self,
        _id: Option<&GlobalElementId>,
        _inspector_id: Option<&InspectorElementId>,
        bounds: Bounds<Pixels>,
        _request_layout: &mut Self::RequestLayoutState,
        _prepaint: &mut Self::PrepaintState,
        window: &mut Window,
        cx: &mut App,
    ) {
        let focus_handle = self.input.read(cx).focus_handle.clone();
        window.handle_input(
            &focus_handle,
            ElementInputHandler::new(bounds, self.input.clone()),
            cx,
        );
    }
}

struct EvaluationApp {
    root_focus: FocusHandle,
    input: Entity<ImeBuffer>,
    messages: Vec<SharedString>,
    preferences: UiPreferences,
    stream_sequence: usize,
}

impl EvaluationApp {
    fn new(input: Entity<ImeBuffer>, cx: &mut Context<Self>) -> Self {
        Self {
            root_focus: cx.focus_handle(),
            input,
            messages: fixture_messages(),
            preferences: UiPreferences {
                reduced_motion: false,
                text_scale: 1.0,
            },
            stream_sequence: 0,
        }
    }

    fn start_stream(&mut self, cx: &mut Context<Self>) {
        cx.spawn(async move |this, cx| {
            for sequence in 0..16 {
                Timer::after(Duration::from_millis(20)).await;
                let _ = this.update(cx, |this, cx| {
                    let index = sequence % MESSAGE_COUNT;
                    this.messages[index] =
                        format!("stream event {sequence:02} updated message {index:04}").into();
                    this.stream_sequence = sequence + 1;
                    cx.notify();
                });
            }
        })
        .detach();
    }

    fn close_window(&mut self, _: &CloseWindow, window: &mut Window, _: &mut Context<Self>) {
        window.remove_window();
    }

    fn copy_transcript(&mut self, _: &CopyTranscript, _: &mut Window, cx: &mut Context<Self>) {
        let excerpt = self
            .messages
            .iter()
            .take(8)
            .map(AsRef::<str>::as_ref)
            .collect::<Vec<_>>()
            .join("\n");
        cx.write_to_clipboard(ClipboardItem::new_string(excerpt));
    }

    fn paste_into_composer(
        &mut self,
        _: &PasteIntoComposer,
        _: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if let Some(text) = cx.read_from_clipboard().and_then(|item| item.text()) {
            self.input.update(cx, |input, cx| {
                input.replace_utf16(None, &text);
                cx.notify();
            });
        }
    }

    fn focus_next(&mut self, _: &FocusNext, window: &mut Window, _: &mut Context<Self>) {
        window.focus_next();
    }

    fn focus_previous(&mut self, _: &FocusPrevious, window: &mut Window, _: &mut Context<Self>) {
        window.focus_prev();
    }

    fn toggle_reduced_motion(
        &mut self,
        _: &ToggleReducedMotion,
        _: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.preferences.reduced_motion = !self.preferences.reduced_motion;
        cx.notify();
    }

    fn increase_text_scale(
        &mut self,
        _: &IncreaseTextScale,
        _: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.preferences.text_scale = match self.preferences.text_scale {
            scale if scale < 1.25 => 1.25,
            scale if scale < 1.5 => 1.5,
            _ => 1.0,
        };
        cx.notify();
    }
}

impl Render for EvaluationApp {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let input_text = self.input.read(cx).content.clone();
        let input_focus = self.input.read(cx).focus_handle.clone();
        let focus_for_click = input_focus.clone();
        let input = self.input.clone();
        let messages = self.messages.clone();
        let status = format!(
            "stream={} reduced-motion={} text-scale={:.2}",
            self.stream_sequence, self.preferences.reduced_motion, self.preferences.text_scale
        );

        div()
            .id("evaluation-root")
            .track_focus(&self.root_focus)
            .key_context("GpuiEvaluation")
            .on_action(cx.listener(Self::close_window))
            .on_action(cx.listener(Self::copy_transcript))
            .on_action(cx.listener(Self::paste_into_composer))
            .on_action(cx.listener(Self::focus_next))
            .on_action(cx.listener(Self::focus_previous))
            .on_action(cx.listener(Self::toggle_reduced_motion))
            .on_action(cx.listener(Self::increase_text_scale))
            .size_full()
            .flex()
            .flex_col()
            .gap_2()
            .p_3()
            .bg(rgb(0xf7f7f7))
            .text_color(rgb(0x171717))
            .text_size(px(14.0 * self.preferences.text_scale))
            .child(status)
            .child(
                div()
                    .id("ime-composer")
                    .track_focus(&input_focus)
                    .tab_index(1)
                    .tab_stop(true)
                    .border_1()
                    .border_color(rgb(0x555555))
                    .p_2()
                    .on_click(move |_, window, _| focus_for_click.focus(window))
                    .child(input_text)
                    .child(ImeElement { input }),
            )
            .child(
                div()
                    .id("copy-control")
                    .tab_index(2)
                    .tab_stop(true)
                    .border_1()
                    .p_2()
                    .child("Copy: cmd-c | Paste: cmd-v | Scale: cmd-plus | Motion: cmd-m"),
            )
            .child(
                uniform_list("message-timeline", messages.len(), move |range, _, _| {
                    range
                        .map(|index| {
                            div()
                                .id(("message", index))
                                .h(px(28.0))
                                .px_2()
                                .border_b_1()
                                .border_color(rgb(0xdddddd))
                                .child(messages[index].clone())
                        })
                        .collect()
                })
                .id("virtualized-1000-message-timeline")
                .flex_1(),
            )
    }
}

fn fixture_messages() -> Vec<SharedString> {
    (0..MESSAGE_COUNT)
        .map(|index| format!("fixture message {index:04}").into())
        .collect()
}

fn utf16_to_byte(text: &str, target: usize) -> usize {
    let mut utf16_offset = 0;
    for (byte_offset, character) in text.char_indices() {
        if utf16_offset >= target {
            return byte_offset;
        }
        utf16_offset += character.len_utf16();
        if utf16_offset >= target {
            return byte_offset + character.len_utf8();
        }
    }
    text.len()
}

fn byte_to_utf16(text: &str, target: usize) -> usize {
    text[..target.min(text.len())].encode_utf16().count()
}

fn utf16_range_to_bytes(text: &str, range: Range<usize>) -> Range<usize> {
    utf16_to_byte(text, range.start)..utf16_to_byte(text, range.end)
}

fn main() {
    Application::new().run(|cx: &mut App| {
        cx.bind_keys([
            KeyBinding::new("cmd-w", CloseWindow, None),
            KeyBinding::new("cmd-c", CopyTranscript, Some("GpuiEvaluation")),
            KeyBinding::new("cmd-v", PasteIntoComposer, Some("GpuiEvaluation")),
            KeyBinding::new("tab", FocusNext, Some("GpuiEvaluation")),
            KeyBinding::new("shift-tab", FocusPrevious, Some("GpuiEvaluation")),
            KeyBinding::new("cmd-m", ToggleReducedMotion, Some("GpuiEvaluation")),
            KeyBinding::new("cmd-plus", IncreaseTextScale, Some("GpuiEvaluation")),
        ]);

        cx.on_window_closed(|cx| {
            if cx.windows().is_empty() {
                cx.quit();
            }
        })
        .detach();

        let bounds = Bounds::centered(None, size(px(760.0), px(640.0)), cx);
        cx.open_window(
            WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(bounds)),
                ..Default::default()
            },
            |window, cx| {
                let input_focus = cx.focus_handle().tab_index(1).tab_stop(true);
                let input = cx.new(|_| ImeBuffer::new(input_focus.clone()));
                let view = cx.new(|cx| EvaluationApp::new(input, cx));
                view.update(cx, |view, cx| view.start_stream(cx));
                input_focus.focus(window);
                view
            },
        )
        .expect("evaluation window must open");

        cx.activate(true);
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeline_fixture_contains_exactly_one_thousand_messages() {
        let messages = fixture_messages();
        assert_eq!(messages.len(), MESSAGE_COUNT);
        assert_eq!(
            messages.first().map(AsRef::<str>::as_ref),
            Some("fixture message 0000")
        );
        assert_eq!(
            messages.last().map(AsRef::<str>::as_ref),
            Some("fixture message 0999")
        );
    }

    #[test]
    fn utf16_boundary_handles_supplementary_characters() {
        let text = "A😀文";
        assert_eq!(utf16_to_byte(text, 0), 0);
        assert_eq!(utf16_to_byte(text, 1), 1);
        assert_eq!(utf16_to_byte(text, 3), 5);
        assert_eq!(byte_to_utf16(text, 5), 3);
        assert_eq!(utf16_range_to_bytes(text, 1..3), 1..5);
    }

    #[test]
    fn preferences_have_safe_initial_values() {
        let preferences = UiPreferences {
            reduced_motion: true,
            text_scale: 1.5,
        };
        assert!(preferences.reduced_motion);
        assert!((1.0..=2.0).contains(&preferences.text_scale));
    }
}
