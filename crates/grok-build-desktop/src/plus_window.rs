//! GB Plus native window on the admitted `slint =1.17.1` pin.
//!
//! Slint types stay in this module. This crate does not `pub use slint`.
//! Last workspace, chat transcript, and contained-run text restore from the
//! documented desktop state root. Unreadable state is "could not restore".

use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;

use crate::admitted_ui_runtime::ADMITTED_UI_RUNTIME;
use crate::plus_host::{
    BoundProject, PLUS_ACCEPT_GROUP, PLUS_COMMAND_SECURITY_LEGEND, PLUS_GH_MISSING,
    PLUS_GH_OPEN_PR, PLUS_GH_STATUS, PLUS_GUEST_ACTION_REPAIR_HINTS,
    PLUS_GUEST_ACTION_START_COLIMA, PLUS_GUEST_ACTION_VERIFY_INSTALL, PLUS_MODE_AGENT,
    PLUS_NEEDS_ACCEPT, PLUS_NOT_NOW, PLUS_PRODUCT_VERSION, PLUS_REJECT_GROUP,
    PLUS_TOOL_LOOP_NOT_RUN, PLUS_TOOL_NOTE_PATH, PLUS_TOOL_PROPOSE_PATH, PLUS_TURN_NOT_STUCK,
    PLUS_TURN_ON_EXTRA_SECURITY, PendingFileSet, PlusAgentStatus, PlusAttachment, PlusChatTurn,
    PlusCommandSecurityKind, PlusCommandSecurityPreference, PlusLiveIdentity, PlusRestoredSession,
    PlusSessionMode, PlusSessionStore, accept_pending_file_in_set, accept_pending_file_set,
    accept_pending_group_in_set, attach_plus_file, bind_and_remember_project_folder,
    bind_project_folder, classify_command_security, plus_chat_provider_label,
    plus_chat_turn_and_remember_with_attachments_in_mode, plus_continue_stuck_turn_and_remember,
    plus_file_path_from_tool_steps, plus_git_commit_accepted, plus_git_status_report,
    plus_github_open_pr, plus_github_status_report, plus_gui_contained_command_and_remember,
    plus_retry_stuck_step_and_remember, plus_run_checks_after_accept_and_remember,
    post_plus_live_chat, prepare_plus_guest, present_command_security_panel,
    present_command_security_status, present_install_root_report, present_needs_accept_inbox,
    present_pending_file_set, present_plus_agent_status, present_plus_agent_status_trail,
    present_plus_context_chips, present_plus_file_pane, present_plus_guest_lifecycle,
    present_plus_guest_repair_hints, present_plus_host_error, present_plus_session_mode,
    present_plus_tool_steps, present_plus_turn_plan, probe_plus_guest_lifecycle,
    propose_assistant_text_as_file, push_plus_attachment, reject_pending_file_in_set,
    reject_pending_file_set, reject_pending_group_in_set, restore_plus_session,
    start_colima_if_safe,
};
use crate::plus_theme::{
    SpaceToken, accept_action_fill, command_security_chip_fill, plus_default_nav,
    plus_nav_from_index, plus_nav_label, plus_nav_view_index, plus_review_badge_visible,
    product_accent, reject_action_fill, space_palette,
};

slint::slint! {
    import { ScrollView, AboutSlint, Palette } from "std-widgets.slint";

    export global SpaceChrome {
        in-out property <color> space-void;
        in-out property <color> space-floor;
        in-out property <color> space-recessed;
        in-out property <color> space-grey;
        in-out property <color> space-raised;
        in-out property <color> space-edge;
        in-out property <color> space-silver;
        in-out property <color> space-silver-bright;
        in-out property <color> space-white;
        in-out property <color> space-muted;
        in-out property <color> space-accent;
        in-out property <color> space-warn;
        in-out property <color> space-refuse;
        in-out property <color> command-security-chip;
        in-out property <color> accept-fill;
        in-out property <color> reject-fill;
    }

    enum SpaceButtonRole {
        chrome,
        primary,
        accept,
        accept-secondary,
        refuse,
        segment,
    }

    component SpaceLabel inherits Text {
        color: SpaceChrome.space-white;
        wrap: word-wrap;
        font-size: 13px;
    }

    component SpaceHint inherits Text {
        color: SpaceChrome.space-muted;
        wrap: word-wrap;
        font-size: 11px;
    }

    component SpaceEyebrow inherits Text {
        color: SpaceChrome.space-silver;
        font-size: 10px;
        font-weight: 700;
        letter-spacing: 1.1px;
        wrap: no-wrap;
    }

    component SpacePanel inherits Rectangle {
        background: SpaceChrome.space-grey;
        border-width: 1px;
        border-color: SpaceChrome.space-edge;
        border-radius: 8px;
    }

    component SpaceButton {
        in property <string> text;
        in property <SpaceButtonRole> role: SpaceButtonRole.chrome;
        in property <bool> active: true;
        in property <bool> compact: false;
        in property <bool> enabled <=> area.enabled;
        callback clicked;

        private property <bool> filled-accent: (root.role == SpaceButtonRole.primary) || (root.role == SpaceButtonRole.accept && root.active);
        private property <bool> outlined-accent: root.role == SpaceButtonRole.accept-secondary && root.active;
        private property <color> base-fill: root.role == SpaceButtonRole.primary ? SpaceChrome.space-accent : (root.role == SpaceButtonRole.accept && root.active ? SpaceChrome.accept-fill : (root.role == SpaceButtonRole.refuse ? SpaceChrome.reject-fill.with-alpha(0.12) : (root.role == SpaceButtonRole.segment && root.active ? SpaceChrome.space-accent.with-alpha(0.18) : (root.outlined-accent ? SpaceChrome.accept-fill.with-alpha(0.10) : SpaceChrome.space-raised))));
        private property <color> base-stroke: root.role == SpaceButtonRole.primary ? SpaceChrome.space-accent : (root.role == SpaceButtonRole.accept && root.active ? SpaceChrome.accept-fill : (root.role == SpaceButtonRole.refuse ? SpaceChrome.reject-fill : ((root.role == SpaceButtonRole.segment && root.active) ? SpaceChrome.space-accent : (root.outlined-accent ? SpaceChrome.accept-fill : SpaceChrome.space-edge))));
        private property <color> label-color: !root.enabled ? SpaceChrome.space-muted : (root.filled-accent ? SpaceChrome.space-white : (root.role == SpaceButtonRole.refuse ? SpaceChrome.space-refuse : (root.outlined-accent || (root.role == SpaceButtonRole.segment && root.active) ? SpaceChrome.space-silver-bright : SpaceChrome.space-white)));

        min-height: root.compact ? 28px : 34px;
        horizontal-stretch: 0;
        vertical-stretch: 0;
        forward-focus: focus-scope;
        accessible-role: button;
        accessible-label: text;
        accessible-enabled: enabled;
        accessible-action-default => {
            if (root.enabled) {
                root.clicked();
            }
        }

        button-face := Rectangle {
            border-radius: root.role == SpaceButtonRole.segment ? 3px : 5px;
            border-width: 1px;
            border-color: area.has-hover && root.enabled ? SpaceChrome.space-silver-bright : root.base-stroke;
            background: !root.enabled ? root.base-fill.with-alpha(0.45) : root.base-fill;

            HorizontalLayout {
                padding-left: root.compact ? 9px : 12px;
                padding-right: root.compact ? 9px : 12px;
                padding-top: root.compact ? 4px : 6px;
                padding-bottom: root.compact ? 4px : 6px;
                alignment: center;
                Text {
                    text: root.text;
                    color: root.label-color;
                    font-size: root.compact ? 10px : 12px;
                    font-weight: (root.filled-accent || (root.active && root.role == SpaceButtonRole.segment)) ? 650 : 500;
                    horizontal-alignment: center;
                    vertical-alignment: center;
                }
            }

            area := TouchArea {
                clicked => {
                    if (root.enabled) {
                        root.clicked();
                    }
                }
            }

            if (area.pressed && root.enabled): Rectangle {
                border-radius: parent.border-radius;
                background: SpaceChrome.space-void.with-alpha(0.22);
            }
        }

        focus-scope := FocusScope {
            x: 0px;
            width: 0px;
            enabled: root.enabled;
            key-pressed(event) => {
                if (event.text == " " || event.text == "\n") {
                    root.clicked();
                    return accept;
                }
                return reject;
            }
        }

        if (focus-scope.has-focus && root.enabled): Rectangle {
            border-radius: button-face.border-radius + 2px;
            border-width: 1px;
            border-color: SpaceChrome.space-accent;
        }
    }

    component SpaceLineEdit {
        in-out property <string> text;
        in property <string> placeholder-text;
        in property <bool> compact: false;
        min-height: root.compact ? 28px : 34px;
        horizontal-stretch: 1;
        vertical-stretch: 0;
        forward-focus: input;

        input-face := Rectangle {
            border-radius: 5px;
            border-width: 1px;
            border-color: input.has-focus ? SpaceChrome.space-accent : SpaceChrome.space-edge;
            background: SpaceChrome.space-recessed;
            clip: true;

            if (root.text == ""): Text {
                x: 11px;
                width: parent.width - 22px;
                height: 100%;
                vertical-alignment: center;
                text: root.placeholder-text;
                color: SpaceChrome.space-muted;
                font-size: root.compact ? 10px : 12px;
                overflow: elide;
                accessible-role: none;
            }

            input-clip := Rectangle {
                x: 11px;
                width: parent.width - 22px;
                height: parent.height;
                clip: true;
                input := TextInput {
                    text <=> root.text;
                    width: max(parent.width, self.preferred-width);
                    height: parent.height;
                    color: SpaceChrome.space-white;
                    selection-background-color: SpaceChrome.space-accent;
                    selection-foreground-color: SpaceChrome.space-white;
                    single-line: true;
                    vertical-alignment: center;
                    font-size: root.compact ? 10px : 12px;
                    accessible-placeholder-text: root.placeholder-text;
                    cursor-position-changed(cpos) => {
                        if (cpos.x + self.x < 0px) {
                            self.x = -cpos.x;
                        } else if (cpos.x + self.x > parent.width - self.text-cursor-width) {
                            self.x = parent.width - cpos.x - self.text-cursor-width;
                        }
                    }
                }
            }

        }
    }

    component SpaceReadout {
        in property <string> text;
        in property <bool> empty: false;
        in property <bool> monospace: true;
        in property <length> text-size: 11px;

        min-height: 56px;
        horizontal-stretch: 1;
        vertical-stretch: 1;
        forward-focus: readout;

        Rectangle {
            background: SpaceChrome.space-recessed;
            border-width: 1px;
            border-color: readout.has-focus ? SpaceChrome.space-accent : SpaceChrome.space-edge;
            border-radius: 5px;
            clip: true;

            if (root.empty): SpaceHint {
                x: 18px;
                y: 12px;
                width: parent.width - 36px;
                height: parent.height - 24px;
                text: root.text;
                horizontal-alignment: center;
                vertical-alignment: center;
                font-size: 12px;
            }

            readout-scroll := ScrollView {
                x: 10px;
                y: 9px;
                width: parent.width - 20px;
                height: parent.height - 18px;
                visible: !root.empty;
                viewport-width: self.visible-width;
                viewport-height: max(self.visible-height, readout.preferred-height);
                horizontal-scrollbar-policy: ScrollBarPolicy.always-off;

                readout := TextInput {
                    text: root.text;
                    enabled: !root.empty;
                    read-only: true;
                    single-line: false;
                    wrap: word-wrap;
                    width: readout-scroll.visible-width;
                    height: max(readout-scroll.visible-height, self.preferred-height);
                    page-height: readout-scroll.visible-height;
                    color: SpaceChrome.space-white;
                    selection-background-color: SpaceChrome.space-accent;
                    selection-foreground-color: SpaceChrome.space-white;
                    font-size: root.text-size;
                    font-family: root.monospace ? "Menlo" : "";
                }
            }
        }
    }

    component SpaceStatusChip {
        in property <string> text;
        in property <color> tone: SpaceChrome.space-edge;

        min-height: 28px;
        horizontal-stretch: 0;
        vertical-stretch: 0;

        Rectangle {
            border-radius: 14px;
            border-width: 1px;
            border-color: root.tone;
            background: root.tone.with-alpha(0.14);
            HorizontalLayout {
                padding-left: 10px;
                padding-right: 11px;
                padding-top: 5px;
                padding-bottom: 5px;
                spacing: 7px;
                alignment: center;
                Rectangle {
                    width: 7px;
                    height: 7px;
                    border-radius: 4px;
                    background: root.tone;
                }
                Text {
                    text: root.text;
                    color: SpaceChrome.space-white;
                    font-size: 10px;
                    font-weight: 700;
                    vertical-alignment: center;
                }
            }
        }
    }

    component SpaceNavItem {
        in property <string> text;
        in property <bool> active: false;
        in property <bool> badge: false;
        callback clicked;

        min-height: 32px;
        horizontal-stretch: 1;
        accessible-role: button;
        accessible-label: text;
        accessible-action-default => { root.clicked(); }

        Rectangle {
            border-radius: 5px;
            border-width: 1px;
            border-color: root.active ? SpaceChrome.space-accent : SpaceChrome.space-edge;
            background: root.active ? SpaceChrome.space-accent.with-alpha(0.18) : (area.has-hover ? SpaceChrome.space-raised : transparent);

            HorizontalLayout {
                padding-left: 10px;
                padding-right: 8px;
                padding-top: 6px;
                padding-bottom: 6px;
                spacing: 8px;
                alignment: center;
                Text {
                    text: root.text;
                    color: root.active ? SpaceChrome.space-white : SpaceChrome.space-silver;
                    font-size: 12px;
                    font-weight: root.active ? 650 : 500;
                    horizontal-stretch: 1;
                    overflow: elide;
                    vertical-alignment: center;
                }
                if (root.badge): Rectangle {
                    width: 7px;
                    height: 7px;
                    border-radius: 4px;
                    background: SpaceChrome.space-accent;
                }
            }

            area := TouchArea {
                clicked => { root.clicked(); }
            }
        }
    }

    export component GrokBuildPlusWindow inherits Window {
        title: "GB Plus";
        preferred-width: 1200px;
        preferred-height: 800px;
        min-width: 900px;
        min-height: 600px;
        background: SpaceChrome.space-void;
        default-font-size: 13px;

        init => {
            Palette.color-scheme = ColorScheme.dark;
        }

        in-out property <string> folder-path;
        in-out property <string> folder-status: "No project folder bound.";
        in-out property <string> chat-log: "No chat yet.";
        in-out property <string> draft;
        in-out property <string> command-outcome: "No contained command has been attempted.";
        in-out property <string> pending-diff: "No pending file proposal.";
        in-out property <string> needs-accept: "Needs Accept";
        in-out property <string> file-path;
        in-out property <string> group-id;
        in-out property <string> attach-path;
        in-out property <string> attach-list: "Context: @file";
        in-out property <string> session-name;
        in-out property <string> session-list: "No sessions.";
        in-out property <string> session-mode: "Agent";
        in-out property <string> plan-steps: "Plan";
        in-out property <string> git-status: "No git status yet.";
        in-out property <string> file-view: "No file open.";
        in-out property <string> tool-steps: "No tool loop yet.";
        in-out property <string> agent-status: "planning";
        in-out property <string> guest-status: "Command security: Off";
        in-out property <string> guest-copy: "extra security for command runs is optional. Chat, file proposals, and Accept work without it.\nCommands are not fully isolated.";
        in-out property <string> guest-detail: "Advanced: guest down / service missing / ready";
        in-out property <bool> has-pending-review: false;
        in-out property <int> main-view: 1;
        in property <string> product-version;
        in property <string> provider-label;
        in property <string> onboarding: "Set XAI_API_KEY for live chat, or use the labeled stub. Bind a folder, chat, and Accept file edits. Extra security for command runs is optional.";

        callback bind-folder();
        callback send-chat();
        callback run-contained();
        callback propose-file();
        callback accept-proposal();
        callback reject-proposal();
        callback accept-file();
        callback reject-file();
        callback accept-group();
        callback reject-group();
        callback show-github-status();
        callback open-pr();
        callback attach-file();
        callback create-session();
        callback switch-session();
        callback rename-session();
        callback show-git-status();
        callback commit-accepted();
        callback open-file();
        callback run-checks();
        callback start-colima();
        callback verify-install-root();
        callback show-repair-hints();
        callback prepare-guest();
        callback turn-on-extra-security();
        callback not-now();
        callback continue-turn();
        callback retry-step();
        callback select-ask();
        callback select-agent();
        callback select-checks();
        callback select-nav(int);

        Rectangle {
            background: SpaceChrome.space-void;

            VerticalLayout {
                padding: 12px;
                spacing: 10px;

                header := SpacePanel {
                    height: 56px;
                    vertical-stretch: 0;
                    background: SpaceChrome.space-floor;

                    HorizontalLayout {
                        padding-left: 14px;
                        padding-right: 12px;
                        spacing: 12px;
                        alignment: center;

                        SpaceLabel {
                            text: "GB Plus";
                            font-size: 18px;
                            font-weight: 750;
                            wrap: no-wrap;
                            vertical-alignment: center;
                        }
                        SpaceHint {
                            text: product-version;
                            font-size: 11px;
                            wrap: no-wrap;
                            vertical-alignment: center;
                        }
                        Rectangle {
                            background: transparent;
                            horizontal-stretch: 1;
                        }
                        SpaceEyebrow {
                            text: "COMMAND SECURITY";
                            vertical-alignment: center;
                        }
                        SpaceStatusChip {
                            text: guest-status;
                            tone: SpaceChrome.command-security-chip;
                        }
                    }
                }

                HorizontalLayout {
                    spacing: 10px;
                    vertical-stretch: 1;

                    rail := SpacePanel {
                        width: 176px;
                        horizontal-stretch: 0;
                        background: SpaceChrome.space-floor;

                        VerticalLayout {
                            padding: 10px;
                            spacing: 4px;

                            SpaceEyebrow { text: "NAV"; }

                            SpaceNavItem {
                                text: "Project";
                                active: main-view == 0;
                                clicked => { select-nav(0); }
                            }
                            SpaceNavItem {
                                text: "Chat";
                                active: main-view == 1;
                                clicked => { select-nav(1); }
                            }
                            SpaceNavItem {
                                text: "Review";
                                active: main-view == 2;
                                badge: has-pending-review;
                                clicked => { select-nav(2); }
                            }
                            SpaceNavItem {
                                text: "Checks";
                                active: main-view == 3;
                                clicked => { select-nav(3); }
                            }
                            SpaceNavItem {
                                text: "Settings / About";
                                active: main-view == 4;
                                clicked => { select-nav(4); }
                            }

                            Rectangle {
                                background: transparent;
                                vertical-stretch: 1;
                            }
                        }
                    }

                    main-deck := SpacePanel {
                        horizontal-stretch: 1;
                        vertical-stretch: 1;
                        background: SpaceChrome.space-grey;

                        if (main-view == 0): VerticalLayout {
                            width: parent.width;
                            height: parent.height;
                            padding: 14px;
                            spacing: 10px;

                            SpaceEyebrow { text: "PROJECT"; }
                            SpaceHint {
                                text: onboarding;
                                font-size: 11px;
                            }
                            HorizontalLayout {
                                height: 34px;
                                spacing: 7px;
                                SpaceLineEdit {
                                    text <=> folder-path;
                                    placeholder-text: "Absolute project folder";
                                    horizontal-stretch: 1;
                                }
                                SpaceButton {
                                    text: "Bind folder";
                                    clicked => { bind-folder(); }
                                }
                            }
                            SpaceHint {
                                text: folder-status;
                                wrap: no-wrap;
                                overflow: elide;
                            }
                            SpaceEyebrow { text: "SESSIONS"; }
                            SpaceHint { text: "idle / running / needs accept"; }
                            SpaceHint {
                                text: session-list;
                                wrap: no-wrap;
                                overflow: elide;
                            }
                            HorizontalLayout {
                                height: 34px;
                                spacing: 5px;
                                SpaceLineEdit {
                                    text <=> session-name;
                                    placeholder-text: "Session name or id";
                                    compact: true;
                                    horizontal-stretch: 1;
                                }
                                SpaceButton {
                                    text: "Create session";
                                    compact: true;
                                    clicked => { create-session(); }
                                }
                                SpaceButton {
                                    text: "Switch session";
                                    compact: true;
                                    clicked => { switch-session(); }
                                }
                                SpaceButton {
                                    text: "Rename session";
                                    compact: true;
                                    clicked => { rename-session(); }
                                }
                            }
                            SpaceReadout {
                                text: "Git\n" + git-status + "\n\nFile\n" + file-view;
                                empty: false;
                                text-size: 10px;
                                vertical-stretch: 1;
                            }
                            HorizontalLayout {
                                height: 32px;
                                spacing: 5px;
                                SpaceButton {
                                    text: "Git status";
                                    compact: true;
                                    clicked => { show-git-status(); }
                                }
                                SpaceButton {
                                    text: "Commit accepted";
                                    compact: true;
                                    clicked => { commit-accepted(); }
                                }
                                SpaceButton {
                                    text: "Open file";
                                    compact: true;
                                    clicked => { open-file(); }
                                }
                                SpaceButton {
                                    text: "GitHub status";
                                    compact: true;
                                    clicked => { show-github-status(); }
                                }
                                SpaceButton {
                                    text: "Open PR";
                                    compact: true;
                                    clicked => { open-pr(); }
                                }
                            }
                        }

                        if (main-view == 1): VerticalLayout {
                            width: parent.width;
                            height: parent.height;
                            padding: 14px;
                            spacing: 10px;

                            HorizontalLayout {
                                height: 28px;
                                alignment: center;
                                SpaceEyebrow {
                                    text: "CHAT";
                                    horizontal-stretch: 1;
                                }
                                SpaceHint {
                                    text: attach-list;
                                    wrap: no-wrap;
                                    overflow: elide;
                                    horizontal-alignment: right;
                                }
                                SpaceButton {
                                    text: "Ask";
                                    role: SpaceButtonRole.segment;
                                    active: session-mode == "Ask";
                                    compact: true;
                                    clicked => { select-ask(); }
                                }
                                SpaceButton {
                                    text: "Agent";
                                    role: SpaceButtonRole.segment;
                                    active: session-mode == "Agent";
                                    compact: true;
                                    clicked => { select-agent(); }
                                }
                                SpaceButton {
                                    text: "Checks";
                                    role: SpaceButtonRole.segment;
                                    active: session-mode == "Checks";
                                    compact: true;
                                    clicked => { select-checks(); }
                                }
                            }
                            SpaceReadout {
                                text: chat-log;
                                empty: chat-log == "No chat yet.";
                                monospace: false;
                                text-size: 12px;
                                vertical-stretch: 1;
                            }
                            HorizontalLayout {
                                height: 32px;
                                spacing: 7px;
                                SpaceLineEdit {
                                    text <=> attach-path;
                                    placeholder-text: "Relative file to attach (@file)";
                                    compact: true;
                                    horizontal-stretch: 1;
                                }
                                SpaceButton {
                                    text: "Attach file";
                                    compact: true;
                                    clicked => { attach-file(); }
                                }
                                SpaceButton {
                                    text: "Propose as file change";
                                    compact: true;
                                    clicked => { propose-file(); }
                                }
                            }
                            HorizontalLayout {
                                height: 40px;
                                spacing: 8px;
                                SpaceLineEdit {
                                    text <=> draft;
                                    placeholder-text: "Ask about this project";
                                    horizontal-stretch: 1;
                                }
                                SpaceButton {
                                    text: "Send";
                                    role: SpaceButtonRole.primary;
                                    width: 84px;
                                    clicked => { send-chat(); }
                                }
                            }
                        }

                        if (main-view == 2): VerticalLayout {
                            width: parent.width;
                            height: parent.height;
                            padding: 14px;
                            spacing: 10px;
                            accessible-role: groupbox;
                            accessible-label: "Pending review";

                            HorizontalLayout {
                                height: 28px;
                                alignment: center;
                                SpaceEyebrow {
                                    text: "PENDING REVIEW";
                                    horizontal-stretch: 1;
                                }
                                SpaceStatusChip {
                                    text: has-pending-review ? "Needs Accept" : "No pending";
                                    tone: has-pending-review ? SpaceChrome.space-accent : SpaceChrome.space-edge;
                                }
                            }
                            SpaceHint {
                                text: needs-accept;
                            }
                            SpaceReadout {
                                text: pending-diff;
                                empty: pending-diff == "No pending file proposal.";
                                text-size: 11px;
                                vertical-stretch: 1;
                            }
                            SpaceHint {
                                text: has-pending-review ? "Accept required" : "No staged writes";
                                color: has-pending-review ? SpaceChrome.space-silver-bright : SpaceChrome.space-muted;
                            }
                            HorizontalLayout {
                                height: 32px;
                                spacing: 5px;
                                SpaceLineEdit {
                                    text <=> file-path;
                                    placeholder-text: "Relative path for per-file accept/reject";
                                    compact: true;
                                    horizontal-stretch: 1;
                                }
                                SpaceButton {
                                    text: "Accept file";
                                    role: SpaceButtonRole.accept-secondary;
                                    active: has-pending-review;
                                    compact: true;
                                    clicked => { accept-file(); }
                                }
                                SpaceButton {
                                    text: "Reject file";
                                    role: SpaceButtonRole.refuse;
                                    compact: true;
                                    clicked => { reject-file(); }
                                }
                            }
                            HorizontalLayout {
                                height: 32px;
                                spacing: 5px;
                                SpaceLineEdit {
                                    text <=> group-id;
                                    placeholder-text: "Group id for per-group accept/reject";
                                    compact: true;
                                    horizontal-stretch: 1;
                                }
                                SpaceButton {
                                    text: "Accept group";
                                    role: SpaceButtonRole.accept-secondary;
                                    active: has-pending-review;
                                    compact: true;
                                    clicked => { accept-group(); }
                                }
                                SpaceButton {
                                    text: "Reject group";
                                    role: SpaceButtonRole.refuse;
                                    compact: true;
                                    clicked => { reject-group(); }
                                }
                            }
                            HorizontalLayout {
                                height: 44px;
                                spacing: 8px;
                                SpaceButton {
                                    text: "Accept all";
                                    role: SpaceButtonRole.accept;
                                    active: has-pending-review;
                                    horizontal-stretch: 1;
                                    clicked => { accept-proposal(); }
                                }
                                SpaceButton {
                                    text: "Reject all";
                                    role: SpaceButtonRole.refuse;
                                    clicked => { reject-proposal(); }
                                }
                            }
                        }

                        if (main-view == 3): VerticalLayout {
                            width: parent.width;
                            height: parent.height;
                            padding: 14px;
                            spacing: 10px;

                            HorizontalLayout {
                                height: 28px;
                                alignment: center;
                                SpaceEyebrow {
                                    text: "COMMAND SECURITY";
                                    horizontal-stretch: 1;
                                }
                                SpaceStatusChip {
                                    text: guest-status;
                                    tone: SpaceChrome.command-security-chip;
                                }
                            }
                            SpaceHint {
                                text: "Command security: Off | Setting up | On | Needs attention";
                            }
                            SpaceHint {
                                text: guest-copy;
                            }
                            SpaceHint {
                                text: guest-detail;
                                wrap: no-wrap;
                                overflow: elide;
                            }
                            HorizontalLayout {
                                height: 34px;
                                spacing: 6px;
                                SpaceButton {
                                    text: "Turn on extra security";
                                    role: SpaceButtonRole.primary;
                                    clicked => { turn-on-extra-security(); }
                                }
                                SpaceButton {
                                    text: "Not now";
                                    clicked => { not-now(); }
                                }
                            }
                            SpaceReadout {
                                text: "Status  " + agent-status + "\n\n" + plan-steps + "\n\nTool steps\n" + tool-steps + "\n\n" + command-outcome;
                                empty: false;
                                text-size: 10px;
                                vertical-stretch: 1;
                            }
                            HorizontalLayout {
                                height: 32px;
                                spacing: 5px;
                                SpaceButton {
                                    text: "Continue";
                                    compact: true;
                                    clicked => { continue-turn(); }
                                }
                                SpaceButton {
                                    text: "Retry";
                                    compact: true;
                                    clicked => { retry-step(); }
                                }
                                SpaceButton {
                                    text: "Run contained command";
                                    compact: true;
                                    clicked => { run-contained(); }
                                }
                                SpaceButton {
                                    text: "Run tests/build";
                                    compact: true;
                                    clicked => { run-checks(); }
                                }
                            }
                            SpaceEyebrow { text: "ADVANCED"; }
                            HorizontalLayout {
                                height: 32px;
                                spacing: 5px;
                                SpaceButton {
                                    text: "prepare guest";
                                    compact: true;
                                    horizontal-stretch: 1;
                                    clicked => { prepare-guest(); }
                                }
                                SpaceButton {
                                    text: "start Colima (if safe)";
                                    compact: true;
                                    horizontal-stretch: 1;
                                    clicked => { start-colima(); }
                                }
                                SpaceButton {
                                    text: "verify install root";
                                    compact: true;
                                    horizontal-stretch: 1;
                                    clicked => { verify-install-root(); }
                                }
                                SpaceButton {
                                    text: "repair hints";
                                    compact: true;
                                    horizontal-stretch: 1;
                                    clicked => { show-repair-hints(); }
                                }
                            }
                        }

                        if (main-view == 4): VerticalLayout {
                            width: parent.width;
                            height: parent.height;
                            padding: 14px;
                            spacing: 10px;

                            SpaceEyebrow { text: "SETTINGS / ABOUT"; }
                            SpaceHint {
                                text: provider-label;
                            }
                            SpaceHint {
                                text: onboarding;
                            }
                            SpaceHint {
                                text: product-version + "  ·  Slint Royalty-free 2.0";
                            }
                            Rectangle {
                                width: 140px;
                                height: 40px;
                                clip: true;
                                border-radius: 4px;
                                border-width: 1px;
                                border-color: SpaceChrome.space-edge;
                                AboutSlint { }
                            }
                            SpaceHint {
                                text: "Slint Royalty-free 2.0 attribution: AboutSlint above.";
                                font-size: 10px;
                            }
                            Rectangle {
                                background: transparent;
                                vertical-stretch: 1;
                            }
                        }
                    }
                }
            }
        }
    }
}

fn space_brush(token: SpaceToken) -> slint::Color {
    let (red, green, blue) = token.rgb();
    slint::Color::from_rgb_u8(red, green, blue)
}

fn apply_space_palette(ui: &GrokBuildPlusWindow) {
    let [
        void,
        floor,
        recessed,
        grey,
        raised,
        edge,
        silver,
        silver_bright,
        white,
        muted,
        accent,
        warn,
        refuse,
    ] = space_palette();
    assert_eq!(void.name(), "void");
    assert_eq!(void.hex().as_bytes().first().copied(), Some(b'#'));
    assert!(void.channel_range() <= 4);
    assert_eq!(accent, product_accent());
    assert_eq!(accent.hex(), product_accent().hex());
    assert!(warn.channel_range() > 20 && refuse.channel_range() > 20);
    let chrome = ui.global::<SpaceChrome>();
    chrome.set_space_void(space_brush(void));
    chrome.set_space_floor(space_brush(floor));
    chrome.set_space_recessed(space_brush(recessed));
    chrome.set_space_grey(space_brush(grey));
    chrome.set_space_raised(space_brush(raised));
    chrome.set_space_edge(space_brush(edge));
    chrome.set_space_silver(space_brush(silver));
    chrome.set_space_silver_bright(space_brush(silver_bright));
    chrome.set_space_white(space_brush(white));
    chrome.set_space_muted(space_brush(muted));
    chrome.set_space_accent(space_brush(accent));
    chrome.set_space_warn(space_brush(warn));
    chrome.set_space_refuse(space_brush(refuse));
    chrome.set_accept_fill(space_brush(accept_action_fill()));
    chrome.set_reject_fill(space_brush(reject_action_fill()));
    chrome.set_command_security_chip(space_brush(command_security_chip_fill(
        PlusCommandSecurityKind::Off,
    )));
}

fn apply_command_security_presentation(ui: &GrokBuildPlusWindow, kind: PlusCommandSecurityKind) {
    let status = present_command_security_status(kind);
    let panel = present_command_security_panel(kind);
    let detail = panel
        .strip_prefix(&status)
        .unwrap_or(&panel)
        .trim_start_matches('\n');
    ui.set_guest_status(status.into());
    ui.set_guest_copy(detail.into());
    ui.global::<SpaceChrome>()
        .set_command_security_chip(space_brush(command_security_chip_fill(kind)));
}

fn apply_pending_review_indicator(ui: &GrokBuildPlusWindow, pending: &PendingFileSet) {
    ui.set_has_pending_review(plus_review_badge_visible(!pending.items.is_empty()));
}

fn instantiate_plus_window() -> Result<GrokBuildPlusWindow, String> {
    let ui = GrokBuildPlusWindow::new().map_err(|error| error.to_string())?;
    apply_space_palette(&ui);
    ui.set_product_version(PLUS_PRODUCT_VERSION.into());
    ui.set_main_view(plus_nav_view_index(plus_default_nav()));
    assert_eq!(plus_nav_label(plus_default_nav()), "Chat");
    ui.set_provider_label(plus_chat_provider_label().into());
    ui.set_onboarding(
        "Set XAI_API_KEY for live chat, or use the labeled stub. Bind a folder, chat, and Accept file edits. Extra security for command runs is optional."
            .into(),
    );
    let _ = ADMITTED_UI_RUNTIME;
    apply_command_security_presentation(&ui, PlusCommandSecurityKind::Off);
    ui.set_guest_detail("Advanced: guest down / service missing / ready".into());
    let _ = PLUS_COMMAND_SECURITY_LEGEND;
    ui.set_attach_list(present_plus_context_chips(&[]).into());
    ui.set_session_mode(PLUS_MODE_AGENT.into());
    ui.set_plan_steps(present_plus_turn_plan(&[], None).into());
    let empty_pending = PendingFileSet::default();
    ui.set_needs_accept(present_needs_accept_inbox(&empty_pending).into());
    apply_pending_review_indicator(&ui, &empty_pending);
    let _ = PLUS_NEEDS_ACCEPT;
    Ok(ui)
}

/// Runs the GB Plus window until the user closes it.
///
/// # Errors
///
/// Returns a platform error when the window cannot be created or shown.
pub fn run_plus_window() -> Result<(), String> {
    let ui = instantiate_plus_window()?;
    let store = PlusSessionStore::from_process_environment();
    let host = Rc::new(RefCell::new(PlusWindowState {
        store: store.clone(),
        bound: None,
        pending: PendingFileSet::default(),
        last_assistant: None,
        attachments: Vec::new(),
        accepted_paths: Vec::new(),
        mode: PlusSessionMode::Agent,
        last_turn: None,
    }));
    apply_restored_session(&ui, &host, &restore_plus_session(&store));
    apply_command_security_surface(&ui, &store, false);
    wire_plus_window(&ui, &host);
    ui.run().map_err(|error| error.to_string())
}

/// Creates the window, checks the clickable bindings, and returns without
/// entering the event loop. Used by `--plus-smoke`.
///
/// # Errors
///
/// Returns a platform error when the window cannot be created.
pub fn smoke_plus_window() -> Result<String, String> {
    let ui = instantiate_plus_window()?;
    let smoke_state =
        std::env::temp_dir().join(format!("grok-build-plus-session-{}", std::process::id()));
    let store = PlusSessionStore::from_state_root(smoke_state);
    let host = Rc::new(RefCell::new(PlusWindowState {
        store: store.clone(),
        bound: None,
        pending: PendingFileSet::default(),
        last_assistant: None,
        attachments: Vec::new(),
        accepted_paths: Vec::new(),
        mode: PlusSessionMode::Agent,
        last_turn: None,
    }));
    wire_plus_window(&ui, &host);
    apply_command_security_surface(&ui, &store, false);
    let label = ui.get_provider_label().to_string();
    let live = crate::plus_host::PlusLiveIdentity::from_process_env().is_some();
    let onboarding = ui.get_onboarding().to_string();
    if !onboarding.contains("Bind a folder") {
        return Err(format!("onboarding one-liner missing: {onboarding}"));
    }
    let first = smoke_require_first_run(&ui)?;
    smoke_require_provider_label(&label, live)?;
    let driven = smoke_drive_click_path(&store, live)?;
    apply_smoke_surfaces(&ui, &host, &driven);
    let restored = restore_plus_session(&store);
    Ok(format_smoke_report(
        &label,
        &onboarding,
        &first,
        &driven,
        &restored,
    ))
}

struct SmokeFirstRun {
    folder: String,
    chat: String,
    command: String,
}

struct SmokeDrivenPath {
    bound: BoundProject,
    chat: String,
    command_outcome: String,
    diff: String,
    tool_steps: String,
    attach: String,
    checks: String,
    status: String,
    plan: String,
    mode: String,
    inbox: String,
    sessions: String,
    github: String,
}

fn smoke_require_first_run(ui: &GrokBuildPlusWindow) -> Result<SmokeFirstRun, String> {
    let first = SmokeFirstRun {
        folder: ui.get_folder_status().to_string(),
        chat: ui.get_chat_log().to_string(),
        command: ui.get_command_outcome().to_string(),
    };
    if first.folder != "No project folder bound." {
        return Err(format!(
            "first-run folder empty-state missing: {}",
            first.folder
        ));
    }
    if first.chat != "No chat yet." {
        return Err(format!(
            "first-run chat empty-state missing: {}",
            first.chat
        ));
    }
    if first.command != "No contained command has been attempted." {
        return Err(format!(
            "first-run command empty-state missing: {}",
            first.command
        ));
    }
    Ok(first)
}

fn smoke_require_provider_label(label: &str, live: bool) -> Result<(), String> {
    if live {
        if label.contains("FakeProvider") {
            return Err(format!(
                "configured live label must not name FakeProvider: {label}"
            ));
        }
    } else if !label.contains("not configured → FakeProvider") {
        return Err(format!(
            "unconfigured label must show not configured → FakeProvider: {label}"
        ));
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "legacy smoke preserves one sequential UI-path receipt and is not part of the shipped Tauri front door"
)]
fn smoke_drive_click_path(store: &PlusSessionStore, live: bool) -> Result<SmokeDrivenPath, String> {
    let folder = std::env::temp_dir().join(format!("grok-build-plus-smoke-{}", std::process::id()));
    std::fs::create_dir_all(&folder).map_err(|error| error.to_string())?;
    let folder = folder.canonicalize().map_err(|error| error.to_string())?;
    let bound =
        bind_and_remember_project_folder(store, &folder).map_err(|error| error.to_string())?;
    let note = format!("plus-tool-note-{}\n", std::process::id());
    std::fs::write(folder.join(PLUS_TOOL_NOTE_PATH), &note).map_err(|error| error.to_string())?;
    let attachments = match attach_plus_file(&bound, PLUS_TOOL_NOTE_PATH) {
        Ok(attachment) => vec![attachment],
        Err(_) => Vec::new(),
    };
    let chat_turn = plus_chat_turn_and_remember_with_attachments_in_mode(
        store,
        &bound,
        "what is in this project?",
        &attachments,
        PlusSessionMode::Agent,
    );
    let (chat, tool_steps, pending, executed, stuck) = match chat_turn {
        Ok(turn) => {
            let steps = present_plus_tool_steps(&turn.steps);
            let text = store
                .load_chat_transcript()
                .ok()
                .flatten()
                .unwrap_or_else(|| turn.assistant_text.clone());
            (text, steps, turn.pending, turn.steps, turn.stuck)
        }
        Err(error) => {
            let text = present_plus_host_error(&error);
            let _ = store.remember_chat_transcript(&text);
            (
                text,
                PLUS_TOOL_LOOP_NOT_RUN.to_owned(),
                None,
                Vec::new(),
                None,
            )
        }
    };
    if live && chat.contains("FakeProvider") && !chat.contains("live") {
        return Err(format!(
            "configured live chat must not be the Fake stub: {chat}"
        ));
    }
    if !live && !chat.contains("not configured → FakeProvider") {
        return Err(format!("unconfigured chat must name FakeProvider: {chat}"));
    }
    if !live {
        for name in [
            "read_file",
            "list_dir",
            "grep",
            "propose_write",
            "run_contained",
        ] {
            if !chat.contains(&format!("tool {name}")) {
                return Err(format!("Fake Send must run tool {name}: {chat}"));
            }
        }
        if !chat.contains(note.trim()) {
            return Err(format!(
                "Fake read_file must return the seeded note: {chat}"
            ));
        }
        if folder.join(PLUS_TOOL_PROPOSE_PATH).exists() {
            return Err("propose_write must not write the proposed file".into());
        }
    }
    let command_outcome = plus_gui_contained_command_and_remember(store, &bound);
    let status = present_plus_agent_status_trail(&executed, pending.as_ref());
    let plan = present_plus_turn_plan(&executed, stuck.as_ref());
    let mut set = PendingFileSet::default();
    if let Some(proposal) = pending {
        set.upsert(proposal);
    } else if let Ok(proposal) = propose_assistant_text_as_file(&bound, &chat) {
        set.upsert(proposal);
    }
    let diff = present_pending_file_set(&set);
    let inbox = present_needs_accept_inbox(&set);
    let _ = store.remember_pending_set(&set);
    let sessions = store.present_plus_session_list();
    let github = plus_github_status_report(&bound);
    let checks = if set.items.is_empty() {
        "No pending files to accept before checks.".into()
    } else {
        accept_pending_file_set(&bound, &set).map_err(|error| error.to_string())?;
        let _ = store.remember_pending_set(&PendingFileSet::default());
        plus_run_checks_after_accept_and_remember(store, &bound)
    };
    Ok(SmokeDrivenPath {
        bound,
        chat,
        command_outcome,
        diff,
        tool_steps,
        attach: present_plus_context_chips(&attachments),
        checks,
        status,
        plan,
        mode: PLUS_MODE_AGENT.to_owned(),
        inbox,
        sessions,
        github: github.text,
    })
}

fn apply_smoke_surfaces(
    ui: &GrokBuildPlusWindow,
    host: &Rc<RefCell<PlusWindowState>>,
    driven: &SmokeDrivenPath,
) {
    ui.set_folder_path(driven.bound.folder().display().to_string().into());
    ui.set_folder_status(format!("Bound project: {}", driven.bound.folder().display()).into());
    ui.set_chat_log(driven.chat.clone().into());
    ui.set_tool_steps(driven.tool_steps.clone().into());
    ui.set_agent_status(driven.status.clone().into());
    ui.set_plan_steps(driven.plan.clone().into());
    ui.set_session_mode(driven.mode.clone().into());
    ui.set_attach_list(driven.attach.clone().into());
    ui.set_command_outcome(driven.command_outcome.clone().into());
    host.borrow_mut().bound = Some(driven.bound.clone());
    host.borrow_mut().last_assistant = Some(driven.chat.clone());
    let mut set = PendingFileSet::default();
    if let Ok(proposal) = propose_assistant_text_as_file(&driven.bound, &driven.chat) {
        set.upsert(proposal);
    }
    host.borrow_mut().pending = set;
    ui.set_pending_diff(driven.diff.clone().into());
    ui.set_needs_accept(driven.inbox.clone().into());
    apply_pending_review_indicator(ui, &host.borrow().pending);
    ui.set_session_list(driven.sessions.clone().into());
    ui.set_git_status(driven.github.clone().into());
    apply_command_security_surface(ui, &driven_store(host), false);
}

fn driven_store(host: &Rc<RefCell<PlusWindowState>>) -> PlusSessionStore {
    host.borrow().store.clone()
}

fn apply_command_security_surface(
    ui: &GrokBuildPlusWindow,
    store: &PlusSessionStore,
    setup_in_progress: bool,
) {
    let lifecycle = probe_plus_guest_lifecycle();
    let kind = classify_command_security(
        store.command_security_preference(),
        lifecycle.kind(),
        setup_in_progress,
    );
    apply_command_security_presentation(ui, kind);
    ui.set_guest_detail(present_plus_guest_lifecycle(&lifecycle).into());
}

fn format_smoke_report(
    label: &str,
    onboarding: &str,
    first: &SmokeFirstRun,
    driven: &SmokeDrivenPath,
    restored: &PlusRestoredSession,
) -> String {
    format!(
        "PLUS WINDOW READY pin={ADMITTED_UI_RUNTIME} version={PLUS_PRODUCT_VERSION} provider={label}\nONBOARD {onboarding}\nFIRST-RUN folder={} chat={} command={}\nCOMMAND-SECURITY {}\nMODES Ask / Agent / Checks\nBOUND {}\nCHAT {}\nCOMMAND {}\nTOOL {}\nSTATUS {}\nPLAN {}\nMODE {}\nATTACH {}\nCHECKS {}\nINBOX {}\nSESSIONS {}\nGITHUB {}\nRESUME last={} chat={} command={}\nDIFF {}",
        first.folder,
        first.chat,
        first.command,
        present_command_security_panel(crate::plus_host::PlusCommandSecurityKind::Off)
            .replace('\n', " | "),
        driven.bound.folder().display(),
        driven.chat.replace('\n', " | "),
        driven.command_outcome.replace('\n', " | "),
        driven.tool_steps.replace('\n', " | "),
        driven.status.replace('\n', " | "),
        driven.plan.replace('\n', " | "),
        driven.mode.replace('\n', " | "),
        driven.attach.replace('\n', " | "),
        driven.checks.replace('\n', " | "),
        driven.inbox.replace('\n', " | "),
        driven.sessions.replace('\n', " | "),
        driven.github.replace('\n', " | "),
        restored
            .last_workspace
            .as_ref()
            .map_or_else(|| "none".into(), |path| path.display().to_string()),
        restored.chat.replace('\n', " | "),
        restored.command_outcome.replace('\n', " | "),
        driven.diff.replace('\n', " | ")
    )
}

struct PlusWindowState {
    store: PlusSessionStore,
    bound: Option<BoundProject>,
    pending: PendingFileSet,
    last_assistant: Option<String>,
    attachments: Vec<PlusAttachment>,
    accepted_paths: Vec<PathBuf>,
    mode: PlusSessionMode,
    last_turn: Option<PlusChatTurn>,
}

fn apply_restored_session(
    ui: &GrokBuildPlusWindow,
    host: &Rc<RefCell<PlusWindowState>>,
    restored: &PlusRestoredSession,
) {
    if let Some(path) = &restored.last_workspace {
        ui.set_folder_path(path.display().to_string().into());
        match bind_project_folder(path) {
            Ok(bound) => {
                host.borrow_mut().bound = Some(bound);
                ui.set_folder_status(restored.folder_status.clone().into());
            }
            Err(error) => {
                ui.set_folder_status(format!("{} ({error})", restored.folder_status).into());
            }
        }
    } else if restored.folder_status != "No project folder bound." {
        ui.set_folder_status(restored.folder_status.clone().into());
    }
    if !restored.chat.is_empty() {
        ui.set_chat_log(restored.chat.clone().into());
        if !restored.chat.contains("could not restore") && restored.chat != "No chat yet." {
            host.borrow_mut().last_assistant = Some(restored.chat.clone());
        }
    }
    if !restored.command_outcome.is_empty() {
        ui.set_command_outcome(restored.command_outcome.clone().into());
    }
    host.borrow_mut().pending = restored.pending.clone();
    ui.set_pending_diff(present_pending_file_set(&restored.pending).into());
    ui.set_needs_accept(restored.needs_accept.clone().into());
    apply_pending_review_indicator(ui, &restored.pending);
    ui.set_session_list(host.borrow().store.present_plus_session_list().into());
}

fn wire_nav(ui: &GrokBuildPlusWindow) {
    ui.on_select_nav({
        let ui = ui.as_weak();
        move |index| {
            let Some(ui) = ui.upgrade() else {
                return;
            };
            ui.set_main_view(plus_nav_view_index(plus_nav_from_index(index)));
        }
    });
}

fn wire_plus_window(ui: &GrokBuildPlusWindow, host: &Rc<RefCell<PlusWindowState>>) {
    wire_nav(ui);
    wire_bind_folder(ui, host);
    wire_sessions(ui, host);
    wire_send_chat(ui, host);
    wire_attach_file(ui, host);
    wire_run_contained(ui, host);
    wire_file_proposal(ui, host);
    wire_accept_reject(ui, host);
    wire_run_checks(ui, host);
    wire_git_and_file(ui, host);
    wire_github(ui, host);
    wire_guest_lifecycle(ui, host);
    wire_harness_and_modes(ui, host);
}

fn wire_guest_lifecycle(ui: &GrokBuildPlusWindow, host: &Rc<RefCell<PlusWindowState>>) {
    ui.on_start_colima({
        let ui = ui.as_weak();
        let host = Rc::clone(host);
        move || {
            let Some(ui) = ui.upgrade() else {
                return;
            };
            let text = match start_colima_if_safe() {
                Ok(text) => text,
                Err(error) => error,
            };
            ui.set_guest_detail(text.into());
            apply_command_security_surface(&ui, &host.borrow().store, false);
        }
    });
    ui.on_verify_install_root({
        let ui = ui.as_weak();
        move || {
            let Some(ui) = ui.upgrade() else {
                return;
            };
            ui.set_guest_detail(
                present_install_root_report(&crate::plus_host::verify_operator_install_root())
                    .into(),
            );
        }
    });
    ui.on_show_repair_hints({
        let ui = ui.as_weak();
        let host = Rc::clone(host);
        move || {
            let Some(ui) = ui.upgrade() else {
                return;
            };
            let lifecycle = probe_plus_guest_lifecycle();
            ui.set_guest_detail(present_plus_guest_repair_hints(lifecycle.kind()).into());
            apply_command_security_surface(&ui, &host.borrow().store, false);
        }
    });
    ui.on_prepare_guest({
        let ui = ui.as_weak();
        let host = Rc::clone(host);
        move || {
            let Some(ui) = ui.upgrade() else {
                return;
            };
            let text = prepare_plus_guest();
            ui.set_guest_detail(text.into());
            apply_command_security_surface(&ui, &host.borrow().store, false);
        }
    });
    ui.on_turn_on_extra_security({
        let ui = ui.as_weak();
        let host = Rc::clone(host);
        move || {
            let Some(ui) = ui.upgrade() else {
                return;
            };
            let store = host.borrow().store.clone();
            let _ =
                store.remember_command_security_preference(PlusCommandSecurityPreference::Extra);
            apply_command_security_surface(&ui, &store, true);
            let text = prepare_plus_guest();
            ui.set_guest_detail(text.into());
            apply_command_security_surface(&ui, &store, false);
        }
    });
    ui.on_not_now({
        let ui = ui.as_weak();
        let host = Rc::clone(host);
        move || {
            let Some(ui) = ui.upgrade() else {
                return;
            };
            let store = host.borrow().store.clone();
            let _ = store.remember_command_security_preference(PlusCommandSecurityPreference::Off);
            apply_command_security_surface(&ui, &store, false);
        }
    });
    let _ = (
        PLUS_GUEST_ACTION_START_COLIMA,
        PLUS_GUEST_ACTION_VERIFY_INSTALL,
        PLUS_GUEST_ACTION_REPAIR_HINTS,
        PLUS_TURN_ON_EXTRA_SECURITY,
        PLUS_NOT_NOW,
    );
}

fn wire_run_checks(ui: &GrokBuildPlusWindow, host: &Rc<RefCell<PlusWindowState>>) {
    ui.on_run_checks({
        let ui = ui.as_weak();
        let host = Rc::clone(host);
        move || {
            let Some(ui) = ui.upgrade() else {
                return;
            };
            let store = host.borrow().store.clone();
            let Some(bound) = host.borrow().bound.clone() else {
                ui.set_command_outcome("Bind a project folder before running tests/build.".into());
                return;
            };
            ui.set_agent_status(present_plus_agent_status(PlusAgentStatus::Running).into());
            ui.set_command_outcome(
                plus_run_checks_after_accept_and_remember(&store, &bound).into(),
            );
        }
    });
}

fn wire_sessions(ui: &GrokBuildPlusWindow, host: &Rc<RefCell<PlusWindowState>>) {
    ui.on_create_session({
        let ui = ui.as_weak();
        let host = Rc::clone(host);
        move || {
            let Some(ui) = ui.upgrade() else {
                return;
            };
            let name = ui.get_session_name().to_string();
            let pending = host.borrow().pending.clone();
            let store = host.borrow().store.clone();
            let _ = store.remember_pending_set(&pending);
            match store.create_plus_session(&name) {
                Ok(_) => {
                    host.borrow_mut().pending = PendingFileSet::default();
                    ui.set_session_list(store.present_plus_session_list().into());
                    ui.set_chat_log("No chat yet.".into());
                    ui.set_command_outcome("No contained command has been attempted.".into());
                    ui.set_pending_diff("No pending file proposal.".into());
                    ui.set_needs_accept(
                        present_needs_accept_inbox(&PendingFileSet::default()).into(),
                    );
                    apply_pending_review_indicator(&ui, &PendingFileSet::default());
                }
                Err(error) => ui.set_session_list(error.to_string().into()),
            }
        }
    });
    ui.on_switch_session({
        let ui = ui.as_weak();
        let host = Rc::clone(host);
        move || {
            let Some(ui) = ui.upgrade() else {
                return;
            };
            let name = ui.get_session_name().to_string();
            let pending = host.borrow().pending.clone();
            let store = host.borrow().store.clone();
            let _ = store.remember_pending_set(&pending);
            match store.switch_plus_session(&name) {
                Ok(session) => {
                    host.borrow_mut().pending = session.pending.clone();
                    ui.set_session_list(store.present_plus_session_list().into());
                    ui.set_chat_log(if session.chat.is_empty() {
                        "No chat yet.".into()
                    } else {
                        session.chat.into()
                    });
                    ui.set_command_outcome(if session.command_outcome.is_empty() {
                        "No contained command has been attempted.".into()
                    } else {
                        session.command_outcome.into()
                    });
                    ui.set_pending_diff(present_pending_file_set(&session.pending).into());
                    ui.set_needs_accept(present_needs_accept_inbox(&session.pending).into());
                    apply_pending_review_indicator(&ui, &session.pending);
                }
                Err(error) => ui.set_session_list(error.to_string().into()),
            }
        }
    });
    ui.on_rename_session({
        let ui = ui.as_weak();
        let host = Rc::clone(host);
        move || {
            let Some(ui) = ui.upgrade() else {
                return;
            };
            let name = ui.get_session_name().to_string();
            let active = host
                .borrow()
                .store
                .load_session_book()
                .ok()
                .map(|book| book.active_id)
                .unwrap_or_default();
            match host.borrow().store.rename_plus_session(&active, &name) {
                Ok(_) => {
                    ui.set_session_list(host.borrow().store.present_plus_session_list().into());
                }
                Err(error) => ui.set_session_list(error.to_string().into()),
            }
        }
    });
}

fn apply_chat_turn_to_window(
    ui: &GrokBuildPlusWindow,
    host: &Rc<RefCell<PlusWindowState>>,
    bound: &BoundProject,
    store: &PlusSessionStore,
    turn: PlusChatTurn,
) {
    host.borrow_mut().last_assistant = Some(turn.assistant_text.clone());
    ui.set_tool_steps(present_plus_tool_steps(&turn.steps).into());
    ui.set_agent_status(present_plus_agent_status_trail(&turn.steps, turn.pending.as_ref()).into());
    ui.set_plan_steps(present_plus_turn_plan(&turn.steps, turn.stuck.as_ref()).into());
    for proposal in turn.pending_set.items.clone() {
        host.borrow_mut().pending.upsert(proposal);
    }
    if let Some(proposal) = turn.pending.clone() {
        host.borrow_mut().pending.upsert(proposal);
    }
    if !host.borrow().pending.items.is_empty() {
        refresh_pending_surfaces(ui, host);
    }
    if let Some(path) = plus_file_path_from_tool_steps(&turn.steps) {
        let pending = host.borrow().pending.clone();
        ui.set_file_path(path.to_owned().into());
        ui.set_file_view(present_plus_file_pane(bound, path, &pending).into());
    }
    let log = store
        .load_chat_transcript()
        .ok()
        .flatten()
        .unwrap_or_else(|| turn.assistant_text.clone());
    ui.set_chat_log(log.into());
    if host.borrow().mode == PlusSessionMode::Checks {
        ui.set_command_outcome(turn.assistant_text.clone().into());
    }
    host.borrow_mut().last_turn = Some(turn);
}

#[allow(
    clippy::too_many_lines,
    reason = "legacy Slint callback wiring is kept behavior-identical and is not the shipped Tauri front door"
)]
fn wire_harness_and_modes(ui: &GrokBuildPlusWindow, host: &Rc<RefCell<PlusWindowState>>) {
    ui.on_select_ask({
        let ui = ui.as_weak();
        let host = Rc::clone(host);
        move || {
            let Some(ui) = ui.upgrade() else {
                return;
            };
            host.borrow_mut().mode = PlusSessionMode::Ask;
            ui.set_session_mode(present_plus_session_mode(PlusSessionMode::Ask).into());
        }
    });
    ui.on_select_agent({
        let ui = ui.as_weak();
        let host = Rc::clone(host);
        move || {
            let Some(ui) = ui.upgrade() else {
                return;
            };
            host.borrow_mut().mode = PlusSessionMode::Agent;
            ui.set_session_mode(present_plus_session_mode(PlusSessionMode::Agent).into());
        }
    });
    ui.on_select_checks({
        let ui = ui.as_weak();
        let host = Rc::clone(host);
        move || {
            let Some(ui) = ui.upgrade() else {
                return;
            };
            host.borrow_mut().mode = PlusSessionMode::Checks;
            ui.set_session_mode(present_plus_session_mode(PlusSessionMode::Checks).into());
        }
    });
    ui.on_continue_turn({
        let ui = ui.as_weak();
        let host = Rc::clone(host);
        move || {
            let Some(ui) = ui.upgrade() else {
                return;
            };
            let store = host.borrow().store.clone();
            let Some(bound) = host.borrow().bound.clone() else {
                ui.set_chat_log("Bind a project folder before Continue.".into());
                return;
            };
            let Some(turn) = host.borrow().last_turn.clone() else {
                ui.set_plan_steps(PLUS_TURN_NOT_STUCK.into());
                return;
            };
            if turn.stuck.is_none() {
                ui.set_plan_steps(PLUS_TURN_NOT_STUCK.into());
                return;
            }
            let mode = host.borrow().mode;
            let identity = PlusLiveIdentity::from_process_env();
            match plus_continue_stuck_turn_and_remember(
                &store,
                &bound,
                turn,
                identity.as_ref(),
                post_plus_live_chat,
                mode,
            ) {
                Ok(turn) => apply_chat_turn_to_window(&ui, &host, &bound, &store, turn),
                Err(error) => ui.set_chat_log(present_plus_host_error(&error).into()),
            }
        }
    });
    ui.on_retry_step({
        let ui = ui.as_weak();
        let host = Rc::clone(host);
        move || {
            let Some(ui) = ui.upgrade() else {
                return;
            };
            let store = host.borrow().store.clone();
            let Some(bound) = host.borrow().bound.clone() else {
                ui.set_chat_log("Bind a project folder before Retry.".into());
                return;
            };
            let Some(turn) = host.borrow().last_turn.clone() else {
                ui.set_plan_steps(PLUS_TURN_NOT_STUCK.into());
                return;
            };
            if turn.stuck.is_none() {
                ui.set_plan_steps(PLUS_TURN_NOT_STUCK.into());
                return;
            }
            let mode = host.borrow().mode;
            let identity = PlusLiveIdentity::from_process_env();
            match plus_retry_stuck_step_and_remember(
                &store,
                &bound,
                turn,
                identity.as_ref(),
                post_plus_live_chat,
                mode,
            ) {
                Ok(turn) => apply_chat_turn_to_window(&ui, &host, &bound, &store, turn),
                Err(error) => ui.set_chat_log(present_plus_host_error(&error).into()),
            }
        }
    });
}

fn wire_bind_folder(ui: &GrokBuildPlusWindow, host: &Rc<RefCell<PlusWindowState>>) {
    ui.on_bind_folder({
        let ui = ui.as_weak();
        let host = Rc::clone(host);
        move || {
            let Some(ui) = ui.upgrade() else {
                return;
            };
            let path = PathBuf::from(ui.get_folder_path().as_str());
            let store = host.borrow().store.clone();
            match bind_and_remember_project_folder(&store, path) {
                Ok(bound) => {
                    let status = format!("Bound project: {}", bound.folder().display());
                    host.borrow_mut().bound = Some(bound);
                    ui.set_folder_status(status.into());
                }
                Err(error) => {
                    host.borrow_mut().bound = None;
                    ui.set_folder_status(error.to_string().into());
                }
            }
        }
    });
}

fn wire_send_chat(ui: &GrokBuildPlusWindow, host: &Rc<RefCell<PlusWindowState>>) {
    ui.on_send_chat({
        let ui = ui.as_weak();
        let host = Rc::clone(host);
        move || {
            let Some(ui) = ui.upgrade() else {
                return;
            };
            let draft = ui.get_draft().to_string();
            let store = host.borrow().store.clone();
            let attachments = host.borrow().attachments.clone();
            let Some(bound) = host.borrow().bound.clone() else {
                ui.set_chat_log("Bind a project folder before chatting.".into());
                return;
            };
            let mode = host.borrow().mode;
            let _ = store.mark_plus_session_in_flight(true);
            ui.set_session_list(store.present_plus_session_list().into());
            match plus_chat_turn_and_remember_with_attachments_in_mode(
                &store,
                &bound,
                &draft,
                &attachments,
                mode,
            ) {
                Ok(turn) => {
                    apply_chat_turn_to_window(&ui, &host, &bound, &store, turn);
                    ui.set_draft("".into());
                    host.borrow_mut().attachments.clear();
                    ui.set_attach_list(present_plus_context_chips(&[]).into());
                }
                Err(error) => ui.set_chat_log(present_plus_host_error(&error).into()),
            }
            let _ = store.mark_plus_session_in_flight(false);
            ui.set_session_list(store.present_plus_session_list().into());
        }
    });
}

fn wire_attach_file(ui: &GrokBuildPlusWindow, host: &Rc<RefCell<PlusWindowState>>) {
    ui.on_attach_file({
        let ui = ui.as_weak();
        let host = Rc::clone(host);
        move || {
            let Some(ui) = ui.upgrade() else {
                return;
            };
            let Some(bound) = host.borrow().bound.clone() else {
                ui.set_attach_list("Bind a project folder before attaching a file.".into());
                return;
            };
            let path = PathBuf::from(ui.get_attach_path().as_str());
            match attach_plus_file(&bound, path) {
                Ok(attachment) => {
                    let mut attachments = host.borrow().attachments.clone();
                    match push_plus_attachment(&mut attachments, attachment) {
                        Ok(()) => {
                            ui.set_attach_list(present_plus_context_chips(&attachments).into());
                            host.borrow_mut().attachments = attachments;
                            ui.set_attach_path("".into());
                        }
                        Err(error) => ui.set_attach_list(error.to_string().into()),
                    }
                }
                Err(error) => ui.set_attach_list(error.to_string().into()),
            }
        }
    });
}

fn wire_run_contained(ui: &GrokBuildPlusWindow, host: &Rc<RefCell<PlusWindowState>>) {
    ui.on_run_contained({
        let ui = ui.as_weak();
        let host = Rc::clone(host);
        move || {
            let Some(ui) = ui.upgrade() else {
                return;
            };
            let store = host.borrow().store.clone();
            let Some(bound) = host.borrow().bound.clone() else {
                ui.set_command_outcome("Bind a project folder before running a command.".into());
                return;
            };
            ui.set_agent_status(present_plus_agent_status(PlusAgentStatus::Running).into());
            let _ = store.mark_plus_session_in_flight(true);
            ui.set_session_list(store.present_plus_session_list().into());
            ui.set_command_outcome(plus_gui_contained_command_and_remember(&store, &bound).into());
            let _ = store.mark_plus_session_in_flight(false);
            ui.set_session_list(store.present_plus_session_list().into());
        }
    });
}

fn wire_file_proposal(ui: &GrokBuildPlusWindow, host: &Rc<RefCell<PlusWindowState>>) {
    ui.on_propose_file({
        let ui = ui.as_weak();
        let host = Rc::clone(host);
        move || {
            let Some(ui) = ui.upgrade() else {
                return;
            };
            let Some(bound) = host.borrow().bound.clone() else {
                ui.set_pending_diff("Bind a project folder before proposing a file change.".into());
                return;
            };
            if host.borrow().mode == PlusSessionMode::Ask {
                ui.set_pending_diff("Ask mode does not stage a pending file proposal.".into());
                return;
            }
            let Some(assistant) = host.borrow().last_assistant.clone() else {
                ui.set_pending_diff("Chat first, then propose as file change.".into());
                return;
            };
            match propose_assistant_text_as_file(&bound, &assistant) {
                Ok(proposal) => {
                    host.borrow_mut().pending.upsert(proposal);
                    refresh_pending_surfaces(&ui, &host);
                }
                Err(error) => ui.set_pending_diff(error.to_string().into()),
            }
        }
    });
}

#[allow(
    clippy::too_many_lines,
    reason = "legacy Slint Accept/Reject callbacks remain together to preserve their shared pending-state refresh sequence"
)]
fn wire_accept_reject(ui: &GrokBuildPlusWindow, host: &Rc<RefCell<PlusWindowState>>) {
    ui.on_accept_proposal({
        let ui = ui.as_weak();
        let host = Rc::clone(host);
        move || {
            let Some(ui) = ui.upgrade() else {
                return;
            };
            let Some(bound) = host.borrow().bound.clone() else {
                ui.set_pending_diff("Bind a project folder before accepting a proposal.".into());
                return;
            };
            let set = host.borrow().pending.clone();
            if set.items.is_empty() {
                ui.set_pending_diff("No pending file proposal.".into());
                return;
            }
            match accept_pending_file_set(&bound, &set) {
                Ok(()) => {
                    let mut host_mut = host.borrow_mut();
                    for item in &set.items {
                        host_mut.accepted_paths.push(item.relative_path.clone());
                    }
                    host_mut.pending = PendingFileSet::default();
                    drop(host_mut);
                    ui.set_pending_diff(
                        format!("Accepted all\n{}", present_pending_file_set(&set)).into(),
                    );
                    persist_pending_inbox(&ui, &host);
                }
                Err(error) => ui.set_pending_diff(error.to_string().into()),
            }
        }
    });
    ui.on_reject_proposal({
        let ui = ui.as_weak();
        let host = Rc::clone(host);
        move || {
            let Some(ui) = ui.upgrade() else {
                return;
            };
            let Some(bound) = host.borrow().bound.clone() else {
                ui.set_pending_diff("Bind a project folder before rejecting a proposal.".into());
                return;
            };
            let set = host.borrow().pending.clone();
            if set.items.is_empty() {
                ui.set_pending_diff("No pending file proposal.".into());
                return;
            }
            match reject_pending_file_set(&bound, &set) {
                Ok(()) => {
                    host.borrow_mut().pending = PendingFileSet::default();
                    ui.set_pending_diff(
                        format!("Rejected all\n{}", present_pending_file_set(&set)).into(),
                    );
                    persist_pending_inbox(&ui, &host);
                }
                Err(error) => ui.set_pending_diff(error.to_string().into()),
            }
        }
    });
    ui.on_accept_file({
        let ui = ui.as_weak();
        let host = Rc::clone(host);
        move || {
            let Some(ui) = ui.upgrade() else {
                return;
            };
            apply_one_pending_file(&ui, &host, true);
        }
    });
    ui.on_reject_file({
        let ui = ui.as_weak();
        let host = Rc::clone(host);
        move || {
            let Some(ui) = ui.upgrade() else {
                return;
            };
            apply_one_pending_file(&ui, &host, false);
        }
    });
    ui.on_accept_group({
        let ui = ui.as_weak();
        let host = Rc::clone(host);
        move || {
            let Some(ui) = ui.upgrade() else {
                return;
            };
            apply_one_pending_group(&ui, &host, true);
        }
    });
    ui.on_reject_group({
        let ui = ui.as_weak();
        let host = Rc::clone(host);
        move || {
            let Some(ui) = ui.upgrade() else {
                return;
            };
            apply_one_pending_group(&ui, &host, false);
        }
    });
}

fn apply_one_pending_file(
    ui: &GrokBuildPlusWindow,
    host: &Rc<RefCell<PlusWindowState>>,
    accept: bool,
) {
    let Some(bound) = host.borrow().bound.clone() else {
        ui.set_pending_diff("Bind a project folder before changing a proposal.".into());
        return;
    };
    let path = std::path::PathBuf::from(ui.get_file_path().as_str());
    let set = host.borrow().pending.clone();
    let result = if accept {
        accept_pending_file_in_set(&bound, &set, &path)
    } else {
        reject_pending_file_in_set(&bound, &set, &path)
    };
    match result {
        Ok(remaining) => {
            let verb = if accept { "Accepted" } else { "Rejected" };
            ui.set_pending_diff(
                format!(
                    "{verb} {}\n{}",
                    path.display(),
                    present_pending_file_set(&remaining)
                )
                .into(),
            );
            let mut host_mut = host.borrow_mut();
            if accept {
                host_mut.accepted_paths.push(path);
            }
            host_mut.pending = remaining;
            drop(host_mut);
            persist_pending_inbox(ui, host);
        }
        Err(error) => ui.set_pending_diff(error.to_string().into()),
    }
}

fn apply_one_pending_group(
    ui: &GrokBuildPlusWindow,
    host: &Rc<RefCell<PlusWindowState>>,
    accept: bool,
) {
    let Some(bound) = host.borrow().bound.clone() else {
        ui.set_pending_diff("Bind a project folder before changing a proposal.".into());
        return;
    };
    let path = std::path::PathBuf::from(ui.get_file_path().as_str());
    let group_id = ui.get_group_id().to_string();
    let set = host.borrow().pending.clone();
    let result = if accept {
        accept_pending_group_in_set(&bound, &set, &path, &group_id)
    } else {
        reject_pending_group_in_set(&bound, &set, &path, &group_id)
    };
    match result {
        Ok(remaining) => {
            let verb = if accept {
                PLUS_ACCEPT_GROUP
            } else {
                PLUS_REJECT_GROUP
            };
            ui.set_pending_diff(
                format!(
                    "{verb} {} {}\n{}",
                    path.display(),
                    group_id,
                    present_pending_file_set(&remaining)
                )
                .into(),
            );
            host.borrow_mut().pending = remaining;
            persist_pending_inbox(ui, host);
        }
        Err(error) => ui.set_pending_diff(error.to_string().into()),
    }
}

fn refresh_pending_surfaces(ui: &GrokBuildPlusWindow, host: &Rc<RefCell<PlusWindowState>>) {
    persist_pending_inbox(ui, host);
    ui.set_pending_diff(present_pending_file_set(&host.borrow().pending).into());
}

fn persist_pending_inbox(ui: &GrokBuildPlusWindow, host: &Rc<RefCell<PlusWindowState>>) {
    let pending = host.borrow().pending.clone();
    let store = host.borrow().store.clone();
    let _ = store.remember_pending_set(&pending);
    ui.set_needs_accept(present_needs_accept_inbox(&pending).into());
    apply_pending_review_indicator(ui, &pending);
    ui.set_session_list(store.present_plus_session_list().into());
}

fn wire_github(ui: &GrokBuildPlusWindow, host: &Rc<RefCell<PlusWindowState>>) {
    ui.on_show_github_status({
        let ui = ui.as_weak();
        let host = Rc::clone(host);
        move || {
            let Some(ui) = ui.upgrade() else {
                return;
            };
            let Some(bound) = host.borrow().bound.clone() else {
                ui.set_git_status("Bind a project folder before GitHub status.".into());
                return;
            };
            let report = plus_github_status_report(&bound);
            let _ = PLUS_GH_STATUS;
            ui.set_git_status(report.text.into());
        }
    });
    ui.on_open_pr({
        let ui = ui.as_weak();
        let host = Rc::clone(host);
        move || {
            let Some(ui) = ui.upgrade() else {
                return;
            };
            let Some(bound) = host.borrow().bound.clone() else {
                ui.set_git_status("Bind a project folder before opening a PR.".into());
                return;
            };
            let report = plus_github_open_pr(&bound);
            let _ = (PLUS_GH_OPEN_PR, PLUS_GH_MISSING);
            ui.set_git_status(report.text.into());
        }
    });
}

fn wire_git_and_file(ui: &GrokBuildPlusWindow, host: &Rc<RefCell<PlusWindowState>>) {
    ui.on_show_git_status({
        let ui = ui.as_weak();
        let host = Rc::clone(host);
        move || {
            let Some(ui) = ui.upgrade() else {
                return;
            };
            let Some(bound) = host.borrow().bound.clone() else {
                ui.set_git_status("Bind a project folder before git status.".into());
                return;
            };
            ui.set_git_status(plus_git_status_report(&bound).into());
        }
    });
    ui.on_commit_accepted({
        let ui = ui.as_weak();
        let host = Rc::clone(host);
        move || {
            let Some(ui) = ui.upgrade() else {
                return;
            };
            let Some(bound) = host.borrow().bound.clone() else {
                ui.set_git_status("Bind a project folder before committing.".into());
                return;
            };
            let paths = host.borrow().accepted_paths.clone();
            match plus_git_commit_accepted(&bound, &paths, "GB Plus accepted files") {
                Ok(text) => {
                    host.borrow_mut().accepted_paths.clear();
                    ui.set_git_status(text.into());
                }
                Err(error) => ui.set_git_status(error.to_string().into()),
            }
        }
    });
    ui.on_open_file({
        let ui = ui.as_weak();
        let host = Rc::clone(host);
        move || {
            let Some(ui) = ui.upgrade() else {
                return;
            };
            let Some(bound) = host.borrow().bound.clone() else {
                ui.set_file_view("Bind a project folder before opening a file.".into());
                return;
            };
            let path = PathBuf::from(ui.get_file_path().as_str());
            let pending = host.borrow().pending.clone();
            ui.set_file_view(present_plus_file_pane(&bound, path, &pending).into());
        }
    });
}

#[cfg(test)]
mod tests {
    #[test]
    #[allow(clippy::too_many_lines)]
    fn shipped_window_source_binds_folder_chat_attribution_and_command() {
        let source = include_str!("plus_window.rs");
        for needle in [
            "Bind folder",
            "bind-folder",
            "Chat",
            "Run contained command",
            "AboutSlint",
            "FakeProvider",
            "plus_gui_contained_command",
            "bind_project_folder",
            "plus_chat_turn_and_remember_with_attachments_in_mode",
            "attach_plus_file",
            "Attach file",
            "Context: @file",
            "present_plus_context_chips",
            "@file",
            "Ask",
            "Agent",
            "Checks",
            "Continue",
            "Retry",
            "present_plus_turn_plan",
            "plus_continue_stuck_turn",
            "plus_retry_stuck_step",
            "Pending review",
            "Create session",
            "Switch session",
            "Rename session",
            "create_plus_session",
            "switch_plus_session",
            "Git status",
            "Commit accepted",
            "plus_git_status_report",
            "plus_git_commit_accepted",
            "Open file",
            "present_plus_file_pane",
            "plus_chat_provider_label",
            "restore_plus_session",
            "bind_and_remember_project_folder",
            "plus_gui_contained_command_and_remember",
            "could not restore",
            "present_pending_file_set",
            "accept_pending_file_set",
            "reject_pending_file_set",
            "accept_pending_file_in_set",
            "reject_pending_file_in_set",
            "Accept all",
            "Reject all",
            "Accept file",
            "Reject file",
            "Accept group",
            "Reject group",
            "accept_pending_group_in_set",
            "reject_pending_group_in_set",
            "Needs Accept",
            "present_needs_accept_inbox",
            "idle",
            "running",
            "needs accept",
            "GitHub status",
            "Open PR",
            "plus_github_status_report",
            "plus_github_open_pr",
            "Run tests/build",
            "plus_run_checks_after_accept_and_remember",
            "Propose as file change",
            "propose_assistant_text_as_file",
            "Chat first, then propose as file change.",
            "FIRST-RUN",
            "Tool steps",
            "tool-steps",
            "present_plus_tool_steps",
            "Status",
            "agent-status",
            "present_plus_agent_status_trail",
            "planning",
            "waiting for accept",
            "list_dir",
            "grep",
            "propose_write",
            "No project folder bound.",
            "No chat yet.",
            "No contained command has been attempted.",
            "No pending file proposal.",
            "Accept required",
            "Set XAI_API_KEY for live chat",
            "Bind a folder, chat, and Accept file edits",
            "extra security for command runs",
            "Command security",
            "Command security: Off",
            "Command security: Off | Setting up | On | Needs attention",
            "Turn on extra security",
            "Not now",
            "turn-on-extra-security",
            "not-now",
            "guest down",
            "service missing",
            "ready",
            "prepare guest",
            "start Colima (if safe)",
            "verify install root",
            "repair hints",
            "Advanced: guest down / service missing / ready",
            "start_colima_if_safe",
            "verify_install_root",
            "present_plus_guest_repair_hints",
            "COMMAND-SECURITY",
            "SpaceChrome",
            "command-security-chip",
            "command_security_chip_fill",
            "accept_action_fill",
            "reject_action_fill",
            "space_palette",
            "apply_space_palette",
            "SpaceButton",
            "SpaceButtonRole.accept",
            "SpaceButtonRole.accept-secondary",
            "SpaceButtonRole.refuse",
            "SpaceLineEdit",
            "SpaceReadout",
            "has-pending-review",
            "set_has_pending_review",
            "apply_pending_review_indicator",
            "guest-copy",
            "present_command_security_status",
            "apply_command_security_presentation",
            "preferred-width: 1200px",
            "preferred-height: 800px",
            "min-width: 900px",
            "min-height: 600px",
            "select-nav",
            "plus_nav_view_index",
            "plus_default_nav",
            "SpaceNavItem",
            "Settings / About",
            "main-deck",
            "product-version",
            "space-void",
        ] {
            assert!(
                source.contains(needle),
                "plus_window.rs must contain {needle}"
            );
        }
        let shipped = source
            .split("#[cfg(test)]")
            .next()
            .expect("shipped window source precedes tests");
        let reexport = format!("{}{}", "pub use sl", "int;");
        let reexport_path = format!("{}{}", "pub use sl", "int::");
        assert!(
            !shipped.contains(&reexport) && !shipped.contains(&reexport_path),
            "window module must not re-export Slint types"
        );
        assert!(
            !shipped.contains("webbrowser::"),
            "window must not call webbrowser"
        );
    }
}
