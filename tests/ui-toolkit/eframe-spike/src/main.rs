//! Eframe activity-list and accessibility fixture.

#![forbid(unsafe_code)]

use std::path::PathBuf;

use eframe::egui::{self, accesskit::Live, accesskit::Role};
use grok_build_core::{
    AcceptanceCriterion, AcceptanceKind, Digest, ExecutionOrigin, ProviderProfile, SprintBudget,
    SprintSpec, WorkspaceGrant, WorkspaceNetworkPolicy, WorkspacePermissions,
};

const INITIAL_ACTIVITY_COUNT: usize = 1_000;

#[derive(Clone, Debug, Eq, PartialEq)]
struct ActivityEntry {
    event_id: u64,
    text: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FixtureStatus {
    Ready,
    Running,
    Cancelled,
    Succeeded,
}

impl FixtureStatus {
    const fn label(self) -> &'static str {
        match self {
            Self::Ready => "Ready — no sprint has started",
            Self::Running => "Running — simulated events may be appended",
            Self::Cancelled => "Done — cancelled; no external effect occurred",
            Self::Succeeded => "Done — all simulated acceptance criteria passed",
        }
    }

    const fn is_running(self) -> bool {
        matches!(self, Self::Running)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum UiIntent {
    StartSprint { sprint_id: String },
    CancelSprint { sprint_id: String },
}

struct FixtureApp {
    sprint: SprintSpec,
    objective_draft: String,
    status: FixtureStatus,
    activity: Vec<ActivityEntry>,
    emitted_intents: Vec<UiIntent>,
    next_event_id: u64,
    visible_rows_last_frame: usize,
}

impl FixtureApp {
    fn seeded() -> Self {
        let sprint = seeded_sprint();
        debug_assert!(sprint.validate().is_ok());
        let activity = (1..=INITIAL_ACTIVITY_COUNT as u64)
            .map(|event_id| ActivityEntry {
                event_id,
                text: format!("Simulated event {event_id:04}"),
            })
            .collect();
        Self {
            objective_draft: sprint.objective.clone(),
            sprint,
            status: FixtureStatus::Ready,
            activity,
            emitted_intents: Vec::new(),
            next_event_id: INITIAL_ACTIVITY_COUNT as u64 + 1,
            visible_rows_last_frame: 0,
        }
    }

    fn append_activity(&mut self, text: impl Into<String>) {
        let event_id = self.next_event_id;
        self.next_event_id += 1;
        self.activity.push(ActivityEntry {
            event_id,
            text: text.into(),
        });
    }

    fn start(&mut self) {
        if self.status.is_running() {
            return;
        }
        self.status = FixtureStatus::Running;
        self.emitted_intents.push(UiIntent::StartSprint {
            sprint_id: self.sprint.sprint_id.clone(),
        });
        self.append_activity("Start intent emitted to the inert facade");
    }

    fn cancel(&mut self) {
        if !self.status.is_running() {
            return;
        }
        self.status = FixtureStatus::Cancelled;
        self.emitted_intents.push(UiIntent::CancelSprint {
            sprint_id: self.sprint.sprint_id.clone(),
        });
        self.append_activity("Cancel intent emitted; no process existed to terminate");
    }

    fn succeed(&mut self) {
        if !self.status.is_running() {
            return;
        }
        self.status = FixtureStatus::Succeeded;
        self.append_activity("Terminal success recorded for the simulated fixture");
    }

    fn show_status(&self, ui: &mut egui::Ui) {
        let status_id = egui::Id::new("fixture-terminal-status");
        let parent_id = ui.id();
        let status_label = self.status.label();
        ui.accesskit_node_builder(status_id, |node| {
            node.set_role(Role::Status);
            node.set_label(status_label);
            node.set_live(Live::Polite);
        });
        ui.scope_builder(
            egui::UiBuilder::new()
                .id(status_id)
                .accessibility_parent(parent_id),
            |ui| {
                ui.heading(status_label);
            },
        );
    }

    fn show_activity(&mut self, ui: &mut egui::Ui) {
        let list_id = egui::Id::new("fixture-activity-list");
        let total_rows = self.activity.len();
        ui.accesskit_node_builder(list_id, |node| {
            node.set_role(Role::List);
            node.set_label("Sprint activity");
            node.set_size_of_set(total_rows);
        });

        let activity = &self.activity;
        let mut visible_rows = 0;
        let row_height = ui.text_style_height(&egui::TextStyle::Monospace);
        egui::ScrollArea::vertical()
            .id_salt("fixture-activity-scroll")
            .stick_to_bottom(true)
            .show_rows(ui, row_height, total_rows, |ui, visible_range| {
                visible_rows = visible_range.len();
                for index in visible_range {
                    let entry = &activity[index];
                    let row_id = list_id.with(("activity-event", entry.event_id));
                    ui.scope_builder(
                        egui::UiBuilder::new()
                            .id(row_id)
                            .accessibility_parent(list_id),
                        |ui| {
                            ui.accesskit_node_builder(row_id, |node| {
                                node.set_role(Role::ListItem);
                                node.set_label(entry.text.clone());
                                node.set_position_in_set(index + 1);
                            });
                            ui.monospace(format!("#{:06}  {}", entry.event_id, entry.text));
                        },
                    );
                }
            });
        self.visible_rows_last_frame = visible_rows;
    }
}

impl eframe::App for FixtureApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ui, |ui| {
            ui.heading("Grok Build UI runtime spike");
            ui.label(format!(
                "Workspace: {}",
                self.sprint.workspace_grant.canonical_root.display()
            ));
            ui.label(format!("Sprint: {}", self.sprint.sprint_id));

            ui.separator();
            let objective_label = ui.label("Objective");
            ui.add(
                egui::TextEdit::multiline(&mut self.objective_draft)
                    .id_salt("fixture-objective")
                    .desired_rows(3)
                    .lock_focus(false),
            )
            .labelled_by(objective_label.id);

            ui.horizontal(|ui| {
                if ui
                    .add_enabled(!self.status.is_running(), egui::Button::new("Run"))
                    .clicked()
                {
                    self.start();
                }
                if ui
                    .add_enabled(self.status.is_running(), egui::Button::new("Cancel"))
                    .clicked()
                {
                    self.cancel();
                }
                if ui
                    .add_enabled(
                        self.status.is_running(),
                        egui::Button::new("Append simulated event"),
                    )
                    .clicked()
                {
                    self.append_activity("Incremental simulated provider event");
                }
                if ui
                    .add_enabled(
                        self.status.is_running(),
                        egui::Button::new("Finish successfully"),
                    )
                    .clicked()
                {
                    self.succeed();
                }
            });

            self.show_status(ui);
            ui.label(format!(
                "Activity rows: {}; visual rows instantiated last frame: {}",
                self.activity.len(),
                self.visible_rows_last_frame
            ));
            self.show_activity(ui);
        });
    }
}

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        renderer: eframe::Renderer::Glow,
        ..Default::default()
    };
    eframe::run_native(
        "Grok Build UI Runtime Spike",
        options,
        Box::new(|_creation_context| Ok(Box::new(FixtureApp::seeded()))),
    )
}

fn seeded_sprint() -> SprintSpec {
    SprintSpec {
        sprint_id: "ui-runtime-spike".into(),
        objective: "Prove the removable native UI facade without external effects".into(),
        acceptance_criteria: vec![AcceptanceCriterion {
            criterion_id: "ui-runtime-matrix".into(),
            description: "Every captured UI runtime matrix cell passes".into(),
            kind: AcceptanceKind::HumanJudgment,
        }],
        provider: ProviderProfile {
            backend_id: "inert-ui-fixture".into(),
            model_id: "no-model".into(),
            execution_origin: ExecutionOrigin::ReadOnly,
        },
        budget: SprintBudget {
            max_tasks: 1,
            max_attempts_per_task: 1,
            max_tool_calls: 1,
            max_duration_ms: 300_000,
        },
        max_workers: 1,
        workspace_grant: WorkspaceGrant {
            grant_id: "ui-runtime-spike-read-only".into(),
            canonical_root: PathBuf::from("/tmp/grok-build-ui-spike"),
            permissions: WorkspacePermissions::read_only(),
            network: WorkspaceNetworkPolicy::Denied,
            policy_version: 1,
            grant_hash: fixed_digest('a'),
        },
        base_snapshot: fixed_digest('b'),
    }
}

fn fixed_digest(character: char) -> Digest {
    match Digest::parse(character.to_string().repeat(64)) {
        Ok(digest) => digest,
        Err(error) => panic!("fixed UI fixture digest must be valid: {error}"),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn seed_has_one_thousand_unique_stable_product_event_ids() {
        let app = FixtureApp::seeded();
        let ids = app
            .activity
            .iter()
            .map(|entry| entry.event_id)
            .collect::<BTreeSet<_>>();
        assert_eq!(ids.len(), INITIAL_ACTIVITY_COUNT);
        assert_eq!(ids.first(), Some(&1));
        assert_eq!(ids.last(), Some(&(INITIAL_ACTIVITY_COUNT as u64)));
    }

    #[test]
    fn append_never_rekeys_retained_entries() {
        let mut app = FixtureApp::seeded();
        let before = app
            .activity
            .iter()
            .map(|entry| entry.event_id)
            .collect::<Vec<_>>();
        app.append_activity("new event");
        let retained = app.activity[..before.len()]
            .iter()
            .map(|entry| entry.event_id)
            .collect::<Vec<_>>();
        assert_eq!(retained, before);
        assert_eq!(
            app.activity.last().map(|entry| entry.event_id),
            Some(INITIAL_ACTIVITY_COUNT as u64 + 1)
        );
    }

    #[test]
    fn fixture_uses_valid_production_contract_shapes() {
        let sprint = seeded_sprint();
        assert!(sprint.validate().is_ok());
        let grant: &WorkspaceGrant = &sprint.workspace_grant;
        assert_eq!(grant.permissions, WorkspacePermissions::read_only());
        assert_eq!(grant.network, WorkspaceNetworkPolicy::Denied);
    }
}
