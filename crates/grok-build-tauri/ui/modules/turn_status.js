"use strict";

import { elapsedText, terminalRunText } from "./run_status.js";

const ACTIVE_RUN_STATES = new Set(["running", "stop_requested"]);

const TOOL_ACTIVITY = Object.freeze({
  list_dir: "Reading project…",
  read_file: "Reading project…",
  grep: "Searching project…",
  glob: "Searching project…",
  propose_write: "Preparing changes…",
  propose_replace: "Preparing changes…",
  todo_write: "Updating plan…",
  run_contained: "Running command…",
  browser_navigate: "Using Browser…",
  browser_inspect: "Using Browser…",
  browser_click: "Using Browser…",
  browser_type: "Using Browser…",
  browser_key: "Using Browser…",
  browser_scroll: "Using Browser…",
  browser_screenshot: "Using Browser…",
  desktop_click: "Using Desktop Control…",
  desktop_type: "Using Desktop Control…",
  desktop_key: "Using Desktop Control…",
  desktop_scroll: "Using Desktop Control…",
});

export function toolActivityLabel(name) {
  return TOOL_ACTIVITY[String(name || "")] || "Using a tool…";
}


export function createTurnStatus({ elements, onChange = () => {} }) {
  let activeProjectId = null;
  let activeRunId = null;
  let activeRunStartedAt = null;
  let label = null;
  let phase = "idle";
  let timer = null;

  function paint(presentedRunId = activeRunId) {
    const visible = typeof label === "string" && label.length > 0;
    const elapsed = activeRunId ? elapsedText(activeRunStartedAt) : null;
    const presented = visible && elapsed ? `${label} · ${elapsed}` : label;
    elements.chatTurnStatus.hidden = !visible;
    elements.chatTurnStatus.dataset.phase = visible ? phase : "idle";
    elements.chatTurnStatusLabel.textContent = visible ? presented : "";
    elements.chatTurnStatus.title = visible ? presented.replace(/…/, "") : "";
    onChange({ runId: presentedRunId, text: visible ? presented : null, phase });
  }

  function syncTimer(active) {
    if (active && timer === null) timer = window.setInterval(paint, 100);
    if (!active && timer !== null) {
      window.clearInterval(timer);
      timer = null;
    }
  }

  function set(nextLabel, nextPhase, presentedRunId = activeRunId) {
    label = nextLabel;
    phase = nextPhase;
    paint(presentedRunId);
  }

  function renderSnapshot(snapshot) {
    const nextProjectId = snapshot?.activeProjectId || null;
    if (activeProjectId !== nextProjectId) {
      syncTimer(false);
      activeRunId = null;
      activeRunStartedAt = null;
      label = null;
      phase = "idle";
    }
    activeProjectId = nextProjectId;
    const run = snapshot?.queue?.runs?.find((candidate) => (
      candidate.projectId === activeProjectId && ACTIVE_RUN_STATES.has(candidate.state)
    ));

    if (run) {
      activeRunStartedAt = run.startedAtUnixMs;
      syncTimer(true);
      if (run.id !== activeRunId) {
        activeRunId = run.id;
        set(
          run.state === "stop_requested" ? "Cancelling…" : "Waiting for response…",
          run.state === "stop_requested" ? "cancelling" : "waiting",
        );
      } else if (run.state === "stop_requested") {
        set("Cancelling…", "cancelling");
      } else if (!label || phase === "idle" || phase === "review") {
        set("Waiting for response…", "waiting");
      }
      return;
    }

    syncTimer(false);
    if (activeRunId) {
      const terminal = snapshot?.queue?.runs?.find((candidate) => candidate.id === activeRunId);
      activeRunId = null;
      activeRunStartedAt = null;
      if (terminal && !ACTIVE_RUN_STATES.has(terminal.state)) {
        set(terminalRunText(terminal), terminal.state, terminal.id);
        return;
      }
    }
    if (!["done", "needs_review", "failed", "stopped", "interrupted"].includes(phase)) {
      set(null, "idle");
    }
  }

  function handleRuntimeEvent(event, runId = null) {
    if (!event || !runId) return;
    if (!activeRunId) activeRunId = runId;
    if (runId && runId !== activeRunId) return;

    switch (event.kind) {
      case "cli_interaction":
        set(event.payload?.kind === "permission" ? "Waiting for your approval…" : "Waiting for your answer…", "approval");
        break;
      case "cli_interaction_resolved":
        set("Still running…", "waiting");
        break;
      case "cli_update":
        if (["tool_call", "tool_call_update"].includes(event.payload?.update?.sessionUpdate)) {
          set(event.payload.update.status === "completed" ? "Still running…" : (event.payload.update.title || "Using a tool…"), "tool");
        }
        break;
      case "thought_delta":
        set("Thinking…", "thinking");
        break;
      case "assistant_delta":
        set("Responding…", "responding");
        break;
      case "tool_request":
        set(toolActivityLabel(event.payload?.name), "tool");
        break;
      case "tool_completed":
        set("Waiting for response…", "waiting");
        break;
      case "tool_refused":
        set("Tool refused", "refused");
        break;
      case "error":
        set("Run failed", "refused");
        break;
      default:
        break;
    }
  }

  return { renderSnapshot, handleRuntimeEvent };
}
