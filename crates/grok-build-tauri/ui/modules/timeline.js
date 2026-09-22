"use strict";

function textElement(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  element.textContent = text;
  return element;
}

function actionLabel(value) {
  return String(value || "event")
    .split("_")
    .filter(Boolean)
    .map((part) => part[0]?.toUpperCase() + part.slice(1))
    .join(" ");
}

function eventSummary(event) {
  const payload = event.payload || {};
  if (event.kind === "message") return "Assistant complete";
  if (event.kind === "thought") return "Thought complete";
  if (event.kind === "usage") return "Usage updated";
  if (event.kind === "tool") return `Tool ${actionLabel(payload.action)} · ${payload.name || "provider_tool"}`;
  if (event.kind === "proposal") {
    const action = payload.action === "rejected"
      ? "Removed" : payload.action === "reject_requested" ? "Remove requested" : actionLabel(payload.action);
    return `Change ${action} · ${payload.count || 0}`;
  }
  if (event.kind === "security") return `${actionLabel(payload.action)} · ${actionLabel(payload.command_security)}`;
  if (event.kind === "queue") return `Queue ${actionLabel(payload.action)}${payload.mode ? ` · ${actionLabel(payload.mode)}` : ""}`;
  if (event.kind === "steering") return `Send now ${actionLabel(payload.action)}`;
  if (event.kind === "run") return `Run ${actionLabel(payload.action)} · ${payload.transport || "selected transport"}`;
  if (event.kind === "git") return `Git ${actionLabel(payload.action)} · ${actionLabel(payload.phase)}`;
  if (event.kind === "pty") return `User Terminal ${actionLabel(payload.action)}`;
  if (event.kind === "voice") return `Voice ${actionLabel(payload.action)}${payload.model ? ` · ${actionLabel(payload.model)}` : ""}`;
  if (event.kind === "browser") return `Browser ${actionLabel(payload.action)}${payload.mode ? ` · ${actionLabel(payload.mode)}` : ""}`;
  if (event.kind === "capture") return `Capture ${actionLabel(payload.action)}${payload.display_id ? ` · display ${payload.display_id}` : ""}`;
  if (event.kind === "desktop_control") return `Desktop Control ${actionLabel(payload.action)}${payload.operation ? ` · ${actionLabel(payload.operation)}` : ""}`;
  if (event.kind === "diagnostic") return `Diagnostic ${actionLabel(payload.action)}`;
  if (payload.type === "unsupported") return `Unsupported ${payload.provider || "provider"} event · ${payload.discriminator || "unknown"}`;
  if (event.kind === "error") return `Error · ${actionLabel(payload.code)}`;
  return actionLabel(event.kind);
}

function eventTone(event) {
  const payload = event.payload || {};
  const action = payload.action;
  if (
    event.kind === "error"
    || (event.kind === "security" && ["refused", "error"].includes(action))
    || action === "refused"
    || action === "blocked"
    || ["refused", "partial_failure"].includes(payload.phase)
    || ["failed", "stopped", "interrupted"].includes(action)
  ) return "error";
  if (
    event.kind === "queue"
    || (event.kind === "steering" && ["queued", "promoted_to_next"].includes(action))
    || (event.kind === "pty" && action === "starting")
    || action === "needs_review"
    || action === "permission_requested"
    || action === "model_install_requested"
    || action === "transcription_started"
    || action === "recording_discard_requested"
    || action === "runtime_install_requested"
    || action === "arm_requested"
    || action === "target_selection_requested"
    || action === "target_selected"
    || action === "stop_requested"
    || ["staged", "accept_requested", "reject_requested"].includes(action)
  ) return "attention";
  if (
    ["started", "live", "done", "completed", "accepted", "rejected", "consumed", "recording_started", "recording_discarded", "model_installed", "transcript_ready", "runtime_installed", "armed", "navigated", "inspected", "clicked", "typed", "key_sent", "scrolled", "event_posted", "frame_captured", "attached"].includes(action)
    || payload.phase === "completed"
  ) return "success";
  return "neutral";
}

function identityText(event) {
  const parts = [];
  if (event.projectId) parts.push(`project ${event.projectId.slice(0, 12)}`);
  if (event.sessionId) parts.push(`session ${event.sessionId.slice(0, 12)}`);
  if (event.runId) parts.push(`run ${event.runId.slice(0, 12)}`);
  return parts.join(" · ") || "system";
}

function captureMetadataLines(event) {
  const payload = event?.payload || {};
  if (event?.kind !== "capture" || payload.action !== "frame_captured") return [];
  const width = Number(payload.width || 0);
  const height = Number(payload.height || 0);
  const byteCount = Number(payload.byte_count || 0);
  const sha256 = typeof payload.sha256 === "string" ? payload.sha256 : "";
  if (width <= 0 || height <= 0 || byteCount <= 0 || !/^[0-9a-f]{64}$/.test(sha256)) {
    return ["Capture metadata incomplete · no still was represented as durable evidence"];
  }
  return [
    `Durable metadata only · transient still not saved · ${width}×${height} · ${byteCount.toLocaleString()} frame bytes`,
    `SHA-256 ${sha256}`,
  ];
}

function eventCard(event) {
  const article = document.createElement("article");
  article.className = "timeline-event";
  article.dataset.tone = eventTone(event);
  article.dataset.sequence = String(event.sequence);
  article.title = `#${event.sequence} · ${identityText(event)}`;

  const marker = document.createElement("span");
  marker.className = "timeline-marker";
  marker.setAttribute("aria-hidden", "true");

  const body = document.createElement("div");
  body.className = "timeline-event-body";
  const heading = document.createElement("div");
  heading.className = "timeline-event-heading";
  heading.append(
    textElement("strong", "", eventSummary(event)),
    textElement("time", "", event.timestamp || "Unknown time"),
  );
  body.append(heading);
  for (const line of captureMetadataLines(event)) {
    body.append(textElement("span", "timeline-event-detail", line));
  }
  article.append(marker, body);
  return article;
}

export function createActivityTimeline({ elements }) {
  let timeline = { available: true, status: "No events", events: [] };
  let activeProjectId = null;

  function paint() {
    elements.timelineStatus.textContent = timeline.status;
    elements.timelineStatus.dataset.kind = timeline.available ? "ready" : "error";
    const visible = timeline.events.slice(-250).reverse();
    elements.timelineList.replaceChildren(...visible.map(eventCard));
    elements.timelineEmpty.hidden = visible.length !== 0 || !timeline.available;
  }

  function render(next, projectId) {
    timeline = next || { available: false, status: "Activity timeline is unavailable.", events: [] };
    activeProjectId = projectId || null;
    paint();
  }

  function append(event) {
    if (!event || (event.projectId && event.projectId !== activeProjectId)) return;
    if (timeline.events.some((candidate) => candidate.sequence === event.sequence)) return;
    timeline = {
      available: true,
      status: `${Math.min(timeline.events.length + 1, 250)} events`,
      events: [...timeline.events, event].slice(-250),
    };
    paint();
  }

  return { render, append };
}
