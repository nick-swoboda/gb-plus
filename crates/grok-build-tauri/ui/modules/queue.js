"use strict";

import { visiblePrompt } from "./cli_input.js";
import { activeSessionId, terminalRunText } from "./run_status.js";
import { parseChatMessages } from "./read_aloud.js";

const ACTIVE_RUN_STATES = new Set(["running"]);
const RETAINED_STATES = new Set(["failed", "stopped", "interrupted"]);
const RETRY_STATES = new Set(["failed"]);

function boundedPreview(text) {
  const compact = visiblePrompt(text).replace(/\s+/g, " ").trim();
  return compact.length > 72 ? `${compact.slice(0, 71)}…` : compact;
}

function runForItem(queue, item) {
  return queue.runs.find((run) => run.queueItemId === item.id) || null;
}

function promotedSteerForItem(queue, item) {
  return item.predecessorRunId && (queue.steering || []).some((intent) => (
    intent.runId === item.predecessorRunId
    && intent.state === "promoted_to_next"
    && intent.message === item.prompt
  ));
}

function pendingItemEntry(queue, item) {
  const run = runForItem(queue, item);
  return { kind: "item", item, run, prompt: visiblePrompt(item.prompt), state: item.state,
    order: item.ordinal, runId: run?.id };
}

export function createChatScheduling({ invoke, elements, onSnapshot, onError, onNotice, onBusy }) {
  let snapshot = null;
  let hostBusy = false;
  let pendingSteer = null;
  let runPresentation = null;

  function projectItems(next) {
    const sessionId = activeSessionId(next);
    return next?.queue?.available && sessionId
      ? next.queue.items.filter((item) => (
        item.projectId === next.activeProjectId && item.sessionId === sessionId
      ))
      : [];
  }

  function retainedItems(queue, items, chat = "") {
    const represented = parseChatMessages(chat)
      .filter((message) => message.role === "user")
      .map((message) => message.displayText);
    return items.filter((item) => {
      const terminalRun = runForItem(queue, item);
      if (!(terminalRun
        && RETAINED_STATES.has(terminalRun.state)
        && !items.some((candidate) => candidate.retryOfRunId === terminalRun.id))) return false;
      const representedIndex = represented.indexOf(visiblePrompt(item.prompt));
      if (representedIndex < 0) return true;
      represented.splice(representedIndex, 1);
      return false;
    });
  }

  function activeRun() {
    const projectId = snapshot?.activeProjectId;
    const sessionId = activeSessionId(snapshot);
    return snapshot?.queue?.runs?.find((run) => (
      run.projectId === projectId
      && run.sessionId === sessionId
      && ACTIVE_RUN_STATES.has(run.state)
    )) || null;
  }

  function hasPendingTurns(next) {
    const items = projectItems(next);
    return items.some((item) => item.state === "queued" || item.state === "running")
      || retainedItems(next.queue, items, next.chat).length > 0;
  }

  function clearSteerConfirmation() {
    pendingSteer = null;
    elements.chatSteerConfirmation.hidden = true;
    elements.chatSteerPreview.textContent = "";
  }

  function closePopover() {
    clearSteerConfirmation();
    elements.chatNextPopover.hidden = true;
    elements.chatNextSummary.setAttribute("aria-expanded", "false");
  }

  async function command(name, payload, notice) {
    if (!invoke || hostBusy) return;
    onBusy(true);
    try {
      const response = await invoke(name, payload);
      onSnapshot(response.snapshot || response);
      if (notice) onNotice(notice);
      return true;
    } catch (error) {
      onError(error instanceof Error ? error.message : String(error));
      return false;
    } finally {
      onBusy(false);
    }
  }

  function actionButton(label, className, handler) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = className;
    button.textContent = label;
    button.disabled = hostBusy;
    button.addEventListener("click", handler);
    return button;
  }

  function appendItemActions(actions, item, run, beforeCommand = () => {}) {
    const perform = (name, payload, notice) => {
      beforeCommand();
      void command(name, payload, notice);
    };
    if (!item.autoStart && item.state === "queued") {
      actions.append(actionButton("Send next", "chat-next-action", () => {
        perform("release_held_message", { queueItemId: item.id }, "Will send next");
      }));
    }
    if (run && RETRY_STATES.has(run.state)) {
      actions.append(actionButton("Retry", "chat-next-action", () => {
        perform("retry_queue_run", { runId: run.id }, "Retry created");
      }));
    }
    actions.append(actionButton("Remove", "chat-next-remove", () => {
      perform("remove_queue_item", { queueItemId: item.id }, "Message removed");
    }));
  }

  function runMatchesItem(run, item) {
    return Boolean(run
      && item.state === "queued"
      && run.projectId === item.projectId
      && run.sessionId === item.sessionId
      && run.transport === item.transport);
  }

  function itemLabel(queue, item) {
    if (!item.autoStart) return "Held from an earlier version";
    const run = runForItem(queue, item);
    if (run?.state === "failed") return "Failed";
    if (run?.state === "stopped") return "Stopped";
    if (run?.state === "interrupted") return "Interrupted";
    if (promotedSteerForItem(queue, item)) return "Send now became next";
    return item.predecessorRunId ? "Next" : "Waiting";
  }

  function offerSendNow(item, run) {
    pendingSteer = {
      queueItemId: item.id,
      projectId: run.projectId,
      sessionId: run.sessionId,
      runId: run.id,
    };
    elements.chatSteerPreview.textContent = boundedPreview(item.prompt);
    elements.chatSteerConfirmation.hidden = false;
    elements.chatSteerSubmit.focus({ preventScroll: true });
  }

  function renderRow(queue, item, currentRun) {
    const row = document.createElement("div");
    row.className = "chat-next-item";
    const copy = document.createElement("div");
    const label = document.createElement("strong");
    label.textContent = itemLabel(queue, item);
    const preview = document.createElement("span");
    preview.textContent = boundedPreview(item.prompt);
    copy.append(label, preview);
    const actions = document.createElement("div");
    if (runMatchesItem(currentRun, item)) {
      const sendNow = actionButton("Send now", "chat-next-action", () => {
        offerSendNow(item, currentRun);
      });
      sendNow.title = "Steer the active run at its next safe step";
      actions.append(sendNow);
    }
    const run = runForItem(queue, item);
    appendItemActions(actions, item, run, closePopover);
    row.append(copy, actions);
    return row;
  }

  function renderSteer(intent) {
    const row = document.createElement("div");
    row.className = "chat-next-item";
    const copy = document.createElement("div");
    const label = document.createElement("strong");
    label.textContent = steeringLabel(intent.state);
    const preview = document.createElement("span");
    preview.textContent = boundedPreview(intent.message);
    copy.append(label, preview);
    row.append(copy);
    return row;
  }

  function steeringLabel(state) {
    return ({ pending: "Waiting for a delivery boundary", submitted: "Submitted · awaiting acknowledgement",
      acknowledged_by_cli: "Queued by Grok CLI", observed_in_provider_history: "Observed in provider history",
      uncertain: "Delivery uncertain · not sent again", refused: "Delivery refused", consumed: "Legacy delivery · uncertain" })[state] || "Delivery unavailable";
  }

  function renderPendingTurn(entry, queue, reviewWait) {
    const article = document.createElement("article");
    article.className = "chat-message chat-pending-message";
    article.dataset.role = "user";
    const copy = document.createElement("pre");
    copy.textContent = entry.prompt;
    const footer = document.createElement("div");
    footer.className = "chat-pending-footer";
    const status = document.createElement("span");
    status.className = "chat-pending-status";
    if (entry.runId) status.dataset.runId = entry.runId;
    status.textContent = entry.kind === "steer"
      ? steeringLabel(entry.state)
      : entry.runId && runPresentation?.runId === entry.runId
        ? runPresentation.text
        : entry.state === "running"
          ? "Waiting for response"
          : entry.run ? terminalRunText(entry.run)
            : entry.item?.autoStart && reviewWait ? reviewWait : itemLabel(queue, entry.item);
    footer.append(status);
    if (entry.kind === "item" && entry.state !== "running"
      && !["done", "needs_review"].includes(entry.run?.state)) {
      const actions = document.createElement("div");
      appendItemActions(actions, entry.item, entry.run);
      footer.append(actions);
    }
    article.append(copy, footer);
    return article;
  }

  function render(next) {
    const projectChanged = snapshot && snapshot.activeProjectId !== next.activeProjectId;
    snapshot = next;
    if (projectChanged) closePopover();
    const queue = next.queue;
    const run = activeRun();
    elements.sendControl.dataset.running = String(Boolean(run));
    elements.sendMenuToggle.hidden = !run;
    elements.sendButton.setAttribute("aria-label", run ? "Send now" : "Send message");
    elements.sendButton.title = run ? "Send now" : "Send";
    elements.sendMenuToggle.setAttribute("aria-label", run ? "Send next options" : "More send options");
    elements.sendMenuToggle.title = run ? "Send next" : "More send options";
    if (!run) {
      elements.sendMenu.hidden = true;
      elements.sendMenuToggle.setAttribute("aria-expanded", "false");
    }

    const currentItems = projectItems(next);
    const waiting = currentItems.filter((item) => item.state === "queued");
    const running = currentItems.filter((item) => item.state === "running");
    const retained = retainedItems(queue, currentItems, next.chat);
    const reviewWait = queue.reviewBlockedProjectIds?.includes(next.activeProjectId)
      && (next.staged || []).length > 0 ? "Waiting" : null;
    const pendingSteering = (queue.steering || []).filter((intent) => (
      intent.projectId === next.activeProjectId
      && intent.sessionId === activeSessionId(next)
      && intent.state !== "promoted_to_next"
    ));
    const visible = run ? [
      ...pendingSteering.map((intent) => ({ kind: "steer", value: intent, order: intent.ordinal })),
      ...waiting.map((item) => ({ kind: "item", value: item, order: item.ordinal })),
    ].sort((left, right) => left.order - right.order) : [];
    const pendingTurns = [
      ...running.map((item) => pendingItemEntry(queue, item)),
      ...waiting.map((item) => pendingItemEntry(queue, item)),
      ...retained.map((item) => pendingItemEntry(queue, item)),
      ...pendingSteering.map((intent) => ({
        kind: "steer", prompt: intent.message, state: intent.state,
        order: intent.ordinal, runId: intent.runId,
      })),
    ].sort((left, right) => left.order - right.order);

    if (pendingSteer && (!run
      || pendingSteer.runId !== run.id
      || pendingSteer.projectId !== run.projectId
      || pendingSteer.sessionId !== run.sessionId
      || !waiting.some((item) => item.id === pendingSteer.queueItemId))) {
      clearSteerConfirmation();
    }

    elements.chatNextStrip.hidden = visible.length === 0;
    elements.chatPendingTurns.hidden = pendingTurns.length === 0;
    elements.chatPendingTurns.replaceChildren(...pendingTurns.map((entry) => (
      renderPendingTurn(entry, queue, reviewWait)
    )));
    elements.chatNextList.replaceChildren(...visible.map((entry) => (
      entry.kind === "steer"
        ? renderSteer(entry.value)
        : renderRow(queue, entry.value, run)
    )));
    elements.chatNextSummary.hidden = false;
    elements.chatNextSummary.textContent = "Steer";
    elements.chatNextPopover.setAttribute("aria-label", "Steering");
    elements.chatNextSummary.setAttribute(
      "aria-expanded",
      String(visible.length > 0 && !elements.chatNextPopover.hidden),
    );
    elements.chatSteerCancel.disabled = hostBusy;
    elements.chatSteerSubmit.disabled = hostBusy;
    if (visible.length === 0) {
      closePopover();
    }
  }

  elements.chatNextSummary.addEventListener("click", () => {
    const open = elements.chatNextPopover.hidden;
    elements.chatNextPopover.hidden = !open;
    elements.chatNextSummary.setAttribute("aria-expanded", String(open));
  });
  elements.chatSteerCancel.addEventListener("click", clearSteerConfirmation);
  elements.chatSteerSubmit.addEventListener("click", async () => {
    const binding = pendingSteer;
    if (!binding) return;
    const succeeded = await command(
      "steer_queue_item",
      binding,
      "Will join this run at the next safe step",
    );
    if (succeeded) closePopover();
  });
  document.addEventListener("pointerdown", (event) => {
    if (!elements.chatNextStrip.contains(event.target)) closePopover();
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") closePopover();
  });

  return {
    activeRun,
    hasPendingTurns,
    render,
    setRunPresentation(presentation) {
      runPresentation = presentation;
      elements.chatPendingTurns.querySelectorAll("[data-run-id]").forEach((status) => {
        if (status.dataset.runId === presentation?.runId && presentation.text) {
          status.textContent = presentation.text;
        }
      });
    },
    setHostBusy(busy) {
      hostBusy = busy;
      if (snapshot) render(snapshot);
    },
  };
}
