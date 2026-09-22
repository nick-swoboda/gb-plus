"use strict";

import { activeSessionId } from "./run_status.js";

export function textNode(tag, text, className = "") {
  const node = document.createElement(tag); node.textContent = text; node.className = className; return node;
}

export function appendToolContent(parent, contents) {
  for (const content of (Array.isArray(contents) ? contents : [])) {
    if (content.type === "diff") {
      const detail = document.createElement("details"); detail.open = true;
      detail.append(textNode("summary", content.path || "File change"));
      const before = textNode("pre", content.oldText ?? "New file", "cli-diff-before");
      const after = textNode("pre", content.newText ?? "", "cli-diff-after");
      before.setAttribute("aria-label", "Before"); after.setAttribute("aria-label", "After"); detail.append(before, after); parent.append(detail);
    } else if (content.type === "content" && content.content?.type === "text") {
      parent.append(textNode("pre", content.content.text));
    } else if (content.type === "terminal") {
      parent.append(textNode("p", `Terminal ${content.terminalId}`));
    } else if (content.type === "content" && content.content?.type === "resource_link") {
      parent.append(textNode("p", content.content.name || content.content.uri));
    }
  }
}

export function createCliInteractionCards({ invoke, getSnapshot, showToast, onBackgroundStopped = () => {} }) {
  const dialog = document.createElement("dialog"); dialog.className = "cli-interaction-dialog";
  dialog.setAttribute("aria-label", "Grok request"); document.body.append(dialog);
  let active = null; let pending = []; let busy = false; let project = null; let session = null; let restored = null; let generation = 0; let idleRun = null;
  const button = (label, action, primary = false) => {
    const node = textNode("button", label, `button ${primary ? "button-primary" : "button-secondary"}`); node.type = "button";
    node.addEventListener("click", action); return node;
  };
  async function answer(value) {
    if (!active || busy) return;
    const selected = active; const epoch = generation; busy = true;
    dialog.querySelectorAll("button").forEach(node => { node.disabled = true; });
    try {
      await invoke("answer_cli_interaction", { projectId: project, runId: selected.run, interactionId: selected.view.id, answer: value });
      if (epoch === generation) { pending = pending.filter(item => item !== selected); active = null; dialog.close(); }
    } catch (error) { showToast(String(error), true); dialog.querySelectorAll("button").forEach(node => { node.disabled = false; }); }
    finally { busy = false; if (epoch === generation) paint(); }
  }
  function paint() {
    if (active || !pending.length) return;
    active = pending[0]; const view = active.view; const request = view.request;
    dialog.replaceChildren(textNode("h2", view.kind === "permission" ? "Review request" : "A question from Grok"));
    if (view.kind === "permission") {
      const tool = request.toolCall || {};
      dialog.append(textNode("p", tool.title || "Grok is asking for permission."));
      const content = document.createElement("div"); content.className = "cli-permission-content";
      appendToolContent(content, tool.content);
      if (request.appPreview) {
        const preview = request.appPreview;
        content.append(textNode("p", preview.path));
        if (preview.oldText != null) {
          const before = textNode("pre", preview.oldText, "cli-diff-before"); before.setAttribute("aria-label", "Before"); content.append(before);
        }
        else content.append(textNode("small", "Previous contents are unavailable. Review the proposed contents below."));
        const after = textNode("pre", preview.newText, "cli-diff-after"); after.setAttribute("aria-label", "After"); content.append(after);
      } else if (tool.rawInput) content.append(textNode("pre", typeof tool.rawInput === "string" ? tool.rawInput : JSON.stringify(tool.rawInput, null, 2)));
      dialog.append(content);
      const actions = document.createElement("div"); actions.className = "cli-actions";
      for (const choice of request.options || []) {
        const label = choice.kind === "allow_once" && tool.kind === "edit" ? "Accept" : choice.name;
        const action = button(label, () => { void answer({ kind: "permission", option_id: choice.optionId }); }, choice.kind === "allow_once");
        action.title = choice.name; actions.append(action);
      }
      actions.append(button("Cancel request", () => { void answer({ kind: "cancel" }); })); dialog.append(actions);
    } else renderQuestions(request);
    const stop = button("Stop run", () => {
      if (active?.run === idleRun) {
        const epoch = generation; const run = idleRun;
        void invoke("stop_cli_background", { projectId: project, runId: run }).then(() => {
          if (epoch === generation) { idle(null, []); onBackgroundStopped(run); }
        }).catch(error => { if (epoch === generation) showToast(String(error), true); });
      }
      else document.querySelector("#cancel-chat")?.click();
    });
    stop.dataset.busyAllowed = ""; dialog.append(stop);
    if (!dialog.open) dialog.showModal();
  }
  function renderQuestions(request) {
    const form = document.createElement("form"); const answers = new Map();
    for (const [index, question] of (request.questions || []).entries()) {
      const field = document.createElement("fieldset"); field.append(textNode("legend", question.question));
      const options = [];
      for (const option of question.options || []) {
        const label = document.createElement("label"); const input = document.createElement("input");
        input.type = question.multiSelect || question.multi_select ? "checkbox" : "radio";
        input.name = `question-${index}`; input.value = option.label; options.push(input);
        label.append(input, textNode("span", option.label), textNode("small", option.description || ""));
        if (option.preview) { const detail = document.createElement("details"); detail.append(textNode("summary", "Preview"), textNode("pre", option.preview)); label.append(detail); }
        field.append(label);
      }
      const notes = document.createElement("textarea"); notes.rows = 2; notes.maxLength = 16384;
      notes.placeholder = "Your answer or additional detail"; notes.setAttribute("aria-label", `Your answer: ${question.question}`); field.append(notes);
      answers.set(question.question, { options, notes }); form.append(field);
    }
    const submit = button("Send answer", () => {} , true); submit.type = "submit"; form.append(submit);
    form.addEventListener("submit", event => {
      event.preventDefault(); const selected = {}; const notes = {};
      for (const [question, controls] of answers) {
        const values = controls.options.filter(input => input.checked).map(input => input.value); const free = controls.notes.value.trim();
        if (values.length || free) { selected[question] = values.length ? values : ["Other"]; if (free) notes[question] = free; }
      }
      void answer({ kind: "questions", answers: selected, notes });
    });
    form.append(button("Cancel", () => { void answer({ kind: "cancel" }); }));
    if (request.mode === "plan") form.append(button("Chat about this", () => { void answer({ kind: "chatAboutThis" }); }), button("Skip interview", () => { void answer({ kind: "skipInterview" }); }));
    dialog.append(form);
  }
  dialog.addEventListener("cancel", event => { event.preventDefault(); void answer({ kind: "cancel" }); });
  function update(event, run) {
    if (!run) return;
    if (event.kind === "cli_interaction") {
      if (!pending.some(item => item.run === run && item.view.id === event.payload.id)) pending.push({ run, view: event.payload });
    } else if (event.kind === "cli_interaction_resolved") {
      pending = pending.filter(item => item.run !== run || item.view.id !== event.payload);
      if (active?.run === run && active.view.id === event.payload) { active = null; dialog.close(); }
    }
    paint();
  }
  function snapshot(value) {
    const next = value?.activeProjectId;
    const nextSession = activeSessionId(value);
    if (project !== next || session !== nextSession) { project = next; session = nextSession; pending = []; active = null; restored = null; idleRun = null; generation += 1; dialog.close(); }
    const running = (value?.queue?.runs || []).filter(run => run.projectId === project && run.sessionId === session && run.state === "running");
    pending = pending.filter(item => item.run === idleRun || running.some(run => run.id === item.run));
    if (active && !pending.includes(active)) { active = null; dialog.close(); }
    if (value?.engine?.mode !== "grokCliStandard") return;
    const run = running[0]?.id;
    if (run && restored !== run) {
      restored = run; const epoch = generation;
      void invoke("pending_cli_interactions", { projectId: project, runId: run }).then(views => {
        if (epoch === generation && getSnapshot()?.activeProjectId === project) views.forEach(view => update({ kind: "cli_interaction", payload: view }, run));
      }).catch(() => { restored = null; });
    }
    paint();
  }
  function idle(run, views) {
    const previous = idleRun; idleRun = run;
    pending = pending.filter(item => item.run !== previous || (item.run === run && views.some(view => view.id === item.view.id)));
    if (active && !pending.includes(active)) { active = null; dialog.close(); }
    if (run) views.forEach(view => update({ kind: "cli_interaction", payload: view }, run));
    paint();
  }
  return { update, snapshot, idle };
}
