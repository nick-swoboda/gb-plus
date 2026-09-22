"use strict";

import { activeSessionId } from "./run_status.js";

export function createCliModelPicker({ invoke, getSnapshot, showToast, button }) {
  const picker = document.createElement("div"); picker.className = "cli-model-popover"; picker.id = "chat-model-popover"; picker.setAttribute("popover", "auto"); picker.setAttribute("role", "dialog"); picker.setAttribute("aria-label", "Model and reasoning effort");
  const title = document.createElement("label"); title.className = "cli-model-label"; title.textContent = "Model";
  const model = document.createElement("select"); model.setAttribute("aria-label", "Model for this chat");
  const control = document.createElement("label"); control.className = "cli-effort-control";
  const heading = document.createElement("span"); heading.className = "cli-effort-heading";
  const caption = document.createElement("span"); caption.textContent = "Reasoning effort";
  const value = document.createElement("output");
  const effort = document.createElement("input"); effort.type = "range"; effort.min = "0"; effort.max = "0"; effort.value = "0"; effort.step = "1"; effort.setAttribute("aria-label", "Reasoning effort for this chat");
  const ends = document.createElement("span"); ends.className = "cli-effort-ends";
  const low = document.createElement("span"); low.textContent = "Default"; const high = document.createElement("span");
  heading.append(caption, value); ends.append(low, high); control.append(heading, effort, ends);
  const status = document.createElement("p"); status.setAttribute("role", "status");
  const apply = document.createElement("button"); apply.type = "button"; apply.className = "button button-primary"; apply.textContent = "Use model";
  const actions = document.createElement("div"); actions.className = "cli-model-actions"; actions.append(apply);
  title.append(model); picker.append(title, control, status, actions);
  if (button.parentElement) button.after(picker); else document.body.append(picker);
  button.setAttribute("aria-haspopup", "dialog"); button.setAttribute("aria-controls", picker.id); button.setAttribute("aria-expanded", "false");
  button.setAttribute("popovertarget", picker.id);
  [button, model, effort, apply].forEach(control => { control.dataset.busyAllowed = ""; });
  let catalog = null; let scope = null; let busy = false; let observed = null; let generation = 0; let loadedScope = null; let labelEpoch = 0; let identity = null; let choices = [""];
  const current = () => ({ projectId: getSnapshot()?.activeProjectId, sessionId: activeSessionId(getSnapshot()) });
  const currentKey = () => JSON.stringify([current(), getSnapshot()?.engine?.mode, getSnapshot()?.account?.selectedTransport]);
  const same = () => scope === currentKey();
  const isOpen = () => picker.matches(":popover-open");
  function closePicker() { if (isOpen()) picker.hidePopover(); }
  function position() {
    if (!isOpen()) return;
    const anchor = button.getBoundingClientRect(); const box = picker.getBoundingClientRect();
    const viewport = document.documentElement;
    picker.style.left = `${Math.max(12, Math.min(anchor.right - box.width, viewport.clientWidth - box.width - 12))}px`;
    picker.style.top = `${Math.max(12, Math.min(anchor.bottom + 8, viewport.clientHeight - box.height - 12))}px`;
  }
  picker.addEventListener("toggle", () => button.setAttribute("aria-expanded", String(isOpen())));
  picker.addEventListener("keydown", event => {
    if (event.key === "Escape") { event.preventDefault(); closePicker(); button.focus(); }
  });
  globalThis.addEventListener?.("resize", position);
  const label = token => token === "xhigh" ? "Extra high" : token ? token[0].toUpperCase() + token.slice(1) : "Default";
  const selectedEffort = () => choices[Number(effort.value)] || null;
  function showEffort() { const text = label(selectedEffort()); value.textContent = text; effort.setAttribute("aria-valuetext", text); }
  function showSelection(selected) {
    button.textContent = `${selected.model.name}${selected.reasoningEffort ? ` · ${selected.reasoningEffort}` : ""}`;
    button.title = `Choose model and reasoning effort: ${button.textContent}`;
    button.setAttribute("aria-label", button.title);
  }
  function efforts(preferred) {
    const selected = catalog?.models.find(item => item.id === model.value);
    const order = ["none", "minimal", "low", "medium", "high", "xhigh", "max"];
    const offered = catalog?.transport === "XaiKeychain" ? order.slice(0, -1) : selected?.reasoningEfforts || [];
    choices = ["", ...order.filter(token => offered.includes(token))];
    effort.max = String(choices.length - 1); effort.value = String(Math.max(0, choices.indexOf(preferred || "")));
    effort.disabled = busy || choices.length === 1; high.textContent = choices.length > 1 ? label(choices.at(-1)) : ""; showEffort();
  }
  async function open() {
    if (isOpen()) { closePicker(); return; }
    if (busy || !getSnapshot()?.account?.connected || !current().sessionId) return;
    scope = currentKey(); const epoch = ++generation; picker.showPopover(); status.hidden = false; status.textContent = "Loading models…"; position(); apply.disabled = true; model.disabled = true; effort.disabled = true;
    try {
      const loaded = await invoke("list_session_models", current());
      if (!same() || epoch !== generation || !isOpen()) return;
      catalog = loaded; model.replaceChildren(...loaded.models.map(item => new Option(item.name, item.id)));
      const selected = loaded.selected?.model?.id || observed?.model;
      model.value = loaded.models.some(item => item.id === selected) ? selected : loaded.models[0]?.id || "";
      model.disabled = !loaded.models.length; efforts(loaded.selected?.reasoningEffort ?? observed?.effort);
      status.hidden = loaded.models.length > 0; status.textContent = loaded.models.length ? "" : "No models available on this connection."; position();
      apply.disabled = !loaded.models.length; model.focus();
    } catch (error) { if (same() && epoch === generation) { status.hidden = false; status.textContent = String(error); position(); } }
  }
  model.addEventListener("change", () => efforts(null)); effort.addEventListener("input", showEffort);
  apply.addEventListener("click", async () => {
    if (!same() || busy || apply.disabled) return;
    const epoch = generation;
    busy = true; apply.disabled = true; model.disabled = true; effort.disabled = true; status.hidden = false; status.textContent = "Selecting…"; position();
    try {
      const selected = await invoke("select_session_model", { ...current(), modelId: model.value, reasoningEffort: selectedEffort() });
      if (same() && epoch === generation) { catalog.selected = selected; labelEpoch += 1; showSelection(selected); closePicker(); }
    } catch (error) { if (same() && epoch === generation) { status.textContent = String(error); position(); showToast(String(error), true); } }
    finally { busy = false; apply.disabled = !catalog?.models.length; model.disabled = !catalog?.models.length; effort.disabled = choices.length === 1; }
  });
  button.addEventListener("click", event => { event.preventDefault(); void open(); });
  function options(values) {
    const model = values?.find(item => item.id === "model"); const effort = values?.find(item => item.id === "reasoning_effort");
    if (model) {
      observed = { model: model.currentValue, effort: effort?.currentValue }; labelEpoch += 1;
      showSelection({ model: { name: model.options?.find(item => item.value === model.currentValue)?.name || model.currentValue }, reasoningEffort: observed.effort });
    }
  }
  function reset() { observed = null; catalog = null; loadedScope = null; labelEpoch += 1; generation += 1; button.textContent = "Grok"; button.setAttribute("aria-label", "Choose model and reasoning effort"); closePicker(); }
  function snapshot(view) {
    const key = currentKey();
    if (identity !== key) { identity = key; reset(); }
    button.hidden = false; button.disabled = !view?.account?.connected || !current().sessionId;
    button.title = button.disabled ? "Connect Account and open a project to choose a model" : "Choose model and reasoning effort";
    if (button.disabled) { loadedScope = null; closePicker(); return; }
    if (loadedScope === key) return;
    loadedScope = key; const epoch = labelEpoch;
    void invoke("list_session_models", current()).then(result => {
      if (currentKey() !== key || epoch !== labelEpoch) return;
      if (result.selected) showSelection(result.selected); else button.textContent = "Grok · model default";
    }).catch(() => { if (currentKey() === key) loadedScope = null; });
  }
  return { options, snapshot, reset };
}
