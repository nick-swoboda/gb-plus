"use strict";

import { activeSessionId } from "./run_status.js";

export function createCliPermissionPicker({ invoke, getSnapshot, showToast }) {
  const select = document.createElement("select"); select.className = "cli-permission-picker"; select.hidden = true;
  select.setAttribute("aria-label", "Permission mode for this chat");
  for (const [value, label] of [["ask", "Ask"], ["acceptEdits", "Accept edits"], ["auto", "Auto"], ["alwaysApprove", "Always approve"]]) {
    const option = new Option(label, value);
    if (value === "acceptEdits") option.title = "Uses the CLI’s session-only edit grant. Other actions still follow CLI permissions.";
    select.append(option);
  }
  document.querySelector(".composer-context")?.prepend(select);
  let scope = null; let generation = 0; let selected = "ask"; let busy = false;
  const current = () => { const view = getSnapshot(); return { project: view?.activeProjectId, session: activeSessionId(view) }; };
  const matches = () => JSON.stringify(scope) === JSON.stringify(current());
  select.addEventListener("change", async () => {
    if (busy || !matches()) return;
    const mode = select.value; const epoch = generation; busy = true; select.disabled = true;
    try {
      const result = await invoke("set_cli_permission", { projectId: scope.project, sessionId: scope.session, mode });
      if (epoch === generation && matches()) { selected = result.mode; select.value = selected; showToast("Permission choice applies to this chat's next message."); }
    } catch (error) { if (epoch === generation) { select.value = selected; showToast(String(error), true); } }
    finally { busy = false; snapshot(getSnapshot()); }
  });
  function snapshot(view) {
    const enabled = view?.engine?.mode === "grokCliStandard"; select.hidden = !enabled;
    const next = current();
    select.disabled = busy || (view?.queue?.runs || []).some(run => ["running", "stop_requested"].includes(run.state));
    if (!enabled || !next.project || !next.session) return;
    if (JSON.stringify(scope) !== JSON.stringify(next)) {
      scope = next; const epoch = ++generation; select.disabled = true;
      void invoke("get_cli_permission", { projectId: scope.project, sessionId: scope.session }).then(value => {
        if (epoch === generation && matches()) { selected = value.mode; select.value = selected; snapshot(getSnapshot()); }
      }).catch(error => { if (epoch === generation) showToast(String(error), true); });
    }
    select.title = `${select.selectedOptions?.[0]?.textContent || "Ask"} for this chat. Accept edits uses the CLI’s own session edit grant.`;
  }
  function update(event) {
    if (event.kind === "cli_update" && event.payload?.update?.sessionUpdate === "permission_mode_update") {
      selected = event.payload.update.mode; select.value = selected;
    }
  }
  return { snapshot, update };
}
