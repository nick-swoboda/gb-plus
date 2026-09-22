"use strict";

import { activeSessionId } from "./run_status.js";

export function createCliBackground({ invoke, getSnapshot, showToast, interactions, update }) {
  let scope = null; let cursor = 0; let run = null; let busy = false; let stopping = false;
  const current = () => {
    const value = getSnapshot();
    return value?.engine?.mode === "grokCliStandard" && value.activeProjectId
      ? { projectId: value.activeProjectId, sessionId: activeSessionId(value) } : null;
  };
  const active = () => (getSnapshot()?.queue?.runs || []).some(row => row.projectId === scope?.projectId && ["running", "stop_requested"].includes(row.state));
  const same = owner => scope === owner && JSON.stringify(current()) === JSON.stringify(owner);
  async function poll() {
    const next = current();
    if (JSON.stringify(next) !== JSON.stringify(scope)) { scope = next; cursor = 0; run = null; interactions.idle(null, []); }
    if (!scope || busy) return;
    if (active()) { run = null; cursor = 0; interactions.idle(null, []); return; }
    const owner = scope; busy = true;
    try {
      const value = await invoke("cli_background_activity", { ...owner, after: cursor, runId: run });
      if (!same(owner) || active()) return;
      if (!value) { run = null; cursor = 0; interactions.idle(null, []); return; }
      run = value.runId; cursor = value.cursor;
      interactions.idle(run, value.pending || []);
      for (const event of value.events || []) update(event, run);
      if (value.truncated) showToast("Earlier background output exceeded the display limit. The CLI session retains its history.");
    } catch { if (same(owner)) interactions.idle(null, []); }
    finally { busy = false; }
  }
  function stopped(target) {
    if (run === target) { run = null; cursor = 0; }
    if (active()) return;
    interactions.idle(null, []);
    update({ kind: "cli_update", payload: { update: { sessionUpdate: "background_stopped" } } }, target);
  }
  async function stop() {
    if (!scope || !run || stopping) return;
    const owner = scope; const target = run; stopping = true;
    try {
      await invoke("stop_cli_background", { projectId: owner.projectId, runId: target });
      if (same(owner)) { stopped(target); showToast("Background work stopped"); }
    } catch (error) { if (same(owner)) showToast(String(error), true); }
    finally { stopping = false; }
  }
  const timer = window.setInterval(() => { void poll(); }, 750);
  window.addEventListener("pagehide", () => window.clearInterval(timer), { once: true });
  return { poll, stop, stopped, connected: () => Boolean(run) };
}
