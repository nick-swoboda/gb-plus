"use strict";

export function activeSessionId(snapshot) {
  if (snapshot?.activeSessionId) return snapshot.activeSessionId;
  const projectId = snapshot?.activeProjectId;
  if (!projectId) return null;
  const worktreeId = snapshot?.workspaceRef?.worktreeId;
  return worktreeId ? `project-${projectId}-worktree-${worktreeId}` : `project-${projectId}`;
}

export function elapsedText(startedAtUnixMs, endedAtUnixMs = Date.now()) {
  const start = Number(startedAtUnixMs);
  const end = Number(endedAtUnixMs);
  if (!Number.isFinite(start) || !Number.isFinite(end) || start <= 0 || end < start) return null;
  const milliseconds = end - start;
  if (milliseconds < 60_000) return `${(milliseconds / 1_000).toFixed(1)}s`;
  const minutes = Math.floor(milliseconds / 60_000);
  const seconds = Math.floor((milliseconds % 60_000) / 1_000);
  return `${minutes}m ${seconds}s`;
}

export function terminalRunText(run) {
  const elapsed = elapsedText(run?.startedAtUnixMs, run?.endedAtUnixMs);
  const prefix = run?.state === "failed"
    ? "Failed after"
    : run?.state === "stopped"
      ? "Stopped after"
      : run?.state === "interrupted" ? "Interrupted after" : "Worked for";
  return elapsed ? `${prefix} ${elapsed}` : prefix.replace(/ (for|after)$/, "");
}
